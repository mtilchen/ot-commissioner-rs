//! The REPL command interpreter: a faithful reimplementation of the C++
//! `ot-commissioner` CLI command surface, backed by the pure-Rust library.
//!
//! Commands that exercise the non-CCM commissioner protocol are fully wired to
//! [`crate::commissioner`]. Commands outside that scope (CCM token flows, the
//! persistent network registry, mDNS discovery, and multi-network `--nwk`/
//! `--dom` job execution) are present with their exact usage and report
//! `[failed]` with an explanatory message.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde_json::json;

use crate::{
    commissioner::{
        Commissioner, CommissionerDatasetFlags, CommissionerEvent, CommissionerState, DatasetFlags,
        StaticJoinerHandler,
    },
    crypto::compute_joiner_id,
    dataset::Dataset,
    meshcop::diag::{NetDiagData, diag_flags},
};

use super::config::CliConfig;
use super::json;
use super::value::CommandValue;

const SYNTAX_FEW_ARGS: &str = "too few arguments";
const NOT_CONNECTED: &str = "commissioner is not started; run 'start' first";

/// One parsed REPL command line.
type Tokens = Vec<String>;

/// The REPL interpreter and its session state.
pub struct Interpreter {
    config: CliConfig,
    commissioner: Option<Commissioner>,
    /// Joiner PSKds keyed by joiner ID, applied via a [`StaticJoinerHandler`].
    joiner_pskds: HashMap<[u8; 8], String>,
    joiner_all_pskd: Option<String>,
    energy_reports: Vec<(String, u32, Vec<u8>)>,
    panid_conflicts: Vec<(String, u32, u16)>,
    should_exit: bool,
}

impl Interpreter {
    /// Creates an interpreter from the loaded configuration.
    pub fn new(config: CliConfig) -> Self {
        Self {
            config,
            commissioner: None,
            joiner_pskds: HashMap::new(),
            joiner_all_pskd: None,
            energy_reports: Vec::new(),
            panid_conflicts: Vec::new(),
            should_exit: false,
        }
    }

    /// Whether `exit`/`quit` has been requested.
    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    /// Evaluates one input line and prints the result.
    pub async fn evaluate_and_print(&mut self, line: &str) {
        let tokens = match tokenize(line) {
            Ok(tokens) => tokens,
            Err(message) => {
                CommandValue::failed(message).print();
                return;
            }
        };
        if tokens.is_empty() {
            return;
        }
        if has_multi_network_flag(&tokens) {
            CommandValue::failed(
                "multi-network selectors (--nwk/--dom) require the network registry, \
                 which is not implemented in this build",
            )
            .print();
            return;
        }
        let value = self.dispatch(&tokens).await;
        value.print();
    }

    async fn dispatch(&mut self, tokens: &Tokens) -> CommandValue {
        match tokens[0].as_str() {
            "help" => self.cmd_help(tokens),
            "exit" | "quit" => {
                self.should_exit = true;
                CommandValue::done()
            }
            "config" => self.cmd_config(tokens),
            "state" => self.cmd_state(),
            "start" => self.cmd_start(tokens).await,
            "stop" => self.cmd_stop().await,
            "active" => self.cmd_active(),
            "sessionid" => self.cmd_sessionid(),
            "borderagent" => self.cmd_border_agent(tokens).await,
            "joiner" => self.cmd_joiner(tokens).await,
            "commdataset" => self.cmd_comm_dataset(tokens).await,
            "opdataset" => self.cmd_op_dataset(tokens).await,
            "bbrdataset" => self.cmd_bbr_dataset(tokens).await,
            "reenroll" => self.cmd_managed(tokens, ManagedCommand::Reenroll).await,
            "domainreset" => self.cmd_managed(tokens, ManagedCommand::DomainReset).await,
            "migrate" => self.cmd_managed(tokens, ManagedCommand::Migrate).await,
            "mlr" => self.cmd_mlr(tokens).await,
            "announce" => self.cmd_announce(tokens).await,
            "panid" => self.cmd_panid(tokens).await,
            "energy" => self.cmd_energy(tokens).await,
            "netdiag" => self.cmd_netdiag(tokens).await,
            // Out-of-scope C++ CLI features, surfaced with their usage.
            "token" => CommandValue::failed("CCM token support is not implemented in this build"),
            "br" | "domain" | "network" => CommandValue::failed(
                "the persistent network registry is not implemented in this build",
            ),
            other => CommandValue::failed(format!(
                "'{other}' is not a valid command, type 'help' to list all commands"
            )),
        }
    }

    // --- session lifecycle ---

    fn cmd_state(&self) -> CommandValue {
        let state = match &self.commissioner {
            None => CommissionerState::Disabled,
            Some(c) => c.state(),
        };
        CommandValue::ok(match state {
            CommissionerState::Disabled => "disabled",
            CommissionerState::Connected => "connected",
            CommissionerState::Petitioning => "petitioning",
            CommissionerState::Active => "active",
        })
    }

    fn cmd_active(&self) -> CommandValue {
        let active = matches!(
            self.commissioner.as_ref().map(|c| c.state()),
            Some(CommissionerState::Active)
        );
        CommandValue::ok(if active { "true" } else { "false" })
    }

    fn cmd_sessionid(&self) -> CommandValue {
        match self.commissioner.as_ref().and_then(|c| c.session_id()) {
            Some(id) => CommandValue::ok(id.to_string()),
            None => CommandValue::failed("commissioner session is not active"),
        }
    }

    async fn cmd_start(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let connect_only = tokens.iter().any(|t| t == "--connect-only");
        let address = match format!("{}:{}", tokens[1], tokens[2]).parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                return CommandValue::failed(format!(
                    "invalid border-agent address '{}:{}'",
                    tokens[1], tokens[2]
                ));
            }
        };
        let config = match self.config.to_commissioner_config() {
            Ok(config) => config,
            Err(err) => return CommandValue::failed(err.to_string()),
        };
        let mut commissioner = match Commissioner::connect(config, address).await {
            Ok(c) => c,
            Err(err) => return CommandValue::failed(err.to_string()),
        };
        self.install_joiner_handler(&mut commissioner);
        // Petition unless `--connect-only`. A border agent that accepts the
        // petition echoes our own Commissioner ID back in the response; that is
        // not a conflict, so an accepted petition (`Ok`) is success. Only
        // `Error::PetitionRejected` — returned when a different commissioner is
        // already active — is a failure.
        let petition_result = if connect_only {
            Ok(())
        } else {
            commissioner.petition().await.map(|_| ())
        };
        // Keep the connected session regardless of the petition outcome so the
        // user can inspect `state` and `stop` to disconnect, as the C++ CLI does.
        self.commissioner = Some(commissioner);
        petition_result.into()
    }

    async fn cmd_stop(&mut self) -> CommandValue {
        match self.commissioner.as_mut() {
            Some(commissioner) => {
                let result = commissioner.resign().await;
                self.commissioner = None;
                result.into()
            }
            None => CommandValue::done(),
        }
    }

    fn cmd_config(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let property = tokens[2].as_str();
        if property != "pskc" && property != "admincode" {
            return CommandValue::failed(format!("{property} is not a valid property"));
        }
        match tokens[1].as_str() {
            "get" => {
                if property == "admincode" {
                    CommandValue::ok(self.config.admin_code.clone())
                } else {
                    CommandValue::ok(hex::encode(&self.config.pskc))
                }
            }
            "set" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                if property == "admincode" {
                    self.config.admin_code = tokens[3].clone();
                    self.config.pskc = tokens[3].as_bytes().to_vec();
                    CommandValue::done()
                } else {
                    match hex::decode(tokens[3].trim()) {
                        Ok(bytes) => {
                            self.config.pskc = bytes;
                            CommandValue::done()
                        }
                        Err(err) => CommandValue::failed(format!("invalid PSKc hex: {err}")),
                    }
                }
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    // --- border agent / joiner ---

    async fn cmd_border_agent(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        match tokens[1].as_str() {
            "discover" => {
                CommandValue::failed("mDNS border-agent discovery is not implemented in this build")
            }
            "get" => {
                if tokens.len() < 3 || tokens[2] != "locator" {
                    return CommandValue::failed("only 'borderagent get locator' is supported");
                }
                let Some(commissioner) = self.commissioner.as_mut() else {
                    return CommandValue::failed(NOT_CONNECTED);
                };
                match commissioner
                    .get_commissioner_dataset(CommissionerDatasetFlags::BORDER_AGENT_LOCATOR)
                    .await
                {
                    Ok(dataset) => match dataset.raw(crate::meshcop::TLV_BORDER_AGENT_LOCATOR) {
                        Some([hi, lo]) => {
                            CommandValue::ok(format!("0x{:04x}", u16::from_be_bytes([*hi, *lo])))
                        }
                        _ => CommandValue::failed("border agent locator not present"),
                    },
                    Err(err) => CommandValue::failed(err.to_string()),
                }
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    async fn cmd_joiner(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let subcommand = tokens[1].as_str();
        let joiner_type = tokens[2].as_str();
        if joiner_type == "ae" || joiner_type == "nmkp" {
            return CommandValue::failed(format!(
                "joiner type '{joiner_type}' (CCM) is not implemented in this build"
            ));
        }
        if joiner_type != "meshcop" {
            return CommandValue::failed(format!("{joiner_type} is not a valid joiner type"));
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match subcommand {
            "enable" => {
                if tokens.len() < 5 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(eui64) = parse_u64(&tokens[3]) else {
                    return CommandValue::failed(format!("invalid EUI-64 '{}'", tokens[3]));
                };
                let pskd = tokens[4].clone();
                let joiner_id = compute_joiner_id(eui64);
                if let Err(err) = commissioner.enable_joiner(&joiner_id).await {
                    return CommandValue::failed(err.to_string());
                }
                self.joiner_pskds.insert(joiner_id, pskd);
                self.reinstall_joiner_handler();
                CommandValue::done()
            }
            "enableall" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                if let Err(err) = commissioner.enable_all_joiners(true).await {
                    return CommandValue::failed(err.to_string());
                }
                self.joiner_all_pskd = Some(tokens[3].clone());
                self.reinstall_joiner_handler();
                CommandValue::done()
            }
            "disable" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(eui64) = parse_u64(&tokens[3]) else {
                    return CommandValue::failed(format!("invalid EUI-64 '{}'", tokens[3]));
                };
                self.joiner_pskds.remove(&compute_joiner_id(eui64));
                self.reinstall_joiner_handler();
                // Steering is rewritten from the remaining enabled joiners.
                CommandValue::done()
            }
            "disableall" => {
                let result = commissioner.enable_all_joiners(false).await;
                self.joiner_pskds.clear();
                self.joiner_all_pskd = None;
                self.reinstall_joiner_handler();
                result.into()
            }
            "getport" => match commissioner
                .get_commissioner_dataset(CommissionerDatasetFlags::JOINER_UDP_PORT)
                .await
            {
                Ok(dataset) => match dataset.raw(crate::meshcop::TLV_JOINER_UDP_PORT) {
                    Some([hi, lo]) => CommandValue::ok(u16::from_be_bytes([*hi, *lo]).to_string()),
                    _ => CommandValue::failed("joiner UDP port not present"),
                },
                Err(err) => CommandValue::failed(err.to_string()),
            },
            "setport" => {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(port) = tokens[3].parse::<u16>().ok() else {
                    return CommandValue::failed(format!("invalid port '{}'", tokens[3]));
                };
                let mut dataset = Dataset::default();
                dataset.set_raw(
                    crate::meshcop::TLV_JOINER_UDP_PORT,
                    port.to_be_bytes().to_vec(),
                );
                commissioner.set_commissioner_dataset(&dataset).await.into()
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    fn install_joiner_handler(&mut self, commissioner: &mut Commissioner) {
        let handler = self.build_joiner_handler();
        commissioner.set_joiner_handler(handler);
    }

    fn reinstall_joiner_handler(&mut self) {
        let handler = self.build_joiner_handler();
        if let Some(commissioner) = self.commissioner.as_mut() {
            commissioner.set_joiner_handler(handler);
        }
    }

    fn build_joiner_handler(&self) -> StaticJoinerHandler {
        let mut handler = StaticJoinerHandler::new();
        if let Some(pskd) = &self.joiner_all_pskd {
            handler.enable_all(pskd.clone());
        }
        for (id, pskd) in &self.joiner_pskds {
            handler.enable_joiner_id(*id, pskd.clone());
        }
        handler
    }

    // --- datasets ---

    async fn cmd_comm_dataset(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match tokens[1].as_str() {
            "get" => match commissioner
                .get_commissioner_dataset(CommissionerDatasetFlags::ALL)
                .await
            {
                Ok(dataset) => CommandValue::ok(json::dump(&json::comm_dataset_to_json(&dataset))),
                Err(err) => CommandValue::failed(err.to_string()),
            },
            "set" => {
                if tokens.len() < 3 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                match serde_json::from_str(&tokens[2])
                    .map_err(|e| e.to_string())
                    .and_then(|v| json::comm_dataset_from_json(&v).map_err(|e| e.to_string()))
                {
                    Ok(dataset) => commissioner.set_commissioner_dataset(&dataset).await.into(),
                    Err(message) => CommandValue::failed(message),
                }
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    async fn cmd_bbr_dataset(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match tokens[1].as_str() {
            "get" => match commissioner
                .get_bbr_dataset(CommissionerDatasetFlags::ALL)
                .await
            {
                Ok(dataset) => {
                    let map: serde_json::Map<String, serde_json::Value> = dataset
                        .entries()
                        .iter()
                        .map(|e| (format!("Tlv{}", e.ty), json!(hex::encode(&e.value))))
                        .collect();
                    CommandValue::ok(json::dump(&serde_json::Value::Object(map)))
                }
                Err(err) => CommandValue::failed(err.to_string()),
            },
            "set" => CommandValue::failed(
                "bbrdataset set requires typed BBR TLVs not yet modeled in this build",
            ),
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    async fn cmd_op_dataset(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let is_set = match tokens[1].as_str() {
            "get" => false,
            "set" => true,
            other => return CommandValue::failed(format!("{other} is not a valid sub-command")),
        };
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        let field = tokens[2].as_str();

        // Full active/pending dataset JSON.
        if field == "active" || field == "pending" {
            let pending = field == "pending";
            if is_set {
                if tokens.len() < 4 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let dataset = match serde_json::from_str(&tokens[3])
                    .map_err(|e| e.to_string())
                    .and_then(|v| {
                        json::op_dataset_from_json(&v, pending).map_err(|e| e.to_string())
                    }) {
                    Ok(dataset) => dataset,
                    Err(message) => return CommandValue::failed(message),
                };
                return if pending {
                    commissioner.set_pending_dataset(&dataset).await.into()
                } else {
                    commissioner.set_active_dataset(&dataset).await.into()
                };
            }
            let dataset = if pending {
                commissioner.get_pending_dataset(DatasetFlags::ALL).await
            } else {
                commissioner.get_active_dataset(DatasetFlags::ALL).await
            };
            return match dataset {
                Ok(dataset) => match json::op_dataset_to_json(&dataset, pending) {
                    Ok(value) => CommandValue::ok(json::dump(&value)),
                    Err(err) => CommandValue::failed(err.to_string()),
                },
                Err(err) => CommandValue::failed(err.to_string()),
            };
        }

        // Per-field get/set: the get reads the active dataset and projects one
        // field; the set issues an active/pending dataset update.
        if is_set {
            self.op_dataset_field_set(field, tokens).await
        } else {
            self.op_dataset_field_get(field).await
        }
    }

    async fn op_dataset_field_get(&mut self, field: &str) -> CommandValue {
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        let dataset = match commissioner.get_active_dataset(DatasetFlags::ALL).await {
            Ok(dataset) => dataset,
            Err(err) => return CommandValue::failed(err.to_string()),
        };
        let result = (|| -> crate::Result<Option<String>> {
            Ok(match field {
                "activetimestamp" => dataset
                    .active_timestamp()?
                    .map(|ts| json::dump(&json::timestamp_json(ts))),
                "channel" => dataset
                    .channel()?
                    .map(|c| json::dump(&json::channel_json(c))),
                "channelmask" => dataset
                    .channel_mask()?
                    .map(|m| json::dump(&json::channel_mask_json(&m))),
                "xpanid" => dataset.extended_pan_id()?.map(hex::encode),
                "meshlocalprefix" => dataset
                    .mesh_local_prefix()?
                    .map(json::mesh_local_prefix_string),
                "networkmasterkey" => dataset.network_key()?.map(hex::encode),
                "networkname" => dataset.network_name()?.map(str::to_string),
                "panid" => dataset.pan_id()?.map(|p| format!("0x{p:04x}")),
                "pskc" => dataset.pskc().map(hex::encode),
                "securitypolicy" => dataset
                    .security_policy()?
                    .map(|p| json::dump(&json::security_policy_json(p))),
                _ => return Ok(None),
            })
        })();
        match result {
            Ok(Some(value)) => CommandValue::ok(value),
            Ok(None) => {
                if is_known_op_field(field) {
                    CommandValue::failed(format!("{field} is not present in the active dataset"))
                } else {
                    CommandValue::failed(format!("{field} is not a valid property"))
                }
            }
            Err(err) => CommandValue::failed(err.to_string()),
        }
    }

    async fn op_dataset_field_set(&mut self, field: &str, tokens: &Tokens) -> CommandValue {
        // Build a minimal dataset carrying the one field (plus delay where the
        // C++ syntax includes it) and issue an active-dataset update.
        let mut dataset = Dataset::default();
        let set_result: std::result::Result<bool, String> = (|| {
            match field {
                "channel" => {
                    let page = parse_u64(tokens.get(3).map(String::as_str).unwrap_or(""))
                        .ok_or("invalid page")?;
                    let number = parse_u64(tokens.get(4).map(String::as_str).unwrap_or(""))
                        .ok_or("invalid channel")?;
                    dataset.set_raw(
                        crate::dataset::TLV_CHANNEL,
                        crate::dataset::Channel {
                            page: page as u8,
                            channel: number as u16,
                        }
                        .to_value()
                        .to_vec(),
                    );
                }
                "xpanid" => dataset.set_raw(
                    crate::dataset::TLV_EXTENDED_PAN_ID,
                    hex::decode(tokens.get(3).map(String::as_str).unwrap_or("").trim())
                        .map_err(|e| e.to_string())?,
                ),
                "networkmasterkey" => dataset.set_raw(
                    crate::dataset::TLV_NETWORK_KEY,
                    hex::decode(tokens.get(3).map(String::as_str).unwrap_or("").trim())
                        .map_err(|e| e.to_string())?,
                ),
                "networkname" => dataset.set_raw(
                    crate::dataset::TLV_NETWORK_NAME,
                    tokens
                        .get(3)
                        .map(String::as_str)
                        .unwrap_or("")
                        .as_bytes()
                        .to_vec(),
                ),
                "panid" => {
                    let panid = json::parse_panid(tokens.get(3).map(String::as_str).unwrap_or(""))
                        .map_err(|e| e.to_string())?;
                    dataset.set_raw(crate::dataset::TLV_PAN_ID, panid.to_be_bytes().to_vec());
                }
                "pskc" => dataset.set_raw(
                    crate::dataset::TLV_PSKC,
                    hex::decode(tokens.get(3).map(String::as_str).unwrap_or("").trim())
                        .map_err(|e| e.to_string())?,
                ),
                "meshlocalprefix" => dataset.set_raw(
                    crate::dataset::TLV_MESH_LOCAL_PREFIX,
                    json::parse_mesh_local_prefix(tokens.get(3).map(String::as_str).unwrap_or(""))
                        .map_err(|e| e.to_string())?
                        .to_vec(),
                ),
                "securitypolicy" => {
                    let rotation = tokens
                        .get(3)
                        .and_then(|t| t.parse::<u16>().ok())
                        .ok_or("invalid rotation time")?;
                    let flag_bytes =
                        hex::decode(tokens.get(4).map(String::as_str).unwrap_or("").trim())
                            .map_err(|e| e.to_string())?;
                    let flags = match flag_bytes.as_slice() {
                        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
                        [only] => u16::from(*only) << 8,
                        [] => return Err("flags must not be empty".to_string()),
                    };
                    dataset.set_raw(
                        crate::dataset::TLV_SECURITY_POLICY,
                        crate::dataset::SecurityPolicy {
                            rotation_time: rotation,
                            flags: crate::dataset::SecurityPolicyFlags::from_bits_retain(flags),
                        }
                        .to_value()
                        .to_vec(),
                    );
                }
                _ => return Ok(false),
            }
            Ok(true)
        })();
        match set_result {
            Ok(true) => {
                let Some(commissioner) = self.commissioner.as_mut() else {
                    return CommandValue::failed(NOT_CONNECTED);
                };
                // MGMT_ACTIVE_SET requires an Active Timestamp TLV newer than
                // the network's. Fetch the current timestamp and bump it, like
                // the C++ CommissionerApp does for per-field setters.
                let seconds = match commissioner
                    .get_active_dataset(DatasetFlags::ACTIVE_TIMESTAMP)
                    .await
                    .and_then(|current| current.active_timestamp())
                {
                    Ok(Some(ts)) => ts.seconds() + 1,
                    Ok(None) => 1,
                    Err(err) => return CommandValue::failed(err.to_string()),
                };
                dataset.set_raw(
                    crate::dataset::TLV_ACTIVE_TIMESTAMP,
                    crate::dataset::Timestamp::from_components(seconds, 0, false)
                        .to_value()
                        .to_vec(),
                );
                commissioner.set_active_dataset(&dataset).await.into()
            }
            Ok(false) => CommandValue::failed(format!("{field} cannot be set")),
            Err(message) => CommandValue::failed(message),
        }
    }

    // --- managed-device commands ---

    async fn cmd_managed(&mut self, tokens: &Tokens, command: ManagedCommand) -> CommandValue {
        let needed = if command == ManagedCommand::Migrate {
            3
        } else {
            2
        };
        if tokens.len() < needed {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(dst) = parse_addr(&tokens[1]) else {
            return CommandValue::failed(format!("invalid device address '{}'", tokens[1]));
        };
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match command {
            ManagedCommand::Reenroll => commissioner.command_reenroll(dst).await.into(),
            ManagedCommand::DomainReset => commissioner.command_domain_reset(dst).await.into(),
            ManagedCommand::Migrate => commissioner.command_migrate(dst, &tokens[2]).await.into(),
        }
    }

    async fn cmd_mlr(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let timeout = match tokens[tokens.len() - 1].parse::<u32>() {
            Ok(t) => t,
            Err(_) => return CommandValue::failed("invalid timeout"),
        };
        let addresses: Vec<String> = tokens[1..tokens.len() - 1].to_vec();
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match commissioner
            .register_multicast_listener(&addresses, timeout)
            .await
        {
            Ok(status) => CommandValue::ok(status.to_string()),
            Err(err) => CommandValue::failed(err.to_string()),
        }
    }

    async fn cmd_announce(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 5 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let (Some(mask), Some(count), Some(period), Some(dst)) = (
            parse_u32(&tokens[1]),
            tokens[2].parse::<u8>().ok(),
            tokens[3].parse::<u16>().ok(),
            parse_addr(&tokens[4]),
        ) else {
            return CommandValue::failed("invalid announce arguments");
        };
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        commissioner
            .announce_begin(mask, count, period, dst)
            .await
            .into()
    }

    async fn cmd_panid(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        match tokens[1].as_str() {
            "query" => {
                if tokens.len() < 5 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let (Some(mask), Some(panid), Some(dst)) = (
                    parse_u32(&tokens[2]),
                    json::parse_panid(&tokens[3]).ok(),
                    parse_addr(&tokens[4]),
                ) else {
                    return CommandValue::failed("invalid panid query arguments");
                };
                {
                    let Some(commissioner) = self.commissioner.as_mut() else {
                        return CommandValue::failed(NOT_CONNECTED);
                    };
                    if let Err(err) = commissioner.pan_id_query(mask, panid, dst).await {
                        return CommandValue::failed(err.to_string());
                    }
                }
                self.pump_events(Duration::from_secs(3)).await;
                CommandValue::done()
            }
            "conflict" => {
                if tokens.len() < 3 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let Some(panid) = json::parse_panid(&tokens[2]).ok() else {
                    return CommandValue::failed("invalid panid");
                };
                let reports: Vec<_> = self
                    .panid_conflicts
                    .iter()
                    .filter(|(_, _, p)| *p == panid)
                    .map(|(peer, mask, p)| {
                        json!({ "Peer": peer, "ChannelMask": format!("0x{mask:08x}"), "PanId": format!("0x{p:04x}") })
                    })
                    .collect();
                CommandValue::ok(json::dump(&serde_json::Value::Array(reports)))
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    async fn cmd_energy(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 2 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        match tokens[1].as_str() {
            "scan" => {
                if tokens.len() < 7 {
                    return CommandValue::failed(SYNTAX_FEW_ARGS);
                }
                let (Some(mask), Some(count), Some(period), Some(duration), Some(dst)) = (
                    parse_u32(&tokens[2]),
                    tokens[3].parse::<u8>().ok(),
                    tokens[4].parse::<u16>().ok(),
                    tokens[5].parse::<u16>().ok(),
                    parse_addr(&tokens[6]),
                ) else {
                    return CommandValue::failed("invalid energy scan arguments");
                };
                {
                    let Some(commissioner) = self.commissioner.as_mut() else {
                        return CommandValue::failed(NOT_CONNECTED);
                    };
                    if let Err(err) = commissioner
                        .energy_scan(mask, count, period, duration, dst)
                        .await
                    {
                        return CommandValue::failed(err.to_string());
                    }
                }
                self.pump_events(Duration::from_secs(3)).await;
                CommandValue::done()
            }
            "report" => {
                let filter = tokens
                    .get(2)
                    .and_then(|t| parse_addr(t))
                    .map(|a| a.to_string());
                let reports: Vec<_> = self
                    .energy_reports
                    .iter()
                    .filter(|(peer, _, _)| filter.as_ref().is_none_or(|f| f == peer))
                    .map(|(peer, mask, list)| {
                        json!({
                            "Peer": peer,
                            "ChannelMask": format!("0x{mask:08x}"),
                            "EnergyList": list.iter().map(|b| *b as i8 as i64).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                CommandValue::ok(json::dump(&serde_json::Value::Array(reports)))
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    async fn cmd_netdiag(&mut self, tokens: &Tokens) -> CommandValue {
        if tokens.len() < 3 {
            return CommandValue::failed(SYNTAX_FEW_ARGS);
        }
        let Some(commissioner) = self.commissioner.as_mut() else {
            return CommandValue::failed(NOT_CONNECTED);
        };
        match tokens[1].as_str() {
            "query" => {
                // netdiag query [extaddr|rloc16] <addr>
                let (flags, addr_token) = if tokens.len() >= 4 {
                    let flags = match tokens[2].as_str() {
                        "extaddr" => diag_flags::EXT_MAC_ADDR,
                        "rloc16" => diag_flags::MAC_ADDR,
                        other => {
                            return CommandValue::failed(format!("{other} is not a valid type"));
                        }
                    };
                    (flags, &tokens[3])
                } else {
                    (DEFAULT_NETDIAG_FLAGS, &tokens[2])
                };
                let Some(dst) = parse_addr(addr_token) else {
                    return CommandValue::failed(format!("invalid address '{addr_token}'"));
                };
                match commissioner.get_diagnostics(dst, flags).await {
                    Ok(data) => CommandValue::ok(json::dump(&net_diag_json(&data))),
                    Err(err) => CommandValue::failed(err.to_string()),
                }
            }
            "reset" => {
                if tokens.len() < 4 || tokens[2] != "maccounters" {
                    return CommandValue::failed(
                        "only 'netdiag reset maccounters <addr>' supported",
                    );
                }
                let Some(dst) = parse_addr(&tokens[3]) else {
                    return CommandValue::failed(format!("invalid address '{}'", tokens[3]));
                };
                commissioner
                    .diagnostic_reset(Some(dst), diag_flags::MAC_COUNTERS)
                    .await
                    .into()
            }
            other => CommandValue::failed(format!("{other} is not a valid sub-command")),
        }
    }

    // --- help ---

    fn cmd_help(&self, tokens: &Tokens) -> CommandValue {
        if tokens.len() == 1 {
            let mut names: Vec<&str> = COMMANDS.iter().map(|(name, _)| *name).collect();
            names.sort_unstable();
            let mut data = String::new();
            for name in names {
                data.push_str(name);
                data.push('\n');
            }
            data.push_str("\ntype 'help <command>' for help of specific command.");
            CommandValue::ok(data)
        } else {
            match COMMANDS.iter().find(|(name, _)| *name == tokens[1]) {
                Some((_, usage)) => CommandValue::ok(format!("usage:\n{usage}")),
                None => CommandValue::failed(format!("{} is not a valid command", tokens[1])),
            }
        }
    }

    /// Drains commissioner events for up to `duration`, storing energy reports
    /// and PAN-ID conflicts for the later `energy report` / `panid conflict`.
    async fn pump_events(&mut self, duration: Duration) {
        let Some(commissioner) = self.commissioner.as_mut() else {
            return;
        };
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, commissioner.next_event()).await {
                Ok(Ok(Some(event))) => match event {
                    CommissionerEvent::EnergyReport {
                        peer_addr,
                        channel_mask,
                        energy_list,
                    } => self
                        .energy_reports
                        .push((peer_addr, channel_mask, energy_list)),
                    CommissionerEvent::PanIdConflict {
                        peer_addr,
                        channel_mask,
                        pan_id,
                    } => self.panid_conflicts.push((peer_addr, channel_mask, pan_id)),
                    _ => {}
                },
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
            }
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ManagedCommand {
    Reenroll,
    DomainReset,
    Migrate,
}

const DEFAULT_NETDIAG_FLAGS: u64 = diag_flags::EXT_MAC_ADDR
    | diag_flags::MAC_ADDR
    | diag_flags::MODE
    | diag_flags::CONNECTIVITY
    | diag_flags::ROUTE64
    | diag_flags::LEADER_DATA;

fn is_known_op_field(field: &str) -> bool {
    matches!(
        field,
        "activetimestamp"
            | "channel"
            | "channelmask"
            | "xpanid"
            | "meshlocalprefix"
            | "networkmasterkey"
            | "networkname"
            | "panid"
            | "pskc"
            | "securitypolicy"
    )
}

/// Renders a [`NetDiagData`] answer as a compact JSON object.
fn net_diag_json(data: &NetDiagData) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(ext) = &data.ext_mac_addr {
        map.insert("ExtAddress".into(), json!(hex::encode(ext)));
    }
    if let Some(rloc) = data.mac_addr {
        map.insert("Rloc16".into(), json!(format!("0x{rloc:04x}")));
    }
    if let Some(leader) = &data.leader_data {
        map.insert(
            "LeaderData".into(),
            json!({ "PartitionId": leader.partition_id, "LeaderRouterId": leader.router_id }),
        );
    }
    if let Some(route) = &data.route64 {
        map.insert("Route64Routers".into(), json!(route.route_data.len()));
    }
    if let Some(addrs) = &data.addresses {
        map.insert(
            "Addresses".into(),
            json!(addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>()),
        );
    }
    serde_json::Value::Object(map)
}

fn parse_addr(s: &str) -> Option<Ipv6Addr> {
    s.trim().parse().ok()
}

fn parse_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn has_multi_network_flag(tokens: &Tokens) -> bool {
    tokens.iter().any(|t| t == "--nwk" || t == "--dom")
}

/// Splits a command line into tokens, honoring single/double-quoted spans
/// (used for JSON dataset arguments).
fn tokenize(line: &str) -> std::result::Result<Tokens, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    in_token = true;
                } else if ch.is_whitespace() {
                    if in_token {
                        tokens.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                } else {
                    current.push(ch);
                    in_token = true;
                }
            }
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted argument".to_string());
    }
    if in_token {
        tokens.push(current);
    }
    Ok(tokens)
}

/// The command table: name plus the verbatim C++ usage string, used by `help`.
const COMMANDS: &[(&str, &str)] = &[
    (
        "config",
        "config get admincode\nconfig set admincode <9-digits-thread-administrator-passcode>\nconfig get pskc\nconfig set pskc <pskc-hex-string>",
    ),
    (
        "start",
        "start <border-agent-addr> <border-agent-port> [--connect-only]\nstart [ --nwk <network-alias-list | --dom <domain-alias>]",
    ),
    (
        "stop",
        "stop\nstop [ --nwk <network-alias-list | --dom <domain-alias>]",
    ),
    (
        "active",
        "active\nactive [ --nwk <network-alias-list | --dom <domain-alias>]",
    ),
    (
        "token",
        "token request <registrar-addr> <registrar-port>\ntoken print\ntoken set <signed-token-hex-string-file>",
    ),
    (
        "br",
        "br list [--nwk <network-alias-list> | --dom <domain-name>]\nbr add <json-file-path>\nbr delete (<br-record-id> | --nwk <network-alias-list> | --dom <domain-name>)\nbr scan [--nwk <network-alias-list> | --dom <domain-name>] [--export <json-file-path>] [--timeout <ms>] [--netif <network-interface>]",
    ),
    ("domain", "domain list [--dom <domain-name>]"),
    (
        "network",
        "network save <network-data-file>\nnetwork sync\nnetwork list [--nwk <network-alias-list> | --dom <domain-name>]\nnetwork select <extended-pan-id>|<name>|<pan-id>|none\nnetwork identify",
    ),
    ("sessionid", "sessionid"),
    (
        "borderagent",
        "borderagent discover [<timeout-in-milliseconds>]\nborderagent get locator",
    ),
    (
        "joiner",
        "joiner enable (meshcop|ae|nmkp) <joiner-eui64> [<joiner-password>] [<provisioning-url>]\njoiner enableall (meshcop|ae|nmkp) [<joiner-password>] [<provisioning-url>]\njoiner disable (meshcop|ae|nmkp) <joiner-eui64>\njoiner disableall (meshcop|ae|nmkp)\njoiner getport (meshcop|ae|nmkp)\njoiner setport (meshcop|ae|nmkp) <joiner-udp-port>",
    ),
    (
        "commdataset",
        "commdataset get\ncommdataset set '<commissioner-dataset-in-json-string>'",
    ),
    (
        "opdataset",
        "opdataset get activetimestamp\nopdataset get channel\nopdataset set channel <page> <channel> <delay-in-milliseconds>\nopdataset get channelmask\nopdataset set channelmask (<page> <channel-mask>)...\nopdataset get xpanid\nopdataset set xpanid <extended-pan-id>\nopdataset get meshlocalprefix\nopdataset set meshlocalprefix <prefix> <delay-in-milliseconds>\nopdataset get networkmasterkey\nopdataset set networkmasterkey <network-master-key> <delay-in-milliseconds>\nopdataset get networkname\nopdataset set networkname <network-name>\nopdataset get panid\nopdataset set panid <panid> <delay-in-milliseconds>\nopdataset get pskc\nopdataset set pskc <PSKc>\nopdataset get securitypolicy\nopdataset set securitypolicy <rotation-timer> <flags-hex>\nopdataset get active\nopdataset set active '<active-dataset-in-json-string>'\nopdataset get pending\nopdataset set pending '<pending-dataset-in-json-string>'",
    ),
    (
        "bbrdataset",
        "bbrdataset get trihostname\nbbrdataset set trihostname <TRI-hostname>\nbbrdataset get reghostname\nbbrdataset set reghostname <registrar-hostname>\nbbrdataset get regaddr\nbbrdataset get\nbbrdataset set '<bbr-dataset-in-json-string>'",
    ),
    ("reenroll", "reenroll <device-addr>"),
    ("domainreset", "domainreset <device-addr>"),
    ("migrate", "migrate <device-addr> <designated-network-name>"),
    ("mlr", "mlr (<multicast-addr>)+ <timeout-in-seconds>"),
    (
        "announce",
        "announce <channel-mask> <count> <period> <dst-addr>",
    ),
    (
        "panid",
        "panid query <channel-mask> <panid> <dst-addr>\npanid conflict <panid>",
    ),
    (
        "energy",
        "energy scan <channel-mask> <count> <period> <scan-duration> <dst-addr>\nenergy report [<dst-addr>]",
    ),
    (
        "netdiag",
        "netdiag query [extaddr | rloc16] <dest mesh local address>\nnetdiag reset maccounters <dest mesh local address>",
    ),
    ("state", "state"),
    ("exit", "exit"),
    ("quit", "quit\n(an alias to 'exit' command)"),
    ("help", "help [<command>]"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioner::CommissionerConfig;
    use crate::commissioner::harness::{
        ScriptedExchange, ScriptedMeshcopTransport, ScriptedResponse,
    };
    use crate::meshcop::CommissionerOperation;

    /// Dispatches one offline command line (no border-agent session) and
    /// returns the rendered `[done]`/`[failed]` output.
    async fn dispatch_line(line: &str) -> String {
        let mut interpreter = Interpreter::new(CliConfig::default());
        let tokens = tokenize(line).unwrap();
        interpreter.dispatch(&tokens).await.rendered()
    }

    /// Dispatches one line on `interpreter` and returns the rendered output.
    async fn run_line(interpreter: &mut Interpreter, line: &str) -> String {
        interpreter
            .dispatch(&tokenize(line).unwrap())
            .await
            .rendered()
    }

    /// Builds an interpreter whose commissioner runs against the scripted
    /// MeshCoP harness, so session commands exercise the production
    /// request/response loop without a network.
    async fn scripted_interpreter(
        exchanges: impl IntoIterator<Item = (CommissionerOperation, Vec<ScriptedResponse>)>,
        initial_events: impl IntoIterator<Item = CommissionerEvent>,
    ) -> Interpreter {
        let script = ScriptedMeshcopTransport::new(
            exchanges
                .into_iter()
                .map(|(operation, responses)| ScriptedExchange::new(operation, responses)),
        );
        let mut commissioner = Commissioner::connect_scripted(
            CommissionerConfig::pskc("ot-commissioner-rs", [0x11; 16]),
            "127.0.0.1:49156".parse().unwrap(),
            script,
            initial_events,
        )
        .await
        .unwrap();
        commissioner.set_cached_mesh_local_prefix(Some([0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0]));
        let mut interpreter = Interpreter::new(CliConfig::default());
        interpreter.commissioner = Some(commissioner);
        interpreter
    }

    /// Like [`scripted_interpreter`], but petitions first so the session is
    /// `Active` — required by mutating and proxied operations.
    async fn active_interpreter(
        exchanges: impl IntoIterator<Item = (CommissionerOperation, Vec<ScriptedResponse>)>,
        initial_events: impl IntoIterator<Item = CommissionerEvent>,
    ) -> Interpreter {
        let mut all = vec![(
            CommissionerOperation::Petition,
            vec![ScriptedResponse::petition_accept(0xbeef)],
        )];
        all.extend(exchanges);
        let mut interpreter = scripted_interpreter(all, initial_events).await;
        interpreter
            .commissioner
            .as_mut()
            .unwrap()
            .petition()
            .await
            .unwrap();
        interpreter
    }

    /// An operational dataset carrying every field the per-field
    /// `opdataset get` projections support.
    fn full_dataset_bytes() -> Vec<u8> {
        let mut dataset = Dataset::default();
        dataset.set_raw(
            crate::dataset::TLV_ACTIVE_TIMESTAMP,
            (1u64 << 16).to_be_bytes().to_vec(),
        );
        dataset.set_raw(crate::dataset::TLV_CHANNEL, vec![0, 0, 19]);
        dataset.set_raw(
            crate::dataset::TLV_CHANNEL_MASK,
            vec![0, 4, 0x00, 0x1f, 0xff, 0xc0],
        );
        dataset.set_raw(
            crate::dataset::TLV_EXTENDED_PAN_ID,
            vec![0xa6, 0x39, 0x13, 0x57, 0xb4, 0x75, 0x1d, 0x8a],
        );
        dataset.set_raw(
            crate::dataset::TLV_MESH_LOCAL_PREFIX,
            vec![0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0],
        );
        dataset.set_raw(crate::dataset::TLV_NETWORK_KEY, vec![0x42; 16]);
        dataset.set_raw(crate::dataset::TLV_NETWORK_NAME, b"cli-net".to_vec());
        dataset.set_raw(crate::dataset::TLV_PAN_ID, 0xfaceu16.to_be_bytes().to_vec());
        dataset.set_raw(crate::dataset::TLV_PSKC, vec![0x24; 16]);
        dataset.set_raw(
            crate::dataset::TLV_SECURITY_POLICY,
            vec![0x02, 0xa0, 0xff, 0xf8],
        );
        dataset.to_bytes().unwrap()
    }

    fn ok(value: impl std::fmt::Display) -> String {
        format!("{value}\n[done]")
    }

    #[test]
    fn tokenize_honors_whitespace_and_quotes() {
        assert_eq!(tokenize("a b  c").unwrap(), ["a", "b", "c"]);
        assert_eq!(tokenize("set '{\"k\": 1}'").unwrap(), ["set", "{\"k\": 1}"]);
        assert_eq!(tokenize("x \"y z\"").unwrap(), ["x", "y z"]);
        assert!(tokenize("oops 'unterminated").is_err());
    }

    #[test]
    fn integer_parsers_accept_hex_and_decimal() {
        assert_eq!(parse_u32("0x10"), Some(16));
        assert_eq!(parse_u32("16"), Some(16));
        assert_eq!(parse_u64("0xFF"), Some(255));
        assert_eq!(parse_u32("nope"), None);
    }

    #[test]
    fn multi_network_flags_and_known_fields_are_detected() {
        assert!(has_multi_network_flag(&vec![
            "start".to_string(),
            "--nwk".to_string()
        ]));
        assert!(!has_multi_network_flag(&vec!["start".to_string()]));
        assert!(is_known_op_field("channel"));
        assert!(!is_known_op_field("bogus"));
    }

    #[tokio::test]
    async fn state_is_disabled_and_active_is_false_before_start() {
        assert_eq!(dispatch_line("state").await, "disabled\n[done]");
        assert_eq!(dispatch_line("active").await, "false\n[done]");
    }

    #[tokio::test]
    async fn invalid_command_reports_the_cpp_help_hint() {
        assert_eq!(
            dispatch_line("bogus").await,
            "'bogus' is not a valid command, type 'help' to list all commands\n[failed]"
        );
    }

    #[tokio::test]
    async fn session_commands_require_a_started_commissioner() {
        assert_eq!(
            dispatch_line("opdataset get active").await,
            format!("{NOT_CONNECTED}\n[failed]")
        );
        assert_eq!(
            dispatch_line("commdataset get").await,
            format!("{NOT_CONNECTED}\n[failed]")
        );
    }

    #[tokio::test]
    async fn out_of_scope_features_fail_with_an_explanation() {
        assert!(
            dispatch_line("token print")
                .await
                .contains("CCM token support is not implemented")
        );
        assert!(
            dispatch_line("br list")
                .await
                .contains("registry is not implemented")
        );
        assert!(
            dispatch_line("borderagent discover")
                .await
                .contains("mDNS border-agent discovery is not implemented")
        );
    }

    #[tokio::test]
    async fn help_lists_every_command_sorted_with_the_footer() {
        let out = dispatch_line("help").await;
        assert!(out.starts_with("active\nannounce\nbbrdataset\nborderagent\nbr\n"));
        assert!(out.contains("\ntype 'help <command>' for help of specific command.\n[done]"));
        // `help <command>` echoes the usage string.
        assert!(
            dispatch_line("help sessionid")
                .await
                .starts_with("usage:\nsessionid")
        );
        assert_eq!(
            dispatch_line("help nope").await,
            "nope is not a valid command\n[failed]"
        );
    }

    #[tokio::test]
    async fn config_set_then_get_pskc_round_trips() {
        let mut interpreter = Interpreter::new(CliConfig::default());
        let set = interpreter
            .dispatch(&tokenize("config set pskc 00112233445566778899aabbccddeeff").unwrap())
            .await;
        assert_eq!(set.rendered(), "[done]");
        let get = interpreter
            .dispatch(&tokenize("config get pskc").unwrap())
            .await;
        assert_eq!(get.rendered(), "00112233445566778899aabbccddeeff\n[done]");
    }

    #[tokio::test]
    async fn too_few_arguments_are_rejected() {
        assert_eq!(
            dispatch_line("config get").await,
            format!("{SYNTAX_FEW_ARGS}\n[failed]")
        );
        assert_eq!(
            dispatch_line("start 127.0.0.1").await,
            format!("{SYNTAX_FEW_ARGS}\n[failed]")
        );
    }

    #[tokio::test]
    async fn evaluate_and_print_handles_blank_bad_and_multi_network_lines() {
        let mut interpreter = Interpreter::new(CliConfig::default());
        // Blank input re-prompts, tokenizer errors and --nwk/--dom report
        // failure, and a normal command dispatches; all print to stdout.
        interpreter.evaluate_and_print("").await;
        interpreter.evaluate_and_print("bad 'quote").await;
        interpreter.evaluate_and_print("start --nwk net1").await;
        interpreter.evaluate_and_print("state").await;
        assert!(!interpreter.should_exit());
        interpreter.evaluate_and_print("exit").await;
        assert!(interpreter.should_exit());
    }

    #[tokio::test]
    async fn start_validates_address_and_config_before_any_network_use() {
        let mut interpreter = Interpreter::new(CliConfig::default());
        assert_eq!(
            run_line(&mut interpreter, "start nothost nope").await,
            "invalid border-agent address 'nothost:nope'\n[failed]"
        );
        // The default configuration has no PSKc, so start fails before
        // connecting anywhere.
        let no_pskc = run_line(&mut interpreter, "start 127.0.0.1 49191").await;
        assert!(no_pskc.ends_with("[failed]"), "{no_pskc}");
    }

    #[tokio::test]
    async fn start_connect_only_binds_without_petitioning() {
        let mut interpreter = Interpreter::new(CliConfig::default());
        let set = run_line(
            &mut interpreter,
            "config set pskc 00112233445566778899aabbccddeeff",
        )
        .await;
        assert_eq!(set, "[done]");
        // --connect-only binds the UDP socket but defers DTLS and petitioning,
        // so it succeeds without a border agent.
        assert_eq!(
            run_line(&mut interpreter, "start 127.0.0.1 49191 --connect-only").await,
            "[done]"
        );
        assert_eq!(run_line(&mut interpreter, "state").await, ok("connected"));
        assert_eq!(run_line(&mut interpreter, "active").await, ok("false"));
        assert_eq!(
            run_line(&mut interpreter, "sessionid").await,
            "commissioner session is not active\n[failed]"
        );
        // stop resigns; without an active session that fails fast (offline)
        // but still drops the session.
        let stopped = run_line(&mut interpreter, "stop").await;
        assert!(stopped.ends_with("[failed]"), "{stopped}");
        assert_eq!(run_line(&mut interpreter, "state").await, ok("disabled"));
        // stop with no session is a no-op success.
        assert_eq!(run_line(&mut interpreter, "stop").await, "[done]");
    }

    #[tokio::test]
    async fn scripted_session_reports_state_sessionid_and_stops() {
        let mut interpreter = scripted_interpreter(
            [
                (
                    CommissionerOperation::Petition,
                    vec![ScriptedResponse::petition_accept(0xbeef)],
                ),
                (
                    CommissionerOperation::KeepAlive,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        interpreter
            .commissioner
            .as_mut()
            .unwrap()
            .petition()
            .await
            .unwrap();
        assert_eq!(run_line(&mut interpreter, "state").await, ok("active"));
        assert_eq!(run_line(&mut interpreter, "active").await, ok("true"));
        assert_eq!(run_line(&mut interpreter, "sessionid").await, ok(0xbeefu16));
        assert_eq!(run_line(&mut interpreter, "stop").await, "[done]");
        assert_eq!(run_line(&mut interpreter, "state").await, ok("disabled"));
    }

    #[tokio::test]
    async fn borderagent_get_locator_renders_present_and_missing() {
        let mut interpreter = scripted_interpreter(
            [
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(vec![
                        crate::meshcop::TLV_BORDER_AGENT_LOCATOR,
                        2,
                        0x4c,
                        0x00,
                    ])],
                ),
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(Vec::new())],
                ),
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::reject()],
                ),
            ],
            [],
        )
        .await;
        assert_eq!(
            run_line(&mut interpreter, "borderagent get locator").await,
            ok("0x4c00")
        );
        assert_eq!(
            run_line(&mut interpreter, "borderagent get locator").await,
            "border agent locator not present\n[failed]"
        );
        let rejected = run_line(&mut interpreter, "borderagent get locator").await;
        assert!(rejected.ends_with("[failed]"), "{rejected}");
        // Argument validation happens before any exchange.
        assert_eq!(
            run_line(&mut interpreter, "borderagent get oops").await,
            "only 'borderagent get locator' is supported\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "borderagent bogus")
                .await
                .contains("is not a valid sub-command")
        );
    }

    #[tokio::test]
    async fn joiner_commands_drive_steering_and_port_exchanges() {
        let mut interpreter = active_interpreter(
            [
                // enable -> read current steering data, then set the updated one
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(Vec::new())],
                ),
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
                // enableall -> wildcard steering set
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
                // disableall -> cleared steering set
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
                // getport
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(vec![
                        crate::meshcop::TLV_JOINER_UDP_PORT,
                        2,
                        0x03,
                        0xea,
                    ])],
                ),
                // setport
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        assert_eq!(
            run_line(
                &mut interpreter,
                "joiner enable meshcop 0xdead00beef00cafe J01ABC"
            )
            .await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner enableall meshcop PSKDALL").await,
            "[done]"
        );
        // disable only rewrites local state; no exchange.
        assert_eq!(
            run_line(
                &mut interpreter,
                "joiner disable meshcop 0xdead00beef00cafe"
            )
            .await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner disableall meshcop").await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner getport meshcop").await,
            ok(1002)
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner setport meshcop 1002").await,
            "[done]"
        );
        // Validation failures need no exchanges.
        assert!(
            run_line(&mut interpreter, "joiner enable ae 0x1 PSKD")
                .await
                .contains("(CCM) is not implemented")
        );
        assert!(
            run_line(&mut interpreter, "joiner enable zigbee 0x1 PSKD")
                .await
                .contains("is not a valid joiner type")
        );
        assert!(
            run_line(&mut interpreter, "joiner enable meshcop noteui PSKD")
                .await
                .contains("invalid EUI-64")
        );
        assert!(
            run_line(&mut interpreter, "joiner setport meshcop 70000")
                .await
                .contains("invalid port")
        );
        assert!(
            run_line(&mut interpreter, "joiner bogus meshcop")
                .await
                .contains("is not a valid sub-command")
        );
    }

    #[tokio::test]
    async fn commdataset_get_and_set_round_trip_json() {
        let mut comm_dataset = Dataset::default();
        comm_dataset.set_raw(
            crate::meshcop::TLV_BORDER_AGENT_LOCATOR,
            0x1234u16.to_be_bytes().to_vec(),
        );
        comm_dataset.set_raw(crate::meshcop::TLV_STEERING_DATA, vec![0xff]);
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(comm_dataset.to_bytes().unwrap())],
                ),
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        let got = run_line(&mut interpreter, "commdataset get").await;
        assert!(got.contains("\"BorderAgentLocator\": 4660"), "{got}");
        assert!(got.contains("\"SteeringData\": \"ff\""), "{got}");
        assert_eq!(
            run_line(
                &mut interpreter,
                "commdataset set '{\"SteeringData\":\"ff\",\"JoinerUdpPort\":1000}'"
            )
            .await,
            "[done]"
        );
        let bad = run_line(&mut interpreter, "commdataset set notjson").await;
        assert!(bad.ends_with("[failed]"), "{bad}");
        assert!(
            run_line(&mut interpreter, "commdataset bogus")
                .await
                .contains("is not a valid sub-command")
        );
    }

    #[tokio::test]
    async fn bbrdataset_get_renders_raw_tlvs() {
        let mut interpreter = scripted_interpreter(
            [(
                CommissionerOperation::GetBbrDataset,
                vec![ScriptedResponse::content(vec![1, 2, 0xab, 0xcd])],
            )],
            [],
        )
        .await;
        let got = run_line(&mut interpreter, "bbrdataset get").await;
        assert!(got.contains("\"Tlv1\": \"abcd\""), "{got}");
        assert!(
            run_line(&mut interpreter, "bbrdataset set")
                .await
                .contains("not yet modeled")
        );
        assert!(
            run_line(&mut interpreter, "bbrdataset bogus")
                .await
                .contains("is not a valid sub-command")
        );
    }

    #[tokio::test]
    async fn opdataset_get_projects_every_field_like_the_cpp_cli() {
        let full = full_dataset_bytes();
        let mut pending_dataset = Dataset::default();
        pending_dataset.set_raw(crate::dataset::TLV_NETWORK_NAME, b"cli-net".to_vec());
        pending_dataset.set_raw(
            crate::dataset::TLV_PENDING_TIMESTAMP,
            (2u64 << 16).to_be_bytes().to_vec(),
        );
        pending_dataset.set_raw(
            crate::dataset::TLV_DELAY_TIMER,
            60000u32.to_be_bytes().to_vec(),
        );
        let minimal = {
            let mut d = Dataset::default();
            d.set_raw(crate::dataset::TLV_NETWORK_NAME, b"min".to_vec());
            d.to_bytes().unwrap()
        };

        let mut exchanges: Vec<(CommissionerOperation, Vec<ScriptedResponse>)> = (0..12)
            .map(|_| {
                (
                    CommissionerOperation::GetActiveDataset,
                    vec![ScriptedResponse::content(full.clone())],
                )
            })
            .collect();
        exchanges.push((
            CommissionerOperation::GetPendingDataset,
            vec![ScriptedResponse::content(
                pending_dataset.to_bytes().unwrap(),
            )],
        ));
        exchanges.push((
            CommissionerOperation::GetActiveDataset,
            vec![ScriptedResponse::content(minimal)],
        ));
        let mut interpreter = scripted_interpreter(exchanges, []).await;

        let active = run_line(&mut interpreter, "opdataset get active").await;
        for key in [
            "ActiveTimestamp",
            "Channel",
            "ChannelMask",
            "ExtendedPanId",
            "MeshLocalPrefix",
            "NetworkMasterKey",
            "NetworkName",
            "PanId",
            "PSKc",
            "SecurityPolicy",
        ] {
            assert!(active.contains(key), "missing {key} in {active}");
        }

        let expect_json = |value: &serde_json::Value| ok(json::dump(value));
        assert_eq!(
            run_line(&mut interpreter, "opdataset get activetimestamp").await,
            expect_json(&json!({ "Seconds": 1, "Ticks": 0, "U": 0 }))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get channel").await,
            expect_json(&json!({ "Page": 0, "Number": 19 }))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get channelmask").await,
            expect_json(&json!([{ "Page": 0, "Masks": "001fffc0" }]))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get xpanid").await,
            ok("a6391357b4751d8a")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get meshlocalprefix").await,
            ok("fd00:db8::/64")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get networkmasterkey").await,
            ok("42".repeat(16))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get networkname").await,
            ok("cli-net")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get panid").await,
            ok("0xface")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get pskc").await,
            ok("24".repeat(16))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get securitypolicy").await,
            expect_json(&json!({ "RotationTime": 672, "Flags": "fff8" }))
        );
        // Unknown fields still fetch the dataset first, then report.
        assert_eq!(
            run_line(&mut interpreter, "opdataset get bogus").await,
            "bogus is not a valid property\n[failed]"
        );
        let pending = run_line(&mut interpreter, "opdataset get pending").await;
        assert!(pending.contains("PendingTimestamp"), "{pending}");
        assert!(pending.contains("\"Delay\": 60000"), "{pending}");
        assert_eq!(
            run_line(&mut interpreter, "opdataset get pskc").await,
            "pskc is not present in the active dataset\n[failed]"
        );
    }

    #[tokio::test]
    async fn opdataset_set_builds_field_and_json_updates() {
        // Each per-field set first fetches the current Active Timestamp (to
        // bump it) and then issues the MGMT_ACTIVE_SET.
        let mut with_timestamp = Dataset::default();
        with_timestamp.set_raw(
            crate::dataset::TLV_ACTIVE_TIMESTAMP,
            (7u64 << 16).to_be_bytes().to_vec(),
        );
        let timestamp_bytes = with_timestamp.to_bytes().unwrap();
        let mut exchanges: Vec<(CommissionerOperation, Vec<ScriptedResponse>)> = Vec::new();
        for index in 0..8 {
            // One get answers without a timestamp to cover the
            // first-ever-update fallback.
            let get_payload = if index == 7 {
                Vec::new()
            } else {
                timestamp_bytes.clone()
            };
            exchanges.push((
                CommissionerOperation::GetActiveDataset,
                vec![ScriptedResponse::content(get_payload)],
            ));
            exchanges.push((
                CommissionerOperation::SetActiveDataset,
                vec![ScriptedResponse::accept()],
            ));
        }
        // The full-JSON forms send the user's dataset as-is (no bump).
        exchanges.push((
            CommissionerOperation::SetActiveDataset,
            vec![ScriptedResponse::accept()],
        ));
        exchanges.push((
            CommissionerOperation::SetPendingDataset,
            vec![ScriptedResponse::accept()],
        ));
        let mut interpreter = active_interpreter(exchanges, []).await;

        for line in [
            "opdataset set channel 0 19",
            "opdataset set xpanid a6391357b4751d8a",
            "opdataset set networkmasterkey 00112233445566778899aabbccddeeff",
            "opdataset set networkname new-name",
            "opdataset set panid 0xface",
            "opdataset set pskc 00112233445566778899aabbccddeeff",
            "opdataset set meshlocalprefix fd00:db8::/64",
            "opdataset set securitypolicy 672 fff8",
            "opdataset set active '{\"ActiveTimestamp\":{\"Seconds\":8,\"Ticks\":0,\"U\":0},\"NetworkName\":\"json-net\"}'",
            "opdataset set pending '{\"ActiveTimestamp\":{\"Seconds\":8,\"Ticks\":0,\"U\":0},\"PendingTimestamp\":{\"Seconds\":9,\"Ticks\":0,\"U\":0},\"Delay\":60000,\"NetworkName\":\"json-pend\"}'",
        ] {
            assert_eq!(run_line(&mut interpreter, line).await, "[done]", "{line}");
        }

        // Validation failures consume no exchanges.
        assert_eq!(
            run_line(&mut interpreter, "opdataset set bogusfield v").await,
            "bogusfield cannot be set\n[failed]"
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset set channel zero nineteen").await,
            "invalid page\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "opdataset set xpanid zz")
                .await
                .ends_with("[failed]")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset set securitypolicy notnum fff8").await,
            "invalid rotation time\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "opdataset set securitypolicy 672")
                .await
                .contains("flags must not be empty")
        );
        assert!(
            run_line(&mut interpreter, "opdataset bogus active")
                .await
                .contains("is not a valid sub-command")
        );
        let bad_json = run_line(&mut interpreter, "opdataset set active notjson").await;
        assert!(bad_json.ends_with("[failed]"), "{bad_json}");
    }

    #[tokio::test]
    async fn managed_commands_mlr_and_announce_route_through_the_proxy() {
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::Reenroll,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::DomainReset,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::Migrate,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::RegisterMulticastListener,
                    vec![ScriptedResponse::content(vec![
                        crate::meshcop::THREAD_TLV_STATUS,
                        1,
                        0,
                    ])],
                ),
                (
                    CommissionerOperation::AnnounceBegin,
                    vec![ScriptedResponse::changed_without_state()],
                ),
            ],
            [],
        )
        .await;
        assert_eq!(
            run_line(&mut interpreter, "reenroll fd00::1").await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "domainreset fd00::1").await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "migrate fd00::1 target-net").await,
            "[done]"
        );
        assert_eq!(run_line(&mut interpreter, "mlr ff05::1 300").await, ok(0));
        assert_eq!(
            run_line(&mut interpreter, "announce 0x7fff800 2 100 fd00::1").await,
            "[done]"
        );
        // Argument validation happens before any exchange.
        assert!(
            run_line(&mut interpreter, "reenroll notaddr")
                .await
                .contains("invalid device address")
        );
        assert_eq!(
            run_line(&mut interpreter, "mlr ff05::1 forever").await,
            "invalid timeout\n[failed]"
        );
        assert_eq!(
            run_line(&mut interpreter, "announce nope 2 100 fd00::1").await,
            "invalid announce arguments\n[failed]"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn panid_query_and_energy_scan_collect_reports() {
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::PanIdQuery,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::EnergyScan,
                    vec![ScriptedResponse::changed_without_state()],
                ),
            ],
            [
                CommissionerEvent::PanIdConflict {
                    peer_addr: "fd00::9".to_string(),
                    channel_mask: 0x07fff800,
                    pan_id: 0xface,
                },
                CommissionerEvent::EnergyReport {
                    peer_addr: "fd00::9".to_string(),
                    channel_mask: 0x07fff800,
                    energy_list: vec![0x9c, 0x80],
                },
            ],
        )
        .await;
        assert_eq!(
            run_line(&mut interpreter, "panid query 0x7fff800 0xface fd00::1").await,
            "[done]"
        );
        let conflicts = run_line(&mut interpreter, "panid conflict 0xface").await;
        assert!(conflicts.contains("\"Peer\": \"fd00::9\""), "{conflicts}");
        assert!(conflicts.contains("\"PanId\": \"0xface\""), "{conflicts}");
        assert_eq!(
            run_line(&mut interpreter, "panid conflict 0xbeef").await,
            ok("[]")
        );
        assert_eq!(
            run_line(&mut interpreter, "energy scan 0x7fff800 2 100 50 fd00::1").await,
            "[done]"
        );
        let reports = run_line(&mut interpreter, "energy report").await;
        assert!(reports.contains("\"Peer\": \"fd00::9\""), "{reports}");
        assert!(reports.contains("-100"), "{reports}");
        assert!(
            run_line(&mut interpreter, "energy report fd00::9")
                .await
                .contains("fd00::9")
        );
        assert_eq!(
            run_line(&mut interpreter, "energy report fd00::8").await,
            ok("[]")
        );
        // Invalid arguments and sub-commands.
        assert_eq!(
            run_line(&mut interpreter, "panid query nope 0xface fd00::1").await,
            "invalid panid query arguments\n[failed]"
        );
        assert_eq!(
            run_line(&mut interpreter, "panid conflict nope").await,
            "invalid panid\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "panid bogus x")
                .await
                .contains("is not a valid sub-command")
        );
        assert_eq!(
            run_line(&mut interpreter, "energy scan nope 2 100 50 fd00::1").await,
            "invalid energy scan arguments\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "energy bogus")
                .await
                .contains("is not a valid sub-command")
        );
    }

    #[tokio::test]
    async fn netdiag_query_and_reset_render_diagnostics() {
        // MAC Address (1) = 0x8000 and Leader Data (6); then an Ext MAC
        // Address (0) answer; then a reset.
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::DiagnosticGetUnicast,
                    vec![ScriptedResponse::content(vec![
                        1, 2, 0x80, 0x00, 6, 8, 0, 0, 0, 1, 64, 10, 9, 5,
                    ])],
                ),
                (
                    CommissionerOperation::DiagnosticGetUnicast,
                    vec![ScriptedResponse::content(vec![
                        0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    ])],
                ),
                (
                    CommissionerOperation::DiagnosticReset,
                    vec![ScriptedResponse::changed_without_state()],
                ),
            ],
            [],
        )
        .await;
        let queried = run_line(&mut interpreter, "netdiag query fd00::1").await;
        assert!(queried.contains("\"Rloc16\": \"0x8000\""), "{queried}");
        assert!(queried.contains("LeaderData"), "{queried}");
        let ext = run_line(&mut interpreter, "netdiag query extaddr fd00::1").await;
        assert!(
            ext.contains("\"ExtAddress\": \"1122334455667788\""),
            "{ext}"
        );
        assert_eq!(
            run_line(&mut interpreter, "netdiag reset maccounters fd00::1").await,
            "[done]"
        );
        // Validation failures need no exchanges.
        assert!(
            run_line(&mut interpreter, "netdiag query bogus fd00::1")
                .await
                .contains("is not a valid type")
        );
        assert!(
            run_line(&mut interpreter, "netdiag query notaddr")
                .await
                .contains("invalid address")
        );
        assert!(
            run_line(&mut interpreter, "netdiag reset other fd00::1")
                .await
                .contains("only 'netdiag reset maccounters <addr>' supported")
        );
        assert!(
            run_line(&mut interpreter, "netdiag bogus fd00::1")
                .await
                .contains("is not a valid sub-command")
        );
    }

    #[tokio::test]
    async fn protocol_errors_surface_as_failed_output() {
        // A 4.04-coded response fails the exchange and the CLI reports it.
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::GetActiveDataset,
                    vec![ScriptedResponse::Coded {
                        code: crate::meshcop::CoapCode(0x84),
                        payload: Vec::new(),
                    }],
                ),
                (
                    CommissionerOperation::SetActiveDataset,
                    vec![ScriptedResponse::reject()],
                ),
            ],
            [],
        )
        .await;
        let active = run_line(&mut interpreter, "opdataset get active").await;
        assert!(active.ends_with("[failed]"), "{active}");
        // A State=Reject answer to a set surfaces as a rejection.
        let set = run_line(
            &mut interpreter,
            "opdataset set active '{\"ActiveTimestamp\":{\"Seconds\":8,\"Ticks\":0,\"U\":0}}'",
        )
        .await;
        assert!(set.contains("rejected"), "{set}");
        assert!(set.ends_with("[failed]"), "{set}");
    }
}
