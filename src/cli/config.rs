//! Commissioner configuration loaded from the JSON config file, matching the
//! C++ `ot-commissioner` config schema (`Id`, `PSKc`, `EnableCcm`, ...).

use std::path::Path;

use serde::Deserialize;

use crate::{
    commissioner::CommissionerConfig,
    error::{Error, Result},
};

/// The subset of the C++ config file this build understands. CCM credential
/// paths are accepted but unused (non-CCM only).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigFile {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "DomainName")]
    domain_name: Option<String>,
    #[serde(rename = "EnableCcm")]
    enable_ccm: bool,
    #[serde(rename = "KeepAliveInterval")]
    keep_alive_interval: Option<u64>,
    #[serde(rename = "PSKc")]
    pskc: Option<String>,
}

/// Runtime commissioner configuration held by the interpreter. The PSKc is
/// mutable through the `config set` command.
#[derive(Debug, Clone)]
pub struct CliConfig {
    /// Human-readable commissioner ID.
    pub id: String,
    /// Domain name (informational in non-CCM mode).
    pub domain_name: String,
    /// Whether CCM mode was requested (unsupported; surfaced as an error).
    pub enable_ccm: bool,
    /// Keep-alive interval in seconds.
    pub keep_alive_interval: u64,
    /// The PSKc used to authenticate to the border agent.
    pub pskc: Vec<u8>,
    /// The Thread administrator passcode set via `config set admincode`.
    pub admin_code: String,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            id: "OT-commissioner".to_string(),
            domain_name: "Thread".to_string(),
            enable_ccm: false,
            keep_alive_interval: 40,
            pskc: Vec::new(),
            admin_code: String::new(),
        }
    }
}

impl CliConfig {
    /// Loads the configuration from a JSON file (C-style comments allowed).
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|err| Error::Dataset(format!("cannot read config file: {err}")))?;
        let cleaned = strip_json_comments(&raw);
        let file: ConfigFile = serde_json::from_str(&cleaned)
            .map_err(|err| Error::Dataset(format!("invalid config file: {err}")))?;

        let mut config = CliConfig::default();
        if let Some(id) = file.id {
            config.id = id;
        }
        if let Some(domain) = file.domain_name {
            config.domain_name = domain;
        }
        config.enable_ccm = file.enable_ccm;
        if let Some(interval) = file.keep_alive_interval {
            config.keep_alive_interval = interval;
        }
        if let Some(pskc_hex) = file.pskc {
            config.pskc = hex::decode(pskc_hex.trim())
                .map_err(|err| Error::Dataset(format!("invalid PSKc hex: {err}")))?;
        }
        Ok(config)
    }

    /// Builds a [`CommissionerConfig`] for connecting to a border agent.
    pub fn to_commissioner_config(&self) -> Result<CommissionerConfig> {
        let pskc: [u8; 16] = self.pskc.clone().try_into().map_err(|_| {
            Error::Dataset(
                "PSKc must be exactly 16 bytes; set it with 'config set pskc'".to_string(),
            )
        })?;
        Ok(CommissionerConfig::pskc(self.id.clone(), pskc))
    }
}

/// Removes `//` line comments and `/* */` block comments, leaving string
/// literals untouched, so a commented config file parses as JSON.
fn strip_json_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match (b, bytes.get(i + 1)) {
            (b'"', _) => {
                in_string = true;
                out.push('"');
                i += 1;
            }
            (b'/', Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_line_and_block_comments_but_preserves_strings() {
        let input = r#"{
            // a line comment
            "Id": "x", /* a block comment */ "PSKc": "00",
            "Url": "http://example.com/a" // slashes inside strings survive
        }"#;
        let cleaned = strip_json_comments(input);
        assert!(!cleaned.contains("line comment"));
        assert!(!cleaned.contains("block comment"));
        assert!(cleaned.contains("http://example.com/a"));
        // The result must still parse as JSON.
        let parsed: serde_json::Value = serde_json::from_str(&cleaned).unwrap();
        assert_eq!(parsed["Id"], "x");
    }

    #[test]
    fn load_parses_fields_and_hex_pskc_with_comments() {
        let path = std::env::temp_dir().join(format!("otcli-cfg-{}.json", std::process::id()));
        std::fs::write(
            &path,
            "{ /* test */ \"Id\": \"my-comm\", \"KeepAliveInterval\": 17, \
             \"PSKc\": \"00112233445566778899aabbccddeeff\" }",
        )
        .unwrap();
        let config = CliConfig::load(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(config.id, "my-comm");
        assert_eq!(config.keep_alive_interval, 17);
        assert_eq!(config.pskc.len(), 16);
    }

    #[test]
    fn to_commissioner_config_requires_a_16_byte_pskc() {
        let mut config = CliConfig::default();
        assert!(config.to_commissioner_config().is_err(), "empty PSKc");
        config.pskc = vec![0u8; 8];
        assert!(config.to_commissioner_config().is_err(), "short PSKc");
        config.pskc = vec![0u8; 16];
        assert!(config.to_commissioner_config().is_ok(), "16-byte PSKc");
    }
}
