//! Live interop test against a real OpenThread border agent.
//!
//! `tools/ci/interop.sh` builds OpenThread (a posix `ot-daemon` border router
//! driven by a simulated RCP), forms a Thread network, and runs this test
//! against the daemon's border agent over loopback. The script provides:
//!
//! - `OT_COMMISSIONER_INTEROP_BORDER_AGENT` — `host:port` of the live agent.
//! - `OT_COMMISSIONER_INTEROP_DATASET_HEX` — the active dataset reported by
//!   `ot-ctl dataset active -x`, including the PSKc used to authenticate.
//!
//! The dataset for this network is disposable CI test data (the fixed vectors
//! from the C++ `ot-commissioner` integration suite), but the test still never
//! prints TLV values on failure — only types and lengths — so it stays safe to
//! run against a private network by hand.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use ot_commissioner_rs::{
    commissioner::{
        Commissioner, CommissionerConfig, CommissionerDatasetFlags, DatasetFlags, ResultCode,
    },
    dataset::Dataset,
    error::Error,
    meshcop::{TLV_BORDER_AGENT_LOCATOR, TLV_COMMISSIONER_SESSION_ID},
};

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_commissioner_session_against_openthread() -> ot_commissioner_rs::Result<()> {
    let border_agent: SocketAddr = std::env::var("OT_COMMISSIONER_INTEROP_BORDER_AGENT")
        .expect("OT_COMMISSIONER_INTEROP_BORDER_AGENT must be host:port")
        .parse()
        .expect("OT_COMMISSIONER_INTEROP_BORDER_AGENT must parse as a socket address");
    let dataset_hex = std::env::var("OT_COMMISSIONER_INTEROP_DATASET_HEX")
        .expect("OT_COMMISSIONER_INTEROP_DATASET_HEX must contain the active dataset with PSKc");

    let expected = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("ot-commissioner-rs-interop", &expected)?;

    // DTLS 1.2 + EC J-PAKE handshake authenticated with the network PSKc.
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    // COMM_PET.req: become the active commissioner.
    let petition = commissioner.petition().await?;
    assert_ne!(petition.session_id, 0, "petition returned session id 0");

    // Run the session body without `?` so the commissioner always resigns,
    // leaving the agent free for the next run even when an assertion fails.
    let session = exercise_session(&mut commissioner, &expected).await;
    let resign = commissioner.resign().await;
    session?;
    resign
}

async fn exercise_session(
    commissioner: &mut Commissioner,
    expected: &Dataset,
) -> ot_commissioner_rs::Result<()> {
    // COMM_KA.req on the established session.
    assert_eq!(
        commissioner.keep_alive().await?,
        ResultCode::Accept,
        "keep-alive was rejected"
    );

    // MGMT_ACTIVE_GET.req directly to the border agent: the live network's
    // dataset must match what ot-ctl reported, independent of TLV order.
    let live = Dataset::from_bytes(
        &commissioner
            .get_raw_active_dataset(DatasetFlags::EMPTY)
            .await?,
    )?;
    assert_datasets_equivalent(expected, &live)?;

    // MGMT_COMMISSIONER_GET.req: routed through the UDP_TX/UDP_RX proxy to
    // the leader ALOC, which exercises the mesh-local-prefix fetch and the
    // encapsulation path against a real leader.
    let commissioner_dataset = commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::EMPTY)
        .await?;
    for (name, ty) in [
        ("Border Agent Locator", TLV_BORDER_AGENT_LOCATOR),
        ("Commissioner Session ID", TLV_COMMISSIONER_SESSION_ID),
    ] {
        assert!(
            commissioner_dataset
                .entries()
                .iter()
                .any(|entry| entry.ty == ty),
            "commissioner dataset is missing the {name} TLV"
        );
    }
    Ok(())
}

/// Compares two datasets as unordered TLV sets, reporting only TLV types and
/// lengths on mismatch so dataset values never reach the logs.
fn assert_datasets_equivalent(
    expected: &Dataset,
    live: &Dataset,
) -> ot_commissioner_rs::Result<()> {
    let canonical = |dataset: &Dataset| -> BTreeSet<(u8, Vec<u8>)> {
        dataset
            .entries()
            .iter()
            .map(|entry| (entry.ty, entry.value.to_vec()))
            .collect()
    };
    if canonical(expected) != canonical(live) {
        return Err(Error::Dataset(format!(
            "active dataset mismatch: expected {}, live {}",
            dataset_summary(expected),
            dataset_summary(live)
        )));
    }
    Ok(())
}

fn dataset_summary(dataset: &Dataset) -> String {
    let type_lengths = dataset
        .entries()
        .iter()
        .map(|entry| format!("0x{:02x}:{}", entry.ty, entry.value.len()))
        .collect::<Vec<_>>()
        .join(",");
    format!("tlvs=[{type_lengths}]")
}
