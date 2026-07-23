//! Thread MeshCoP DTLS 1.2 profile.
//!
//! This crate implements the DTLS 1.2 handshake and record-protection profile
//! that Thread commissioner sessions use: EC J-PAKE authentication over the
//! commissioner PSKc (and the joiner PSKd), the TLS 1.2 PRF key schedule, and
//! AES-128-CCM-8 record protection. It exposes runtime-neutral client and
//! server handshake state machines plus a Tokio-backed session driver
//! ([`DtlsSession`]): the state machines frame and consume individual
//! handshake messages while the driver owns the socket and record I/O.
//!
//! The EC J-PAKE party and Schnorr NIZK primitives live in the public
//! [`ecjpake`] module. The `test-support` feature exposes an in-process
//! loopback DTLS server used by this workspace's deterministic handshake
//! tests; it is unstable scaffolding, not a supported public API.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

mod ccm;
mod constants;
pub mod ecjpake;
mod error;
mod handshake;
mod hello;
mod key_schedule;
mod record;
mod record_protection;
mod session;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod thread_handshake;
mod thread_server_handshake;
mod util;

pub use ccm::{
    AesCcm8, RecordProtectionKey, TLS_CCM_8_TAG_LEN, TLS_CCM_EXPLICIT_NONCE_LEN,
    TLS_CCM_FIXED_IV_LEN, TLS_CCM_NONCE_LEN, dtls_ccm_nonce,
};
pub use constants::*;
pub use error::{Error, Result};
pub use handshake::{
    FinishedRole, HandshakeFragment, HandshakeHeader, HandshakeMessage, HandshakeReassembler,
    HandshakeTranscript, HandshakeType, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record,
};
pub use hello::{ClientHello, DtlsClientHelloState, HelloVerifyRequest, ServerHello, TlsExtension};
pub use key_schedule::{
    ThreadDtlsKeyMaterial, Tls12Aes128Ccm8KeyBlock, derive_aes_128_ccm_8_key_block,
    derive_joiner_router_kek, derive_master_secret, finished_verify_data, tls12_prf,
};
pub use record::{ContentType, DtlsRecord, RecordHeader};
pub use record_protection::{open_aes_128_ccm_8_record, protect_aes_128_ccm_8_record};
pub use session::DtlsSession;
pub use thread_handshake::ThreadDtlsHandshake;
pub use thread_server_handshake::{
    DTLS_COOKIE_LEN, DtlsCookieGenerator, ThreadDtlsServerHandshake,
};

#[cfg(test)]
mod tests;
