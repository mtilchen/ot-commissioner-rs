//! DTLS 1.2 profile pieces used by Thread commissioner sessions.
//!
//! The module keeps public DTLS types under `ot_commissioner_rs::dtls` while
//! splitting record framing, handshake codecs, the key schedule, record
//! protection, and the Tokio session driver into smaller implementation files.

mod constants;
mod handshake;
mod hello;
mod key_schedule;
mod record;
mod record_protection;
mod session;
#[cfg(test)]
pub(crate) mod test_support;
mod thread_handshake;
mod thread_server_handshake;
mod util;

pub use constants::*;
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
