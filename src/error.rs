//! Error types used across the commissioner implementation.

use thiserror::Error;

/// Crate-wide result type.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by `ot-commissioner-rs`.
#[derive(Debug, Error)]
pub enum Error {
    /// A TLV stream is malformed or incomplete.
    #[error("TLV error: {0}")]
    Tlv(#[from] crate::tlv::TlvError),

    /// A dataset field has an invalid length or value.
    #[error("dataset error: {0}")]
    Dataset(String),

    /// A cryptographic input or verification failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Hex decoding failed.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    /// An I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A protocol operation timed out.
    #[error("timeout: {0}")]
    Timeout(&'static str),

    /// The commissioner is not in the state required by the operation.
    #[error("invalid state: {0}")]
    InvalidState(&'static str),

    /// A petition request was rejected by the border agent or active commissioner.
    #[error("petition was rejected{suffix}", suffix = petition_rejected_suffix(.existing_commissioner_id))]
    PetitionRejected {
        /// Existing commissioner ID reported by the border agent, when present.
        existing_commissioner_id: Option<String>,
    },

    /// The requested operation is intentionally deferred.
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
}

fn petition_rejected_suffix(existing_commissioner_id: &Option<String>) -> String {
    existing_commissioner_id
        .as_ref()
        .map(|id| format!(" by existing commissioner `{id}`"))
        .unwrap_or_default()
}
