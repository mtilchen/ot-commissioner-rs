//! Cryptographic helpers used by Thread commissioning.

pub mod pskc;

pub use pskc::{
    MAX_PSKC_LEN, add_joiner_to_steering_data, compute_joiner_id, generate_pskc,
    pskc_from_active_dataset,
};
/// Re-exported so `CommissionerConfig::pskc` and callers keep a single key type.
pub use thread_dtls::RecordProtectionKey;
