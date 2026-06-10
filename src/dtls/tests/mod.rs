//! Tests for the DTLS profile modules.

use super::*;
use crate::crypto::{
    EcJpakeParty, EcJpakeRole, RecordProtectionKey, RoundTwo, TLS_CCM_8_TAG_LEN,
    TLS_CCM_EXPLICIT_NONCE_LEN,
};
use crate::dtls::hello::ec_point_formats_extension;
use crate::dtls::util::{MAX_U24, read_u24, write_u24};
use rand_core::OsRng;

mod codec;
mod framing;
mod hello;
mod keys;
mod server_session;
