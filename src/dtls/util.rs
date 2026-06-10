//! Shared DTLS utility helpers.

use crate::{Result, error::Error};

pub(crate) const MAX_U24: u32 = 0x00ff_ffff;

pub(crate) fn read_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

pub(crate) fn write_u24(value: u32, out: &mut [u8]) -> Result<()> {
    if value > MAX_U24 || out.len() != 3 {
        return Err(Error::Crypto("invalid 24-bit integer".to_string()));
    }
    out[0] = (value >> 16) as u8;
    out[1] = (value >> 8) as u8;
    out[2] = value as u8;
    Ok(())
}

pub(crate) fn dtls_trace(args: core::fmt::Arguments<'_>) {
    if std::env::var_os("OT_COMMISSIONER_TRACE").is_some() {
        eprintln!("[dtls] {args}");
    }
}

pub(crate) fn dtls_trace_secret(label: &str, bytes: &[u8]) {
    if std::env::var_os("OT_COMMISSIONER_TRACE_SECRETS").is_some() {
        eprintln!("[dtls-secret] {label}={}", hex::encode(bytes));
    }
}
