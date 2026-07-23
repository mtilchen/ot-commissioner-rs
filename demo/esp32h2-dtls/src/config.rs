//! Fixed radio and application settings for the two-board desk demo.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// IEEE 802.15.4 channel used by both boards.
pub(crate) const CHANNEL: u8 = 15;
/// IEEE 802.15.4 PAN identifier used by both boards.
pub(crate) const PAN_ID: u16 = 0x2ee7;
/// Server board short address.
pub(crate) const SERVER_SHORT_ADDRESS: u16 = 0x0001;
/// Client board short address.
#[cfg(feature = "role-client")]
pub(crate) const CLIENT_SHORT_ADDRESS: u16 = 0x0002;
/// Synthetic UDP port used by the raw-radio adapter.
pub(crate) const DEMO_PORT: u16 = 0x2ee7;

/// Demo-only shared PSKc. Replace this credential before any non-demo use.
///
/// This value, key material, and raw handshake payloads must never be logged.
pub(crate) const DEMO_PSKC: [u8; 16] = [
    0x9f, 0x62, 0x31, 0x84, 0xa7, 0x0d, 0x55, 0xc2, 0x16, 0xe9, 0x43, 0x78, 0x0b, 0xd4, 0x6a, 0xf1,
];

/// Maps a 16-bit radio short address into the demo's synthetic IPv4 space.
///
/// The two configured addresses fit in one octet. The upper octet is rejected
/// at the adapter boundary rather than silently truncated.
pub(crate) const fn socket_addr(short_address: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(10, 0, 0, short_address as u8),
        DEMO_PORT,
    ))
}
