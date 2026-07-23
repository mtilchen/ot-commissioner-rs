//! Datagram fragmentation over raw ESP32-H2 IEEE 802.15.4 data frames.
//!
//! Each radio payload starts with `[magic, sequence, fragment_index,
//! fragment_count]`. Reassembly is keyed by `(source, sequence)`. There is one
//! expected peer in this desk demo, so a new sequence from that source replaces
//! and drops any incomplete datagram, including when the `u8` sequence wraps.
//! Fragments may arrive out of order and duplicates are ignored.

use alloc::{vec, vec::Vec};
use core::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU8, Ordering},
};

use embassy_time::{Duration, Instant, Timer};
use embedded_io_async::ErrorKind;
use embedded_nal_async::UnconnectedUdp;
use esp_radio::ieee802154::{Config, Frame, Ieee802154};
use ieee802154::mac::{
    Address, FrameContent, FrameType, FrameVersion, Header, PanId, ShortAddress,
};

use crate::config::{self, CHANNEL, DEMO_PORT, PAN_ID};

const PHY_MAX_FRAME_BYTES: usize = 127;
const FRAME_CONTROL_BYTES: usize = 2;
const SEQUENCE_NUMBER_BYTES: usize = 1;
const PAN_ID_BYTES: usize = 2;
const SHORT_ADDRESS_BYTES: usize = 2;
const MAC_FOOTER_BYTES: usize = 2;
const MAC_HEADER_BYTES: usize =
    FRAME_CONTROL_BYTES + SEQUENCE_NUMBER_BYTES + PAN_ID_BYTES + (2 * SHORT_ADDRESS_BYTES);
const FRAME_PAYLOAD_BYTES: usize = PHY_MAX_FRAME_BYTES - MAC_HEADER_BYTES - MAC_FOOTER_BYTES;

const FRAGMENT_MAGIC: u8 = 0xd7;
const FRAGMENT_HEADER_BYTES: usize = 4;
const FRAGMENT_DATA_BYTES: usize = FRAME_PAYLOAD_BYTES - FRAGMENT_HEADER_BYTES;
const MAX_DATAGRAM_BYTES: usize = thread_dtls::driver::MAX_DATAGRAM_SIZE;
const MAX_FRAGMENTS: usize = MAX_DATAGRAM_BYTES.div_ceil(FRAGMENT_DATA_BYTES);
const RECEIVED_BITMAP_BYTES: usize = MAX_FRAGMENTS.div_ceil(u8::BITS as usize);

const TX_COMPLETION_TIMEOUT: Duration = Duration::from_millis(100);
const RADIO_POLL_INTERVAL: Duration = Duration::from_millis(1);

const TX_PENDING: u8 = 0;
const TX_SUCCEEDED: u8 = 1;
const TX_FAILED: u8 = 2;
static TX_STATUS: AtomicU8 = AtomicU8::new(TX_PENDING);

fn mark_tx_done() {
    TX_STATUS.store(TX_SUCCEEDED, Ordering::Release);
}

fn mark_tx_failed() {
    TX_STATUS.store(TX_FAILED, Ordering::Release);
}

/// Errors surfaced through the async UDP compatibility trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RadioError {
    InvalidAddress,
    DatagramTooLarge,
    TransmitFailed,
    TransmitTimeout,
}

impl fmt::Display for RadioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => formatter.write_str("invalid demo socket address"),
            Self::DatagramTooLarge => formatter.write_str("datagram exceeds DTLS adapter limit"),
            Self::TransmitFailed => formatter.write_str("IEEE 802.15.4 transmit failed"),
            Self::TransmitTimeout => formatter.write_str("IEEE 802.15.4 transmit timed out"),
        }
    }
}

impl core::error::Error for RadioError {}

impl embedded_io_async::Error for RadioError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidAddress | Self::DatagramTooLarge => ErrorKind::InvalidInput,
            Self::TransmitTimeout => ErrorKind::TimedOut,
            Self::TransmitFailed => ErrorKind::Other,
        }
    }
}

struct Reassembly {
    source: u16,
    sequence: u8,
    fragment_count: u8,
    received_count: u8,
    received: [u8; RECEIVED_BITMAP_BYTES],
    final_length: Option<usize>,
    bytes: Vec<u8>,
}

impl Reassembly {
    fn new(source: u16, sequence: u8, fragment_count: u8) -> Option<Self> {
        let fragment_count_usize = usize::from(fragment_count);
        if fragment_count_usize == 0 || fragment_count_usize > MAX_FRAGMENTS {
            return None;
        }
        Some(Self {
            source,
            sequence,
            fragment_count,
            received_count: 0,
            received: [0; RECEIVED_BITMAP_BYTES],
            final_length: None,
            bytes: vec![0; fragment_count_usize * FRAGMENT_DATA_BYTES],
        })
    }

    fn matches(&self, source: u16, sequence: u8, fragment_count: u8) -> bool {
        self.source == source && self.sequence == sequence && self.fragment_count == fragment_count
    }

    fn insert(&mut self, fragment_index: u8, chunk: &[u8]) -> bool {
        if fragment_index >= self.fragment_count {
            return false;
        }

        let is_final = fragment_index == self.fragment_count - 1;
        if (!is_final && chunk.len() != FRAGMENT_DATA_BYTES) || chunk.len() > FRAGMENT_DATA_BYTES {
            return false;
        }

        let index = usize::from(fragment_index);
        let bitmap_byte = index / u8::BITS as usize;
        let bitmap_mask = 1 << (index % u8::BITS as usize);
        if self.received[bitmap_byte] & bitmap_mask != 0 {
            return true;
        }

        let offset = index * FRAGMENT_DATA_BYTES;
        self.bytes[offset..offset + chunk.len()].copy_from_slice(chunk);
        self.received[bitmap_byte] |= bitmap_mask;
        self.received_count += 1;
        if is_final {
            self.final_length = Some(offset + chunk.len());
        }
        true
    }

    fn is_complete(&self) -> bool {
        self.received_count == self.fragment_count && self.final_length.is_some()
    }

    fn finish(mut self) -> Option<Vec<u8>> {
        let final_length = self.final_length?;
        if final_length > MAX_DATAGRAM_BYTES {
            return None;
        }
        self.bytes.truncate(final_length);
        Some(self.bytes)
    }
}

/// Raw-radio adapter presenting fragmented frames as UDP-like datagrams.
pub(crate) struct RadioDatagram<'d> {
    radio: Ieee802154<'d>,
    local_short_address: u16,
    next_datagram_sequence: u8,
    next_mac_sequence: u8,
    reassembly: Option<Reassembly>,
}

impl<'d> RadioDatagram<'d> {
    /// Configures and starts the H2 radio for the fixed demo PAN and channel.
    pub(crate) fn new(
        radio_peripheral: esp_hal::peripherals::IEEE802154<'d>,
        local_short_address: u16,
    ) -> Self {
        let mut radio = Ieee802154::new(radio_peripheral);
        radio.set_config(Config {
            auto_ack_tx: true,
            auto_ack_rx: true,
            channel: CHANNEL,
            pan_id: Some(PAN_ID),
            rx_when_idle: true,
            short_addr: Some(local_short_address),
            ..Config::default()
        });
        radio.set_tx_done_callback_fn(mark_tx_done);
        radio.set_tx_failed_callback_fn(mark_tx_failed);
        radio.start_receive();

        Self {
            radio,
            local_short_address,
            next_datagram_sequence: 0,
            next_mac_sequence: 0,
            reassembly: None,
        }
    }

    async fn wait_for_transmit(&self) -> Result<(), RadioError> {
        let deadline = Instant::now() + TX_COMPLETION_TIMEOUT;
        loop {
            match TX_STATUS.load(Ordering::Acquire) {
                TX_SUCCEEDED => {
                    TX_STATUS.store(TX_PENDING, Ordering::Release);
                    return Ok(());
                }
                TX_FAILED => {
                    TX_STATUS.store(TX_PENDING, Ordering::Release);
                    return Err(RadioError::TransmitFailed);
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(RadioError::TransmitTimeout);
            }
            Timer::after(RADIO_POLL_INTERVAL).await;
        }
    }

    async fn send_datagram(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), RadioError> {
        if local != config::socket_addr(self.local_short_address) {
            return Err(RadioError::InvalidAddress);
        }
        if data.len() > MAX_DATAGRAM_BYTES {
            return Err(RadioError::DatagramTooLarge);
        }
        let destination = short_address(remote)?;
        let fragment_count = data.len().max(1).div_ceil(FRAGMENT_DATA_BYTES);
        let fragment_count =
            u8::try_from(fragment_count).map_err(|_| RadioError::DatagramTooLarge)?;
        let datagram_sequence = self.next_datagram_sequence;
        self.next_datagram_sequence = self.next_datagram_sequence.wrapping_add(1);

        for fragment_index in 0..fragment_count {
            let start = usize::from(fragment_index) * FRAGMENT_DATA_BYTES;
            let end = (start + FRAGMENT_DATA_BYTES).min(data.len());
            let chunk = &data[start.min(data.len())..end];

            let mut payload = [0u8; FRAME_PAYLOAD_BYTES];
            payload[..FRAGMENT_HEADER_BYTES].copy_from_slice(&[
                FRAGMENT_MAGIC,
                datagram_sequence,
                fragment_index,
                fragment_count,
            ]);
            payload[FRAGMENT_HEADER_BYTES..FRAGMENT_HEADER_BYTES + chunk.len()]
                .copy_from_slice(chunk);

            let frame = Frame {
                header: Header {
                    frame_type: FrameType::Data,
                    frame_pending: false,
                    ack_request: true,
                    pan_id_compress: true,
                    seq_no_suppress: false,
                    ie_present: false,
                    version: FrameVersion::Ieee802154_2006,
                    seq: self.next_mac_sequence,
                    destination: Some(Address::Short(PanId(PAN_ID), ShortAddress(destination))),
                    source: Some(Address::Short(
                        PanId(PAN_ID),
                        ShortAddress(self.local_short_address),
                    )),
                    auxiliary_security_header: None,
                },
                content: FrameContent::Data,
                payload: payload[..FRAGMENT_HEADER_BYTES + chunk.len()].to_vec(),
                footer: [0; MAC_FOOTER_BYTES],
            };
            self.next_mac_sequence = self.next_mac_sequence.wrapping_add(1);

            TX_STATUS.store(TX_PENDING, Ordering::Release);
            self.radio
                .transmit(&frame, true)
                .map_err(|_| RadioError::TransmitFailed)?;
            self.wait_for_transmit().await?;
        }
        Ok(())
    }

    fn process_received(&mut self) -> Option<(u16, Vec<u8>)> {
        let received = self.radio.received()?.ok()?;
        if received.channel != CHANNEL || received.frame.content != FrameContent::Data {
            return None;
        }

        let source = frame_short_address(received.frame.header.source)?;
        let destination = frame_short_address(received.frame.header.destination)?;
        if destination != self.local_short_address {
            return None;
        }

        let payload = received.frame.payload.as_slice();
        if payload.len() < FRAGMENT_HEADER_BYTES || payload[0] != FRAGMENT_MAGIC {
            return None;
        }
        let sequence = payload[1];
        let fragment_index = payload[2];
        let fragment_count = payload[3];
        let chunk = &payload[FRAGMENT_HEADER_BYTES..];

        if !self
            .reassembly
            .as_ref()
            .is_some_and(|state| state.matches(source, sequence, fragment_count))
        {
            self.reassembly = Reassembly::new(source, sequence, fragment_count);
        }
        let state = self.reassembly.as_mut()?;
        if !state.insert(fragment_index, chunk) {
            self.reassembly = None;
            return None;
        }
        if !state.is_complete() {
            return None;
        }

        let state = self.reassembly.take()?;
        Some((source, state.finish()?))
    }

    async fn receive_datagram(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr), RadioError> {
        loop {
            if let Some((source, datagram)) = self.process_received() {
                let copied = buffer.len().min(datagram.len());
                buffer[..copied].copy_from_slice(&datagram[..copied]);
                return Ok((
                    datagram.len(),
                    config::socket_addr(self.local_short_address),
                    config::socket_addr(source),
                ));
            }
            Timer::after(RADIO_POLL_INTERVAL).await;
        }
    }
}

impl UnconnectedUdp for &mut RadioDatagram<'_> {
    type Error = RadioError;

    async fn send(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.send_datagram(local, remote, data).await
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        self.receive_datagram(buffer).await
    }
}

fn frame_short_address(address: Option<Address>) -> Option<u16> {
    match address {
        Some(Address::Short(PanId(pan_id), ShortAddress(short_address))) if pan_id == PAN_ID => {
            Some(short_address)
        }
        _ => None,
    }
}

fn short_address(address: SocketAddr) -> Result<u16, RadioError> {
    match address {
        SocketAddr::V4(address)
            if address.port() == DEMO_PORT
                && address.ip().octets()[..3] == [10, 0, 0]
                && address.ip() != &Ipv4Addr::new(10, 0, 0, 0) =>
        {
            Ok(u16::from(address.ip().octets()[3]))
        }
        SocketAddr::V6(_) | SocketAddr::V4(_) => Err(RadioError::InvalidAddress),
    }
}
