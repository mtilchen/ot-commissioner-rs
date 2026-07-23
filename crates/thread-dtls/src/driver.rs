//! Runtime-neutral asynchronous DTLS record I/O.
//!
//! The driver uses [`embedded_nal_async::UnconnectedUdp`] because DTLS
//! servers must learn the sender of each datagram before committing handshake
//! state, and must send the stateless HelloVerifyRequest back to that sender.
//! Its explicit local and remote addresses model that exchange directly.
//! [`embedded_hal_async::delay::DelayNs`] supplies the timer future raced
//! against each receive. Both traits are executor-independent and are already
//! part of the embedded networking ecosystem. `embassy-net` 0.9 depends on
//! the same trait crate but does not currently implement `UnconnectedUdp` for
//! its raw `udp::UdpSocket`; an Embassy application therefore uses a local
//! newtype that forwards `send`/`receive_into` to `send_to`/`recv_from`.
//! The future ESP32-H2 demo is the intended home for that board-specific
//! adapter, socket buffers, and executor policy while this crate owns only
//! DTLS state.
//!
//! Tokio support uses small adapters for the same traits. The receive policy
//! deliberately matches the original Tokio client: each expected flight gets
//! the caller's timeout and sent flights are not automatically retransmitted.
//! No additional retry or backoff policy is imposed here.

use alloc::{format, vec::Vec};
use core::{
    fmt,
    future::{Future, poll_fn},
    net::SocketAddr,
    task::Poll,
    time::Duration,
};

pub use embedded_hal_async::delay::DelayNs;
pub use embedded_nal_async::UnconnectedUdp;

use crate::{
    ContentType, DtlsRecord, Error, RecordProtectionKey, ThreadDtlsKeyMaterial,
    open_aes_128_ccm_8_record, protect_aes_128_ccm_8_record,
};

/// Maximum UDP datagram accepted by the async drivers.
pub const MAX_DATAGRAM_SIZE: usize = 4096;

/// Error produced by a runtime-neutral DTLS driver.
#[derive(Debug)]
pub enum DriverError<E> {
    /// DTLS framing, handshake, or cryptographic processing failed.
    Protocol(Error),
    /// The datagram transport failed.
    Transport(E),
    /// A receive did not complete within the supplied timeout.
    Timeout,
}

impl<E> From<Error> for DriverError<E> {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}

impl<E: fmt::Display> fmt::Display for DriverError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::Transport(error) => write!(formatter, "datagram transport error: {error}"),
            Self::Timeout => formatter.write_str("DTLS receive timed out"),
        }
    }
}

impl<E> core::error::Error for DriverError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Timeout => None,
        }
    }
}

/// Runtime-neutral result returned by async DTLS drivers.
pub type DriverResult<T, E> = core::result::Result<T, DriverError<E>>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum SessionRole {
    Client,
    Server,
}

#[derive(Debug)]
pub(crate) struct SessionState {
    key_material: ThreadDtlsKeyMaterial,
    role: SessionRole,
    next_application_sequence: u64,
    application_replay: DtlsReplayWindow,
}

impl SessionState {
    pub(crate) fn new(key_material: ThreadDtlsKeyMaterial, role: SessionRole) -> Self {
        Self {
            key_material,
            role,
            next_application_sequence: 1,
            application_replay: DtlsReplayWindow::new(),
        }
    }

    pub(crate) const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        &self.key_material
    }

    pub(crate) fn protect_application_data(
        &mut self,
        plaintext: &[u8],
    ) -> crate::Result<DtlsRecord> {
        let (key, iv) = match self.role {
            SessionRole::Client => (
                self.key_material.key_block.client_write_key,
                self.key_material.key_block.client_write_iv,
            ),
            SessionRole::Server => (
                self.key_material.key_block.server_write_key,
                self.key_material.key_block.server_write_iv,
            ),
        };
        let record = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            self.next_application_sequence,
            RecordProtectionKey::new(key),
            &iv,
            plaintext,
        )?;
        self.next_application_sequence = self.next_application_sequence.wrapping_add(1);
        Ok(record)
    }

    pub(crate) fn open_application_data(
        &mut self,
        record: &DtlsRecord,
    ) -> crate::Result<Option<Vec<u8>>> {
        if self
            .application_replay
            .has_seen(record.header.sequence_number)
        {
            return Ok(None);
        }
        let (key, iv) = match self.role {
            SessionRole::Client => (
                self.key_material.key_block.server_write_key,
                self.key_material.key_block.server_write_iv,
            ),
            SessionRole::Server => (
                self.key_material.key_block.client_write_key,
                self.key_material.key_block.client_write_iv,
            ),
        };
        let plaintext = open_aes_128_ccm_8_record(record, RecordProtectionKey::new(key), &iv)?;
        self.application_replay
            .mark_seen(record.header.sequence_number);
        Ok(Some(plaintext))
    }
}

pub(crate) async fn send_records<U>(
    transport: &mut U,
    local: SocketAddr,
    remote: SocketAddr,
    records: &[DtlsRecord],
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
{
    let mut datagram = Vec::new();
    for record in records {
        datagram.extend_from_slice(&record.encode()?);
    }
    transport
        .send(local, remote, &datagram)
        .await
        .map_err(DriverError::Transport)
}

pub(crate) async fn recv_records<U, D>(
    transport: &mut U,
    delay: &mut D,
    duration: Duration,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    let mut buffer = [0u8; MAX_DATAGRAM_SIZE];
    let (length, local, remote) =
        recv_with_timeout(transport, delay, &mut buffer, duration).await?;
    if length > buffer.len() {
        return Err(Error::Crypto("DTLS datagram is too long".into()).into());
    }
    Ok((
        DtlsRecord::parse_datagram(&buffer[..length])?,
        local,
        remote,
    ))
}

pub(crate) async fn recv_application_data<U, D>(
    state: &mut SessionState,
    transport: &mut U,
    delay: &mut D,
    peer: SocketAddr,
    duration: Duration,
) -> DriverResult<Vec<u8>, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    loop {
        let (records, _, source) = recv_records(transport, delay, duration).await?;
        if source != peer {
            continue;
        }
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (1, ContentType::ApplicationData) => {
                    if let Some(plaintext) = state.open_application_data(&record)? {
                        return Ok(plaintext);
                    }
                }
                (_, ContentType::Alert) => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
}

pub(crate) fn decode_alert_error(record: &DtlsRecord) -> Error {
    if record.payload.len() >= 2 {
        Error::Crypto(format!(
            "DTLS alert epoch={} seq={} level={} description={}",
            record.header.epoch,
            record.header.sequence_number,
            record.payload[0],
            record.payload[1]
        ))
    } else {
        Error::Crypto(format!(
            "DTLS alert epoch={} seq={} received",
            record.header.epoch, record.header.sequence_number
        ))
    }
}

async fn recv_with_timeout<U, D>(
    transport: &mut U,
    delay: &mut D,
    buffer: &mut [u8],
    duration: Duration,
) -> DriverResult<(usize, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    let receive = transport.receive_into(buffer);
    let timeout = delay_duration(delay, duration);
    let mut receive = core::pin::pin!(receive);
    let mut timeout = core::pin::pin!(timeout);

    poll_fn(|context| {
        if let Poll::Ready(result) = receive.as_mut().poll(context) {
            return Poll::Ready(result.map_err(DriverError::Transport));
        }
        if timeout.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(DriverError::Timeout));
        }
        Poll::Pending
    })
    .await
}

async fn delay_duration(delay: &mut impl DelayNs, duration: Duration) {
    let mut nanoseconds = duration.as_nanos();
    while nanoseconds > 0 {
        let chunk = nanoseconds.min(u32::MAX as u128) as u32;
        delay.delay_ns(chunk).await;
        nanoseconds -= u128::from(chunk);
    }
}

#[derive(Debug)]
struct DtlsReplayWindow {
    newest_sequence: Option<u64>,
    seen: u64,
}

impl DtlsReplayWindow {
    const fn new() -> Self {
        Self {
            newest_sequence: None,
            seen: 0,
        }
    }

    fn has_seen(&self, sequence: u64) -> bool {
        let Some(newest) = self.newest_sequence else {
            return false;
        };
        if sequence > newest {
            return false;
        }
        let offset = newest - sequence;
        offset >= u64::BITS as u64 || ((self.seen >> offset) & 1) == 1
    }

    fn mark_seen(&mut self, sequence: u64) {
        match self.newest_sequence {
            None => {
                self.newest_sequence = Some(sequence);
                self.seen = 1;
            }
            Some(newest) if sequence > newest => {
                let shift = sequence - newest;
                self.seen = if shift >= u64::BITS as u64 {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.newest_sequence = Some(sequence);
            }
            Some(newest) => {
                let offset = newest - sequence;
                if offset < u64::BITS as u64 {
                    self.seen |= 1 << offset;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::VecDeque, vec};
    use core::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr},
        task::Poll,
    };

    use super::*;

    const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);

    struct ScriptedUdp {
        received: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl UnconnectedUdp for ScriptedUdp {
        type Error = Infallible;

        async fn send(
            &mut self,
            _local: SocketAddr,
            _remote: SocketAddr,
            data: &[u8],
        ) -> core::result::Result<(), Self::Error> {
            self.sent.push(data.to_vec());
            Ok(())
        }

        async fn receive_into(
            &mut self,
            buffer: &mut [u8],
        ) -> core::result::Result<(usize, SocketAddr, SocketAddr), Self::Error> {
            poll_fn(|_| {
                let Some(datagram) = self.received.pop_front() else {
                    return Poll::Pending;
                };
                buffer[..datagram.len()].copy_from_slice(&datagram);
                Poll::Ready(Ok((datagram.len(), LOCAL, PEER)))
            })
            .await
        }
    }

    struct PendingDelay;

    impl DelayNs for PendingDelay {
        async fn delay_ns(&mut self, _nanoseconds: u32) {
            poll_fn(|_| Poll::<()>::Pending).await;
        }
    }

    #[test]
    fn scripted_transport_drives_record_io_without_a_socket() {
        let record =
            DtlsRecord::new(ContentType::Handshake, 0, 4, vec![1, 2, 3]).expect("test record");
        let mut transport = ScriptedUdp {
            received: VecDeque::from([record.encode().expect("encoded test record")]),
            sent: Vec::new(),
        };
        let mut delay = PendingDelay;
        let (records, local, peer) = futures_lite_for_test::block_on(recv_records(
            &mut transport,
            &mut delay,
            Duration::from_secs(1),
        ))
        .expect("scripted receive");
        assert_eq!(records, vec![record]);
        assert_eq!(local, LOCAL);
        assert_eq!(peer, PEER);
    }

    mod futures_lite_for_test {
        use core::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };

        pub(super) fn block_on<T>(future: impl Future<Output = T>) -> T {
            let mut future = pin!(future);
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => output,
                Poll::Pending => panic!("scripted future unexpectedly pending"),
            }
        }
    }
}
