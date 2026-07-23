//! Tokio-backed DTLS session driver.

use crate::{Result, crypto::RecordProtectionKey, error::Error};

use super::{
    handshake::{
        HandshakeType, parse_unfragmented_handshake_messages, parse_unfragmented_handshake_record,
    },
    hello::DtlsClientHelloState,
    key_schedule::ThreadDtlsKeyMaterial,
    record::{ContentType, DtlsRecord},
    record_protection::{open_aes_128_ccm_8_record, protect_aes_128_ccm_8_record},
    thread_handshake::ThreadDtlsHandshake,
    util::dtls_trace,
};

/// Established Thread DTLS commissioner session.
#[derive(Debug)]
pub struct DtlsSession {
    key_material: ThreadDtlsKeyMaterial,
    next_client_application_sequence: u64,
    server_application_replay: DtlsReplayWindow,
}

impl DtlsSession {
    /// Creates a session from already-derived key material.
    pub fn new(key_material: ThreadDtlsKeyMaterial) -> Self {
        Self {
            key_material,
            next_client_application_sequence: 1,
            server_application_replay: DtlsReplayWindow::new(),
        }
    }

    /// Returns the derived key material.
    pub const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        &self.key_material
    }
}

impl DtlsSession {
    /// Runs the Thread PSKc/ECJPAKE DTLS handshake over a connected UDP socket.
    pub async fn connect(
        socket: &tokio::net::UdpSocket,
        pskc: &[u8],
        timeout: core::time::Duration,
    ) -> Result<Self> {
        let mut rng = rand_core::OsRng;
        let mut handshake = ThreadDtlsHandshake::new(pskc, &mut rng);
        let mut hello_state = handshake.client_hello_state()?;

        let first_client_hello = hello_state.next_client_hello_record()?;
        dtls_trace(format_args!(
            "send first ClientHello record_seq={}",
            first_client_hello.header.sequence_number
        ));
        send_records(socket, &[first_client_hello]).await?;
        wait_for_hello_verify(socket, &mut hello_state, timeout).await?;

        let second_client_hello = hello_state.next_client_hello_record()?;
        let client_hello_message =
            parse_unfragmented_handshake_record(&second_client_hello, HandshakeType::ClientHello)?;
        dtls_trace(format_args!(
            "send second ClientHello record_seq={} message_seq={}",
            second_client_hello.header.sequence_number, client_hello_message.message_seq
        ));
        handshake.record_client_hello(&client_hello_message)?;
        send_records(socket, &[second_client_hello]).await?;

        wait_for_server_flight(socket, &mut handshake, timeout).await?;

        let client_key_exchange_seq = hello_state.next_message_sequence();
        let client_key_exchange =
            handshake.build_client_key_exchange(client_key_exchange_seq, &mut rng)?;
        let key_material = handshake.derive_key_material()?;
        let client_finished =
            handshake.build_client_finished(client_key_exchange_seq.wrapping_add(1))?;

        let next_epoch_zero_record = hello_state.next_record_sequence();
        let client_key_exchange_record = DtlsRecord::new(
            ContentType::Handshake,
            0,
            next_epoch_zero_record,
            client_key_exchange.encode()?,
        )?;
        let change_cipher_spec = DtlsRecord::new(
            ContentType::ChangeCipherSpec,
            0,
            next_epoch_zero_record.wrapping_add(1),
            vec![1],
        )?;
        let client_finished_record = protect_aes_128_ccm_8_record(
            ContentType::Handshake,
            1,
            0,
            RecordProtectionKey::new(key_material.key_block.client_write_key),
            &key_material.key_block.client_write_iv,
            &client_finished.encode()?,
        )?;
        dtls_trace(format_args!(
            "send ClientKeyExchange message_seq={} record_seq={}, CCS record_seq={}, Finished message_seq={} epoch1_record_seq=0",
            client_key_exchange.message_seq,
            client_key_exchange_record.header.sequence_number,
            change_cipher_spec.header.sequence_number,
            client_finished.message_seq
        ));
        send_records(
            socket,
            &[
                client_key_exchange_record,
                change_cipher_spec,
                client_finished_record,
            ],
        )
        .await?;

        wait_for_server_finished(socket, &mut handshake, &key_material, timeout).await?;
        Ok(Self::new(key_material))
    }

    /// Sends protected application data and waits for the next protected application record.
    pub async fn request_application_data(
        &mut self,
        socket: &tokio::net::UdpSocket,
        plaintext: &[u8],
        timeout: core::time::Duration,
    ) -> Result<Vec<u8>> {
        self.send_application_data(socket, plaintext).await?;
        self.recv_application_data(socket, timeout).await
    }

    /// Sends one protected application-data record.
    pub async fn send_application_data(
        &mut self,
        socket: &tokio::net::UdpSocket,
        plaintext: &[u8],
    ) -> Result<()> {
        let record = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            self.next_client_application_sequence,
            RecordProtectionKey::new(self.key_material.key_block.client_write_key),
            &self.key_material.key_block.client_write_iv,
            plaintext,
        )?;
        self.next_client_application_sequence =
            self.next_client_application_sequence.wrapping_add(1);
        send_records(socket, &[record]).await
    }

    /// Receives and opens the next protected application-data record.
    pub async fn recv_application_data(
        &mut self,
        socket: &tokio::net::UdpSocket,
        timeout: core::time::Duration,
    ) -> Result<Vec<u8>> {
        loop {
            let records = recv_records(socket, timeout).await?;
            for record in records {
                match (record.header.epoch, record.header.content_type) {
                    (1, ContentType::ApplicationData) => {
                        if self
                            .server_application_replay
                            .has_seen(record.header.sequence_number)
                        {
                            continue;
                        }
                        let plaintext = open_aes_128_ccm_8_record(
                            &record,
                            RecordProtectionKey::new(self.key_material.key_block.server_write_key),
                            &self.key_material.key_block.server_write_iv,
                        )?;
                        self.server_application_replay
                            .mark_seen(record.header.sequence_number);
                        return Ok(plaintext);
                    }
                    (_, ContentType::Alert) => return Err(decode_alert_error(&record)),
                    _ => {}
                }
            }
        }
    }
}

#[derive(Debug)]
struct DtlsReplayWindow {
    newest_sequence: Option<u64>,
    seen: u64,
}

impl DtlsReplayWindow {
    fn new() -> Self {
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

async fn send_records(socket: &tokio::net::UdpSocket, records: &[DtlsRecord]) -> Result<()> {
    let mut datagram = Vec::new();
    for record in records {
        datagram.extend_from_slice(&record.encode()?);
    }
    socket.send(&datagram).await?;
    Ok(())
}

async fn recv_records(
    socket: &tokio::net::UdpSocket,
    duration: core::time::Duration,
) -> Result<Vec<DtlsRecord>> {
    let mut buf = [0u8; 4096];
    let len = tokio::time::timeout(duration, socket.recv(&mut buf))
        .await
        .map_err(|_| Error::Timeout("DTLS receive timed out"))??;
    DtlsRecord::parse_datagram(&buf[..len])
}

async fn wait_for_hello_verify(
    socket: &tokio::net::UdpSocket,
    hello_state: &mut DtlsClientHelloState,
    duration: core::time::Duration,
) -> Result<()> {
    loop {
        let records = recv_records(socket, duration).await?;
        for record in records {
            match record.header.content_type {
                ContentType::Handshake => {
                    let messages = parse_unfragmented_handshake_messages(&record)?;
                    if messages
                        .iter()
                        .any(|message| message.message_type == HandshakeType::HelloVerifyRequest)
                    {
                        hello_state.handle_hello_verify_request(&record)?;
                        dtls_trace(format_args!(
                            "recv HelloVerifyRequest cookie_len={}",
                            hello_state.cookie().len()
                        ));
                        return Ok(());
                    }
                }
                ContentType::Alert => return Err(decode_alert_error(&record)),
                _ => {}
            }
        }
    }
}

async fn wait_for_server_flight(
    socket: &tokio::net::UdpSocket,
    handshake: &mut ThreadDtlsHandshake,
    duration: core::time::Duration,
) -> Result<()> {
    loop {
        let records = recv_records(socket, duration).await?;
        for record in records {
            match record.header.content_type {
                ContentType::Handshake => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        dtls_trace(format_args!(
                            "recv handshake {:?} message_seq={} len={}",
                            message.message_type,
                            message.message_seq,
                            message.payload.len()
                        ));
                        match message.message_type {
                            HandshakeType::ServerHello => {
                                let hello = handshake.handle_server_hello(&message)?;
                                dtls_trace(format_args!(
                                    "server extensions={:?}",
                                    hello
                                        .extensions
                                        .iter()
                                        .map(|extension| extension.extension_type)
                                        .collect::<Vec<_>>()
                                ));
                            }
                            HandshakeType::ServerKeyExchange => {
                                handshake.handle_server_key_exchange(&message)?;
                            }
                            HandshakeType::ServerHelloDone => {
                                handshake.handle_server_hello_done(&message)?;
                                return Ok(());
                            }
                            HandshakeType::HelloVerifyRequest => {
                                return Err(Error::Crypto(
                                    "received unexpected second HelloVerifyRequest".to_string(),
                                ));
                            }
                            _ => {
                                return Err(Error::Crypto(format!(
                                    "unexpected DTLS handshake message {:?}",
                                    message.message_type
                                )));
                            }
                        }
                    }
                }
                ContentType::Alert => return Err(decode_alert_error(&record)),
                _ => {}
            }
        }
    }
}

async fn wait_for_server_finished(
    socket: &tokio::net::UdpSocket,
    handshake: &mut ThreadDtlsHandshake,
    key_material: &ThreadDtlsKeyMaterial,
    duration: core::time::Duration,
) -> Result<()> {
    let mut saw_change_cipher_spec = false;
    loop {
        let records = recv_records(socket, duration).await?;
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (_, ContentType::ChangeCipherSpec) => {
                    if record.payload != [1] {
                        return Err(Error::Crypto(
                            "invalid ChangeCipherSpec payload".to_string(),
                        ));
                    }
                    dtls_trace(format_args!(
                        "recv ChangeCipherSpec epoch={} seq={}",
                        record.header.epoch, record.header.sequence_number
                    ));
                    saw_change_cipher_spec = true;
                }
                (1, ContentType::Handshake) => {
                    if !saw_change_cipher_spec {
                        return Err(Error::Crypto(
                            "received encrypted Finished before ChangeCipherSpec".to_string(),
                        ));
                    }
                    let plaintext = open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(key_material.key_block.server_write_key),
                        &key_material.key_block.server_write_iv,
                    )?;
                    let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
                    for message in parse_unfragmented_handshake_messages(&plain_record)? {
                        dtls_trace(format_args!(
                            "recv encrypted handshake {:?} message_seq={} len={}",
                            message.message_type,
                            message.message_seq,
                            message.payload.len()
                        ));
                        if message.message_type == HandshakeType::Finished {
                            handshake.verify_server_finished(&message, key_material)?;
                            return Ok(());
                        }
                    }
                }
                (_, ContentType::Alert) => return Err(decode_alert_error(&record)),
                _ => {}
            }
        }
    }
}

fn decode_alert_error(record: &DtlsRecord) -> Error {
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

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use tokio::net::UdpSocket;

    use super::super::key_schedule::Tls12Aes128Ccm8KeyBlock;
    use super::*;

    #[tokio::test]
    async fn application_data_request_sends_and_receives_protected_records() -> Result<()> {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(server.local_addr()?).await?;
        server.connect(client.local_addr()?).await?;

        let key_material = test_key_material();
        let server_key_material = key_material.clone();
        let mut session = DtlsSession::new(key_material);
        let client_request =
            session.request_application_data(&client, b"request", Duration::from_secs(1));
        let server_response = async move {
            let mut buf = [0u8; 4096];
            // Bound the mock server's receive so a client that never sends
            // (e.g. when a regression breaks record protection) fails the test
            // promptly instead of hanging the joined future indefinitely.
            let len = tokio::time::timeout(Duration::from_secs(1), server.recv(&mut buf))
                .await
                .map_err(|_| Error::Timeout("test server receive timed out"))??;
            let records = DtlsRecord::parse_datagram(&buf[..len])?;
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].header.epoch, 1);
            assert_eq!(records[0].header.content_type, ContentType::ApplicationData);
            assert_eq!(records[0].header.sequence_number, 1);

            let plaintext = open_aes_128_ccm_8_record(
                &records[0],
                RecordProtectionKey::new(server_key_material.key_block.client_write_key),
                &server_key_material.key_block.client_write_iv,
            )?;
            assert_eq!(plaintext, b"request");

            let response = protect_aes_128_ccm_8_record(
                ContentType::ApplicationData,
                1,
                7,
                RecordProtectionKey::new(server_key_material.key_block.server_write_key),
                &server_key_material.key_block.server_write_iv,
                b"response",
            )?;
            server.send(&response.encode()?).await?;
            Result::<()>::Ok(())
        };

        let (client_result, server_result) = tokio::join!(client_request, server_response);
        server_result?;
        assert_eq!(client_result?, b"response");
        Ok(())
    }

    #[tokio::test]
    async fn recv_application_data_ignores_plain_records_and_reports_alerts() -> Result<()> {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(server.local_addr()?).await?;
        server.connect(client.local_addr()?).await?;

        let ignored = DtlsRecord::new(ContentType::Handshake, 0, 0, vec![0xde])?;
        let alert = DtlsRecord::new(ContentType::Alert, 1, 1, vec![2, 40])?;
        let mut datagram = ignored.encode()?;
        datagram.extend_from_slice(&alert.encode()?);
        server.send(&datagram).await?;

        let mut session = DtlsSession::new(test_key_material());
        let err = session
            .recv_application_data(&client, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Crypto(message) if message.contains("description=40")));
        Ok(())
    }

    #[tokio::test]
    async fn recv_application_data_drops_replayed_application_records() -> Result<()> {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(server.local_addr()?).await?;
        server.connect(client.local_addr()?).await?;

        let key_material = test_key_material();
        let replayed = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            7,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            b"first",
        )?;
        let next = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            8,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            b"second",
        )?;

        let mut session = DtlsSession::new(key_material);
        server.send(&replayed.encode()?).await?;
        assert_eq!(
            session
                .recv_application_data(&client, Duration::from_secs(1))
                .await?,
            b"first"
        );

        let mut datagram = replayed.encode()?;
        datagram.extend_from_slice(&next.encode()?);
        server.send(&datagram).await?;
        assert_eq!(
            session
                .recv_application_data(&client, Duration::from_secs(1))
                .await?,
            b"second"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recv_records_parses_every_record_in_a_datagram() -> Result<()> {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(server.local_addr()?).await?;
        server.connect(client.local_addr()?).await?;

        let first = DtlsRecord::new(ContentType::Handshake, 0, 3, vec![0x0e])?;
        let second = DtlsRecord::new(ContentType::ApplicationData, 1, 4, vec![0xaa, 0xbb])?;
        let mut datagram = first.encode()?;
        datagram.extend_from_slice(&second.encode()?);
        server.send(&datagram).await?;

        let records = recv_records(&client, Duration::from_secs(1)).await?;
        assert_eq!(records, vec![first, second]);
        Ok(())
    }

    #[tokio::test]
    async fn recv_application_data_times_out_without_records() -> Result<()> {
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        client.connect(server.local_addr()?).await?;

        let mut session = DtlsSession::new(test_key_material());
        let err = session
            .recv_application_data(&client, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Timeout("DTLS receive timed out")));
        Ok(())
    }

    #[test]
    fn decode_alert_error_handles_truncated_alerts() -> Result<()> {
        let record = DtlsRecord::new(ContentType::Alert, 0, 9, vec![2])?;
        let message = decode_alert_error(&record).to_string();
        assert!(message.contains("DTLS alert epoch=0 seq=9 received"));
        Ok(())
    }

    #[test]
    fn replay_window_detects_in_window_replays_and_preserves_bits() {
        let mut window = DtlsReplayWindow::new();
        assert!(!window.has_seen(100)); // empty window has seen nothing

        window.mark_seen(10);
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11)); // future sequence
        assert!(!window.has_seen(9)); // older, never marked

        window.mark_seen(12); // newer: window slides left by two, bit 2 holds 10
        assert!(window.has_seen(12));
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11)); // gap stays unseen
        assert!(!window.has_seen(9)); // beyond the marked bits, still unseen
        assert!(!window.has_seen(13)); // future

        window.mark_seen(11); // older within window: fills the gap
        assert!(window.has_seen(11));
        assert!(window.has_seen(10)); // neighbouring bits untouched
        assert!(window.has_seen(12));
    }

    #[test]
    fn replay_window_handles_window_edges() {
        // An older sequence two positions back must set bit two, distinguishing
        // subtraction from division/addition in the offset computation.
        let mut window = DtlsReplayWindow::new();
        window.mark_seen(20);
        window.mark_seen(18);
        assert!(window.has_seen(18));
        assert!(!window.has_seen(19));
        assert!(window.has_seen(20));

        // A jump of exactly the window width resets the bitmap to the newest
        // sequence only. The boundary checks keep the 64-bit shifts in range.
        let width = u64::BITS as u64;
        let mut window = DtlsReplayWindow::new();
        window.mark_seen(1);
        window.mark_seen(1 + width); // shift == 64 resets rather than shifting
        assert!(window.has_seen(1 + width));
        assert!(window.has_seen(1)); // offset == 64 is treated as too old to trust
        assert!(!window.has_seen(2)); // within the fresh window but never marked
        window.mark_seen(1); // offset == 64 must be a no-op, not a 1 << 64 shift
        assert!(!window.has_seen(2));
    }

    fn test_key_material() -> ThreadDtlsKeyMaterial {
        ThreadDtlsKeyMaterial {
            master_secret: [0x11; 48],
            key_block: Tls12Aes128Ccm8KeyBlock {
                client_write_key: [0x21; 16],
                server_write_key: [0x32; 16],
                client_write_iv: [0x43; 4],
                server_write_iv: [0x54; 4],
            },
        }
    }
}
