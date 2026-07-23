//! In-process DTLS loopback server shared by dtls and commissioner tests.

use tokio::net::UdpSocket;

use crate::{Error, Result, crypto::RecordProtectionKey};

use super::{
    ContentType, DTLS_1_2_VERSION, DtlsCookieGenerator, DtlsRecord, HandshakeMessage,
    HandshakeType, HelloVerifyRequest, ThreadDtlsKeyMaterial, ThreadDtlsServerHandshake,
    hello::ClientHello, open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record, protect_aes_128_ccm_8_record,
};

/// How the loopback server finishes the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopbackEnd {
    /// Complete the handshake and return the session keys.
    Complete,
    /// Send a fatal alert instead of the ChangeCipherSpec + Finished flight.
    AlertInsteadOfFinished,
}

/// Serves one commissioner DTLS handshake over a connected UDP socket.
///
/// Returns the negotiated key material when the handshake completes.
pub(crate) async fn loopback_dtls_server(
    socket: &UdpSocket,
    psk: &[u8],
    end: LoopbackEnd,
) -> Result<Option<ThreadDtlsKeyMaterial>> {
    let mut rng = rand_core::OsRng;
    let mut server = ThreadDtlsServerHandshake::new(psk, &mut rng);
    let cookies = DtlsCookieGenerator::new(&mut rng);
    let mut buf = [0u8; 4096];
    let mut epoch0_seq = 0u64;
    let mut saw_change_cipher_spec = false;
    let mut key_material: Option<ThreadDtlsKeyMaterial> = None;

    loop {
        let len = tokio::time::timeout(core::time::Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout("loopback server receive timed out"))??;
        for record in DtlsRecord::parse_datagram(&buf[..len])? {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::Handshake) => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        match message.message_type {
                            HandshakeType::ClientHello => {
                                let hello = ClientHello::decode(&message.payload)?;
                                if !cookies.verify(&hello.random, &hello.cookie) {
                                    let verify = HandshakeMessage {
                                        message_type: HandshakeType::HelloVerifyRequest,
                                        message_seq: message.message_seq,
                                        payload: HelloVerifyRequest {
                                            server_version: DTLS_1_2_VERSION,
                                            cookie: cookies.cookie(&hello.random)?.to_vec(),
                                        }
                                        .encode()?,
                                    };
                                    let record = DtlsRecord::new(
                                        ContentType::Handshake,
                                        0,
                                        epoch0_seq,
                                        verify.encode()?,
                                    )?;
                                    epoch0_seq += 1;
                                    socket.send(&record.encode()?).await?;
                                    continue;
                                }
                                server.handle_client_hello(&message)?;
                                let mut datagram = Vec::new();
                                for built in [
                                    server.build_server_hello(1)?,
                                    server.build_server_key_exchange(2, &mut rng)?,
                                    server.build_server_hello_done(3)?,
                                ] {
                                    let record = DtlsRecord::new(
                                        ContentType::Handshake,
                                        0,
                                        epoch0_seq,
                                        built.encode()?,
                                    )?;
                                    epoch0_seq += 1;
                                    datagram.extend_from_slice(&record.encode()?);
                                }
                                socket.send(&datagram).await?;
                            }
                            HandshakeType::ClientKeyExchange => {
                                server.handle_client_key_exchange(&message)?;
                                key_material = Some(server.derive_key_material()?);
                            }
                            other => {
                                return Err(Error::Crypto(format!(
                                    "loopback server got {other:?}"
                                )));
                            }
                        }
                    }
                }
                (0, ContentType::ChangeCipherSpec) => saw_change_cipher_spec = true,
                (1, ContentType::Handshake) => {
                    let keys = key_material
                        .as_ref()
                        .ok_or(Error::InvalidState("no key material"))?;
                    if !saw_change_cipher_spec {
                        return Err(Error::Crypto(
                            "client Finished before ChangeCipherSpec".to_string(),
                        ));
                    }
                    if end == LoopbackEnd::AlertInsteadOfFinished {
                        let alert =
                            DtlsRecord::new(ContentType::Alert, 0, epoch0_seq, vec![2, 40])?;
                        socket.send(&alert.encode()?).await?;
                        return Ok(None);
                    }
                    let plaintext = open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(keys.key_block.client_write_key),
                        &keys.key_block.client_write_iv,
                    )?;
                    let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
                    let finished = parse_unfragmented_handshake_record(
                        &plain_record,
                        HandshakeType::Finished,
                    )?;
                    server.verify_client_finished(&finished, keys)?;
                    let server_finished = server.build_server_finished(4, keys)?;
                    let mut datagram =
                        DtlsRecord::new(ContentType::ChangeCipherSpec, 0, epoch0_seq, vec![1])?
                            .encode()?;
                    datagram.extend_from_slice(
                        &protect_aes_128_ccm_8_record(
                            ContentType::Handshake,
                            1,
                            0,
                            RecordProtectionKey::new(keys.key_block.server_write_key),
                            &keys.key_block.server_write_iv,
                            &server_finished.encode()?,
                        )?
                        .encode()?,
                    );
                    socket.send(&datagram).await?;
                    return Ok(key_material);
                }
                _ => {}
            }
        }
    }
}
