//! Two-board ESP32-H2 Thread-profile DTLS demo over raw IEEE 802.15.4.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::expect_used, clippy::unwrap_used)]

extern crate alloc;

#[cfg(feature = "role-client")]
use alloc::format;
#[cfg(feature = "role-server")]
use alloc::vec::Vec;
use core::{str, time::Duration};

use embassy_executor::Spawner;
use embassy_time::{Delay, Timer};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    rng::{Trng, TrngSource},
    timer::timg::TimerGroup,
};
use esp_println::println;
#[cfg(feature = "role-client")]
use thread_dtls::DtlsClient;
#[cfg(feature = "role-server")]
use thread_dtls::DtlsServer;

#[cfg(feature = "role-client")]
use crate::config::CLIENT_SHORT_ADDRESS;
use crate::{
    config::{CHANNEL, DEMO_PSKC, SERVER_SHORT_ADDRESS, socket_addr},
    radio::RadioDatagram,
};

mod config;
mod radio;

#[cfg(all(feature = "role-server", feature = "role-client"))]
compile_error!("enable exactly one of `role-server` or `role-client`, not both");
#[cfg(not(any(feature = "role-server", feature = "role-client")))]
compile_error!("enable exactly one of `role-server` or `role-client`");

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const APPLICATION_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "role-client")]
const CLIENT_RETRY_DELAY: embassy_time::Duration = embassy_time::Duration::from_secs(3);
#[cfg(feature = "role-client")]
const CLIENT_MESSAGE_INTERVAL: embassy_time::Duration = embassy_time::Duration::from_secs(2);
#[cfg(feature = "role-server")]
const SERVER_RETRY_DELAY: embassy_time::Duration = embassy_time::Duration::from_millis(250);

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) -> ! {
    let hal_config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(hal_config);

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);

    let timer_group = TimerGroup::new(peripherals.TIMG0);
    let software_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timer_group.timer0, software_interrupt.software_interrupt0);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let rng = match Trng::try_new() {
        Ok(rng) => rng,
        Err(error) => {
            println!("fatal: could not start hardware TRNG: {:?}", error);
            loop {
                Timer::after(embassy_time::Duration::from_secs(1)).await;
            }
        }
    };

    #[cfg(feature = "role-server")]
    {
        println!(
            "ESP32-H2 DTLS demo: role=server short=0x{:04x} channel={}",
            SERVER_SHORT_ADDRESS, CHANNEL
        );
        let radio = RadioDatagram::new(peripherals.IEEE802154, SERVER_SHORT_ADDRESS);
        run_server(radio, rng).await
    }

    #[cfg(feature = "role-client")]
    {
        println!(
            "ESP32-H2 DTLS demo: role=client short=0x{:04x} channel={}",
            CLIENT_SHORT_ADDRESS, CHANNEL
        );
        let radio = RadioDatagram::new(peripherals.IEEE802154, CLIENT_SHORT_ADDRESS);
        run_client(radio, rng).await
    }
}

#[cfg(feature = "role-server")]
async fn run_server(mut radio: RadioDatagram<'_>, mut rng: Trng) -> ! {
    let local = socket_addr(SERVER_SHORT_ADDRESS);
    let mut attempt = 1u32;
    loop {
        println!("server: waiting for client (accept attempt {})", attempt);
        let server = DtlsServer::new(&mut radio, Delay, local);
        match server
            .accept_with_rng(&mut rng, &DEMO_PSKC, HANDSHAKE_TIMEOUT)
            .await
        {
            Ok(mut session) => {
                println!("server: DTLS established with {}", session.peer_addr());
                loop {
                    match session.recv_application_data(APPLICATION_TIMEOUT).await {
                        Ok(payload) => {
                            log_application_payload("server: received", &payload);
                            let mut response = Vec::with_capacity(5 + payload.len());
                            response.extend_from_slice(b"ack: ");
                            response.extend_from_slice(&payload);
                            if let Err(error) = session.send_application_data(&response).await {
                                println!("server: send failed, restarting session: {}", error);
                                break;
                            }
                        }
                        Err(error) => {
                            println!("server: session ended, listening again: {}", error);
                            break;
                        }
                    }
                }
            }
            Err(error) => println!("server: accept attempt failed: {}", error),
        }
        attempt = attempt.wrapping_add(1);
        Timer::after(SERVER_RETRY_DELAY).await;
    }
}

#[cfg(feature = "role-client")]
async fn run_client(mut radio: RadioDatagram<'_>, mut rng: Trng) -> ! {
    let local = socket_addr(CLIENT_SHORT_ADDRESS);
    let peer = socket_addr(SERVER_SHORT_ADDRESS);
    let mut connection_attempt = 1u32;
    let mut message_counter = 0u32;

    loop {
        println!(
            "client: connecting to {} (attempt {})",
            peer, connection_attempt
        );
        let client = DtlsClient::new(&mut radio, Delay, local, peer);
        match client
            .connect_with_rng(&mut rng, &DEMO_PSKC, HANDSHAKE_TIMEOUT)
            .await
        {
            Ok(mut session) => {
                println!("client: DTLS established with {}", session.peer_addr());
                loop {
                    Timer::after(CLIENT_MESSAGE_INTERVAL).await;
                    let message = format!("hello {}", message_counter);
                    println!("client: sending {}", message);

                    match session
                        .request_application_data(message.as_bytes(), APPLICATION_TIMEOUT)
                        .await
                    {
                        Ok(response) => {
                            let expected = format!("ack: {}", message);
                            if response == expected.as_bytes() {
                                println!("client: round trip ok: {}", expected);
                            } else {
                                log_application_payload("client: unexpected response", &response);
                            }
                            message_counter = message_counter.wrapping_add(1);
                        }
                        Err(error) => {
                            println!("client: round trip failed, reconnecting: {}", error);
                            break;
                        }
                    }
                }
            }
            Err(error) => println!("client: connect attempt failed: {}", error),
        }
        connection_attempt = connection_attempt.wrapping_add(1);
        Timer::after(CLIENT_RETRY_DELAY).await;
    }
}

fn log_application_payload(prefix: &str, payload: &[u8]) {
    match str::from_utf8(payload) {
        Ok(text) => println!("{}: {}", prefix, text),
        Err(_) => println!(
            "{}: <non-UTF-8 application data, {} bytes>",
            prefix,
            payload.len()
        ),
    }
}
