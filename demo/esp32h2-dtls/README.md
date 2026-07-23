# ESP32-H2 two-board DTLS demo

This firmware runs the `thread-dtls` embedded client and server drivers on two
ESP32-H2 devkits. It carries DTLS datagrams directly in fragmented raw IEEE
802.15.4 data frames. It deliberately does **not** run a Thread network stack:
the point of the demo is to exercise this repository's DTLS layer over the H2
radio.

The firmware uses the raw-frame module in `esp-radio`, which replaced the
standalone `esp-ieee802154` crate in the current stable Espressif project
generator and is compatible with `esp-hal` 1.1.

The credential compiled into the firmware is only for this desk demo. Do not
reuse it in another environment.

## Prerequisites

Install a current stable Rust toolchain, the H2 target, and `espflash`:

```console
rustup target add riscv32imac-unknown-none-elf
rustup component add rust-src
cargo install espflash
```

## Build and flash

Build each role from this directory. Exactly one role feature must be enabled:

```console
cargo build --release --features role-server
cargo build --release --features role-client
```

Connect the board that will be the server, build that role, and flash it
(`--port` can select a board when more than one is connected):

```console
cargo build --release --features role-server
espflash flash --monitor --chip esp32h2 \
  target/riscv32imac-unknown-none-elf/release/esp32h2-dtls-demo
```

Then connect the client board and do the same for its role:

```console
cargo build --release --features role-client
espflash flash --monitor --chip esp32h2 \
  target/riscv32imac-unknown-none-elf/release/esp32h2-dtls-demo
```

The server build uses short address `0x0001`; the client uses `0x0002`.
Because both feature builds use the same output filename, flash or copy the
first artifact before building the other role. The configured Cargo runner
also permits `cargo run --release --features role-server` (or `role-client`).

## Fixed radio settings

| Setting | Value |
| --- | --- |
| Channel | 15 |
| PAN ID | `0x2ee7` |
| Server short address | `0x0001` |
| Client short address | `0x0002` |
| Synthetic UDP port | `0x2ee7` |

A short address `S` is presented to `thread-dtls` as
`10.0.0.(S as u8):0x2ee7`; the adapter rejects addresses outside the demo
mapping rather than using a real IP stack.

## Expected output

Once both boards are running, the server monitor should resemble:

```text
ESP32-H2 DTLS demo: role=server short=0x0001 channel=15
server: waiting for client (accept attempt 1)
server: DTLS established with 10.0.0.2:12007
server: received: hello 0
server: received: hello 1
```

The client should resemble:

```text
ESP32-H2 DTLS demo: role=client short=0x0002 channel=15
client: connecting to 10.0.0.1:12007 (attempt 1)
client: DTLS established with 10.0.0.1:12007
client: sending hello 0
client: round trip ok: ack: hello 0
```

The PSKc, derived keys, and raw handshake bytes are never logged.

## Fragmentation and first-hardware caveats

The IEEE 802.15.4 PHY permits 127 bytes per frame. These frames use a 9-byte
short-address MAC header (PAN compression enabled) and a 2-byte FCS, leaving
116 payload bytes. The adapter uses four bytes for
`[magic, datagram_sequence, fragment_index, fragment_count]`, so every
non-final fragment carries 112 DTLS bytes.

Reassembly accepts out-of-order fragments and ignores duplicates, but it is
intentionally lossy: there is no fragment-level retransmission. A new datagram
sequence from a source drops that source's incomplete datagram; sequence
wraparound has the same behavior. MAC acknowledgements and clear-channel
assessment are enabled, and each fragment waits for the radio's success or
failure callback before the next fragment is submitted. The DTLS driver retries
whole connection attempts rather than individual handshake flights.

On first hardware, keep the boards close, verify both report channel 15 and the
intended short addresses, and watch for transmit timeouts or repeated
connection attempts. Nearby 802.15.4 traffic on channel 15 can still cause loss
even though hardware address filtering is enabled.
