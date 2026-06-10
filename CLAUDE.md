# CLAUDE.md

The canonical working agreement for this repo lives in `AGENTS.md` (environment
variables, Rust conventions, coverage/mutation expectations, live-test gating,
tooling preferences). Read it and treat it as authoritative.

@AGENTS.md

The notes below are an orientation map; they do not override `AGENTS.md`.

## What this crate is

`ot-commissioner-rs` is a pure-Rust Thread MeshCoP commissioner with the
non-CCM feature set of the C++ `ot-commissioner` reference (matrix in
`docs/PARITY.md`). It establishes a Thread DTLS 1.2 session authenticated with
EC J-PAKE over PSKc, petitions a border agent, keeps the session alive,
reads/writes operational and commissioner datasets, routes MGMT commands and
network diagnostics through the UDP_TX/UDP_RX proxy (ALOC addressing), and
commissions joiners over the relay (DTLS server over PSKd, JOIN_FIN, KEK
entrustment). Crypto is built on small RustCrypto crates — no OpenSSL or
mbedTLS at runtime.

## Reference specifications

- Thread 1.4.0 specification — the wire formats, MeshCoP CoAP resources, dataset
  TLVs, and security policy bits implemented here.
- RFC 8236 (J-PAKE) and RFC 8235 (Schnorr NIZK) — the EC J-PAKE handshake in
  `src/crypto/ecjpake/` follows the EC form of both.
- OpenThread `ot-commissioner` (github.com/openthread/ot-commissioner) — the C++
  reference implementation, used for parity and as a source of test vectors. The
  `tools/mbedtls_*.c` harnesses and the mbedTLS reference vector in the
  `crypto/ecjpake` tests come from this lineage.

## Module map (`src/`)

- `tlv.rs` — Thread TLV codec. Preserves wire order, duplicates, unknown types,
  and supports the extended (0xff) length form. Foundation for everything else.
- `dataset.rs` — Operational dataset (`Dataset` = active/pending alias) built on
  `TlvSet`, with typed accessors (channel, PAN ID, security policy, timestamps,
  channel mask, …) that validate lengths.
- `crypto/`
  - `ecjpake/` — EC J-PAKE party + Schnorr NIZK over P-256, split into the
    protocol state machine and shared P-256 helpers (`mod.rs`), the Schnorr
    proof gen/verify (`schnorr.rs`), and the TLS `ECJPAKEKeyKPPairList` /
    key-exchange codecs (`codec.rs`).
  - `pskc.rs` — PSKc via PBKDF2-AES-CMAC-PRF-128, joiner ID, steering-data
    Bloom filter.
  - `record.rs` — AES-CCM-8 record protection key + nonce helpers.
- `dtls/` — DTLS 1.2 profile. `thread_handshake.rs` is the runtime-neutral
  client handshake state machine and `thread_server_handshake.rs` its server
  counterpart (used for joiner sessions; includes HelloVerifyRequest cookies
  and Joiner Router KEK export); `session.rs` is the Tokio driver
  (`DtlsSession::connect`). Record framing, the TLS 1.2 PRF key schedule, and
  AES-128-CCM-8 record protection live in sibling files.
- `meshcop/` — CoAP codec (`coap.rs`), MeshCoP request builders (`builders.rs`,
  incl. UDP_TX/RLY_TX encapsulation), response/notification parsers
  (`parsers.rs`, incl. UDP_RX decapsulation), URI + TLV constants, and the
  dataset-flag → TLV-type mapping (`flags.rs`). The network-diagnostic data
  model lives in `diag/` (`model.rs` types, `decode.rs` wire decoders,
  `diag_flags.rs` request flags, `NetDiagData`).
- `commissioner/` — Async public API. `client/` holds `Commissioner`, split by
  concern: `mod.rs` (struct, connect, lifecycle, shared helpers), `datasets.rs`
  (operational/commissioner/BBR dataset get/set), `commands.rs` (announce/scan/
  PAN-ID and managed-device commands), `diagnostics.rs` (network-diagnostic
  queries), `relay.rs` (joiner relay handling), and `transport.rs` (DTLS session,
  request/response routing, mesh-local-prefix/ALOC routing, UDP-proxy
  encapsulation). `joiner.rs` holds the joiner session state machine plus
  `JoinerHandler` / `StaticJoinerHandler`. `harness.rs` is a test-only scripted
  MeshCoP transport that exercises the production incoming-message loop.
- `error.rs` — Crate-wide `thiserror` `Error`/`Result`.

## Conventions and gotchas worth knowing

- Secrets (PSKc, J-PAKE scalars, datasets) are redacted in `Debug` and zeroized
  on drop. Examples redact dataset fields unless `--show-secrets` is passed.
- Live border-router tests are `#[ignore]` and require a real agent plus
  `ESP_MATTER_TEST_THREAD_DATASET_HEX`; they must not leak secrets.
- Mutating CLI/example operations are gated behind `OT_COMMISSIONER_MUTATE_OK=1`.
- CCM (token/certificate) flows are intentionally deferred and return
  `Error::Unsupported`.
- `OT_COMMISSIONER_TRACE` / `dtls_trace*` print non-secret protocol traces to
  stderr.

## Verify (must pass before work is "done", per AGENTS.md)

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

`tools/ci/coverage.sh` (cargo-llvm-cov) and `tools/ci/mutants.sh`
(cargo-mutants) back the coverage and mutation gates in
`.github/workflows/quality.yml`.

## Supply chain

`cargo audit --deny warnings` (advisories) and `cargo deny check` (licenses,
bans, sources; config in `deny.toml`) gate the dependency graph in the
`supply-chain` job of `.github/workflows/quality.yml`.

## Fuzzing

Coverage-guided fuzz harnesses for every wire parser live in the isolated
`fuzz/` crate (libfuzzer). It is excluded from the stable workspace and requires
nightly, so it never gates normal PRs:

```sh
cargo +nightly fuzz run <target> -- -max_total_time=60   # e.g. dtls_record
cargo +nightly fuzz list                                 # all targets
```

`.github/workflows/fuzz.yml` runs every target weekly and on demand.
