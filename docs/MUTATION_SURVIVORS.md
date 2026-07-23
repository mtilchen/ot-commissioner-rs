# Surviving mutants (review notes)

`cargo-mutants` is run against the high-risk protocol files (see
`tools/ci/mutants.sh`, `targeted` scope). The survivors below are documented
with their specific equivalence, observability, diagnostic-contract,
infrastructure, or non-termination rationale; the rest of the catalog is
killed by the test suite.

## Equivalent mutants (no input distinguishes them)

- `crates/thread-dtls/src/handshake.rs` `HandshakeHeader::validate`, second `||` → `&&`.
  A sole `fragment_length > MAX_U24` is unreachable: the follow-up
  `fragment_offset + fragment_length > length` check already rejects it, and
  any `fragment_length > MAX_U24` forces `length > MAX_U24` too. So the two
  forms accept and reject exactly the same inputs.
- `crates/thread-dtls/src/session.rs` `DtlsReplayWindow::mark_seen`, `>` → `>=` and `| 1` →
  `^ 1`. Both only matter in the `sequence > newest` branch, where the shift
  is ≥ 1: the shifted bit 0 is always 0, so `^ 1` equals `| 1`, and a
  `sequence == newest` repeat re-sets an already-set bit either way.
- `crates/ot-commissioner-rs/src/meshcop/diag/diag_flags.rs` `EXT_MAC_ADDR = 1 << 0` → `1 >> 0`. A shift by zero is identity.
- `crates/ot-commissioner-rs/src/meshcop/diag/decode.rs` `decode_child_table`, `<< 8 | low` → `<< 8 ^ low`.
  The 9th child-ID bit (`<< 8`) and the low byte occupy disjoint bit ranges,
  so `|` and `^` produce the same value.
- `crates/ot-commissioner-rs/src/meshcop/coap.rs` CoAP header composition, `|` → `^`. The version, type,
  and token-length values occupy disjoint bit fields after their bounds are
  validated, so OR and XOR produce the same byte.
- `crates/ot-commissioner-rs/src/meshcop/coap.rs` option-header composition, `|` → `^`. The delta and
  length values occupy disjoint four-bit nibbles, so OR and XOR are identical.
- `crates/ot-commissioner-rs/src/commissioner/joiner.rs` `JoinerHandler::on_joiner_connected` default
  `→ ()` and `on_joiner_finalize` default `→ true`. The provided defaults are
  already a no-op and a constant `true`, so the mutations are byte-for-byte
  equivalent.

## Intrinsic / unobservable

- `crates/thread-dtls/src/ecjpake/mod.rs` `Drop for EcJpakeParty` → `()`. The body only
  zeroizes private scalars immediately before their storage is freed; observing
  the mutation would require reading freed memory with unsafe code.

## Intentionally uncontracted diagnostics

- `crates/ot-commissioner-rs/src/commissioner/client/mod.rs` `commissioner_trace` → `()`. Tracing is a
  best-effort `eprintln!` gated on `OT_COMMISSIONER_TRACE`. Its text and
  presence are deliberately not part of the program's behavioral contract.

## Deferred infrastructure-bound behavior

- `crates/ot-commissioner-rs/src/commissioner/client/relay.rs` `handle_relay_rx`, `!expired` in the sweep
  `retain`. Killing this requires injecting a synthetic clock into the
  commissioner; the joiner-session expiry boundary itself is covered by
  `JoinerSession::expired` unit tests. Deferred until the commissioner takes
  an injectable time source.

## Intrinsic timeouts

- `crates/thread-dtls/src/session.rs:248` `recv_records → Ok(vec![])` and
  `crates/ot-commissioner-rs/src/meshcop/diag/decode.rs` `NetworkDataTlvIter::next` advance `+` → `-`/`*`.
  These turn a bounded loop into a non-terminating one; `cargo-mutants`
  reports them as timeouts rather than misses, which already signals the
  tests detect the broken behavior (the suite hangs rather than passing).
