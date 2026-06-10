# Surviving mutants (review notes)

`cargo-mutants` is run against the high-risk protocol files (see
`tools/ci/mutants.sh`, `targeted` scope). The survivors below are documented
as equivalent or intrinsic per the working agreement; the rest of the catalog
is killed by the test suite.

## Equivalent mutants (no input distinguishes them)

- `src/dtls/handshake.rs` `HandshakeHeader::validate`, second `||` → `&&`.
  A sole `fragment_length > MAX_U24` is unreachable: the follow-up
  `fragment_offset + fragment_length > length` check already rejects it, and
  any `fragment_length > MAX_U24` forces `length > MAX_U24` too. So the two
  forms accept and reject exactly the same inputs.
- `src/dtls/session.rs` `DtlsReplayWindow::mark_seen`, `>` → `>=` and `| 1` →
  `^ 1`. Both only matter in the `sequence > newest` branch, where the shift
  is ≥ 1: the shifted bit 0 is always 0, so `^ 1` equals `| 1`, and a
  `sequence == newest` repeat re-sets an already-set bit either way.
- `src/meshcop/diag/diag_flags.rs` `EXT_MAC_ADDR = 1 << 0` → `1 >> 0`. A shift by zero is identity.
- `src/meshcop/diag/decode.rs` `decode_child_table`, `<< 8 | low` → `<< 8 ^ low`.
  The 9th child-ID bit (`<< 8`) and the low byte occupy disjoint bit ranges,
  so `|` and `^` produce the same value.
- `src/commissioner/joiner.rs` `JoinerHandler::on_joiner_connected` default
  `→ ()` and `on_joiner_finalize` default `→ true`. The provided defaults are
  already a no-op and a constant `true`, so the mutations are byte-for-byte
  equivalent.

## Intrinsic / unobservable

- `src/commissioner/joiner.rs` `Drop for StaticJoinerHandler` → `()`. The drop
  body only zeroizes PSKd bytes; removing it has no observable functional
  behavior (it is a defense-in-depth secret-hygiene step, not a contract a
  behavioral test can assert).
- `src/commissioner/client/mod.rs` `commissioner_trace` → `()`. Tracing is a
  best-effort `eprintln!` gated on `OT_COMMISSIONER_TRACE`; it carries no
  program logic.
- `src/commissioner/client/relay.rs` `handle_relay_rx`, `!expired` in the sweep
  `retain`. Killing this requires injecting a synthetic clock into the
  commissioner; the joiner-session expiry boundary itself is covered by
  `JoinerSession::expired` unit tests. Deferred until the commissioner takes
  an injectable time source.

## Intrinsic timeouts

- `src/dtls/session.rs:248` `recv_records → Ok(vec![])` and
  `src/meshcop/diag/decode.rs` `NetworkDataTlvIter::next` advance `+` → `-`/`*`.
  These turn a bounded loop into a non-terminating one; `cargo-mutants`
  reports them as timeouts rather than misses, which already signals the
  tests detect the broken behavior (the suite hangs rather than passing).
