#![no_main]

use libfuzzer_sys::fuzz_target;
use ot_commissioner_rs::tlv::{TlvSet, parse_one};

// Thread TLV decoding: single-entry and full-stream parsing must never panic,
// and a parsed set must survive an encode/parse round-trip with equal entries.
fuzz_target!(|data: &[u8]| {
    let _ = parse_one(data);

    if let Ok(set) = TlvSet::parse(data) {
        if let Ok(encoded) = set.encode() {
            let reparsed = TlvSet::parse(&encoded).expect("re-encoded TlvSet must parse");
            assert_eq!(set, reparsed);
        }
    }
});
