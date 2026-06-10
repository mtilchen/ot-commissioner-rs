use super::*;

#[test]
fn coap_round_trip_with_options_and_payload() {
    let msg = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 0x1234,
        token: vec![1, 2, 3, 4],
        options: vec![
            CoapOption {
                number: 11,
                value: b"c".to_vec(),
            },
            CoapOption {
                number: 15,
                value: b"meshcop".to_vec(),
            },
        ],
        payload: vec![0xde, 0xad, 0xbe, 0xef],
    };

    let encoded = msg.encode().unwrap();
    assert_eq!(CoapMessage::decode(&encoded).unwrap(), msg);
}

#[test]
fn coap_decoder_rejects_malformed_inputs() {
    let cases = [
        ("truncated header", vec![0x40, 0x02, 0x00]),
        ("unsupported version", vec![0x00, 0x02, 0x00, 0x01]),
        ("invalid token length", vec![0x49, 0x02, 0x00, 0x01]),
        (
            "truncated option extension",
            vec![0x40, 0x02, 0x00, 0x01, 0xd0],
        ),
        ("reserved option nibble", vec![0x40, 0x02, 0x00, 0x01, 0xf0]),
        (
            "truncated option value",
            vec![0x40, 0x02, 0x00, 0x01, 0x02, 0xaa],
        ),
        (
            "overflowing option extension",
            vec![0x40, 0x02, 0x00, 0x01, 0xe0, 0xff, 0xff],
        ),
    ];

    for (name, bytes) in cases {
        assert!(CoapMessage::decode(&bytes).is_err(), "{name}");
    }
}

#[test]
fn uri_path_options_round_trip_in_segment_order() {
    let msg = CoapMessage::post_request(
        CoapType::Confirmable,
        1,
        [0xaa],
        uri::MGMT_ACTIVE_GET,
        Vec::new(),
    )
    .unwrap();

    let decoded = CoapMessage::decode(&msg.encode().unwrap()).unwrap();
    assert_eq!(decoded.uri_path().unwrap(), Some("/c/ag".to_string()));
}

#[test]
fn uri_path_rejects_empty_segments_and_non_utf8_options() {
    assert!(CoapMessage::post_request(CoapType::Confirmable, 1, [], "/c//ag", Vec::new()).is_err());

    let msg = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 1,
        token: Vec::new(),
        options: vec![CoapOption {
            number: COAP_OPTION_URI_PATH,
            value: vec![0xff],
        }],
        payload: Vec::new(),
    };

    assert!(msg.uri_path().is_err());
}

#[test]
fn commissioner_operation_uris_match_openthread() {
    let cases = [
        (CommissionerOperation::Petition, "/c/cp"),
        (CommissionerOperation::KeepAlive, "/c/ca"),
        (CommissionerOperation::GetCommissionerDataset, "/c/cg"),
        (CommissionerOperation::SetCommissionerDataset, "/c/cs"),
        (CommissionerOperation::GetActiveDataset, "/c/ag"),
        (CommissionerOperation::SetActiveDataset, "/c/as"),
        (CommissionerOperation::GetPendingDataset, "/c/pg"),
        (CommissionerOperation::SetPendingDataset, "/c/ps"),
        (CommissionerOperation::SetSecurePendingDataset, "/c/sp"),
        (CommissionerOperation::GetBbrDataset, "/c/bg"),
        (CommissionerOperation::SetBbrDataset, "/c/bs"),
        (CommissionerOperation::AnnounceBegin, "/c/ab"),
        (CommissionerOperation::PanIdQuery, "/c/pq"),
        (CommissionerOperation::EnergyScan, "/c/es"),
        (CommissionerOperation::RegisterMulticastListener, "/n/mr"),
        (CommissionerOperation::Reenroll, "/c/re"),
        (CommissionerOperation::DomainReset, "/c/rt"),
        (CommissionerOperation::Migrate, "/c/nm"),
        (CommissionerOperation::DiagnosticGet, "/d/dq"),
        (CommissionerOperation::DiagnosticReset, "/d/dr"),
        (CommissionerOperation::SendToJoiner, "/c/tx"),
    ];

    for (operation, expected) in cases {
        assert_eq!(operation.uri_path(), expected);
    }
}

#[test]
fn petition_request_carries_commissioner_id() {
    let msg = petition_request(0x1111, [1, 2], "ot-commissioner-rs").unwrap();
    assert_eq!(msg.uri_path().unwrap(), Some("/c/cp".to_string()));

    let tlvs = TlvSet::parse(&msg.payload).unwrap();
    assert_eq!(
        tlvs.last_value(TLV_COMMISSIONER_ID),
        Some(&b"ot-commissioner-rs"[..])
    );
}

#[test]
fn keep_alive_and_resign_state_values_are_encoded() {
    let keep_alive = keep_alive_request(1, [], 0xabcd, true).unwrap();
    let resign = keep_alive_request(2, [], 0xabcd, false).unwrap();
    let keep_alive_tlvs = TlvSet::parse(&keep_alive.payload).unwrap();
    let resign_tlvs = TlvSet::parse(&resign.payload).unwrap();

    assert_eq!(keep_alive_tlvs.last_value(TLV_STATE), Some(&[1][..]));
    assert_eq!(resign_tlvs.last_value(TLV_STATE), Some(&[0xff][..]));
    assert_eq!(
        keep_alive_tlvs.last_value(TLV_COMMISSIONER_SESSION_ID),
        Some(&[0xab, 0xcd][..])
    );
}

#[test]
fn dataset_get_and_set_requests_use_get_and_session_tlvs() {
    let get = dataset_get_request(
        CommissionerOperation::GetActiveDataset,
        1,
        [],
        &[TLV_ACTIVE_TIMESTAMP, DATASET_TLV_NETWORK_NAME],
    )
    .unwrap();
    let get_tlvs = TlvSet::parse(&get.payload).unwrap();
    assert_eq!(
        get_tlvs.last_value(TLV_GET),
        Some(&[TLV_ACTIVE_TIMESTAMP, DATASET_TLV_NETWORK_NAME][..])
    );

    let dataset =
        Dataset::from_bytes(&[DATASET_TLV_NETWORK_NAME, 4, b't', b'e', b's', b't']).unwrap();
    let set = dataset_set_request(
        CommissionerOperation::SetCommissionerDataset,
        2,
        [],
        0x1234,
        &dataset,
    )
    .unwrap();
    let set_tlvs = TlvSet::parse(&set.payload).unwrap();
    assert_eq!(
        set_tlvs.last_value(TLV_COMMISSIONER_SESSION_ID),
        Some(&[0x12, 0x34][..])
    );
    assert_eq!(
        set_tlvs.last_value(DATASET_TLV_NETWORK_NAME),
        Some(&b"test"[..])
    );
}

#[test]
fn dataset_flag_mapping_uses_openthread_present_flag_bits() {
    assert_eq!(
        active_dataset_tlv_types((1 << 15) | (1 << 9)),
        vec![TLV_ACTIVE_TIMESTAMP, DATASET_TLV_NETWORK_NAME]
    );
    assert_eq!(
        pending_dataset_tlv_types((1 << 5) | (1 << 4)),
        vec![
            crate::dataset::TLV_DELAY_TIMER,
            crate::dataset::TLV_PENDING_TIMESTAMP
        ]
    );
    assert_eq!(
        commissioner_dataset_tlv_types((1 << 13) | (1 << 10)),
        vec![TLV_STEERING_DATA, TLV_JOINER_UDP_PORT]
    );
}

#[test]
fn query_builders_encode_channel_mask_and_command_fields() {
    let announce = announce_begin_request(1, [], 0x1111, 0x07fff800, 3, 200, false).unwrap();
    assert_eq!(announce.ty, CoapType::NonConfirmable);
    assert_eq!(announce.uri_path().unwrap(), Some("/c/ab".to_string()));
    let announce_tlvs = TlvSet::parse(&announce.payload).unwrap();
    assert_eq!(announce_tlvs.last_value(TLV_COUNT), Some(&[3][..]));
    assert_eq!(announce_tlvs.last_value(TLV_PERIOD), Some(&[0, 200][..]));
    assert_eq!(
        announce_tlvs.last_value(TLV_CHANNEL_MASK),
        Some(&[0, 4, 0x07, 0xff, 0xf8, 0x00][..])
    );

    let pan_id = pan_id_query_request(2, [], 0x1111, 0x07fff800, 0xface, true).unwrap();
    let pan_id_tlvs = TlvSet::parse(&pan_id.payload).unwrap();
    assert_eq!(pan_id_tlvs.last_value(TLV_PAN_ID), Some(&[0xfa, 0xce][..]));

    let energy = energy_scan_request(
        3,
        [],
        0x1111,
        EnergyScanRequest {
            channel_mask: 0x07fff800,
            count: 2,
            period_ms: 100,
            scan_duration_ms: 50,
            confirmable: true,
        },
    )
    .unwrap();
    let energy_tlvs = TlvSet::parse(&energy.payload).unwrap();
    assert_eq!(
        energy_tlvs.last_value(TLV_SCAN_DURATION),
        Some(&[0, 50][..])
    );
}
