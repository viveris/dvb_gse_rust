// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

use std::vec;

use crate::crc::{CrcCalculator, DefaultCrc};
use crate::gse_decap::{
    read_gse_header, DecapContext, DecapError, DecapMetadata, DecapStatus, Decapsulator,
};
use crate::gse_standard::{
    COMPLETE_PKT, CRC_LEN, END_PKT, FIRST_PKT, FIXED_HEADER_LEN, FRAG_ID_LEN, INTERMEDIATE_PKT,
    LABEL_3_B, LABEL_3_B_LEN, LABEL_6_B, LABEL_6_B_LEN, LABEL_BROADCAST, LABEL_BROADCAST_LEN,
    LABEL_REUSE, LABEL_REUSE_LEN, PROTOCOL_LEN, TOTAL_LENGTH_LEN,
};
use crate::label::{Label, LabelType};
use crate::pkt_type::PktType;
use crate::utils::{
    GseCompletePacket, GseEndFragPacket, GseFirstFragPacket, GseIntermediatePacket, Serialisable,
};

use crate::gse_decap::gse_decap_memory::{DecapMemoryError, GseDecapMemory, SimpleGseMemory};

/// Read_gse_header tests
///
/// Decapsulation of the packet type, the label type and the gse length off a 16b buffer.
/// pkt complet, 6B label
#[test]
fn test_read_gse_header_001() {
    let header_in = COMPLETE_PKT + LABEL_6_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::CompletePkt;
    let lt_exp = LabelType::SixBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// pkt complet, 3B label
#[test]
fn test_read_gse_header_002() {
    let header_in = COMPLETE_PKT + LABEL_3_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::CompletePkt;
    let lt_exp = LabelType::ThreeBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

// /// pkt complet, label broadcast
#[test]
fn test_read_gse_header_003() {
    let header_in = COMPLETE_PKT + LABEL_BROADCAST + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::CompletePkt;
    let lt_exp = LabelType::Broadcast;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

// /// pkt complet, label re use
#[test]
fn test_read_gse_header_004() {
    let header_in = COMPLETE_PKT + LABEL_REUSE + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::CompletePkt;
    let lt_exp = LabelType::ReUse;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// first frag pkt, 6B label
#[test]
fn test_read_gse_header_005() {
    let header_in = FIRST_PKT + LABEL_6_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::FirstFragPkt;
    let lt_exp = LabelType::SixBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// first frag pkt, 3B label
#[test]
fn test_read_gse_header_006() {
    let header_in = FIRST_PKT + LABEL_3_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::FirstFragPkt;
    let lt_exp = LabelType::ThreeBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// first frag pkt, label broadcast
#[test]
fn test_read_gse_header_007() {
    let header_in = FIRST_PKT + LABEL_BROADCAST + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::FirstFragPkt;
    let lt_exp = LabelType::Broadcast;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// first frag pkt, label re use
#[test]
fn test_read_gse_header_008() {
    let header_in = FIRST_PKT + LABEL_REUSE + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::FirstFragPkt;
    let lt_exp = LabelType::ReUse;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// intermediate pkt, 6B label
#[test]
fn test_read_gse_header_009() {
    let header_in = INTERMEDIATE_PKT + LABEL_6_B + 26;

    let exp_header = None;
    let obs_header = read_gse_header(header_in);

    assert_eq!(exp_header, obs_header);
}

/// intermediate pkt, 3B label
#[test]
fn test_read_gse_header_010() {
    let header_in = INTERMEDIATE_PKT + LABEL_3_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::IntermediateFragPkt;
    let lt_exp = LabelType::ThreeBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// intermediate pkt, label broadcast
#[test]
fn test_read_gse_header_011() {
    let header_in = INTERMEDIATE_PKT + LABEL_BROADCAST + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::IntermediateFragPkt;
    let lt_exp = LabelType::Broadcast;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// intermediate pkt, label re use
#[test]
fn test_read_gse_header_012() {
    let header_in = INTERMEDIATE_PKT + LABEL_REUSE + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::IntermediateFragPkt;
    let lt_exp = LabelType::ReUse;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// end frag pkt, 6B label
#[test]
fn test_read_gse_header_013() {
    let header_in = END_PKT + LABEL_6_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::EndFragPkt;
    let lt_exp = LabelType::SixBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// end frag pkt, 3B label
#[test]
fn test_read_gse_header_014() {
    let header_in = END_PKT + LABEL_3_B + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::EndFragPkt;
    let lt_exp = LabelType::ThreeBytesLabel;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// end frag pkt, label broadcast
#[test]
fn test_read_gse_header_015() {
    let header_in = END_PKT + LABEL_BROADCAST + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::EndFragPkt;
    let lt_exp = LabelType::Broadcast;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

/// end frag pkt, label re use
#[test]
fn test_read_gse_header_016() {
    let header_in = END_PKT + LABEL_REUSE + 26;

    let gse_len_exp = 26;
    let pkt_type_exp = PktType::EndFragPkt;
    let lt_exp = LabelType::ReUse;

    let (gse_len_obs, pkt_type_obs, lt_obs) = read_gse_header(header_in).unwrap();

    assert_eq!(gse_len_exp, gse_len_obs);
    assert_eq!(pkt_type_exp, pkt_type_obs);
    assert_eq!(lt_exp, lt_obs);
}

fn create_decapsulator(
    max_frag_id: usize,
    max_pdu_size: usize,
) -> Decapsulator<SimpleGseMemory, DefaultCrc> {
    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, 0, 0);

    for _ in 0..max_frag_id {
        let storage = vec![0; max_pdu_size].into_boxed_slice();
        memory.provision_storage(storage).unwrap();
    }

    let crc_calculator = DefaultCrc {};
    let decapsulator: Decapsulator<SimpleGseMemory, DefaultCrc> =
        Decapsulator::new(memory, crc_calculator);
    decapsulator
}

/// Decap function tests
///
/// Decapsulation of the alphabet out a buffer.
/// If the decap works: the status has to be true and the pdu has to be filled with the alphabet.
/// Else the status has to be false and the pdu empty.
macro_rules! test_decap_complete {
    ($comment:expr,  $buffer:expr,  $packet:expr,  $decapsulator:expr,  $exp_decapsulator:expr, $exp_pkt_len:expr,  $exp_status:expr) => {
        // Feed the buffer
        $packet.generate(&mut $buffer);
        println!("{:?}", &$buffer);

        // Use the decap function
        let (obs_status, obs_pkt_len) = match $decapsulator.decap(&$buffer) {
            Ok((status, len)) => (Ok(status), len),
            Err((status, len)) => (Err(status), len),
        };

        // Compare the expected values and the observed values
        assert_eq!($exp_status, obs_status, "status error: {}", $comment);
        assert_eq!(
            $exp_decapsulator.last_label, $decapsulator.last_label,
            "decapsulator error: {}",
            $comment
        );
        assert_eq!($exp_pkt_len, obs_pkt_len, "pkt len error: {}", $comment);
    };
}

#[test]
// 6B Label, buffer larger than packet
fn test_decap_complete_001() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, buffer larger than packet";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata {
            pdu_len: PDU_LEN,
            label: Label::SixBytesLabel(*b"012345"),
            protocol_type: 0xFFFF,
        },
    ));
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 3B Label, buffer as large as packet
fn test_decap_complete_002() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "3B Label, buffer as large as packet";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xF0F0,
        Label::ThreeBytesLabel(*b"012"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = None;

    let exp_pkt_len = PKT_LEN;
    let exp_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata {
            pdu_len: PDU_LEN,
            label: Label::ThreeBytesLabel(*b"012"),
            protocol_type: 0xF0F0,
        },
    ));
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 6B Label, wrong size buffer: gse length larger than buffer
fn test_decap_complete_003() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, wrong size buffer: gse length larger than buffer";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        (GSE_LEN + 1) as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorSizeBuffer);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 6B Label, Wrong size buffer: smaller than fixed header length
fn test_decap_complete_004() {
    const PDU_LEN: usize = 26;

    let comment = "6B Label, Wrong size buffer: smaller than fixed header length";
    let buffer: [u8; 1] = [0; 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = 1;
    let exp_status = DecapError::ErrorSizeBuffer;

    if let Err((obs_status, obs_pkt_len)) = decapsulator.decap(&buffer) {
        // Compare the expected values and the observed values
        assert_eq!(exp_status, obs_status, "status error: {}", comment);
        assert_eq!(exp_pkt_len, obs_pkt_len, "pkt len error: {}", comment);
    } else {
        panic!("Wrong result, expected Err got Ok")
    }
}

#[test]
// Label broadcast, empty pdu
fn test_decap_complete_005() {
    const PDU_LEN: usize = 0;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Label broadcast, empty pdu";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(GSE_LEN as u16, 0x0F0F, Label::Broadcast, b"");
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Ok(DecapStatus::CompletedPkt(
        Box::new([0; PDU_LEN]),
        DecapMetadata {
            pdu_len: PDU_LEN,
            label: Label::Broadcast,
            protocol_type: 0x0F0F,
        },
    ));
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
//  ReUse 3B label
fn test_decap_complete_006() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse 3B Label";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xF0F0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata {
            pdu_len: PDU_LEN,
            label: Label::ThreeBytesLabel(*b"012"),
            protocol_type: 0xF0F0,
        },
    ));
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// ReUse label 6B
fn test_decap_complete_007() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse Label 6B";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xF0F0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata {
            pdu_len: PDU_LEN,
            label: Label::SixBytesLabel(*b"012345"),
            protocol_type: 0xF0F0,
        },
    ));
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// ReUse Broadcast Label: ILLEGAL
fn test_decap_complete_008() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse Broadcast Label: ILLEGAL";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xF0F0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::Broadcast);

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorLabelBroadcastSaved);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// ReUse ReUse Label: Error
fn test_decap_complete_009() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse ReUse Label: Error";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xF0F0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ReUse);

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorLabelReUseSaved);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// ReUse None Label: Error
fn test_decap_complete_010() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse None Label: Error";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xF0F0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = None;

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorNoLabelSaved);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 6B Label, Wrong gse_length smaller than the minimal size of a pkt
fn test_decap_complete_011() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, Wrong gse_length smaller than the minimal size of a pkt";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        (PROTOCOL_LEN + LABEL_6_B_LEN - 1) as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut decapsulator = create_decapsulator(1, 26);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorGseLength);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 6B Label, gse length = 0
fn test_decap_complete_012() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, gse length = 0";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        0,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorGseLength);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 6B Label, invalid label complete packet
fn test_decap_complete_013() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, invalid label complete packet";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    packet.generate(&mut buffer);
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    if let Err((obs_status, obs_pkt_len)) = decapsulator.decap(&buffer) {
        let exp_pkt_len = PKT_LEN;
        let exp_status = DecapError::ErrorInvalidLabel;

        assert_eq!(exp_status, obs_status, "{}", comment);
        assert_eq!(decapsulator.last_label, None, "{}", comment);
        assert_eq!(exp_pkt_len, obs_pkt_len, "{}", comment);
    } else {
        panic!("Wrong result, expected Err got Ok")
    }
}

#[test]
// 6B Label, buffer for pdu smaller than pdu received
fn test_decap_complete_014() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, buffer for pdu smaller than pdu received";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN - 1);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorSizePduBuffer);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

#[test]
// 6B Label, Wrong Protocol Type
fn test_decap_complete_015() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Labe
    l, Wrong Protocol Type";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let packet = GseCompletePacket::new(
        GSE_LEN as u16,
        0x000F,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let exp_pkt_len = PKT_LEN;
    let exp_status = Err(DecapError::ErrorProtocolType);
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_complete!(
        comment,
        buffer,
        packet,
        decapsulator,
        exp_decapsulator,
        exp_pkt_len,
        exp_status
    );
}

macro_rules! test_decap_frag {
    ($comment: expr, $buffer: expr, $decapsulator: expr, $exp_decapsulator: expr, $frag: expr, $frag_id: expr, $exp_decap_status: expr, $exp_pkt_len: expr, $exp_pdu: expr ) => {
        $frag.generate(&mut $buffer);
        let (obs_decap_status, obs_pkt_len) = match $decapsulator.decap(&$buffer) {
            Ok((status, len)) => (Ok(status), len),
            Err((status, len)) => (Err(status), len),
        };

        let obs_pdu = match obs_decap_status.clone() {
            Ok(DecapStatus::FragmentedPkt) => $decapsulator.memory.take_frag($frag_id).unwrap().1,
            Ok(DecapStatus::CompletedPkt(pdu, _)) => pdu,
            _ => $decapsulator.memory.new_pdu().unwrap(),
        };

        let stop = $exp_pdu.len();
        assert_eq!(
            $exp_decap_status, obs_decap_status,
            "status error: {}",
            $comment
        );
        assert_eq!($exp_pkt_len, obs_pkt_len, "pkt len error: {}", $comment);
        assert_eq!(
            $exp_decapsulator.last_label, $decapsulator.last_label,
            "decapsulator error: {}",
            $comment
        );
        assert_eq!($exp_pdu[..stop], obs_pdu[..stop], "pdu error {}", $comment);
    };
}

// 6B Label, buffer larger than packet
#[test]
fn test_decap_first_001() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, buffer larger than packet";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = None;

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xFFFF;
    let label = Label::SixBytesLabel(*b"012345");
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// 3B Label, buffer as large as packet
#[test]
fn test_decap_first_002() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "3B Label, buffer as large as packet";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = None;

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xF0F0;
    let label = Label::ThreeBytesLabel(*b"012");
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// 6B Label, wrong size buffer: gse length larger than buffer
#[test]
fn test_decap_first_003() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, wrong size buffer: gse length larger than buffer";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let gse_len = (GSE_LEN + 1) as u16;
    let frag_id = 42;
    let total_length = 42;
    let protocol_type = 0xF0F0;
    let label = Label::SixBytesLabel(*b"012345");
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Err(DecapError::ErrorSizeBuffer);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; PDU_LEN] = [0; PDU_LEN];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// 3B Label, total length < pdu len
#[test]
fn test_decap_first_004() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "3B Label, total length < pdu len";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = (PDU_LEN - 1) as u16;
    let protocol_type = 0xF0F0;
    let label = Label::ThreeBytesLabel(*b"012");
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Err(DecapError::ErrorTotalLength);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; 26] = [0; 26];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// 6B Label, invalid label first packet
#[test]
fn test_decap_first_005() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, invalid label first packet";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xFFFF;
    let label = Label::SixBytesLabel([0, 0, 0, 0, 0, 0]);
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);
    frag.generate(&mut buffer);

    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    if let Err((obs_status, obs_pkt_len)) = decapsulator.decap(&buffer) {
        let exp_decap_status = DecapError::ErrorInvalidLabel;
        let exp_pkt_len = PKT_LEN;
        assert_eq!(
            exp_decapsulator.last_label, decapsulator.last_label,
            "{}",
            comment
        );
        assert_eq!(exp_decap_status, obs_status, "{}", comment);
        assert_eq!(exp_pkt_len, obs_pkt_len, "{}", comment);
    } else {
        panic!("Wrong result, expected Err got Ok")
    }
}

#[test]
// test 6B Label, owerwrite a fragment
fn test_decap_first_006() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, owerwrite a fragment";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xFFFF;

    // init a fragment
    let context = DecapContext::new(
        Label::ReUse,
        protocol_type,
        frag_id,
        total_length,
        total_length,
        false,
    );
    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let gse_len = GSE_LEN as u16;
    let label = Label::SixBytesLabel(*b"012345");
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// Broadcast Label, buffer larger than packet
#[test]
fn test_decap_first_007() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize =
        FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Broadcast Label, buffer larger than packet";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::Broadcast);

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xFFFF;
    let label = Label::Broadcast;
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// 6B Label, invalid protocol type
#[test]
fn test_decap_first_008() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label, invalid protocol type";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0x000F;
    let label = Label::SixBytesLabel([0, 1, 2, 3, 4, 5]);
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);
    frag.generate(&mut buffer);

<<<<<<< HEAD
    if let Err((obs_status, _obs_pkt_len)) = decapsulator.decap(&buffer) {
        let exp_decap_status = DecapError::ErrorProtocolType;
        let _exp_pkt_len = buffer.len();
        assert_eq!(exp_decap_status, obs_status, "{}", comment);

        //Because returning pkt_len instead of buffer len this assert is useless
        //assert_eq!(exp_pkt_len, obs_pkt_len, "{}", comment);
=======
    if let Err((obs_status, obs_pkt_len)) = decapsulator.decap(&buffer) {
        let exp_decap_status = DecapError::ErrorProtocolType;
        let exp_pkt_len = buffer.len();
        assert_eq!(exp_decap_status, obs_status, "{}", comment);
        assert_eq!(exp_pkt_len, obs_pkt_len, "{}", comment);
>>>>>>> 669d003 (Publication to open source)
    } else {
        panic!("Wrong result, expected Err got Ok")
    }
}

// 6B Label ReUse
#[test]
fn test_decap_first_009() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize =
        FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label Reuse";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xFFFF;
    let label = Label::ReUse;
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// 3B Label ReUse
#[test]
fn test_decap_first_010() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize =
        FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "6B Label Reuse";
    let mut buffer: [u8; PKT_LEN + 1] = [0; PKT_LEN + 1];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = 1000;
    let protocol_type = 0xFFFF;
    let label = Label::ReUse;
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// ReUse Broadcast Label: ILLEGAL
#[test]
fn test_decap_first_011() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize =
        FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse Broadcast Label: ILLEGAL";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::Broadcast);

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = (PDU_LEN + 1) as u16;
    let protocol_type = 0xF0F0;
    let label = Label::ReUse;
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Err(DecapError::ErrorLabelBroadcastSaved);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; 26] = [0; 26];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// ReUse ReUse Label: Error
#[test]
fn test_decap_first_012() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize =
        FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse ReUse Label: Error";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::ReUse);

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = (PDU_LEN + 1) as u16;
    let protocol_type = 0xF0F0;
    let label = Label::ReUse;
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Err(DecapError::ErrorLabelReUseSaved);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; 26] = [0; 26];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// ReUse None Label: Error
#[test]
fn test_decap_first_013() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize =
        FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "ReUse None Label: Error";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = None;

    let gse_len = GSE_LEN as u16;
    let frag_id = 42;
    let total_length = (PDU_LEN + 1) as u16;
    let protocol_type = 0xF0F0;
    let label = Label::ReUse;
    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let frag = GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, &pdu);

    let exp_decap_status = Err(DecapError::ErrorNoLabelSaved);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; 26] = [0; 26];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// Intermediate frag fits in the pdu
#[test]
fn test_decap_intermediate_001() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Intermediate frag fits in the pdu";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let gse_len = GSE_LEN as u16;
    let frag_id = 12;
    let frag = GseIntermediatePacket::new(gse_len, frag_id, &pdu);

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = PKT_LEN as u16;

    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = FIXED_HEADER_LEN + gse_len as usize;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// Intermediate frag, more space
#[test]
fn test_decap_intermediate_002() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Intermediate frag, more space";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN + 1);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    let gse_len = GSE_LEN;
    let frag_id = 12;
    let frag = GseIntermediatePacket::new(gse_len as u16, frag_id, &pdu);

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = PKT_LEN as u16;

    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// Intermediate frag, max pdu
#[test]
fn test_decap_intermediate_003() {
    const PDU_LEN: usize = 4093;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Intermediate frag, max pdu";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PKT_LEN);
    decapsulator.last_label = None;

    let pdu = [66; PDU_LEN];
    let frag_id = 12;
    let frag = GseIntermediatePacket::new(GSE_LEN as u16, frag_id, &pdu);

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = 10000;

    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_decap_status = Ok(DecapStatus::FragmentedPkt);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu = pdu;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// Intermediate frag, pdu buffer smaller than the pdu received
#[test]
fn test_decap_intermediate_004() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Intermediate frag, pdu buffer smaller than the pdu received";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN - 1);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;
    let frag = GseIntermediatePacket::new(GSE_LEN as u16, frag_id, &pdu);

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = 10000;

    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_decap_status = Err(DecapError::ErrorSizePduBuffer);
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; PDU_LEN - 1] = [0; PDU_LEN - 1];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// Intermediate frag, unknown frag id
#[test]
fn test_decap_intermediate_005() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Intermediate frag, unknown frag id";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN - 1);
    decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;
    let frag = GseIntermediatePacket::new(GSE_LEN as u16, frag_id, &pdu);

    let exp_decap_status = Err(DecapError::ErrorMemory(DecapMemoryError::UndefinedId));
    let exp_pkt_len = PKT_LEN;
    let exp_pdu: [u8; PDU_LEN - 1] = [0; PDU_LEN - 1];
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, fit
#[test]
fn test_decap_end_001() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, fit";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;

    let crc = DefaultCrc {}.calculate_crc32(&pdu, protocol_type, total_len, label.get_bytes());
    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, crc);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let metadata = DecapMetadata {
        label,
        pdu_len: pdu.len(),
        protocol_type,
    };

    let exp_pdu = pdu;
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(Box::new(exp_pdu), metadata));
    let exp_pkt_len = PKT_LEN;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, out pdu bigger than in pdu
#[test]
fn test_decap_end_002() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, out pdu bigger than in pdu";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN + 1);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;

    let crc = DefaultCrc {}.calculate_crc32(&pdu, protocol_type, total_len, label.get_bytes());
    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, crc);

    let mut state = decapsulator.memory.new_frag(context).unwrap();
    state.1.copy_from_slice(b"---------------------------");
    decapsulator.memory.save_frag(state).unwrap();

    let metadata = DecapMetadata {
        label,
        pdu_len: pdu.len(),
        protocol_type,
    };

    let exp_pdu = *b"abcdefghijklmnopqrstuvwxyz-";
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(Box::new(exp_pdu), metadata));
    let exp_pkt_len = PKT_LEN;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, max pdu size
#[test]
fn test_decap_end_003() {
    const PDU_LEN: usize = 4090;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, max pdu size";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);

    let pdu: [u8; PDU_LEN] = [66; PDU_LEN];

    let frag_id = 12;
    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;

    let crc = DefaultCrc {}.calculate_crc32(&pdu, protocol_type, total_len, label.get_bytes());
    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, crc);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let metadata = DecapMetadata {
        label,
        pdu_len: pdu.len(),
        protocol_type,
    };

    let exp_pdu = pdu;
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(Box::new(exp_pdu), metadata));
    let exp_pkt_len = PKT_LEN;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, pdu buffer is smaller than the pdu received
#[test]
fn test_decap_end_004() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, pdu buffer is smaller than the pdu received";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN - 1);
    decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, 0xFFFFFFFF);

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;
    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_pdu: [u8; PDU_LEN - 1] = [0; PDU_LEN - 1];
    let exp_decap_status = Err(DecapError::ErrorSizePduBuffer);
    let exp_pkt_len = PKT_LEN;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, crc error
#[test]
fn test_decap_end_005() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, crc error";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;

    let crc = 0;
    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, crc);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_pdu = pdu;
    let exp_decap_status = Err(DecapError::ErrorCrc);
    let exp_pkt_len = PKT_LEN;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, empty pdu
#[test]
fn test_decap_end_006() {
    const PDU_LEN: usize = 0;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, empty pdu";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);

    let pdu = *b"";

    let frag_id = 12;

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let pdu_len = 0;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;

    let crc = DefaultCrc {}.calculate_crc32(&pdu, protocol_type, total_len, label.get_bytes());
    let context = DecapContext::new(label, protocol_type, frag_id, total_len, pdu_len, false);
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, crc);

    let state = decapsulator.memory.new_frag(context).unwrap();
    decapsulator.memory.save_frag(state).unwrap();

    let exp_pdu = pdu;
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b""),
        DecapMetadata::new(0, protocol_type, label),
    ));
    let exp_pkt_len = PKT_LEN;
    let mut exp_decapsulator = create_decapsulator(1, PDU_LEN);
    exp_decapsulator.last_label = None;

    test_decap_frag!(
        comment,
        buffer,
        decapsulator,
        exp_decapsulator,
        frag,
        frag_id,
        exp_decap_status,
        exp_pkt_len,
        exp_pdu
    );
}

// End frag, unknown frag id
#[test]
fn test_decap_end_007() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = FRAG_ID_LEN + PDU_LEN + CRC_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "End frag, unknown frag id";
    let mut buffer: [u8; PKT_LEN] = [0; PKT_LEN];
    let mut decapsulator = create_decapsulator(1, PDU_LEN);

    let pdu = *b"abcdefghijklmnopqrstuvwxyz";

    let frag_id = 12;

    let label = Label::ReUse;
    let protocol_type = 0x1111;
    let total_len = (pdu.len() + PROTOCOL_LEN + label.len()) as u16;

    let crc = DefaultCrc {}.calculate_crc32(&pdu, protocol_type, total_len, label.get_bytes());
    let frag = GseEndFragPacket::new(GSE_LEN as u16, frag_id, &pdu, crc);
    frag.generate(&mut buffer);

    if let Err((obs_decap_status, obs_pkt_len)) = decapsulator.decap(&buffer) {
        let (exp_decap_status, exp_pkt_len) = (
            DecapError::ErrorMemory(DecapMemoryError::UndefinedId),
            PKT_LEN,
        );

        assert_eq!(obs_decap_status, exp_decap_status, "{}", comment);
        assert_eq!(obs_pkt_len, exp_pkt_len, "{}", comment);
    } else {
        panic!("Wrong result, expected Err got Ok")
    }
}

#[test]
fn test_decap_signalisation_small() {
    let storage_size = 20;
    let mut decapsulator = create_decapsulator(1, storage_size);

    //packet containing a small table
    let packet = r"e0080081f8008000003f";

    let result = decapsulator.decap(&hex_to_vec_u8(packet));

    match result {
        Ok(e) => match e.0 {
            DecapStatus::CompletedPkt(a, _b) => {
                assert_eq!(a[0..6], [248, 0, 128, 0, 0, 63]);
            }
            _ => {
                panic!("Error when decapsulating small table");
            }
        },
        Err(e) => {
            panic!("Error when decapsulating small table, error {:?}", e);
        }
    }
}

#[test]
fn test_decap_signalisation_medium() {
    let storage_size = 2000;
    let mut decapsulator = create_decapsulator(1, storage_size);

    //packet containing a medium table
    let packet = "e0e30082a40064011a3f13\
    cbf8008000003f13caf8008000003f13c7f8008000\
    003f1379f8008000003f1371f8008000003f135df8\
    008000003f131af8008000003f12f6f8008000003f\
    12daf8008000003f12d8f8008000003f1274f80080\
    00003f1237f8008000003f1210f8008000003f120e\
    f8008000003f11eaf8008000003f11d3f800800000\
    3f1197f8008000003f116ef8008000003f1143f800\
    8000003f112ef8008000003f110ef8008000003f10\
    d1f8008000003f106ef8008000003f105ef8008000\
    003f1030f8008000003f100ff8008000003f1007f8\
    0080000000000000";

    let result = decapsulator.decap(&hex_to_vec_u8(packet));

    // Result should be a Completed packet starting with [164,0,100,1,26,63]
    match result {
        Ok(e) => match e.0 {
            DecapStatus::CompletedPkt(data, _metadata) => {
                assert_eq!(data[0..6], [164, 0, 100, 1, 26, 63])
            }
            _ => {
                panic!("Error on medium decap");
            }
        },
        Err(e) => {
            panic!("Error on medium decap, Error {:?}", e);
        }
    }
}

#[test]
fn test_decap_signalisation_big() {
    let storage_size: usize = 15000;
    let mut decapsulator = create_decapsulator(1, storage_size);
    //First part of a big table
    //Checking if the lib is able to fragment
    let pkt1 = "a6d6000cdb0082ad0064013f01007c0c7e0000000005033f13e8033f13e6033f13e5033f13e3033f\
        13e2023f13b30001880005033f13db033f13d6033f13d6033f13d5033f13d4023f13a30003100005\
        033f13d3033f13d3033f13d2033f13ce033f13cc023f13a00004980005033f13cb033f13ca033f13\
        c8033f13c7033f13c6023f13780006200005033f13c5033f13c3033f13c3033f13c1033f13be023f\
        13460007a80005033f13bd033f13bc033f13bb033f13ba033f13b7023f131d0009300005033f13b3\
        033f13b2033f13b2033f13b1033f13b1023f1305000ab80005033f13a9033f13a7033f13a6033f13\
        a5033f13a5023f12ee000c400005033f13a4033f13a3033f13a1033f13a1033f13a0023f12bf000d\
        c80005033f139f033f139e033f139c033f139b033f1398023f1266000f500005033f1398033f1397\
        033f1393033f1391033f1390023f11f20010d80005033f1390033f138e033f138c033f1386033f13\
        86023f11ec0012600005033f1383033f1382033f1380033f137f033f1379023f11e60013e8000503\
        3f1378033f1377033f1377033f1375033f1372023f11c70015700005033f1371033f1370033f136f\
        033f136e033f1369023f11c00016f80005033f1368033f1367033f1365033f1364033f1364023f11\
        8c0018800005033f1363033f1360033f135d033f135b033f135a023f1180001a080005033f135903\
        3f1357033f1357033f1356033f1355023f116b001b900005033f1352033f1352033f134d033f134d\
        033f134b023f10f1001d180005033f134a033f1346033f1345033f1344033f1340023f10ec001ea0\
        0005033f1340033f133f033f133a033f1339033f1337023f10b00020280005033f1337033f133603\
        3f1336033f1333033f1332023f10a60021b00005033f1332033f1331033f132f033f132f033f132e\
        023f10970023380005033f132e033f132b033f1329033f1329033f1325023f10850024c00005033f\
        1324033f1324033f1322033f1321033f131e023f10450026480005033f131d033f131c033f131c03\
        3f131a033f1318023f103c0027d00004033f1317033f1317033f1316033f1315033f131400295800\
        04033f1313033f1312033f1311033f1311033f1310002ae00004033f130f033f130e033f130d033f\
        1309033f1307002c680004033f1305033f1303033f1302033f1302033f1301002df00004033f12fd\
        033f12fc033f12f9033f12f6033f12f0002f780004033f12ef033f12ee033f12eb033f12e6033f12\
        e50031000004033f12e4033f12e4033f12e3033f12e2033f12e10032880004033f12e0033f12df03\
        3f12df033f12dc033f12db0034100004033f12da033f12d9033f12d8033f12d7033f12d600359800\
        04033f12d5033f12d3033f12d1033f12cf033f12cf0037200004033f12ce033f12cc033f12cc033f\
        12c8033f12c60038a80004033f12c5033f12c3033f12c2033f12c2033f12bf003a300004033f12be\
        033f12bd033f12ba033f12ba033f12b9003bb80004033f12b7033f12b7033f12b6033f12b6033f12\
        b4003d400004033f12b3033f12b3033f12b2033f12b0033f12af003ec80004033f12ae033f12ab03\
        3f12a9033f12a7033f12a60040500004033f12a4033f12a1033f129d033f129b033f129a0041d800\
        04033f1299033f1295033f1294033f1291033f128e0043600004033f128b033f1289033f1286033f\
        1285033f12820044e80004033f1282033f1281033f1280033f1280033f127f0046700004033f127c\
        033f127c033f1279033f1278033f12770047f80004033f1276033f1276033f1274033f1273033f12\
        700049800004033f126f033f126f033f126e033f126e033f126c004b080004033f126c033f126903\
        3f1267033f1266033f1264004c900004033f1262033f1261033f1261033f1260033f125e004e1800\
        04033f125d033f125c033f125b033f1258033f1255004fa00004033f1253033f1252033f124c033f\
        1247033f12440051280004033f1243033f1242033f1241033f123f033f123e0052b00004033f123d\
        033f123b033f123a033f1237033f12360054380004033f1234033f1234033f1232033f1231033f12\
        2c0055c00004033f122b033f1222033f1222033f1221033f12200057480004033f121c033f121c03\
        3f1219033f1218033f12170058d00004033f1215033f1213033f1210033f120f033f120e005a5800\
        04033f120d033f120c033f120c033f1209033f1207005be00004033f1206033f1206033f1204033f\
        1204033f1202005d680004033f1201033f11ff033f11fd033f11fc033f11fb005ef00004033f11fa\
        033f11fa033f11f9033f11f8033f11f70060780004033f11f6033f11f5033f11f4033f11f4033f11\
        f30062000004033f11f2033f11ed033f11ec033f11ea033f11e9006388000403";
    let result = decapsulator.decap(&hex_to_vec_u8(pkt1));
    //should be fragmented
    match result {
        Ok(e) => match e.0 {
            DecapStatus::FragmentedPkt => {}
            _ => {
                panic!("Error when fragmenting big table");
            }
        },
        Err(e) => {
            panic!("Error when fragmenting big table, Error {:?}", e);
        }
    }
    //second part of a big table
    let pkt2 = "760d003f11e7033f11e7033f11e6033f11e4033f11e30065100004033f11e2033f11e0033f11e003\
        3f11dc033f11d90066980004033f11d7033f11d6033f11d4033f11d3033f11d10068200004033f11\
        d0033f11cd033f11ca033f11c9033f11c90069a80004033f11c8033f11c7033f11c4033f11c4033f\
        11c2006b300004033f11c0033f11be033f11be033f11bc033f11b7006cb80004033f11b7033f11b6\
        033f11b4033f11b2033f11b1006e400004033f11b0033f11af033f11af033f11ae033f11ab006fc8\
        0004033f11aa033f11a9033f11a6033f11a5033f11a40071500004033f11a3033f11a2033f119e03\
        3f119c033f119c0072d80004033f119a033f1199033f1197033f1196033f11960074600004033f11\
        95033f1193033f118f033f118c033f118b0075e80004033f118b033f1189033f1187033f1186033f\
        11860077700004033f1185033f1183033f1182033f1181033f11800078f80004033f117f033f117d\
        033f117b033f1178033f1176007a800004033f1176033f1175033f116e033f116d033f116b007c08\
        0004033f116a033f1168033f1166033f1162033f1160007d900004033f115f033f115d033f115b03\
        3f115a033f1159007f180004033f1159033f1157033f1157033f1154033f11530080a00004033f11\
        4f033f114e033f114e033f114a033f11490082280004033f1148033f1145033f1144033f1143033f\
        11410083b00004033f1141033f113f033f113f033f113e033f113c0085380004033f113b033f113a\
        033f1137033f1137033f11350086c00004033f1135033f1133033f1131033f1130033f112f008848\
        0004033f112f033f112e033f1129033f1128033f11260089d00004033f1125033f1124033f112303\
        3f1122033f1121008b580004033f111e033f1119033f1118033f1116033f1115008ce00004033f11\
        11033f1110033f110f033f110f033f110e008e680004033f110d033f1109033f1107033f1107033f\
        1106008ff00004033f1105033f1104033f1102033f1100033f10ff0091780004033f10fc033f10fb\
        033f10f8033f10f7033f10f70093000004033f10f6033f10f4033f10f2033f10f1033f10ee009488\
        0004033f10ed033f10ec033f10eb033f10ea033f10e90096100004033f10e9033f10e8033f10e703\
        3f10e3033f10e20097980004033f10e2033f10e1033f10df033f10df033f10de0099200004033f10\
        dd033f10dc033f10dc033f10db033f10db009aa80004033f10da033f10d9033f10d8033f10d7033f\
        10d3009c300004033f10d2033f10d1033f10cd033f10cc033f10cb009db80004033f10ca033f10c9\
        033f10c9033f10c5033f10c2009f400004033f10c2033f10be033f10b9033f10b8033f10b600a0c8\
        0004033f10b6033f10b2033f10b2033f10b0033f10af00a2500004033f10af033f10ae033f10ab03\
        3f10aa033f10aa00a3d80004033f10a9033f10a8033f10a7033f10a6033f10a500a5600004033f10\
        a3033f10a2033f10a1033f109f033f109e00a6e80004033f109d033f109c033f1099033f1097033f\
        109600a8700004033f1095033f1091033f1090033f1090033f108f00a9f80004033f108f033f108c\
        033f108b033f1085033f108000ab800004033f107f033f107d033f107b033f1078033f107800ad08\
        0004033f1076033f1075033f1074033f1073033f106e00ae900004033f1067033f1065033f106303\
        3f1063033f106000b0180004033f105e033f105c033f105c033f105b033f105b00b1a00004033f10\
        59033f1059033f1055033f1052033f105200b3280004033f1050033f104d033f104d033f104c033f\
        104b00b4b00004033f104a033f1049033f1048033f1047033f104700b6380004033f1046033f1045\
        033f1043033f1042033f104000b7c00004033f103f033f103e033f103d033f103c033f103b00b948\
        0004033f1039033f1038033f1035033f1034033f103300bad00004033f1032033f1030033f102e03\
        3f102b033f102900bc580004033f1028033f1023033f1022033f1022033f101e00bde00004033f10\
        1e033f1018033f1013033f1012033f101000bf680004033f100f033f100d033f100d033f100a033f\
        100800c0f00004033f1007033f1003033f1003033f1002033f10012377d2a7";
    let result2 = decapsulator.decap(&hex_to_vec_u8(pkt2));
    //should be complete and end with [173, 0, 100, 1, 63, 1,]
    match result2 {
        Ok(e) => match e.0 {
            DecapStatus::CompletedPkt(data, _metadata) => {
                assert_eq!(data[0..6], [173, 0, 100, 1, 63, 1,])
            }
            _ => {
                panic!("Error when fragmenting big table");
            }
        },
        Err(e) => {
            panic!("Error when fragmenting big table, Error {:?}", e);
        }
    }
}

fn hex_to_vec_u8(hex: &str) -> Vec<u8> {
    let mut vec = Vec::new();
    for i in 0..(hex.len() / 2) {
        let res = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16);
        match res {
            Ok(v) => vec.push(v),
            Err(e) => println!("Problem with index {}: {}", i, e),
        };
    }
    vec
}
