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

    if let Err((obs_status, _obs_pkt_len)) = decapsulator.decap(&buffer) {
        let exp_decap_status = DecapError::ErrorProtocolType;
        let _exp_pkt_len = buffer.len();
        assert_eq!(exp_decap_status, obs_status, "{}", comment);

        //Because returning pkt_len instead of buffer len this assert is useless
        //assert_eq!(exp_pkt_len, obs_pkt_len, "{}", comment);
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
