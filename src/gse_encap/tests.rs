// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

use crate::crc::{CrcCalculator, DefaultCrc};
use crate::gse_encap::{
    encap_frag_preview, encap_preview, generate_gse_header, ContextFrag, EncapError, EncapMetadata,
    EncapStatus, Encapsulator,
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

const DEFAULT_FRAG_ID: u8 = 42;

/// Generate_gse_header test
///
/// Encapsulation of the label type and the gse length in a 16b buffer.
/// The output expected is the gse_length in the right 12b, the label type in the 2 next bit and the packet type in the first 2b
///
/// pkt complet, 6B label
#[test]
fn test_generate_gse_header_001() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::CompletePkt;
    let label_type_in = LabelType::SixBytesLabel;

    let header_exp = COMPLETE_PKT + LABEL_6_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// pkt complet, 3B label
#[test]
fn test_generate_gse_header_002() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::CompletePkt;
    let label_type_in = LabelType::ThreeBytesLabel;

    let header_exp = COMPLETE_PKT + LABEL_3_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

// /// pkt complet, label broadcast
#[test]
fn test_generate_gse_header_003() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::CompletePkt;
    let label_type_in = LabelType::Broadcast;

    let header_exp = COMPLETE_PKT + LABEL_BROADCAST + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

// /// pkt complet, label re use
#[test]
fn test_generate_gse_header_004() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::CompletePkt;
    let label_type_in = LabelType::ReUse;

    let header_exp = COMPLETE_PKT + LABEL_REUSE + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// first frag pkt, 6B label
#[test]
fn test_generate_gse_header_005() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::FirstFragPkt;
    let label_type_in = LabelType::SixBytesLabel;

    let header_exp = FIRST_PKT + LABEL_6_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// first frag pkt, 3B label
#[test]
fn test_generate_gse_header_006() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::FirstFragPkt;
    let label_type_in = LabelType::ThreeBytesLabel;

    let header_exp = FIRST_PKT + LABEL_3_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// first frag pkt, label broadcast
#[test]
fn test_generate_gse_header_007() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::FirstFragPkt;
    let label_type_in = LabelType::Broadcast;

    let header_exp = FIRST_PKT + LABEL_BROADCAST + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// first frag pkt, label re use
#[test]
fn test_generate_gse_header_008() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::FirstFragPkt;
    let label_type_in = LabelType::ReUse;

    let header_exp = FIRST_PKT + LABEL_REUSE + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// intermediate pkt, 6B label
#[test]
fn test_generate_gse_header_009() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::IntermediateFragPkt;
    let label_type_in = LabelType::SixBytesLabel;

    let header_exp = INTERMEDIATE_PKT + LABEL_6_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// intermediate pkt, 3B label
#[test]
fn test_generate_gse_header_010() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::IntermediateFragPkt;
    let label_type_in = LabelType::ThreeBytesLabel;

    let header_exp = INTERMEDIATE_PKT + LABEL_3_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// intermediate pkt, label broadcast
#[test]
fn test_generate_gse_header_011() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::IntermediateFragPkt;
    let label_type_in = LabelType::Broadcast;

    let header_exp = INTERMEDIATE_PKT + LABEL_BROADCAST + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// intermediate pkt, label re use
#[test]
fn test_generate_gse_header_012() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::IntermediateFragPkt;
    let label_type_in = LabelType::ReUse;

    let header_exp = INTERMEDIATE_PKT + LABEL_REUSE + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// end frag pkt, 6B label
#[test]
fn test_generate_gse_header_013() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::EndFragPkt;
    let label_type_in = LabelType::SixBytesLabel;

    let header_exp = END_PKT + LABEL_6_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// end frag pkt, 3B label
#[test]
fn test_generate_gse_header_014() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::EndFragPkt;
    let label_type_in = LabelType::ThreeBytesLabel;

    let header_exp = END_PKT + LABEL_3_B + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// end frag pkt, label broadcast
#[test]
fn test_generate_gse_header_015() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::EndFragPkt;
    let label_type_in = LabelType::Broadcast;

    let header_exp = END_PKT + LABEL_BROADCAST + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// end frag pkt, label re use
#[test]
fn test_generate_gse_header_016() {
    let gse_len_in = 26;
    let pkt_type_in = PktType::EndFragPkt;
    let label_type_in = LabelType::ReUse;

    let header_exp = END_PKT + LABEL_REUSE + 26;

    let header_obs = generate_gse_header(&pkt_type_in, &label_type_in, gse_len_in);

    assert_eq!(header_exp, header_obs);
}

/// Encap function tests
///
/// Gse encapsulation in a buffer.
/// If the encap works: the status has to be CompletedPkt or FragmentedPkt and the buffer filled by a gse pkt
/// Else, the status has to describe the error
macro_rules! test_encap {
    ($comment:expr, $encapsulator:expr, $exp_encapsulator:expr, $pdu:expr, $payload:expr, $buffer:expr, $exp_values:expr, $exp_status:expr, $pkt_type:ty) => {
        // Use the encap function
        let obs_status = $encapsulator.encap($pdu, DEFAULT_FRAG_ID, $payload, &mut $buffer);

        // Compute the observed values
        let gse_pkt = <$pkt_type>::parse(&$buffer);

        // Compare the expected values and the observed values
        match gse_pkt {
            Ok(obs_values) => {
                assert_eq!($exp_values, obs_values, "values error: {}", $comment);
                assert_eq!($encapsulator, $exp_encapsulator)
            }
            _ => panic!(),
        }

        assert_eq!($exp_status, obs_status, "status error: {}", $comment);
    };
}

/// test: 6B Label, buffer larger than packet
#[test]
fn test_encap_001() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 6B Label, buffer as the same length as pkt
#[test]
fn test_encap_002() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, buffer as the same length as pkt";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 6B Label, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_003() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) =
        (GSE_LEN as u16, 0xFFFF, Label::SixBytesLabel(*b"012345"));
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_6_B_LEN)) as u16,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: 6B Label, buffer has the same length as gse fix header(2) + frag_id(1) + total_length(2) + protocol_type(2) + label(6)
#[test]
fn test_encap_004() {
    const PDU_LEN: usize = 26;
    const TOTAL_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const EXP_PKT_LEN: usize =
        FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN;
    let comment = "6B Label, fragmented pkt with pdu_len_frag = 0";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; 13];

    let (exp_total_len, exp_protocol_type, exp_label) =
        ((TOTAL_LEN) as u16, 0xFFFF, Label::SixBytesLabel(*b"012345"));
    let exp_values = GseFirstFragPacket::new(
        (EXP_PKT_LEN - FIXED_HEADER_LEN) as u16,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        13,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: 0,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: 6B Label, buffer too small
#[test]
fn test_encap_005() {
    const MIN_BUFFER_LEN: usize =
        FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN;
    let comment = "6B Label, buffer too small";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; MIN_BUFFER_LEN - 1];

    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Err(EncapError::ErrorSizeBuffer);

    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    assert_eq!(exp_status, obs_status, "status error: {}", comment);
}

/// test: 3B Label, buffer larger than packet
#[test]
fn test_encap_006() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "3B Label, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        26 + 3 + 2,
        0xFFFF,
        Label::ThreeBytesLabel(*b"012"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::CompletedPkt((PKT_LEN) as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 3B Label, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_007() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    const FIRST_FRAG_LEN: usize =
        FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_3_B_LEN;
    const EXP_PDU_LEN: usize = (PKT_LEN - 1) - FIRST_FRAG_LEN;

    let comment = "3B Label, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) =
        (GSE_LEN as u16, 0xFFFF, Label::ThreeBytesLabel(*b"012"));
    let exp_values = GseFirstFragPacket::new(
        (FIRST_FRAG_LEN + EXP_PDU_LEN - FIXED_HEADER_LEN) as u16,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        (FIRST_FRAG_LEN + EXP_PDU_LEN) as u16,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: EXP_PDU_LEN as u16,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: Label Broadcast, buffer larger than packet
#[test]
fn test_encap_008() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Label Broadcast, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::Broadcast,
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::Broadcast,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: Label Broadcast, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_009() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    const FIRST_FRAG_LEN: usize =
        FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_BROADCAST_LEN;
    const EXP_PDU_LEN: usize = (PKT_LEN - 1) - FIRST_FRAG_LEN;

    let comment = "Label Broadcast, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::Broadcast,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) = (
        (PDU_LEN + PROTOCOL_LEN + LABEL_BROADCAST_LEN) as u16,
        0xFFFF,
        Label::Broadcast,
    );
    let exp_values = GseFirstFragPacket::new(
        (FIRST_FRAG_LEN - FIXED_HEADER_LEN + EXP_PDU_LEN) as u16,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        (FIRST_FRAG_LEN + EXP_PDU_LEN) as u16,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: EXP_PDU_LEN as u16,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: Label ReUse, buffer larger than packet
#[test]
fn test_encap_010() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label ReUse, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: Label ReUse, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_011() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    const FIRST_FRAG_LEN: usize =
        FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN;
    const EXP_PDU_LEN: usize = (PKT_LEN - 1) - FIRST_FRAG_LEN;
    const EXP_TOTAL_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const EXP_GSE_LEN: usize = FIRST_FRAG_LEN - FIXED_HEADER_LEN + EXP_PDU_LEN;
    let comment = "Label ReUse, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) =
        (EXP_TOTAL_LEN as u16, 0xFFFF, Label::ReUse);
    let exp_values = GseFirstFragPacket::new(
        EXP_GSE_LEN as u16,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        (PKT_LEN - 1) as u16,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: EXP_PDU_LEN as u16,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: Label ReUse, protocol type not managed
#[test]
fn test_encap_012() {
    let comment = "Label ReUse, protocol type not managed";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0x100,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; 29];

    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Err(EncapError::ErrorProtocolType);

    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    assert_eq!(exp_status, obs_status, "status error: {}", comment);
}

/// test: Label ReUse, pdu_len > 16b
#[test]
fn test_encap_013() {
    let comment = "Label ReUse, pdu_len > 16b";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in: &[u8; 0x10000] = &[0; 0x10000];
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; 29];

    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Err(EncapError::ErrorPduLength);

    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    assert_eq!(exp_status, obs_status, "status error: {}", comment);
}

/// test: 6B Label, invalid label CompletePkt
#[test]
fn test_encap_014() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, invalid label CompletePkt";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        // &[0, 0, 0, 0, 0, 0]
    };
    let mut buffer_in = [0; PKT_LEN + 1];
    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Err(EncapError::ErrorInvalidLabel);

    assert_eq!(obs_status, exp_status, "{}", comment);
}

/// test: 6B Label, invalid label FirstFragPkt
#[test]
fn test_encap_015() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, invalid label FirstFragPkt";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        // &[0, 0, 0, 0, 0, 0]
    };
    let mut buffer_in = [0; PKT_LEN - 1];
    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(false);
    let exp_status = Err(EncapError::ErrorInvalidLabel);

    assert_eq!(obs_status, exp_status, "{}", comment);
}

/// test: 6B Label ReUsed, buffer larger than packet
#[test]
fn test_encap_016() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label ReUsed, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 6B Label Not ReUsed, buffer larger than packet
#[test]
fn test_encap_017() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label Not ReUsed, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"543210"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 6B Label ReUsed, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_018() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label ReUsed, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) = (GSE_LEN as u16, 0xFFFF, Label::ReUse);
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_REUSE_LEN)) as u16,
        },
    ));
    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}
/// test: 6B Label Not ReUsed, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_019() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label Not ReUsed, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) =
        (GSE_LEN as u16, 0xFFFF, Label::SixBytesLabel(*b"012345"));
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_6_B_LEN)) as u16,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: 3B Label ReUsed, buffer larger than packet
#[test]
fn test_encap_020() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label ReUsed, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 3B Label Not ReUsed, buffer larger than packet
#[test]
fn test_encap_021() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "3B Label Not ReUsed, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::ThreeBytesLabel(*b"012"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: 3B Label ReUsed, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_022() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "3B Label ReUsed, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"221"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"221"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) = (GSE_LEN as u16, 0xFFFF, Label::ReUse);
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"221"));
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_REUSE_LEN)) as u16,
        },
    ));
    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: 3B Label Not ReUsed, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_023() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "3B Label Not ReUsed, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) =
        (GSE_LEN as u16, 0xFFFF, Label::ThreeBytesLabel(*b"012"));
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"012"));
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_3_B_LEN)) as u16,
        },
    ));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: Label Broadcast set last_label at None, buffer larger than packet
#[test]
fn test_encap_024() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label Broadcast set last_label at None, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::Broadcast,
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::Broadcast,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = None;
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: Label Broadcast set last_label at None, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_025() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment =
        "Label Broadcast set last_label at None, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"221"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::Broadcast,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) = (GSE_LEN as u16, 0xFFFF, Label::Broadcast);
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = None;
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_BROADCAST_LEN)) as u16,
        },
    ));
    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: Label ReUse dont change last label, buffer larger than packet
#[test]
fn test_encap_026() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label ReUse dont change last label, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: Label ReUse dont change last label, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_027() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label ReUse dont change last label, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"221"));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) = (GSE_LEN as u16, 0xFFFF, Label::ReUse);
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"221"));
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_REUSE_LEN)) as u16,
        },
    ));
    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: Initialize at 6BLabel last_label set at None, buffer larger than packet
#[test]
fn test_encap_028() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label ReUse dont change last label, buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = None;

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    let exp_values = GseCompletePacket::new(
        GSE_LEN as u16,
        0xFFFF,
        Label::SixBytesLabel(*b"012345"),
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel(*b"012345"));
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseCompletePacket
    );
}

/// test: Initialize at 3BLabel last_label set at None , buffer smaller than pkt: encap first frag
#[test]
fn test_encap_029() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label ReUse dont change last label, buffer smaller than pkt: encap first frag";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = None;

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"221"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let (exp_total_len, exp_protocol_type, exp_label) =
        (GSE_LEN as u16, 0xFFFF, Label::ThreeBytesLabel(*b"221"));
    let exp_values = GseFirstFragPacket::new(
        GSE_LEN as u16 - 1,
        DEFAULT_FRAG_ID,
        exp_total_len,
        exp_protocol_type,
        exp_label,
        b"abcdefghijklmnopqrstuv",
    );
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::ThreeBytesLabel(*b"221"));
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        PKT_LEN as u16 - 1,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: DefaultCrc {}.calculate_crc32(
                b"abcdefghijklmnopqrstuvwxyz",
                exp_protocol_type,
                exp_total_len,
                exp_label.get_bytes(),
            ),
            len_pdu_frag: (PKT_LEN
                - (1 + FIXED_HEADER_LEN
                    + FRAG_ID_LEN
                    + TOTAL_LENGTH_LEN
                    + PROTOCOL_LEN
                    + LABEL_3_B_LEN)) as u16,
        },
    ));
    test_encap!(
        comment,
        encapsulator,
        exp_encapsulator,
        pdu_in,
        payload_in,
        buffer_in,
        exp_values,
        exp_status,
        GseFirstFragPacket
    );
}

/// test: 6B Label ReUse enabled, invalid label CompletePkt
#[test]
fn test_encap_030() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label ReUse enabled, invalid label CompletePkt";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel([0, 0, 0, 0, 0, 0]));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        // &[0, 0, 0, 0, 0, 0]
    };
    let mut buffer_in = [0; PKT_LEN + 1];
    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel([0, 0, 0, 0, 0, 0]));
    let exp_status = Err(EncapError::ErrorInvalidLabel);

    assert_eq!(obs_status, exp_status, "{}", comment);
}

/// test: 6B Label ReUse enabled, invalid label FirstFragPkt
#[test]
fn test_encap_031() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label ReUse enabled, invalid label FirstFragPkt";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(true);
    encapsulator.last_label = Some(Label::SixBytesLabel([0, 0, 0, 0, 0, 0]));

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        // &[0, 0, 0, 0, 0, 0]
    };
    let mut buffer_in = [0; PKT_LEN - 1];
    let obs_status = encapsulator.encap(pdu_in, DEFAULT_FRAG_ID, payload_in, &mut buffer_in);
    let mut exp_encapsulator = Encapsulator::new(DefaultCrc {});
    exp_encapsulator.enable_re_use_label(true);
    exp_encapsulator.last_label = Some(Label::SixBytesLabel([0, 0, 0, 0, 0, 0]));
    let exp_status = Err(EncapError::ErrorInvalidLabel);

    assert_eq!(obs_status, exp_status, "{}", comment);
}

/// Encap preview function tests
macro_rules! test_encap_preview {
    ($comment:expr, $pdu:expr, $payload:expr, $buffer:expr, $pkt_type:ty) => {
        let mut encapsulator = Encapsulator::new(DefaultCrc {});
        encapsulator.enable_re_use_label(false);

        // Use the encap function
        let obs_status = encapsulator.encap($pdu, DEFAULT_FRAG_ID, $payload, &mut $buffer);
        let preview = encap_preview($pdu, $payload, &$buffer);

        match (obs_status, preview) {
            (Ok(status), Ok(preview)) => {
                let (pkt_type, pkt_len) = match status {
                    EncapStatus::CompletedPkt(len) => (PktType::CompletePkt, len),
                    EncapStatus::FragmentedPkt(len, _) => (PktType::FirstFragPkt, len),
                };

                assert_eq!(pkt_type, preview.pkt_type, "{}", $comment);
                assert_eq!(pkt_len, preview.pkt_len, "{}", $comment);
            }
            (Err(err_status), Err(err_preview)) => {
                assert_eq!(err_status, err_preview);
            }
            (x, y) => {
                panic!("{}: {:?} != {:?}", $comment, x, y);
            }
        }
    };
}

/// test: 6B Label, buffer larger than packet
#[test]
fn test_encap_preview_001() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, buffer larger than packet";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseCompletePacket);
}

/// test: 6B Label, buffer as the same length as pkt
#[test]
fn test_encap_preview_002() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, buffer as the same length as pkt";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseCompletePacket);
}

/// test: 6B Label, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_preview_003() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, buffer smaller than pkt: encap first frag";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: 6B Label, buffer has the same length as gse fix header(2) + frag_id(1) + total_length(2) + protocol_type(2) + label(6)
#[test]
fn test_encap_preview_004() {
    let comment = "6B Label, fragmented pkt with pdu_len_frag = 0";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; 13];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: 6B Label, buffer too small
#[test]
fn test_encap_preview_005() {
    const MIN_BUFFER_LEN: usize =
        FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + LABEL_6_B_LEN;
    let comment = "6B Label, buffer too small";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel(*b"012345"),
    };
    let mut buffer_in = [0; MIN_BUFFER_LEN - 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: 3B Label, buffer larger than packet
#[test]
fn test_encap_preview_006() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "3B Label, buffer larger than packet";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: 3B Label, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_preview_007() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "3B Label, buffer smaller than pkt: encap first frag";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ThreeBytesLabel(*b"012"),
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: Label Broadcast, buffer larger than packet
#[test]
fn test_encap_preview_008() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Label Broadcast, buffer larger than packet";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::Broadcast,
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: Label Broadcast, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_preview_009() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_BROADCAST_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Label Broadcast, buffer smaller than pkt: encap first frag";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::Broadcast,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: Label ReUse, buffer larger than packet
#[test]
fn test_encap_preview_010() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "Label ReUse, buffer larger than packet";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseCompletePacket);
}

/// test: Label ReUse, buffer smaller than pkt: encap first frag
#[test]
fn test_encap_preview_011() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;

    let comment = "Label ReUse, buffer smaller than pkt: encap first frag";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: Label ReUse, protocol type not managed
#[test]
fn test_encap_preview_012() {
    let comment = "Label ReUse, protocol type not managed";

    let pdu_in: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0x100,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; 29];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: Label ReUse, pdu_len > 16b
#[test]
fn test_encap_preview_013() {
    let comment = "Label ReUse, pdu_len > 16b";

    let pdu_in: &[u8; 0x10000] = &[0; 0x10000];
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::ReUse,
    };
    let mut buffer_in = [0; 29];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: 6B Label, invalid label CompletePkt
#[test]
fn test_encap_preview_014() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, invalid label CompletePkt";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        // &[0, 0, 0, 0, 0, 0]
    };
    let mut buffer_in = [0; PKT_LEN + 1];

    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// test: 6B Label, invalid label FirstFragPkt
#[test]
fn test_encap_preview_015() {
    const PDU_LEN: usize = 26;
    const GSE_LEN: usize = PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;
    const PKT_LEN: usize = FIXED_HEADER_LEN + GSE_LEN;
    let comment = "6B Label, invalid label FirstFragPkt";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let payload_in = EncapMetadata {
        protocol_type: 0xFFFF,
        label: Label::SixBytesLabel([0, 0, 0, 0, 0, 0]),
        // &[0, 0, 0, 0, 0, 0]
    };
    let mut buffer_in = [0; PKT_LEN - 1];
    test_encap_preview!(comment, pdu_in, payload_in, buffer_in, GseFirstFragPacket);
}

/// Encap frag function tests
///
/// Gse encapsulation in a buffer.
/// If the encap works: the status has to be CompletedPkt or FragmentedPkt and the buffer filled by a gse pkt
/// Else, the status has to describe the error
macro_rules! test_encap_frag {
    ($comment:expr, $encapsulator:expr, $pdu:expr, $context_frag:expr, $buffer:expr, $exp_values:expr, $exp_status:expr, $pkt_type:ty) => {
        // Use the encap function
        let obs_status = $encapsulator.encap_frag($pdu, $context_frag, &mut $buffer);

        // Compute the observed values
        let gse_pkt = <$pkt_type>::parse(&$buffer);

        // Compare the expected values and the observed values
        match gse_pkt {
            Ok(obs_values) => assert_eq!($exp_values, obs_values, "values error: {}", $comment),
            _ => panic!(),
        }

        assert_eq!($exp_status, obs_status, "status error: {}", $comment);
    };
}

/// test: buffer larger than packet
#[test]
fn test_encap_frag_001() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;

    let comment = "buffer larger than packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; 1000];

    let exp_values = GseEndFragPacket::new(
        (EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN) as u16,
        DEFAULT_FRAG_ID,
        b"abcdefghijklmnopqrstuvwxyz",
        88,
    );
    let exp_status = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + FRAG_ID_LEN + EXP_PDU_LEN + CRC_LEN) as u16,
    ));

    test_encap_frag!(
        comment,
        encapsulator,
        pdu_in,
        &context_frag_in,
        buffer_in,
        exp_values,
        exp_status,
        GseEndFragPacket
    );
}

/// test: buffer has the same length as the packet
#[test]
fn test_encap_frag_002() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;
    const PKT_LEN: usize = EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN + PROTOCOL_LEN;
    let comment = "buffer has the same length as the packet";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; PKT_LEN];

    let exp_values = GseEndFragPacket::new(
        (EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN) as u16,
        DEFAULT_FRAG_ID,
        b"abcdefghijklmnopqrstuvwxyz",
        88,
    );
    let exp_status = Ok(EncapStatus::CompletedPkt(PKT_LEN as u16));

    test_encap_frag!(
        comment,
        encapsulator,
        pdu_in,
        &context_frag_in,
        buffer_in,
        exp_values,
        exp_status,
        GseEndFragPacket
    );
}

/// test: buffer to small to contains crc
#[test]
fn test_encap_frag_003() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;
    const PKT_LEN: usize = EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN + PROTOCOL_LEN;
    let comment = "buffer to small to contains crc";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    let exp_values = GseIntermediatePacket::new(
        (EXP_PDU_LEN + 1) as u16,
        DEFAULT_FRAG_ID,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        (FIXED_HEADER_LEN + FRAG_ID_LEN + EXP_PDU_LEN) as u16,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: 88,
            len_pdu_frag: PDU_LEN as u16,
        },
    ));

    test_encap_frag!(
        comment,
        encapsulator,
        pdu_in,
        &context_frag_in,
        buffer_in,
        exp_values,
        exp_status,
        GseIntermediatePacket
    );
}

/// test: buffer to small to contains the entire pdu
#[test]
fn test_encap_frag_004() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;
    const PKT_LEN: usize = EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN + PROTOCOL_LEN;
    let comment = "buffer to small to contains the entire pdu";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: 10,
        crc: 88,
    };
    let mut buffer_in = [0; PKT_LEN - CRC_LEN - 1];

    let exp_values = GseIntermediatePacket::new(
        (EXP_PDU_LEN - 1 + FRAG_ID_LEN) as u16,
        DEFAULT_FRAG_ID,
        b"abcdefghijklmnopqrstuvwxy",
    );
    let exp_status = Ok(EncapStatus::FragmentedPkt(
        (PKT_LEN - 5) as u16,
        ContextFrag {
            frag_id: DEFAULT_FRAG_ID,
            crc: 88,
            len_pdu_frag: (PDU_LEN - 1) as u16,
        },
    ));

    test_encap_frag!(
        comment,
        encapsulator,
        pdu_in,
        &context_frag_in,
        buffer_in,
        exp_values,
        exp_status,
        GseIntermediatePacket
    );
}

/// test: buffer to small to contains a single byte of pdu
#[test]
fn test_encap_frag_005() {
    const PDU_FRAG_LEN: usize = 10;

    let comment = "buffer to small to contains a single byte of pdu";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; FIXED_HEADER_LEN + FRAG_ID_LEN];

    let exp_status = Err(EncapError::ErrorSizeBuffer);

    let obs_status = encapsulator.encap_frag(pdu_in, &context_frag_in, &mut buffer_in);

    assert_eq!(exp_status, obs_status, "{}", comment);
}

/// test: end frag pkt with only crc
#[test]
fn test_encap_frag_006() {
    let comment = "pdu already sent: end frag pkt with only crc";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: 26,
        crc: 88,
    };
    let mut buffer_in = [0; 1000];

    let exp_values =
        GseEndFragPacket::new((FRAG_ID_LEN + CRC_LEN) as u16, DEFAULT_FRAG_ID, b"", 88);
    let exp_status = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + FRAG_ID_LEN + CRC_LEN) as u16,
    ));

    test_encap_frag!(
        comment,
        encapsulator,
        pdu_in,
        &context_frag_in,
        buffer_in,
        exp_values,
        exp_status,
        GseEndFragPacket
    );
}

/// test: pdu smaller than pdu already sent
#[test]
fn test_encap_frag_007() {
    let comment = "pdu already sent: pdu smaller than pdu already sent";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label(false);

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: 26 + 1,
        crc: 88,
    };
    let mut buffer_in = [0; 1000];

    let exp_status = Err(EncapError::ErrorPduLength);

    let obs_status = encapsulator.encap_frag(pdu_in, &context_frag_in, &mut buffer_in);

    assert_eq!(exp_status, obs_status, "{}", comment);
}

/// Encap preview function tests
macro_rules! test_encap_frag_preview {
    ($comment:expr, $pdu:expr, $context_frag:expr, $buffer:expr, $pkt_type:ty) => {
        let mut encapsulator = Encapsulator::new(DefaultCrc {});
        encapsulator.enable_re_use_label(false);

        // Use the encap function
        let obs_status = encapsulator.encap_frag($pdu, $context_frag, &mut $buffer);
        let preview = encap_frag_preview($pdu, $context_frag, &$buffer);

        match (obs_status, preview) {
            (Ok(status), Ok(preview)) => {
                let (pkt_type, pkt_len) = match status {
                    EncapStatus::CompletedPkt(len) => (PktType::EndFragPkt, len),
                    EncapStatus::FragmentedPkt(len, _) => (PktType::IntermediateFragPkt, len),
                };

                assert_eq!(pkt_type, preview.pkt_type, "{}", $comment);
                assert_eq!(pkt_len, preview.pkt_len, "{}", $comment);
            }
            (Err(err_status), Err(err_preview)) => {
                assert_eq!(err_status, err_preview);
            }
            (x, y) => {
                panic!("{}: {:?} != {:?}", $comment, x, y);
            }
        }
    };
}

/// test: buffer larger than packet
#[test]
fn test_encap_frag_preview_001() {
    const PDU_FRAG_LEN: usize = 10;

    let comment = "buffer larger than packet";

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; 1000];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseEndFragPacket
    );
}

/// test: buffer has the same length as the packet
#[test]
fn test_encap_frag_preview_002() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;
    const PKT_LEN: usize = EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN + PROTOCOL_LEN;
    let comment = "buffer has the same length as the packet";

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; PKT_LEN];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseEndFragPacket
    );
}

/// test: buffer to small to contains crc
#[test]
fn test_encap_frag_preview_003() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;
    const PKT_LEN: usize = EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN + PROTOCOL_LEN;
    let comment = "buffer to small to contains crc";

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; PKT_LEN - 1];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseIntermediatePacket
    );
}

/// test: buffer to small to contains the entire pdu
#[test]
fn test_encap_frag_preview_004() {
    const PDU_LEN: usize = 36;
    const PDU_FRAG_LEN: usize = 10;
    const EXP_PDU_LEN: usize = PDU_LEN - PDU_FRAG_LEN;
    const PKT_LEN: usize = EXP_PDU_LEN + FRAG_ID_LEN + CRC_LEN + PROTOCOL_LEN;
    let comment = "buffer to small to contains the entire pdu";

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: 10,
        crc: 88,
    };
    let mut buffer_in = [0; PKT_LEN - CRC_LEN - 1];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseIntermediatePacket
    );
}

/// test: buffer to small to contains a single byte of pdu
#[test]
fn test_encap_frag_preview_005() {
    const PDU_FRAG_LEN: usize = 10;

    let comment = "buffer to small to contains a single byte of pdu";

    let pdu_in = b"----------abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: PDU_FRAG_LEN as u16,
        crc: 88,
    };
    let mut buffer_in = [0; FIXED_HEADER_LEN + FRAG_ID_LEN];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseEndFragPacket
    );
}

/// test: end frag pkt with only crc
#[test]
fn test_encap_frag_preview_006() {
    let comment = "pdu already sent: end frag pkt with only crc";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: 26,
        crc: 88,
    };
    let mut buffer_in = [0; 1000];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseEndFragPacket
    );
}

/// test: pdu smaller than pdu already sent
#[test]
fn test_encap_frag_preview_007() {
    let comment = "pdu already sent: pdu smaller than pdu already sent";

    let pdu_in = b"abcdefghijklmnopqrstuvwxyz";
    let context_frag_in = ContextFrag {
        frag_id: DEFAULT_FRAG_ID,
        len_pdu_frag: 26 + 1,
        crc: 88,
    };
    let mut buffer_in = [0; 1000];

    test_encap_frag_preview!(
        comment,
        pdu_in,
        &context_frag_in,
        buffer_in,
        GseEndFragPacket
    );
}
