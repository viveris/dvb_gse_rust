// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

use crate::{
    label::Label,
    utils::{
        GseCompletePacket, GseEndFragPacket, GseFirstFragPacket, GseIntermediatePacket,
        Serialisable,
    },
};

#[test]
fn test_new_complete_pkt() {
    let gse_len: u16 = 12;
    let protocol_type: u16 = 4200;
    let label = Label::SixBytesLabel(*b"abcdef");
    let pdu = b"abcdefghijklmnopqrstuvwxyz";

    let exp_gse_complete_pkt = GseCompletePacket {
        gse_len: 12,
        protocol_type: 4200,
        label: Label::SixBytesLabel(*b"abcdef"),
        pdu: b"abcdefghijklmnopqrstuvwxyz",
    };

    let obs_gse_complete_pkt = GseCompletePacket::new(gse_len, protocol_type, label, pdu);

    assert_eq!(exp_gse_complete_pkt, obs_gse_complete_pkt);
}

#[test]
// 3B Label, Cmplt pkt
fn test_generate_complete_001() {
    let input = GseCompletePacket::new(
        2 + 3 + 26,
        5000,
        Label::ThreeBytesLabel(*b"abc"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0xD0, 0x1F]);
    exp_buffer[2..4].copy_from_slice(&5000_u16.to_be_bytes());
    exp_buffer[4..7].copy_from_slice(b"abc");
    exp_buffer[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
// 6B Label, Cmplt pkt
fn test_generate_complete_002() {
    let input = GseCompletePacket::new(
        2 + 6 + 26,
        4200,
        Label::SixBytesLabel(*b"abcdef"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0xC0, 0x22]);
    exp_buffer[2..4].copy_from_slice(&4200_u16.to_be_bytes());
    exp_buffer[4..10].copy_from_slice(b"abcdef");
    exp_buffer[10..36].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
// Label broadcast, Cmplt pkt
fn test_generate_complete_003() {
    let input = GseCompletePacket::new(2, 4200, Label::Broadcast, b"");

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0xE0, 0x02]);
    exp_buffer[2..4].copy_from_slice(&4200_u16.to_be_bytes());

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
// Label Reuse, Cmplt pkt
fn test_generate_complete_004() {
    let input = GseCompletePacket::new(2 + 26, 0, Label::ReUse, b"abcdefghijklmnopqrstuvwxyz");

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0xF0, 0x1C]);
    exp_buffer[2..4].copy_from_slice(&0_u16.to_be_bytes());
    exp_buffer[4..30].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
#[should_panic]
// Label Reuse, Cmplt pkt, Wrong buffer size: Should panic
fn test_generate_complete_005() {
    let input = GseCompletePacket::new(2 + 26, 0, Label::ReUse, b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 1];
    input.generate(&mut obs_buffer);
}

#[test]
// 3B Label, Cmplt pkt
fn test_parse_complete_001() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xD0, 0x1F]);
    input[2..4].copy_from_slice(&5000_u16.to_be_bytes());
    input[4..7].copy_from_slice(b"abc");
    input[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_pkt = GseCompletePacket::new(
        2 + 3 + 26,
        5000,
        Label::ThreeBytesLabel(*b"abc"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// 6B Label, Cmplt pkt
fn test_parse_complete_002() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xC0, 0x22]);
    input[2..4].copy_from_slice(&4200_u16.to_be_bytes());
    input[4..10].copy_from_slice(b"abcdef");
    input[10..36].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_pkt = GseCompletePacket::new(
        2 + 6 + 26,
        4200,
        Label::SixBytesLabel(*b"abcdef"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// Label broadcast, Cmplt pkt
fn test_parse_complete_003() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xE0, 0x02]);
    input[2..4].copy_from_slice(&5000_u16.to_be_bytes());

    let exp_pkt = GseCompletePacket::new(2, 5000, Label::Broadcast, b"");

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// Label Reuse, Cmplt pkt
fn test_parse_complete_004() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xF0, 0x1C]);
    input[2..4].copy_from_slice(&4200_u16.to_be_bytes());
    input[4..30].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_pkt = GseCompletePacket::new(2 + 26, 4200, Label::ReUse, b"abcdefghijklmnopqrstuvwxyz");

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// Label Reuse, complete pkt as first frag pkt: Wrong Pkt Type
fn test_parse_complete_005() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xB0, 0x1C]);
    input[2..4].copy_from_slice(&4200_u16.to_be_bytes());
    input[4..30].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_err = "Wrong PktType";

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// Label Reuse, complete pkt as intermediate pkt: Wrong Pkt Type
fn test_parse_complete_006() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x30, 0x1C]);
    input[2..4].copy_from_slice(&4200_u16.to_be_bytes());
    input[4..30].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_err = "Wrong PktType";

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// Label Reuse, complete pkt as end frag pkt: Wrong Pkt Type
fn test_parse_complete_007() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x70, 0x1C]);
    input[2..4].copy_from_slice(&4200_u16.to_be_bytes());
    input[4..30].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_err = "Wrong PktType";

    let result_pkt = GseCompletePacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
fn test_new_first_frag_pkt() {
    let gse_len: u16 = 12;
    let frag_id: u8 = 2;
    let total_length: u16 = 1000;
    let protocol_type: u16 = 4200;
    let label = Label::SixBytesLabel(*b"abcdef");
    let pdu = b"abcdefghijklmnopqrstuvwxyz";

    let exp_gse_first_frag_pkt = GseFirstFragPacket {
        gse_len: 12,
        frag_id: 2,
        total_length: 1000,
        protocol_type: 4200,
        label: Label::SixBytesLabel(*b"abcdef"),
        pdu: b"abcdefghijklmnopqrstuvwxyz",
    };

    let obs_gse_first_frag_pkt =
        GseFirstFragPacket::new(gse_len, frag_id, total_length, protocol_type, label, pdu);

    assert_eq!(exp_gse_first_frag_pkt, obs_gse_first_frag_pkt);
}

#[test]
// 3B Label, First frag pkt
fn test_generate_first_frag_001() {
    let input = GseFirstFragPacket::new(
        1 + 2 + 2 + 3 + 26,
        3,
        1000,
        5000,
        Label::ThreeBytesLabel(*b"abc"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0x90, 0x22]);
    exp_buffer[2..3].copy_from_slice(&3_u8.to_be_bytes());
    exp_buffer[3..5].copy_from_slice(&1000_u16.to_be_bytes());
    exp_buffer[5..7].copy_from_slice(&5000_u16.to_be_bytes());
    exp_buffer[7..10].copy_from_slice(b"abc");
    exp_buffer[10..36].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
// 6B Label, first frag pkt
fn test_generate_first_frag_002() {
    let input = GseFirstFragPacket::new(
        2 + 6 + 26 + 1 + 2,
        0,
        50,
        4200,
        Label::SixBytesLabel(*b"abcdef"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0x80, 0x25]);
    exp_buffer[2..3].copy_from_slice(&0_u8.to_be_bytes());
    exp_buffer[3..5].copy_from_slice(&50_u16.to_be_bytes());
    exp_buffer[5..7].copy_from_slice(&4200_u16.to_be_bytes());
    exp_buffer[7..13].copy_from_slice(b"abcdef");
    exp_buffer[13..39].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
// Label broadcast, first frag pkt
fn test_generate_first_frag_003() {
    let input = GseFirstFragPacket::new(5, 255, 50, 4200, Label::Broadcast, b"");

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0xA0, 0x05]);
    exp_buffer[2..3].copy_from_slice(&255_u8.to_be_bytes());
    exp_buffer[3..5].copy_from_slice(&50_u16.to_be_bytes());
    exp_buffer[5..7].copy_from_slice(&4200_u16.to_be_bytes());

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
// Label Reuse, first frag pkt
fn test_generate_first_frag_004() {
    let input = GseFirstFragPacket::new(
        2 + 1 + 2 + 26,
        125,
        125,
        0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0xB0, 0x1F]);
    exp_buffer[2..3].copy_from_slice(&125_u8.to_be_bytes());
    exp_buffer[3..5].copy_from_slice(&125_u16.to_be_bytes());
    exp_buffer[5..7].copy_from_slice(&0_u16.to_be_bytes());
    exp_buffer[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
#[should_panic]
// Label Reuse, first frag pkt
fn test_generate_first_frag_005() {
    let input = GseFirstFragPacket::new(
        2 + 1 + 2 + 26,
        125,
        125,
        0,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let mut obs_buffer = [0; 1];
    input.generate(&mut obs_buffer);
}

#[test]
// 3B Label, first frag pkt
fn test_parse_first_frag_001() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x90, 0x22]);
    input[2..3].copy_from_slice(&0_u8.to_be_bytes());
    input[3..5].copy_from_slice(&1000_u16.to_be_bytes());
    input[5..7].copy_from_slice(&5000_u16.to_be_bytes());
    input[7..10].copy_from_slice(b"abc");
    input[10..36].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_pkt = GseFirstFragPacket::new(
        2 + 3 + 2 + 1 + 26,
        0,
        1000,
        5000,
        Label::ThreeBytesLabel(*b"abc"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// 6B Label, first frag pkt
fn test_parse_first_frag_002() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x80, 0x25]);
    input[2..3].copy_from_slice(&0_u8.to_be_bytes());
    input[3..5].copy_from_slice(&300_u16.to_be_bytes());
    input[5..7].copy_from_slice(&4200_u16.to_be_bytes());
    input[7..13].copy_from_slice(b"abcdef");
    input[13..39].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_pkt = GseFirstFragPacket::new(
        2 + 2 + 1 + 26 + 6,
        0,
        300,
        4200,
        Label::SixBytesLabel(*b"abcdef"),
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// Label broadcast, first frag pkt
fn test_parse_first_frag_003() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xA0, 0x05]);
    input[2..3].copy_from_slice(&125_u8.to_be_bytes());
    input[3..5].copy_from_slice(&125_u16.to_be_bytes());
    input[5..7].copy_from_slice(&5000_u16.to_be_bytes());

    let exp_pkt = GseFirstFragPacket::new(2 + 1 + 2, 125, 125, 5000, Label::Broadcast, b"");

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// Label Reuse, first frag pkt
fn test_parse_first_frag_004() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xB0, 0x1F]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..5].copy_from_slice(&1000_u16.to_be_bytes());
    input[5..7].copy_from_slice(&4200_u16.to_be_bytes());
    input[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_pkt = GseFirstFragPacket::new(
        2 + 26 + 1 + 2,
        255,
        1000,
        4200,
        Label::ReUse,
        b"abcdefghijklmnopqrstuvwxyz",
    );

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// Label Reuse, first frag pkt as complete pkt: Wrong Pkt Type
fn test_parse_first_frag_005() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xF0, 0x1F]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..5].copy_from_slice(&1000_u16.to_be_bytes());
    input[5..7].copy_from_slice(&4200_u16.to_be_bytes());
    input[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_err = "Wrong PktType";

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// Label Reuse, first frag pkt as intermediate frag pkt: Wrong Pkt Type
fn test_parse_first_frag_006() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x30, 0x1F]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..5].copy_from_slice(&1000_u16.to_be_bytes());
    input[5..7].copy_from_slice(&4200_u16.to_be_bytes());
    input[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_err = "Wrong PktType";

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// Label Reuse, first frag pkt as end frag pkt: Wrong Pkt Type
fn test_parse_first_frag_007() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x70, 0x1F]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..5].copy_from_slice(&1000_u16.to_be_bytes());
    input[5..7].copy_from_slice(&4200_u16.to_be_bytes());
    input[7..33].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let exp_err = "Wrong PktType";

    let result_pkt = GseFirstFragPacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
fn test_new_intermediate_pkt() {
    let gse_len: u16 = 12;
    let frag_id: u8 = 42;
    let pdu = b"abcdefghijklmnopqrstuvwxyz";

    let exp_gse_complete_pkt = GseIntermediatePacket {
        gse_len: 12,
        frag_id: 42,
        pdu: b"abcdefghijklmnopqrstuvwxyz",
    };

    let obs_gse_complete_pkt = GseIntermediatePacket::new(gse_len, frag_id, pdu);

    assert_eq!(exp_gse_complete_pkt, obs_gse_complete_pkt);
}

#[test]
// Intermediate pkt
fn test_generate_intermediate_001() {
    let input = GseIntermediatePacket::new(1 + 26, 50, b"abcdefghijklmnopqrstuvwxyz");

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0x30, 0x1B]);
    exp_buffer[2..3].copy_from_slice(&50_u8.to_be_bytes());
    exp_buffer[3..29].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
#[should_panic]
// Intermediate pkt, Wrong pkt size: should panic
fn test_generate_intermediate_002() {
    let input = GseIntermediatePacket::new(1 + 26, 50, b"abcdefghijklmnopqrstuvwxyz");

    let mut obs_buffer = [0; 1];
    input.generate(&mut obs_buffer);
}

#[test]
// Intermediate pkt
fn test_parse_intermediate_001() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x30, 0x01]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());

    let exp_pkt = GseIntermediatePacket::new(1, 255, b"");

    let result_pkt = GseIntermediatePacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// intermediate pkt as Complete pkt: Wrong Pkt Type
fn test_parse_intermediate_002() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xF0, 0x01]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());

    let exp_err = "Wrong PktType";

    let result_pkt = GseIntermediatePacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// intermediate pkt as first frag pkt: Wrong Pkt Type
fn test_parse_intermediate_003() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xB0, 0x01]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());

    let exp_err = "Wrong PktType";

    let result_pkt = GseIntermediatePacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// intermediate pkt as end pkt: Wrong Pkt Type
fn test_parse_intermediate_004() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x70, 0x01]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());

    let exp_err = "Wrong PktType";

    let result_pkt = GseIntermediatePacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
fn test_new_end_frag_pkt() {
    let gse_len: u16 = 12;
    let frag_id: u8 = 42;
    let pdu = b"abcdefghijklmnopqrstuvwxyz";
    let crc = 7500;

    let exp_gse_complete_pkt = GseEndFragPacket {
        gse_len: 12,
        frag_id: 42,
        pdu: b"abcdefghijklmnopqrstuvwxyz",
        crc: 7500,
    };

    let obs_gse_complete_pkt = GseEndFragPacket::new(gse_len, frag_id, pdu, crc);

    assert_eq!(exp_gse_complete_pkt, obs_gse_complete_pkt);
}

#[test]
// End Frag pkt
fn test_generate_end_frag_001() {
    let input = GseEndFragPacket::new(1 + 4 + 26, 50, b"abcdefghijklmnopqrstuvwxyz", 0);

    let mut exp_buffer = [0; 100];
    exp_buffer[..2].copy_from_slice(&[0x70, 0x1F]);
    exp_buffer[2..3].copy_from_slice(&50_u8.to_be_bytes());
    exp_buffer[3..29].copy_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    exp_buffer[29..33].copy_from_slice(&0_u32.to_be_bytes());

    let mut obs_buffer = [0; 100];
    input.generate(&mut obs_buffer);

    assert_eq!(exp_buffer, obs_buffer);
}

#[test]
#[should_panic]
// End Frag pkt, Too small buffer: Should panic
fn test_generate_end_frag_002() {
    let input = GseEndFragPacket::new(1 + 4 + 26, 50, b"abcdefghijklmnopqrstuvwxyz", 0);

    let mut obs_buffer = [0; 1];
    input.generate(&mut obs_buffer);
}

#[test]
// End Frag pkt
fn test_parse_end_frag_001() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x70, 0x05]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..7].copy_from_slice(&570_u32.to_be_bytes());

    let exp_pkt = GseEndFragPacket::new(5, 255, b"", 570);

    let result_pkt = GseEndFragPacket::parse(&input);
    match result_pkt {
        Ok(obs_pkt) => assert_eq!(exp_pkt, obs_pkt),
        Err(_) => panic!(),
    }
}

#[test]
// End Frag pkt as complete pkt: Wrong pkt Type
fn test_parse_end_frag_002() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xF0, 0x05]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..7].copy_from_slice(&570_u32.to_be_bytes());

    let exp_err = "Wrong PktType";

    let result_pkt = GseEndFragPacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// End Frag pkt as first frag pkt: Wrong pkt Type
fn test_parse_end_frag_003() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0xB0, 0x05]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..7].copy_from_slice(&570_u32.to_be_bytes());

    let exp_err = "Wrong PktType";

    let result_pkt = GseEndFragPacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}

#[test]
// End Frag pkt as intermediate pkt: Wrong pkt type
fn test_parse_end_frag_004() {
    let mut input = [0; 100];
    input[..2].copy_from_slice(&[0x30, 0x05]);
    input[2..3].copy_from_slice(&255_u8.to_be_bytes());
    input[3..7].copy_from_slice(&570_u32.to_be_bytes());

    let exp_err = "Wrong PktType";

    let result_pkt = GseEndFragPacket::parse(&input);
    match result_pkt {
        Ok(_) => panic!(),
        Err(obs_err) => assert_eq!(exp_err, obs_err),
    }
}
