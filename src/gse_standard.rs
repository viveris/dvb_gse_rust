// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for GseStandard
//!
//! This module contains the GSE standard constants

// Gse constant for start and end bits
pub const COMPLETE_PKT: u16 = 0xC000;
pub const FIRST_PKT: u16 = 0x8000;
pub const INTERMEDIATE_PKT: u16 = 0x0000;
pub const END_PKT: u16 = 0x4000;
pub const START_END_MASK: u16 = 0xC000;

// Gse constant for label type
pub const LABEL_6_B: u16 = 0;
pub const LABEL_3_B: u16 = 0x1000;
pub const LABEL_BROADCAST: u16 = 0x2000;
pub const LABEL_REUSE: u16 = 0x3000;
pub const LABEL_TYPE_MASK: u16 = 0x3000;

pub const LABEL_6_B_LEN: usize = 6;
pub const LABEL_3_B_LEN: usize = 3;
pub const LABEL_BROADCAST_LEN: usize = 0;
pub const LABEL_REUSE_LEN: usize = 0;

// Gse fields size
pub const FIXED_HEADER_LEN: usize = 2;
pub const PROTOCOL_LEN: usize = 2;
pub const FRAG_ID_LEN: usize = 1;
pub const TOTAL_LENGTH_LEN: usize = 2;
pub const FIRST_FRAG_LEN: usize = FIXED_HEADER_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN;
pub const GSE_LEN_MAX: usize = 0xFFF;

// Gse constant for gse len
pub const GSE_LEN_MASK: u16 = 0x0FFF;

// Gse constant for total_length
pub const TOTAL_LEN_MAX: usize = 0xFFFF;


// Gse constant for CRC
pub const CRC_LEN: usize = 4;
pub const CRC_INIT: u32 = 0xFFFFFFFF;

// GSE constant for protocol type
// All protocols above 1535 are procesed as user trafic
// https://www.etsi.org/deliver/etsi_ts/102600_102699/10260601/01.02.01_60/ts_10260601v010201p.pdf
pub const SECOND_RANGE_PTYPE: u16 = 0x600;

// https://www.etsi.org/deliver/etsi_en/301500_301599/30154502/01.03.01_60/en_30154502v010301p.pdf
// Section 5.1.0
pub const NCR_PROTOCOL_ID: u16 = 0x0081;
pub const INTERNAL_SIGNALING_PROTOCOL_ID: u16 = 0x0082;
