// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

use super::{Label, LabelType};

/// Get type test: 6B Label
#[test]
fn test_get_type_001() {
    let label_in = Label::SixBytesLabel([0; 6]);

    let exp_label_type = LabelType::SixBytesLabel;

    let obs_label_type = label_in.get_type();

    assert_eq!(obs_label_type, exp_label_type);
}

/// Get type test: 3B Label
#[test]
fn test_get_type_002() {
    let label_in = Label::ThreeBytesLabel([0; 3]);

    let exp_label_type = LabelType::ThreeBytesLabel;

    let obs_label_type = label_in.get_type();

    assert_eq!(obs_label_type, exp_label_type);
}

/// Get type test: Label Broadcast
#[test]
fn test_get_type_003() {
    let label_in = Label::Broadcast;

    let exp_label_type = LabelType::Broadcast;

    let obs_label_type = label_in.get_type();

    assert_eq!(obs_label_type, exp_label_type);
}

/// Get type test: Label ReUse
#[test]
fn test_get_type_004() {
    let label_in = Label::ReUse;

    let exp_label_type = LabelType::ReUse;

    let obs_label_type = label_in.get_type();

    assert_eq!(obs_label_type, exp_label_type);
}

/// Get len test: Label 6B
#[test]
fn test_get_len_001() {
    let label_in = Label::SixBytesLabel([0; 6]);

    let exp_label_len = 6;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// Get len test: 3B Label
#[test]
fn test_get_len_002() {
    let label_in = Label::ThreeBytesLabel([0; 3]);

    let exp_label_len = 3;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// Get len test: Label Broadcast
#[test]
fn test_get_len_003() {
    let label_in = Label::Broadcast;

    let exp_label_len = 0;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// Get len test: Label ReUse
#[test]
fn test_get_len_004() {
    let label_in = Label::ReUse;

    let exp_label_len = 0;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// New label: 6B Label
#[test]
fn test_new_label_001() {
    let label_type_in = LabelType::SixBytesLabel;
    let bytes_in = [0; 6];

    let exp_label = Label::SixBytesLabel([0; 6]);

    let obs_label = Label::new(&label_type_in, &bytes_in);

    assert_eq!(obs_label, exp_label);
}

/// New label: 6B Label
#[test]
fn test_new_label_002() {
    let label_type_in = LabelType::SixBytesLabel;
    let bytes_in = *b"abcdef";

    let exp_label = Label::SixBytesLabel(*b"abcdef");

    let obs_label = Label::new(&label_type_in, &bytes_in);

    assert_eq!(obs_label, exp_label);
}

/// New label: 3B Label
#[test]
fn test_new_label_003() {
    let label_type_in = LabelType::ThreeBytesLabel;
    let bytes_in = [0; 3];

    let exp_label = Label::ThreeBytesLabel([0; 3]);

    let obs_label = Label::new(&label_type_in, &bytes_in[..]);

    assert_eq!(obs_label, exp_label);
}

/// New label: 3B Label
#[test]
fn test_new_label_004() {
    let label_type_in = LabelType::ThreeBytesLabel;
    let bytes_in = *b"abc";

    let exp_label = Label::ThreeBytesLabel(*b"abc");

    let obs_label = Label::new(&label_type_in, &bytes_in);

    assert_eq!(obs_label, exp_label);
}

/// New label: Label Broadcast
#[test]
fn test_new_label_005() {
    let label_type_in = LabelType::Broadcast;
    let bytes_in = [];

    let exp_label = Label::Broadcast;

    let obs_label = Label::new(&label_type_in, &bytes_in[..]);

    assert_eq!(obs_label, exp_label);
}

/// New label: Label ReUse
#[test]
fn test_new_label_006() {
    let label_type_in = LabelType::ReUse;
    let bytes_in = [];

    let exp_label = Label::ReUse;

    let obs_label = Label::new(&label_type_in, &bytes_in[..]);

    assert_eq!(obs_label, exp_label);
}

/// new label test: Edit original before compare to verify the copy of the content in the label
///
/// 6B label
#[test]
fn test_new_label_007() {
    let label_type_in = LabelType::SixBytesLabel;
    let mut bytes_in = [0; 6];

    let exp_label = Label::SixBytesLabel([0; 6]);

    let obs_label = Label::new(&label_type_in, &bytes_in);
    // Edit original before comparing
    bytes_in[0] = 0xFF as u8;

    assert_eq!(obs_label, exp_label);
}

/// new label test: Edit original before compare to verify the copy of the content in the label
///
/// 3B label
#[test]
fn test_new_label_008() {
    let label_type_in = LabelType::ThreeBytesLabel;
    let mut bytes_in = [0; 3];

    let exp_label = Label::ThreeBytesLabel([0; 3]);

    let obs_label = Label::new(&label_type_in, &bytes_in);
    // Edit original before comparing
    bytes_in[0] = 0xFF as u8;

    assert_eq!(obs_label, exp_label);
}

/// new label test: faulty 001
///
/// larger slice than expected
/// 6B label
#[test]
#[should_panic]
fn test_new_label_009() {
    let label_type = LabelType::SixBytesLabel;
    let label = &[0; 7];

    Label::new(&label_type, label);
}

/// new label test: faulty 002
///
/// smaller slice than expected
/// 6B label
#[test]
#[should_panic]
fn test_new_label_010() {
    let label_type = LabelType::SixBytesLabel;
    let label = b"01234";

    Label::new(&label_type, label);
}

/// new label test: faulty 003
///
/// smaller slice than expected
/// 3B label
#[test]
#[should_panic]
fn test_new_label_011() {
    let label_type = LabelType::ThreeBytesLabel;
    let label = &[0; 4];

    Label::new(&label_type, label);
}

/// new label test: faulty 004
///
/// larger slice than expected
/// 3B label
#[test]
#[should_panic]
fn test_new_label_012() {
    let label_type = LabelType::ThreeBytesLabel;
    let label = b"0123";

    Label::new(&label_type, label);
}

/// new label test: faulty 005
///
/// larger slice than expected
/// label broadcast
#[test]
#[should_panic]
fn test_new_label_0013() {
    let label_type = LabelType::Broadcast;
    let label = &[0; 1];

    Label::new(&label_type, label);
}

/// new label test: faulty 006
///
/// larger slice than expected
/// label re use
#[test]
#[should_panic]
fn test_new_label_0014() {
    let label_type = LabelType::ReUse;
    let label = b"0";

    Label::new(&label_type, label);
}

/// get_bytes label test: 6B
#[test]
fn test_get_bytes_label_001() {
    let label_in = Label::SixBytesLabel(*b"012345");

    let exp_bytes = b"012345";

    let obs_bytes = label_in.get_bytes();

    assert_eq!(obs_bytes, exp_bytes);
}

/// get_bytes label test: 3B
#[test]
fn test_get_bytes_label_002() {
    let label_in = Label::ThreeBytesLabel(*b"012");

    let exp_bytes = b"012";

    let obs_bytes = label_in.get_bytes();

    assert_eq!(obs_bytes, exp_bytes);
}

/// get_bytes label test: Broadcast
#[test]
fn test_get_bytes_label_003() {
    let label_in = Label::Broadcast;

    let exp_bytes = b"";

    let obs_bytes = label_in.get_bytes();

    assert_eq!(obs_bytes, exp_bytes);
}

/// get_bytes label test: ReUse
#[test]
fn test_get_bytes_label_004() {
    let label_in = Label::ReUse;

    let exp_bytes = b"";

    let obs_bytes = label_in.get_bytes();

    assert_eq!(obs_bytes, exp_bytes);
}

/// Get len test: LabelType 6B
#[test]
fn test_get_len_from_label_type_001() {
    let label_in = LabelType::SixBytesLabel;

    let exp_label_len = 6;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// Get len test: 3B LabelType
#[test]
fn test_get_len_from_label_type_002() {
    let label_in = LabelType::ThreeBytesLabel;

    let exp_label_len = 3;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// Get len test: LabelType Broadcast
#[test]
fn test_get_len_from_label_type_003() {
    let label_in = LabelType::Broadcast;

    let exp_label_len = 0;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}

/// Get len test: LabelType ReUse
#[test]
fn test_get_len_from_label_type_004() {
    let label_in = LabelType::ReUse;

    let exp_label_len = 0;

    let obs_label_len = label_in.len();

    assert_eq!(obs_label_len, exp_label_len);
}
