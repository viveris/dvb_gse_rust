// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for label
//!
//! This module contains the representation of GSE Label and the functions associated.
//! 
#[cfg(test)]
mod tests;
use crate::gse_standard::{LABEL_3_B_LEN, LABEL_6_B_LEN, LABEL_BROADCAST_LEN, LABEL_REUSE_LEN};

/// Represent a Label and its data
///
/// Define label byte array based on the label type
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Label {
    SixBytesLabel([u8; 6]),
    ThreeBytesLabel([u8; 3]),
    Broadcast,
    ReUse,
}

#[derive(PartialEq, Eq, Debug)]
/// Represent the type of Label
pub enum LabelType {
    SixBytesLabel,
    ThreeBytesLabel,
    Broadcast,
    ReUse,
}

impl Label {
    /// Get label type (u16)
    ///
    /// Return the 2 bits label type shifted by 12 to the left
    pub fn get_type(&self) -> LabelType {
        let label_type: LabelType = match self {
            Label::SixBytesLabel(_) => LabelType::SixBytesLabel,
            Label::ThreeBytesLabel(_) => LabelType::ThreeBytesLabel,
            Label::Broadcast => LabelType::Broadcast,
            Label::ReUse => LabelType::ReUse,
        };
        label_type
    }

    /// Get label len
    ///
    /// Return the size of the label byte array

    #[allow(clippy::len_without_is_empty)]

 pub fn len(&self) -> usize {
        let label_length: usize = match self {
            Label::SixBytesLabel(_) => LABEL_6_B_LEN,
            Label::ThreeBytesLabel(_) => LABEL_3_B_LEN,
            Label::Broadcast => LABEL_BROADCAST_LEN,
            Label::ReUse => LABEL_REUSE_LEN,
        };
        label_length
    }

    /// Create a new label based on label type and label content
    pub fn new(label_type: &LabelType, label: &[u8]) -> Label {
        if label.len() == label_type.len() {
            let label: Label = match label_type {
                LabelType::SixBytesLabel => Label::SixBytesLabel(label.try_into().unwrap()),
                LabelType::ThreeBytesLabel => Label::ThreeBytesLabel(label.try_into().unwrap()),
                LabelType::Broadcast => Label::Broadcast,
                LabelType::ReUse => Label::ReUse,
            };
            label
        } else {
            // Misuse of function
            panic!("Wrong size label content");
        }
    }

    /// Get the label byte array from label
    pub fn get_bytes(&self) -> &[u8] {
        let label: &[u8] = match self {
            Label::SixBytesLabel(label) => label,
            Label::ThreeBytesLabel(label) => label,
            Label::Broadcast | Label::ReUse => &[],
        };
        label
    }
}

impl LabelType {
    /// Get label len
    ///
    /// Return the size of the label byte array

    #[allow(clippy::len_without_is_empty)]

    pub fn len(&self) -> usize {
        let label_length: usize = match self {
            LabelType::SixBytesLabel => LABEL_6_B_LEN,
            LabelType::ThreeBytesLabel => LABEL_3_B_LEN,
            LabelType::Broadcast => LABEL_BROADCAST_LEN,
            LabelType::ReUse => LABEL_REUSE_LEN,
        };
        label_length
    }
}
