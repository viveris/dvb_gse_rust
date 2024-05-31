// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for gse encapsulation
//!
//! The encapsulation module follows the dvb gse standard.
//! It supports complete packet, first fragment packet, intermediate fragment packet, end fragment packet and padding.
//! It also allows you to manage any type of label including the re-use label.

use crate::crc::CrcCalculator;
use crate::gse_standard::{
    COMPLETE_PKT, CRC_LEN, END_PKT, FIRST_FRAG_LEN, FIRST_PKT, FIRST_RANGE_PTYPE, FIXED_HEADER_LEN,
    FRAG_ID_LEN, GSE_LEN_MASK, GSE_LEN_MAX, INTERMEDIATE_PKT, LABEL_3_B, LABEL_6_B,
    LABEL_BROADCAST, LABEL_REUSE, LABEL_TYPE_MASK, PROTOCOL_LEN, START_END_MASK, TOTAL_LENGTH_LEN,
    TOTAL_LEN_MAX,
};
use crate::label::Label;
use crate::label::LabelType;
use crate::pkt_type::PktType;

#[cfg(test)]
mod tests;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// Structure PayloadMetadata
///
/// *   Protocol type describe the protocol of that pdu
/// *   Label describe the recipient of that pdu
pub struct EncapMetadata {
    pub protocol_type: u16,
    pub label: Label,
}

impl EncapMetadata {
    pub fn new(protocol_type: u16, label: Label) -> Self {
        Self {
            protocol_type,
            label,
        }
    }
}
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// Structure ContextFrag : Define the context of the fragmentation
/// *   Frag Id describe the fragment id
/// *   Crc describe the cyclic redundancy check
/// *   Len pdu frag describe the len of the pdu already written
pub struct ContextFrag {
    pub frag_id: u8,
    pub crc: u32,
    pub len_pdu_frag: u16,
}

impl ContextFrag {
    pub fn new(frag_id: u8, crc: u32, len_pdu_frag: u16) -> Self {
        Self {
            frag_id,
            crc,
            len_pdu_frag,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
/// Enumeration EncapStatus : Define the status of the encapsulation.
/// If a pdu is encapsulated, the status return the length of the packet by the option completed packet.
pub enum EncapStatus {
    CompletedPkt(u16),
    FragmentedPkt(u16, ContextFrag),
}

impl EncapStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::CompletedPkt(_) => "Fully encapsulated packet",
            Self::FragmentedPkt(_, _) => "Partially encapsulated packet",
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
/// Enumeration EncapError : Define the error of the encapsulation.
/// The encapsulation failed, the status return a comment about the error that occured.
pub enum EncapError {
    ErrorSizeBuffer,
    ErrorPduLength,
    ErrorProtocolType,
    ErrorInvalidLabel,
}

impl EncapError {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::ErrorSizeBuffer => "Too small buffer",
            Self::ErrorPduLength => "Too large pdu to be stocked in total_length",
            Self::ErrorProtocolType => "Extension header are not implemented",
            Self::ErrorInvalidLabel => "Label 6B [0, 0, 0, 0, 0, 0] shall not be used",
        }
    }
}

/// Structure Encapsulator
/// 
/// The object oriented structure Encapsulator saves the trait of crc calculation and allows an autonomous use of the Re Use Label.
/// 
/// When "re_use_activated" is true : the autonomous use of Re Use Label is enable.
/// Then, if the label of the pdu is 3 or 6 Bytes and it is the same as last_label, the label sent in the next packet will be a Re Use Label. 
/// Else, the last label is update. 
/// 
/// The last label has to be reset by the user at the begining of each new base band frame. 
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Encapsulator<C: CrcCalculator> {
    crc_calculator: C,
    re_use_activated: bool,
    last_label: Option<Label>,
}

impl<C: CrcCalculator> Encapsulator<C> {
    /// Encapsulator constructor
    pub fn new(crc_calculator: C) -> Encapsulator<C> {
        let encapsulator = Encapsulator {
            last_label: None,
            crc_calculator,
            re_use_activated: true,
        };
        encapsulator
    }

    pub fn set_crc_calculator(&mut self, calculator: C) {
        self.crc_calculator = calculator;
    }

    pub fn get_crc_calculator(&mut self) -> &C {
        &self.crc_calculator
    }

    /// Set the last label at None, it has to be done at the begining of each new base band frame
    pub fn reset_last_label(&mut self) {
        self.last_label = None;
    }

    pub fn enable_re_use_label(&mut self, enable: bool) {
        self.re_use_activated = enable;
    }

    pub fn is_enabled_re_use_label(&mut self) -> bool {
        self.re_use_activated
    }

    /// GSE encapsulation of a gse header and the payload in a buffer
    ///
    /// The metadata and the pdu are written in the buffer next the gse header and the function returns the size of the packet if the encapsulation succeed.
    /// If the buffer is large enough, the pdu is completely encapsulated and the function returns the status completed packet.
    /// Else, the pdu is partially encapsulated and a context of fragmentation is returned with the status fragmented packet.
    /// If the pdu can not be encapsulated, it returns the error status.
    /// 
    /// # Example of encapsulating a complete payload in a gse packet
    /// ```
    /// use dvb_gse_rust::crc::DefaultCrc;
    /// use dvb_gse_rust::label::Label;
    /// use dvb_gse_rust::gse_encap::{Encapsulator, EncapMetadata, EncapStatus, EncapError};
    /// 
    /// 
    /// // Metadata and Payload (pdu) has to be set :
    /// let protocol_type = 0xFFFF;
    /// let label = Label::SixBytesLabel(*b"012345");
    /// let metadata = EncapMetadata {
    ///     protocol_type: protocol_type, 
    ///     label: label,
    /// };
    /// let default_frag_id = 1;
    /// let pdu = b"abcdefghijklmnopqrstuvwxyz";
    ///
    /// // The packet has to be written in a buffer
    /// let mut buffer = [0; 1000];
    /// 
    /// // Creation of the encapsulator with his crc calculation trait
    /// let mut encapsulator = Encapsulator::new(DefaultCrc {});
    ///
    /// // Thus, the buffer can be fulfilled with the payload encapsulated in a gse packet
    /// let encap_status = encapsulator.encap(pdu, default_frag_id, metadata, &mut buffer);
    /// let exp_encap_status = Ok(EncapStatus::CompletedPkt((2+2+label.len()+pdu.len()) as u16));
    /// assert_eq!(encap_status, exp_encap_status);
    /// 
    /// ```
    /// 
    /// # Example of encapsulating a fragmented payload in a gse packet
    /// ```
    /// use dvb_gse_rust::crc::{DefaultCrc, CrcCalculator};
    /// use dvb_gse_rust::label::Label;
    /// use dvb_gse_rust::gse_encap::{Encapsulator, EncapMetadata, EncapStatus, EncapError, ContextFrag};
    /// 
    /// 
    /// // Metadata and Payload (pdu) has to be set :
    /// let protocol_type = 0xFFFF;
    /// let label = Label::SixBytesLabel(*b"012345");
    /// let metadata = EncapMetadata {
    ///     protocol_type: protocol_type, 
    ///     label: label,
    /// };
    /// let default_frag_id = 1;
    /// let pdu = b"abcdefghijklmnopqrstuvwxyz";
    ///
    /// // The packet has to be written in a buffer
    /// let mut buffer = [0; 20];
    ///
    /// // Creation of the encapsulator with his crc calculation trait
    /// let mut encapsulator = Encapsulator::new(DefaultCrc {});
    /// 
    /// // Thus, the buffer can be fulfilled with a fragment of the payload encapsulated in a gse packet
    /// let encap_status = encapsulator.encap(pdu, default_frag_id, metadata, &mut buffer);
    /// let crc = DefaultCrc{}.calculate_crc32(&pdu[..], protocol_type, (pdu.len()+label.len()+2).try_into().unwrap(), label.get_bytes());
    /// let exp_encap_status = Ok(EncapStatus::FragmentedPkt(20, ContextFrag{ frag_id: default_frag_id, crc, len_pdu_frag: 7 }));
    /// assert_eq!(encap_status, exp_encap_status);
    /// 
    /// ```
    /// 
    /// # Example of unsuccessful encapsulation
    /// 
    /// ```
    /// use dvb_gse_rust::label::Label;
    /// use dvb_gse_rust::gse_encap::{Encapsulator, EncapMetadata, EncapStatus, EncapError};
    /// use dvb_gse_rust::crc::DefaultCrc;
    /// 
    /// // Metadata and Payload (pdu) has to be set :
    /// let protocol_type = 0xFFFF;
    /// let label = Label::SixBytesLabel(*b"012345");
    /// let metadata = EncapMetadata {
    ///     protocol_type: protocol_type, 
    ///     label: label,
    /// };
    /// let default_frag_id = 1;
    /// let pdu = b"abcdefghijklmnopqrstuvwxyz";
    ///
    /// // The packet has to be written in a buffer
    /// let mut buffer = [0; 10];
    /// 
    /// // Creation of the encapsulator with his crc calculation trait
    /// let mut encapsulator = Encapsulator::new(DefaultCrc {});
    ///
    /// // Thus, the buffer can not be fulfilled with the payload because the buffer is too small
    /// let encap_status = encapsulator.encap(pdu, default_frag_id, metadata, &mut buffer);
    /// let exp_encap_status = Err(EncapError::ErrorSizeBuffer);
    /// assert_eq!(encap_status, exp_encap_status);
    /// 
    /// ```
    pub fn encap(
        &mut self,
        pdu: &[u8],
        frag_id: u8,
        metadata: EncapMetadata,
        buffer: &mut [u8],
    ) -> Result<EncapStatus, EncapError> {
        let mut label = metadata.label;
        let protocol_type = metadata.protocol_type;

        // check label
        if label == Label::SixBytesLabel([0, 0, 0, 0, 0, 0]) {
            return Err(EncapError::ErrorInvalidLabel);
        }

        // check protocol_type
        if protocol_type <= FIRST_RANGE_PTYPE {
            return Err(EncapError::ErrorProtocolType);
        }

        // label reuse
        if self.re_use_activated {
            // check label reuse
            if Some(label) == self.last_label {
                label = Label::ReUse;
            }

            // update last_label
            if label == Label::Broadcast {
                self.last_label = None;
            } else if label != Label::ReUse {
                self.last_label = Some(label);
            }
        }

        let label_len = label.len();
        let pdu_len = pdu.len();
        let gse_len_min = pdu_len + label_len + PROTOCOL_LEN;

        // if it fits into a complete package
        let min_header_len = FIXED_HEADER_LEN + PROTOCOL_LEN + label_len;
        let buffer_len = buffer.len();

        let pdu_len_encapsulated: usize;
        let pkt_type: PktType;
        let gse_len: u16;

        // if all the data and metadata will fit in the buffer, and
        // if the protocol can handle the size of the packer
        if (buffer_len >= min_header_len + pdu_len) && (GSE_LEN_MAX >= gse_len_min) {
            // complet packet
            pkt_type = PktType::CompletePkt;
            pdu_len_encapsulated = pdu_len;
            gse_len = gse_len_min as u16;
        } else {
            // first packet
            let min_header_len = min_header_len + FRAG_ID_LEN + TOTAL_LENGTH_LEN;

            // check the buffer size
            // if it cannot write at least more than the header
            if buffer_len < min_header_len {
                return Err(EncapError::ErrorSizeBuffer);
            }

            // check the metadata len
            // if the protocol cannot handle such large amounts of data
            if TOTAL_LEN_MAX < pdu_len + PROTOCOL_LEN + label_len {
                return Err(EncapError::ErrorPduLength);
            }

            pkt_type = PktType::FirstFragPkt;
            pdu_len_encapsulated = buffer_len - min_header_len;
            gse_len =
                (FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + label_len + pdu_len_encapsulated)
                    as u16;
        }

        // write gse fixed header
        let header = generate_gse_header(&pkt_type, &label.get_type(), gse_len as u16);
        let mut offset = FIXED_HEADER_LEN;
        buffer[..offset].copy_from_slice(&header.to_be_bytes());

        let encap_status = match pkt_type {
            PktType::FirstFragPkt => {
                // write fragId
                buffer[offset..offset + FRAG_ID_LEN].copy_from_slice(&frag_id.to_be_bytes());
                offset += FRAG_ID_LEN;

                // write total_length
                let total_len = (pdu_len + PROTOCOL_LEN + label_len) as u16;
                buffer[offset..offset + TOTAL_LENGTH_LEN].copy_from_slice(&total_len.to_be_bytes());
                offset += TOTAL_LENGTH_LEN;

                // define context frag
                let context_frag = ContextFrag {
                    frag_id,
                    crc: self.crc_calculator.calculate_crc32(
                        &pdu[..pdu_len],
                        protocol_type,
                        total_len,
                        label.get_bytes(),
                    ),
                    len_pdu_frag: pdu_len_encapsulated as u16,
                };

                // define encap status
                let pkt_len = FIRST_FRAG_LEN + label_len + pdu_len_encapsulated;
                EncapStatus::FragmentedPkt(pkt_len as u16, context_frag)
            }
            _ => EncapStatus::CompletedPkt(gse_len + FIXED_HEADER_LEN as u16),
        };

        // write protocol type
        buffer[offset..offset + PROTOCOL_LEN].copy_from_slice(&protocol_type.to_be_bytes());
        offset += PROTOCOL_LEN;

        // write label
        buffer[offset..offset + label_len].copy_from_slice(&label.get_bytes());
        offset += label_len;

        // write pdu
        buffer[offset..offset + pdu_len_encapsulated].copy_from_slice(&pdu[..pdu_len_encapsulated]);

        // return status
        Ok(encap_status)
    }

    /// GSE encapsulation of a fragment of a PDU in a buffer
    ///
    /// If the fragment encapsulated in packet fits into the buffer, the function returns the status packet completed.
    /// Else, the fragmented pdu is partially encapsulated and a context of fragmentation is returned with the status fragmented packet.
    /// If the pdu can not be encapsulated, it returns the error status.
    /// 
    /// # Example of encapsulating the entire pdu fragment in a gse packet
    /// ```
    /// use dvb_gse_rust::crc::DefaultCrc;
    /// use dvb_gse_rust::gse_encap::{Encapsulator, ContextFrag, EncapStatus, EncapError};
    /// 
    /// // Context of fragmentation and pdu has to be defined
    /// let default_frag_id = 1;
    /// let default_crc = 1;
    /// let len_pdu_frag= 1;
    /// let pdu = *b"-abcdefghijklmnopqrstuvwxyz";
    /// let context_frag = ContextFrag{ frag_id: default_frag_id, crc: default_crc, len_pdu_frag };
    /// 
    /// // The packet has to be written in a buffer
    /// let mut buffer = [0; 1000];
    /// 
    /// // Creation of the encapsulator with his crc calculation trait
    /// let mut encapsulator = Encapsulator::new(DefaultCrc {});
    ///
    /// // Thus, the buffer can be fulfilled with the payload encapsulated in a gse packet
    /// let encap_status = encapsulator.encap_frag(&pdu, &context_frag, &mut buffer);
    /// let exp_encap_status = Ok(EncapStatus::CompletedPkt((2+1+pdu.len()+4) as u16 - len_pdu_frag));
    /// assert_eq!(encap_status, exp_encap_status);
    ///  ```
    /// 
    /// # Example of partial encapsulation of the pdu fragment in a gse packet
    /// ```
    /// use dvb_gse_rust::crc::DefaultCrc;
    /// use dvb_gse_rust::gse_encap::{Encapsulator, ContextFrag, EncapStatus, EncapError};
    /// 
    /// // Context of fragmentation and pdu has to be defined
    /// let default_frag_id = 1;
    /// let default_crc = 1;
    /// let len_pdu_frag= 1;
    /// let pdu = *b"-abcdefghijklmnopqrstuvwxyz";
    /// let context_frag = ContextFrag{ frag_id: default_frag_id, crc: default_crc, len_pdu_frag };
    /// 
    /// // The packet has to be written in a buffer
    /// let mut buffer = [0; 10];
    /// 
    /// // Creation of the encapsulator with his crc calculation trait
    /// let mut encapsulator = Encapsulator::new(DefaultCrc {});
    ///
    /// // Thus, the buffer can be fulfilled with the payload encapsulated in a gse packet
    /// let encap_status = encapsulator.encap_frag(&pdu, &context_frag, &mut buffer);
    /// let exp_encap_status = Ok(EncapStatus::FragmentedPkt(10, ContextFrag{ frag_id: default_frag_id, crc: default_crc, len_pdu_frag: len_pdu_frag + 7 }));
    /// assert_eq!(encap_status, exp_encap_status);
    ///  ```
    /// 
    /// # Example of unsuccessful encapsulation
    ///
    /// ```
    /// use dvb_gse_rust::crc::DefaultCrc;
    /// use dvb_gse_rust::gse_encap::{Encapsulator, ContextFrag, EncapStatus, EncapError};
    /// 
    /// // Context of fragmentation and pdu has to be defined
    /// let default_frag_id = 1;
    /// let default_crc = 1;
    /// let len_pdu_frag= 1;
    /// let pdu = *b"-abcdefghijklmnopqrstuvwxyz";
    /// let context_frag = ContextFrag{ frag_id: default_frag_id, crc: default_crc, len_pdu_frag };
    ///
    /// // The packet has to be written in a buffer
    /// let mut buffer = [0; 2];
    /// 
    /// // Creation of the encapsulator with his crc calculation trait
    /// let mut encapsulator = Encapsulator::new(DefaultCrc {});
    ///
    /// // Thus, the buffer can not be fulfilled with the payload because the buffer is too small
    /// let encap_status = encapsulator.encap_frag(&pdu[..], &context_frag, &mut buffer);
    /// let exp_encap_status = Err(EncapError::ErrorSizeBuffer);
    /// assert_eq!(encap_status, exp_encap_status);
    /// 
    pub fn encap_frag(
        &self,
        pdu: &[u8],
        context: &ContextFrag,
        buffer: &mut [u8],
    ) -> Result<EncapStatus, EncapError> {
        let len_pdu_frag = context.len_pdu_frag as usize;
        let frag_id = context.frag_id;
        let crc = context.crc;
        let buffer_len = buffer.len();
        let pdu_len = pdu.len();

        // Metadata error
        if len_pdu_frag > pdu_len {
            return Err(EncapError::ErrorPduLength);
        }
        let pdu_len_remaining = pdu_len - len_pdu_frag;

        let gse_end_len = FRAG_ID_LEN + pdu_len_remaining + CRC_LEN;

        let header: u16;
        let pdu_len_encapsulated: usize;
        let encap_status: EncapStatus;
        // End packet
        // if the rest of packet fits in the buffer
        if buffer_len >= gse_end_len + FIXED_HEADER_LEN {
            header =
                generate_gse_header(&PktType::EndFragPkt, &LabelType::ReUse, gse_end_len as u16);
            pdu_len_encapsulated = pdu_len_remaining;

            let mut buffer_offset = FIXED_HEADER_LEN + FRAG_ID_LEN + pdu_len_encapsulated;
            buffer[buffer_offset..buffer_offset + CRC_LEN].copy_from_slice(&crc.to_be_bytes());
            buffer_offset += CRC_LEN;

            encap_status = EncapStatus::CompletedPkt(buffer_offset as u16);
        }
        // if a fragment of the rest fits in the buffer
        else if buffer_len > FIXED_HEADER_LEN + FRAG_ID_LEN {
            let gse_len: usize;

            let pdu_len_available = buffer_len - (FIXED_HEADER_LEN + FRAG_ID_LEN);

            if pdu_len_available > pdu_len_remaining {
                gse_len = FRAG_ID_LEN + pdu_len_remaining;
                pdu_len_encapsulated = pdu_len_remaining;
            } else {
                gse_len = FRAG_ID_LEN + pdu_len_available;
                pdu_len_encapsulated = pdu_len_available;
            }

            header = generate_gse_header(
                &PktType::IntermediateFragPkt,
                &LabelType::ReUse,
                gse_len as u16,
            );

            let buffer_offset = FIXED_HEADER_LEN + gse_len;
            let new_context = ContextFrag {
                frag_id,
                crc,
                len_pdu_frag: (len_pdu_frag + pdu_len_encapsulated) as u16,
            };
            encap_status = EncapStatus::FragmentedPkt(buffer_offset as u16, new_context);
        }
        // not enough room
        else {
            return Err(EncapError::ErrorSizeBuffer);
        }

        // Write the header
        buffer[..FIXED_HEADER_LEN].copy_from_slice(&header.to_be_bytes());
        buffer[FIXED_HEADER_LEN] = frag_id;
        let buffer_offset = FIXED_HEADER_LEN + FRAG_ID_LEN;

        // Write the fragment
        buffer[buffer_offset..buffer_offset + pdu_len_encapsulated]
            .copy_from_slice(&pdu[len_pdu_frag..len_pdu_frag + pdu_len_encapsulated]);

        Ok(encap_status)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct EncapPreview {
    pkt_type: PktType,
    pdu_len: usize,
    pkt_len: u16,
}

/// Preview the encapsulation of the input data and metadata into a GSE packet.
///
/// Given a Protocol Data Unit (PDU), label, protocol type, and a buffer,
/// this function calculates the packet type and length for encapsulation.
///
/// # Arguments
///
/// * `pdu` - The Protocol Data Unit to be encapsulated.
/// * `metadata` - Metadata including the label and protocol type.
/// * `buffer` - Buffer for packet construction.
///
/// # Returns
///
/// Returns a preview of the encapsulated packet or an encapsulation error.
pub fn encap_preview(
    pdu: &[u8],
    metadata: EncapMetadata,
    buffer: &[u8],
) -> Result<EncapPreview, EncapError> {
    let label = metadata.label;
    let protocol_type = metadata.protocol_type;

    let label_len = label.len();
    let pdu_len = pdu.len();
    let gse_len_min = pdu_len + label_len + PROTOCOL_LEN;

    // check label
    if label == Label::SixBytesLabel([0, 0, 0, 0, 0, 0]) {
        return Err(EncapError::ErrorInvalidLabel);
    }

    // check protocol_type
    if protocol_type <= FIRST_RANGE_PTYPE {
        return Err(EncapError::ErrorProtocolType);
    }

    // if it fits into a complete package
    let min_header_len = FIXED_HEADER_LEN + PROTOCOL_LEN + label_len;
    let buffer_len = buffer.len();

    let pdu_len_encapsulated: usize;
    let pkt_type: PktType;
    let gse_len: u16;
    let pkt_len: u16;

    // if all the data and metadata will fit in the buffer, and
    // if the protocol can handle the size of the packer
    if (buffer_len >= min_header_len + pdu_len) && (GSE_LEN_MAX >= gse_len_min) {
        // complet packet
        pkt_type = PktType::CompletePkt;
        gse_len = gse_len_min as u16;
        pkt_len = gse_len + FIXED_HEADER_LEN as u16;
    } else {
        // first packet
        let min_header_len = min_header_len + FRAG_ID_LEN + TOTAL_LENGTH_LEN;

        // check the buffer size
        // if it cannot write at least more than the header
        if buffer_len < min_header_len {
            return Err(EncapError::ErrorSizeBuffer);
        }

        // check the metadata len
        // if the protocol cannot handle such large amounts of data
        if TOTAL_LEN_MAX < pdu_len + PROTOCOL_LEN + label_len {
            return Err(EncapError::ErrorPduLength);
        }

        pkt_type = PktType::FirstFragPkt;
        pdu_len_encapsulated = buffer_len - min_header_len;
        gse_len = (FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + label_len + pdu_len_encapsulated)
            as u16;
        pkt_len = gse_len + (FIXED_HEADER_LEN) as u16;
    }

    Ok(EncapPreview {
        pdu_len,
        pkt_type,
        pkt_len,
    })
}

/// Preview of GSE encapsulation for a PDU fragment.
///
/// This function generates a preview of encapsulating a fragment of a Protocol Data Unit (PDU)
/// along with context information into a buffer, forming a GSE packet. If the fragment fits
/// into the buffer, the function returns a preview indicating the encapsulated packet details.
/// If encapsulation is not possible due to buffer size limitations, it returns an encapsulation error.
///
/// # Arguments
///
/// * `pdu` - The Protocol Data Unit fragment for encapsulation preview.
/// * `context` - Context information for the fragment encapsulation.
/// * `buffer` - Buffer for packet construction.
///
/// # Returns
///
/// Returns a preview of encapsulated packet details or an encapsulation error.
pub fn encap_frag_preview(
    pdu: &[u8],
    context: &ContextFrag,
    buffer: &[u8],
) -> Result<EncapPreview, EncapError> {
    let len_pdu_frag = context.len_pdu_frag as usize;
    let buffer_len = buffer.len();
    let pdu_len = pdu.len();

    // Metadata error
    if len_pdu_frag > pdu_len {
        return Err(EncapError::ErrorPduLength);
    }
    let pdu_len_remaining = pdu_len - len_pdu_frag;

    let gse_end_len = FRAG_ID_LEN + pdu_len_remaining + CRC_LEN;

    let pdu_len_encapsulated: usize;
    let pkt_type: PktType;
    let pkt_len: u16;
    // End packet
    // if the rest of packet fits in the buffer
    if buffer_len >= gse_end_len + FIXED_HEADER_LEN {
        pdu_len_encapsulated = pdu_len_remaining;

        let mut buffer_offset = FIXED_HEADER_LEN + FRAG_ID_LEN + pdu_len_encapsulated;
        buffer_offset += CRC_LEN;

        pkt_type = PktType::EndFragPkt;
        pkt_len = buffer_offset as u16;
    }
    // if a fragment of the rest fits in the buffer
    else if buffer_len > FIXED_HEADER_LEN + FRAG_ID_LEN {
        let gse_len: usize;

        let pdu_len_available = buffer_len - (FIXED_HEADER_LEN + FRAG_ID_LEN);

        if pdu_len_available > pdu_len_remaining {
            gse_len = FRAG_ID_LEN + pdu_len_remaining;
            pdu_len_encapsulated = pdu_len_remaining;
        } else {
            gse_len = FRAG_ID_LEN + pdu_len_available;
            pdu_len_encapsulated = pdu_len_available;
        }

        let buffer_offset = FIXED_HEADER_LEN + gse_len;
        pkt_type = PktType::IntermediateFragPkt;
        pkt_len = buffer_offset as u16;
    }
    // not enough room
    else {
        return Err(EncapError::ErrorSizeBuffer);
    }

    Ok(EncapPreview {
        pkt_type,
        pdu_len: pdu_len_encapsulated,
        pkt_len,
    })
}

/// Generate 16 bits gse header
pub fn generate_gse_header(pkt_type: &PktType, label_type: &LabelType, gse_len: u16) -> u16 {
    let start_end_bits: u16 = match pkt_type {
        PktType::CompletePkt => COMPLETE_PKT,
        PktType::FirstFragPkt => FIRST_PKT,
        PktType::IntermediateFragPkt => INTERMEDIATE_PKT,
        PktType::EndFragPkt => END_PKT,
    };

    let label_type_u16: u16 = match label_type {
        LabelType::SixBytesLabel => LABEL_6_B,
        LabelType::ThreeBytesLabel => LABEL_3_B,
        LabelType::Broadcast => LABEL_BROADCAST,
        LabelType::ReUse => LABEL_REUSE,
    };

    let buffer: u16 = (start_end_bits & START_END_MASK)
        | (label_type_u16 & LABEL_TYPE_MASK)
        | (gse_len & GSE_LEN_MASK);
    buffer
}
