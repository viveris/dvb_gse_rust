// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for gse decapsulation
//!
//! The decapsulation module follows the dvb gse standard.
//! It supports complete packet, first fragment packet, intermediate fragment packet, end fragment packet and padding.
//! It also allows you to manage any type of label including the re-use label.

use crate::crc::CrcCalculator;
use crate::gse_standard::{
    COMPLETE_PKT, CRC_LEN, END_PKT, FIRST_PKT, FIRST_RANGE_PTYPE, FIXED_HEADER_LEN, FRAG_ID_LEN,
    GSE_LEN_MASK, INTERMEDIATE_PKT, LABEL_3_B, LABEL_6_B, LABEL_BROADCAST, LABEL_REUSE,
    LABEL_TYPE_MASK, PROTOCOL_LEN, START_END_MASK, TOTAL_LENGTH_LEN,
};
use crate::label::{Label, LabelType};
use crate::pkt_type::PktType;

pub use self::gse_decap_memory::{DecapMemoryError, GseDecapMemory, SimpleGseMemory};

pub mod gse_decap_memory;
#[cfg(test)]
mod tests;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
/// Structure PayloadMetadata
///
/// *   Pdu length describe the length of the pdu store in a buffer
/// *   Protocol type describe the protocol of that pdu
/// *   Label describe the recipient of that pdu
pub struct DecapMetadata {
    pub pdu_len: usize,
    pub protocol_type: u16,
    pub label: Label,
}

impl DecapMetadata {
    pub fn new(pdu_len: usize, protocol_type: u16, label: Label) -> Self {
        Self {
            pdu_len,
            protocol_type,
            label,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Enumeration DecapStatus : Define the status of the decapsulation.
/// 
/// If a pdu is completely decapsulated, the status return a by payload the option completed packet.
/// Else, if the decapsulation failed, the status return a comment about the error that occured.
pub enum DecapStatus {
    CompletedPkt(Box<[u8]>, DecapMetadata),
    FragmentedPkt,
    Padding,
}

impl DecapStatus {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::CompletedPkt(_, _) => "Fully decapsulated packet",
            Self::FragmentedPkt => "Partially decapsulated packet",
            Self::Padding => "Padding detected",
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Enumeration DecapError
///
/// The decapsulation failed, the status return a comment about the error that occured.
pub enum DecapError {
    ErrorSizeBuffer,
    ErrorTotalLength,
    ErrorGseLength,
    ErrorSizePduBuffer,
    ErrorProtocolType,
    ErrorMemory(DecapMemoryError),
    ErrorCrc,
    ErrorInvalidLabel,
    ErrorNoLabelSaved,
    ErrorLabelBroadcastSaved,
    ErrorLabelReUseSaved,
}

impl DecapError {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::ErrorSizeBuffer => "Buffer is too small",
            Self::ErrorSizePduBuffer => "Pdu buffer is smaller than pdu received",
            Self::ErrorProtocolType => "Extension header are not implemented",
            Self::ErrorMemory(_) => "Internal Memory Error",
            Self::ErrorCrc => "Crc Error",
            Self::ErrorInvalidLabel => "Label 6B [0, 0, 0, 0, 0, 0] shall not be used",
            Self::ErrorNoLabelSaved => {
                "A Reused label is used, but no label has been used in the same bbframe"
            }
            Self::ErrorLabelBroadcastSaved => {
                "A Reused label is used, but the last label received is a label broadcast"
            }
            Self::ErrorLabelReUseSaved => {
                "A Reused label is used, but the last label saved is a label re use"
            }
            _ => "Pdu buffer is smaller than pdu received",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// Structure DecapContext
///
/// Represents the information needed to continue decapsulation : 
/// *   This structure is initialised after the decapsulation of a start fragment and maintained until the end fragment.
/// *   Label, protocol type, total len are read in the first fragment
/// *   Frag id is used to identify the context.
/// *   Pdu len represents the length of the PDU already received, it's updated with each new fragment received
pub struct DecapContext {
    pub label: Label,
    pub protocol_type: u16,
    pub frag_id: u8,
    pub total_len: u16,
    pub pdu_len: u16,
    pub from_label_reuse: bool,
}

impl DecapContext {
    pub fn new(
        label: Label,
        protocol_type: u16,
        frag_id: u8,
        total_len: u16,
        pdu_len: u16,
        from_label_reuse: bool,
    ) -> Self {
        Self {
            label,
            protocol_type,
            frag_id,
            total_len,
            pdu_len,
            from_label_reuse,
        }
    }
}

/// Structure Decapsulator
/// 
/// The object oriented structure Decapsulator contains the gse memory and his trait, saves the trait of crc calculation and allows an autonomous use of the Re Use Label.
/// 
/// The memory has to implement the trait GseDecapMemory. It is required to use the decap function. 
/// 
/// The last label has to be reset by the user at the begining of each new base band frame 
pub struct Decapsulator<T: GseDecapMemory, C: CrcCalculator> {
    pub memory: T,
    crc_calculator: C,
    last_label: Option<Label>,
}

impl<T: GseDecapMemory, C: CrcCalculator> Decapsulator<T, C> {
    pub fn new(memory: T, crc_calculator: C) -> Decapsulator<T, C> {
        let decapsulator: Decapsulator<T, C> = Decapsulator {
            last_label: None,
            memory,
            crc_calculator,
        };
        decapsulator
    }

    pub fn new_pdu(&mut self) -> Result<Box<[u8]>, DecapMemoryError> {
        self.memory.new_pdu()
    }

    pub fn provision_storage(&mut self, storage: Box<[u8]>) -> Result<(), DecapMemoryError> {
        self.memory.provision_storage(storage)
    }
    
    /// Set the last label at None, it has to be done at the begining of each new base band frame
    pub fn reset_last_label(&mut self) {
        self.last_label = None;
    }

    /// GSE decapsulation of the payload from a buffer
    ///
    /// The function decap reads the buffer to extract a packet.
    /// Nominal cases:
    /// *   if the packet is complete, a memory buffer is taken in the GseDecapMemory and written to the pdu
    /// and this buffer is returned as a field of CompletedPkt status.
    /// *  if the packet is a start packet, a memory buffer is taken in GseDecapMemory and the fragment of the
    /// of the pdu and the context is stored in GseDecapMemory.
    /// *  if the packet is an intermediate packet, the context in GseDecapMemory is read and
    /// and updated.
    /// *  if the packet is an end packet, the context in the GseDecapMemory is taken, updated and
    /// and returned as a file with the status CompletedPkt.
    /// *  if the buffer contains 0, Padding status is returned.
    /// in each case, it returns the offset of the buffer to apply.
    /// Error cases:
    /// *  if the inputs are wrong, the function returns an error via the status
    /// 
    /// # Example of decapsulating a gse packet
    ///
    /// ```
    /// use dvb_gse_rust::gse_decap::{Decapsulator, DecapMetadata, DecapStatus, SimpleGseMemory, GseDecapMemory};
    /// use dvb_gse_rust::label::Label;
    /// use dvb_gse_rust::crc::DefaultCrc;
    /// 
    /// // The packet is written in buffer, the length of the packet is inform inside
    /// let mut buffer = [0; 1000];
    /// 
    /// // For the example, we build the packet by hand
    /// let protocol_type: u16= 0xFFFF;
    /// let pdu = *b"abcdefghijklmnopqrstuvwxyz";
    /// buffer[0] = 0xE0; // Complete packet, label brodcast
    /// buffer[1] = 28; // Length of the rest of the packet
    /// buffer[2..4].copy_from_slice(&protocol_type.to_be_bytes()); // Protocol Type
    /// buffer[4..30].copy_from_slice(&pdu);  // Payload
    /// 
    /// // The pdu decapsulated from the buffer has to be written in a buffer from memory
    /// let size_memory = 1;
    /// let pdu_len = 26;
    /// let mut memory = SimpleGseMemory::new(size_memory, pdu_len, 0, 0);
    /// let storage = vec![0; pdu_len].into_boxed_slice();
    /// memory.provision_storage(storage).unwrap();
    ///
    /// // Creation of the decapsulator with his crc calculation trait and his memory
    /// let mut decapsulator = Decapsulator::new(memory, DefaultCrc {}); 
    /// 
    /// // Next, the gse packet can be decapsulated
    /// let (decap_status, pkt_len) = match decapsulator.decap(&buffer) { Ok((decap_status, pkt_len)) => (decap_status, pkt_len), Err(_) => unreachable!() };
    ///
    /// // Finally, the pdu and the metadata received can be compared with those sent
    /// let exp_decap_status = DecapStatus::CompletedPkt(
    ///    Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
    ///    DecapMetadata {
    ///        pdu_len: 26,
    ///        label: Label::Broadcast,
    ///        protocol_type: 0xFFFF,
    ///    },
    /// );
    /// let exp_pkt_len = 30;
    /// 
    /// assert_eq!(decap_status, exp_decap_status);
    /// assert_eq!(pkt_len, exp_pkt_len);
    /// ```
    pub fn decap(&mut self, buffer: &[u8]) -> Result<(DecapStatus, usize), (DecapError, usize)> {
        // check buffer length
        let buffer_len = buffer.len();
        if buffer_len < FIXED_HEADER_LEN {
            self.last_label = None;
            // len_pkt = buffer_len because the buffer is too small to contain another packet
            return Err((DecapError::ErrorSizeBuffer, buffer_len));
        }

        // read gse header
        let (gse_len, pkt_type, label_type) = match read_gse_header(u16::from_be_bytes(
            buffer[..FIXED_HEADER_LEN].try_into().unwrap(),
        )) {
            Some(header) => header,
            None => {
                self.last_label = None;
                return Ok((DecapStatus::Padding, buffer_len));
            }
        };

        let pkt_len = gse_len + FIXED_HEADER_LEN;

        // check buffer size
        if buffer_len < pkt_len {
            self.last_label = None;
            // len_pkt = buffer_len because the buffer is too small to contain another packet
            return Err((DecapError::ErrorSizeBuffer, buffer_len));
        }

        match pkt_type {
            PktType::CompletePkt => {
                self.decap_complete(buffer, label_type, pkt_len, gse_len)
            }
            PktType::FirstFragPkt => {
                self.decap_first(buffer, label_type, pkt_len, gse_len)
            }
            PktType::IntermediateFragPkt => {
                self.decap_intermediate(buffer, pkt_len, gse_len)
            }
            PktType::EndFragPkt => {
                self.decap_end(buffer, pkt_len, gse_len)
            }
        }
    }

        
    #[inline(always)]
    fn decap_complete(
        &mut self,
        buffer: &[u8],
        label_type: LabelType,
        pkt_len: usize,
        gse_len: usize,
    ) -> Result<(DecapStatus, usize), (DecapError, usize)> {
        let mut offset = FIXED_HEADER_LEN;
        let buffer_len = buffer.len();
        let label_len = label_type.len();

        // read protocol type
        let protocol_type =
            u16::from_be_bytes(buffer[offset..offset + PROTOCOL_LEN].try_into().unwrap());
        offset += PROTOCOL_LEN;
        if protocol_type <= FIRST_RANGE_PTYPE && protocol_type != 0x0081 && protocol_type != 0x0082 {
            self.last_label = None;
            return Err((DecapError::ErrorProtocolType, pkt_len));
        }

        // read label
        let label: Label = Label::new(&label_type, &buffer[offset..offset + label_len]);
        offset += label_len;

        // check label
        if label == Label::SixBytesLabel([0, 0, 0, 0, 0, 0]) {
            self.last_label = None;
            return Err((DecapError::ErrorInvalidLabel, pkt_len));
        }

        // get pdu buffer
        let mut pdu_buffer = match self.memory.new_pdu() {
            Ok(pdu) => pdu,
            Err(err) => {
                self.last_label = None;
                return Err((DecapError::ErrorMemory(err), pkt_len));
            }
        };

        // check pdu buffer size
        let pdu_buffer_len = pdu_buffer.len();
        if gse_len < label_len + PROTOCOL_LEN {
            self.last_label = None;
            self.memory.provision_storage(pdu_buffer).unwrap();
            // len_pkt = buffer_len because the label type or the gse length is wrong so the start of the next packet is undefined
            return Err((DecapError::ErrorGseLength, buffer_len));
        }

        // check buffer size
        if pdu_buffer_len + label_len + PROTOCOL_LEN < gse_len {
            self.last_label = None;
            self.memory.provision_storage(pdu_buffer).unwrap();
            return Err((DecapError::ErrorSizePduBuffer, pkt_len));
        }
        let calculed_pdu_len = gse_len - label_len - PROTOCOL_LEN;

        // read pdu
        pdu_buffer[..calculed_pdu_len].copy_from_slice(&buffer[offset..offset + calculed_pdu_len]);

        // update last label
        let current_label = match label_type {
            // read last_label
            LabelType::ReUse => match self.last_label {
                Some(Label::Broadcast) => {
                    self.last_label = None;
                    return Err((DecapError::ErrorLabelBroadcastSaved, pkt_len));
                }
                Some(Label::ReUse) => {
                    self.last_label = None;
                    return Err((DecapError::ErrorLabelReUseSaved, pkt_len));
                }
                None => {
                    self.last_label = None;
                    return Err((DecapError::ErrorNoLabelSaved, pkt_len));
                }
                _ => self.last_label.unwrap(),
            },
            // label broadcast
            LabelType::Broadcast => {
                self.last_label = None;
                Label::Broadcast
            }
            _ => {
                // save label
                self.last_label = Some(label);
                label
            }
        };

        // return status and pkt_length
        let metadata = DecapMetadata {
            pdu_len: calculed_pdu_len,
            label: current_label,
            protocol_type,
        };
        Ok((DecapStatus::CompletedPkt(pdu_buffer, metadata), pkt_len))
    }

    #[inline(always)]
    fn decap_first(
        &mut self,
        buffer: &[u8],
        label_type: LabelType,
        pkt_len: usize,
        gse_len: usize,
    ) -> Result<(DecapStatus, usize), (DecapError, usize)> {
        let mut offset = FIXED_HEADER_LEN;
        let buffer_len = buffer.len();
        let label_len = label_type.len();
        let calculed_pdu_len = gse_len - (FRAG_ID_LEN + TOTAL_LENGTH_LEN + PROTOCOL_LEN + label_len);

        // read frag id
        let frag_id = u8::from_be_bytes(buffer[offset..offset + FRAG_ID_LEN].try_into().unwrap());
        offset += FRAG_ID_LEN;

        // read total length
        let total_len = u16::from_be_bytes(
            buffer[offset..offset + TOTAL_LENGTH_LEN]
                .try_into()
                .unwrap(),
        );
        offset += TOTAL_LENGTH_LEN;

        // check the total len
        if total_len <= calculed_pdu_len as u16 {
            self.last_label = None;
            return Err((DecapError::ErrorTotalLength, buffer_len));
        }

        // read protocol type
        let protocol_type =
            u16::from_be_bytes(buffer[offset..offset + PROTOCOL_LEN].try_into().unwrap());
        offset += PROTOCOL_LEN;

        // check protocol type
        if protocol_type <= FIRST_RANGE_PTYPE && protocol_type != 0x0081 && protocol_type != 0x0082{
            self.last_label = None;
            return Err((DecapError::ErrorProtocolType, pkt_len));
        }

        // check buffer size
        if gse_len < label_len + PROTOCOL_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN {
            // len_pkt = buffer_len because the label type or the gse length is wrong so the start of the next packet is undefined
            self.last_label = None;
            return Err((DecapError::ErrorGseLength, buffer_len));
        }

        // read label
        let label: Label = Label::new(&label_type, &buffer[offset..offset + label_len]);
        offset += label_len;

        if label == Label::SixBytesLabel([0, 0, 0, 0, 0, 0]) {
            self.last_label = None;
            return Err((DecapError::ErrorInvalidLabel, pkt_len));
        }

        // update last label
        let current_label = match label_type {
            // read last_label
            LabelType::ReUse => match self.last_label {
                Some(Label::Broadcast) => {
                    self.last_label = None;
                    return Err((DecapError::ErrorLabelBroadcastSaved, pkt_len));
                }
                Some(Label::ReUse) => {
                    self.last_label = None;
                    return Err((DecapError::ErrorLabelReUseSaved, pkt_len));
                }
                None => {
                    self.last_label = None;
                    return Err((DecapError::ErrorNoLabelSaved, pkt_len));
                }
                _ => self.last_label.unwrap(),
            },
            // label broadcast
            LabelType::Broadcast => {
                self.last_label = None;
                Label::Broadcast
            }
            _ => {
                // save label
                self.last_label = Some(label);
                label
            }
        };

        // create a new decap context
        let decap_context = DecapContext::new(
            current_label,
            protocol_type,
            frag_id,
            total_len,
            calculed_pdu_len as u16,
            label_type == LabelType::ReUse,
        );

        // Take a new frag from memory
        let (decap_context, mut pdu_buffer) = match self.memory.new_frag(decap_context) {
            Ok(ok) => ok,
            Err(err) => {
                self.last_label = None;
                return Err((DecapError::ErrorMemory(err), pkt_len));
            }
        };

        // read pdu
        pdu_buffer[..calculed_pdu_len].copy_from_slice(&buffer[offset..offset + calculed_pdu_len]);

        // check pdu buffer size
        let pdu_buffer_len = pdu_buffer.len();
        if pdu_buffer_len + label_len + PROTOCOL_LEN + FRAG_ID_LEN + TOTAL_LENGTH_LEN < gse_len {
            self.last_label = None;
            self.memory.provision_storage(pdu_buffer).unwrap();
            return Err((DecapError::ErrorSizePduBuffer, pkt_len));
        }

        // save state
        match self.memory.save_frag((decap_context, pdu_buffer)) {
            Ok(_) => Ok((DecapStatus::FragmentedPkt, pkt_len)),
            Err(err) => Err((DecapError::ErrorMemory(err), pkt_len)),
        }
    }

    #[inline(always)]
    fn decap_intermediate(
        &mut self,
        buffer: &[u8],
        pkt_len: usize,
        gse_len: usize,
    ) -> Result<(DecapStatus, usize), (DecapError, usize)> {
        let mut offset = FIXED_HEADER_LEN;
        let buffer_len = buffer.len();

        let frag_id = buffer[offset];
        offset += FRAG_ID_LEN;

        if gse_len <= FRAG_ID_LEN {
            self.last_label = None;
            return Err((DecapError::ErrorGseLength, buffer_len));
        }
        let calculed_pdu_len = gse_len - FRAG_ID_LEN;

        let (mut decap_context, mut pdu) = match self.memory.take_frag(frag_id) {
            Ok(ok) => ok,
            Err(err) => return Err((DecapError::ErrorMemory(err), pkt_len)),
        };

        let pdu_buffer = &mut pdu[decap_context.pdu_len as usize..];

        let pdu_buffer_len = pdu_buffer.len();

        if pdu_buffer_len < calculed_pdu_len {
            self.memory.provision_storage(pdu).unwrap();
            return Err((DecapError::ErrorSizePduBuffer, pkt_len));
        }
        pdu_buffer[..calculed_pdu_len].copy_from_slice(&buffer[offset..offset + calculed_pdu_len]);

        // save state
        decap_context.pdu_len += calculed_pdu_len as u16;

        match self.memory.save_frag((decap_context, pdu)) {
            Err(err) => {
                Err((DecapError::ErrorMemory(err), pkt_len))
            }
            Ok(()) => Ok((DecapStatus::FragmentedPkt, pkt_len)),
        }
    }

    #[inline(always)]
    fn decap_end(
        &mut self,
        buffer: &[u8],
        pkt_len: usize,
        gse_len: usize,
    ) -> Result<(DecapStatus, usize), (DecapError, usize)> {
        let mut offset = FIXED_HEADER_LEN;
        let buffer_len = buffer.len();
        let frag_id = buffer[offset];
        offset += FRAG_ID_LEN;

        if gse_len < FRAG_ID_LEN + CRC_LEN {
            self.last_label = None;
            return Err((DecapError::ErrorSizeBuffer, buffer_len));
        }
        let calculed_pdu_len = gse_len - (FRAG_ID_LEN + CRC_LEN);

        let (decap_context, mut pdu) = match self.memory.take_frag(frag_id) {
            Ok(ok) => ok,
            Err(err) => return Err((DecapError::ErrorMemory(err), pkt_len)),
        };

        let pdu_buffer = &mut pdu[decap_context.pdu_len as usize..];

        let pdu_buffer_len = pdu_buffer.len();

        if pdu_buffer_len < calculed_pdu_len {
            self.memory.provision_storage(pdu).unwrap();
            return Err((DecapError::ErrorSizePduBuffer, pkt_len));
        }

        pdu_buffer[..calculed_pdu_len].copy_from_slice(&buffer[offset..offset + calculed_pdu_len]);
        offset += calculed_pdu_len;

        let buffer_crc: [u8; 4] = buffer[offset..offset + CRC_LEN].try_into().unwrap();
        let received_crc: u32 = u32::from_be_bytes(buffer_crc);

        let pdu_len = decap_context.pdu_len as usize + calculed_pdu_len;
        let metadata = DecapMetadata {
            pdu_len,
            protocol_type: decap_context.protocol_type,
            label: decap_context.label,
        };

        let (first_label_len, crc_label): (usize, &[u8]) = if decap_context.from_label_reuse {
            (0, &[])
        } else {
            (
                decap_context.label.get_type().len(),
                decap_context.label.get_bytes(),
            )
        };

        let total_len_received = (pdu_len + PROTOCOL_LEN + first_label_len) as u16;
        if decap_context.total_len != total_len_received {
            self.memory.provision_storage(pdu).unwrap();
            return Err((DecapError::ErrorTotalLength, pkt_len));
        }

        let calculted_crc = self.crc_calculator.calculate_crc32(
            &pdu[..pdu_len],
            decap_context.protocol_type,
            decap_context.total_len,
            crc_label,
        );

        if calculted_crc != received_crc {
            self.memory.provision_storage(pdu).unwrap();
            return Err((DecapError::ErrorCrc, pkt_len));
        }

        Ok((DecapStatus::CompletedPkt(pdu, metadata), pkt_len))
    }
}


/// GSE reading of 16b header
///
/// Return the tuple (gse_len, pktType, Label_type) based on the input buffer
pub fn read_gse_header(buffer: u16) -> Option<(usize, PktType, LabelType)> {
    let pkt_type: PktType = match buffer & START_END_MASK {
        COMPLETE_PKT => PktType::CompletePkt,
        FIRST_PKT => PktType::FirstFragPkt,
        END_PKT => PktType::EndFragPkt,
        INTERMEDIATE_PKT => PktType::IntermediateFragPkt,
        // Unreachable code
        _ => panic!("Wrong u16 pkt type, unreachable code"),
    };

    // Read label type
    let label_type: LabelType = match buffer & LABEL_TYPE_MASK {
        LABEL_6_B => LabelType::SixBytesLabel,
        LABEL_3_B => LabelType::ThreeBytesLabel,
        LABEL_BROADCAST => LabelType::Broadcast,
        LABEL_REUSE => LabelType::ReUse,
        // Unreachable code
        _ => panic!("Wrong u16 label type, unreachable code"),
    };

    if let (PktType::IntermediateFragPkt, LabelType::SixBytesLabel) = (&pkt_type, &label_type) {
        return None;
    }
    // Read gse_length
    let gse_len = buffer & GSE_LEN_MASK;

    Some((gse_len as usize, pkt_type, label_type))
}
