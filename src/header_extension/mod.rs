// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for Header Extension
//!
#[cfg(test)]
mod tests;
use crate::gse_standard::{INTERNAL_SIGNALING_PROTOCOL_ID, MAX_MANDATORY_VAL_PTYPE, NCR_PROTOCOL_ID, PROTOCOL_LEN, SECOND_RANGE_PTYPE};

/// Header Extension
///
/// The header extension ID replaces the protocol type. Any associated data and the true protocol type are moved to the end of the header.
/// The presence of a header extension can be detected by checking if the value of the protocol type is less than 1536
///
///
///    GSE Packet (first frag or complete packet) without header extension :
///    +-------+------------------+-------+------------------------------------------------------------------------------------+
///    |  ...  |   Protocol Type  |  ...  |                                    PDU                                             |
///    +-------+------------------+-------+------------------------------------------------------------------------------------+
///    <----------- GSE header ----------->
///
///
///    GSE Packet (first frag or complete packet) with one header extension with data :
///    +-------+-----------------------+-------+---------------------------------------+---------------------------------------+
///    |  ...  |  Header Extension ID  |  ...  | Header Extension Data | Protocol Type |                 PDU                   |
///    +-------+-----------------------+-------+---------------------------------------+---------------------------------------+
///    <--------------------------------- GSE header ---------------------------------->
///
///
///    GSE Packet (first frag or complete packet) with two header extension each with both data :
///    +-------+-------------+-------+--------------+-----------+-------------+---------------+--------------------------------+
///    |  ...  |  H.E. 1 ID  |  ...  |  H.E. 1 Data | H.E. 2 ID | H.E. 2 Data | Protocol Type |              PDU               |
///    +-------+-------------+-------+--------------+-----------+-------------+---------------+--------------------------------+
///    <------------------------------------ GSE header -------------------------------------->
///  
/// Documentations :
/// GSE header extension cames from previous ULE protocol
/// [IETF RFC 5163] : "Extension Formats for Unidirectional Lightweight Encapsulation (ULE) and the Generic Stream Encapsulation (GSE)" - Section 5
/// [ETSI TS 102 606] : "Digital Video Broadcasting (DVB); Generic Stream Encapsulation (GSE) Protocol"
/// [ETSI TS 102 771] : "Digital Video Broadcasting (DVB); Generic Stream Encapsulation (GSE) implementation guidelines" - Section 6.1.2
/// [ETSI EN 301 542-2] : "Digital Video Broadcasting (DVB) ; Second Generation DVB Interactive Satellite System" - Section 5.1
pub type ExtID = u16;

#[derive(Debug, PartialEq, Eq, Clone)]

/// This structure represents one header extension.
/// A header extension is composed of one ID (2 bytes) and its data (if present).
/// The length of the data can be determined through the ID.
///
///  Extension header ID (2 bytes)
///  +--------------------+------------------+
///  |  0 0 0 0 0 H H H   |  D D D D D D D D |
///  +--------------------+------------------+
///
/// First 5 bits: Always zero. If not, the ID value exceeds 1536, and this is not an header extension but a protocol type.
/// Next 3 bits (HHH): Known as H-LEN. H-LEN cannot exceed 5 . It determines the size of the extension data.
/// 
///  | HLEN Value | data length |  Range of id corresponding
///  |     0      |  unkwown    |  [0 ; 255] -----------> Mandatory header extension
///  |     1      |  0          |  [256 ; 511]   ⌝
///  |     2      |  2 Bytes    |  [512 ; 767]    |
///  |     3      |  4 Bytes    |  [768 ; 1023]   | ----> Optionnal Header Extension
///  |     4      |  6 Bytes    |  [1024 ; 1279]  |
///  |     5      |  8 Bytes    |  [1280 ; 1535] ⌟
///  |     > 5    |  impossible |  [1536 ; ...]  -------> Protocol type
///  
/// 
/// For H-LEN in [1; 5]: The extension is optional. The data size is known using the table above. These extensions are not necessary to understand the PDU load.
/// 
/// If H-LEN is 0, the extension is mandatory. The data size cannot be determined; the receiver must know this extension to process the packet.
/// Packets with at least one unknown mandatory header extension must be dropped.
///
/// Mandatory Extension Headers :
///  - Final Mandatory Extension Header: Replaces the protocol type.
///  - Non-Final Mandatory Extension Header: Does not replace the protocol type.
///
/// 
pub struct Extension {
    pub id: ExtID,
    pub data: ExtensionData,
}
#[derive(Debug, Clone, PartialEq, Eq)]
/// enumeration ExtensionData : stores the data of the extension
/// Data can be 0, 2, 4, 6, 8 bytes depending on H-LEN for optionnal header extension
pub enum ExtensionData {
    Data2([u8; 2]),
    Data4([u8; 4]),
    Data6([u8; 6]),
    Data8([u8; 8]),
    NoData,
    MandatoryData(Vec<u8>),
}

#[derive(Debug,PartialEq)]
pub enum  NewExtensionError{
    IdAndVecSizeNotMatchingError,
    IncorrectExtensionId,
}

//Extension should always be created using new
impl Extension {
    #[allow(clippy::len_without_is_empty)]
    /// Get the total extension len (ID + Data)
    pub fn len(&self) -> usize {
        match &self.data {
            ExtensionData::Data2(_) => 2 + PROTOCOL_LEN,
            ExtensionData::Data4(_) =>  4 + PROTOCOL_LEN,
            ExtensionData::Data6(_) =>  6 + PROTOCOL_LEN,
            ExtensionData::Data8(_) => 8 + PROTOCOL_LEN,
            ExtensionData::NoData => PROTOCOL_LEN,
            ExtensionData::MandatoryData(data) => PROTOCOL_LEN + data.len(),
        }
    }

    
    pub fn new(id : u16,  data : &[u8]) -> Result<Self,NewExtensionError>{
        if id > SECOND_RANGE_PTYPE {
            return Err(NewExtensionError::IncorrectExtensionId)
        }
        if id < MAX_MANDATORY_VAL_PTYPE {
            return Ok(Extension { id, data: ExtensionData::MandatoryData(data.into())});
        }

        let data_size_from_id = match optionnal_extension_data_size_from_hlen((id >> 8).try_into().unwrap()){
            Err(_) => unreachable!(), // HLEN > 5 <=> id > SECOND_RANGE_PTYPE, HLEN = 0 <=> id < MAX_MANDATORY_VAL_PTYPE
            Ok(size) => size,
        };

        if data_size_from_id != data.len() {
            return Err(NewExtensionError::IdAndVecSizeNotMatchingError);
        };

        match data.len() {
            0 => Ok(Extension { id, data: ExtensionData::NoData}),
            2 => Ok(Extension { id, data: ExtensionData::Data2(data.try_into().expect("unreachable"))}),
            4 => Ok(Extension { id, data: ExtensionData::Data4(data.try_into().expect("unreachable"))}),
            6 => Ok(Extension { id, data: ExtensionData::Data6(data.try_into().expect("unreachable"))}),
            8 => Ok(Extension { id, data: ExtensionData::Data8(data.try_into().expect("unreachable"))}),
            _ => unreachable!(),
        }
    }
}



/// Enumeration MandatoryHeaderExt : Defines the type of the mandatory header extension.
///
/// If a mandatory header extension is unknown to the receiver, its data size is also unknown. Moreover, it can indicate that
/// the packet is compressed or encrypted. Therefore, the packet must be dropped.
///
/// If a mandatory header extension is final, it replaces the protocol type.

/// A known, non-final mandatory header extension is treated like an optional header extension,
/// except that its size cannot be extracted from the packet but is known to the receiver (through the Rust trait).
#[derive(PartialEq)]
pub enum MandatoryHeaderExt {
    Final(u8),
    NonFinal(u8),
    Unknown,
}

/// `MandatoryHeaderExtensionManager` is a trait that contains data on all the Mandatory header extension known from the receiver.
pub trait MandatoryHeaderExtensionManager {
    /// For each known mandatory header extension, it should return the size of the data following this header extension.
    /// return MandatoryHeaderExt::Unknown if the extension is unknown
    fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt;
}

#[derive(Copy, Clone)]
/// `SimpleMandatoryExtensionHeaderManager` is a naive and simple implementation of the trait `MandatoryHeaderExtensionManager`
/// It doesn't know any mandatory extension manager which causes any package that contains one to be dropped.
pub struct SimpleMandatoryExtensionHeaderManager {}
impl MandatoryHeaderExtensionManager for SimpleMandatoryExtensionHeaderManager {
    fn is_mandatory_header_id_known(&self, _: u16) -> MandatoryHeaderExt {
        MandatoryHeaderExt::Unknown
    }
}

/// `SignalisationMandatoryExtensionHeaderManager` is implementation of the trait `MandatoryHeaderExtensionManager`
/// It knows the final extension 0x0081 and 0x0082 used in signalisation.
/// 0x0081 : Network Clock Reference, no data
/// 0x0082 : Internal M&C signalling (L2S), no data
#[derive(Copy, Clone)]
pub struct SignalisationMandatoryExtensionHeaderManager {}
impl MandatoryHeaderExtensionManager for SignalisationMandatoryExtensionHeaderManager {
    fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt {
        match id {
            NCR_PROTOCOL_ID => MandatoryHeaderExt::Final(0),
            INTERNAL_SIGNALING_PROTOCOL_ID => MandatoryHeaderExt::Final(0),
            _ => MandatoryHeaderExt::Unknown,
        }
    }
}

#[derive(Debug)]
pub enum HlenError {
    MandatoryHeader,
    UnknownHLen(u8),
}

impl HlenError {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::MandatoryHeader => "Mandatory Extension Header, can not get the size of its data",
            Self::UnknownHLen(_) => {
                "H_LEN doesn't correspond to a header extension, this is a protocol type"
            }
        }
    }
}

#[inline(always)]
// return the size of the OPTIONNAL header extension based on the H-LEN given
// if this is a mandatory extension -> HlenError::MandatoryHeader
// if H_LEN doesn't correspond to a header extension (i.e. H-LEN > 5) -> HlenError::UnknownHLen
pub fn optionnal_extension_data_size_from_hlen(h_len: u8) -> Result<usize, HlenError> {
    match h_len {
        0 => Err(HlenError::MandatoryHeader),
        1 => Ok(0),
        2 => Ok(2),
        3 => Ok(4),
        4 => Ok(6),
        5 => Ok(8),
        _ => Err(HlenError::UnknownHLen(h_len)),
    }
}

#[derive(Debug)]
pub enum AreIdAndVariantCorrespondingError {
    NotAnOptionnalHeaderExtensionId,
}
pub fn are_id_and_variant_corresponding(
    ext: &Extension,
) -> Result<bool, AreIdAndVariantCorrespondingError> {
    let len = match optionnal_extension_data_size_from_hlen((ext.id >> 8).try_into().unwrap()) {
        Ok(l) => l,
        Err(_) => return Err(AreIdAndVariantCorrespondingError::NotAnOptionnalHeaderExtensionId),
    };

    match len {
        0 => Ok(matches!(ext.data, ExtensionData::NoData)),
        2 => Ok(matches!(ext.data, ExtensionData::Data2(..))),
        4 => Ok(matches!(ext.data, ExtensionData::Data4(..))),
        6 => Ok(matches!(ext.data, ExtensionData::Data6(..))),
        8 => Ok(matches!(ext.data, ExtensionData::Data8(..))),
        _ => Err(AreIdAndVariantCorrespondingError::NotAnOptionnalHeaderExtensionId),
    }
}
