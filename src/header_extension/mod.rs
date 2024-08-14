// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for Header Extension
//! 
//! The header extension ID replaces the protocol type. Any associated data and the true protocol type are moved to the end of the header.
//! The presence of a header extension can be detected by checking if the value of the protocol type is less than 1535.
//!
//! # Optionnal Header Extension & Mandatory Header Extension
//! Extension Header can be optionnal or mandatory.
//! Optionnal Header Extension are not necessary to understand the PDU load. The size of the associated data can be known using its ID.
//! 
//! The receiver must know all Mandatory Extension Header contained by a packet to be able to process it correctly.
//! Thus, packets with at least one unknown mandatory header extension are dropped by the `decapsulator` from [`crate::gse_decap`].
//! 
//! The trait [`MandatoryHeaderExtensionManager`] (given at the creation of the `decapsulator`) allows user to define which mandatory extension are known and how to treat them. \
//! Its default implementation [`SimpleMandatoryExtensionHeaderManager`] doesn't known any mandatory extension.
//! 
//! 
//! 
//! # Examples of packet
//! 
//! ### GSE Packet (first frag or complete packet) without header extension
//! ```text
//!    +-------+------------------+-------+------------------------------------------------------+
//!    |  ...  |   Protocol Type  |  ...  |                         PDU                          |
//!    +-------+------------------+-------+------------------------------------------------------+
//!    <----------- GSE header ----------->
//! ```
//!
//! ###  GSE Packet (first frag or complete packet) with one header extension with data
//! ```text
//!    +-------+-----------+-------+-----------+---------------+---------------------------------+
//!    |  ...  |  H.E. ID  |  ...  | H.E. Data | Protocol Type |           PDU                   |
//!    +-------+-----------+-------+-----------+---------------+---------------------------------+
//!    <--------------------- GSE header --------------------- >
//! ```
//! 
//! ### GSE Packet (first frag or complete packet) with two header extension each with both data
//! ```text
//!    +-------+-------------+-------+--------------+-----------+-------------+---------------+--------------------------------+
//!    |  ...  |  H.E. 1 ID  |  ...  |  H.E. 1 Data | H.E. 2 ID | H.E. 2 Data | Protocol Type |              PDU               |
//!    +-------+-------------+-------+--------------+-----------+-------------+---------------+--------------------------------+
//!    <------------------------------------ GSE header -------------------------------------->
//!  ``` 
//! 
//! # Documentations
//! GSE header extension cames from previous ULE protocol
//! * `[IETF RFC 5163]` : "Extension Formats for Unidirectional Lightweight Encapsulation (ULE) and the Generic Stream Encapsulation (GSE)" - § Section 5 \
//! * `[ETSI TS 102 606]` : "Digital Video Broadcasting (DVB); Generic Stream Encapsulation (GSE) Protocol" \
//! * `[ETSI TS 102 771]` : "Digital Video Broadcasting (DVB); Generic Stream Encapsulation (GSE) implementation guidelines" - § Section 6.1.2 \
//! * `[ETSI EN 301 542-2]` : "Digital Video Broadcasting (DVB) ; Second Generation DVB Interactive Satellite System" - § Section 5.1
#[cfg(test)]
mod tests;
use crate::gse_standard::{INTERNAL_SIGNALING_PROTOCOL_ID, MAX_MANDATORY_VAL_PTYPE, NCR_PROTOCOL_ID, PROTOCOL_LEN, SECOND_RANGE_PTYPE};


pub type ExtID = u16;

#[derive(Debug, PartialEq, Eq, Clone)]

/// This represents one header extension. \
/// 
/// A header extension is composed of one ID (2 bytes) and its data (if present). \
/// For a certain range of IDs, the length of the data can be determined by the ID. (see the table below) \
///
///  ### Extension header ID (always 2 bytes) 
/// ```text
///  +--------------------+------------------+
///  |  0 0 0 0 0 H H H   |  D D D D D D D D |
///  +--------------------+------------------+
/// ```
/// * First 5 bits: Always zero. If not, the ID value exceeds 1536, and this is not an header extension but a protocol type. \
/// * Next 3 bits (HHH): Known as H-LEN. H-LEN cannot exceed 5 . It determines the size of the extension data. \
///  ```text
///  | HLEN Value | data length |  Range of id corresponding
///  |     0      |  unkwown    |  [0 ; 255] -----------> Mandatory header extension
///  |     1      |  0          |  [256 ; 511]    ⌝
///  |     2      |  2 Bytes    |  [512 ; 767]    |
///  |     3      |  4 Bytes    |  [768 ; 1023]   | ----> Optionnal Header Extension
///  |     4      |  6 Bytes    |  [1024 ; 1279]  |
///  |     5      |  8 Bytes    |  [1280 ; 1535]  ⌟
///  |     > 5    |  impossible |  [1536 ; 65535]  -----> Protocol type
///  ```
/// 
/// For H-LEN in `[1; 5]`: The extension is optional. The data size is known using the table above. These extensions are not necessary to understand the PDU load.
/// 
/// If H-LEN is 0, the extension is mandatory. The data size cannot be determined; the receiver must know this extension to process the packet.
/// Packets with at least one unknown mandatory header extension must be dropped.
///
/// Mandatory Extension Headers :
///  - Final Mandatory Extension Header: Replaces the protocol type.
///  - Non-Final Mandatory Extension Header: Does not replace the protocol type.
///  # Warning 
/// Extension should always be created using new  
pub struct Extension {
    id: ExtID,
    data: ExtensionData,
}


#[derive(Debug, Clone, PartialEq, Eq)]
/// Stores the data of one extension header
/// 
/// Mandatory Header Extension data length depends on the extension itself.
pub enum ExtensionData {
    Data2([u8; 2]),
    Data4([u8; 4]),
    Data6([u8; 6]),
    Data8([u8; 8]),
    NoData,
    MandatoryData(Vec<u8>),
}



/// Error returned by [`Extension::new`] function when it fails.
/// 
/// This enum is intended to be used as the `Err` variant in a `Result` type.
/// 
#[derive(Debug,PartialEq)]
pub enum  NewExtensionError{
    /// Indicates that the length of data doesn't match the id given.
    IdAndVecSizeNotMatchingError,

    /// Indicates that id provided exceed the maximum value (>1535)
    IncorrectExtensionId,
}


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

    /// # Warning 
    /// Extension should always be created using new 
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

    // getters
    pub fn id(&self) -> ExtID {
        self.id
    }
    
    pub fn data(&self) -> &ExtensionData {
        &self.data
    }
}



/// Defines whether the mandatory extension header is recognized by the receiver and its size in the [`MandatoryHeaderExtensionManager`] trait.
///
/// If a mandatory header extension is unknown to the receiver, its size is also unknown. This scenario may also indicate that
/// the packet is compressed or encrypted, in which case the packet must be discarded.
///
/// A final mandatory header extension replaces the protocol type.
///
/// A known, non-final mandatory header extension is treated similarly to an optional header extension.
/// However, its size cannot be extracted from the packet directly but is known to the receiver through the trait.
#[derive(PartialEq)]
pub enum MandatoryHeaderExt {
    Final(u8),
    NonFinal(u8),
    Unknown,
}

/// Trait defining which mandatory extension are known by the receiver (and their data length).
pub trait MandatoryHeaderExtensionManager {
    /// For each known mandatory header extension, it should return the size of the data following this header extension.
    /// should return `MandatoryHeaderExt::Unknown` if the extension is unknown
    fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt;
}

#[derive(Copy, Clone)]
/// Naive implementation of the trait [`MandatoryHeaderExtensionManager`], that 
/// doesn't know any mandatory extension manager
/// 
/// Thus, any packet that contains one will be dropped by a `decapsulator` using this trait.
pub struct SimpleMandatoryExtensionHeaderManager {}
impl MandatoryHeaderExtensionManager for SimpleMandatoryExtensionHeaderManager {
    fn is_mandatory_header_id_known(&self, _: u16) -> MandatoryHeaderExt {
        MandatoryHeaderExt::Unknown
    }
}

/// Implementation of the trait [`MandatoryHeaderExtensionManager`] for signalisation.
/// 
/// It knows the final extension 0x0081 and 0x0082 used in signalisation.
/// * 0x0081 : Network Clock Reference, no data
/// * 0x0082 : Internal M&C signalling (L2S), no data
/// 
/// ## Specification
/// See `[ETSI 301 545-2]` :  "Second Generation DVB for Interactive Satellite System (DVB-RCS2); Part 2: Lower Layers for Satellite standard"
#[derive(Copy, Clone)]
pub struct SignalisationMandatoryExtensionHeaderManager {}
impl MandatoryHeaderExtensionManager for SignalisationMandatoryExtensionHeaderManager {
    fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt {
        match id {
            INTERNAL_SIGNALING_PROTOCOL_ID | NCR_PROTOCOL_ID => MandatoryHeaderExt::Final(0),
            _ => MandatoryHeaderExt::Unknown,
        }
    }
}

#[derive(Debug)]
#[doc(hidden)]
/// Errors returned by [`optionnal_extension_data_size_from_hlen`] function when it fails.
///
/// This enum is intended to be used as the `Err` variant in a `Result` type.
pub(crate)  enum HlenError {
    /// Indicates that the h-len given correspond to a mandatory header extension, so the size of the data can not be obtain from it.
    MandatoryHeader,
    /// Indicates that `HLen` provided exceed the maximum value for an extension (5), probably a protocol type.
    UnknownHLen,
}

#[inline(always)]
#[doc(hidden)]
/// This function return the size (in bytes) of the optionnal header extension based on the H-LEN given.
///
/// # Arguments
///
/// * `h_len`
/// 
/// # Returns
/// * `Ok(usize)` - the size of header extension data (in bytes)
/// * `Err(HlenError::MandatoryHeader)` - if this is a mandatory extension (h_len = 0)
/// * `Err(HlenError::UnknownHLe)` - if H_LEN doesn't correspond to a header extension (i.e. H-LEN > 5) 
pub(crate) fn optionnal_extension_data_size_from_hlen(h_len: u8) -> Result<usize, HlenError> { //todo p
    match h_len {
        0 => Err(HlenError::MandatoryHeader),
        1 => Ok(0),
        2 => Ok(2),
        3 => Ok(4),
        4 => Ok(6),
        5 => Ok(8),
        _ => Err(HlenError::UnknownHLen),
    }
}