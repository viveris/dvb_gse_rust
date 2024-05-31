// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! dvb_gse_rust is a library for encapsulating gse packet from a payload and metadata in a buffer and decapsulating gse packet from a buffer in a payload and metadata.
//! The library follows the dvb gse standards. Then, it allows the fragmentation of a pdu in different gse packet and the label re use.
//! 
//! # Example of encapsulating and decapsulating a gse packet
//!
//! ```
//! use dvb_gse_rust::gse_encap::{Encapsulator, EncapMetadata, EncapStatus};
//! use dvb_gse_rust::gse_decap::{Decapsulator, DecapMetadata, DecapStatus, SimpleGseMemory, GseDecapMemory};
//! use dvb_gse_rust::label::Label;
//! use dvb_gse_rust::crc::DefaultCrc;
//! 
//! // Metadata and Payload (pdu) has to be set :
//! let protocol_type = 0xFFFF;
//! let label = Label::SixBytesLabel(*b"012345");
//! let metadata = EncapMetadata {
//!     protocol_type: protocol_type,
//!     label: label,
//! };
//! let default_frag_id = 1;
//! let pdu = b"abcdefghijklmnopqrstuvwxyz";
//!
//! // The packet has to be written in a buffer
//! let mut buffer = [0; 1000];
//! 
//! // Creation of the encapsulator with his crc calculation trait
//! let mut encapsulator = Encapsulator::new(DefaultCrc {});
//!
//! // Thus, the buffer can be fulfilled with the payload encapsulated in a gse packet
//! let encap_status = encapsulator.encap(pdu, default_frag_id, metadata, &mut buffer);
//! 
//! // The pdu decapsulated from the buffer has to be written in a buffer from memory
//! let size_memory = 1;
//! let pdu_len = 26;
//! let mut memory = SimpleGseMemory::new(size_memory, pdu_len, 0, 0);
//! let storage = vec![0; pdu_len].into_boxed_slice();
//! memory.provision_storage(storage).unwrap();
//!
//! // Creation of the decapsulator with his crc calculation trait and his memory
//! let mut decapsulator = Decapsulator::new(memory, DefaultCrc {}); 
//! 
//! // Next, the gse packet can be decapsulated
//! let (decap_status, pkt1_len) = match decapsulator.decap(&buffer) { Ok((decap_status, pkt_len)) => (decap_status, pkt_len), Err(_) => unreachable!() };
//!
//! // Finally, the pdu and the metadata received can be compared with those sent
//! let exp_decap_status = DecapStatus::CompletedPkt(
//!    Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
//!    DecapMetadata {
//!        pdu_len: pdu.len(),
//!        label,
//!        protocol_type,
//!    },
//! );
//! assert_eq!(decap_status, exp_decap_status);
//! ```
//!
//! # Example of the fragmentation of a pdu in different gse packets
//!
//! ```
//! use dvb_gse_rust::gse_encap::{Encapsulator, EncapMetadata, EncapStatus, EncapError};
//! use dvb_gse_rust::gse_decap::{Decapsulator, DecapMetadata, DecapStatus, SimpleGseMemory, GseDecapMemory};
//! use dvb_gse_rust::label::Label;
//! use dvb_gse_rust::crc::DefaultCrc;
//! 
//! // Metadata and Payload (pdu) has to be set :
//! let protocol_type = 0xFFFF;
//! let label = Label::SixBytesLabel(*b"012345");
//! let metadata = EncapMetadata {
//!     protocol_type: protocol_type,
//!     label: label,
//! };
//! let default_frag_id = 1;
//! let pdu = b"abcdefghijklmnopqrstuvwxyz";
//!
//! // The packet has to be written in a buffer.
//! let mut buffer = [0; 1000];
//!
//! // Creation of the encapsulator with his crc calculation trait
//! let mut encapsulator = Encapsulator::new(DefaultCrc {});
//! 
//! // Thus, the buffer can be fulfilled with the payload encapsulated in different gse packet
//! let encap_first_frag_status = encapsulator.encap(pdu, default_frag_id, metadata, &mut buffer[0..15]);
//! let context_frag1 = match encap_first_frag_status { Ok(EncapStatus::FragmentedPkt(_, context_frag)) => context_frag, _=> unreachable!() };
//! let encap_intermediate_status =  encapsulator.encap_frag(pdu, &context_frag1, &mut buffer[15..30]);
//! let context_frag2 = match encap_intermediate_status { Ok(EncapStatus::FragmentedPkt(_, context_frag)) => context_frag, _ => unreachable!() };
//! let encap_end_frag_status =  encapsulator.encap_frag(pdu, &context_frag2, &mut buffer[30..1000]);
//! 
//! // The pdu decapsulated from the buffer has to be written in a buffer from memory
//! let size_memory = 1;
//! let pdu_len = 26;
//! let mut memory = SimpleGseMemory::new(size_memory, pdu_len, 0, 0);
//! let storage = vec![0; pdu_len].into_boxed_slice();
//! memory.provision_storage(storage).unwrap();
//! 
//! // Creation of the decapsulator with his crc calculation trait and his memory
//! let mut decapsulator = Decapsulator::new(memory, DefaultCrc {}); 
//!
//! // Next, the 3 gse packets can be decapsulated
//! let (decap_status, pkt1_len) = match decapsulator.decap(&buffer) { Ok((decap_status, pkt_len)) => (decap_status, pkt_len), Err(_) => unreachable!() };
//! let (decap_intermediate_status, pkt2_len) =  match decapsulator.decap(&buffer[pkt1_len..]) { Ok((decap_status, pkt_len)) => (decap_status, pkt_len), Err(_) => unreachable!() };
//! let (decap_end_frag_status, pkt3_len) = match decapsulator.decap(&buffer[pkt1_len+pkt2_len..]) { Ok((decap_status, pkt_len)) => (decap_status, pkt_len), Err(_) => unreachable!() };
//! 
//! // Finally, the pdu and the metadata received can be compared with those sent
//! let exp_decap_end_frag_status = DecapStatus::CompletedPkt(
//!    Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
//!    DecapMetadata {
//!        pdu_len: pdu.len(),
//!        label,
//!        protocol_type,
//!    },
//! );
//! assert_eq!(decap_end_frag_status, exp_decap_end_frag_status);
//! ```


pub mod crc;
pub mod gse_decap;
pub mod gse_encap;
pub mod gse_standard;
pub mod label;
mod pkt_type;

pub mod utils;
