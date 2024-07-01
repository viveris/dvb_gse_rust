// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for Utils
//!
//! This module contains the functional tools for creating and parsing GSE packets.
use crate::gse_decap::read_gse_header;
use crate::gse_encap::generate_gse_header;
use crate::gse_standard::{CRC_LEN, FIXED_HEADER_LEN, FRAG_ID_LEN, PROTOCOL_LEN, TOTAL_LENGTH_LEN};
use crate::label::{Label, LabelType};
use crate::pkt_type::PktType;

#[cfg(test)]
mod tests;

pub trait Serialisable<'a> {
    // Serialise a packet in a buffer
    fn generate(&self, buffer: &mut [u8]);

    // Deserialise a packet into a structure structure
    fn parse(buffer: &'a [u8]) -> Result<Self, &'static str>
    where
        Self: Sized;
}

/// Structure of Gse Complete Packet:
#[derive(PartialEq, Eq, Debug)]
pub struct GseCompletePacket<'a> {
    gse_len: u16,
    protocol_type: u16,
    label: Label,
    pdu: &'a [u8],
}

impl<'a> GseCompletePacket<'a> {
    pub fn new(gse_len: u16, protocol_type: u16, label: Label, pdu: &'a [u8]) -> Self {
        Self {
            gse_len,
            protocol_type,
            label,
            pdu,
        }
    }
}

impl<'a> Serialisable<'a> for GseCompletePacket<'a> {
    fn generate(&self, buffer: &mut [u8]) {
        let mut offset = 0;

        let fixed_header: u16 =
            generate_gse_header(&PktType::CompletePkt, &self.label.get_type(), self.gse_len);
        buffer[..FIXED_HEADER_LEN].copy_from_slice(&fixed_header.to_be_bytes());
        offset += FIXED_HEADER_LEN;

        buffer[offset..offset + PROTOCOL_LEN].copy_from_slice(&self.protocol_type.to_be_bytes());
        offset += PROTOCOL_LEN;

        buffer[offset..offset + self.label.len()].copy_from_slice(self.label.get_bytes());
        offset += self.label.len();

        buffer[offset..offset + self.pdu.len()].copy_from_slice(self.pdu);
    }

    fn parse(buffer: &[u8]) -> Result<GseCompletePacket, &'static str> {
        let mut offset = 0;

        let (gse_len, pkt_type, label_type) = read_gse_header(u16::from_be_bytes(
            buffer[..FIXED_HEADER_LEN].try_into().unwrap(),
        ))
        .unwrap();
        if pkt_type != PktType::CompletePkt {
            return Err("Wrong PktType");
        }
        offset += FIXED_HEADER_LEN;

        let protocol_type =
            u16::from_be_bytes(buffer[offset..offset + PROTOCOL_LEN].try_into().unwrap());
        offset += PROTOCOL_LEN;

        let label = Label::new(&label_type, &buffer[offset..offset + label_type.len()]);
        offset += label.len();

        let pdu = &buffer[offset..gse_len + FIXED_HEADER_LEN];

        Ok(GseCompletePacket::new(
            gse_len.try_into().unwrap(),
            protocol_type,
            label,
            pdu,
        ))
    }
}

/// Structure of Gse First Fragment Packet:
#[derive(PartialEq, Eq, Debug)]
pub struct GseFirstFragPacket<'a> {
    gse_len: u16,
    frag_id: u8,
    total_length: u16,
    protocol_type: u16,
    label: Label,
    pdu: &'a [u8],
}

impl<'a> GseFirstFragPacket<'a> {
    pub fn new(
        gse_len: u16,
        frag_id: u8,
        total_length: u16,
        protocol_type: u16,
        label: Label,
        pdu: &'a [u8],
    ) -> Self {
        Self {
            gse_len,
            frag_id,
            total_length,
            protocol_type,
            label,
            pdu,
        }
    }
}

impl<'a> Serialisable<'a> for GseFirstFragPacket<'a> {
    fn generate(&self, buffer: &mut [u8]) {
        let mut offset = 0;

        let fixed_header: u16 =
            generate_gse_header(&PktType::FirstFragPkt, &self.label.get_type(), self.gse_len);
        buffer[..FIXED_HEADER_LEN].copy_from_slice(&fixed_header.to_be_bytes());
        offset += FIXED_HEADER_LEN;

        buffer[offset..offset + FRAG_ID_LEN].copy_from_slice(&self.frag_id.to_be_bytes());
        offset += FRAG_ID_LEN;

        buffer[offset..offset + TOTAL_LENGTH_LEN].copy_from_slice(&self.total_length.to_be_bytes());
        offset += TOTAL_LENGTH_LEN;

        buffer[offset..offset + PROTOCOL_LEN].copy_from_slice(&self.protocol_type.to_be_bytes());
        offset += PROTOCOL_LEN;

        buffer[offset..offset + self.label.len()].copy_from_slice(self.label.get_bytes());
        offset += self.label.len();

        buffer[offset..offset + self.pdu.len()].copy_from_slice(self.pdu);
    }

    fn parse(buffer: &[u8]) -> Result<GseFirstFragPacket, &'static str> {
        let mut offset = 0;

        let (gse_len, pkt_type, label_type) = read_gse_header(u16::from_be_bytes(
            buffer[..FIXED_HEADER_LEN].try_into().unwrap(),
        ))
        .unwrap();
        if pkt_type != PktType::FirstFragPkt {
            return Err("Wrong PktType");
        }
        offset += FIXED_HEADER_LEN;

        let frag_id = u8::from_be_bytes(buffer[offset..offset + FRAG_ID_LEN].try_into().unwrap());
        offset += FRAG_ID_LEN;

        let total_length = u16::from_be_bytes(
            buffer[offset..offset + TOTAL_LENGTH_LEN]
                .try_into()
                .unwrap(),
        );
        offset += TOTAL_LENGTH_LEN;

        let protocol_type =
            u16::from_be_bytes(buffer[offset..offset + PROTOCOL_LEN].try_into().unwrap());
        offset += PROTOCOL_LEN;

        let label = Label::new(&label_type, &buffer[offset..offset + label_type.len()]);
        offset += label.len();

        let pdu = &buffer[offset..gse_len + FIXED_HEADER_LEN];

        Ok(GseFirstFragPacket::new(
            gse_len.try_into().unwrap(),
            frag_id,
            total_length,
            protocol_type,
            label,
            pdu,
        ))
    }
}

/// Structure of Gse Intermediate Packet:
#[derive(PartialEq, Eq, Debug)]
pub struct GseIntermediatePacket<'a> {
    gse_len: u16,
    frag_id: u8,
    pdu: &'a [u8],
}

impl<'a> GseIntermediatePacket<'a> {
    pub fn new(gse_len: u16, frag_id: u8, pdu: &'a [u8]) -> Self {
        Self {
            gse_len,
            frag_id,
            pdu,
        }
    }
}

impl<'a> Serialisable<'a> for GseIntermediatePacket<'a> {
    fn generate(&self, buffer: &mut [u8]){
        let mut offset = 0;

        let fixed_header: u16 = generate_gse_header(
            &PktType::IntermediateFragPkt,
            &LabelType::ReUse,
            self.gse_len,
        );
        buffer[..FIXED_HEADER_LEN].copy_from_slice(&fixed_header.to_be_bytes());
        offset += FIXED_HEADER_LEN;

        buffer[offset..offset + FRAG_ID_LEN].copy_from_slice(&self.frag_id.to_be_bytes());
        offset += FRAG_ID_LEN;

        buffer[offset..offset + self.pdu.len()].copy_from_slice(self.pdu);
    }

    fn parse(buffer: &[u8]) -> Result<GseIntermediatePacket, &'static str> {
        let mut offset = 0;

        let (gse_len, pkt_type, _label_type) = read_gse_header(u16::from_be_bytes(
            buffer[..FIXED_HEADER_LEN].try_into().unwrap(),
        ))
        .unwrap();
        if pkt_type != PktType::IntermediateFragPkt {
            return Err("Wrong PktType");
        }
        offset += FIXED_HEADER_LEN;

        let frag_id = u8::from_be_bytes(buffer[offset..offset + FRAG_ID_LEN].try_into().unwrap());
        offset += FRAG_ID_LEN;

        let pdu = &buffer[offset..gse_len + FIXED_HEADER_LEN];

        Ok(GseIntermediatePacket::new(
            gse_len.try_into().unwrap(),
            frag_id,
            pdu,
        ))
    }
}

/// Structure of Gse End Frag Packet:
#[derive(PartialEq, Eq, Debug)]
pub struct GseEndFragPacket<'a> {
    gse_len: u16,
    frag_id: u8,
    pdu: &'a [u8],
    crc: u32,
}

impl<'a> GseEndFragPacket<'a> {
    pub fn new(gse_len: u16, frag_id: u8, pdu: &'a [u8], crc: u32) -> Self {
        Self {
            gse_len,
            frag_id,
            pdu,
            crc,
        }
    }
}

impl<'a> Serialisable<'a> for GseEndFragPacket<'a> {
    fn generate(&self, buffer: &mut [u8]){
        let mut offset = 0;

        let fixed_header: u16 =
            generate_gse_header(&PktType::EndFragPkt, &LabelType::ReUse, self.gse_len);
        buffer[..FIXED_HEADER_LEN].copy_from_slice(&fixed_header.to_be_bytes());
        offset += FIXED_HEADER_LEN;

        buffer[offset..offset + FRAG_ID_LEN].copy_from_slice(&self.frag_id.to_be_bytes());
        offset += FRAG_ID_LEN;

        buffer[offset..offset + self.pdu.len()].copy_from_slice(self.pdu);
        offset += self.pdu.len();

        buffer[offset..offset + CRC_LEN].copy_from_slice(&self.crc.to_be_bytes());
    }

    fn parse(buffer: &[u8]) -> Result<GseEndFragPacket, &'static str> {
        let mut offset = 0;

        let (gse_len, pkt_type, _label_type) = read_gse_header(u16::from_be_bytes(
            buffer[..FIXED_HEADER_LEN].try_into().unwrap(),
        ))
        .unwrap();
        if pkt_type != PktType::EndFragPkt {
            return Err("Wrong PktType");
        }
        offset += FIXED_HEADER_LEN;

        let frag_id = u8::from_be_bytes(buffer[offset..offset + FRAG_ID_LEN].try_into().unwrap());
        offset += FRAG_ID_LEN;

        let pdu = &buffer[offset..gse_len + FIXED_HEADER_LEN - CRC_LEN];
        offset = gse_len + FIXED_HEADER_LEN - CRC_LEN;

        let crc = u32::from_be_bytes(buffer[offset..offset + CRC_LEN].try_into().unwrap());

        Ok(GseEndFragPacket::new(
            gse_len.try_into().unwrap(),
            frag_id,
            pdu,
            crc,
        ))
    }
}
