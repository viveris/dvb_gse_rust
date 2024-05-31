// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

//! Module for Packet Type
//!
//! This module contains the packet type enum
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
/// enum Packet Type
///
/// Describe the packet type:
/// Complete packet: Start bit = 1, End bit = 1
/// First fragment packet: Start bit = 1, End bit = 0
/// Intermediate fragment packet: Start bit = 0, End bit = 0
/// End fragment packet: Start bit = 0, End bit = 1
pub enum PktType {
    CompletePkt,
    FirstFragPkt,
    IntermediateFragPkt,
    EndFragPkt,
}
