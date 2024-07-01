// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

#[cfg(test)]
mod tests;

use super::super::gse_decap::DecapContext;
use std::mem;

#[derive(Debug, PartialEq, Eq, Clone)]
/// describes the possible errors.
pub enum DecapMemoryError {
    StorageOverflow(Box<[u8]>),
    StorageUnderflow,
    UndefinedId,
    BufferTooSmall(Box<[u8]>),
    MemoryCorrupted,
}

pub type MemoryContext = (DecapContext, Box<[u8]>);

/// `GseDecapMemory` is a trait that describes the function required by the decap function.
pub trait GseDecapMemory {
    /// Create a new empty DecapMemory
    fn new(max_frag_id: usize, max_pdu_size: usize, max_delay: usize, max_pdu_frag: usize) -> Self;

    /// Provision of a storage buffer for the decap memory for writing purposes.
    /// If there is not enough place, it should return StorageOverflow Error.
    /// If the storage is too small, it sould return BufferTooSmall Error.
    fn provision_storage(&mut self, storage: Box<[u8]>) -> Result<(), DecapMemoryError>;

    /// Returns a memory buffer from memory without context,
    /// should only be used for a complete packet.
    /// If there is not storage available it should return a StorageUnderflow Error.
    fn new_pdu(&mut self) -> Result<Box<[u8]>, DecapMemoryError>;

    /// Take a buffer in memory and reserve it for a specific context.
    /// If there is already a frag, it should replace it and steal is storage.
    /// If there is no storage available it should return a StorageUnderflow Error.
    fn new_frag(&mut self, context: DecapContext) -> Result<MemoryContext, DecapMemoryError>;

    /// Take an existing context attached to a frag_id.
    /// This function is used to continue the defragmentation.
    /// If the frag_id isn't stored, it should return a UndefinedId.
    fn take_frag(&mut self, frag_id: u8) -> Result<MemoryContext, DecapMemoryError>;

    /// Save an existing context.
    /// Should be called after `take_context` or `new_context` to save the current state.
    /// If there is already a fragment saved it should return an MemoryCorrupted Error.
    fn save_frag(&mut self, context: MemoryContext) -> Result<(), DecapMemoryError>;
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// `SimpleGseMemory` is a naive and simple implementation of the trait `GseDecapMemory`
/// Limitations:
/// *   The maximum number of buffer is fixed at the initialisation
/// *   The index of the frag ids are calculted with `frag_id % max_frag_id`
pub struct SimpleGseMemory {
    storages: Vec<Box<[u8]>>,
    frags: Box<[Option<MemoryContext>]>,

    max_frag_id: usize,
    max_pdu_size: usize,
    // TODO:
    //max_pdu_frag: usize,
    //max_delay: usize,
}

impl SimpleGseMemory {
    const MIN_MARGIN: usize = 2;
}

impl GseDecapMemory for SimpleGseMemory {
    fn new(
        max_frag_id: usize,
        max_pdu_size: usize,
        _max_delay: usize,
        _max_pdu_frag: usize,
    ) -> Self {
        let storages = Vec::with_capacity(max_frag_id + Self::MIN_MARGIN);
        let frags = vec![None; max_frag_id].into_boxed_slice();
        Self {
            storages,
            frags,
            max_frag_id,
            max_pdu_size,
        }
    }

    fn provision_storage(&mut self, storage: Box<[u8]>) -> Result<(), DecapMemoryError> {
        if self.storages.capacity() == self.storages.len() {
            return Err(DecapMemoryError::StorageOverflow(storage));
        }

        if storage.len() < self.max_pdu_size {
            return Err(DecapMemoryError::BufferTooSmall(storage));
        }

        self.storages.push(storage);
        Ok(())
    }

    fn new_pdu(&mut self) -> Result<Box<[u8]>, DecapMemoryError> {
        match self.storages.pop() {
            None => Err(DecapMemoryError::StorageUnderflow),
            Some(storage) => Ok(storage),
        }
    }

    fn new_frag(&mut self, context: DecapContext) -> Result<MemoryContext, DecapMemoryError> {
        let frag_id = context.frag_id;
        let idx = frag_id as usize % self.max_frag_id;

        let mut frag: Option<MemoryContext> = None;
        mem::swap(&mut self.frags[idx], &mut frag);

        match frag {
            None => match self.new_pdu() {
                Ok(pdu) => Ok((context, pdu)),
                Err(err) => Err(err),
            },
            Some((_, pdu)) => Ok((context, pdu)),
        }
    }

    fn take_frag(&mut self, frag_id: u8) -> Result<MemoryContext, DecapMemoryError> {
        let idx = frag_id as usize % self.max_frag_id;

        let mut frag: Option<MemoryContext> = None;
        mem::swap(&mut self.frags[idx], &mut frag);

        match frag {
            None => Err(DecapMemoryError::UndefinedId),
            Some((context, pdu)) => {
                if context.frag_id == frag_id {
                    Ok((context, pdu))
                } else {
                    Err(DecapMemoryError::UndefinedId)
                }
            }
        }
    }

    fn save_frag(&mut self, context: MemoryContext) -> Result<(), DecapMemoryError> {
        let (decap_context, pdu) = context;
        let idx = decap_context.frag_id as usize % self.max_frag_id;

        match self.frags[idx] {
            None => {
                self.frags[idx] = Some((decap_context, pdu));
                Ok(())
            }
            Some(_) => Err(DecapMemoryError::MemoryCorrupted),
        }
    }
}
