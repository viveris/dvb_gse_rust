// Copyright 2023, Viveris Technologies
// Distributed under the terms of the MIT License

use crate::gse_decap::{DecapContext, DecapMemoryError, GseDecapMemory, SimpleGseMemory};
use crate::label::Label;

// -------------------- SimpleGseMemory
#[test]
fn test_too_small_storage() {
    let max_frag_id = 1;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    let _ = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);

    // Buffer too small
    let storage = vec![0; max_pdu_size - 1].into_boxed_slice();
    let exp_storage = vec![0; max_pdu_size - 1].into_boxed_slice();
    let err = memory.provision_storage(storage);
    assert_eq!(Err(DecapMemoryError::BufferTooSmall(exp_storage)), err);
}

#[test]
fn test_perfect_size_storage() {
    let max_frag_id = 1;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    // Correct buffer (fit perfectly)
    let storage = vec![0; max_pdu_size].into_boxed_slice();
    let err = memory.provision_storage(storage);
    assert_eq!(Ok(()), err);
}

#[test]
fn test_larger_storage() {
    let max_frag_id = 1;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    // Correct buffer (larger)
    let storage = vec![33; max_pdu_size + 1].into_boxed_slice();
    let err = memory.provision_storage(storage);
    assert_eq!(Ok(()), err);
}

#[test]
fn test_uninitialised() {
    let max_frag_id = 1;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    memory
        .provision_storage(vec![0; max_pdu_size].into_boxed_slice())
        .unwrap();

    // Uninitialised
    let err = memory.take_frag(0);
    assert_eq!(Err(DecapMemoryError::UndefinedId), err);
}

#[test]
fn test_simple_memory_overflow() {
    let max_frag_id = 0;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    for _ in 0..SimpleGseMemory::MIN_MARGIN {
        memory
            .provision_storage(vec![0; max_pdu_size].into_boxed_slice())
            .unwrap();
    }

    let storage = vec![1; max_pdu_size].into_boxed_slice();
    let exp_storage = vec![1; max_pdu_size].into_boxed_slice();
    let obs_err = memory.provision_storage(storage);
    let exp_err = Err(DecapMemoryError::StorageOverflow(exp_storage));

    assert_eq!(exp_err, obs_err);
}

#[test]
fn test_simple_memory_new_pdu() {
    let max_frag_id = 8;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    memory
        .provision_storage(vec![33; max_pdu_size].into_boxed_slice())
        .unwrap();

    // New pdu
    let obs = memory.new_pdu();
    let exp = Ok(vec![33; max_pdu_size].into_boxed_slice());
    assert_eq!(exp, obs);
}

#[test]
fn test_new_pdu_underflow() {
    let max_frag_id = 1;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    // Not enough memory
    let err = memory.new_pdu();
    assert_eq!(Err(DecapMemoryError::StorageUnderflow), err);
}

#[test]
fn test_simple_memory_new_frag() {
    let max_frag_id = 1;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    memory
        .provision_storage(vec![1; max_pdu_size].into_boxed_slice())
        .unwrap();

    // New frag
    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let obs = memory.new_frag(context);
    let exp_storage = vec![1; 100].into_boxed_slice();
    let exp_context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    assert_eq!(Ok((exp_context, exp_storage)), obs);
}

#[test]
fn test_simple_memory_new_frag_underflow() {
    let max_frag_id = 8;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    // New frag
    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let obs = memory.new_frag(context);
    assert_eq!(Err(DecapMemoryError::StorageUnderflow), obs);
}

#[test]
fn test_simple_memory_save_frag() {
    let max_frag_id = 8;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    let obs = memory.save_frag((context, storage));

    assert_eq!(obs, Ok(()));
}

#[test]
fn test_simple_memory_save_frag_corrupted() {
    let max_frag_id = 8;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    memory.save_frag((context, storage)).unwrap();

    let storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let obs = memory.save_frag((context, storage));

    assert_eq!(obs, Err(DecapMemoryError::MemoryCorrupted));
}

#[test]
fn test_simple_memory_take() {
    let max_frag_id = 8;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    memory.save_frag((context, storage)).unwrap();

    // Take frag
    let exp_context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let exp_storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    let obs = memory.take_frag(0);
    DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);

    assert_eq!(Ok((exp_context, exp_storage)), obs);
}

#[test]
fn test_simple_memory_take_undefined() {
    let max_frag_id = 8;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);
    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    memory.save_frag((context, storage)).unwrap();
    memory.take_frag(0).unwrap();
    DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);

    // Take frag again
    let obs = memory.take_frag(0);
    assert_eq!(Err(DecapMemoryError::UndefinedId), obs);
}

#[test]
fn test_simple_memory_multiple_frag() {
    let max_frag_id = 2;
    let max_pdu_size = 100;
    let max_delay = 0;
    let max_pdu_frag = 0;

    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, max_delay, max_pdu_frag);

    let context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    memory.save_frag((context, storage)).unwrap();

    let context = DecapContext::new(Label::Broadcast, 0, 1, 0, 0, false, vec![]);
    let storage: Box<[u8]> = vec![1; max_pdu_size].into_boxed_slice();
    memory.save_frag((context, storage)).unwrap();

    // Take frag 0
    let exp_context = DecapContext::new(Label::ReUse, 0, 0, 0, 0, false, vec![]);
    let exp_storage: Box<[u8]> = vec![0; max_pdu_size].into_boxed_slice();
    let obs = memory.take_frag(0);
    let exp = Ok((exp_context, exp_storage));
    assert_eq!(exp, obs);

    // Take frag 1
    let exp_context = DecapContext::new(Label::Broadcast, 0, 1, 0, 0, false,  vec![]);
    let exp_storage: Box<[u8]> = vec![1; max_pdu_size].into_boxed_slice();
    let obs = memory.take_frag(1);
    let exp = Ok((exp_context, exp_storage));
    assert_eq!(exp, obs);
}
