use dvb_gse_rust::crc::{CrcCalculator, DefaultCrc};
use dvb_gse_rust::gse_decap::{
    DecapError, DecapMetadata, DecapStatus, Decapsulator, GseDecapMemory, SimpleGseMemory,
};
use dvb_gse_rust::gse_encap::{ContextFrag, EncapMetadata, EncapStatus, Encapsulator};
use dvb_gse_rust::gse_standard::{
    FIXED_HEADER_LEN, LABEL_3_B_LEN, LABEL_6_B_LEN, LABEL_REUSE_LEN, PROTOCOL_LEN,
};
use dvb_gse_rust::header_extension::{Extension, MandatoryHeaderExt, MandatoryHeaderExtensionManager, SignalisationMandatoryExtensionHeaderManager, SimpleMandatoryExtensionHeaderManager};
use dvb_gse_rust::label::Label;
use std::collections::VecDeque;
use std::vec;

fn create_decapsulator(
    max_frag_id: usize,
    max_pdu_size: usize,
) -> Decapsulator<SimpleGseMemory, DefaultCrc, SimpleMandatoryExtensionHeaderManager> {
    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, 0, 0);

    for _ in 0..max_frag_id {
        let storage = vec![0; max_pdu_size].into_boxed_slice();
        memory.provision_storage(storage).unwrap();
    }

    let crc_calculator = DefaultCrc {};
    let header_ext_manager = SimpleMandatoryExtensionHeaderManager {};
    let decapsulator: Decapsulator<
        SimpleGseMemory,
        DefaultCrc,
        SimpleMandatoryExtensionHeaderManager,
    > = Decapsulator::new(memory, crc_calculator, header_ext_manager);
    decapsulator
}

fn create_decapsulator_signalisation(
    max_frag_id: usize,
    max_pdu_size: usize,
) -> Decapsulator<SimpleGseMemory, DefaultCrc, SignalisationMandatoryExtensionHeaderManager> {
    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, 0, 0);

    for _ in 0..max_frag_id {
        let storage = vec![0; max_pdu_size].into_boxed_slice();
        memory.provision_storage(storage).unwrap();
    }

    let crc_calculator = DefaultCrc {};
    let header_ext_manager = SignalisationMandatoryExtensionHeaderManager {};
    let decapsulator: Decapsulator<
        SimpleGseMemory,
        DefaultCrc,
        SignalisationMandatoryExtensionHeaderManager,
    > = Decapsulator::new(memory, crc_calculator, header_ext_manager);
    decapsulator
}

fn create_decapsulator_with_header_ext_manager<MHEM: MandatoryHeaderExtensionManager>(
    header_ext_manager: MHEM, 
    max_frag_id: usize,
    max_pdu_size: usize,
) -> Decapsulator<SimpleGseMemory, DefaultCrc, MHEM> {
    let mut memory = SimpleGseMemory::new(max_frag_id, max_pdu_size, 0, 0);

    for _ in 0..max_frag_id {
        let storage = vec![0; max_pdu_size].into_boxed_slice();
        memory.provision_storage(storage).unwrap();
    }

    let crc_calculator = DefaultCrc {};
    let decapsulator: Decapsulator<
        SimpleGseMemory,
        DefaultCrc,
        MHEM,
    > = Decapsulator::new(memory, crc_calculator, header_ext_manager);
    decapsulator
}

/// Encap and decap tests
///
/// Encapsulation of the alphabet in a packet.
/// Decapsulation of the alphabet out a packet.
/// The pdu used in the encapsulation has to be the same as the pdu received in the decapsulation.
macro_rules! test_encap_decap_complete {
    ($comment:expr, $encapsulator:expr, $decapsulator:expr, $pdu:expr, $payload:expr, $buffer:expr, $memory:expr, $exp_encap_status:expr,  $exp_decap_status:expr, $exp_pkt_len:expr) => {
        // Use the encap function
        let obs_encap_status = match $encapsulator.encap($pdu, 42, $payload, &mut $buffer) {
            Ok(status) => Ok(status),
            Err(status) => Err(status),
        };

        assert_eq!(
            $exp_encap_status, obs_encap_status,
            "status encap error: {}",
            $comment
        );

        // Use the decap function
        let (obs_decap_status, obs_len_pkt) = match $decapsulator.decap(&$buffer) {
            Ok((status, len)) => (Ok(status), len),
            Err((status, len)) => (Err(status), len),
        };

        assert_eq!(
            $exp_decap_status, obs_decap_status,
            "status decap error: {}",
            $comment
        );

        assert_eq!($exp_pkt_len, obs_len_pkt, "length pkt error: {}", $comment);
    };
}

#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu.
fn test_encap_decap_complete_001() {
    const PDU_LEN: usize = 26;
    let comment = "6B Label, buffer larger than pdu";
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let payload = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));
    let exp_encap_status = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN) as u16,
    ));
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata::new(
            PDU_LEN,
            0xFFFF,
            Label::SixBytesLabel(*b"012345"),
            vec![],
        )
    ));
    let exp_pkt_len = FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffer,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a complete packet when label is 3B and buffer is as large than pdu.
fn test_encap_decap_complete_002() {
    const PDU_LEN: usize = 26;
    let comment = "3B Label, buffer as large as pdu";
    let mut buffer: [u8; FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN] = [0; 33];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    let pdu: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let payload = EncapMetadata::new(0xF0F0, Label::ThreeBytesLabel(*b"012"));
    let exp_encap_status = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN) as u16,
    ));
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata::new(
            PDU_LEN,
            0xF0F0,
            Label::ThreeBytesLabel(*b"012"),
            vec![],
        )
    ));
    let exp_pkt_len = FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffer,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a complete packet when label is 3B and buffer is smaller than pdu.
fn test_encap_decap_complete_003() {
    const PDU_LEN: usize = 26;
    const PKT_LEN: usize = FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN;
    let comment = "3B Label, buffer smaller than pdu";
    let mut buffer: [u8; PKT_LEN] = [0; 33];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, PDU_LEN - 1);
    let mut storage = decapsulator.new_pdu().unwrap();
    storage.copy_from_slice(b"-------------------------");
    decapsulator.provision_storage(storage).unwrap();

    let pdu: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let payload = EncapMetadata::new(0xFFFF, Label::ThreeBytesLabel(*b"012"));
    let exp_encap_status = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN) as u16,
    ));
    let exp_decap_status = Err(DecapError::ErrorSizePduBuffer);
    let exp_pkt_len = PKT_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffer,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a complete packet when label is broadcast and buffer is empty.
fn test_encap_decap_complete_004() {
    const PDU_LEN: usize = 0;
    let comment = "Label broadcast, empty pdu";
    let mut buffer: [u8; 1000] = [0; 1000];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    let pdu: &[u8; PDU_LEN] = b"";

    let payload = EncapMetadata::new(0x0F0F, Label::Broadcast);
    let exp_encap_status = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN) as u16,
    ));
    let exp_decap_status = Ok(DecapStatus::CompletedPkt(
        Box::new(*b""),
        DecapMetadata::new(
            PDU_LEN,
            0x0F0F,
            Label::Broadcast,
            vec![],
        )
    ));
    let exp_pkt_len = FIXED_HEADER_LEN + PROTOCOL_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffer,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a complete packet when label is re-use but unset and buffer is larger than
// pdu.
fn test_encap_decap_complete_005() {
    const PDU_LEN: usize = 26;
    const PKT_LEN: usize = FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN;
    let comment = "Label re use (unset), pdu buffer larger than pdu";
    let mut buffer: [u8; 1000] = [0; 1000];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, PDU_LEN);
    let pdu: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let payload = EncapMetadata::new(0xFFFF, Label::ReUse);
    let exp_encap_status = Ok(EncapStatus::CompletedPkt((PKT_LEN) as u16));
    let exp_decap_status = Err(DecapError::ErrorNoLabelSaved);
    let exp_pkt_len = PKT_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffer,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu
// ReUse the same label in the next pkt
fn test_encap_decap_complete_006() {
    const PDU_LEN: usize = 26;
    let comment = "6B Label to be ReUsed, buffer larger than pdu";
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu1: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";
    let pdu2: &[u8; PDU_LEN] = b"zyxwvutsrqponmlkjihgfedcba";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let payload1 = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));
    let payload2 = EncapMetadata::new(0xEEEE, Label::ReUse);
    let exp_encap_status1 = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_6_B_LEN + PDU_LEN) as u16,
    ));
    let exp_encap_status2 = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN) as u16,
    ));
    let exp_decap_status1 = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata::new(
            PDU_LEN,
            0xFFFF,
            Label::SixBytesLabel(*b"012345"),
            vec![],
        )
    ));
    let exp_decap_status2 = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"zyxwvutsrqponmlkjihgfedcba"),
        DecapMetadata::new(
            PDU_LEN,
            0xEEEE,
            Label::SixBytesLabel(*b"012345"),
            vec![],
        )
    ));
    let exp_pkt_len = FIXED_HEADER_LEN + PROTOCOL_LEN + PDU_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu1,
        payload1,
        buffer,
        memory,
        exp_encap_status1,
        exp_decap_status1,
        exp_pkt_len + LABEL_6_B_LEN
    );

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu2,
        payload2,
        buffer,
        memory,
        exp_encap_status2,
        exp_decap_status2,
        exp_pkt_len + LABEL_REUSE_LEN
    );
}

#[test]
// Test end-to-end encap decap of a complete packet when label is 3B and buffer is as large than pdu.
// ReUse the same label in the next pkt
fn test_encap_decap_complete_007() {
    const PDU_LEN: usize = 26;
    let comment = "3B Label to be ReUsed, buffer as large as pdu";
    let mut buffer: [u8; FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN] = [0; 33];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.enable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);
    let pdu1: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";
    let pdu2: &[u8; PDU_LEN] = b"zyxwvutsrqponmlkjihgfedcba";

    let payload1 = EncapMetadata::new(0xF0F0, Label::ThreeBytesLabel(*b"012"));
    let payload2 = EncapMetadata::new(0xFF00, Label::ThreeBytesLabel(*b"012"));
    let exp_encap_status1 = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_3_B_LEN + PDU_LEN) as u16,
    ));
    let exp_encap_status2 = Ok(EncapStatus::CompletedPkt(
        (FIXED_HEADER_LEN + PROTOCOL_LEN + LABEL_REUSE_LEN + PDU_LEN) as u16,
    ));
    let exp_decap_status1 = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        DecapMetadata::new(
            PDU_LEN,
            0xF0F0,
            Label::ThreeBytesLabel(*b"012"),
            vec![],
        )
    ));
    let exp_decap_status2 = Ok(DecapStatus::CompletedPkt(
        Box::new(*b"zyxwvutsrqponmlkjihgfedcba"),
            DecapMetadata::new(
                PDU_LEN,
                0xFF00,
                Label::ThreeBytesLabel(*b"012"),
                vec![],
            )

    ));
    let exp_pkt_len = FIXED_HEADER_LEN + PROTOCOL_LEN + PDU_LEN;

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu1,
        payload1,
        buffer,
        memory,
        exp_encap_status1,
        exp_decap_status1,
        exp_pkt_len + LABEL_3_B_LEN
    );

    test_encap_decap_complete!(
        comment,
        encapsulator,
        decapsulator,
        pdu2,
        payload2,
        buffer,
        memory,
        exp_encap_status2,
        exp_decap_status2,
        exp_pkt_len + LABEL_REUSE_LEN
    );
}

macro_rules! test_encap_decap_frag {
    ($comment:expr, $encapsulator:expr, $decapsulator:expr, $pdu:expr, $payload:expr, $buffers:expr, $memory:expr, $exp_encap_status:expr,  $exp_decap_status:expr, $exp_pkt_len:expr) => {
        let nb_frag = $buffers.len();
        let mut obs_encap_status: Vec<EncapStatus> = Vec::with_capacity(nb_frag);
        let mut obs_decap_status: Vec<DecapStatus> = Vec::with_capacity(nb_frag);

        // Encap first frag
        obs_encap_status.push(
            $encapsulator
                .encap($pdu, 42, $payload, &mut $buffers[0])
                .unwrap(),
        );
        for i in 1..nb_frag {
            let (_, ctx) = if let EncapStatus::FragmentedPkt(pkt_len, ctx) = obs_encap_status[i - 1]
            {
                (pkt_len, ctx)
            } else {
                unreachable!()
            };
            obs_encap_status.push(
                $encapsulator
                    .encap_frag($pdu, &ctx, &mut $buffers[i])
                    .unwrap(),
            );
        }

        assert_eq!(
            $exp_encap_status, obs_encap_status,
            "status encap error: {}",
            $comment
        );

        let mut obs_pkt_len: usize = 0;
        // Use the decap function
        for i in 0..nb_frag {
            let (decap_status, pkt_len) = $decapsulator.decap(&$buffers[i]).unwrap();
            obs_decap_status.push(decap_status);

            obs_pkt_len += pkt_len;
        }

        assert_eq!(
            $exp_decap_status, obs_decap_status,
            "status decap error: {}",
            $comment
        );

        assert_eq!($exp_pkt_len, obs_pkt_len, "length pkt error: {}", $comment);
    };
}

#[test]
// Test end-to-end encap decap of a fragmented packet when label is 6B in 3 fragments.
fn test_encap_decap_frag_001() {
    let comment = "Label 6B, send a pdu with 3 fragments";

    let pdu = b"abcdefghijklmnopqrstuvwxyz";
    let pdu_len = pdu.len();

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, pdu_len);
    let protocol_type = 0x0FFF;
    let label = Label::SixBytesLabel(*b"012345");

    let payload = EncapMetadata::new(protocol_type, label);

    let total_length = PROTOCOL_LEN + label.len() + pdu_len;
    let crc =
        DefaultCrc {}.calculate_crc32(pdu, protocol_type, total_length as u16, label.get_bytes());

    let mut buffers: Vec<Box<[u8]>> = vec![Box::new([0; 20]), Box::new([0; 20]), Box::new([0; 20])];

    let frag_id = 42;
    let exp_encap_status = vec![
        EncapStatus::FragmentedPkt(20, ContextFrag::new(frag_id, crc, 7)),
        EncapStatus::FragmentedPkt(20, ContextFrag::new(frag_id, crc, 24)),
        EncapStatus::CompletedPkt(9),
    ];

    let exp_decap_status = vec![

        DecapStatus::FragmentedPkt(        DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(        DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::CompletedPkt(
            Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
            DecapMetadata::new(
                26,
                protocol_type,
                label,
                vec![],
            ),
        ),
    ];

    let exp_pkt_len = 49;

    test_encap_decap_frag!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffers,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a fragmented packet when label is 6B in 2 fragments.
fn test_encap_decap_frag_002() {
    let comment = "Label 6B, send a pdu with 2 fragments, fit perfectly";

    let pdu = b"abcdefghijklmnopqrstuvwxyz";
    let pdu_len = pdu.len();

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, pdu_len);
    let protocol_type = 0x0FFF;
    let label = Label::SixBytesLabel(*b"012345");

    let payload = EncapMetadata::new(protocol_type, label);

    let total_length = PROTOCOL_LEN + label.len() + pdu_len;
    let crc =
        DefaultCrc {}.calculate_crc32(pdu, protocol_type, total_length as u16, label.get_bytes());

    let mut buffers: Vec<Box<[u8]>> = vec![Box::new([0; 20]), Box::new([0; 26])];

    let exp_encap_status = vec![
        EncapStatus::FragmentedPkt(20, ContextFrag::new(42, crc, 7)),
        EncapStatus::CompletedPkt(26),
    ];

    let exp_decap_status = vec![
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::CompletedPkt(
            Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
            DecapMetadata::new(
                26,
                protocol_type,
                label,
                vec![],
            ),
        ),
    ];

    let exp_pkt_len = 46;

    test_encap_decap_frag!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffers,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

#[test]
// Test end-to-end encap decap of a fragmented packet when label is 6B in 10 fragments.
fn test_encap_decap_frag_003() {
    let comment = "Label 6B, send a pdu with 10 fragments, more space";

    let pdu =
        b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus
tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam.
Maecenas ligula massa, varius a, semper congue, euismod non, mi. Proin porttitor, orci nec nonummy
molestie, enim est eleifend mi, non fermentum diam nisl sit amet erat. Duis semper. Duis arcu
massa, scelerisque vitae, consequat in, pretium a, enim. Pellentesque congue. Ut in risus volutpat
libero pharetra tempor. Cras vestibulum bibendum augue. Praesent egestas leo in pede. Praesent
blandit odio eu enim. Pellentesque sed dui ut augue blandit sodales. Vestibulum ante ipsum primis
in faucibus orci luctus et ultrices posuere cubilia Curae; Aliquam nibh. Mauris ac mauris sed pede
pellentesque fermentum. Maecenas adipiscing ante non diam sodales hendrerit. Ut velit mauris,
egestas sed, gravida nec, ornare ut, mi. Aenean ut orci vel massa suscipit pulvinar. Nulla
sollicitudin. Fusce varius, ligula non tempus aliquam, nunc turpis ullamcorper nibh, in tempus
sapien eros vitae ligula. Pellentesque rhoncus nunc et augue. Integer id felis. Curabitur aliquet
pellentesque diam. Integer quis metus vitae elit lobortis egestas. Lorem ipsum dolor sit amet,
consectetuer adipiscing elit. Morbi vel erat non mauris convallis vehicula. Nulla et sapien.
Integer tortor tellus, aliquam faucibus, convallis id, congue eu, quam. Mauris ullamcorper felis
vitae erat. Proin feugiat, augue non elementum posuere, metus purus iaculis lectus, et tristique
ligula justo vitae magna.

Aliquam convallis sollicitudin purus. Praesent aliquam, enim at fermentum mollis, ligula massa
adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo.
Aliquam euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla
in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem
vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur
eu amet.";

    let pdu_len = pdu.len();

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(1, pdu_len);

    let protocol_type = 0x8888;
    let label = Label::ThreeBytesLabel(*b"123");
    let frag_id = 42;

    let payload = EncapMetadata::new(protocol_type, label);

    let total_length = PROTOCOL_LEN + label.len() + pdu_len;
    let crc =
        DefaultCrc {}.calculate_crc32(pdu, protocol_type, total_length as u16, label.get_bytes());

    let mut buffers: Vec<Box<[u8]>> = vec![
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 200]),
        Box::new([0; 300]),
    ];

    let exp_encap_status = vec![
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 190)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 387)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 584)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 781)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 978)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 1175)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 1372)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 1569)),
        EncapStatus::FragmentedPkt(200, ContextFrag::new(frag_id, crc, 1766)),
        EncapStatus::CompletedPkt(291),
    ];

    let exp_decap_status = vec![
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            protocol_type,
            label,
            vec![],
        )),
        DecapStatus::CompletedPkt(
            Box::new(pdu.to_owned()),
            DecapMetadata::new(
                pdu.len(),
                protocol_type,
                label,
                vec![],
            ),
        ),
    ];

    let exp_pkt_len = 2091;

    test_encap_decap_frag!(
        comment,
        encapsulator,
        decapsulator,
        pdu,
        payload,
        buffers,
        memory,
        exp_encap_status,
        exp_decap_status,
        exp_pkt_len
    );
}

macro_rules! test_encap_decap_multiple_frag {
    ($comment: expr, $encapsulator:expr, $decapsulator:expr, $pdus: expr, $storage_buffers: expr, $memory: expr, $encap_metadata: expr, $exp_decap_status: expr) => {
        let mut vec_encap_metadata = $encap_metadata.to_vec();

        let mut to_encap: Vec<Box<[u8]>> = $pdus.to_vec();
        let mut to_encap_frag: VecDeque<((u16, ContextFrag), Box<[u8]>)> =
            VecDeque::with_capacity(to_encap.len());

        let mut data_buffers: Vec<Box<[u8]>> = Vec::with_capacity($storage_buffers.len());

        let mut obs_decap_status: Vec<DecapStatus> = Vec::with_capacity(100);

        // encap first frag
        let mut frag_id: u8 = 0;
        while !to_encap.is_empty() {
            let mut buffer = $storage_buffers.pop().unwrap();
            let pdu = to_encap.pop().unwrap();
            let payload_metadata = vec_encap_metadata.pop().unwrap();

            let encap_status = $encapsulator
                .encap(&pdu, frag_id, payload_metadata, &mut buffer)
                .unwrap();

            if let EncapStatus::FragmentedPkt(len, ctx) = encap_status {
                to_encap_frag.push_back(((len, ctx), pdu));
                frag_id += 1;
            }

            data_buffers.push(buffer);
        }

        // encap other frags
        while !to_encap_frag.is_empty() {
            let ((_, ctx), pdu) = to_encap_frag.pop_front().unwrap();
            let mut buffer = $storage_buffers.pop().unwrap();

            let encap_status = $encapsulator.encap_frag(&pdu, &ctx, &mut buffer).unwrap();

            if let EncapStatus::FragmentedPkt(len, ctx) = encap_status {
                to_encap_frag.push_back(((len, ctx), pdu));
            }
            data_buffers.push(buffer);
        }
        // decap

        for buffer in data_buffers {
            let (decap_status, _) = $decapsulator.decap(&buffer).unwrap();
            obs_decap_status.push(decap_status);
        }

        for i in 0..obs_decap_status.len() {
            match (&$exp_decap_status[i], &obs_decap_status[i]) {
                (
                    DecapStatus::CompletedPkt(exp_pdu, exp_metadata),
                    DecapStatus::CompletedPkt(obs_pdu, obs_metadata),
                ) => {
                    assert_eq!(
                        exp_pdu[..obs_metadata.pdu_len()],
                        obs_pdu[..obs_metadata.pdu_len()]
                    );
                    assert_eq!(obs_metadata, exp_metadata, "{}", $comment);
                }
                (obs, exp) => assert_eq!(obs, exp, "{i} -> {}, {}", $comment, i),
            }
        }
    };
}

#[test]
// Test end-to-end encap decap of fragmented packets when label is 6B, two fragments in same time.
fn test_encap_decap_multiple_frag_001() {
    let comment = "Two frag in same time";

    let pdus: [Box<[u8]>; 2] = [
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        Box::new(*b"azertyuiopqsdfghjklmwxcvbn"),
    ];

    let mut storage_buffers: Vec<Box<[u8]>> = vec![Box::new([0; 20]); 10];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(8, pdus[0].len());

    let encap_metadata: [EncapMetadata; 2] = [
        EncapMetadata::new(0x1234, Label::SixBytesLabel(*b"123456")),
        EncapMetadata::new(0x1234, Label::SixBytesLabel(*b"123456")),
    ];

    let decap_metadata: [DecapMetadata; 2] = [
        DecapMetadata::new(
            26,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        ),
    DecapMetadata::new(
            26,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        ),
    ];

    let exp_decap_status = [
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::CompletedPkt(pdus[1].clone(), decap_metadata[1].clone()),
        DecapStatus::CompletedPkt(pdus[0].clone(), decap_metadata[0].clone()),
    ];

    test_encap_decap_multiple_frag!(
        comment,
        encapsulator,
        decapsulator,
        pdus,
        storage_buffers,
        memory,
        encap_metadata,
        exp_decap_status
    );
}

#[test]
// Test end-to-end encap decap of fragmented packets when label is 6B, two fragments in same time.
fn test_encap_decap_multiple_frag_002() {
    let comment = "Two frag in same time";

    let pdus: [Box<[u8]>; 2] = [
        Box::new(*b"abcdefghijklmnopqrstuvwxyz"),
        Box::new(*b"azertyuiopqsdfghjklmwxcvbn"),
    ];

    let mut storage_buffers: Vec<Box<[u8]>> = vec![Box::new([0; 20]); 10];

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(8, pdus[0].len());

    let encap_metadata: [EncapMetadata; 2] = [
        EncapMetadata::new(0x1234, Label::ReUse),
        EncapMetadata::new(0x1234, Label::SixBytesLabel(*b"123456")),
    ];

    let decap_metadata: [DecapMetadata; 2] = [
        DecapMetadata::new(
            pdus[0].len(),
            0x1234,
            Label::SixBytesLabel(*b"123456"),

            vec![],

        ),
        DecapMetadata::new(
            pdus[0].len(),
            0x1234,
            Label::SixBytesLabel(*b"123456"),

            vec![],

        ),

    ];

    let exp_decap_status = [
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::CompletedPkt(pdus[0].clone(), decap_metadata[0].clone()),
        DecapStatus::CompletedPkt(pdus[1].clone(), decap_metadata[1].clone()),
    ];

    test_encap_decap_multiple_frag!(
        comment,
        encapsulator,
        decapsulator,
        pdus,
        storage_buffers,
        memory,
        encap_metadata,
        exp_decap_status
    );
}

#[test]
// Test end-to-end encap decap of fragmented packets when label is 6B, four fragments in same time.
fn test_encap_decap_multiple_frag_003() {
    let comment = "4 large frags in same time";

    let pdus: [Box<[u8]>; 4] = [
        Box::new(*b"Fusce tempus vel eros sed ullamcorper. Aenean sit amet dui mattis, luctus eros vel, pretium quam.
Quisque accumsan, sem quis aliquet finibus, dui ligula mattis mauris, sed porttitor mauris diam at
nisi. Fusce sodales fringilla erat et egestas. Quisque dictum venenatis dolor, nec iaculis dui
volutpat vel. Suspendisse eget felis lacus. Pellentesque nec tortor at dolor porta consectetur eget
eu felis. In hac habitasse platea dictumst. Aenean imperdiet tempus turpis. Phasellus ornare at
massa at accumsan.

Nunc odio magna, imperdiet in ante sit amet, scelerisque consequat sem. In non cursus nisl, vitae
tincidunt ipsum. Fusce eu varius augue, nec venenatis velit. Lorem ipsum dolor sit amet,
consectetur adipiscing elit. Vestibulum eget arcu tincidunt, consectetur lacus eget, molestie
magna. Sed eu congue urna, ac viverra ligula. Maecenas sodales rutrum aliquam. Vestibulum risus
metus, auctor sed ipsum pellentesque, posuere condimentum sapien. Mauris ac purus non diam dictum
molestie in nullam.",),
        Box::new(*b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc sed venenatis
nulla. Praesent lacinia, ipsum quis facilisis aliquam, sapien justo scelerisque eros, ac iaculis
augue tellus vel tortor. Suspendisse pulvinar arcu odio, quis pellentesque ex pellentesque eu.
Pellentesque sed massa id augue volutpat porta at ut libero. Vestibulum interdum est magna, at
egestas nibh rutrum a. Duis vehicula erat diam, sit amet egestas dolor dapibus eu. Mauris metus
velit, auctor sit amet sem et, malesuada tempor mi. Nullam suscipit posuere odio nec feugiat. Nunc
cursus rutrum nulla eget varius. Nullam a auctor mauris, at egestas nibh. Nulla sit amet gravida
nisl, id facilisis velit. Donec luctus laoreet nunc, eget porttitor massa tincidunt sed. Sed
maximus vitae libero eget finibus. Nullam sit amet orci lectus. Donec congue a erat eget tincidunt.
Nulla non libero lacinia, aliquam massa non, pretium justo."),
        Box::new(*b"Donec molestie mi ac mi suscipit, in vehicula mi pretium. Ut auctor tincidunt
ullamcorper. Mauris justo lacus, pharetra eget pulvinar at, vulputate nec orci. Mauris vitae
aliquet eros, eu feugiat ligula. Morbi dapibus diam ac nisi eleifend ullamcorper. Proin maximus
turpis quis arcu congue, et mattis orci pulvinar. Aliquam erat volutpat. Sed efficitur nec velit
vitae posuere. Donec est arcu, auctor efficitur iaculis vel, sodales nec mauris. Cras in eleifend
dui. Sed eget tempor enim. Mauris rhoncus, lectus eget tincidunt facilisis, tellus risus commodo
eros, vel rutrum ante orci ac sem. Nunc at lectus a risus luctus consectetur in eget tortor."), 
        Box::new(*b"
Vestibulum vestibulum lacinia pharetra. Maecenas maximus leo eu libero dapibus ornare. Phasellus
sollicitudin quam ligula. Sed metus enim, mattis vitae lectus vitae, aliquet fringilla ante.
Phasellus vel commodo neque, et faucibus orci. Morbi interdum neque at sem aliquam, at dictum ante
fermentum. Suspendisse aliquet nisi id nisl bibendum, vel porttitor leo iaculis. Duis tincidunt
massa nec sapien vehicula, eget viverra ex tempor. Proin tincidunt est accumsan pretium eleifend.
Donec rhoncus purus eleifend tellus porta, nec maximus diam euismod. Nullam sagittis tincidunt
fermentum. Praesent augue nulla, pretium quis efficitur at, rutrum a turpis. Maecenas nec diam sed
risus dictum imperdiet. "
        )];

    let mut storage_buffers: Vec<Box<[u8]>> = vec![Box::new([0; 100]); 100];

    // Create a big enough memory

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(4, 1500);

    let encap_metadata: [EncapMetadata; 4] = [
        EncapMetadata::new(0x4242, Label::ReUse),
        EncapMetadata::new(0x1234, Label::SixBytesLabel(*b"123456")),
        EncapMetadata::new(0x9999, Label::ReUse),
        EncapMetadata::new(0x1111, Label::ThreeBytesLabel(*b"123")),
    ];

    let decap_metadata: [DecapMetadata; 4] = [
        DecapMetadata::new(
            pdus[0].len(),
            0x4242,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        ),
        DecapMetadata::new(
            pdus[1].len(),
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        ),
        DecapMetadata::new(
            pdus[2].len(),
            0x9999,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        ),

        DecapMetadata::new(
            pdus[3].len(),
            0x1111,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )
    ];
    let exp_decap_status = [
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x1111,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x9999,
                Label::ThreeBytesLabel(*b"123"),
                vec![],
            )),
            DecapStatus::FragmentedPkt(
                DecapMetadata::new(
                    0,
                    0x1234,
                    Label::SixBytesLabel(*b"123456"),
                    vec![],
                )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x4242,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
            DecapStatus::FragmentedPkt(DecapMetadata::new(
                0,
                0x1111,
                Label::ThreeBytesLabel(*b"123"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x9999,
                Label::ThreeBytesLabel(*b"123"),
                vec![],
            )),
            DecapStatus::FragmentedPkt(
                DecapMetadata::new(
                    0,
                    0x1234,
                    Label::SixBytesLabel(*b"123456"),
                    vec![],
                )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x4242,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x1111,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x9999,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x4242,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x1111,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x9999,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x4242,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x1111,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x9999,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x1234,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
        DecapMetadata::new(
            0,
            0x4242,
            Label::SixBytesLabel(*b"123456"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x1111,
                Label::ThreeBytesLabel(*b"123"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(DecapMetadata::new(
            0,
            0x9999,
            Label::ThreeBytesLabel(*b"123"),
            vec![],
        )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x1234,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )
        ),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x4242,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x1111,
                Label::ThreeBytesLabel(*b"123"),
                vec![],
            )),
        DecapStatus::CompletedPkt(pdus[2].clone(), decap_metadata[2].clone()),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x1234,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x4242,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::CompletedPkt(pdus[3].clone(), decap_metadata[3].clone()),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x1234,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x4242,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x1234,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x4242,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::CompletedPkt(pdus[1].clone(), decap_metadata[1].clone()),
        DecapStatus::FragmentedPkt(
            DecapMetadata::new(
                0,
                0x4242,
                Label::SixBytesLabel(*b"123456"),
                vec![],
            )),
        DecapStatus::CompletedPkt(pdus[0].clone(), decap_metadata[0].clone()),
    ];

    test_encap_decap_multiple_frag!(
        comment,
        encapsulator,
        decapsulator,
        pdus,
        storage_buffers,
        memory,
        encap_metadata,
        exp_decap_status
    );
}


#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu with header extension (data = 4 bytes).
fn test_encap_decap_complete_ext_001() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 60] = [0; 60];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));

    let extension = Extension::new (770, &[1,2,3,4]).unwrap();
    let extensions : Vec<Extension> = vec![extension];
    let exp_extensions : Vec<Extension> = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);
    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),

    }

}

#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu with header extension (data = 6 bytes).
fn test_encap_decap_complete_ext_002() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));

    let extension = Extension::new(1025, &[1,2,3,4,5,6]).unwrap();
    let extensions : Vec<Extension> = vec![extension.clone()];
    let exp_extensions: Vec<Extension> = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),

    }

}


#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu with header extension (data = 8 bytes).
fn test_encap_decap_complete_ext_003() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));

    let extension = Extension::new(1280,&[1,2,3,4,5,6,7,8]).unwrap();
    let extensions : Vec<Extension> = vec![extension];
    let exp_extensions: Vec<Extension> = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),

    }

}


#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu with header extension (data = 2 bytes).
fn test_encap_decap_complete_ext_004() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));

    let extension = Extension::new(515,&[1,2]).unwrap();
    let extensions : Vec<Extension> = vec![extension.clone()];
    let exp_extensions : Vec<Extension> = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),

    }
}


#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu with header extension ( no data).
fn test_encap_decap_complete_ext_005() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));

    let extension = Extension::new(260, &[]).unwrap();
    let extensions : Vec<Extension> = vec![extension.clone()];
    let exp_extensions : Vec<Extension> = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),

    }

}


#[test]
// Test end-to-end encap decap of a complete packet when label is 6B and buffer is larger than pdu with 2 header extensions.
fn test_encap_decap_complete_ext_006() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));

    let extension1 = Extension::new(260, &[]).unwrap();
    let extension2 = Extension::new(265, &[]).unwrap();
    let extension3 = Extension::new(1025,&([0, 1, 2, 3, 4, 5])).unwrap();
    let extension4 = Extension::new(1026,&([0, 1, 2, 3, 4, 5])).unwrap();
    let extension5 = Extension::new(514, &[9, 9]).unwrap();
    let extension6 = Extension::new(1354,&([7, 7, 7, 7, 8, 8, 8, 8])).unwrap();

    let extensions = vec![extension1, extension2,extension3,extension4,extension5,extension6];


    let exp_extensions = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),

    }

}


#[test]
// Test end-to-end encap/decap of a complete packet when label is 6B and buffer is larger than pdu with 1 final mandatory header extension with no data.
fn test_encap_decap_complete_ext_007() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator_signalisation(2, PDU_LEN);
    // signalisation decapsulator use the trait SignalisationMandatoryExtensionHeaderManager and knows that 0x0081 is a final mandatoy extension header with no data

    let extension1 = Extension::new(0x0081, &[]).unwrap(); // 0x0081 is the ID of NCR in DVB-RCS2
    
    let metadata_in = EncapMetadata::new(extension1.id(), Label::SixBytesLabel(*b"012345"));
    let extensions = vec![extension1];

    let exp_extensions = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),
    }
}

#[test]
// Test end-to-end encap/decap of a complete packet when label is 6B and buffer is larger than pdu with 1 final mandatory header extension with no data using encap.
fn test_encap_decap_complete_ext_008() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 1000] = [0; 1000];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();
    let mut decapsulator = create_decapsulator_signalisation(2, PDU_LEN);
    // signalisation decapsulator use the trait SignalisationMandatoryExtensionHeaderManager and knows that 0x0081 is a final mandatoy extension header with no data

    
    let id_final_ext = 0x0081;
    let metadata_in = EncapMetadata::new(id_final_ext, Label::SixBytesLabel(*b"012345"));

    let exp_extensions = vec![Extension::new(id_final_ext,&[]).unwrap()];

    let _ = encapsulator.encap(pdu_in, 4, metadata_in, &mut buffer);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}",res.0)

        },
        Err(e) => panic!("return err instead of ok {:?}",e),
    }
}

#[test]
// Test end-to-end encap/decap of a complete packet when label is 6B and buffer is larger than pdu with 1 nonfinal mandatory header extension with 5B of data.
fn test_encap_decap_complete_ext_009() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 60] = [0; 60];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();

    struct CustomHeaderExtManager {}

    impl MandatoryHeaderExtensionManager for CustomHeaderExtManager {
        fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt {
            if id == 0x0055 {
                return MandatoryHeaderExt::NonFinal(5);
            }
        return MandatoryHeaderExt::Unknown;
        }
    }
    let mut decapsulator = create_decapsulator_with_header_ext_manager(CustomHeaderExtManager {}, 2, PDU_LEN);
    let extension1 = Extension::new(0x0055, &[0,1,2,3,4]).unwrap(); // 0x0055 is an invented extension ID
    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));
    let extensions = vec![extension1];
    let exp_extensions = extensions.clone();
    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);

    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected DecapStatus::CompletedPkt but got {:?}", res.0)

        },
        Err(e) => panic!("expected Ok but got Err {:?}",e),
    }
}



#[test]
// Test end-to-end encap/decap of a complete packet when label is 6B and buffer is larger than pdu with 1 nonfinal mandatory header extension with 5B of data, but decapsulator doesn't know this extension.
fn test_encap_decap_complete_ext_010() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 60] = [0; 60];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();

    #[allow(dead_code)]
    struct CustomHeaderExtManager {}

    impl MandatoryHeaderExtensionManager for CustomHeaderExtManager {
        fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt {
            if id == 0x0055 {
                return MandatoryHeaderExt::NonFinal(5);
            }
        return MandatoryHeaderExt::Unknown;
        }
    }
    let mut decapsulator = create_decapsulator(2, PDU_LEN);
    let extension1 = Extension::new(0x0055, &[0,1,2,3,4]).unwrap(); // 0x0055 is an invented extension ID
    let metadata_in = EncapMetadata::new(0xFFFF, Label::SixBytesLabel(*b"012345"));
    let extensions = vec![extension1];


    let exp_error = DecapError::ErrorUnkownMandatoryHeader;
    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);

    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => panic!("expected Err but got Ok : {:?} : ",res),
        Err(e) => assert_eq!(exp_error,e.0),
    }
}


#[test]
// Test end-to-end encap/decap of a complete packet when label is 6B and buffer is larger than pdu with several optionnal header extensions and one known final mandatory header extension.
fn test_encap_decap_complete_ext_011() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 150] = [0; 150];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();

    #[allow(dead_code)]
    struct CustomHeaderExtManager {}

    impl MandatoryHeaderExtensionManager for CustomHeaderExtManager {
        fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt {
            if id == 0x0055 {
                return MandatoryHeaderExt::NonFinal(5);
            }
        return MandatoryHeaderExt::Unknown;
        }
    }
    let mut decapsulator = create_decapsulator_signalisation(2, PDU_LEN);

    let id_final_ext = 0x0081;
    let metadata_in = EncapMetadata::new(id_final_ext, Label::SixBytesLabel(*b"012345"));

    let extension1 = Extension::new(260, &[]).unwrap();
    let extension2 = Extension::new(265, &[]).unwrap();
    let extension3 = Extension::new(1025,&([0, 1, 2, 3, 4, 5])).unwrap();
    let extension4 = Extension::new(1026,&([0, 1, 2, 3, 4, 5])).unwrap();
    let extension5 = Extension::new(514, &[9, 9]).unwrap();
    let extension6 = Extension::new(1354,&([7, 7, 7, 7, 8, 8, 8, 8])).unwrap();
    let finalextension = Extension::new(id_final_ext,&[]).unwrap();
    let extensions = vec![extension1, extension2,extension3,extension4,extension5,extension6,finalextension];

    let exp_extensions = extensions.clone();

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => match res.0 {
            DecapStatus::CompletedPkt(pdu_out, metadata_out) => {
                assert_eq!(pdu_in, &pdu_out[..metadata_out.pdu_len()],"pdu differ");
                assert_eq!(metadata_in.label,metadata_out.label(),"labels differ");
                assert_eq!(metadata_in.protocol_type,metadata_out.protocol_type(),"protocol types differ");
                assert_eq!(exp_extensions,*metadata_out.extensions(),"extensions differ");
            }
            _ => panic!("Expected CompletedPkt but got status {:?}",res),

        },
        Err(e) => panic!("expected Ok but got Err {:?}",e),
    }
}


#[test]
// Test end-to-end encap/decap of a complete packet when label is 6B and buffer is larger than pdu with several optionnal header extensions and one UNKNOWN final mandatory header extension. -> Err
fn test_encap_decap_complete_ext_012() {
    const PDU_LEN: usize = 26;
    let mut buffer: [u8; 150] = [0; 150];
    let pdu_in: &[u8; PDU_LEN] = b"abcdefghijklmnopqrstuvwxyz";

    let mut encapsulator = Encapsulator::new(DefaultCrc {});
    encapsulator.disable_re_use_label();

    #[allow(dead_code)]
    struct CustomHeaderExtManager {}

    impl MandatoryHeaderExtensionManager for CustomHeaderExtManager {
        fn is_mandatory_header_id_known(&self, id: u16) -> MandatoryHeaderExt {
            if id == 0x0055 {
                return MandatoryHeaderExt::NonFinal(5);
            }
        return MandatoryHeaderExt::Unknown;
        }
    }
    let mut decapsulator = create_decapsulator(2, PDU_LEN);

    let id_final_ext = 0x0081;
    let metadata_in = EncapMetadata::new(id_final_ext, Label::SixBytesLabel(*b"012345"));

    let extension1 = Extension::new(260, &[]).unwrap();
    let extension2 = Extension::new(265, &[]).unwrap();
    let extension3 = Extension::new(1025,&([0, 1, 2, 3, 4, 5])).unwrap();
    let extension4 = Extension::new(1026,&([0, 1, 2, 3, 4, 5])).unwrap();
    let extension5 = Extension::new(514, &[9, 9]).unwrap();
    let extension6 = Extension::new(1354,&([7, 7, 7, 7, 8, 8, 8, 8])).unwrap();
    let finalextension = Extension::new(id_final_ext,&[]).unwrap();
    let extensions = vec![extension1, extension2,extension3,extension4,extension5,extension6,finalextension];

    let exp_err = DecapError::ErrorUnkownMandatoryHeader;

    let _ = encapsulator.encap_ext(pdu_in, 4, metadata_in, &mut buffer, extensions);
    let status_decap = decapsulator.decap(&buffer);

    match status_decap {
        Ok(res) => panic!("expected Err but got Ok {:?}",res),
        Err(e) => assert_eq!(e.0,exp_err),
    }
}

