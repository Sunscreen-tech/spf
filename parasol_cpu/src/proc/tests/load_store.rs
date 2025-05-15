use std::sync::Arc;

use crate::{
    ArgsBuilder, Byte, Error, Memory, proc::IsaOp, register_names::*, test_utils::make_computer_80,
};

use parasol_runtime::{L1GlweCiphertext, fluent::UInt, test_utils::get_secret_keys_80};

#[test]
fn can_load_store_plain_bit_width() {
    let (mut proc, _) = make_computer_80();

    let mut case = |width| {
        let memory = Arc::new(Memory::new_default_stack());
        let input_ptr = memory.try_allocate(16).unwrap();
        let output_ptr = memory.try_allocate(16).unwrap();

        for i in 0..16 {
            memory
                .try_store(input_ptr.try_offset(i).unwrap(), Byte::from(i as u8))
                .unwrap();
        }

        let program = memory.allocate_program(&[
            IsaOp::Load(T0, A0, width),
            IsaOp::Store(A1, T0, width),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new()
            .arg(input_ptr)
            .arg(output_ptr)
            .no_return_value();

        proc.run_program(program, &memory, args).unwrap();

        let bytes = width / 8;

        for i in 0..bytes {
            let byte = memory.try_load(output_ptr.try_offset(i).unwrap()).unwrap();

            assert_eq!(byte.unwrap_plaintext(), i as u8, "bytes={bytes}");
        }

        for i in bytes..16 {
            let byte = memory.try_load(output_ptr.try_offset(i).unwrap()).unwrap();

            assert_eq!(byte.unwrap_plaintext(), 0, "bytes={bytes}");
        }
    };

    for i in 1..=4 {
        case(8 << i);
    }
}

#[test]
fn can_load_store_ciphertext_bit_width() {
    let (mut proc, enc) = make_computer_80();
    let sk = get_secret_keys_80();

    let mut case = |width| {
        let plain_values = (1..=16).collect::<Vec<_>>();

        let memory = Arc::new(Memory::new_default_stack());
        let program = memory.allocate_program(&[
            IsaOp::Load(T0, A0, width),
            IsaOp::Store(A1, T0, width),
            IsaOp::Ret(),
        ]);

        let src: [UInt<8, _>; 16] = plain_values
            .iter()
            .map(|x| UInt::<8, L1GlweCiphertext>::encrypt_secret(*x as u64, &enc, &sk))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let src = memory.try_allocate_type(&src).unwrap();

        let dst: [UInt<8, _>; 16] = (0..16)
            .map(|_| UInt::<8, L1GlweCiphertext>::encrypt_secret(0, &enc, &sk))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let dst = memory.try_allocate_type(&dst).unwrap();

        let args = ArgsBuilder::new().arg(src).arg(dst).no_return_value();

        proc.run_program(program, &memory, args).unwrap();

        let bytes = (width / 8) as usize;

        for (i, p) in plain_values.iter().take(bytes).enumerate() {
            let actual: UInt<8, L1GlweCiphertext> = memory
                .try_load_type(dst.try_offset(i as u32).unwrap())
                .unwrap();
            assert_eq!(actual.decrypt(&enc, &sk) as u8, *p);
        }

        for i in bytes..plain_values.len() {
            let actual: UInt<8, L1GlweCiphertext> = memory
                .try_load_type(dst.try_offset(i as u32).unwrap())
                .unwrap();
            assert_eq!(actual.decrypt(&enc, &sk) as u8, 0);
        }
    };

    for i in 0..=4 {
        case(8 << i);
    }
}

#[test]
fn can_load_immediate() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    for (val, width) in [
        // 0x30 is 0b110000 which is at least 6 bits long as unsigned (or 7 bits long as signed positive)
        (0x30, 6),
        // 0xF0 is 0b1000000 which is at least 8 bits long as unsigned (or 9 bits long as signed positive)
        (0xF0, 8),
        // 0xFFFFFF30 is 0b1..100110000 which is at least 9 bits long as signed negative (or 32 bits as unsigned)
        (0xFFFFFF30, 9),
        // 0xFFFFFFE0 is 0b1..111100000 which is at least 6 bits long as signed negative (or 32 bits as unsigned)
        (0xFFFFFFE0, 6),
    ] {
        let args = ArgsBuilder::new().return_value::<u32>();

        let program = memory.allocate_program(&[IsaOp::LoadI(A0, val, width), IsaOp::Ret()]);

        let result = proc.run_program(program, &memory, args).unwrap();

        assert_eq!(result, val & ((1 << width) - 1));
    }
}

#[test]
fn load_immediate_fails_out_of_range() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());

    // see test above for why these values are chosen
    for (val, width) in [(0x30, 5), (0xF0, 7), (0xFFFFFF30, 8), (0xFFFFFFE0, 5)] {
        let args = ArgsBuilder::new().return_value::<u32>();

        let result = proc.run_program(
            memory.allocate_program(&[IsaOp::LoadI(A0, val, width), IsaOp::Ret()]),
            &memory,
            args,
        );

        assert!(matches!(
            result,
            Err(Error::OutOfRange { inst_id: _, pc: _ })
        ));
    }
}

#[test]
fn can_offset_load() {
    let (mut proc, _) = make_computer_80();

    let memory = Arc::new(Memory::new_default_stack());
    let src = memory
        .try_allocate_type(&[1u8, 2, 3, 4, 5, 6, 7, 8])
        .unwrap();

    let args = ArgsBuilder::new().arg(src).return_value::<u16>();

    let actual = proc
        .run_program(
            memory.allocate_program(&[
                IsaOp::LoadI(T0, 2, 32),
                IsaOp::Add(A0, A0, T0),
                IsaOp::Load(A0, A0, 16),
                IsaOp::Ret(),
            ]),
            &memory,
            args,
        )
        .unwrap();

    assert_eq!(actual, 0x0403);
}
