use std::sync::Arc;

use crate::{
    ArgsBuilder, Error, Memory, proc::IsaOp, register_names::*, test_utils::make_computer_128,
};

use parasol_runtime::{fluent::UInt8, test_utils::get_secret_keys_128};

#[test]
fn can_malloc_from_plaintext_size_and_pass_plaintext_data() {
    let (mut proc, _) = make_computer_128();

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::LoadI(T2, 1, 32),
        IsaOp::Malloc(T3, T2),
        IsaOp::Load(T3, T0, 8, 0),
        IsaOp::Store(T1, T3, 8, 0),
        IsaOp::Ret(),
    ]);

    let input_ptr = memory.try_allocate(4).unwrap();
    let output_ptr = memory.try_allocate(4).unwrap();
    let args = ArgsBuilder::new()
        .arg(input_ptr)
        .arg(output_ptr)
        .no_return_value();

    let val: u8 = 42;

    memory.try_write_type(input_ptr, &val).unwrap();

    proc.run_program(program, &memory, args).unwrap();

    let output: u8 = memory.try_load_type(output_ptr).unwrap();

    assert_eq!(output, 42);
}

#[test]
fn can_malloc_from_plaintext_size_and_pass_ciphertext_data() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let memory = Arc::new(Memory::new_default_stack());

    let program = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 32, 0),
        IsaOp::Load(T1, SP, 32, 4),
        IsaOp::LoadI(T2, 1, 32),
        IsaOp::Malloc(T3, T2),
        IsaOp::Load(T3, T0, 8, 0),
        IsaOp::Store(T1, T3, 8, 0),
        IsaOp::Ret(),
    ]);

    let input_ptr = memory.try_allocate(4).unwrap();
    let output_ptr = memory.try_allocate(4).unwrap();
    let args = ArgsBuilder::new()
        .arg(input_ptr)
        .arg(output_ptr)
        .no_return_value();

    let val = 42;

    memory
        .try_write_type(input_ptr, &UInt8::encrypt_secret(val, &enc, &sk))
        .unwrap();

    proc.run_program(program, &memory, args).unwrap();

    let output: UInt8 = memory.try_load_type(output_ptr).unwrap();

    assert_eq!(output.decrypt(&enc, &sk), val);
}

#[test]
fn cannot_malloc_from_ciphertext_size() {
    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    let mut case = || {
        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            IsaOp::Load(T0, SP, 32, 0),
            IsaOp::Load(T0, T0, 32, 0),
            IsaOp::Malloc(T1, T0),
            IsaOp::Ret(),
        ]);

        let encrypted: [UInt8; 4] = [0; 4]
            .into_iter()
            .map(|x| UInt8::encrypt_secret(x, &enc, &sk))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        let ciphertext_size_ptr = memory.try_allocate_type(&encrypted).unwrap();

        let args = ArgsBuilder::new()
            .arg(ciphertext_size_ptr)
            .no_return_value();

        let result = proc.run_program(program, &memory, args);

        assert!(matches!(result, Err(Error::IllegalOperands { .. })));
    };

    case();
}

#[test]
fn cannot_malloc_from_plaintext_size_with_wrong_width() {
    let (mut proc, _) = make_computer_128();

    let mut case = || {
        let memory = Arc::new(Memory::new_default_stack());

        let program = memory.allocate_program(&[
            IsaOp::LoadI(T0, 4, 16),
            IsaOp::Malloc(T1, T0),
            IsaOp::Ret(),
        ]);

        let args = ArgsBuilder::new().no_return_value();

        let result = proc.run_program(program, &memory, args);

        assert!(matches!(result, Err(Error::IllegalOperands { .. })));
    };

    case();
}
