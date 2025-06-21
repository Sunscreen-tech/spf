use std::sync::Arc;

use crate::{
    ArgsBuilder, IsaOp, Memory, Register, RunProgramOptionsBuilder, register_names::*,
    test_utils::make_computer_128,
};
use parasol_runtime::test_utils::get_secret_keys_128;

#[test]
fn can_pass_args_small_to_large() {
    let (mut proc, enc) = make_computer_128();

    // Check that there is no padding between arguments.
    let memory = Arc::new(Memory::new_default_stack());
    let prog = memory.allocate_program(&[
        // Check the u8 argument
        IsaOp::Load(T0, SP, 8),
        IsaOp::Dbg(T0, 0),
        // Check the u16 arg
        IsaOp::LoadI(T1, 2, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 16),
        IsaOp::Dbg(T0, 1),
        // Check the u32 arg
        IsaOp::LoadI(T1, 4, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 32),
        IsaOp::Dbg(T0, 2),
        // Check the u64 arg
        IsaOp::LoadI(T1, 8, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 64),
        IsaOp::Dbg(T0, 3),
        // Check the u128 arg
        IsaOp::LoadI(T1, 16, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 128),
        IsaOp::Dbg(T0, 4),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(1u8)
        .arg(2u16)
        .arg(3u32)
        .arg(4u64)
        .arg(5u128)
        .no_return_value();

    let options = RunProgramOptionsBuilder::new()
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 8);
                assert_eq!(*val, 1);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 16);
                assert_eq!(*val, 2);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 32);
                assert_eq!(*val, 3);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 64);
                assert_eq!(*val, 4);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 128);
                assert_eq!(*val, 5);
            }
            _ => panic!("Expected plaintext register"),
        })
        .build();

    proc.run_program_with_options(prog, &memory, args, &options)
        .unwrap();
}

#[test]
fn can_pass_args_large_to_small() {
    let (mut proc, enc) = make_computer_128();

    let memory = Arc::new(Memory::new_default_stack());
    let prog = memory.allocate_program(&[
        // Check the u128 argument
        IsaOp::Load(T0, SP, 128),
        IsaOp::Dbg(T0, 0),
        // Check the u64 arg
        IsaOp::LoadI(T1, 16, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 64),
        IsaOp::Dbg(T0, 1),
        // Check the u32 arg
        IsaOp::LoadI(T1, 24, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 32),
        IsaOp::Dbg(T0, 2),
        // Check the u16 arg
        IsaOp::LoadI(T1, 28, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 16),
        IsaOp::Dbg(T0, 3),
        // Check the u8 arg
        IsaOp::LoadI(T1, 30, 32),
        IsaOp::Add(T1, SP, T1),
        IsaOp::Load(T0, T1, 8),
        IsaOp::Dbg(T0, 4),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new()
        .arg(1u128)
        .arg(2u64)
        .arg(3u32)
        .arg(4u16)
        .arg(5u8)
        .no_return_value();

    let options = RunProgramOptionsBuilder::new()
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 128);
                assert_eq!(*val, 1);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 64);
                assert_eq!(*val, 2);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 32);
                assert_eq!(*val, 3);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 16);
                assert_eq!(*val, 4);
            }
            _ => panic!("Expected plaintext register"),
        })
        .debug_handler(|_, _, r| match r {
            Register::Plaintext { val, width } => {
                assert_eq!(*width, 8);
                assert_eq!(*val, 5);
            }
            _ => panic!("Expected plaintext register"),
        })
        .build();

    proc.run_program_with_options(prog, &memory, args, &options)
        .unwrap();
}

#[test]
fn return_val() {
    let (mut proc, _enc) = make_computer_128();

    let memory = Arc::new(Memory::new_default_stack());
    let prog = memory.allocate_program(&[
        IsaOp::Load(T0, SP, 8),
        IsaOp::Zext(T0, T0, 16),
        IsaOp::Store(A0, T0, 16),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new().arg(42u8).return_value::<u16>();

    let actual = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(actual, 42);
}
