use std::sync::Arc;

use crate::{
    ArgsBuilder, IsaOp, Memory, Register, RunProgramOptionsBuilder, register_names::*,
    test_utils::make_computer_128,
};

#[test]
fn can_pass_args_small_to_large() {
    let (mut proc, _) = make_computer_128();

    // Check that there is no padding between arguments.
    let memory = Arc::new(Memory::new_default_stack());
    let prog = memory.allocate_program(&[
        // Check the u8 argument
        IsaOp::Load(T0, SP, 8, 0),
        IsaOp::Dbg(T0, 0),
        // Check the u16 arg
        IsaOp::Load(T0, SP, 16, 2),
        IsaOp::Dbg(T0, 1),
        // Check the u32 arg
        IsaOp::Load(T0, SP, 32, 4),
        IsaOp::Dbg(T0, 2),
        // Check the u64 arg
        IsaOp::Load(T0, SP, 64, 8),
        IsaOp::Dbg(T0, 3),
        // Check the u128 arg
        IsaOp::Load(T0, SP, 128, 16),
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
    let (mut proc, _) = make_computer_128();

    let memory = Arc::new(Memory::new_default_stack());
    let prog = memory.allocate_program(&[
        // Check the u128 argument
        IsaOp::Load(T0, SP, 128, 0),
        IsaOp::Dbg(T0, 0),
        // Check the u64 arg
        IsaOp::Load(T0, SP, 64, 16),
        IsaOp::Dbg(T0, 1),
        // Check the u32 arg
        IsaOp::Load(T0, SP, 32, 24),
        IsaOp::Dbg(T0, 2),
        // Check the u16 arg
        IsaOp::Load(T0, SP, 16, 28),
        IsaOp::Dbg(T0, 3),
        // Check the u8 arg
        IsaOp::Load(T0, SP, 8, 30),
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
        IsaOp::Load(T0, SP, 8, 0),
        IsaOp::Zext(T0, T0, 16),
        IsaOp::Store(RP, T0, 16, 0),
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new().arg(42u8).return_value::<u16>();

    let actual = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(actual, 42);
}
