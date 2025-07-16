use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    ArgsBuilder, IsaOp, Memory, Register, RunProgramOptionsBuilder, register_names::T0,
    test_utils::make_computer_128,
};

#[test]
fn can_invoke_dbg_handlers() {
    let (mut proc, _enc) = make_computer_128();

    // Check that there is no padding between arguments.
    let memory = Arc::new(Memory::new_default_stack());
    let prog = memory.allocate_program(&[
        IsaOp::LoadI(T0, 1, 5),
        IsaOp::Dbg(T0, 0),
        IsaOp::LoadI(T0, 16, 7),
        IsaOp::Dbg(T0, 1),
        IsaOp::Dbg(T0, 2), // Not hit, no handler
        IsaOp::Ret(),
    ]);

    let args = ArgsBuilder::new().no_return_value();

    let num_dbgs = Arc::new(AtomicUsize::new(0));
    let dbg_1 = num_dbgs.clone();
    let dbg_2 = num_dbgs.clone();

    let options = RunProgramOptionsBuilder::new()
        .debug_handler(move |id, pc, r| {
            dbg_1.clone().fetch_add(1, Ordering::Relaxed);
            match r {
                Register::Plaintext { val, width } => {
                    assert_eq!(id, 1);
                    assert_eq!(pc, prog.try_offset(8).unwrap().0);
                    assert_eq!(*width, 5);
                    assert_eq!(*val, 1);
                }
                _ => panic!("Expected plaintext register"),
            }
        })
        .debug_handler(move |id, pc, r| {
            dbg_2.clone().fetch_add(1, Ordering::Relaxed);
            match r {
                Register::Plaintext { val, width } => {
                    assert_eq!(id, 3);
                    assert_eq!(pc, prog.try_offset(24).unwrap().0);
                    assert_eq!(*width, 7);
                    assert_eq!(*val, 16);
                }
                _ => panic!("Expected plaintext register"),
            }
        })
        .build();

    proc.run_program_with_options(prog, &memory, args, &options)
        .unwrap();

    assert_eq!(num_dbgs.load(Ordering::Relaxed), 2);
}
