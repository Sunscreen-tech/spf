use std::sync::Arc;

use crate::{
    ArgsBuilder, Memory,
    proc::IsaOp,
    register_names::*,
    test_utils::{MaybeEncryptedUInt, make_computer_80},
};

use parasol_runtime::test_utils::get_secret_keys_128;

#[test]
fn can_mov() {
    let test = |src_val, src_enc, dst_val, dst_enc| {
        let (mut proc, enc) = make_computer_80();
        let sk = get_secret_keys_128();

        let memory = Memory::new_default_stack();

        let program = memory.allocate_program(&[IsaOp::Move(A0, A1), IsaOp::Ret()]);

        let args = ArgsBuilder::new()
            .arg(MaybeEncryptedUInt::<32>::new(
                dst_val as u64,
                &enc,
                &sk,
                dst_enc,
            ))
            .arg(MaybeEncryptedUInt::<32>::new(
                src_val as u64,
                &enc,
                &sk,
                src_enc,
            ))
            .return_value::<MaybeEncryptedUInt<32>>();

        let result = proc.run_program(program, &Arc::new(memory), args).unwrap();

        let ret_val = result.get(&enc, &sk);

        assert_eq!(
            src_val, ret_val,
            "src_val: {src_val:#02x}, ans_sum: {ret_val:#02x}, [unimportant from here] src_enc: {src_enc}, dst_val: {dst_val:#02x}, dst_enc; {dst_enc}"
        );
    };

    for src_enc in [true, false] {
        for dst_enc in [true, false] {
            test(0xF00Du32, src_enc, 0xFEEDu32, dst_enc);
        }
    }
}
