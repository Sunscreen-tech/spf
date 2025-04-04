use sunscreen_tfhe::entities::Polynomial;

use crate::{
    proc::IsaOp,
    proc::{program::FheProgram, Buffer},
    test_utils::make_computer_80,
    tomasulo::registers::RegisterName,
    Error,
};

use parasol_runtime::{test_utils::get_secret_keys_80, DEFAULT_80};

#[test]
fn can_load_store_plain_byte_width() {
    let (mut proc, _) = make_computer_80();

    let mut case = |bytes: u32| {
        let plaintext = (0u8..16).collect::<Vec<_>>();
        let buffer_0 = Buffer::plain_from_value(&plaintext);
        let buffer_1 = Buffer::plain_from_value(&vec![0u8; 16]);

        let program = FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::named(0), 0, false),
            IsaOp::BindReadWrite(RegisterName::named(1), 1, false),
            IsaOp::Load(RegisterName::named(0), RegisterName::named(0), bytes * 8),
            IsaOp::Store(RegisterName::named(1), RegisterName::named(0), bytes * 8),
        ]);

        let params = vec![buffer_0, buffer_1];

        proc.run_program(&program, &params).unwrap();

        let ans = params[1].plain_try_into_value::<Vec<u8>>().unwrap();

        for (i, x) in ans.iter().enumerate().take(bytes as usize) {
            assert_eq!(i as u8, *x);
        }

        for x in ans.iter().skip(bytes as usize) {
            assert_eq!(*x, 0);
        }
    };

    for i in 1..=16 {
        case(i);
    }
}

#[test]
fn can_load_store_ciphertext_byte_width() {
    let (mut proc, enc) = make_computer_80();

    let mut case = |width: u32| {
        let plain_values = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let buffer_0 = Buffer::cipher_from_value(&plain_values, &enc, &get_secret_keys_80());
        let output = Buffer::cipher_from_value(&vec![0u8; 8], &enc, &get_secret_keys_80());

        let params = vec![buffer_0.clone(), output];

        proc.run_program(
            &FheProgram::from_instructions(vec![
                IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
                IsaOp::BindReadWrite(RegisterName::named(1), 1, true),
                IsaOp::Load(RegisterName::named(0), RegisterName::named(0), width),
                IsaOp::Store(RegisterName::named(1), RegisterName::named(0), width),
            ]),
            &params,
        )
        .unwrap();

        for (a, b) in buffer_0
            .try_ciphertext()
            .unwrap()
            .iter()
            .zip(params[1].try_ciphertext().unwrap())
            .take(width as usize)
        {
            assert_eq!(a.0, b.0);
        }

        for (plain, out) in plain_values
            .iter()
            .zip(params[1].try_ciphertext().unwrap()[0..width as usize].chunks(8))
        {
            for j in 0..out.len() {
                let expected = (plain >> j) & 0x1;
                let actual = enc.decrypt_glwe_l1(&out[j], &get_secret_keys_80()).coeffs()[0];
                assert_eq!(expected as u64, actual);
            }
        }

        for x in params[1]
            .try_ciphertext()
            .unwrap()
            .iter()
            .skip(width as usize)
        {
            assert_eq!(
                enc.decrypt_glwe_l1(x, &get_secret_keys_80()),
                Polynomial::zero(DEFAULT_80.l1_poly_degree().0)
            );
        }
    };

    for i in 1..=8 {
        case(i);
    }
}

#[test]
fn can_load_immediate() {
    let (mut proc, _) = make_computer_80();

    let output = Buffer::plain_from_value(&0u32);

    let params = vec![output];

    proc.run_program(
        &FheProgram::from_instructions(vec![
            IsaOp::BindReadWrite(RegisterName::named(0), 0, false),
            IsaOp::LoadI(RegisterName::named(0), 1234, 15),
            IsaOp::Store(RegisterName::named(0), RegisterName::named(0), 15),
        ]),
        &params,
    )
    .unwrap();

    let acutal = params[0].plain_try_into_value::<u32>().unwrap();

    assert_eq!(acutal, 1234u32);
}

#[test]
fn load_immediate_fails_out_of_range() {
    let (mut proc, _) = make_computer_80();

    let output = Buffer::plain_from_value(&0u32);

    let params = vec![output];

    let result = proc.run_program(
        &&FheProgram::from_instructions(vec![
            IsaOp::BindReadWrite(RegisterName::named(0), 0, false),
            IsaOp::LoadI(RegisterName::named(0), 1234, 4),
            IsaOp::Store(RegisterName::named(0), RegisterName::named(0), 15),
        ]),
        &params,
    );

    assert!(matches!(
        result,
        Err(Error::OutOfRange { inst_id: 1, pc: 1 })
    ));
}

#[test]
fn can_compute_effective_address_plain_ptr() {
    let (mut proc, _) = make_computer_80();

    let input = Buffer::plain_from_value(&0xDEADBEEFu32);
    let output = Buffer::plain_from_value(&0u16);

    let params = vec![input, output];

    proc.run_program(
        &&FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::named(0), 0, false),
            IsaOp::BindReadWrite(RegisterName::named(1), 1, false),
            IsaOp::LoadI(RegisterName::named(0), 2, 16),
            IsaOp::Cea(
                RegisterName::named(0),
                RegisterName::named(0),
                RegisterName::named(0),
            ),
            IsaOp::Load(RegisterName::named(1), RegisterName::named(0), 16),
            IsaOp::Store(RegisterName::named(1), RegisterName::named(1), 16),
        ]),
        &params,
    )
    .unwrap();

    let actual = params[1].plain_try_into_value::<u16>().unwrap();

    assert_eq!(actual, 0xDEAD);
}

#[test]
fn can_compute_effective_address_encrypted_ptr_plain_offset() {
    let (mut proc, enc) = make_computer_80();

    let input = Buffer::cipher_from_value(&0xDEADBEEFu32, &enc, &get_secret_keys_80());
    let output = Buffer::cipher_from_value(&0u16, &enc, &get_secret_keys_80());

    let params = vec![input, output];

    proc.run_program(
        &FheProgram::from_instructions(vec![
            IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
            IsaOp::BindReadWrite(RegisterName::named(1), 1, true),
            IsaOp::LoadI(RegisterName::named(0), 2, 16),
            IsaOp::Cea(
                RegisterName::named(0),
                RegisterName::named(0),
                RegisterName::named(0),
            ),
            IsaOp::Load(RegisterName::named(1), RegisterName::named(0), 16),
            IsaOp::Store(RegisterName::named(1), RegisterName::named(1), 16),
        ]),
        &params,
    )
    .unwrap();

    let actual = params[1]
        .cipher_try_into_value::<u16>(&enc, &get_secret_keys_80())
        .unwrap();

    assert_eq!(actual, 0xDEAD);
}
