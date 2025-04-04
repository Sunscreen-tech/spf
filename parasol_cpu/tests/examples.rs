use std::{ffi::CString, time::Instant};

use parasol_cpu::{test_utils::*, FheApplication, Symbol};
use rand::{thread_rng, RngCore};

const CHI_SQUARED_ELF: &[u8] = include_bytes!("test_data/chi_squared.o");
const CMUX_ELF: &[u8] = include_bytes!("test_data/cmux.o");
const CARDIO_ELF: &[u8] = include_bytes!("test_data/cardio.o");
const VECTOR_ADD: &[u8] = include_bytes!("test_data/vector-add.o");

use parasol_runtime::{
    fluent::UInt,
    test_utils::{get_secret_keys_128, get_secret_keys_80},
    L1GlweCiphertext,
};

#[test]
fn can_run_chi_squared_elf_program() {
    let result = FheApplication::parse_elf(CHI_SQUARED_ELF).unwrap();

    let program = result
        .get_program(&Symbol::new(
            &CString::new("chi_squared_optimized").unwrap(),
        ))
        .unwrap();

    let (mut proc, enc) = make_computer_80();

    let n_0 = 2u16;
    let n_1 = 7u16;
    let n_2 = 9u16;

    let n_0 = buffer_from_value_80(n_0, &enc, true);
    let n_1 = buffer_from_value_80(n_1, &enc, true);
    let n_3 = buffer_from_value_80(n_2, &enc, true);

    let alpha = buffer_from_value_80(0u16, &enc, true);
    let b_1 = buffer_from_value_80(0u16, &enc, true);
    let b_2 = buffer_from_value_80(0u16, &enc, true);
    let b_3 = buffer_from_value_80(0u16, &enc, true);

    let params = vec![
        n_0,
        n_1,
        n_3,
        alpha.clone(),
        b_1.clone(),
        b_2.clone(),
        b_3.clone(),
    ];

    let now = Instant::now();

    proc.run_program(program, &params).unwrap();

    dbg!(now.elapsed().as_secs_f64());

    let alpha = alpha
        .cipher_try_into_value::<u16>(&enc, &get_secret_keys_80())
        .unwrap();
    let b_1 = b_1
        .cipher_try_into_value::<u16>(&enc, &get_secret_keys_80())
        .unwrap();
    let b_2 = b_2
        .cipher_try_into_value::<u16>(&enc, &get_secret_keys_80())
        .unwrap();
    let b_3 = b_3
        .cipher_try_into_value::<u16>(&enc, &get_secret_keys_80())
        .unwrap();

    dbg!(alpha);
    dbg!(b_1);
    dbg!(b_2);
    dbg!(b_3);

    assert_eq!(alpha, 529);
    assert_eq!(b_1, 242);
    assert_eq!(b_2, 275);
    assert_eq!(b_3, 1250);
}

// This test is for checking that we can run against the extracted buffer
// information and pass in UInt values instead of buffers. This enables us to
// compute on arbitrary programs and values from the fluent crate.
#[test]
fn can_run_chi_squared_elf_program_with_generated_write_buffers() {
    let result = FheApplication::parse_elf(CHI_SQUARED_ELF).unwrap();

    // Get the program and its buffer information
    let program = result
        .get_program(&Symbol::new(
            &CString::new("chi_squared_optimized").unwrap(),
        ))
        .unwrap();

    let (mut proc, enc) = make_computer_128();
    let sk = get_secret_keys_128();

    // Input values (n_0, n_1, n_2)
    let input_values = [2u16, 7u16, 9u16];
    let input_values = input_values
        .into_iter()
        .map(|x| UInt::<16, L1GlweCiphertext>::encrypt_secret(x as u64, &enc, &sk).into())
        .collect::<Vec<_>>();

    // Create buffers based on buffer info
    let now = std::time::Instant::now();
    let outputs = proc
        .run_programs_with_generated_write_buffers(program, &input_values)
        .unwrap();
    dbg!(now.elapsed().as_secs_f64());

    // Convert output buffers to UInts and decrypt
    // Based on the original test, outputs are alpha, b_1, b_2, b_3
    let alpha: UInt<16, L1GlweCiphertext> = (&outputs[0]).try_into().unwrap();
    let b_1: UInt<16, L1GlweCiphertext> = (&outputs[1]).try_into().unwrap();
    let b_2: UInt<16, L1GlweCiphertext> = (&outputs[2]).try_into().unwrap();
    let b_3: UInt<16, L1GlweCiphertext> = (&outputs[3]).try_into().unwrap();

    let alpha = alpha.decrypt(&enc, &sk) as u16;
    let b_1 = b_1.decrypt(&enc, &sk) as u16;
    let b_2 = b_2.decrypt(&enc, &sk) as u16;
    let b_3 = b_3.decrypt(&enc, &sk) as u16;

    dbg!(alpha);
    dbg!(b_1);
    dbg!(b_2);
    dbg!(b_3);

    assert_eq!(alpha, 529);
    assert_eq!(b_1, 242);
    assert_eq!(b_2, 275);
    assert_eq!(b_3, 1250);
}

#[test]
fn can_run_cmux_elf_program() {
    let result = FheApplication::parse_elf(CMUX_ELF).unwrap();

    let program = result
        .get_program(&Symbol::new(&CString::new("cmux").unwrap()))
        .unwrap();

    let (mut proc, enc) = make_computer_80();
    let encrypted_computation = true;

    // Make an array of size 10 of random numbers modulo 20
    let random_conditions = (0..10).map(|_| thread_rng().next_u32() % 20);

    for bound in random_conditions {
        let a = thread_rng().next_u32() as u8;
        let b = thread_rng().next_u32() as u8;

        let expected = if bound > 10 { a } else { b };

        let buffer_0 = buffer_from_value_80(bound, &enc, encrypted_computation);
        let buffer_1 = buffer_from_value_80(a, &enc, encrypted_computation);
        let buffer_2 = buffer_from_value_80(b, &enc, encrypted_computation);
        let output_buffer = buffer_from_value_80(0u8, &enc, encrypted_computation);

        let params = vec![buffer_0, buffer_1, buffer_2, output_buffer];

        proc.run_program(program, &params).unwrap();

        let ans = read_result(&params[3], &enc, encrypted_computation);
        assert_eq!(expected, ans);
    }
}

fn cardio(
    flags: u8,
    age: u8,
    hdl: u8,
    weight: u8,
    height: u8,
    physical_activity: u8,
    glasses_alcohol: u8,
) -> u8 {
    let man = (flags & 1) != 0;
    let smoking = ((flags >> 1) & 1) != 0;
    let diabetic = ((flags >> 2) & 1) != 0;
    let high_bp = ((flags >> 3) & 1) != 0;

    let cond1 = (man && (age > 50)) as u8;
    let cond2 = (!man && (age > 60)) as u8;
    let cond3 = smoking as u8;
    let cond4 = diabetic as u8;
    let cond5 = high_bp as u8;
    let cond6 = (hdl < 40) as u8;
    let cond7 = (weight > height - 90) as u8;
    let cond8 = (physical_activity < 30) as u8;
    let cond9 = (man && (glasses_alcohol > 3)) as u8;
    let cond10 = (!man && (glasses_alcohol > 2)) as u8;

    cond1 + cond2 + cond3 + cond4 + cond5 + cond6 + cond7 + cond8 + cond9 + cond10
}

#[test]
fn can_run_cardio_elf_program() {
    let result = FheApplication::parse_elf(CARDIO_ELF).unwrap();

    let program = result
        .get_program(&Symbol::new(&CString::new("cardio").unwrap()))
        .unwrap();

    let (mut proc, enc) = make_computer_80();
    let encrypted_computation = true;

    let man = false;
    let smoking = false;
    let diabetic = true;
    let high_bp = true;

    let age = 40u8;
    let hdl = 50u8;
    let weight = 70u8;
    let height = 170u8;
    let physical_activity = 1u8;
    let glasses_alcohol = 1u8;

    let flags = [man, smoking, diabetic, high_bp]
        .iter()
        .enumerate()
        .map(|(i, &x)| (x as u8) << i)
        .sum::<u8>();

    let expected = cardio(
        flags,
        age,
        hdl,
        weight,
        height,
        physical_activity,
        glasses_alcohol,
    );

    let params_raw = [
        flags,
        age,
        hdl,
        weight,
        height,
        physical_activity,
        glasses_alcohol,
        0u8, // Output buffer
    ];

    let params = params_raw
        .iter()
        .map(|&x| buffer_from_value_80(x, &enc, encrypted_computation))
        .collect::<Vec<_>>();

    let now = std::time::Instant::now();
    proc.run_program(program, &params).unwrap();
    let elapsed = now.elapsed();
    dbg!("Elapsed time for cardio program: ", elapsed);

    let ans = params[7]
        .cipher_try_into_value::<u8>(&enc, &get_secret_keys_80())
        .unwrap();

    dbg!(ans);

    assert_eq!(expected, ans);
}

#[test]
fn can_vector_add() {
    let result = FheApplication::parse_elf(VECTOR_ADD).unwrap();

    let program = result
        .get_program(&Symbol::new(&CString::new("vector_add").unwrap()))
        .unwrap();

    let (mut proc, enc) = make_computer_128();

    let params = (1..=24u8)
        .map(|x| buffer_from_value_128(x, &enc, true))
        .collect::<Vec<_>>();

    let start = Instant::now();
    proc.run_program(program, &params).unwrap();
    println!("Runtime: {}s", start.elapsed().as_secs_f64());

    let ans = params[16..]
        .iter()
        .map(|x| {
            x.cipher_try_into_value::<u8>(&enc, &get_secret_keys_128())
                .unwrap()
        })
        .collect::<Vec<_>>();

    dbg!(ans);
}
