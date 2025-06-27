use std::sync::Arc;

use parasol_cpu::{ArgsBuilder, Byte, FheComputer, Memory, RunProgramOptionsBuilder, ToArg};
use parasol_runtime::{
    Encryption, Evaluation,
    fluent::{Int8, Int16, Int32, Int64, UInt, UInt8, UInt16, UInt32, UInt64},
};

use crate::{get_ck, get_sk};

#[test]
fn can_run_from_elf_fn1() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/args")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let result = memory.try_allocate_type(&UInt64::new(&enc)).unwrap();

    let args = ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(42, &enc, sk))
        .arg(UInt16::encrypt_secret(54, &enc, sk))
        .arg(UInt32::encrypt_secret(96, &enc, sk))
        .arg(UInt64::encrypt_secret(17, &enc, sk))
        .arg(result)
        .no_return_value();

    let prog = memory.get_function_entry("fn1").unwrap();

    proc.run_program(prog, &memory, args).unwrap();

    let result = memory.try_load_type::<UInt64>(result).unwrap();
    assert_eq!(result.decrypt(&enc, sk), 209);
}

#[test]
fn can_run_from_elf_fn2() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/args")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(UInt8::encrypt_secret(42, &enc, sk))
        .arg(UInt16::encrypt_secret(54, &enc, sk))
        .arg(UInt32::encrypt_secret(96, &enc, sk))
        .arg(UInt64::encrypt_secret(17, &enc, sk))
        .return_value::<UInt32>();

    let prog = memory.get_function_entry("fn2").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 209);
}

#[test]
fn can_run_from_elf_fn3() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/args")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(UInt64::encrypt_secret(42, &enc, sk))
        .arg(UInt32::encrypt_secret(54, &enc, sk))
        .arg(UInt16::encrypt_secret(96, &enc, sk))
        .arg(UInt8::encrypt_secret(17, &enc, sk))
        .return_value::<UInt32>();

    let prog = memory.get_function_entry("fn3").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.decrypt(&enc, sk), 209);
}

struct Fn4Result {
    a: Int8,
    b: Int16,
    c: Int32,
    d: Int64,
}

impl ToArg for Fn4Result {
    fn alignment() -> usize {
        8
    }

    fn size() -> usize {
        16
    }

    fn to_bytes(&self) -> Vec<Byte> {
        unimplemented!()
    }

    fn try_from_bytes(data: Vec<Byte>) -> parasol_cpu::Result<Self> {
        if data.len() != Self::size() {
            return Err(parasol_cpu::Error::TypeSizeMismatch);
        }

        Ok(Self {
            a: Int8::try_from_bytes(data[0..1].to_owned())?,
            b: Int16::try_from_bytes(data[2..4].to_owned())?,
            c: Int32::try_from_bytes(data[4..8].to_owned())?,
            d: Int64::try_from_bytes(data[8..].to_owned())?,
        })
    }
}

#[test]
fn can_run_from_elf_fn4() {
    let memory = Arc::new(Memory::new_from_elf(include_bytes!("../test_data/args")).unwrap());

    let sk = get_sk();
    let ck = get_ck();

    let enc = Encryption::default();
    let eval = Evaluation::with_default_params(ck);

    let mut proc = FheComputer::new(&enc, &eval);

    let args = ArgsBuilder::new()
        .arg(UInt64::encrypt_secret(42, &enc, sk))
        .arg(UInt32::encrypt_secret(54, &enc, sk))
        .arg(UInt16::encrypt_secret(96, &enc, sk))
        .arg(UInt8::encrypt_secret(17, &enc, sk))
        .return_value::<Fn4Result>();

    let prog = memory.get_function_entry("fn4").unwrap();

    let result = proc.run_program(prog, &memory, args).unwrap();

    assert_eq!(result.a.decrypt(&enc, sk), 17);
    assert_eq!(result.b.decrypt(&enc, sk), 96);
    assert_eq!(result.c.decrypt(&enc, sk), 54);
    assert_eq!(result.d.decrypt(&enc, sk), 42);
}
