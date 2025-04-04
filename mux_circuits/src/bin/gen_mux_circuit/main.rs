use clap::{Parser, ValueEnum};
use mux_circuits::mul::{gradeschool_reduce_impl, multiplier_impl, MultiplierParams};
use std::{fs, path::PathBuf};

#[derive(ValueEnum, Clone)]
enum CircuitType {
    Mul,
    GSR,
}

#[derive(Parser)]
struct Args {
    #[arg(long, value_enum)]
    circuit_type: CircuitType,

    #[arg(long)]
    n: usize,

    #[arg(long)]
    m: usize,

    #[arg(long)]
    output_dir: String,
}

/// Example command:
/// cargo run --bin gen_mux_circuit -- --circuit-type mul --n 8 --m 8 --output-dir mux_circuits/src/data
/// Make sure the output directory is desired if a relative path is used
fn main() {
    let args = Args::parse();

    let params = MultiplierParams {
        n: args.n,
        m: args.m,
    };
    let path = PathBuf::from(&args.output_dir);
    fs::create_dir_all(&path).expect("Failed to create path if needed");
    let path = fs::canonicalize(path).expect("Cannot determine absolute path");

    let func: fn(MultiplierParams) -> _;
    let circuit_type;
    match args.circuit_type {
        CircuitType::Mul => {
            func = multiplier_impl;
            circuit_type = "multiplier";
        }
        CircuitType::GSR => {
            func = gradeschool_reduce_impl;
            circuit_type = "gradeschool-reduction";
        }
    }
    let file_name = path.join(format!("{}-n{}-m{}", circuit_type, params.n, params.m));

    println!(
        "Generating {} circuit with params {} to be saved as {}",
        circuit_type,
        params,
        file_name.as_os_str().to_str().unwrap()
    );

    let circuit = func(params).expect("Failed to generate circuit");
    let data = bincode::serialize(&circuit).expect("Failed to serialize with bincode");

    std::fs::write(&file_name, data).expect("Failed to write data to file");

    println!("Done!")
}
