use std::path::{Path, PathBuf};

use args::{AnalyzeNoise, Command};
use cbs::analyze_cbs;
use clap::Parser;
use cmux::analyze_cmux;
use lwe_keyswitch::analyze_lwe_keyswitch;
use mean_comp_radix_decomp::analyze_mean_compensation_radix_decomposition;
use modulus_switch::analyze_modulus_switch;
use parasol_runtime::{ComputeKeyNonFft, Params, SecretKey};
use pbs::analyze_pbs;
use scheme_switch::{analyze_scheme_switch, search_scheme_switch};
use secret_key_encryption::run_secret_key_encryption;
use serde::Serialize;

mod args;
mod cbs;
mod cmux;
mod error;
mod pbs;
pub use error::*;
mod math;
pub use math::*;
mod cmux_tree;
mod lwe_keyswitch;
mod mean_comp_radix_decomp;
mod modulus_switch;
mod noise;
mod scheme_switch;
mod secret_key_encryption;

pub fn get_keys(params: &Params) -> (SecretKey, ComputeKeyNonFft) {
    let sk = SecretKey::generate(params);

    let compute = ComputeKeyNonFft::generate(&sk, params);

    (sk, compute)
}

pub fn write_results<R: Serialize>(path: &Path, r: &R) {
    std::fs::write(path, serde_json::to_string_pretty(r).unwrap()).unwrap();
    println!("Results written to {}", path.to_string_lossy());
}

fn main() {
    let args = AnalyzeNoise::parse();

    let _ = std::fs::create_dir("noise_analysis");
    let path = PathBuf::from("noise_analysis");

    match args.command {
        Command::SecretKeyEncryption(cmd) => {
            let result = run_secret_key_encryption(cmd);
            write_results(&path.join("secret_key_encryption.json"), &result);
        }
        Command::SearchSchemeSwitch(cmd) => {
            let result = search_scheme_switch(&cmd);
            write_results(&path.join("search_scheme_switch.json"), &result);
        }
        Command::AnalyzeSchemeSwitch(cmd) => {
            let result = analyze_scheme_switch(&cmd);
            write_results(&path.join("analyze_scheme_switch.json"), &result);
        }
        Command::AnalyzeModulusSwitch(cmd) => {
            let result = analyze_modulus_switch(&cmd);
            write_results(&path.join("analyze_modulus_switch.json"), &result);
        }
        Command::AnalyzeLweKeyswitch(cmd) => {
            let result = analyze_lwe_keyswitch(&cmd);
            write_results(&path.join("analyze_lwe_key_switch.json"), &result);
        }
        Command::AnalyzeMeanCompRadixDecomp(cmd) => {
            let result = analyze_mean_compensation_radix_decomposition(&cmd);
            write_results(
                &path.join("analyze_mean_compensation_radix_decomposition.json"),
                &result,
            );
        }
        Command::AnalyzeCbs(cmd) => {
            let result = analyze_cbs(&cmd);
            write_results(&path.join("analyze_cbs.json"), &result);
        }
        Command::AnalyzePbs(cmd) => {
            let result = analyze_pbs(&cmd);
            write_results(&path.join("analyze_pbs.json"), &result);
        }
        Command::AnalyzeCmux(cmd) => {
            if let Err(e) = cmd.load_config() {
                eprintln!("Error loading configuration: {e}");
                return;
            }
            let result = analyze_cmux(&cmd);
            write_results(&path.join("analyze_cmux.json"), &result);
        }
        Command::AnalyzeCmuxTree(cmd) => {
            let cmux_tree_params = cmd
                .source
                .load_config()
                .expect("Error loading configuration");
            let result = cmux_tree::analyze_cmux_tree(&cmux_tree_params);
            write_results(&path.join("analyze_cmux_tree.json"), &result);
        }
    };
}
