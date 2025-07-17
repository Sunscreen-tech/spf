use std::time::Instant;

use parasol_cpu::make_computer_128;
use parasol_runtime::{
    fluent::PackedDynamicUInt,
    test_utils::{get_public_key_128, get_secret_keys_128},
};
use rand::{RngCore, rng};

fn main() {
    let (mut proc, enc) = make_computer_128();
    let pk = get_public_key_128();
    let sk = get_secret_keys_128();

    let n = 320;

    for bits in [8, 16, 32, 64] {
        println!("USE {bits}");

        for i in 1..=n {
            eprintln!("Round {i} / {n} for {bits}");

            let packed = PackedDynamicUInt::encrypt(
                rng().next_u64() as u128 & ((1 << bits) - 1),
                &enc,
                &pk,
                bits,
            );

            let now = Instant::now();
            let unpacked = proc.unpack_int_dyn(packed.clone()).unwrap();
            let elapsed = now.elapsed().as_secs_f64() * 1_000_000.0;

            println!("Unpack {}", elapsed);

            let now = Instant::now();
            let repacked = proc.pack_int_dyn(unpacked).unwrap();
            let elapsed = now.elapsed().as_secs_f64() * 1_000_000.0;

            println!("Pack {}", elapsed);

            assert_eq!(packed.decrypt(&enc, &sk), repacked.decrypt(&enc, &sk));
        }
    }
}
