# Parasol Runtime
This crate contains the Sunscreen Parasol runtime, which supports running programs over encrypted data with the [`parasol_cpu`](https://crates.io/parasol_cpu) crate. This crate provides key generation, encryption, and decryption functionality. Additionally, you can use the `fluent` module to generate if you want to directly compose with TFHE circuits with programmable bootstrapping:

```rust
use parasol_runtime::{ComputeKey, Encryption, SecretKey, DEFAULT_128, UOpProcessor};

fn main() {
    let sk = SecretKey::generate_with_default_params();
    let ck = Arc::new(ComputeKey::generate_with_default_params(&sk));
    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(ck, &DEFAULT_128, &enc);

    let ctx = FheCircuitCtx::new();
    let (mut proc, flow_control) = UOpProcessor::new(16384, None, &eval, &enc);

    let a = UInt::<16, L1GgswCiphertext>::encrypt_secret(42, &enc, &sk).graph_inputs(&ctx);
    let b = UInt::<16, L1GgswCiphertext>::encrypt_secret(16, &enc, &sk).graph_inputs(&ctx);

    let c = a.mul::<L1GlweCiphertext>(&b, &ctx).collect_outputs(&ctx, &enc);

    proc.run_graph_blocking(&ctx.circuit.borrow(), &flow_control);

    assert_eq!(c.decrypt(&enc, &sk), 672);
}
```