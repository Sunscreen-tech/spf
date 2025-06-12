# Parasol Runtime
This crate contains the Sunscreen Parasol runtime, which supports running programs over encrypted data with the [`Parasol processor`](https://crates.io/parasol_cpu). This crate provides key generation, encryption, and decryption functionality. Additionally, you can use the `fluent` module to directly compose and run TFHE circuit bootstrapping circuits:

```rust
use crate::{
    fluent::{FheCircuitCtx, PackedUInt}, ComputeKey, Encryption, Evaluation, L1GgswCiphertext, L1GlweCiphertext, PublicKey, SecretKey, CircuitProcessor, DEFAULT_128
};
use std::sync::Arc;

fn multiply_16_bit() {
    // Generate our keys.
    let sk = SecretKey::generate_with_default_params();
    let ck = Arc::new(ComputeKey::generate_with_default_params(&sk));
    let pk = PublicKey::generate(&DEFAULT_128, &sk);

    // Generate the things needed to encrypt data and run our circuit.
    let enc = Encryption::new(&DEFAULT_128);
    let eval = Evaluation::new(ck, &DEFAULT_128, &enc);
    let (mut proc, flow_control) = CircuitProcessor::new(16384, None, &eval, &enc);

    // Encrypt our 2 16-bit unsigned inputs, each packed into a single GLWE ciphertext. 
    let a = PackedUInt::<16, L1GlweCiphertext>::encrypt(42, &enc, &pk);
    let b = PackedUInt::<16, L1GlweCiphertext>::encrypt(16, &enc, &pk);

    // Build a circuit that first `unpack()`s each encrypted value into 16 ciphertexts.
    // Next, we convert our encrypted values to L1GgswCiphertext, which will insert 
    // circuit bootstrapping operations.
    // The fluent types ensure at compile time that you only create valid graphs
    // and guarantees you've `convert()`ed ciphertexts appropriately.
    let ctx = FheCircuitCtx::new();
    let a = a
        .graph_input(&ctx)
        .unpack(&ctx)
        .convert::<L1GgswCiphertext>(&ctx);
    let b = b
        .graph_input(&ctx)
        .unpack(&ctx)
        .convert::<L1GgswCiphertext>(&ctx);

    // With our data in GGSW form, we can now multiply the two encrypted integers, which will result in
    // L1GlweCiphertexts that we re`pack()` into a single ciphertext.
    let c = a
        .mul::<L1GlweCiphertext>(&b, &ctx)
        .pack(&ctx, &enc)
        .collect_output(&ctx, &enc);

    proc.run_graph_blocking(&ctx.circuit.borrow(), &flow_control);

    assert_eq!(c.decrypt(&enc, &sk), 672);
}
```