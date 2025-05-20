# Parasol processor
This crate contains Sunscreen's virtual processor, which allows users to run computations over encrypted data using FHE (Fully Homomorphic Encryption). Its out-of-order processor design automatically extracts parallelism from user-provided programs to run them efficiently on modern architectures. Additionally, its design provides more flexibility than the traditional circuits used in FHE.

# Basic example
Let's build a basic program where an end user can encrypt two values and send them to a server which will compute and respond with their encrypted sum. After that, the user decrypts the result. For simplicity, we'll describe both parties in a single program.

Program that will run on our virtual processor:

`add.c`:
```C
typedef unsigned char uint8_t;

[[clang::fhe_program]] uint8_t add(
    [[clang::encrypted]] uint8_t a,
    [[clang::encrypted]] uint8_t b
) {
    return a + b;
}
```

Compile `add.c`
```bash
$LLVM_DIR/clang -c add.c -o add.o -O2 -target parasol
$LLVM_DIR/ld.lld add.o -o add
```

This Rust program that runs on the host generates keys, encrypts our data, runs our program, and decrypts the result:

`main.rs`
```rust
use parasol_cpu::{run_program, ArgsBuilder};
use parasol_runtime::{ComputeKey, Encryption, SecretKey, fluent::Uint};

// Embed the compiled Parasol add program into a constant.
const FHE_FILE: &[u8] = include_bytes!("../data/add");

fn main() {
    // Generate a secret key for the user. By default this ensures
    // 128-bit security.
    let secret_key =
        SecretKey::generate_with_default_params();

    // Generate a compute key for the user. These keys are used for
    // FHE operations and do not give access to the plaintext data;
    // therefore, this key can safely be shared with another party.
    let compute_key =
        ComputeKey::generate_with_default_params(
            &secret_key,
        );

    // Define the values we want to add. The values' 
    // sizes must match the Parasol C program's parameters
    // when we encrypt them. Create the arguments and specify
    // the return type
    let enc = Encryption::default();
    let args = ArgsBuilder::new()
        .arg(UInt::<8, _>::encrypt_secret(2, &enc, &sk))
        .arg(UInt::<8, _>::encrypt_secret(7, &enc, &sk))
        .return_value::<UInt<8, _>>();

    // Run the program.
    let encrypted_result = run_program(
        compute_key.clone(),
        FHE_FILE,
        "add",
        &args,
    )
    .unwrap();

    // Decrypt the result.
    let result = encrypted_result.decrypt(&enc, &sk);

    println!("Encrypted {a} + {b} = {result}");
}
```

And finally, our `Cargo.toml`
```toml
[package]
name = "hello-world"
version = "0.1.0"
edition = "2024"

[dependencies]
parasol_cpu = "0.9"
parasol_runtime = "0.9"
```

When we run our program

```rust
cargo run --release
```

we get

```
Encrypted 2 + 7 = 9
```
