# Parasol CPU
This crate contains Sunscreen's Parasol CPU, which allows users to run computations over encrypted data using FHE (Fully Homomorphic Encryption). Its out-of-order processor design automatically extracts parallelism from user-provided programs to run them efficiently on modern architectures. Additionally, its processor design that can crunch numbers over a mix of plaintext and encrypted data provides more flexibility than the traditional circuits used in FHE.

When combined with the `parasol_runtime` crate, you can build rich privacy-preserving applications.

# Prereqs
While the contained `parasol_cpu` crate contains everything your need to *run* programs, to write them you'll need the Parasol-llvm compiler. You can get that [here](https://github.com/Sunscreen-tech/testnet-starter/tree/main/compiler).

* Download the tar file for your host architecture and OS.
* Run `tar xvzf parasol-compiler-<variant>.tar.gz`.
* Optionally an environment variable to the untarred location's contained bin directory.

# Basic example
Let's build a basic program where an end user can encrypt two values, send them to a server which will compute and respond with their sum, after which the user finally decrypts the result. For simplicity, we'll describe both parties in a single program.

Program that will run on the Parasol processor:

`add.c`:
```C
typedef unsigned char uint8_t;

[[clang::fhe_circuit]] void add(
    [[clang::encrypted]] uint8_t *a,
    [[clang::encrypted]] uint8_t *b,
    [[clang::encrypted]] uint8_t *output
) {
    *output = *a + *b;
}
```

Compile `add.c`
```bash
$LLVM_DIR/clang -c add.c -o add.a -O2 -target parasol
```

This Rust program that runs on the host generates keys, encrypts our data, runs our program, and decrypts the result:

`main.rs`
```rust
use parasol_cpu::{run_program, Buffer};
use parasol_runtime::{ComputeKey, Encryption, SecretKey};

// Embed the compiled Parasol add program into a constant.
const FHE_FILE: &[u8] = include_bytes!("../data/add.a");

fn main() {
    // Generate a secret key for the user. By default this ensures
    // 128-bit security.
    let secret_key =
        SecretKey::generate_with_default_params();

    // Generate a compute key for the user. These keys are used for
    // operations and do not give access to the plaintext data;
    // therefore, this key can safely be shared with another party.
    let compute_key =
        ComputeKey::generate_with_default_params(
            &secret_key,
        );

    // Define the values we want to add. The sizes of the values' 
    // sizes must match the values' sizes defined in the
    // Parasol C program!
    let a = 2u8;
    let b = 7u8;

    // To pass arguments into the Parasol C program, we must convert
    // them to `Buffer`s. Note that we must provide an output
    // buffer as well!
    let arguments = [a, b, 0u8].map(|x| {
        Buffer::cipher_from_value(
            &x,
            &Encryption::default(),
            &secret_key,
        )
    });

    // Run the program.
    let encrypted_result = run_program(
        compute_key.clone(),
        FHE_FILE,
        "add",
        &arguments,
    )
    .unwrap();

    // Decrypt the result. Note that we have to choose the index
    // to decrypt from all the arguments passed to the C function;
    // since the result is written out to the third argument of
    // the `add` function in C, we specify that index here.
    let result = encrypted_result[2]
        .cipher_try_into_value::<u8>(
            &Encryption::default(),
            &secret_key,
        )
        .unwrap();
    println!("Encrypted {a} + {b} = {result}");
}
```

And finally, our `Cargo.toml`
```toml
[package]
name = "hello-world"
version = "0.1.0"
edition = "2021"

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