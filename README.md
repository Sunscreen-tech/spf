# Parasol CPU
This repository contains Sunscreen's Parasol CPU, which allows users to run computations over encrypted data using FHE (Fully Homomorphic Encryption). Its out-of-order processor design automatically extracts parallelism from user-provided programs to run them efficiently on modern architectures. Additionally, its processor design that can crunch numbers over a mix of plaintext and encrypted data provides more flexibility than the traditional circuits used in FHE.

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
{{#include examples/basic_add/data/add.c}}
```

Compile `add.c`
```bash
$LLVM_DIR/clang -c add.o -o add.a -O2 -target parasol
```

This Rust program that runs on the host. This performs encryption, key generation, runs our program, and decrypts the result:

`main.rs`
```rust
{{#include examples/basic_add/src/main.rs}}
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