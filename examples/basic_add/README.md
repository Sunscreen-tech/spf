# Basic Add Program with Parasol FHE

This Rust program demonstrates the use of Parasol FHE CPU to perform a simple addition operation on encrypted data using the Parasol library. The program generates or loads secret and compute keys, encrypts the input values, performs the addition operation on the encrypted values, and then decrypts the result.

This example will both generate the keys needed to run a program and run the program. Since the keys only need to be generated once, the secret and compute keys are serialized to disk in the `target` directory.

## Running the Program

To run the program, execute the following command in the terminal:

```bash
cargo run --release
```
