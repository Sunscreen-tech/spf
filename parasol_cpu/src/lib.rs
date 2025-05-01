#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate provides the Parasol processor for running programs over encrypted data. The general
//! workflow for using it is:
//! * Compile a program using Parasol-clang
//! * Load the output ELF file using [`FheApplication::parse_elf`].
//! * Create the [`FheComputer`] to run your program.
//! * Allocate and fill [`Buffer`]s that will be passed to your program.
//! * Look up the [`FheProgram`] you want to run by name.
//! * Call [`FheComputer::run_program`].
//! * Return or decrypt your program's result buffer(s).
//!
//! # Example
//! ```ignore
//! use parasol_cpu::{run_program, Buffer};
//! use parasol_runtime::{ComputeKey, Encryption, SecretKey};
//!
//! // Embed the compiled Parasol add program into a constant.
//! const FHE_FILE: &[u8] = include_bytes!("../data/add.a");
//!
//! // Generate a secret key for the user. By default this ensures
//! // 128-bit security.
//! let secret_key =
//!     SecretKey::generate_with_default_params();
//!
//! // Generate a compute key for the user. These keys are used for
//! // operations and do not give access to the plaintext data;
//! // therefore, this key can safely be shared with another party.
//! let compute_key =
//!     ComputeKey::generate_with_default_params(
//!         &secret_key,
//!     );
//!
//! // Define the values we want to add. The values'
//! // sizes must match the Parasol C program's parameters!
//! let a = 2u8;
//! let b = 7u8;
//!
//! // To pass arguments into the Parasol C program, we must convert
//! // them to `Buffer`s. Note that we must provide an output
//! // buffer as well!
//! let arguments = [a, b, 0u8].map(|x| {
//!    Buffer::cipher_from_value(
//!         &x,
//!         &Encryption::default(),
//!         &secret_key,
//!     )
//! });
//!
//! // Run the program.
//! let (gas, encrypted_result) = run_program(
//!     compute_key.clone(),
//!     FHE_FILE,
//!     "add",
//!     &arguments,
//!     200_000,
//! )
//! .unwrap();
//!
//! // Decrypt the result. Note that we have to choose the index
//! // to decrypt from all the arguments passed to the C function;
//! // since the result is written out to the third argument of
//! // the `add` function in C, we specify that index here.
//! let result = encrypted_result[2]
//!     .cipher_try_into_value::<u8>(
//!         &Encryption::default(),
//!         &secret_key,
//!     )
//!     .unwrap();
//! println!("Encrypted {a} + {b} = {result}, using {gas} gas");
//! ```

mod error;
pub use error::*;

// TODO: finish this V2 memory implementation
pub(crate) mod memory;

mod runner;
pub use runner::*;

mod proc;
pub use proc::{Buffer, FheApplication, FheComputer, FheProgram};

#[doc(hidden)]
pub mod test_utils;

#[doc(hidden)]
pub mod tomasulo;
pub use proc::*;
mod util;
pub use parasol_cpu_macros::IntoBytes;
pub use util::IntoBytes;
