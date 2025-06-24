#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate provides the Parasol processor for running programs over encrypted data. The general
//! workflow for using it is:
//! * Compile a program using Parasol-clang
//! * Encrypt our data and create an [`CallData`] object.
//! * Call [`FheComputer::run_program`], passing our key, program binary, the name of
//!   the program we want to run, and args.
//! * Return or decrypt your program's result.
//!
//! # Example
//! ```ignore
//! use parasol_cpu::{run_program, ArgsBuilder};
//! use parasol_runtime::{ComputeKey, Encryption, SecretKey, fluent::Uint};
//!
//! // Embed the compiled Parasol add program into a constant.
//! const FHE_FILE: &[u8] = include_bytes!("../data/add");
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
//! // sizes must match the Parasol C program's parameters
//! // when we encrypt them. Create the arguments and specify
//! // the return type
//! let enc = Encryption::default();
//! let args = ArgsBuilder::new()
//!     .arg(UInt::<8, _>::encrypt_secret(2, &enc, &sk))
//!     .arg(UInt::<8, _>::encrypt_secret(7, &enc, &sk))
//!     .return_value::<UInt<8, _>>();
//!
//! // Run the program.
//! let encrypted_result = run_program(
//!     compute_key.clone(),
//!     FHE_FILE,
//!     "add",
//!     &args,
//! )
//! .unwrap();
//!
//! // Decrypt the result.
//! let result = encrypted_result.decrypt(&enc, &sk);
//!
//! println!("Encrypted {a} + {b} = {result}");
//! ```

mod error;
pub use error::*;

mod memory;
pub use memory::*;

mod proc;
pub use proc::FheComputer;
pub use proc::assembly::register_names;

#[doc(hidden)]
pub mod test_utils;

#[doc(hidden)]
pub mod tomasulo;
pub use parasol_cpu_macros::IntoBytes;
pub use proc::*;

mod runner;
pub use runner::*;
