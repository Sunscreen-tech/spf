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
