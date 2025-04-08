#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate provides a number of types and methods for interacting with the Parasol processor
//! and FHE.
//!
//! Furthermore, the [`circuits`] module provides [`FheCircuit`] generators that build circuits
//! for performing integer computation.
//!
//! Additionally, the [`fluent`] module provides convenient and readable builders for constructing
//! circuits over integers that one can directly run on a [`UOpProcessor`] and perform low-level
//! operations, such as ciphertext conversion.
mod circuit_processor;

/// Contains circuits that perform integer computation.
pub mod circuits;
mod crypto;
mod error;
pub use error::*;
mod fhe_circuit;

/// A module that allows one to build [`FheCircuit`]s that perform computation over integers and
/// perform low-level operations, such as ciphertext conversion.
pub mod fluent;
mod params;
#[doc(hidden)]
pub mod test_utils;

pub use circuit_processor::{CompletionHandler, UOpProcessor};
pub use crypto::{
    ciphertext::CiphertextType, Encryption, Evaluation, L0LweCiphertext, L1GgswCiphertext,
    L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext, PublicKey, SecretKey, ServerKey,
    ServerKeyFft, TrivialOne, TrivialZero,
};
pub use fhe_circuit::{
    insert_ciphertext_conversion, prune, FheCircuit, FheEdge, FheOp, SharedL0LweCiphertext,
    SharedL1GgswCiphertext, SharedL1GlevCiphertext, SharedL1GlweCiphertext, SharedL1LweCiphertext,
};
pub use params::*;

/// A safe wrapper around [`bincode`] deserialization to limit input sizes and prevent malicious or
/// improperly serialized data from causing panics.
pub mod safe_bincode;
