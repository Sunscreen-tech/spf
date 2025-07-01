#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! This crate provides a number of types and methods for interacting with the Parasol processor
//! and FHE.
//!
//! Furthermore, the [`circuits`] module provides [`FheCircuit`] generators that build circuits
//! for performing integer computation.
//!
//! Additionally, the [`fluent`] module provides convenient and readable builders for constructing
//! circuits over integers that one can directly run on a [`CircuitProcessor`] and perform low-level
//! operations, such as ciphertext conversion.
//!
//! # Example
//!
//! ```rust
//! use parasol_runtime::{
//! fluent::{
//!     FheCircuitCtx, PackedUInt}, ComputeKey, Encryption, Evaluation, L1GgswCiphertext,
//!     L1GlweCiphertext, PublicKey, SecretKey, CircuitProcessor, DEFAULT_128
//! };
//! use std::sync::Arc;
//!
//! // Generate our keys.
//! let sk = SecretKey::generate_with_default_params();
//! let ck = Arc::new(ComputeKey::generate_with_default_params(&sk));
//! let pk = PublicKey::generate(&DEFAULT_128, &sk);
//!
//! // Generate the things needed to encrypt data and run our circuit.
//! let enc = Encryption::new(&DEFAULT_128);
//! let eval = Evaluation::new(ck, &DEFAULT_128, &enc);
//! let (mut proc, flow_control) = CircuitProcessor::new(16384, None, &eval, &enc);
//!
//! // Encrypt our 2 16-bit unsigned inputs, each packed into a single GLWE ciphertext.
//! let a = PackedUInt::<16, L1GlweCiphertext>::encrypt(42, &enc, &pk);
//! let b = PackedUInt::<16, L1GlweCiphertext>::encrypt(16, &enc, &pk);
//!
//! // Build a circuit that first `unpack()`s each encrypted value into 16 ciphertexts.
//! // Next, we convert our encrypted values to L1GgswCiphertext, which will insert
//! // circuit bootstrapping operations.
//! // The fluent types ensure at compile time that you only create valid graphs
//! // and guarantees you've `convert()`ed ciphertexts appropriately.
//! let ctx = FheCircuitCtx::new();
//! let a = a
//!     .graph_input(&ctx)
//!     .unpack(&ctx)
//!     .convert::<L1GgswCiphertext>(&ctx);
//! let b = b
//!     .graph_input(&ctx)
//!     .unpack(&ctx)
//!     .convert::<L1GgswCiphertext>(&ctx);
//!
//! // With our data in GGSW form, we can now multiply the two encrypted integers, which will result in
//! // L1GlweCiphertexts that we re`pack()` into a single ciphertext.
//! let c = a
//!     .mul::<L1GlweCiphertext>(&b, &ctx)
//!     .pack(&ctx, &enc)
//!     .collect_output(&ctx, &enc);
//!
//! proc.run_graph_blocking(&ctx.circuit.borrow(), &flow_control);
//!
//! assert_eq!(c.decrypt(&enc, &sk), 672);
//! ```
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

pub use circuit_processor::{CircuitProcessor, CompletionHandler, RuntimeError};
pub use crypto::{
    ComputeKey, ComputeKeyNonFft, Encryption, Evaluation, KeylessEvaluation, L0LweCiphertext,
    L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext, PublicKey, SecretKey,
    TrivialOne, TrivialZero, ciphertext::CiphertextType, decrypt_one_time_pad,
    generate_one_time_pad, transcipher_one_time_pad,
};
pub use fhe_circuit::{
    FheCircuit, FheEdge, FheOp, SharedL0LweCiphertext, SharedL1GgswCiphertext,
    SharedL1GlevCiphertext, SharedL1GlweCiphertext, SharedL1LweCiphertext,
    insert_ciphertext_conversion, prune,
};
pub use params::*;

/// A safe wrapper around [`bincode`] deserialization to limit input sizes and prevent malicious or
/// improperly serialized data from causing panics.
pub mod safe_bincode;
