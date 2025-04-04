#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

//! This crate contains a set of math structures and operations for working with
//! FHE and ZKPs.

/// Traits for working with fields
pub mod field;

/// Functions related to combinatorics
pub mod combination;

/// Statistics functions
pub mod stats;

/// Functions related to calculating security and correctness parameters.
pub mod security;

/// Functions and data structures related to geometry
pub mod geometry;

mod error;
pub use error::*;

/// Traits and types for performing arithmetic over rings.
pub mod ring;

/// Traits and types for performing arithmetic with polynomials.
pub mod poly;

mod misc_traits;
pub use misc_traits::*;

pub use sunscreen_math_macros::{refify_binary_op, BarrettConfig};
