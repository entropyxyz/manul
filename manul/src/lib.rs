#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![warn(
    clippy::mod_module_files,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications,
    missing_debug_implementations
)]
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::indexing_slicing,))]

extern crate alloc;

pub mod combinators;
pub mod protocol;
pub mod session;
pub mod utils;

#[cfg(any(test, feature = "dev"))]
pub mod dev;

#[cfg(test)]
mod tests;

// Re-exports for easier version matching
pub use digest;
pub use signature;
