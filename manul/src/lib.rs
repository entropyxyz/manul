#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../../README.md")]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

extern crate alloc;

pub mod protocol;
pub mod session;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
