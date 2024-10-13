#![no_std]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    //missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

extern crate alloc;

pub mod protocol;
mod serde_bytes;
pub mod session;
pub mod testing;
