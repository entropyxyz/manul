extern crate alloc;

mod format;
pub mod simple;

#[cfg(test)]
mod simple_malicious;

pub use format::Bincode;
