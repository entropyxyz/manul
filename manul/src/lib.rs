#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    //missing_docs,
    //missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

mod echo;
mod error;
mod message;
mod round;
mod serde_bytes;
mod session;
mod signing;
pub mod testing;

pub use error::{Error, LocalError};
pub use message::MessageBundle;
pub use round::{
    Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, FirstRound, Payload,
    Protocol, ProtocolError, ReceiveError, Round, RoundId,
};
pub use session::{RoundOutcome, Session};
pub use signing::{Digest, DigestSigner, DigestVerifier, Keypair};
