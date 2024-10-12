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
    unused_qualifications,
)]

extern crate alloc;

mod echo;
mod error;
mod evidence;
mod message;
mod object_safe;
mod round;
mod serde_bytes;
mod session;
mod signing;
pub mod testing;
mod transcript;

#[cfg(feature = "rustcrypto-traits")]
mod signing_rustcrypto;

pub use error::LocalError;
pub use message::MessageBundle;
pub use round::{
    AnotherRound, Artifact, DeserializationError, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome,
    FirstRound, MessageValidationError, Payload, Protocol, ProtocolError, ProtocolValidationError, ReceiveError, Round,
    RoundId,
};
pub use session::{CanFinalize, RoundOutcome, Session, SessionId};
pub use signing::{Digest, DigestVerifier, Keypair, RandomizedDigestSigner};
pub use transcript::{SessionOutcome, SessionReport};
