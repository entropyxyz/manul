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
mod evidence;
mod message;
mod round;
mod serde_bytes;
mod session;
mod signing;
pub mod testing;
mod transcript;

pub use error::LocalError;
pub use message::MessageBundle;
pub use round::{
    Artifact, DeserializationError, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome,
    FirstRound, MessageValidationError, Payload, Protocol, ProtocolError, ProtocolValidationError,
    ReceiveError, Round, RoundId,
};
pub use session::{CanFinalize, RoundOutcome, Session, SessionId};
pub use signing::{Digest, DigestSigner, DigestVerifier, Keypair};
pub use transcript::{SessionOutcome, SessionReport};
