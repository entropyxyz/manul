mod echo;
mod evidence;
mod message;
#[allow(clippy::module_inception)]
mod session;
mod signing;
mod transcript;

#[cfg(feature = "rustcrypto-traits")]
mod signing_rustcrypto;

pub use crate::protocol::{LocalError, RemoteError};
pub use message::MessageBundle;
pub use session::{CanFinalize, RoundAccumulator, RoundOutcome, Session, SessionId};
pub use signing::{Digest, DigestVerifier, Keypair, RandomizedDigestSigner};
pub use transcript::{SessionOutcome, SessionReport};

pub(crate) use echo::EchoRoundError;
