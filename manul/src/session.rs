/*!
API for protocol users.

The round-based protocols `manul` is designed to build use a [`Session`] object to drive the protocol forward.
Each participant constructs a [`Session`], defining the actions needed for each round (who to send messages
to, what kind of message and what to do next etc). The rest of the API from this module provide auxilliary
types: setup and parametrization, errors and outcomes.
*/

mod echo;
mod evidence;
mod message;
#[allow(clippy::module_inception)]
mod session;
mod transcript;
mod wire_format;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use crate::protocol::{EvidenceError, LocalError, RemoteError};
pub use evidence::Evidence;
pub use message::{Message, VerifiedMessage};
pub use session::{
    CanFinalize, PreprocessOutcome, RoundAccumulator, RoundOutcome, Session, SessionId, SessionParameters,
};
pub use transcript::{SessionOutcome, SessionReport};
pub use wire_format::WireFormat;

pub(crate) use echo::EchoRoundError;
