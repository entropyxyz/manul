/*!
API for protocol users.

This is some description.
*/

mod echo;
mod evidence;
mod message;
#[allow(clippy::module_inception)]
mod session;
mod transcript;

pub use crate::protocol::{LocalError, RemoteError};
pub use message::MessageBundle;
pub use session::{
    CanFinalize, Deserializer, Format, RoundAccumulator, RoundOutcome, Serializer, Session, SessionId,
    SessionParameters,
};
pub use transcript::{SessionOutcome, SessionReport};

pub(crate) use echo::EchoRoundError;

pub use signature;
