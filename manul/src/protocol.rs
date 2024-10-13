/*!
API for protocol implementors.

A protocol is a directed acyclic graph with the nodes being objects of types implementing [`Round`]
(to be specific, "acyclic" means that the values returned by [`Round::id`]
should not repeat during the protocol execution; the types might).
The starting point is a type also implementing [`FirstRound`].
All the rounds should have their associated type [`Round::Protocol`] set to the same [`Protocol`] instance
to be executed by a [`Session`](`crate::session::Session`).

For more details, see the documentation of the mentioned traits.
*/

mod error;
mod object_safe;
mod round;

pub use crate::session::SessionId;
pub use error::{LocalError, RemoteError};
pub use round::{
    AnotherRound, Artifact, DeserializationError, DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError,
    FinalizeError, FinalizeOutcome, FirstRound, MessageValidationError, Payload, Protocol, ProtocolError,
    ProtocolValidationError, ReceiveError, Round, RoundId,
};

pub(crate) use object_safe::{ObjectSafeRound, ObjectSafeRoundWrapper};
pub(crate) use round::ReceiveErrorType;

pub use digest;
