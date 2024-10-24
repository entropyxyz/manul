/*!
API for protocol implementors.

A protocol is a directed acyclic graph with the nodes being objects of types implementing [`Round`]
(to be specific, "acyclic" means that the values returned by [`Round::id`]
should not repeat during the protocol execution; the types might).
The starting point is a type that implements [`FirstRound`].
All the rounds must have their associated type [`Round::Protocol`] set to the same [`Protocol`] instance
to be executed by a [`Session`](`crate::session::Session`).

For more details, see the documentation of the mentioned traits.
*/

mod errors;
mod object_safe;
mod round;

pub use errors::{
    DeserializationError, DirectMessageError, EchoBroadcastError, FinalizeError, LocalError, MessageValidationError,
    ProtocolValidationError, ReceiveError, RemoteError,
};
pub use round::{
    AnotherRound, Artifact, DirectMessage, EchoBroadcast, FinalizeOutcome, FirstRound, Payload, Protocol,
    ProtocolError, Round, RoundId,
};

pub(crate) use errors::ReceiveErrorType;
pub(crate) use object_safe::{ObjectSafeRound, ObjectSafeRoundWrapper};

pub use digest;
