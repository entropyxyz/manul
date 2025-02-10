/*!
API for protocol implementors.

A protocol is a directed acyclic graph with the nodes being objects of types implementing [`Round`]
(to be specific, "acyclic" means that the values returned by [`Round::id`]
should not repeat during the protocol execution; the types might).
The starting point is a type that implements [`EntryPoint`].
All the rounds must have their associated type [`Round::Protocol`] set to the same [`Protocol`] instance
to be executed by a [`Session`](`crate::session::Session`).

For more details, see the documentation of the mentioned traits.
*/

mod errors;
mod message;
mod object_safe;
mod round;
mod serialization;

pub use errors::{
    DeserializationError, DirectMessageError, EchoBroadcastError, LocalError, MessageValidationError,
    NormalBroadcastError, ProtocolValidationError, ReceiveError, RemoteError,
};
pub use message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage, ProtocolMessagePart};
pub use object_safe::BoxedRound;
pub use round::{
    Artifact, EchoRoundParticipation, EntryPoint, FinalizeOutcome, NoProtocolErrors, PartyId, Payload, Protocol,
    ProtocolError, RequiredMessageParts, RequiredMessages, Round, RoundId,
};
pub use serialization::{Deserializer, Serializer};

pub(crate) use errors::ReceiveErrorType;
pub(crate) use message::ProtocolMessagePartHashable;
pub(crate) use object_safe::{BoxedRng, ObjectSafeRound};
