/*!
API for protocol implementors.

A protocol is a directed acyclic graph with the nodes being objects of types implementing [`Round`]
(to be specific, "acyclic" means that the values returned in the `id` field of [`TransitionInfo`]
should not repeat during the protocol execution; the types might).
The starting point is a type that implements [`EntryPoint`].
All the rounds must have their associated type [`Round::Protocol`] set to the same [`Protocol`] instance
to be executed by a [`Session`](`crate::session::Session`).

For more details, see the documentation of the mentioned traits.
*/

mod boxed_format;
mod boxed_round;
mod errors;
mod message;
mod round;
mod round_id;
mod round_info;
mod static_round;

pub use boxed_format::BoxedFormat;
pub use boxed_round::BoxedRound;
pub use errors::{
    DeserializationError, DirectMessageError, EchoBroadcastError, LocalError, MessageValidationError,
    NormalBroadcastError, ProtocolValidationError, ReceiveError, RemoteError,
};
pub use message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage, ProtocolMessagePart};
pub use round::{
    Artifact, CommunicationInfo, EchoRoundParticipation, EntryPoint, FinalizeOutcome, NoProtocolErrors, PartyId,
    Payload, Protocol, ProtocolError, RequiredMessageParts, RequiredMessages, Round,
};
pub use round_id::{RoundId, TransitionInfo};
pub use round_info::BoxedRoundInfo;
pub use static_round::{
    EvidenceMessages, NoMessage, NoProvableErrors, ProvableError, StaticProtocolMessage, StaticRound,
};

pub(crate) use errors::ReceiveErrorType;
pub(crate) use message::ProtocolMessagePartHashable;
pub(crate) use round_info::RoundInfo;
pub(crate) use static_round::StaticRoundAdapter;
