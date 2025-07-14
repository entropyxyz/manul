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

mod dyn_evidence;
mod dyn_round;
mod errors;
mod evidence;
mod message;
mod rng;
mod round;
mod round_id;
mod round_info;
mod wire_format;

pub use dyn_round::BoxedRound;
pub use errors::{LocalError, ReceiveError, RemoteError};
pub use evidence::{
    EvidenceError, EvidenceMessages, NoProtocolErrors, ProtocolError, RequiredMessageParts, RequiredMessages,
};
pub use round::{
    CommunicationInfo, EchoRoundParticipation, EntryPoint, FinalizeOutcome, NoArtifact, NoMessage, PartyId, Protocol,
    ProtocolMessage, Round,
};
pub use round_id::{RoundId, RoundNum, TransitionInfo};
pub use round_info::RoundInfo;

pub(crate) use dyn_evidence::{BoxedProtocolError, SerializedProtocolError};
pub(crate) use dyn_round::{Artifact, BoxedReceiveError, BoxedTypedRound, DynRound, Payload};
pub(crate) use evidence::EvidenceProtocolMessage;
pub(crate) use message::{
    DirectMessage, DirectMessageError, DynProtocolMessage, EchoBroadcast, EchoBroadcastError, NormalBroadcast,
    NormalBroadcastError, ProtocolMessagePart, ProtocolMessagePartHashable,
};
pub(crate) use rng::BoxedRng;
pub(crate) use round::NoType;
pub(crate) use round_info::DynRoundInfo;
pub(crate) use wire_format::BoxedFormat;
