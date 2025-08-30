use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
};
use core::{any::TypeId, fmt::Debug, marker::PhantomData};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    dyn_round::BoxedRound,
    errors::{LocalError, ReceiveError},
    evidence::ProtocolError,
    round_id::{RoundId, TransitionInfo},
    round_info::RoundInfo,
};

pub(crate) trait NoType: 'static + Sized {
    fn new() -> Self;

    fn equals<T: 'static>() -> bool {
        TypeId::of::<T>() == TypeId::of::<Self>()
    }

    fn new_if_equals<T: 'static>() -> Option<T> {
        if Self::equals::<T>() {
            let boxed = Box::new(Self::new());
            // SAFETY: can cast since we checked that T == NoMessage
            let boxed_downcast = unsafe { Box::<T>::from_raw(Box::into_raw(boxed) as *mut T) };
            Some(*boxed_downcast)
        } else {
            None
        }
    }
}

/// A placeholder type for [`Round::DirectMessage`], [`Round::NormalBroadcast`], and [`Round::EchoBroadcast`]
/// indicating that the round does not send corresponding message parts.
// `PhantomData` is here to make it un-constructable by an external user.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NoMessage(PhantomData<()>);

impl NoType for NoMessage {
    fn new() -> Self {
        Self(PhantomData)
    }
}

/// A placeholder type for [`Round::DirectMessage`], [`Round::NormalBroadcast`], and [`Round::EchoBroadcast`]
/// indicating that the round does not send corresponding message parts.
// `PhantomData` is here to make it un-constructable by an external user.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NoArtifact(PhantomData<()>);

impl NoType for NoArtifact {
    fn new() -> Self {
        Self(PhantomData)
    }
}

/// A structure encapsulating different parts of a message from a single node.
#[derive(Debug)]
pub struct ProtocolMessage<Id, R: Round<Id> + ?Sized> {
    /// The part of the message specific for each destination.
    pub direct_message: R::DirectMessage,
    /// The part of the message that will be additionally echo-broadcasted to ensure every receiver
    /// gets the same data.
    pub echo_broadcast: R::EchoBroadcast,
    /// The part of the message that will be sent to all destinations.
    pub normal_broadcast: R::NormalBroadcast,
}

/// A type representing a single round of a protocol.
///
/// The way a round will be used by an external caller:
/// - create messages to send out (by calling [`make_direct_message`](`Self::make_direct_message`),
///   [`make_normal_broadcast`](`Self::make_normal_broadcast`),
///   and [`make_echo_broadcast`](`Self::make_echo_broadcast`));
/// - process received messages from other nodes (by calling [`receive_message`](`Self::receive_message`));
/// - attempt to finalize (by calling [`finalize`](`Self::finalize`)) to produce the next round, or return a result.
pub trait Round<Id>: 'static + Debug + Send + Sync {
    /// The protocol this round is a part of.
    type Protocol: Protocol<Id>;

    /// The provable error type that can be returned on receiving a message.
    ///
    /// If this round does not generate errors, [`NoProtocolErrors`](`crate::protocol::NoProtocolErrors`)
    /// can be used here.
    type ProtocolError: ProtocolError<Id, Round = Self>;

    /// Returns the information about the position of this round in the state transition graph.
    ///
    /// See [`TransitionInfo`] documentation for more details.
    fn transition_info(&self) -> TransitionInfo;

    /// Returns the information about the communication this rounds engages in with other nodes.
    ///
    /// See [`CommunicationInfo`] documentation for more details.
    fn communication_info(&self) -> CommunicationInfo<Id>;

    /// The part of the message specific for each destination.
    ///
    /// Set to [`NoMessage`] if the round does not use this part of the message.
    type DirectMessage: 'static + Serialize + for<'de> Deserialize<'de>;

    /// The part of the message that will be sent to all destinations.
    ///
    /// Set to [`NoMessage`] if the round does not use this part of the message.
    type NormalBroadcast: 'static + Serialize + for<'de> Deserialize<'de>;

    /// The part of the message that will be additionally echo-broadcasted to ensure every receiver
    /// gets the same data.
    ///
    /// Set to [`NoMessage`] if the round does not use this part of the message.
    type EchoBroadcast: 'static + Serialize + for<'de> Deserialize<'de>;

    /// Message payload created in [`Self::receive_message`].
    ///
    /// [`Self::Payload`]s are created as the output of processing an incoming message.
    /// When a [`Round`] finalizes, all the `Payload`s received during the round are made available
    /// and can be used to decide what to do next (next round? return a final result?).
    /// Payloads are not sent to other nodes.
    type Payload: Send + Sync;

    /// Associated data created alongside a message in [`Self::make_direct_message`].
    ///
    /// [`Self::Artifact`]s are local to the participant that created it and are usually containers
    /// for intermediary secrets and/or dynamic parameters needed in subsequent stages of the protocol.
    /// Artifacts are never sent over the wire; they are made available to [`Self::finalize`]
    /// for the participant, delivered in the form of a `BTreeMap`
    /// where the key is the destination id of the participant to whom the direct message was sent.
    ///
    /// Set to [`NoArtifact`] if [`Self::DirectMessage`] is [`NoMessage`].
    type Artifact: 'static + Send + Sync;

    /// Returns the direct message to the given destination and (maybe) an accompanying artifact.
    ///
    /// In some protocols, when a message to another node is created, there is some associated information
    /// that needs to be retained for later (randomness, proofs of knowledge, and so on).
    /// These should be put in an [`Self::Artifact`] and will be available
    /// at the time of [`finalize`](`Self::finalize`).
    ///
    /// If this method is not implemented, [`Self::DirectMessage`] must be set to [`NoMessage`],
    /// and [`Self::Artifact`] to [`NoArtifact`].
    #[allow(clippy::type_complexity)]
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
        #[allow(unused_variables)] destination: &Id,
    ) -> Result<(Self::DirectMessage, Self::Artifact), LocalError> {
        if let Some(message) = NoMessage::new_if_equals::<Self::DirectMessage>() {
            match NoArtifact::new_if_equals::<Self::Artifact>() {
                Some(artifact) => Ok((message, artifact)),
                None => Err(LocalError::new(
                    "If `DirectMessage` is `NoMessage`, `Artifact` must be `NoArtifact`",
                )),
            }
        } else if self.communication_info().message_destinations.is_empty() {
            // TODO (#4): this branch could potentially be eliminated
            Err(LocalError::new(
                "`make_direct_message() called when the round does not send messages - internal error",
            ))
        } else {
            Err(LocalError::new(concat!(
                "If `DirectMessage` is not `NoMessage`, and the round sends messages, ",
                "`make_direct_message()` must be implemented"
            )))
        }
    }

    /// Returns the echo broadcast for this round.
    ///
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast. This
    /// also means that a message containing the broadcasts from all nodes and signed by each node is available. This is
    /// used as part of the evidence of malicious behavior when producing provable offence reports.
    ///
    /// If this method is not implemented, [`Self::EchoBroadcast`] must be set to [`NoMessage`].
    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
    ) -> Result<Self::EchoBroadcast, LocalError> {
        if let Some(message) = NoMessage::new_if_equals::<Self::EchoBroadcast>() {
            Ok(message)
        } else if self.communication_info().message_destinations.is_empty() {
            // TODO (#4): this branch could potentially be eliminated
            Err(LocalError::new(
                "`make_echo_broadcast() called when the round does not send messages - internal error",
            ))
        } else {
            Err(LocalError::new(concat!(
                "If `EchoBroadcast` is not `NoMessage`, and the round sends messages, ",
                "`make_echo_broadcast()` must be implemented"
            )))
        }
    }

    /// Returns the normal broadcast for this round.
    ///
    /// Unlike echo broadcasts, normal broadcasts are "send and forget" and delivered to every node defined in
    /// [`Self::communication_info`] without any confirmation required by the receiving node.
    ///
    /// If this method is not implemented, [`Self::NormalBroadcast`] must be set to [`NoMessage`].
    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
    ) -> Result<Self::NormalBroadcast, LocalError> {
        if let Some(message) = NoMessage::new_if_equals::<Self::NormalBroadcast>() {
            Ok(message)
        } else if self.communication_info().message_destinations.is_empty() {
            // TODO (#4): this branch could potentially be eliminated
            Err(LocalError::new(
                "`make_normal_broadcast() called when the round does not send messages - internal error",
            ))
        } else {
            Err(LocalError::new(concat!(
                "If `NormalBroadcast` is not `NoMessage`, and the round sends messages, ",
                "`make_normal_broadcast()` must be implemented"
            )))
        }
    }

    /// Processes a received message and generates the payload that will be used in [`finalize`](`Self::finalize`). The
    /// message content can be arbitrarily checked and processed to build the exact payload needed to finalize the
    /// round.
    ///
    /// Note that there is no need to authenticate the message at this point;
    /// it has already been done by the execution layer.
    fn receive_message(
        &self,
        from: &Id,
        message_parts: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`), and
    /// `artifacts` are the ones previously generated by [`make_direct_message`](`Self::make_direct_message`).
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError>;
}

/// Describes what other parties this rounds sends messages to, and what other parties it expects messages from.
#[derive(Debug, Clone)]
pub struct CommunicationInfo<Id> {
    /// The destinations of the messages to be sent out by this round.
    ///
    /// The way it is interpreted by the execution layer is
    /// - An echo broadcast (if any) is sent to all of these destinations;
    /// - A direct message is sent to each of these destinations,
    ///   which means [`make_direct_message`](`Round::make_direct_message`) may be called
    ///   for each element of the returned set.
    pub message_destinations: BTreeSet<Id>,

    /// Returns the set of node IDs from which this round expects messages.
    ///
    /// The execution layer will not call [`finalize`](`Round::finalize`) until all these nodes have responded
    /// (and the corresponding [`receive_message`](`Round::receive_message`) finished successfully).
    pub expecting_messages_from: BTreeSet<Id>,

    /// Returns the specific way the node participates in the echo round following this round.
    ///
    /// Returns [`EchoRoundParticipation::Default`] by default; this works fine when every node
    /// sends messages to every other one, or do not send or receive any echo broadcasts.
    /// Otherwise, review the options in [`EchoRoundParticipation`] and pick the appropriate one.
    pub echo_round_participation: EchoRoundParticipation<Id>,
}

impl<Id> CommunicationInfo<Id>
where
    Id: PartyId,
{
    /// A regular round that sends messages to all `other_parties`, and expects messages back from them.
    pub fn regular(other_parties: &BTreeSet<Id>) -> Self {
        Self {
            message_destinations: other_parties.clone(),
            expecting_messages_from: other_parties.clone(),
            echo_round_participation: EchoRoundParticipation::Default,
        }
    }
}

/// Possible successful outcomes of [`Round::finalize`].
#[derive(Debug)]
pub enum FinalizeOutcome<Id, P: Protocol<Id>> {
    /// Transition to a new round.
    AnotherRound(BoxedRound<Id, P>),
    /// The protocol reached a result.
    Result(P::Result),
}

/// A distributed protocol.
pub trait Protocol<Id>: 'static {
    /// The successful result of an execution of this protocol.
    type Result: Debug;

    /// The subset of public data shared between all participating nodes before the beginning of the protocol
    /// (excluding the session ID) that is necessary for evidence verification.
    type SharedData: Debug;

    /// Returns the round metadata for each round mapped to round IDs.
    fn round_info(round_id: &RoundId) -> Option<RoundInfo<Id, Self>>;
}

/// A round that initiates a protocol and defines how execution begins. It is the only round that can be created outside
/// the protocol flow.
///
/// The `EntryPoint` can carry data, e.g. configuration or external initialization data. All the
/// other rounds are only reachable by the execution layer through [`Round::finalize`].
pub trait EntryPoint<Id: PartyId> {
    /// The protocol implemented by the round this entry points returns.
    type Protocol: Protocol<Id>;

    /// Returns the ID of the round returned by [`Self::make_round`].
    fn entry_round_id() -> RoundId;

    /// Creates the starting round.
    ///
    /// `shared_randomness` can be assumed to be the same for each node participating in a session and can be thought of
    /// as a "session id" bytestring.
    /// `id` is the ID of this node.
    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError>;
}

/// A trait alias for the combination of traits needed for a party identifier.
pub trait PartyId: 'static + Debug + Clone + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

impl<T> PartyId for T where T: 'static + Debug + Clone + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

/// The specific way the node participates in the echo round (if any).
#[derive(Debug, Clone)]
pub enum EchoRoundParticipation<Id> {
    /// The default behavior: sends broadcasts and receives echoed messages, or does neither.
    ///
    /// That is, this node will be a part of the echo round if [`Round::make_echo_broadcast`] generates a message.
    Default,

    /// This node sends broadcasts that will be echoed, but does not receive any.
    Send,

    /// This node receives broadcasts that it needs to echo, but does not send any itself.
    Receive {
        /// The other participants of the echo round
        /// (that is, the nodes to which echoed messages will be sent).
        echo_targets: BTreeSet<Id>,
    },
}
