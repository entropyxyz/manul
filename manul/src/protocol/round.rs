use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::{any::Any, fmt::Debug};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};

use super::{
    errors::{
        DeserializationError, DirectMessageError, EchoBroadcastError, FinalizeError, LocalError,
        MessageValidationError, ProtocolValidationError, ReceiveError,
    },
    object_safe::{ObjectSafeRound, ObjectSafeRoundWrapper},
};
use crate::session::SessionId;

/// Possible successful outcomes of [`Round::finalize`].
pub enum FinalizeOutcome<Id, P: Protocol> {
    /// Transition to a new round.
    AnotherRound(AnotherRound<Id, P>),
    /// The protocol reached a result.
    Result(P::Result),
}

impl<Id, P> FinalizeOutcome<Id, P>
where
    Id: 'static,
    P: 'static + Protocol,
{
    /// A helper method to create an [`AnotherRound`](`Self::AnotherRound`) variant.
    pub fn another_round(round: impl Round<Id, Protocol = P>) -> Self {
        Self::AnotherRound(AnotherRound::new(round))
    }
}

// We do not want to expose `ObjectSafeRound` to the user, so it is hidden in a struct.
/// A wrapped new round that may be returned by [`Round::finalize`].
pub struct AnotherRound<Id, P: Protocol>(Box<dyn ObjectSafeRound<Id, Protocol = P>>);

impl<Id, P> AnotherRound<Id, P>
where
    Id: 'static,
    P: 'static + Protocol,
{
    /// Wraps an object implementing [`Round`].
    pub fn new(round: impl Round<Id, Protocol = P>) -> Self {
        Self(Box::new(ObjectSafeRoundWrapper::new(round)))
    }

    /// Returns the inner boxed type.
    /// This is an internal method to be used in `Session`.
    pub(crate) fn into_boxed(self) -> Box<dyn ObjectSafeRound<Id, Protocol = P>> {
        self.0
    }

    /// Attempts to extract an object of a concrete type.
    pub fn downcast<T: Round<Id>>(self) -> Result<T, LocalError> {
        self.0.downcast::<T>()
    }

    /// Attempts to extract an object of a concrete type, preserving the original on failure.
    pub fn try_downcast<T: Round<Id>>(self) -> Result<T, Self> {
        self.0.try_downcast::<T>().map_err(Self)
    }
}

/// A round identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundId {
    round_num: u8,
    is_echo: bool,
}

impl RoundId {
    /// Creates a new round identifier.
    pub fn new(round_num: u8) -> Self {
        Self {
            round_num,
            is_echo: false,
        }
    }

    /// Returns the identifier of the echo round corresponding to the given non-echo round.
    ///
    /// Panics if `self` is already an echo round identifier.
    pub(crate) fn echo(&self) -> Self {
        // If this panic happens, there is something wrong with the internal logic
        // of managing echo-broadcast rounds.
        if self.is_echo {
            panic!("This is already an echo round ID");
        }
        Self {
            round_num: self.round_num,
            is_echo: true,
        }
    }

    /// Returns the identifier of the non-echo round corresponding to the given echo round.
    ///
    /// Panics if `self` is already a non-echo round identifier.
    pub(crate) fn non_echo(&self) -> Self {
        // If this panic happens, there is something wrong with the internal logic
        // of managing echo-broadcast rounds.
        if !self.is_echo {
            panic!("This is already an non-echo round ID");
        }
        Self {
            round_num: self.round_num,
            is_echo: false,
        }
    }
}

/// A distributed protocol.
pub trait Protocol: Debug + Sized {
    /// The successful result of an execution of this protocol.
    type Result;

    /// An object of this type will be returned when a provable error happens during [`Round::receive_message`].
    type ProtocolError: ProtocolError + Serialize + for<'de> Deserialize<'de>;

    /// An object of this type will be returned when an unattributable error happens during [`Round::finalize`].
    ///
    /// It proves that the node did its job correctly, to be adjudicated by a third party.
    type CorrectnessProof: Send + Serialize + for<'de> Deserialize<'de>;

    /// Serializes the given object into a bytestring.
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError>;

    /// Tries to deserialize the given bytestring as an object of type `T`.
    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, DeserializationError>;

    /// Returns `Ok(())` if the given direct message cannot be deserialized
    /// assuming it is a direct message from the round `round_id`.
    ///
    /// Normally one would use [`DirectMessage::verify_is_invalid`] when implementing this.
    fn verify_direct_message_is_invalid(
        round_id: RoundId,
        #[allow(unused_variables)] message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::InvalidEvidence(format!(
            "There are no direct messages in {round_id:?}"
        )))
    }

    /// Returns `Ok(())` if the given echo broadcast cannot be deserialized
    /// assuming it is an echo broadcast from the round `round_id`.
    ///
    /// Normally one would use [`EchoBroadcast::verify_is_invalid`] when implementing this.
    fn verify_echo_broadcast_is_invalid(
        round_id: RoundId,
        #[allow(unused_variables)] message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::InvalidEvidence(format!(
            "There are no echo broadcasts in {round_id:?}"
        )))
    }
}

/// Describes provable errors originating during protocol execution.
///
/// Provable here means that we can create an evidence object entirely of messages signed by some party,
/// which, in combination, prove the party's malicious actions.
pub trait ProtocolError: Debug + Clone + Send {
    /// The rounds direct messages from which are required to prove malicious behavior for this error.
    ///
    /// **Note:** Should not include the round where the error happened.
    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    /// The rounds echo broadcasts from which are required to prove malicious behavior for this error.
    ///
    /// **Note:** Should not include the round where the error happened.
    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    /// The rounds combined echos from which are required to prove malicious behavior for this error.
    ///
    /// **Note:** Should not include the round where the error happened.
    ///
    /// The combined echos are echo broadcasts sent by a party during the echo round,
    /// where it bundles all the received broadcasts and sends them back to everyone.
    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    /// Returns `Ok(())` if the attached messages indeed prove that a malicious action happened.
    ///
    /// The signatures and metadata of the messages will be checked by the calling code,
    /// the responsibility of this method is just to check the message contents.
    ///
    /// `echo_broadcast` and `direct_message` are the messages that triggered the error
    /// during [`Round::receive_message`].
    /// `echo_broadcasts` and `direct_messages` are messages from the previous rounds, as requested by
    /// [`required_direct_messages`](`Self::required_direct_messages`) and
    /// [`required_echo_broadcasts`](`Self::required_echo_broadcasts`).
    /// `combined_echos` are bundled echos from other parties from the previous rounds,
    /// as requested by [`required_combined_echos`](`Self::required_combined_echos`).
    fn verify_messages_constitute_error(
        &self,
        echo_broadcast: &Option<EchoBroadcast>,
        direct_message: &DirectMessage,
        echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        direct_messages: &BTreeMap<RoundId, DirectMessage>,
        combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError>;
}

/// A serialized direct message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage(#[serde(with = "SliceLike::<Base64>")] Box<[u8]>);

impl DirectMessage {
    /// Creates a new serialized direct message.
    pub fn new<P: Protocol, T: Serialize>(message: T) -> Result<Self, LocalError> {
        P::serialize(message).map(Self)
    }

    /// Returns `Ok(())` if the message cannot be deserialized into `T`.
    ///
    /// This is intended to be used in the implementations of [`Protocol::verify_direct_message_is_invalid`].
    pub fn verify_is_invalid<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<(), MessageValidationError> {
        if self.deserialize::<P, T>().is_err() {
            Ok(())
        } else {
            Err(MessageValidationError::InvalidEvidence(
                "Message deserialized successfully".into(),
            ))
        }
    }

    /// Deserializes the direct message.
    pub fn deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<T, DirectMessageError> {
        P::deserialize(&self.0).map_err(DirectMessageError::new)
    }
}

/// A serialized echo broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoBroadcast(#[serde(with = "SliceLike::<Base64>")] Box<[u8]>);

impl EchoBroadcast {
    /// Creates a new serialized echo broadcast.
    pub fn new<P: Protocol, T: Serialize>(message: T) -> Result<Self, LocalError> {
        P::serialize(message).map(Self)
    }

    /// Returns `Ok(())` if the message cannot be deserialized into `T`.
    ///
    /// This is intended to be used in the implementations of [`Protocol::verify_direct_message_is_invalid`].
    pub fn verify_is_invalid<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<(), MessageValidationError> {
        if self.deserialize::<P, T>().is_err() {
            Ok(())
        } else {
            Err(MessageValidationError::InvalidEvidence(
                "Message deserialized successfully".into(),
            ))
        }
    }

    /// Deserializes the echo broadcast.
    pub fn deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<T, EchoBroadcastError> {
        P::deserialize(&self.0).map_err(EchoBroadcastError::new)
    }
}

/// Message payload created in [`Round::receive_message`].
pub struct Payload(pub Box<dyn Any + Send + Sync>);

impl Payload {
    /// Creates a new payload.
    ///
    /// Would be normally called in [`Round::receive_message`].
    pub fn new<T: 'static + Send + Sync>(payload: T) -> Self {
        Self(Box::new(payload))
    }

    /// Creates an empty payload.
    ///
    /// Use it in [`Round::receive_message`] if it does not need to create artifacts.
    pub fn empty() -> Self {
        Self::new(())
    }

    /// Attempts to downcast back to the concrete type.
    ///
    /// Would be normally called in [`Round::finalize`].
    pub fn try_to_typed<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self
            .0
            .downcast::<T>()
            .map_err(|_| LocalError::new(format!("Failed to downcast into {}", core::any::type_name::<T>())))?))
    }
}

/// Associated data created alongside a message in [`Round::make_direct_message`].
pub struct Artifact(pub Box<dyn Any + Send + Sync>);

impl Artifact {
    /// Creates a new artifact.
    ///
    /// Would be normally called in [`Round::make_direct_message`].
    pub fn new<T: 'static + Send + Sync>(artifact: T) -> Self {
        Self(Box::new(artifact))
    }

    /// Creates an empty artifact.
    ///
    /// Use it in [`Round::make_direct_message`] if it does not need to create artifacts.
    pub fn empty() -> Self {
        Self::new(())
    }

    /// Attempts to downcast back to the concrete type.
    ///
    /// Would be normally called in [`Round::finalize`].
    pub fn try_to_typed<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self
            .0
            .downcast::<T>()
            .map_err(|_| LocalError::new(format!("Failed to downcast into {}", core::any::type_name::<T>())))?))
    }
}

/// A round that initiates a protocol.
///
/// This is a round that can be created directly;
/// all the others are only reachable throud [`Round::finalize`] by the execution layer.
pub trait FirstRound<Id: 'static>: Round<Id> + Sized {
    /// Additional inputs for the protocol (besides the mandatory ones in [`new`](`Self::new`)).
    type Inputs;

    /// Creates the round.
    ///
    /// `session_id` can be assumed to be the same for each node participating in a session.
    /// `id` is the ID of this node.
    fn new(
        rng: &mut impl CryptoRngCore,
        session_id: &SessionId,
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<Self, LocalError>;
}

/**
A type representing a single round of a protocol.

The way a round will be used by an external caller:
- create messages to send out (by calling [`make_direct_message`](`Self::make_direct_message`)
  and [`make_echo_broadcast`](`Self::make_echo_broadcast`));
- process received messages from other nodes (by calling [`receive_message`](`Self::receive_message`));
- attempt to finalize (by calling [`finalize`](`Self::finalize`)) to produce the next round, or return a result.
*/
pub trait Round<Id>: 'static + Send + Sync {
    /// The protocol this round is a part of.
    type Protocol: Protocol;

    /// The round ID.
    ///
    /// **Note:** these should not repeat during execution.
    fn id(&self) -> RoundId;

    /// The round IDs of the rounds this round can finalize into.
    ///
    /// Returns an empty set if this round only finalizes into a result.
    fn possible_next_rounds(&self) -> BTreeSet<RoundId>;

    /// The destinations of the messages to be sent out by this round.
    ///
    /// The way it is interpreted by the execution layer is
    /// - An echo broadcast (if any) is sent to all of these destinations;
    /// - A direct message is sent to each of these destinations,
    ///   which means [`make_direct_message`](`Self::make_direct_message`) may be called
    ///   for each element of the returned set.
    fn message_destinations(&self) -> &BTreeSet<Id>;

    /// Returns the direct message to the given destination and an accompanying artifact.
    ///
    /// In some protocols, when a message to another node is created, there is some associated information
    /// that needs to be retained for later (randomness, proofs of knowledge, and so on).
    /// These should be put in an [`Artifact`] and will be available at the time of [`finalize`](`Self::finalize`).
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError>;

    /// Returns the echo broadcast for this round, or `None` if the round does not require echo-broadcasting.
    ///
    /// Returns `None` if not implemented.
    ///
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast.
    /// This also means that a message with the broadcasts from all nodes signed by each node is available
    /// if an evidence of malicious behavior has to be constructed.
    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
    ) -> Option<Result<EchoBroadcast, LocalError>> {
        None
    }

    /// Processes the received message and generates the payload that will be used in [`finalize`](`Self::finalize`).
    ///
    /// Note that there is no need to authenticate the message at this point;
    /// it has already been done by the execution layer.
    fn receive_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &Id,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`),
    /// and `artifacts` are the ones previously generated by [`make_direct_message`](`Self::make_direct_message`).
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>>;

    /// Returns the set of node IDs from which this round expects messages.
    ///
    /// The execution layer will not call [`finalize`](`Self::finalize`) until all these nodes have responded
    /// (and the corresponding [`receive_message`](`Self::receive_message`) finished successfully).
    fn expecting_messages_from(&self) -> &BTreeSet<Id>;

    /// A convenience method to create an [`EchoBroadcast`] object
    /// to return in [`make_echo_broadcast`](`Self::make_echo_broadcast`).
    fn serialize_echo_broadcast(message: impl Serialize) -> Result<EchoBroadcast, LocalError> {
        EchoBroadcast::new::<Self::Protocol, _>(message)
    }

    /// A convenience method to create a [`DirectMessage`] object
    /// to return in [`make_direct_message`](`Self::make_direct_message`).
    fn serialize_direct_message(message: impl Serialize) -> Result<DirectMessage, LocalError> {
        DirectMessage::new::<Self::Protocol, _>(message)
    }
}
