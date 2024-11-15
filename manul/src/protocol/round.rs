use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::{
    any::Any,
    fmt::{self, Debug, Display},
};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tinyvec::TinyVec;

use super::{
    errors::{FinalizeError, LocalError, MessageValidationError, ProtocolValidationError, ReceiveError},
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePart},
    object_safe::BoxedRound,
    serialization::{Deserializer, Serializer},
};

/// Possible successful outcomes of [`Round::finalize`].
#[derive(Debug)]
pub enum FinalizeOutcome<Id: PartyId, P: Protocol> {
    /// Transition to a new round.
    AnotherRound(BoxedRound<Id, P>),
    /// The protocol reached a result.
    Result(P::Result),
}

/// A round identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundId {
    round_nums: TinyVec<[u8; 4]>,
    is_echo: bool,
}

impl Display for RoundId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Round ")?;
        for (i, round_num) in self.round_nums.iter().enumerate().rev() {
            write!(f, "{}", round_num)?;
            if i != 0 {
                write!(f, "-")?;
            }
        }
        if self.is_echo {
            write!(f, " (echo)")?;
        }
        Ok(())
    }
}

impl RoundId {
    /// Creates a new round identifier.
    pub fn new(round_num: u8) -> Self {
        let mut round_nums = TinyVec::new();
        round_nums.push(round_num);
        Self {
            round_nums,
            is_echo: false,
        }
    }

    /// Prefixes this round ID (possibly already nested) with a group number.
    pub(crate) fn group_under(&self, round_num: u8) -> Self {
        let mut round_nums = self.round_nums.clone();
        round_nums.push(round_num);
        Self {
            round_nums,
            is_echo: self.is_echo,
        }
    }

    /// Removes the top group prefix from this round ID.
    ///
    /// Returns the `Err` variant if the round ID is not nested.
    pub(crate) fn ungroup(&self) -> Result<Self, LocalError> {
        if self.round_nums.len() == 1 {
            Err(LocalError::new("This round ID is not in a group"))
        } else {
            let mut round_nums = self.round_nums.clone();
            round_nums.pop().expect("vector size greater than 1");
            Ok(Self {
                round_nums,
                is_echo: self.is_echo,
            })
        }
    }

    /// Returns `true` if this is an ID of an echo broadcast round.
    pub(crate) fn is_echo(&self) -> bool {
        self.is_echo
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
            round_nums: self.round_nums.clone(),
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
            round_nums: self.round_nums.clone(),
            is_echo: false,
        }
    }
}

/// A distributed protocol.
pub trait Protocol: 'static {
    /// The successful result of an execution of this protocol.
    type Result: Debug;

    /// An object of this type will be returned when a provable error happens during [`Round::receive_message`].
    type ProtocolError: ProtocolError;

    /// An object of this type will be returned when an unattributable error happens during [`Round::finalize`].
    ///
    /// It proves that the node did its job correctly, to be adjudicated by a third party.
    type CorrectnessProof: CorrectnessProof;

    /// Returns `Ok(())` if the given direct message cannot be deserialized
    /// assuming it is a direct message from the round `round_id`.
    ///
    /// Normally one would use [`DirectMessage::verify_is_not`] when implementing this.
    fn verify_direct_message_is_invalid(
        #[allow(unused_variables)] deserializer: &Deserializer,
        round_id: RoundId,
        #[allow(unused_variables)] message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::InvalidEvidence(format!(
            "Invalid round number: {round_id:?}"
        )))
    }

    /// Returns `Ok(())` if the given echo broadcast cannot be deserialized
    /// assuming it is an echo broadcast from the round `round_id`.
    ///
    /// Normally one would use [`EchoBroadcast::verify_is_not`] when implementing this.
    fn verify_echo_broadcast_is_invalid(
        #[allow(unused_variables)] deserializer: &Deserializer,
        round_id: RoundId,
        #[allow(unused_variables)] message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::InvalidEvidence(format!(
            "Invalid round number: {round_id:?}"
        )))
    }

    /// Returns `Ok(())` if the given echo broadcast cannot be deserialized
    /// assuming it is an echo broadcast from the round `round_id`.
    ///
    /// Normally one would use [`EchoBroadcast::verify_is_not`] when implementing this.
    fn verify_normal_broadcast_is_invalid(
        #[allow(unused_variables)] deserializer: &Deserializer,
        round_id: RoundId,
        #[allow(unused_variables)] message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::InvalidEvidence(format!(
            "Invalid round number: {round_id:?}"
        )))
    }
}

/// Describes provable errors originating during protocol execution.
///
/// Provable here means that we can create an evidence object entirely of messages signed by some party,
/// which, in combination, prove the party's malicious actions.
pub trait ProtocolError: Debug + Clone + Send + Serialize + for<'de> Deserialize<'de> {
    /// A description of the error that will be included in the generated evidence.
    ///
    /// Make it short and informative.
    fn description(&self) -> String;

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

    /// The rounds normal broadcasts from which are required to prove malicious behavior for this error.
    ///
    /// **Note:** Should not include the round where the error happened.
    fn required_normal_broadcasts(&self) -> BTreeSet<RoundId> {
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
    #[allow(clippy::too_many_arguments)]
    fn verify_messages_constitute_error(
        &self,
        deserializer: &Deserializer,
        echo_broadcast: &EchoBroadcast,
        normal_broadcast: &NormalBroadcast,
        direct_message: &DirectMessage,
        echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        direct_messages: &BTreeMap<RoundId, DirectMessage>,
        combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError>;
}

// A convenience implementation for protocols that don't define any errors.
// Have to do it for `()`, since `!` is unstable.
impl ProtocolError for () {
    fn description(&self) -> String {
        panic!("Attempt to use an empty error type in an evidence. This is a bug in the protocol implementation.")
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _echo_broadcast: &EchoBroadcast,
        _normal_broadcast: &NormalBroadcast,
        _direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        panic!("Attempt to use an empty error type in an evidence. This is a bug in the protocol implementation.")
    }
}

/// Describes unattributable errors originating during protocol execution.
///
/// In the situations where no specific message can be blamed for an error,
/// each node must generate a correctness proof proving that they performed their duties correctly,
/// and the collection of proofs is verified by a third party.
/// One of the proofs will necessarily be missing or invalid.
pub trait CorrectnessProof: Debug + Clone + Send + Serialize + for<'de> Deserialize<'de> {}

// A convenience implementation for protocols that don't define any errors.
// Have to do it for `()`, since `!` is unstable.
impl CorrectnessProof for () {}

/// Message payload created in [`Round::receive_message`].
#[derive(Debug)]
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
#[derive(Debug)]
pub struct Artifact(pub Box<dyn Any + Send + Sync>);

impl Artifact {
    /// Creates a new artifact.
    ///
    /// Would be normally called in [`Round::make_direct_message`].
    pub fn new<T: 'static + Send + Sync>(artifact: T) -> Self {
        Self(Box::new(artifact))
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
pub trait EntryPoint<Id: PartyId> {
    /// Additional inputs for the protocol (besides the mandatory ones in [`new`](`Self::new`)).
    type Inputs;

    /// The protocol implemented by the round this entry points returns.
    type Protocol: Protocol;

    /// Returns the ID of the round returned by [`Self::new`].
    fn entry_round() -> RoundId {
        RoundId::new(1)
    }

    /// Creates the round.
    ///
    /// `session_id` can be assumed to be the same for each node participating in a session.
    /// `id` is the ID of this node.
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError>;
}

/// A trait alias for the combination of traits needed for a party identifier.
pub trait PartyId: 'static + Debug + Clone + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

impl<T> PartyId for T where T: 'static + Debug + Clone + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

/**
A type representing a single round of a protocol.

The way a round will be used by an external caller:
- create messages to send out (by calling [`make_direct_message`](`Self::make_direct_message`)
  and [`make_echo_broadcast`](`Self::make_echo_broadcast`));
- process received messages from other nodes (by calling [`receive_message`](`Self::receive_message`));
- attempt to finalize (by calling [`finalize`](`Self::finalize`)) to produce the next round, or return a result.
*/
pub trait Round<Id: PartyId>: 'static + Debug + Send + Sync {
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

    /// Returns the direct message to the given destination and (maybe) an accompanying artifact.
    ///
    /// Return [`DirectMessage::none`] if this round does not send direct messages.
    ///
    /// In some protocols, when a message to another node is created, there is some associated information
    /// that needs to be retained for later (randomness, proofs of knowledge, and so on).
    /// These should be put in an [`Artifact`] and will be available at the time of [`finalize`](`Self::finalize`).
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
        #[allow(unused_variables)] serializer: &Serializer,
        #[allow(unused_variables)] destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        Ok((DirectMessage::none(), None))
    }

    /// Returns the echo broadcast for this round.
    ///
    /// Return [`EchoBroadcast::none`] if this round does not send echo-broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast.
    /// This also means that a message with the broadcasts from all nodes signed by each node is available
    /// if an evidence of malicious behavior has to be constructed.
    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
        #[allow(unused_variables)] serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        Ok(EchoBroadcast::none())
    }

    /// Returns the normal broadcast for this round.
    ///
    /// Return [`NormalBroadcast::none`] if this round does not send normal broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// Unlike the echo broadcasts, these will be just sent to every node from [`Self::message_destinations`]
    /// without any confirmation required.
    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
        #[allow(unused_variables)] serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        Ok(NormalBroadcast::none())
    }

    /// Processes the received message and generates the payload that will be used in [`finalize`](`Self::finalize`).
    ///
    /// Note that there is no need to authenticate the message at this point;
    /// it has already been done by the execution layer.
    fn receive_message(
        &self,
        rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`),
    /// and `artifacts` are the ones previously generated by
    /// [`make_direct_message`](`Self::make_direct_message`).
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
}
