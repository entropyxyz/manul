#![allow(dead_code, unused_variables, missing_docs)]

use alloc::{boxed::Box, collections::BTreeMap};
use core::{any::TypeId, fmt::Debug, marker::PhantomData};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    boxed_format::BoxedFormat,
    errors::{LocalError, ProtocolValidationError, ReceiveError},
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage, ProtocolMessagePart},
    round::{
        Artifact, CommunicationInfo, DynTypeId, FinalizeOutcome, PartyId, Payload, Protocol, ProtocolError,
        RequiredMessages, Round,
    },
    round_id::{RoundId, TransitionInfo},
};

// PhantomData is here to make it un-constructable by an external user.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NoMessage(PhantomData<()>);

impl NoMessage {
    pub(crate) fn equals<T: 'static>() -> bool {
        TypeId::of::<T>() == TypeId::of::<NoMessage>()
    }

    fn new_if_equals<T: 'static>() -> Option<T> {
        if Self::equals::<T>() {
            let boxed = Box::new(NoMessage(PhantomData));
            // SAFETY: can cast since we checked that T == NoMessage
            let boxed_downcast = unsafe { Box::<T>::from_raw(Box::into_raw(boxed) as *mut T) };
            Some(*boxed_downcast)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct StaticProtocolMessage<Id, R: StaticRound<Id> + ?Sized> {
    pub direct_message: R::DirectMessage,
    pub echo_broadcast: R::EchoBroadcast,
    pub normal_broadcast: R::NormalBroadcast,
}

pub trait StaticRound<Id>: 'static + Debug + Send + Sync + DynTypeId {
    /// The protocol this round is a part of.
    type Protocol: Protocol<Id>;

    type ProvableError: ProvableError<Id, Round = Self>;

    /// Returns the information about the position of this round in the state transition graph.
    ///
    /// See [`TransitionInfo`] documentation for more details.
    fn transition_info(&self) -> TransitionInfo;

    /// Returns the information about the communication this rounds engages in with other nodes.
    ///
    /// See [`CommunicationInfo`] documentation for more details.
    fn communication_info(&self) -> CommunicationInfo<Id>;

    type DirectMessage: 'static + Serialize + for<'de> Deserialize<'de>;
    type NormalBroadcast: 'static + Serialize + for<'de> Deserialize<'de>;
    type EchoBroadcast: 'static + Serialize + for<'de> Deserialize<'de>;

    type Payload: Send + Sync;
    type Artifact: Send + Sync;

    fn expects_direct_message(
        round_id: &RoundId,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> bool {
        true
    }

    fn expects_normal_broadcast(
        round_id: &RoundId,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> bool {
        true
    }

    fn expects_echo_broadcast(
        round_id: &RoundId,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> bool {
        true
    }

    /// Returns the direct message to the given destination and (maybe) an accompanying artifact.
    ///
    /// Return [`DirectMessage::none`] if this round does not send direct messages.
    ///
    /// In some protocols, when a message to another node is created, there is some associated information
    /// that needs to be retained for later (randomness, proofs of knowledge, and so on).
    /// These should be put in an [`Artifact`] and will be available at the time of [`finalize`](`Self::finalize`).
    #[allow(clippy::type_complexity)]
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] destination: &Id,
    ) -> Result<Option<(Self::DirectMessage, Self::Artifact)>, LocalError> {
        Ok(None)
    }

    /// Returns the echo broadcast for this round.
    ///
    /// Return [`EchoBroadcast::none`] if this round does not send echo-broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast. This
    /// also means that a message containing the broadcasts from all nodes and signed by each node is available. This is
    /// used as part of the evidence of malicious behavior when producing provable offence reports.
    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Self::EchoBroadcast>, LocalError> {
        Ok(None)
    }

    /// Returns the normal broadcast for this round.
    ///
    /// Return [`NormalBroadcast::none`] if this round does not send normal broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// Unlike echo broadcasts, normal broadcasts are "send and forget" and delivered to every node defined in
    /// [`Self::communication_info`] without any confirmation required by the receiving node.
    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Self::NormalBroadcast>, LocalError> {
        Ok(None)
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
        message: StaticProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self::Protocol>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`), and
    /// `artifacts` are the ones previously generated by [`make_direct_message`](`Self::make_direct_message`).
    fn finalize(
        self,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError>;
}

pub(crate) struct StaticRoundAdapter<R> {
    round: R,
}

impl<R> StaticRoundAdapter<R> {
    pub fn new(round: R) -> Self {
        Self { round }
    }

    pub fn as_inner(&self) -> &R {
        &self.round
    }

    pub fn into_inner(self) -> R {
        self.round
    }
}

impl<R> Debug for StaticRoundAdapter<R> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}

impl<Id, R> Round<Id> for StaticRoundAdapter<R>
where
    Id: PartyId,
    R: StaticRound<Id>,
{
    type Protocol = <R as StaticRound<Id>>::Protocol;

    fn transition_info(&self) -> TransitionInfo {
        self.round.transition_info()
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        self.round.communication_info()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        if let Some((direct_message, artifact)) = self.round.make_direct_message(rng, destination)? {
            Ok((
                DirectMessage::new(format, direct_message)?,
                Some(Artifact::new(artifact)),
            ))
        } else {
            Ok((DirectMessage::none(), None))
        }
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        let echo_broadcast = self.round.make_echo_broadcast(rng)?;
        if let Some(echo_broadcast) = echo_broadcast {
            EchoBroadcast::new(format, echo_broadcast)
        } else {
            Ok(EchoBroadcast::none())
        }
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        let normal_broadcast = self.round.make_normal_broadcast(rng)?;
        if let Some(normal_broadcast) = normal_broadcast {
            NormalBroadcast::new(format, normal_broadcast)
        } else {
            Ok(NormalBroadcast::none())
        }
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, <Self as Round<Id>>::Protocol>> {
        let direct_message = if NoMessage::equals::<R::DirectMessage>() {
            message.direct_message.assert_is_none()?;
            // TODO: `expect()` can be eliminated here
            NoMessage::new_if_equals::<R::DirectMessage>().expect("DirectMessage is NoMessage")
        } else {
            message.direct_message.deserialize::<R::DirectMessage>(format)?
        };

        let echo_broadcast = if NoMessage::equals::<R::EchoBroadcast>() {
            message.echo_broadcast.assert_is_none()?;
            NoMessage::new_if_equals::<R::EchoBroadcast>().expect("EchoBroadcast is NoMessage")
        } else {
            message.echo_broadcast.deserialize::<R::EchoBroadcast>(format)?
        };

        let normal_broadcast = if NoMessage::equals::<R::NormalBroadcast>() {
            message.normal_broadcast.assert_is_none()?;
            // this is infallible
            NoMessage::new_if_equals::<R::NormalBroadcast>().expect("NormalBroadcast is NoMessage")
        } else {
            message.normal_broadcast.deserialize::<R::NormalBroadcast>(format)?
        };

        let payload = self.round.receive_message(
            from,
            StaticProtocolMessage {
                direct_message,
                echo_broadcast,
                normal_broadcast,
            },
        )?;

        Ok(Payload::new(payload))
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, <Self as Round<Id>>::Protocol>, LocalError> {
        let payloads = payloads
            .into_iter()
            .map(|(id, payload)| payload.downcast::<R::Payload>().map(|payload| (id, payload)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let artifacts = artifacts
            .into_iter()
            .map(|(id, artifact)| artifact.downcast::<R::Artifact>().map(|artifact| (id, artifact)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        self.round.finalize(rng, payloads, artifacts)
    }
}

/// Describes provable errors originating during protocol execution.
///
/// Provable here means that we can create an evidence object entirely of messages signed by some party,
/// which, in combination, prove the party's malicious actions.
pub trait ProvableError<Id>: Debug + Clone + Serialize + for<'de> Deserialize<'de> {
    type Round: StaticRound<Id>;

    /// Specifies the messages of the guilty party that need to be stored as the evidence
    /// to prove its malicious behavior.
    fn required_previous_messages(&self) -> RequiredMessages;

    /// Returns `Ok(())` if the attached messages indeed prove that a malicious action happened.
    ///
    /// The signatures and metadata of the messages will be checked by the calling code,
    /// the responsibility of this method is just to check the message contents.
    ///
    /// `message` contain the message parts that triggered the error
    /// during [`Round::receive_message`].
    ///
    /// `previous_messages` are message parts from the previous rounds, as requested by
    /// [`required_messages`](Self::required_messages).
    ///
    /// Note that if some message part was not requested by above methods, it will be set to an empty one
    /// in the [`ProtocolMessage`], even if it was present originally.
    ///
    /// `combined_echos` are bundled echos from other parties from the previous rounds,
    /// as requested by [`required_messages`](Self::required_messages).
    fn verify_evidence(
        &self,
        from: &Id,
        shared_randomness: &[u8],
        shared_data: &<<Self::Round as StaticRound<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<Id, Self::Round>,
    ) -> Result<(), ProtocolValidationError>;
}

#[derive(Debug)]
pub struct EvidenceMessages<Id, R: StaticRound<Id>> {
    message: ProtocolMessage,
    previous_messages: BTreeMap<RoundId, ProtocolMessage>,
    combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    format: BoxedFormat,
    phantom: PhantomData<R>,
}

impl<Id, R: StaticRound<Id>> EvidenceMessages<Id, R> {
    pub fn previous_echo_broadcast<PR: StaticRound<Id>>(
        &self,
        round_num: u8,
    ) -> Result<PR::EchoBroadcast, ProtocolValidationError> {
        Ok(self
            .previous_messages
            .get(&RoundId::new(round_num))
            .unwrap()
            .echo_broadcast
            .deserialize::<PR::EchoBroadcast>(&self.format)
            .unwrap())
    }

    pub fn combined_echos<PR: StaticRound<Id>>(
        &self,
        round_num: u8,
    ) -> Result<BTreeMap<Id, PR::EchoBroadcast>, ProtocolValidationError> {
        todo!()
    }

    pub fn direct_message(&self) -> Result<R::DirectMessage, ProtocolValidationError> {
        todo!()
    }

    pub(crate) fn into_round<NR>(self) -> EvidenceMessages<Id, NR>
    where
        NR: StaticRound<
            Id,
            EchoBroadcast = R::EchoBroadcast,
            NormalBroadcast = R::NormalBroadcast,
            DirectMessage = R::DirectMessage,
        >,
    {
        EvidenceMessages::<Id, NR> {
            message: self.message,
            previous_messages: self.previous_messages,
            combined_echos: self.combined_echos,
            format: self.format,
            phantom: PhantomData,
        }
    }
}

#[derive_where::derive_where(Clone)]
#[derive(Debug, Copy, Serialize, Deserialize)]
pub struct NoProvableErrors<R>(PhantomData<R>);

impl<Id: PartyId, R: StaticRound<Id>> ProvableError<Id> for NoProvableErrors<R> {
    type Round = R;
    fn required_previous_messages(&self) -> RequiredMessages {
        unimplemented!()
    }
    fn verify_evidence(
        &self,
        from: &Id,
        shared_randomness: &[u8],
        shared_data: &<<Self::Round as StaticRound<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<Id, Self::Round>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
}
