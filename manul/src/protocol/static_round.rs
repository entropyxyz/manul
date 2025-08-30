#![allow(dead_code, unused_variables, missing_docs)]

use alloc::{boxed::Box, collections::BTreeMap};
use core::{any::TypeId, fmt::Debug, marker::PhantomData};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    boxed_format::BoxedFormat,
    errors::{LocalError, ReceiveError},
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage, ProtocolMessagePart},
    round::{Artifact, CommunicationInfo, DynTypeId, FinalizeOutcome, PartyId, Payload, Protocol, Round},
    round_id::TransitionInfo,
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
pub struct StaticProtocolMessage<Id: PartyId, R: StaticRound<Id> + ?Sized> {
    pub direct_message: R::DirectMessage,
    pub echo_broadcast: R::EchoBroadcast,
    pub normal_broadcast: R::NormalBroadcast,
}

pub trait StaticRound<Id: PartyId>: 'static + Debug + Send + Sync + DynTypeId {
    /// The protocol this round is a part of.
    type Protocol: Protocol<Id>;

    /// Returns the information about the position of this round in the state transition graph.
    ///
    /// See [`TransitionInfo`] documentation for more details.
    fn transition_info(&self) -> TransitionInfo;

    /// Returns the information about the communication this rounds engages in with other nodes.
    ///
    /// See [`CommunicationInfo`] documentation for more details.
    fn communication_info(&self) -> CommunicationInfo<Id>;

    type DirectMessage: Serialize + for<'de> Deserialize<'de>;
    type NormalBroadcast: Serialize + for<'de> Deserialize<'de>;
    type EchoBroadcast: Serialize + for<'de> Deserialize<'de>;

    type Payload: Send + Sync;
    type Artifact: Send + Sync;

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
            NoMessage::new_if_equals::<R::DirectMessage>().unwrap()
        } else {
            message.direct_message.deserialize::<R::DirectMessage>(format)?
        };

        let echo_broadcast = if NoMessage::equals::<R::EchoBroadcast>() {
            message.echo_broadcast.assert_is_none()?;
            NoMessage::new_if_equals::<R::EchoBroadcast>().unwrap()
        } else {
            message.echo_broadcast.deserialize::<R::EchoBroadcast>(format)?
        };

        let normal_broadcast = if NoMessage::equals::<R::NormalBroadcast>() {
            message.normal_broadcast.assert_is_none()?;
            // this is infallible
            NoMessage::new_if_equals::<R::NormalBroadcast>().unwrap()
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
