use alloc::{boxed::Box, collections::BTreeMap, format};
use core::{any::Any, fmt::Debug};

#[cfg(any(test, feature = "dev"))]
use core::any::TypeId;

use rand_core::CryptoRngCore;

use super::{
    dyn_evidence::BoxedProtocolError,
    errors::{LocalError, ReceiveError, RemoteError},
    message::{
        DirectMessage, DirectMessageError, DynProtocolMessage, EchoBroadcast, EchoBroadcastError, NormalBroadcast,
        NormalBroadcastError, ProtocolMessagePart,
    },
    rng::BoxedRng,
    round::{CommunicationInfo, FinalizeOutcome, NoMessage, NoType, PartyId, Protocol, ProtocolMessage, Round},
    round_id::{GroupNum, RoundId, TransitionInfo},
    wire_format::BoxedFormat,
};
use crate::{session::EchoRoundError, utils::DynTypeId};

#[derive(Debug)]
pub(crate) struct Payload(pub Box<dyn Any + Send + Sync>);

impl Payload {
    /// Creates a new payload.
    pub fn new<T: 'static + Send + Sync>(payload: T) -> Self {
        Self(Box::new(payload))
    }

    /// Creates an empty payload.
    ///
    /// Use it in [`Round::receive_message`] if it does not need to create payloads.
    pub fn empty() -> Self {
        Self::new(())
    }

    /// Attempts to downcast back to the concrete type.
    pub fn downcast<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self.0.downcast::<T>().map_err(|_| {
            LocalError::new(format!(
                "Failed to downcast Payload into {}",
                core::any::type_name::<T>()
            ))
        })?))
    }
}

#[derive(Debug)]
pub(crate) struct Artifact(pub Box<dyn Any + Send + Sync>);

impl Artifact {
    /// Creates a new artifact.
    pub fn new<T: 'static + Send + Sync>(artifact: T) -> Self {
        Self(Box::new(artifact))
    }

    /// Attempts to downcast back to the concrete type.
    pub fn downcast<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self.0.downcast::<T>().map_err(|_| {
            LocalError::new(format!(
                "Failed to downcast Artifact into {}",
                core::any::type_name::<T>()
            ))
        })?))
    }
}

pub(crate) trait DynRound<Id>: 'static + Debug + Send + Sync + DynTypeId {
    type Protocol: Protocol<Id>;

    fn transition_info(&self) -> TransitionInfo;

    fn communication_info(&self) -> CommunicationInfo<Id>;

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError>;

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError>;

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError>;

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: DynProtocolMessage,
    ) -> Result<Payload, BoxedReceiveError<Id>>;

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError>;
}

#[derive(Debug)]
struct RoundWrapper<R> {
    round: R,
}

impl<R> RoundWrapper<R> {
    pub fn new(round: R) -> Self {
        Self { round }
    }

    #[cfg(any(test, feature = "dev"))]
    pub fn into_inner(self) -> R {
        self.round
    }
}

impl<Id, R> DynRound<Id> for RoundWrapper<R>
where
    Id: PartyId,
    R: Round<Id>,
{
    type Protocol = <R as Round<Id>>::Protocol;

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
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        let (direct_message, artifact) = self.round.make_direct_message(&mut BoxedRng(rng), destination)?;
        Ok((DirectMessage::new(format, direct_message)?, Artifact::new(artifact)))
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        let echo_broadcast = self.round.make_echo_broadcast(&mut BoxedRng(rng))?;
        EchoBroadcast::new(format, echo_broadcast)
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        let normal_broadcast = self.round.make_normal_broadcast(&mut BoxedRng(rng))?;
        NormalBroadcast::new(format, normal_broadcast)
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: DynProtocolMessage,
    ) -> Result<Payload, BoxedReceiveError<Id>> {
        let direct_message = if let Some(direct_message) = NoMessage::new_if_equals::<R::DirectMessage>() {
            message.direct_message.assert_is_none()?;
            direct_message
        } else {
            message.direct_message.deserialize::<R::DirectMessage>(format)?
        };

        let echo_broadcast = if let Some(echo_broadcast) = NoMessage::new_if_equals::<R::EchoBroadcast>() {
            message.echo_broadcast.assert_is_none()?;
            echo_broadcast
        } else {
            message.echo_broadcast.deserialize::<R::EchoBroadcast>(format)?
        };

        let normal_broadcast = if let Some(normal_broadcast) = NoMessage::new_if_equals::<R::NormalBroadcast>() {
            message.normal_broadcast.assert_is_none()?;
            normal_broadcast
        } else {
            message.normal_broadcast.deserialize::<R::NormalBroadcast>(format)?
        };

        let payload = self
            .round
            .receive_message(
                from,
                ProtocolMessage {
                    direct_message,
                    echo_broadcast,
                    normal_broadcast,
                },
            )
            .map_err(|error| BoxedReceiveError::new(error, &self.transition_info().id))?;

        Ok(Payload::new(payload))
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads
            .into_iter()
            .map(|(id, payload)| payload.downcast::<R::Payload>().map(|payload| (id, payload)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let artifacts = artifacts
            .into_iter()
            .map(|(id, artifact)| artifact.downcast::<R::Artifact>().map(|artifact| (id, artifact)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        self.round.finalize(&mut BoxedRng(rng), payloads, artifacts)
    }
}

/// A wrapped new round that may be returned by [`Round::finalize`]
/// or [`EntryPoint::make_round`](`crate::protocol::EntryPoint::make_round`).
#[derive_where::derive_where(Debug)]
pub struct BoxedRound<Id, P: Protocol<Id>>(BoxedRoundEnum<Id, P>);

#[derive_where::derive_where(Debug)]
enum BoxedRoundEnum<Id, P: Protocol<Id>> {
    Dynamic(Box<dyn DynRound<Id, Protocol = P>>),
    Typed(BoxedTypedRound<Id, P>),
}

impl<Id: PartyId, P: Protocol<Id>> BoxedRound<Id, P> {
    /// Wraps an object implementing the typed round trait ([`Round`](`crate::protocol::Round`)).
    pub fn new<R: Round<Id, Protocol = P>>(round: R) -> Self {
        Self(BoxedRoundEnum::Typed(BoxedTypedRound::new(round)))
    }

    pub(crate) fn new_dynamic<R: DynRound<Id, Protocol = P>>(round: R) -> Self {
        Self(BoxedRoundEnum::Dynamic(Box::new(round)))
    }

    pub(crate) fn as_ref(&self) -> &dyn DynRound<Id, Protocol = P> {
        match &self.0 {
            BoxedRoundEnum::Dynamic(boxed) => boxed.as_ref(),
            BoxedRoundEnum::Typed(boxed) => boxed.as_ref(),
        }
    }

    pub(crate) fn into_inner(self) -> Box<dyn DynRound<Id, Protocol = P>> {
        match self.0 {
            BoxedRoundEnum::Dynamic(boxed) => boxed,
            BoxedRoundEnum::Typed(boxed) => boxed.into_inner(),
        }
    }

    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn as_typed(&self) -> Result<&BoxedTypedRound<Id, P>, LocalError> {
        match &self.0 {
            BoxedRoundEnum::Dynamic(_boxed) => {
                Err(LocalError::new("Attempted to use a boxed dynamic round as a typed one"))
            }
            BoxedRoundEnum::Typed(boxed) => Ok(boxed),
        }
    }

    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn into_typed(self) -> Result<BoxedTypedRound<Id, P>, LocalError> {
        match self.0 {
            BoxedRoundEnum::Dynamic(_boxed) => {
                Err(LocalError::new("Attempted to use a boxed dynamic round as a typed one"))
            }
            BoxedRoundEnum::Typed(boxed) => Ok(boxed),
        }
    }
}

#[derive_where::derive_where(Debug)]
pub(crate) struct BoxedTypedRound<Id, P: Protocol<Id>>(Box<dyn DynRound<Id, Protocol = P>>);

impl<Id: PartyId, P: Protocol<Id>> BoxedTypedRound<Id, P> {
    pub fn new<R: Round<Id, Protocol = P>>(round: R) -> Self {
        Self(Box::new(RoundWrapper::new(round)))
    }

    pub(crate) fn as_ref(&self) -> &dyn DynRound<Id, Protocol = P> {
        self.0.as_ref()
    }

    pub(crate) fn into_inner(self) -> Box<dyn DynRound<Id, Protocol = P>> {
        self.0
    }

    /// Returns the type ID of the encapsulated `Round` implementor.
    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn type_id(&self) -> TypeId {
        self.0.as_ref().get_type_id()
    }

    /// Returns the type ID that [`type_id`] would return for an object created with [`new()`]
    /// given a round of type `R`.
    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn type_id_for<R: 'static + Round<Id, Protocol = P>>() -> TypeId {
        TypeId::of::<RoundWrapper<R>>()
    }

    /// Attempts to extract an object of a concrete type, preserving the original on failure.
    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn try_downcast<T: Round<Id>>(self) -> Result<T, Self> {
        if self.type_id() == TypeId::of::<RoundWrapper<T>>() {
            // Safety: This is safe since we just checked that we are casting to the correct type.
            let boxed_downcast =
                unsafe { Box::<RoundWrapper<T>>::from_raw(Box::into_raw(self.0) as *mut RoundWrapper<T>) };
            Ok((*boxed_downcast).into_inner())
        } else {
            Err(self)
        }
    }

    /// Attempts to extract an object of a concrete type.
    ///
    /// Fails if the wrapped type is not `T`.
    #[cfg(any(test, feature = "dev"))]
    pub(crate) fn downcast<T: Round<Id>>(self) -> Result<T, LocalError> {
        self.try_downcast()
            .map_err(|_| LocalError::new(format!("Failed to downcast into type {}", core::any::type_name::<T>())))
    }
}

#[derive(Debug)]
pub(crate) enum BoxedReceiveError<Id> {
    Local(LocalError),
    /// The given direct message cannot be deserialized.
    InvalidDirectMessage(DirectMessageError),
    /// The given echo broadcast cannot be deserialized.
    InvalidEchoBroadcast(EchoBroadcastError),
    /// The given normal broadcast cannot be deserialized.
    InvalidNormalBroadcast(NormalBroadcastError),
    /// A provable protocol error associated with the round.
    Protocol(BoxedProtocolError<Id>),
    /// An unprovable error.
    Unprovable(RemoteError),
    /// An error during an echo round.
    Echo(Box<EchoRoundError<Id>>),
}

impl<Id> BoxedReceiveError<Id> {
    pub(crate) fn new<R: Round<Id>>(error: ReceiveError<Id, R>, round_id: &RoundId) -> Self {
        match error {
            ReceiveError::Local(error) => Self::Local(error),
            ReceiveError::Unprovable(error) => Self::Unprovable(error),
            ReceiveError::Protocol(error) => Self::Protocol(BoxedProtocolError::new::<R>(error, round_id)),
        }
    }

    pub(crate) fn group_under(self, group_num: GroupNum) -> Self {
        if let Self::Protocol(error) = self {
            Self::Protocol(error.group_under(group_num))
        } else {
            self
        }
    }
}

impl<Id> From<LocalError> for BoxedReceiveError<Id> {
    fn from(error: LocalError) -> Self {
        BoxedReceiveError::Local(error)
    }
}

impl<Id> From<BoxedProtocolError<Id>> for BoxedReceiveError<Id> {
    fn from(error: BoxedProtocolError<Id>) -> Self {
        BoxedReceiveError::Protocol(error)
    }
}

impl<Id> From<DirectMessageError> for BoxedReceiveError<Id> {
    fn from(error: DirectMessageError) -> Self {
        BoxedReceiveError::InvalidDirectMessage(error)
    }
}

impl<Id> From<EchoBroadcastError> for BoxedReceiveError<Id> {
    fn from(error: EchoBroadcastError) -> Self {
        BoxedReceiveError::InvalidEchoBroadcast(error)
    }
}

impl<Id> From<NormalBroadcastError> for BoxedReceiveError<Id> {
    fn from(error: NormalBroadcastError) -> Self {
        BoxedReceiveError::InvalidNormalBroadcast(error)
    }
}
