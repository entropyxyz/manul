use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
};
use core::{fmt::Debug, marker::PhantomData};

use rand_core::{CryptoRng, CryptoRngCore, RngCore};

use super::{
    errors::{LocalError, ReceiveError},
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage},
    round::{Artifact, EchoRoundParticipation, FinalizeOutcome, PartyId, Payload, Protocol, Round, RoundId},
    serialization::{Deserializer, Serializer},
};

/// Since object-safe trait methods cannot take `impl CryptoRngCore` arguments,
/// this structure wraps the dynamic object and exposes a `CryptoRngCore` interface,
/// to be passed to statically typed round methods.
pub(crate) struct BoxedRng<'a>(pub(crate) &'a mut dyn CryptoRngCore);

impl CryptoRng for BoxedRng<'_> {}

impl RngCore for BoxedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

// Since we want `Round` methods to take `&mut impl CryptoRngCore` arguments
// (which is what all cryptographic libraries generally take), it cannot be object-safe.
// Thus we have to add this crate-private object-safe layer on top of `Round`.
pub(crate) trait ObjectSafeRound<Id: PartyId>: 'static + Debug + Send + Sync {
    type Protocol: Protocol<Id>;

    fn id(&self) -> RoundId;

    fn possible_next_rounds(&self) -> BTreeSet<RoundId>;

    fn may_produce_result(&self) -> bool;

    fn message_destinations(&self) -> &BTreeSet<Id>;

    fn expecting_messages_from(&self) -> &BTreeSet<Id>;

    fn echo_round_participation(&self) -> EchoRoundParticipation<Id>;

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError>;

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
    ) -> Result<EchoBroadcast, LocalError>;

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
    ) -> Result<NormalBroadcast, LocalError>;

    fn receive_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>>;

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError>;

    /// Returns the type ID of the implementing type.
    fn get_type_id(&self) -> core::any::TypeId {
        core::any::TypeId::of::<Self>()
    }
}

// The `fn(Id) -> Id` bit is so that `ObjectSafeRoundWrapper` didn't require a bound on `Id` to be
// `Send + Sync`.
#[derive(Debug)]
pub(crate) struct ObjectSafeRoundWrapper<Id, R> {
    round: R,
    phantom: PhantomData<fn(Id) -> Id>,
}

impl<Id, R> ObjectSafeRoundWrapper<Id, R>
where
    Id: PartyId,
    R: Round<Id>,
{
    pub fn new(round: R) -> Self {
        Self {
            round,
            phantom: PhantomData,
        }
    }
}

impl<Id, R> ObjectSafeRound<Id> for ObjectSafeRoundWrapper<Id, R>
where
    Id: PartyId,
    R: Round<Id>,
{
    type Protocol = <R as Round<Id>>::Protocol;

    fn id(&self) -> RoundId {
        self.round.id()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        self.round.possible_next_rounds()
    }

    fn may_produce_result(&self) -> bool {
        self.round.may_produce_result()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        self.round.message_destinations()
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        self.round.expecting_messages_from()
    }

    fn echo_round_participation(&self) -> EchoRoundParticipation<Id> {
        self.round.echo_round_participation()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        #[allow(unused_variables)] deserializer: &Deserializer,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.make_direct_message(&mut boxed_rng, serializer, destination)
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        #[allow(unused_variables)] deserializer: &Deserializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.make_echo_broadcast(&mut boxed_rng, serializer)
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        #[allow(unused_variables)] deserializer: &Deserializer,
    ) -> Result<NormalBroadcast, LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.make_normal_broadcast(&mut boxed_rng, serializer)
    }

    fn receive_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.receive_message(&mut boxed_rng, deserializer, from, message)
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.finalize(&mut boxed_rng, payloads, artifacts)
    }
}

// We do not want to expose `ObjectSafeRound` to the user, so it is hidden in a struct.
/// A wrapped new round that may be returned by [`Round::finalize`]
/// or [`EntryPoint::make_round`](`crate::protocol::EntryPoint::make_round`).
#[derive_where::derive_where(Debug)]
pub struct BoxedRound<Id: PartyId, P: Protocol<Id>> {
    wrapped: bool,
    round: Box<dyn ObjectSafeRound<Id, Protocol = P>>,
}

impl<Id: PartyId, P: Protocol<Id>> BoxedRound<Id, P> {
    /// Wraps an object implementing the dynamic round trait ([`Round`](`crate::protocol::Round`)).
    pub fn new_dynamic<R: Round<Id, Protocol = P>>(round: R) -> Self {
        Self {
            wrapped: true,
            round: Box::new(ObjectSafeRoundWrapper::new(round)),
        }
    }

    pub(crate) fn new_object_safe<R: ObjectSafeRound<Id, Protocol = P>>(round: R) -> Self {
        Self {
            wrapped: false,
            round: Box::new(round),
        }
    }

    pub(crate) fn as_ref(&self) -> &dyn ObjectSafeRound<Id, Protocol = P> {
        self.round.as_ref()
    }

    pub(crate) fn into_boxed(self) -> Box<dyn ObjectSafeRound<Id, Protocol = P>> {
        self.round
    }

    fn boxed_type_is<T: 'static>(&self) -> bool {
        core::any::TypeId::of::<T>() == self.round.get_type_id()
    }

    /// Attempts to extract an object of a concrete type, preserving the original on failure.
    pub fn try_downcast<T: Round<Id>>(self) -> Result<T, Self> {
        if self.wrapped && self.boxed_type_is::<ObjectSafeRoundWrapper<Id, T>>() {
            // Safety: This is safe since we just checked that we are casting to the correct type.
            let boxed_downcast = unsafe {
                Box::<ObjectSafeRoundWrapper<Id, T>>::from_raw(
                    Box::into_raw(self.round) as *mut ObjectSafeRoundWrapper<Id, T>
                )
            };
            Ok(boxed_downcast.round)
        } else {
            Err(self)
        }
    }

    /// Attempts to extract an object of a concrete type.
    ///
    /// Fails if the wrapped type is not `T`.
    pub fn downcast<T: Round<Id>>(self) -> Result<T, LocalError> {
        self.try_downcast()
            .map_err(|_| LocalError::new(format!("Failed to downcast into type {}", core::any::type_name::<T>())))
    }

    /// Attempts to provide a reference to an object of a concrete type.
    ///
    /// Fails if the wrapped type is not `T`.
    pub fn downcast_ref<T: Round<Id>>(&self) -> Result<&T, LocalError> {
        if self.wrapped && self.boxed_type_is::<ObjectSafeRoundWrapper<Id, T>>() {
            let ptr: *const dyn ObjectSafeRound<Id, Protocol = P> = self.round.as_ref();
            // Safety: This is safe since we just checked that we are casting to the correct type.
            Ok(unsafe { &*(ptr as *const T) })
        } else {
            Err(LocalError::new(format!(
                "Failed to downcast into type {}",
                core::any::type_name::<T>()
            )))
        }
    }

    /// Returns the round's ID.
    pub fn id(&self) -> RoundId {
        self.round.id()
    }
}
