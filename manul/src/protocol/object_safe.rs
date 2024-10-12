use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
};
use core::marker::PhantomData;

use rand_core::{CryptoRng, CryptoRngCore, RngCore};

use super::{
    error::LocalError,
    round::{
        Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, Payload, Protocol, ReceiveError, Round,
        RoundId,
    },
};

/// Since object-safe trait methods cannot take `impl CryptoRngCore` arguments,
/// this structure wraps the dynamic object and exposes a `CryptoRngCore` interface,
/// to be passed to statically typed round methods.
struct BoxedRng<'a>(&'a mut dyn CryptoRngCore);

impl<'a> CryptoRng for BoxedRng<'a> {}

impl<'a> RngCore for BoxedRng<'a> {
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
pub(crate) trait ObjectSafeRound<Id>: 'static + Send + Sync {
    type Protocol: Protocol;

    fn id(&self) -> RoundId;

    fn possible_next_rounds(&self) -> BTreeSet<RoundId>;

    fn message_destinations(&self) -> &BTreeSet<Id>;

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError>;

    fn make_echo_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Option<Result<EchoBroadcast, LocalError>>;

    fn receive_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        from: &Id,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>>;

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Id, Self::Protocol>>;

    fn expecting_messages_from(&self) -> &BTreeSet<Id>;

    /// Returns the type ID of the implementing type.
    ///
    /// **Warning:** this is not a part of the public API.
    #[doc(hidden)]
    fn __get_type_id(&self) -> core::any::TypeId;
}

pub(crate) struct ObjectSafeRoundWrapper<Id, R> {
    round: R,
    phantom: PhantomData<fn(Id) -> Id>,
}

impl<Id: 'static, R: Round<Id>> ObjectSafeRoundWrapper<Id, R> {
    pub fn new(round: R) -> Self {
        Self {
            round,
            phantom: PhantomData,
        }
    }
}

impl<Id, R> ObjectSafeRound<Id> for ObjectSafeRoundWrapper<Id, R>
where
    Id: 'static,
    R: Round<Id>,
{
    type Protocol = <R as Round<Id>>::Protocol;

    fn id(&self) -> RoundId {
        self.round.id()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        self.round.possible_next_rounds()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        self.round.message_destinations()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.make_direct_message(&mut boxed_rng, destination)
    }

    fn make_echo_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Option<Result<EchoBroadcast, LocalError>> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.make_echo_broadcast(&mut boxed_rng)
    }

    fn receive_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        from: &Id,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        let mut boxed_rng = BoxedRng(rng);
        self.round
            .receive_message(&mut boxed_rng, from, echo_broadcast, direct_message)
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Id, Self::Protocol>> {
        let mut boxed_rng = BoxedRng(rng);
        self.round.finalize(&mut boxed_rng, payloads, artifacts)
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        self.round.expecting_messages_from()
    }

    #[doc(hidden)]
    fn __get_type_id(&self) -> core::any::TypeId {
        core::any::TypeId::of::<Self>()
    }
}

// When we are wrapping types implementing Round and overriding `finalize()`,
// we need to unbox the result of `finalize()`, set it as an attribute of the wrapping round,
// and then box the result.
//
// Because of Rust's peculiarities, Box<dyn Round> that we return in `finalize()`
// cannot be unboxed into an object of a concrete type with `downcast()`,
// so we have to provide this workaround.
impl<Id, P> dyn ObjectSafeRound<Id, Protocol = P>
where
    Id: 'static,
    P: 'static + Protocol,
{
    pub fn try_downcast<T: Round<Id>>(self: Box<Self>) -> Result<T, Box<Self>> {
        if core::any::TypeId::of::<ObjectSafeRoundWrapper<Id, T>>() == self.__get_type_id() {
            let boxed_downcast = unsafe {
                Box::<ObjectSafeRoundWrapper<Id, T>>::from_raw(Box::into_raw(self) as *mut ObjectSafeRoundWrapper<Id, T>)
            };
            Ok(boxed_downcast.round)
        } else {
            Err(self)
        }
    }

    pub fn downcast<T: Round<Id>>(self: Box<Self>) -> Result<T, LocalError> {
        self.try_downcast()
            .map_err(|_| LocalError::new(format!("Failed to downcast into type {}", core::any::type_name::<T>())))
    }
}
