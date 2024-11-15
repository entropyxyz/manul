/*!
A combinator allowing one to intercept outgoing messages from a round, and replace or modify them.

Usage:

1. Define a behavior type, subject to [`Behavior`] bounds.
   This will represent the possible actions the override may perform.

2. Implement [`Misbehaving`] for a type of your choice. Usually it will be a ZST.
   You will need to specify the entry point for the unmodified protocol,
   and some of `modify_*` methods (the blanket implementations simply pass through the original messages).

3. The `modify_*` methods can be called from any round, use [`BoxedRound::id`](`crate::protocol::BoxedRound::id`)
   on the `round` argument to determine which round it is.

4. In the `modify_*` methods, you can get the original typed message using the provided `deserializer` argument,
   and create a new one using the `serializer`.

5. You can get access to the typed `Round` object by using
   [`BoxedRound::downcast_ref`](`crate::protocol::BoxedRound::downcast_ref`).

6. Use [`MisbehavingEntryPoint`] parametrized by `Id`, the behavior type from step 1, and the type from step 2
   as the entry point of the new protocol.
*/

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
};
use core::fmt::Debug;

use rand_core::CryptoRngCore;

use crate::protocol::{
    Artifact, BoxedRng, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EchoRoundParticipation, EntryPoint,
    FinalizeError, FinalizeOutcome, LocalError, NormalBroadcast, ObjectSafeRound, PartyId, Payload, ReceiveError,
    RoundId, Serializer,
};

/// A trait describing required properties for a behavior type.
pub trait Behavior: 'static + Debug + Send + Sync {}

impl<T: 'static + Debug + Send + Sync> Behavior for T {}

/// A trait defining a sequence of misbehaving rounds modifying or replacing the messages sent by some existing ones.
///
/// Override one or more optional methods to modify the specific messages.
pub trait Misbehaving<Id, B>: 'static
where
    Id: PartyId,
    B: Behavior,
{
    /// The entry point of the wrapped rounds.
    type EntryPoint: Debug + EntryPoint<Id>;

    /// Called after [`Round::make_echo_broadcast`](`crate::protocol::Round::make_echo_broadcast`)
    /// and may modify its result.
    ///
    /// The default implementation passes through the original message.
    #[allow(unused_variables)]
    fn modify_echo_broadcast(
        rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        serializer: &Serializer,
        deserializer: &Deserializer,
        echo_broadcast: EchoBroadcast,
    ) -> Result<EchoBroadcast, LocalError> {
        Ok(echo_broadcast)
    }

    /// Called after [`Round::make_normal_broadcast`](`crate::protocol::Round::make_normal_broadcast`)
    /// and may modify its result.
    ///
    /// The default implementation passes through the original message.
    #[allow(unused_variables)]
    fn modify_normal_broadcast(
        rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        serializer: &Serializer,
        deserializer: &Deserializer,
        normal_broadcast: NormalBroadcast,
    ) -> Result<NormalBroadcast, LocalError> {
        Ok(normal_broadcast)
    }

    /// Called after [`Round::make_direct_message`](`crate::protocol::Round::make_direct_message`)
    /// and may modify its result.
    ///
    /// The default implementation passes through the original message.
    #[allow(unused_variables, clippy::too_many_arguments)]
    fn modify_direct_message(
        rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        serializer: &Serializer,
        deserializer: &Deserializer,
        destination: &Id,
        direct_message: DirectMessage,
        artifact: Option<Artifact>,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        Ok((direct_message, artifact))
    }
}

/// The new entry point for the misbehaving rounds.
///
/// Use as an entry point to run the session, with your ID, the behavior `B` and the misbehavior definition `M` set.
#[derive_where::derive_where(Debug)]
pub struct MisbehavingEntryPoint<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    entry_point: M::EntryPoint,
    behavior: Option<B>,
}

impl<Id, B, M> MisbehavingEntryPoint<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    /// Creates an entry point for the misbehaving protocol using an entry point for the inner protocol.
    pub fn new(entry_point: M::EntryPoint, behavior: Option<B>) -> Self {
        Self { entry_point, behavior }
    }
}

impl<Id, B, M> EntryPoint<Id> for MisbehavingEntryPoint<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    type Protocol = <M::EntryPoint as EntryPoint<Id>>::Protocol;

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let round = self.entry_point.make_round(rng, shared_randomness, id)?;
        Ok(BoxedRound::new_object_safe(MisbehavingRound::<Id, B, M> {
            round,
            behavior: self.behavior,
        }))
    }
}

#[derive_where::derive_where(Debug)]
struct MisbehavingRound<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    round: BoxedRound<Id, <M::EntryPoint as EntryPoint<Id>>::Protocol>,
    behavior: Option<B>,
}

impl<Id, B, M> ObjectSafeRound<Id> for MisbehavingRound<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    type Protocol = <M::EntryPoint as EntryPoint<Id>>::Protocol;

    fn id(&self) -> RoundId {
        self.round.as_ref().id()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        self.round.as_ref().possible_next_rounds()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        self.round.as_ref().message_destinations()
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        self.round.as_ref().expecting_messages_from()
    }

    fn echo_round_participation(&self) -> EchoRoundParticipation<Id> {
        self.round.as_ref().echo_round_participation()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let (direct_message, artifact) =
            self.round
                .as_ref()
                .make_direct_message(rng, serializer, deserializer, destination)?;
        if let Some(behavior) = self.behavior.as_ref() {
            let mut boxed_rng = BoxedRng(rng);
            M::modify_direct_message(
                &mut boxed_rng,
                &self.round,
                behavior,
                serializer,
                deserializer,
                destination,
                direct_message,
                artifact,
            )
        } else {
            Ok((direct_message, artifact))
        }
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let echo_broadcast = self.round.as_ref().make_echo_broadcast(rng, serializer, deserializer)?;
        if let Some(behavior) = self.behavior.as_ref() {
            let mut boxed_rng = BoxedRng(rng);
            M::modify_echo_broadcast(
                &mut boxed_rng,
                &self.round,
                behavior,
                serializer,
                deserializer,
                echo_broadcast,
            )
        } else {
            Ok(echo_broadcast)
        }
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
    ) -> Result<NormalBroadcast, LocalError> {
        let normal_broadcast = self
            .round
            .as_ref()
            .make_normal_broadcast(rng, serializer, deserializer)?;
        if let Some(behavior) = self.behavior.as_ref() {
            let mut boxed_rng = BoxedRng(rng);
            M::modify_normal_broadcast(
                &mut boxed_rng,
                &self.round,
                behavior,
                serializer,
                deserializer,
                normal_broadcast,
            )
        } else {
            Ok(normal_broadcast)
        }
    }

    fn receive_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        self.round.as_ref().receive_message(
            rng,
            deserializer,
            from,
            echo_broadcast,
            normal_broadcast,
            direct_message,
        )
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>> {
        match self.round.into_boxed().finalize(rng, payloads, artifacts) {
            Ok(FinalizeOutcome::Result(result)) => Ok(FinalizeOutcome::Result(result)),
            Ok(FinalizeOutcome::AnotherRound(round)) => {
                Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_object_safe(Self {
                    round,
                    behavior: self.behavior,
                })))
            }
            Err(err) => Err(err),
        }
    }
}
