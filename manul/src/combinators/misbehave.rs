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

use alloc::{boxed::Box, collections::BTreeMap};
use core::fmt::Debug;

use rand_core::CryptoRngCore;

use crate::protocol::{
    Artifact, BoxedFormat, BoxedRound, CommunicationInfo, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome,
    LocalError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolMessage, ReceiveError, Round, RoundId,
    TransitionInfo,
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
        rng: &mut dyn CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        format: &BoxedFormat,
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
        rng: &mut dyn CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        format: &BoxedFormat,
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
        rng: &mut dyn CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        format: &BoxedFormat,
        destination: &Id,
        direct_message: DirectMessage,
        artifact: Option<Artifact>,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        Ok((direct_message, artifact))
    }

    /// Called before [`Round::finalize`](`crate::protocol::Round::finalize`)
    /// and may override its result.
    ///
    /// Return [`FinalizeOverride::UseDefault`] to use the existing `finalize()`
    /// (the default behavior is to do that passing through `round`, `payloads`, and `artifacts`).
    /// Otherwise finalize manually and return [`FinalizeOverride::Override`],
    /// in which case the existing `finalize()` will not be called.
    #[allow(unused_variables)]
    fn override_finalize(
        rng: &mut dyn CryptoRngCore,
        round: BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &B,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOverride<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>, LocalError> {
        Ok(FinalizeOverride::UseDefault {
            round,
            payloads,
            artifacts,
        })
    }
}

/// Possible return values for [`Misbehaving::override_finalize`].
#[derive(Debug)]
pub enum FinalizeOverride<Id: PartyId, P: Protocol<Id>> {
    /// Use the existing [`Round::finalize`](`crate::protocol::Round::finalize`) with the given arguments.
    UseDefault {
        /// The round object to pass to `finalize()`.
        round: BoxedRound<Id, P>,
        /// The payloads map to pass to `finalize()`.
        payloads: BTreeMap<Id, Payload>,
        /// The artifacts map to pass to `finalize()`.
        artifacts: BTreeMap<Id, Artifact>,
    },
    /// Finalize manually; the existing [`Round::finalize`](`crate::protocol::Round::finalize`) will not be called.
    Override(FinalizeOutcome<Id, P>),
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

    fn entry_round_id() -> RoundId {
        M::EntryPoint::entry_round_id()
    }

    fn make_round(
        self,
        rng: &mut dyn CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let round = self.entry_point.make_round(rng, shared_randomness, id)?;
        Ok(BoxedRound::new(MisbehavingRound::<Id, B, M> {
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

impl<Id, B, M> MisbehavingRound<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    /// Wraps the outcome of the underlying Round into the MisbehavingRound structure.
    fn map_outcome(
        outcome: FinalizeOutcome<Id, <Self as Round<Id>>::Protocol>,
        behavior: Option<B>,
    ) -> FinalizeOutcome<Id, <Self as Round<Id>>::Protocol> {
        match outcome {
            FinalizeOutcome::Result(result) => FinalizeOutcome::Result(result),
            FinalizeOutcome::AnotherRound(round) => {
                FinalizeOutcome::AnotherRound(BoxedRound::new(Self { round, behavior }))
            }
        }
    }
}

impl<Id, B, M> Round<Id> for MisbehavingRound<Id, B, M>
where
    Id: PartyId,
    B: Behavior,
    M: Misbehaving<Id, B>,
{
    type Protocol = <M::EntryPoint as EntryPoint<Id>>::Protocol;

    fn transition_info(&self) -> TransitionInfo {
        self.round.as_ref().transition_info()
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        self.round.as_ref().communication_info()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let (direct_message, artifact) = self.round.as_ref().make_direct_message(rng, format, destination)?;
        if let Some(behavior) = self.behavior.as_ref() {
            M::modify_direct_message(
                rng,
                &self.round,
                behavior,
                format,
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
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        let echo_broadcast = self.round.as_ref().make_echo_broadcast(rng, format)?;
        if let Some(behavior) = self.behavior.as_ref() {
            M::modify_echo_broadcast(rng, &self.round, behavior, format, echo_broadcast)
        } else {
            Ok(echo_broadcast)
        }
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        let normal_broadcast = self.round.as_ref().make_normal_broadcast(rng, format)?;
        if let Some(behavior) = self.behavior.as_ref() {
            M::modify_normal_broadcast(rng, &self.round, behavior, format, normal_broadcast)
        } else {
            Ok(normal_broadcast)
        }
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        self.round.as_ref().receive_message(format, from, message)
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let (round, payloads, artifacts) = if let Some(behavior) = self.behavior.as_ref() {
            let result = M::override_finalize(rng, self.round, behavior, payloads, artifacts)?;
            match result {
                FinalizeOverride::UseDefault {
                    round,
                    payloads,
                    artifacts,
                } => (round, payloads, artifacts),
                FinalizeOverride::Override(outcome) => return Ok(Self::map_outcome(outcome, self.behavior)),
            }
        } else {
            (self.round, payloads, artifacts)
        };

        let outcome = round.into_boxed().finalize(rng, payloads, artifacts)?;
        Ok(Self::map_outcome(outcome, self.behavior))
    }
}
