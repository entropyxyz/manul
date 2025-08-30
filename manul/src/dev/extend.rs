#![allow(missing_docs, unused_variables, missing_debug_implementations)]
/*!
This module contains tools to extend or override methods of a [`Round`] in a protocol.

Usage:

1. Implement [`RoundExtension`] for an object (which may be an empty struct or contain some data).

2. Wrap an [`EntryPoint`] of a protocol in an [`ExtendableEntryPoint`].

3. Add extensions to it via [`ExtendableEntryPoint::extend`] or [`ExtendableEntryPoint::with_extension`].

4. Use the [`ExtendableEntryPoint`] object as the new entry point.
   The extension will be activated for every round whose type is equal to [`RoundExtension::Round`].
*/

use alloc::{boxed::Box, collections::BTreeMap};
use core::{any::TypeId, fmt::Debug};

use dyn_clone::DynClone;
use rand_core::CryptoRngCore;

use crate::protocol::{
    Artifact, BoxedFormat, BoxedRound, CommunicationInfo, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome,
    LocalError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolMessage, ReceiveError, Round, RoundId,
    StaticProtocolMessage, StaticRound, StaticRoundAdapter, TransitionInfo,
};

/// An extension to a round, allowing one to extend or override its methods.
pub trait RoundExtension<Id>: 'static + Debug + Send + Sync + Clone {
    /// The round type to which the extension is applied.
    type Round: StaticRound<Id>;

    /// Called instead of [`Round::make_normal_broadcast`].
    ///
    /// The default implementation calls [`Round::make_normal_broadcast`].
    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        round: &Self::Round,
    ) -> Result<Option<<Self::Round as StaticRound<Id>>::NormalBroadcast>, LocalError> {
        round.make_normal_broadcast(rng)
    }

    /// Called instead of [`Round::make_echo_broadcast`].
    ///
    /// The default implementation calls [`Round::make_echo_broadcast`].
    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        round: &Self::Round,
    ) -> Result<Option<<Self::Round as StaticRound<Id>>::EchoBroadcast>, LocalError> {
        round.make_echo_broadcast(rng)
    }

    /// Called instead of [`Round::make_direct_message`].
    ///
    /// The default implementation calls [`Round::make_direct_message`].
    #[allow(clippy::type_complexity)]
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        round: &Self::Round,
        destination: &Id,
    ) -> Result<
        Option<(
            <Self::Round as StaticRound<Id>>::DirectMessage,
            <Self::Round as StaticRound<Id>>::Artifact,
        )>,
        LocalError,
    > {
        round.make_direct_message(rng, destination)
    }

    /// Called instead of [`Round::finalize`].
    ///
    /// The default implementation calls [`Round::finalize`].
    fn finalize(
        &self,
        rng: &mut dyn CryptoRngCore,
        round: Self::Round,
        payloads: BTreeMap<Id, <Self::Round as StaticRound<Id>>::Payload>,
        artifacts: BTreeMap<Id, <Self::Round as StaticRound<Id>>::Artifact>,
    ) -> Result<FinalizeOutcome<Id, <Self::Round as StaticRound<Id>>::Protocol>, LocalError> {
        round.finalize(rng, payloads, artifacts)
    }
}

#[allow(clippy::type_complexity)]
#[derive_where::derive_where(Debug)]
struct ExtendedRound<Id, Ext: RoundExtension<Id>> {
    round: Ext::Round,
    /// The extension active for the current round type.
    extension: Ext,
    /// A mapping between round types and extensions.
    /// During protocol execution, this map is checked and if the current round type has an extension defined,
    /// use it to extend the round. Otherwise fall through to the "normal" round.
    ///
    /// It is saved here since we have no access to external context from a round,
    /// so we have to pass this mapping from round to round during finalization.
    extensions: BTreeMap<TypeId, Box<dyn DynRoundExtension<Id, <Ext::Round as StaticRound<Id>>::Protocol>>>,
}

impl<Id, Ext> StaticRound<Id> for ExtendedRound<Id, Ext>
where
    Id: PartyId,
    Ext: RoundExtension<Id>,
{
    type Protocol = <Ext::Round as StaticRound<Id>>::Protocol;

    type DirectMessage = <Ext::Round as StaticRound<Id>>::DirectMessage;
    type NormalBroadcast = <Ext::Round as StaticRound<Id>>::NormalBroadcast;
    type EchoBroadcast = <Ext::Round as StaticRound<Id>>::EchoBroadcast;

    type Payload = <Ext::Round as StaticRound<Id>>::Payload;
    type Artifact = <Ext::Round as StaticRound<Id>>::Artifact;

    fn transition_info(&self) -> TransitionInfo {
        self.round.transition_info()
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        self.round.communication_info()
    }

    fn receive_message(
        &self,
        from: &Id,
        message: StaticProtocolMessage<Id, Self>,
    ) -> Result<<Self as StaticRound<Id>>::Payload, ReceiveError<Id, <Self as StaticRound<Id>>::Protocol>> {
        self.round.receive_message(
            from,
            StaticProtocolMessage {
                echo_broadcast: message.echo_broadcast,
                normal_broadcast: message.normal_broadcast,
                direct_message: message.direct_message,
            },
        )
    }

    fn make_normal_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Option<Self::NormalBroadcast>, LocalError> {
        self.extension.make_normal_broadcast(rng, &self.round)
    }

    fn make_echo_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Option<Self::EchoBroadcast>, LocalError> {
        self.extension.make_echo_broadcast(rng, &self.round)
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: &Id,
    ) -> Result<Option<(Self::DirectMessage, Self::Artifact)>, LocalError> {
        self.extension.make_direct_message(rng, &self.round, destination)
    }

    fn finalize(
        self,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let outcome = self.extension.finalize(rng, self.round, payloads, artifacts)?;
        Ok(match outcome {
            FinalizeOutcome::Result(result) => FinalizeOutcome::Result(result),
            FinalizeOutcome::AnotherRound(round) => FinalizeOutcome::AnotherRound(wrap_round(round, self.extensions)),
        })
    }
}

pub trait DynRoundExtension<Id, P: Protocol<Id>>: 'static + Debug + Send + Sync + DynClone {
    fn extend_round(
        self: Box<Self>,
        round: BoxedRound<Id, P>,
        extensions: BTreeMap<TypeId, Box<dyn DynRoundExtension<Id, P>>>,
    ) -> Option<BoxedRound<Id, P>>;
}

#[derive(Debug, Clone)]
struct RoundExtensionWrapper<Ext>(Ext);

impl<Ext> RoundExtensionWrapper<Ext> {
    fn new(extension: Ext) -> Self {
        Self(extension)
    }
}

impl<Id, Ext> DynRoundExtension<Id, <Ext::Round as StaticRound<Id>>::Protocol> for RoundExtensionWrapper<Ext>
where
    Id: PartyId,
    Ext: RoundExtension<Id>,
{
    fn extend_round(
        self: Box<Self>,
        round: BoxedRound<Id, <Ext::Round as StaticRound<Id>>::Protocol>,
        extensions: BTreeMap<TypeId, Box<dyn DynRoundExtension<Id, <Ext::Round as StaticRound<Id>>::Protocol>>>,
    ) -> Option<BoxedRound<Id, <Ext::Round as StaticRound<Id>>::Protocol>> {
        let typed_round = round.downcast_static::<Ext::Round>().ok()?;
        let extended_round = ExtendedRound::<Id, Ext> {
            round: typed_round,
            extension: (*self).0,
            extensions,
        };
        Some(BoxedRound::new_static(extended_round))
    }
}

#[derive_where::derive_where(Debug)]
struct PassthroughRound<Id, P: Protocol<Id>> {
    round: BoxedRound<Id, P>,
    extensions: BTreeMap<TypeId, Box<dyn DynRoundExtension<Id, P>>>,
}

impl<Id, P> Round<Id> for PassthroughRound<Id, P>
where
    Id: PartyId,
    P: Protocol<Id>,
{
    type Protocol = P;

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let outcome = self.round.into_boxed().finalize(rng, payloads, artifacts)?;
        Ok(match outcome {
            FinalizeOutcome::Result(result) => FinalizeOutcome::Result(result),
            FinalizeOutcome::AnotherRound(round) => FinalizeOutcome::AnotherRound(wrap_round(round, self.extensions)),
        })
    }

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
        self.round.as_ref().make_direct_message(rng, format, destination)
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        self.round.as_ref().make_echo_broadcast(rng, format)
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        self.round.as_ref().make_normal_broadcast(rng, format)
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        self.round.as_ref().receive_message(format, from, message)
    }
}

fn wrap_round<Id: PartyId, P: Protocol<Id>>(
    round: BoxedRound<Id, P>,
    extensions: BTreeMap<TypeId, Box<dyn DynRoundExtension<Id, P>>>,
) -> BoxedRound<Id, P> {
    if let Some(extension) = extensions.get(&round.boxed_type_id()) {
        let extension = dyn_clone::clone_box(extension.as_ref());
        // This will only panic if the fetched element was previously added to `extensions` with a wrong key.
        extension
            .extend_round(round, extensions)
            .expect("RoundExtension's associated `Round` has a correct type")
    } else {
        BoxedRound::new_dynamic(PassthroughRound { round, extensions })
    }
}

/// A wrapper for a protocol's [`EntryPoint`], allowing registering [`RoundExtension`] implementors
/// to extend or override [`Round`] methods.
#[derive(Debug)]
pub struct ExtendableEntryPoint<Id: PartyId, EP: EntryPoint<Id>> {
    entry_point: EP,
    extensions: BTreeMap<TypeId, Box<dyn DynRoundExtension<Id, EP::Protocol>>>,
}

impl<Id, EP> ExtendableEntryPoint<Id, EP>
where
    Id: PartyId,
    EP: EntryPoint<Id>,
{
    /// Wraps an entry point making it extendable.
    pub fn new(entry_point: EP) -> Self {
        Self {
            entry_point,
            extensions: BTreeMap::new(),
        }
    }

    /// Registers an extension and returns the updated entry point.
    pub fn with_extension<Ext: RoundExtension<Id>>(self, extension: Ext) -> Self
    where
        Ext::Round: StaticRound<Id, Protocol = EP::Protocol>,
    {
        let mut entry_point = self;
        entry_point.extend(extension);
        entry_point
    }

    pub fn extend<Ext: RoundExtension<Id>>(&mut self, extension: Ext)
    where
        Ext::Round: StaticRound<Id, Protocol = EP::Protocol>,
    {
        let type_id = TypeId::of::<StaticRoundAdapter<Ext::Round>>();
        self.extensions
            .insert(type_id, Box::new(RoundExtensionWrapper::new(extension)));
    }
}

impl<Id, EP> EntryPoint<Id> for ExtendableEntryPoint<Id, EP>
where
    Id: PartyId,
    EP: EntryPoint<Id>,
{
    type Protocol = <EP as EntryPoint<Id>>::Protocol;
    fn entry_round_id() -> RoundId {
        EP::entry_round_id()
    }
    fn make_round(
        self,
        rng: &mut dyn CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let round = self.entry_point.make_round(rng, shared_randomness, id)?;
        Ok(wrap_round(round, self.extensions))
    }
}
