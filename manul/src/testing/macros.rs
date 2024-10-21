use alloc::collections::BTreeMap;

use rand_core::CryptoRngCore;

use crate::protocol::{
    Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, LocalError, Payload, Round,
};

/// A trait defining a wrapper around an existing type implementing [`Round`].
pub trait RoundWrapper<Id>: 'static + Sized + Send + Sync {
    /// The inner round type.
    type InnerRound: Round<Id>;

    /// Returns a reference to the inner round.
    fn inner_round_ref(&self) -> &Self::InnerRound;

    /// Returns the inner round by value.
    fn inner_round(self) -> Self::InnerRound;
}

/// This trait defines overrides of some methods [`RoundWrapper::InnerRound`].
///
/// Intended to be used with [`round_override`] to generate the [`Round`] implementation.
///
/// The blanket implementations default to the methods of the wrapped round.
pub trait RoundOverride<Id>: RoundWrapper<Id> {
    /// An override for [`Round::make_direct_message`].
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        self.inner_round_ref().make_direct_message(rng, destination)
    }

    /// An override for [`Round::make_echo_broadcast`].
    fn make_echo_broadcast(&self, rng: &mut impl CryptoRngCore) -> Option<Result<EchoBroadcast, LocalError>> {
        self.inner_round_ref().make_echo_broadcast(rng)
    }

    /// An override for [`Round::finalize`].
    #[allow(clippy::type_complexity)]
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<
        FinalizeOutcome<Id, <<Self as RoundWrapper<Id>>::InnerRound as Round<Id>>::Protocol>,
        FinalizeError<<<Self as RoundWrapper<Id>>::InnerRound as Round<Id>>::Protocol>,
    > {
        self.inner_round().finalize(rng, payloads, artifacts)
    }
}

/// A macro for "inheriting" from a [`Round`]-implementing type, and overriding some of its behavior.
///
/// The given `$round` must implement [`RoundOverride`], and is generally some type
/// with one of its fiels implementing [`Round`].
/// Then, using the macro will implement [`Round`] for `$round` by delegating non-overridden methods to
/// the internal [`RoundWrapper::InnerRound`].
#[macro_export]
macro_rules! round_override {
    ($round: ident) => {
        impl<Id> Round<Id> for $round<Id>
        where
            $round<Id>: RoundOverride<Id>,
        {
            type Protocol =
                <<$round<Id> as $crate::testing::RoundWrapper<Id>>::InnerRound as $crate::protocol::Round<Id>>::Protocol;

            fn id(&self) -> $crate::protocol::RoundId {
                self.inner_round_ref().id()
            }

            fn possible_next_rounds(&self) -> ::alloc::collections::BTreeSet<$crate::protocol::RoundId> {
                self.inner_round_ref().possible_next_rounds()
            }

            fn message_destinations(&self) -> &::alloc::collections::BTreeSet<Id> {
                self.inner_round_ref().message_destinations()
            }

            fn make_direct_message(
                &self,
                rng: &mut impl CryptoRngCore,
                destination: &Id,
            ) -> Result<($crate::protocol::DirectMessage, $crate::protocol::Artifact), $crate::protocol::LocalError> {
                <Self as $crate::testing::RoundOverride<Id>>::make_direct_message(self, rng, destination)
            }

            fn make_echo_broadcast(
                &self,
                rng: &mut impl CryptoRngCore,
            ) -> Option<Result<$crate::protocol::EchoBroadcast, $crate::protocol::LocalError>> {
                <Self as $crate::testing::RoundOverride<Id>>::make_echo_broadcast(self, rng)
            }

            fn receive_message(
                &self,
                rng: &mut impl CryptoRngCore,
                from: &Id,
                echo_broadcast: Option<$crate::protocol::EchoBroadcast>,
                direct_message: $crate::protocol::DirectMessage,
            ) -> Result<$crate::protocol::Payload, $crate::protocol::ReceiveError<Id, Self::Protocol>> {
                self.inner_round_ref()
                    .receive_message(rng, from, echo_broadcast, direct_message)
            }

            fn finalize(
                self,
                rng: &mut impl CryptoRngCore,
                payloads: ::alloc::collections::BTreeMap<Id, $crate::protocol::Payload>,
                artifacts: ::alloc::collections::BTreeMap<Id, $crate::protocol::Artifact>,
            ) -> Result<
                    $crate::protocol::FinalizeOutcome<Id, Self::Protocol>,
                    $crate::protocol::FinalizeError<Self::Protocol>
            > {
                <Self as RoundOverride<Id>>::finalize(self, rng, payloads, artifacts)
            }

            fn expecting_messages_from(&self) -> &BTreeSet<Id> {
                self.inner_round_ref().expecting_messages_from()
            }
        }
    };
}

pub use round_override;
