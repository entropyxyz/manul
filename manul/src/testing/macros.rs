use alloc::collections::BTreeMap;

use crate::round::{
    Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, Payload, Round,
};
use crate::LocalError;

pub trait RoundWrapper<Id>: 'static + Sized + Send + Sync {
    type InnerRound: Round<Id>;
    fn inner_round_ref(&self) -> &Self::InnerRound;
    fn inner_round(self) -> Self::InnerRound;
}

pub trait RoundOverride<Id>: RoundWrapper<Id> {
    fn make_direct_message(
        &self,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        self.inner_round_ref().make_direct_message(destination)
    }
    fn make_echo_broadcast(&self) -> Option<Result<EchoBroadcast, LocalError>> {
        self.inner_round_ref().make_echo_broadcast()
    }
    fn finalize(
        self: Box<Self>,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<
        FinalizeOutcome<Id, <<Self as RoundWrapper<Id>>::InnerRound as Round<Id>>::Protocol>,
        FinalizeError<Id, <<Self as RoundWrapper<Id>>::InnerRound as Round<Id>>::Protocol>,
    > {
        Box::new(self.inner_round()).finalize(payloads, artifacts)
    }
}

#[macro_export]
macro_rules! round_override {
    ($round: ident) => {
        impl<Id> Round<Id> for $round<Id>
        where
            $round<Id>: RoundOverride<Id>,
        {
            type Protocol =
                <<$round<Id> as $crate::testing::RoundWrapper<Id>>::InnerRound as $crate::Round<
                    Id,
                >>::Protocol;

            fn id(&self) -> $crate::RoundId {
                self.inner_round_ref().id()
            }

            fn possible_next_rounds(&self) -> ::alloc::collections::BTreeSet<$crate::RoundId> {
                self.inner_round_ref().possible_next_rounds()
            }

            fn message_destinations(&self) -> &::alloc::collections::BTreeSet<Id> {
                self.inner_round_ref().message_destinations()
            }

            fn make_direct_message(
                &self,
                destination: &Id,
            ) -> Result<($crate::DirectMessage, $crate::Artifact), $crate::LocalError> {
                <Self as $crate::testing::RoundOverride<Id>>::make_direct_message(self, destination)
            }

            fn make_echo_broadcast(
                &self,
            ) -> Option<Result<$crate::EchoBroadcast, $crate::LocalError>> {
                <Self as $crate::testing::RoundOverride<Id>>::make_echo_broadcast(self)
            }

            fn receive_message(
                &self,
                from: &Id,
                echo_broadcast: Option<$crate::EchoBroadcast>,
                direct_message: $crate::DirectMessage,
            ) -> Result<$crate::Payload, $crate::ReceiveError<Id, Self::Protocol>> {
                self.inner_round_ref()
                    .receive_message(from, echo_broadcast, direct_message)
            }

            fn finalize(
                self: Box<Self>,
                payloads: ::alloc::collections::BTreeMap<Id, $crate::Payload>,
                artifacts: ::alloc::collections::BTreeMap<Id, $crate::Artifact>,
            ) -> Result<
                $crate::FinalizeOutcome<Id, Self::Protocol>,
                $crate::FinalizeError<Id, Self::Protocol>,
            > {
                <Self as RoundOverride<Id>>::finalize(self, payloads, artifacts)
            }

            // Do we need to take `artifacts` here? Can we just judge by payloads?
            fn can_finalize(
                &self,
                payloads: &::alloc::collections::BTreeMap<Id, $crate::Payload>,
                artifacts: &::alloc::collections::BTreeMap<Id, $crate::Artifact>,
            ) -> bool {
                self.inner_round_ref().can_finalize(payloads, artifacts)
            }
        }
    };
}

pub use round_override;
