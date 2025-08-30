use alloc::{boxed::Box, collections::BTreeMap, format};
use core::{fmt::Debug, marker::PhantomData};

use super::{
    dyn_evidence::SerializedProtocolError,
    evidence::{EvidenceError, EvidenceMessages, EvidenceProtocolMessage, ProtocolError},
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePart},
    round::{NoMessage, NoType, Protocol, Round},
    round_id::RoundId,
    wire_format::BoxedFormat,
};

pub(crate) trait DynRoundInfo<Id>: Debug {
    type Protocol: Protocol<Id>;
    fn verify_direct_message_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &DirectMessage,
    ) -> Result<(), EvidenceError>;
    fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), EvidenceError>;
    fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), EvidenceError>;

    #[allow(clippy::too_many_arguments)]
    fn verify_evidence(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        error: &SerializedProtocolError,
        guilty_party: &Id,
        shared_randomness: &[u8],
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
        message: EvidenceProtocolMessage,
        previous_messages: BTreeMap<RoundId, EvidenceProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), EvidenceError>;
}

#[derive(Debug)]
struct RoundInfoObject<R>(PhantomData<fn() -> R>);

impl<Id, R> DynRoundInfo<Id> for RoundInfoObject<R>
where
    R: Round<Id>,
{
    type Protocol = R::Protocol;

    fn verify_direct_message_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &DirectMessage,
    ) -> Result<(), EvidenceError> {
        if NoMessage::equals::<R::DirectMessage>() {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::DirectMessage>(format)
        }
    }

    fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), EvidenceError> {
        if NoMessage::equals::<R::EchoBroadcast>() {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::EchoBroadcast>(format)
        }
    }

    fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), EvidenceError> {
        if NoMessage::equals::<R::NormalBroadcast>() {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::NormalBroadcast>(format)
        }
    }

    fn verify_evidence(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        error: &SerializedProtocolError,
        guilty_party: &Id,
        shared_randomness: &[u8],
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
        message: EvidenceProtocolMessage,
        previous_messages: BTreeMap<RoundId, EvidenceProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), EvidenceError> {
        let error = error.deserialize::<Id, R>(format).map_err(|err| {
            EvidenceError::InvalidEvidence(format!(
                "Cannot deserialize the error as {}: {err}",
                core::any::type_name::<R::ProtocolError>()
            ))
        })?;
        let evidence_messages = EvidenceMessages::new(format, message, previous_messages, combined_echos);
        error.verify_evidence(
            round_id,
            guilty_party,
            shared_randomness,
            shared_data,
            evidence_messages,
        )
    }
}

/// Type- and state-independent round metadata.
#[derive_where::derive_where(Debug)]
pub struct RoundInfo<Id, P: Protocol<Id> + ?Sized>(Box<dyn DynRoundInfo<Id, Protocol = P>>);

impl<Id, P> RoundInfo<Id, P>
where
    P: Protocol<Id>,
{
    /// Creates a new metadata object for a round of type `R`.
    pub fn new<R>() -> Self
    where
        R: Round<Id, Protocol = P>,
    {
        Self(Box::new(RoundInfoObject::<R>(PhantomData)))
    }

    pub(crate) fn new_obj(round: impl DynRoundInfo<Id, Protocol = P> + 'static) -> Self {
        Self(Box::new(round))
    }

    pub(crate) fn as_ref(&self) -> &dyn DynRoundInfo<Id, Protocol = P> {
        self.0.as_ref()
    }
}
