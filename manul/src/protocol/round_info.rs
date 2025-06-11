#![allow(dead_code, unused_variables, missing_docs)]

use alloc::boxed::Box;
use core::marker::PhantomData;

use super::{
    boxed_format::BoxedFormat,
    errors::MessageValidationError,
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePart},
    round::PartyId,
    round_id::TransitionInfo,
    static_round::{NoMessage, StaticRound},
};

trait RoundInfo<Id> {
    fn transition_info(&self) -> TransitionInfo;
    fn verify_direct_message_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError>;
    fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError>;
    fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError>;
}

pub(crate) struct StaticRoundInfoAdapter<R>(PhantomData<R>);

impl<Id, R> RoundInfo<Id> for StaticRoundInfoAdapter<R>
where
    Id: PartyId,
    R: StaticRound<Id>,
{
    fn transition_info(&self) -> TransitionInfo {
        R::transition_info()
    }

    fn verify_direct_message_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        if NoMessage::equals::<R::DirectMessage>() {
            message.verify_is_not::<R::DirectMessage>(format)
        } else {
            message.verify_is_some()
        }
    }

    fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        if NoMessage::equals::<R::EchoBroadcast>() {
            message.verify_is_not::<R::EchoBroadcast>(format)
        } else {
            message.verify_is_some()
        }
    }

    fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        if NoMessage::equals::<R::NormalBroadcast>() {
            message.verify_is_not::<R::NormalBroadcast>(format)
        } else {
            message.verify_is_some()
        }
    }
}

pub struct BoxedRoundInfo<Id>(Box<dyn RoundInfo<Id>>);

impl<Id> BoxedRoundInfo<Id> {
    pub fn new<R>() -> Self
    where
        Id: PartyId,
        R: StaticRound<Id>,
    {
        Self(Box::new(StaticRoundInfoAdapter(PhantomData::<R>)))
    }

    pub(crate) fn transition_info(&self) -> TransitionInfo {
        self.0.transition_info()
    }

    pub(crate) fn verify_direct_message_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        self.0.verify_direct_message_is_invalid(format, message)
    }

    pub(crate) fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        self.0.verify_echo_broadcast_is_invalid(format, message)
    }

    pub(crate) fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        self.0.verify_normal_broadcast_is_invalid(format, message)
    }
}
