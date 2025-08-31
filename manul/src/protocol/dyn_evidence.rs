use alloc::{boxed::Box, string::String};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};

use super::{
    errors::LocalError,
    evidence::{ProtocolError, RequiredMessages},
    round::Round,
    round_id::{GroupNum, RoundId},
    wire_format::{BoxedFormat, DeserializationError},
};

pub(crate) trait DynProtocolError<Id>: Debug {
    fn description(&self) -> String;
    fn serialize(self: Box<Self>, format: &BoxedFormat) -> Result<SerializedProtocolError, LocalError>;
}

impl<Id, T: ProtocolError<Id>> DynProtocolError<Id> for T {
    fn description(&self) -> String {
        self.description()
    }

    fn serialize(self: Box<Self>, format: &BoxedFormat) -> Result<SerializedProtocolError, LocalError> {
        format.serialize(*self).map(SerializedProtocolError)
    }
}

#[derive(Debug)]
pub(crate) struct BoxedProtocolError<Id> {
    required_messages: RequiredMessages,
    error: Box<dyn DynProtocolError<Id> + Send + Sync>,
}

impl<Id> BoxedProtocolError<Id> {
    pub fn new<R: Round<Id>>(error: R::ProtocolError, round_id: &RoundId) -> Self {
        let required_messages = error.required_messages(round_id);
        Self {
            required_messages,
            error: Box::new(error),
        }
    }

    pub fn as_ref(&self) -> &dyn DynProtocolError<Id> {
        self.error.as_ref()
    }

    pub fn into_inner(self) -> Box<dyn DynProtocolError<Id>> {
        self.error
    }

    pub fn group_under(self, group_num: GroupNum) -> Self {
        Self {
            required_messages: self.required_messages.group_under(group_num),
            error: self.error,
        }
    }

    pub fn required_messages(&self) -> &RequiredMessages {
        &self.required_messages
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SerializedProtocolError(#[serde(with = "SliceLike::<Base64>")] Box<[u8]>);

impl SerializedProtocolError {
    pub fn deserialize<Id, R: Round<Id>>(
        &self,
        format: &BoxedFormat,
    ) -> Result<R::ProtocolError, DeserializationError> {
        format.deserialize::<R::ProtocolError>(&self.0)
    }
}
