use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};

use super::{
    errors::{DirectMessageError, EchoBroadcastError, LocalError, MessageValidationError},
    round::Protocol,
};

/// A serialized direct message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessagePayload(#[serde(with = "SliceLike::<Base64>")] Box<[u8]>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage(Option<DirectMessagePayload>);

impl DirectMessage {
    pub fn none() -> Self {
        Self(None)
    }

    /// Creates a new serialized direct message.
    pub fn new<P: Protocol, T: Serialize>(message: T) -> Result<Self, LocalError> {
        Ok(Self(Some(DirectMessagePayload(P::serialize(message)?))))
    }

    pub(crate) fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn assert_is_none(&self) -> Result<(), DirectMessageError> {
        if self.is_none() {
            Ok(())
        } else {
            Err(DirectMessageError::new("The expected direct message is missing"))
        }
    }

    /// Returns `Ok(())` if the message cannot be deserialized into `T`.
    ///
    /// This is intended to be used in the implementations of [`Protocol::verify_direct_message_is_invalid`].
    pub fn verify_is_invalid<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<(), MessageValidationError> {
        if self.deserialize::<P, T>().is_err() {
            Ok(())
        } else {
            Err(MessageValidationError::InvalidEvidence(
                "Message deserialized successfully".into(),
            ))
        }
    }

    /// Deserializes the direct message.
    pub fn deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<T, DirectMessageError> {
        let payload = self
            .0
            .as_ref()
            .ok_or_else(|| DirectMessageError::new("The direct message is missing in the payload"))?;
        P::deserialize(&payload.0).map_err(DirectMessageError::from)
    }
}

/// A serialized echo broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoBroadcastPayload(#[serde(with = "SliceLike::<Base64>")] Box<[u8]>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoBroadcast(Option<EchoBroadcastPayload>);

impl EchoBroadcast {
    pub fn none() -> Self {
        Self(None)
    }

    /// Creates a new serialized echo broadcast.
    pub fn new<P: Protocol, T: Serialize>(message: T) -> Result<Self, LocalError> {
        Ok(Self(Some(EchoBroadcastPayload(P::serialize(message)?))))
    }

    pub(crate) fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn assert_is_none(&self) -> Result<(), EchoBroadcastError> {
        if self.is_none() {
            Ok(())
        } else {
            Err(EchoBroadcastError::new("The expected echo broadcast is missing"))
        }
    }

    /// Returns `Ok(())` if the message cannot be deserialized into `T`.
    ///
    /// This is intended to be used in the implementations of [`Protocol::verify_direct_message_is_invalid`].
    pub fn verify_is_invalid<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<(), MessageValidationError> {
        if self.deserialize::<P, T>().is_err() {
            Ok(())
        } else {
            Err(MessageValidationError::InvalidEvidence(
                "Message deserialized successfully".into(),
            ))
        }
    }

    /// Deserializes the echo broadcast.
    pub fn deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<T, EchoBroadcastError> {
        let payload = self
            .0
            .as_ref()
            .ok_or_else(|| EchoBroadcastError::new("The direct message is missing in the payload"))?;
        P::deserialize(&payload.0).map_err(EchoBroadcastError::from)
    }
}
