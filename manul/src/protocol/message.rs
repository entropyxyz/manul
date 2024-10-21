use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use super::{
    errors::{DirectMessageError, EchoBroadcastError, LocalError, MessageValidationError, NormalBroadcastError},
    Deserializer, Serializer,
};

mod private {
    use alloc::boxed::Box;
    use serde::{Deserialize, Serialize};
    use serde_encoded_bytes::{Base64, SliceLike};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MessagePayload(#[serde(with = "SliceLike::<Base64>")] pub Box<[u8]>);

    pub trait ProtocolMessageWrapper: Sized {
        fn new_inner(maybe_message: Option<MessagePayload>) -> Self;
        fn maybe_message(&self) -> &Option<MessagePayload>;
    }
}

use private::{MessagePayload, ProtocolMessageWrapper};

/// A serialized part of the protocol message.
///
/// These would usually be generated separately by the round, but delivered together to
/// [`Round::receive_message`](`crate::protocol::Round::receive_message`).
pub trait ProtocolMessagePart: ProtocolMessageWrapper {
    /// The error specific to deserializing this message.
    ///
    /// Used to distinguish which deserialization failed in
    /// [`Round::receive_message`](`crate::protocol::Round::receive_message`)
    /// and store the corresponding message in the evidence.
    type Error: From<String>;

    /// Creates an empty message.
    ///
    /// Use in case the round does not send a message of this type.
    fn none() -> Self {
        Self::new_inner(None)
    }

    /// Creates a new serialized message.
    fn new<T: Serialize>(serializer: &Serializer, message: T) -> Result<Self, LocalError> {
        let payload = MessagePayload(serializer.serialize(message)?);
        Ok(Self::new_inner(Some(payload)))
    }

    /// Returns `true` if this is an empty message.
    fn is_none(&self) -> bool {
        self.maybe_message().is_none()
    }

    /// Returns `Ok(())` if the message is indeed an empty message.
    fn assert_is_none(&self) -> Result<(), Self::Error> {
        if self.is_none() {
            Ok(())
        } else {
            Err("The payload was expected to contain a message, but is `None`"
                .to_string()
                .into())
        }
    }

    /// Returns `Ok(())` if the message cannot be deserialized into `T`.
    ///
    /// This is intended to be used in the implementations of
    /// [`Protocol::verify_direct_message_is_invalid`] or [`Protocol::verify_echo_broadcast_is_invalid`].
    fn verify_is_not<T: for<'de> Deserialize<'de>>(
        &self,
        deserializer: &Deserializer,
    ) -> Result<(), MessageValidationError> {
        if self.deserialize::<T>(deserializer).is_err() {
            Ok(())
        } else {
            Err(MessageValidationError::InvalidEvidence(
                "Message deserialized successfully, as expected by the protocol".into(),
            ))
        }
    }

    /// Returns `Ok(())` if the message contains a payload.
    ///
    /// This is intended to be used in the implementations of
    /// [`Protocol::verify_direct_message_is_invalid`] or [`Protocol::verify_echo_broadcast_is_invalid`].
    fn verify_is_some(&self) -> Result<(), MessageValidationError> {
        if self.maybe_message().is_some() {
            Ok(())
        } else {
            Err(MessageValidationError::InvalidEvidence(
                "The payload is `None`, as expected by the protocol".into(),
            ))
        }
    }

    /// Deserializes the message into `T`.
    fn deserialize<T: for<'de> Deserialize<'de>>(&self, deserializer: &Deserializer) -> Result<T, Self::Error> {
        let payload = self
            .maybe_message()
            .as_ref()
            .ok_or_else(|| "The payload is `None` and cannot be deserialized".into())?;
        deserializer
            .deserialize(&payload.0)
            .map_err(|err| err.to_string().into())
    }
}

/// A serialized direct message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectMessage(Option<MessagePayload>);

impl ProtocolMessageWrapper for DirectMessage {
    fn new_inner(maybe_message: Option<MessagePayload>) -> Self {
        Self(maybe_message)
    }

    fn maybe_message(&self) -> &Option<MessagePayload> {
        &self.0
    }
}

impl ProtocolMessagePart for DirectMessage {
    type Error = DirectMessageError;
}

/// A serialized echo broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoBroadcast(Option<MessagePayload>);

impl ProtocolMessageWrapper for EchoBroadcast {
    fn new_inner(maybe_message: Option<MessagePayload>) -> Self {
        Self(maybe_message)
    }

    fn maybe_message(&self) -> &Option<MessagePayload> {
        &self.0
    }
}

impl ProtocolMessagePart for EchoBroadcast {
    type Error = EchoBroadcastError;
}

/// A serialized regular (non-echo) broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalBroadcast(Option<MessagePayload>);

impl ProtocolMessageWrapper for NormalBroadcast {
    fn new_inner(maybe_message: Option<MessagePayload>) -> Self {
        Self(maybe_message)
    }

    fn maybe_message(&self) -> &Option<MessagePayload> {
        &self.0
    }
}

impl ProtocolMessagePart for NormalBroadcast {
    type Error = NormalBroadcastError;
}
