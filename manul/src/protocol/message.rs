use alloc::{
    boxed::Box,
    string::{String, ToString},
};

use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};

use super::wire_format::BoxedFormat;
use crate::protocol::{EvidenceError, LocalError, NoMessage, NoType};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MessagePayload(#[serde(with = "SliceLike::<Base64>")] pub Box<[u8]>);

impl AsRef<[u8]> for MessagePayload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A serialized part of the protocol message.
///
/// These would usually be generated separately by the round, but delivered together to
/// [`Round::receive_message`](`crate::protocol::Round::receive_message`).
pub(crate) trait ProtocolMessagePart: Sized {
    /// The error specific to deserializing this message.
    ///
    /// Used to distinguish which deserialization failed in
    /// [`Round::receive_message`](`crate::protocol::Round::receive_message`)
    /// and store the corresponding message in the evidence.
    type Error: From<String>;

    // Alternatively, we could not use an `Option`, but instead just serialize `NoMessage`.
    // Since it produces the same serialization as any other empty type, and the user may use one of those
    // as a message part type, there would be a possibility of a false positive on deserialization.
    // So it's safer to make `NoMessage` a special case of empty message.
    fn new_inner(maybe_message: Option<MessagePayload>) -> Self;

    fn maybe_message(&self) -> &Option<MessagePayload>;

    /// Creates an empty message.
    ///
    /// Use in case the round does not send a message of this type.
    fn none() -> Self {
        Self::new_inner(None)
    }

    /// Creates a new serialized message.
    fn new<T>(format: &BoxedFormat, message: T) -> Result<Self, LocalError>
    where
        T: 'static + Serialize,
    {
        Ok(if NoMessage::equals::<T>() {
            Self::none()
        } else {
            Self::new_inner(Some(MessagePayload(format.serialize(message)?)))
        })
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
            Err("The payload was expected to be `None`, but contains a message"
                .to_string()
                .into())
        }
    }

    /// Returns `Ok(())` if the message cannot be deserialized into `T`.
    ///
    /// This is intended to be used in the implementations of
    /// [`Protocol::verify_direct_message_is_invalid`](`crate::protocol::Protocol::verify_direct_message_is_invalid`) or
    /// [`Protocol::verify_echo_broadcast_is_invalid`](`crate::protocol::Protocol::verify_echo_broadcast_is_invalid`).
    fn verify_is_not<'de, T: 'static + Deserialize<'de>>(&'de self, format: &BoxedFormat) -> Result<(), EvidenceError> {
        if self.deserialize::<T>(format).is_err() {
            Ok(())
        } else {
            Err(EvidenceError::InvalidEvidence(
                "Message deserialized successfully, as expected by the protocol".into(),
            ))
        }
    }

    /// Returns `Ok(())` if the message contains a payload.
    ///
    /// This is intended to be used in the implementations of
    /// [`Protocol::verify_direct_message_is_invalid`](`crate::protocol::Protocol::verify_direct_message_is_invalid`) or
    /// [`Protocol::verify_echo_broadcast_is_invalid`](`crate::protocol::Protocol::verify_echo_broadcast_is_invalid`).
    fn verify_is_some(&self) -> Result<(), EvidenceError> {
        if self.maybe_message().is_some() {
            Ok(())
        } else {
            Err(EvidenceError::InvalidEvidence(
                "The payload is `None`, as expected by the protocol".into(),
            ))
        }
    }

    /// Deserializes the message into `T`.
    fn deserialize<'de, T>(&'de self, format: &BoxedFormat) -> Result<T, Self::Error>
    where
        T: 'static + Deserialize<'de>,
    {
        match (self.maybe_message().as_ref(), NoMessage::new_if_equals::<T>()) {
            (Some(payload), None) => format.deserialize(&payload.0).map_err(|err| err.to_string().into()),
            (None, Some(no_message)) => Ok(no_message),
            (Some(_payload), Some(_no_message)) => Err("Got a non-empty payload when no message part was expected"
                .to_string()
                .into()),
            (None, None) => Err("Got an empty payload when a message part was expected"
                .to_string()
                .into()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum PartKind {
    EchoBroadcast,
    NormalBroadcast,
    DirectMessage,
}

pub(crate) trait HasPartKind {
    const KIND: PartKind;
}

// We don't want to expose this functionality to the user, so it is separate from `ProtocolMessagePart` trait.
pub(crate) trait ProtocolMessagePartHashable: ProtocolMessagePart + HasPartKind {
    fn hash<D: Digest>(&self) -> digest::Output<D> {
        let mut digest = D::new_with_prefix(b"ProtocolMessagePart");
        match Self::KIND {
            PartKind::EchoBroadcast => digest.update([0u8]),
            PartKind::NormalBroadcast => digest.update([1u8]),
            PartKind::DirectMessage => digest.update([2u8]),
        }
        match self.maybe_message().as_ref() {
            None => digest.update([0u8]),
            Some(payload) => {
                let payload_len =
                    u64::try_from(payload.as_ref().len()).expect("payload length does not exceed 18 exabytes");
                digest.update([1u8]);
                digest.update(payload_len.to_be_bytes());
                digest.update(payload);
            }
        };
        digest.finalize()
    }
}

impl<T: ProtocolMessagePart + HasPartKind> ProtocolMessagePartHashable for T {}

/// A serialized direct message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectMessage(Option<MessagePayload>);

impl ProtocolMessagePart for DirectMessage {
    type Error = DirectMessageError;

    fn new_inner(maybe_message: Option<MessagePayload>) -> Self {
        Self(maybe_message)
    }

    fn maybe_message(&self) -> &Option<MessagePayload> {
        &self.0
    }
}

impl HasPartKind for DirectMessage {
    const KIND: PartKind = PartKind::DirectMessage;
}

/// A serialized echo broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EchoBroadcast(Option<MessagePayload>);

impl ProtocolMessagePart for EchoBroadcast {
    type Error = EchoBroadcastError;

    fn new_inner(maybe_message: Option<MessagePayload>) -> Self {
        Self(maybe_message)
    }

    fn maybe_message(&self) -> &Option<MessagePayload> {
        &self.0
    }
}

impl HasPartKind for EchoBroadcast {
    const KIND: PartKind = PartKind::EchoBroadcast;
}

/// A serialized regular (non-echo) broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NormalBroadcast(Option<MessagePayload>);

impl ProtocolMessagePart for NormalBroadcast {
    type Error = NormalBroadcastError;

    fn new_inner(maybe_message: Option<MessagePayload>) -> Self {
        Self(maybe_message)
    }

    fn maybe_message(&self) -> &Option<MessagePayload> {
        &self.0
    }
}

impl HasPartKind for NormalBroadcast {
    const KIND: PartKind = PartKind::NormalBroadcast;
}

/// A bundle containing the message parts for one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynProtocolMessage {
    /// The echo-broadcased message part.
    pub echo_broadcast: EchoBroadcast,
    /// The message part broadcasted without additional verification.
    pub normal_broadcast: NormalBroadcast,
    /// The message part sent directly to one node.
    pub direct_message: DirectMessage,
}

/// An error during deserialization of a direct message.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Direct message error: {0}")]
pub(crate) struct DirectMessageError(String);

impl From<String> for DirectMessageError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

/// An error during deserialization of an echo broadcast.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Echo broadcast error: {0}")]
pub(crate) struct EchoBroadcastError(String);

impl From<String> for EchoBroadcastError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

/// An error during deserialization of a normal broadcast.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Normal broadcast error: {0}")]
pub(crate) struct NormalBroadcastError(String);

impl From<String> for NormalBroadcastError {
    fn from(message: String) -> Self {
        Self(message)
    }
}
