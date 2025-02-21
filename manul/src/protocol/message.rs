use alloc::string::{String, ToString};

use digest::Digest;
use serde::{Deserialize, Serialize};

use super::{
    errors::{DirectMessageError, EchoBroadcastError, LocalError, MessageValidationError, NormalBroadcastError},
    BoxedFormat,
};

mod private {
    use alloc::boxed::Box;
    use serde::{Deserialize, Serialize};
    use serde_encoded_bytes::{Base64, SliceLike};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MessagePayload(#[serde(with = "SliceLike::<Base64>")] pub Box<[u8]>);

    impl AsRef<[u8]> for MessagePayload {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

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
    fn new<T>(format: &BoxedFormat, message: T) -> Result<Self, LocalError>
    where
        T: 'static + Serialize,
    {
        let payload = MessagePayload(format.serialize(message)?);
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
    fn verify_is_not<'de, T: Deserialize<'de>>(&'de self, format: &BoxedFormat) -> Result<(), MessageValidationError> {
        if self.deserialize::<T>(format).is_err() {
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
    /// [`Protocol::verify_direct_message_is_invalid`](`crate::protocol::Protocol::verify_direct_message_is_invalid`) or
    /// [`Protocol::verify_echo_broadcast_is_invalid`](`crate::protocol::Protocol::verify_echo_broadcast_is_invalid`).
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
    fn deserialize<'de, T>(&'de self, format: &BoxedFormat) -> Result<T, Self::Error>
    where
        T: Deserialize<'de>,
    {
        let payload = self
            .maybe_message()
            .as_ref()
            .ok_or_else(|| "The payload is `None` and cannot be deserialized".into())?;
        format.deserialize(&payload.0).map_err(|err| err.to_string().into())
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
pub struct DirectMessage(Option<MessagePayload>);

impl ProtocolMessageWrapper for DirectMessage {
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

impl HasPartKind for EchoBroadcast {
    const KIND: PartKind = PartKind::EchoBroadcast;
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

impl HasPartKind for NormalBroadcast {
    const KIND: PartKind = PartKind::NormalBroadcast;
}

impl ProtocolMessagePart for NormalBroadcast {
    type Error = NormalBroadcastError;
}

/// A bundle containing the message parts for one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolMessage {
    /// The echo-broadcased message part.
    pub echo_broadcast: EchoBroadcast,
    /// The message part broadcasted without additional verification.
    pub normal_broadcast: NormalBroadcast,
    /// The message part sent directly to one node.
    pub direct_message: DirectMessage,
}
