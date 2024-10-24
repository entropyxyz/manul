use alloc::{boxed::Box, format};

use digest::Digest;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};
use signature::{DigestVerifier, RandomizedDigestSigner};

use super::{
    format::Format,
    session::{SessionId, SessionParameters},
    LocalError,
};
use crate::protocol::{DeserializationError, Deserializer, DirectMessage, EchoBroadcast, RoundId, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SerializedSignature(#[serde(with = "SliceLike::<Hex>")] Box<[u8]>);

impl SerializedSignature {
    pub fn new<SP>(serializer: &Serializer, signature: SP::Signature) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        serializer.serialize(signature).map(Self)
    }

    pub fn deserialize<SP>(&self, deserializer: &Deserializer) -> Result<SP::Signature, DeserializationError>
    where
        SP: SessionParameters,
    {
        deserializer.deserialize::<SP::Signature>(&self.0)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum MessageVerificationError {
    Local(LocalError),
    /// The signature could not be deserialized.
    InvalidSignature,
    /// The signature does not match the signed payload.
    SignatureMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedMessage<M> {
    signature: SerializedSignature,
    message_with_metadata: MessageWithMetadata<M>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MessageMetadata {
    session_id: SessionId,
    round_id: RoundId,
}

impl MessageMetadata {
    pub fn new(session_id: &SessionId, round_id: RoundId) -> Self {
        Self {
            session_id: session_id.clone(),
            round_id,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn round_id(&self) -> RoundId {
        self.round_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageWithMetadata<M> {
    metadata: MessageMetadata,
    message: M,
}

impl<M> SignedMessage<M>
where
    M: Serialize,
{
    pub fn new<SP>(
        rng: &mut impl CryptoRngCore,
        signer: &SP::Signer,
        serializer: &Serializer,
        session_id: &SessionId,
        round_id: RoundId,
        message: M,
    ) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        let metadata = MessageMetadata::new(session_id, round_id);
        let message_with_metadata = MessageWithMetadata { metadata, message };
        let message_bytes = SP::Format::serialize(&message_with_metadata)?;
        let digest = SP::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        let signature = signer
            .try_sign_digest_with_rng(rng, digest)
            .map_err(|err| LocalError::new(format!("Failed to sign: {:?}", err)))?;
        Ok(Self {
            signature: SerializedSignature::new::<SP>(serializer, signature)?,
            message_with_metadata,
        })
    }

    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub(crate) fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub(crate) fn verify<SP>(
        self,
        verifier: &SP::Verifier,
        deserializer: &Deserializer,
    ) -> Result<VerifiedMessage<M>, MessageVerificationError>
    where
        SP: SessionParameters,
    {
        let message_bytes =
            SP::Format::serialize(&self.message_with_metadata).map_err(MessageVerificationError::Local)?;
        let digest = SP::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        let signature = self
            .signature
            .deserialize::<SP>(deserializer)
            .map_err(|_| MessageVerificationError::InvalidSignature)?;
        if verifier.verify_digest(digest, &signature).is_ok() {
            Ok(VerifiedMessage {
                signature: self.signature,
                message_with_metadata: self.message_with_metadata,
            })
        } else {
            Err(MessageVerificationError::SignatureMismatch)
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedMessage<M> {
    signature: SerializedSignature,
    message_with_metadata: MessageWithMetadata<M>,
}

impl<M> VerifiedMessage<M> {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub(crate) fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub fn into_unverified(self) -> SignedMessage<M> {
        SignedMessage {
            signature: self.signature,
            message_with_metadata: self.message_with_metadata,
        }
    }
}

/// A message bundle to be sent to another node.
///
/// Note that this is already signed.
#[derive(Clone, Debug)]
pub struct MessageBundle {
    direct_message: SignedMessage<DirectMessage>,
    echo_broadcast: Option<SignedMessage<EchoBroadcast>>,
}

impl MessageBundle {
    pub(crate) fn new<SP>(
        rng: &mut impl CryptoRngCore,
        signer: &SP::Signer,
        serializer: &Serializer,
        session_id: &SessionId,
        round_id: RoundId,
        direct_message: DirectMessage,
        echo_broadcast: Option<SignedMessage<EchoBroadcast>>,
    ) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        let direct_message = SignedMessage::new::<SP>(rng, signer, serializer, session_id, round_id, direct_message)?;
        Ok(Self {
            direct_message,
            echo_broadcast,
        })
    }

    pub(crate) fn unify_metadata(self) -> Option<CheckedMessageBundle> {
        let metadata = self.direct_message.message_with_metadata.metadata.clone();
        if !self
            .echo_broadcast
            .as_ref()
            .map(|echo| echo.metadata() == self.direct_message.metadata())
            .unwrap_or(true)
        {
            return None;
        }

        Some(CheckedMessageBundle {
            metadata,
            direct_message: self.direct_message,
            echo_broadcast: self.echo_broadcast,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CheckedMessageBundle {
    metadata: MessageMetadata,
    direct_message: SignedMessage<DirectMessage>,
    echo_broadcast: Option<SignedMessage<EchoBroadcast>>,
}

impl CheckedMessageBundle {
    pub fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub fn verify<SP>(
        self,
        verifier: &SP::Verifier,
        deserializer: &Deserializer,
    ) -> Result<VerifiedMessageBundle<SP>, MessageVerificationError>
    where
        SP: SessionParameters,
    {
        let direct_message = self.direct_message.verify::<SP>(verifier, deserializer)?;
        let echo_broadcast = self
            .echo_broadcast
            .map(|echo| echo.verify::<SP>(verifier, deserializer))
            .transpose()?;
        Ok(VerifiedMessageBundle {
            from: verifier.clone(),
            metadata: self.metadata,
            direct_message,
            echo_broadcast,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedMessageBundle<SP: SessionParameters> {
    from: SP::Verifier,
    metadata: MessageMetadata,
    direct_message: VerifiedMessage<DirectMessage>,
    echo_broadcast: Option<VerifiedMessage<EchoBroadcast>>,
}

impl<SP> VerifiedMessageBundle<SP>
where
    SP: SessionParameters,
{
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub(crate) fn from(&self) -> &SP::Verifier {
        &self.from
    }

    pub(crate) fn direct_message(&self) -> &DirectMessage {
        self.direct_message.payload()
    }

    pub(crate) fn into_unverified(self) -> (Option<SignedMessage<EchoBroadcast>>, SignedMessage<DirectMessage>) {
        let direct_message = self.direct_message.into_unverified();
        let echo_broadcast = self.echo_broadcast.map(|echo| echo.into_unverified());
        (echo_broadcast, direct_message)
    }

    pub(crate) fn echo_broadcast(&self) -> Option<&EchoBroadcast> {
        self.echo_broadcast.as_ref().map(|echo| echo.payload())
    }
}
