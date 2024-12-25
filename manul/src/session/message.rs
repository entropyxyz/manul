use alloc::{boxed::Box, format};

use digest::Digest;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};
use signature::{DigestVerifier, RandomizedDigestSigner};

use super::{
    session::{SessionId, SessionParameters},
    wire_format::WireFormat,
    LocalError,
};
use crate::protocol::{
    DeserializationError, DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePart, RoundId,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SerializedSignature(#[serde(with = "SliceLike::<Hex>")] Box<[u8]>);

impl SerializedSignature {
    pub fn new<SP>(signature: SP::Signature) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        SP::WireFormat::serialize(signature).map(Self)
    }

    pub fn deserialize<SP>(&self) -> Result<SP::Signature, DeserializationError>
    where
        SP: SessionParameters,
    {
        SP::WireFormat::deserialize::<SP::Signature>(&self.0)
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
pub(crate) struct SignedMessagePart<M> {
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
        self.round_id.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageWithMetadata<M> {
    metadata: MessageMetadata,
    message: M,
}

impl<M: ProtocolMessagePart> MessageWithMetadata<M> {
    fn digest<SP>(&self) -> Result<SP::Digest, LocalError>
    where
        SP: SessionParameters,
    {
        let digest =
            SP::Digest::new_with_prefix(b"SignedMessagePart").chain_update(SP::WireFormat::serialize(&self.metadata)?);

        let digest = match self.message.maybe_message().as_ref() {
            None => digest.chain_update([0u8]),
            Some(payload) => digest.chain_update([1u8]).chain_update(payload),
        };

        Ok(digest)
    }
}

impl<M> SignedMessagePart<M>
where
    M: ProtocolMessagePart,
{
    pub fn new<SP>(
        rng: &mut impl CryptoRngCore,
        signer: &SP::Signer,
        session_id: &SessionId,
        round_id: RoundId,
        message: M,
    ) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        let metadata = MessageMetadata::new(session_id, round_id);
        let message_with_metadata = MessageWithMetadata { metadata, message };
        let digest = message_with_metadata.digest::<SP>()?;
        let signature = signer
            .try_sign_digest_with_rng(rng, digest)
            .map_err(|err| LocalError::new(format!("Failed to sign: {:?}", err)))?;
        Ok(Self {
            signature: SerializedSignature::new::<SP>(signature)?,
            message_with_metadata,
        })
    }

    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub(crate) fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub(crate) fn verify<SP>(self, verifier: &SP::Verifier) -> Result<VerifiedMessagePart<M>, MessageVerificationError>
    where
        SP: SessionParameters,
    {
        let digest = self
            .message_with_metadata
            .digest::<SP>()
            .map_err(MessageVerificationError::Local)?;
        let signature = self
            .signature
            .deserialize::<SP>()
            .map_err(|_| MessageVerificationError::InvalidSignature)?;
        if verifier.verify_digest(digest, &signature).is_ok() {
            Ok(VerifiedMessagePart {
                signature: self.signature,
                message_with_metadata: self.message_with_metadata,
            })
        } else {
            Err(MessageVerificationError::SignatureMismatch)
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedMessagePart<M> {
    signature: SerializedSignature,
    message_with_metadata: MessageWithMetadata<M>,
}

impl<M> VerifiedMessagePart<M> {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub(crate) fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub(crate) fn into_payload(self) -> M {
        self.message_with_metadata.message
    }

    pub fn into_unverified(self) -> SignedMessagePart<M> {
        SignedMessagePart {
            signature: self.signature,
            message_with_metadata: self.message_with_metadata,
        }
    }
}

/// A signed message destined for another node.
#[derive(Clone, Debug)]
pub struct Message<Verifier> {
    destination: Verifier,
    direct_message: SignedMessagePart<DirectMessage>,
    echo_broadcast: SignedMessagePart<EchoBroadcast>,
    normal_broadcast: SignedMessagePart<NormalBroadcast>,
}

impl<Verifier> Message<Verifier>
where
    Verifier: Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new<SP>(
        rng: &mut impl CryptoRngCore,
        signer: &SP::Signer,
        session_id: &SessionId,
        round_id: RoundId,
        destination: &Verifier,
        direct_message: DirectMessage,
        echo_broadcast: SignedMessagePart<EchoBroadcast>,
        normal_broadcast: SignedMessagePart<NormalBroadcast>,
    ) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        let direct_message = SignedMessagePart::new::<SP>(rng, signer, session_id, round_id, direct_message)?;
        Ok(Self {
            destination: destination.clone(),
            direct_message,
            echo_broadcast,
            normal_broadcast,
        })
    }

    /// The verifier of the party this message is intended for.
    pub fn destination(&self) -> &Verifier {
        &self.destination
    }

    pub(crate) fn unify_metadata(self) -> Option<CheckedMessage> {
        if self.echo_broadcast.metadata() != self.direct_message.metadata() {
            return None;
        }

        if self.normal_broadcast.metadata() != self.direct_message.metadata() {
            return None;
        }

        let metadata = self.direct_message.message_with_metadata.metadata.clone();
        Some(CheckedMessage {
            metadata,
            direct_message: self.direct_message,
            echo_broadcast: self.echo_broadcast,
            normal_broadcast: self.normal_broadcast,
        })
    }
}

/// A `CheckedMessage` is like a [`Message`] but where we have checked that the metadata
/// (i.e. SessionId and RoundId) from the Echo message (if any) matches with that of the
/// [`DirectMessage`].
/// `CheckedMessage`s can transition to [`VerifiedMessage`].
#[derive(Clone, Debug)]
pub(crate) struct CheckedMessage {
    metadata: MessageMetadata,
    direct_message: SignedMessagePart<DirectMessage>,
    echo_broadcast: SignedMessagePart<EchoBroadcast>,
    normal_broadcast: SignedMessagePart<NormalBroadcast>,
}

impl CheckedMessage {
    pub fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub fn verify<SP>(self, verifier: &SP::Verifier) -> Result<VerifiedMessage<SP::Verifier>, MessageVerificationError>
    where
        SP: SessionParameters,
    {
        let direct_message = self.direct_message.verify::<SP>(verifier)?;
        let echo_broadcast = self.echo_broadcast.verify::<SP>(verifier)?;
        let normal_broadcast = self.normal_broadcast.verify::<SP>(verifier)?;

        Ok(VerifiedMessage {
            from: verifier.clone(),
            metadata: self.metadata,
            direct_message,
            echo_broadcast,
            normal_broadcast,
        })
    }
}

// A `VerifiedMessage` is the final evolution of a [`Message`]. At this point in the
// process, the [`DirectMessage`] and an eventual [`EchoBroadcast`] have been fully checked and the
// signatures of message parts (direct, broadcast etc) from the original [`Message`] successfully verified.

/// A [`Message`] that had its metadata and signatures verified.
#[derive(Debug, Clone)]
pub struct VerifiedMessage<Verifier> {
    from: Verifier,
    metadata: MessageMetadata,
    direct_message: VerifiedMessagePart<DirectMessage>,
    echo_broadcast: VerifiedMessagePart<EchoBroadcast>,
    normal_broadcast: VerifiedMessagePart<NormalBroadcast>,
}

impl<Verifier> VerifiedMessage<Verifier> {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub(crate) fn from(&self) -> &Verifier {
        &self.from
    }

    pub(crate) fn direct_message(&self) -> &DirectMessage {
        self.direct_message.payload()
    }

    pub(crate) fn echo_broadcast(&self) -> &EchoBroadcast {
        self.echo_broadcast.payload()
    }

    pub(crate) fn normal_broadcast(&self) -> &NormalBroadcast {
        self.normal_broadcast.payload()
    }

    /// Split the `VerifiedMessage` into its signed constituent parts:
    /// the echo broadcast and the direct message.
    pub(crate) fn into_parts(
        self,
    ) -> (
        SignedMessagePart<EchoBroadcast>,
        SignedMessagePart<NormalBroadcast>,
        SignedMessagePart<DirectMessage>,
    ) {
        let direct_message = self.direct_message.into_unverified();
        let echo_broadcast = self.echo_broadcast.into_unverified();
        let normal_broadcast = self.normal_broadcast.into_unverified();
        (echo_broadcast, normal_broadcast, direct_message)
    }
}
