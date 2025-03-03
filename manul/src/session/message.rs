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
use crate::protocol::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePartHashable, RoundId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SerializedSignature(#[serde(with = "SliceLike::<Hex>")] Box<[u8]>);

impl SerializedSignature {
    pub fn new<SP>(signature: SP::Signature) -> Result<Self, LocalError>
    where
        SP: SessionParameters,
    {
        SP::WireFormat::serialize(signature).map(Self)
    }

    pub fn deserialize<SP>(&self) -> Result<SP::Signature, MessageVerificationError>
    where
        SP: SessionParameters,
    {
        SP::WireFormat::deserialize::<SP::Signature>(&self.0).map_err(|_| MessageVerificationError::InvalidSignature)
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

impl From<LocalError> for MessageVerificationError {
    fn from(source: LocalError) -> Self {
        Self::Local(source)
    }
}

impl From<signature::Error> for MessageVerificationError {
    fn from(_source: signature::Error) -> Self {
        Self::SignatureMismatch
    }
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
    pub fn new(session_id: &SessionId, round_id: &RoundId) -> Self {
        Self {
            session_id: session_id.clone(),
            round_id: round_id.clone(),
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn round_id(&self) -> &RoundId {
        &self.round_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageWithMetadata<M> {
    metadata: MessageMetadata,
    message: M,
}

fn message_digest<SP: SessionParameters>(
    metadata: &MessageMetadata,
    message_part_hash: &[u8],
) -> Result<SP::Digest, LocalError> {
    let message_part_hash_len =
        u64::try_from(message_part_hash.as_ref().len()).expect("message part hash length does not exceed 18 exabytes");
    Ok(SP::Digest::new_with_prefix(b"SignedMessagePartDigest")
        .chain_update(SP::WireFormat::serialize(metadata)?)
        .chain_update(message_part_hash_len.to_be_bytes())
        .chain_update(message_part_hash))
}

impl<M: ProtocolMessagePartHashable> MessageWithMetadata<M> {
    fn digest<SP>(&self) -> Result<SP::Digest, LocalError>
    where
        SP: SessionParameters,
    {
        let message_part_hash = self.message.hash::<SP::Digest>();
        let digest = message_digest::<SP>(&self.metadata, &message_part_hash)?;
        Ok(digest)
    }
}

impl<M> SignedMessagePart<M>
where
    M: ProtocolMessagePartHashable,
{
    pub fn new<SP>(
        rng: &mut impl CryptoRngCore,
        signer: &SP::Signer,
        session_id: &SessionId,
        round_id: &RoundId,
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

    pub(crate) fn to_signed_hash<SP>(&self) -> SignedMessageHash
    where
        SP: SessionParameters,
    {
        let message_part_hash = self.message_with_metadata.message.hash::<SP::Digest>();
        SignedMessageHash {
            signature: self.signature.clone(),
            metadata: self.message_with_metadata.metadata.clone(),
            message_part_hash: message_part_hash.as_ref().into(),
        }
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
        let digest = self.message_with_metadata.digest::<SP>()?;
        let signature = self.signature.deserialize::<SP>()?;
        verifier.verify_digest(digest, &signature)?;
        Ok(VerifiedMessagePart {
            signature: self.signature,
            message_with_metadata: self.message_with_metadata,
        })
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
        round_id: &RoundId,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedMessageHash {
    signature: SerializedSignature,
    metadata: MessageMetadata,
    #[serde(with = "SliceLike::<Hex>")]
    message_part_hash: Box<[u8]>,
}

impl SignedMessageHash {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub(crate) fn verify<SP>(self, verifier: &SP::Verifier) -> Result<VerifiedMessageHash, MessageVerificationError>
    where
        SP: SessionParameters,
    {
        let digest = message_digest::<SP>(&self.metadata, &self.message_part_hash)?;
        let signature = self.signature.deserialize::<SP>()?;
        verifier.verify_digest(digest, &signature)?;
        Ok(VerifiedMessageHash {
            signature: self.signature,
            metadata: self.metadata,
            message_part_hash: self.message_part_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedMessageHash {
    signature: SerializedSignature,
    metadata: MessageMetadata,
    message_part_hash: Box<[u8]>,
}

impl VerifiedMessageHash {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub(crate) fn is_hash_of<SP, M>(&self, message: &SignedMessagePart<M>) -> bool
    where
        SP: SessionParameters,
        M: ProtocolMessagePartHashable,
    {
        let message_part_hash = message.message_with_metadata.message.hash::<SP::Digest>();
        message_part_hash.as_ref() == self.message_part_hash.as_ref()
    }
}
