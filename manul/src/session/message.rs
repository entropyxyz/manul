use alloc::format;

use digest::Digest;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::{DigestVerifier, RandomizedDigestSigner};

use super::{session::SessionId, LocalError};
use crate::protocol::{DirectMessage, EchoBroadcast, Protocol, RoundId};

#[derive(Debug, Clone)]
pub(crate) enum MessageVerificationError {
    Local(LocalError),
    InvalidSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedMessage<S, M> {
    signature: S,
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

impl<S, M> SignedMessage<S, M>
where
    M: Serialize,
{
    pub fn new<P: Protocol, Signer>(
        rng: &mut impl CryptoRngCore,
        signer: &Signer,
        session_id: &SessionId,
        round_id: RoundId,
        message: M,
    ) -> Result<Self, LocalError>
    where
        Signer: RandomizedDigestSigner<P::Digest, S>,
    {
        let metadata = MessageMetadata::new(session_id, round_id);
        let message_with_metadata = MessageWithMetadata { metadata, message };
        let message_bytes = P::serialize(&message_with_metadata)?;
        let digest = P::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        let signature = signer
            .try_sign_digest_with_rng(rng, digest)
            .map_err(|err| LocalError::new(format!("Failed to sign: {:?}", err)))?;
        Ok(Self {
            signature,
            message_with_metadata,
        })
    }

    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub(crate) fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub(crate) fn verify<P: Protocol, Verifier>(
        self,
        verifier: &Verifier,
    ) -> Result<VerifiedMessage<S, M>, MessageVerificationError>
    where
        Verifier: Clone + DigestVerifier<P::Digest, S>,
    {
        let message_bytes = P::serialize(&self.message_with_metadata).map_err(MessageVerificationError::Local)?;
        let digest = P::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        if verifier.verify_digest(digest, &self.signature).is_ok() {
            Ok(VerifiedMessage {
                signature: self.signature,
                message_with_metadata: self.message_with_metadata,
            })
        } else {
            Err(MessageVerificationError::InvalidSignature)
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedMessage<S, M> {
    signature: S,
    message_with_metadata: MessageWithMetadata<M>,
}

impl<S, M> VerifiedMessage<S, M> {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub(crate) fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub fn into_unverified(self) -> SignedMessage<S, M> {
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
pub struct MessageBundle<S> {
    direct_message: SignedMessage<S, DirectMessage>,
    echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
}

impl<S> MessageBundle<S>
where
    S: PartialEq + Clone,
{
    pub(crate) fn new<P, Signer>(
        rng: &mut impl CryptoRngCore,
        signer: &Signer,
        session_id: &SessionId,
        round_id: RoundId,
        direct_message: DirectMessage,
        echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
    ) -> Result<Self, LocalError>
    where
        P: Protocol,
        Signer: RandomizedDigestSigner<P::Digest, S>,
    {
        let direct_message = SignedMessage::new::<P, _>(rng, signer, session_id, round_id, direct_message)?;
        Ok(Self {
            direct_message,
            echo_broadcast,
        })
    }

    pub(crate) fn unify_metadata(self) -> Option<CheckedMessageBundle<S>> {
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
pub(crate) struct CheckedMessageBundle<S> {
    metadata: MessageMetadata,
    direct_message: SignedMessage<S, DirectMessage>,
    echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
}

impl<S> CheckedMessageBundle<S> {
    pub fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub fn verify<P: Protocol, Verifier>(
        self,
        verifier: &Verifier,
    ) -> Result<VerifiedMessageBundle<Verifier, S>, MessageVerificationError>
    where
        Verifier: Clone + DigestVerifier<P::Digest, S>,
    {
        let direct_message = self.direct_message.verify::<P, _>(verifier)?;
        let echo_broadcast = self
            .echo_broadcast
            .map(|echo| echo.verify::<P, _>(verifier))
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
pub struct VerifiedMessageBundle<Verifier, S> {
    from: Verifier,
    metadata: MessageMetadata,
    direct_message: VerifiedMessage<S, DirectMessage>,
    echo_broadcast: Option<VerifiedMessage<S, EchoBroadcast>>,
}

impl<Verifier, S> VerifiedMessageBundle<Verifier, S> {
    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.metadata
    }

    pub(crate) fn from(&self) -> &Verifier {
        &self.from
    }

    pub(crate) fn direct_message(&self) -> &DirectMessage {
        self.direct_message.payload()
    }

    pub(crate) fn into_unverified(self) -> (Option<SignedMessage<S, EchoBroadcast>>, SignedMessage<S, DirectMessage>) {
        let direct_message = self.direct_message.into_unverified();
        let echo_broadcast = self.echo_broadcast.map(|echo| echo.into_unverified());
        (echo_broadcast, direct_message)
    }

    pub(crate) fn echo_broadcast(&self) -> Option<&EchoBroadcast> {
        self.echo_broadcast.as_ref().map(|echo| echo.payload())
    }
}
