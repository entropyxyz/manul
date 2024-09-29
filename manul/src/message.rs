use serde::{Deserialize, Serialize};

use crate::error::{Error, LocalError, RemoteError};
use crate::round::{DirectMessage, EchoBroadcast, RoundId};
use crate::signing::{Digest, DigestSigner, DigestVerifier};
use crate::Protocol;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage<S, M> {
    signature: S,
    message_with_metadata: MessageWithMetadata<M>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MessageMetadata {
    round_id: RoundId,
    // TODO: session ID
}

impl MessageMetadata {
    pub fn new(round_id: RoundId) -> Self {
        Self { round_id }
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

#[derive(Debug, Clone)]
pub enum VerificationError<Verifier> {
    Local(LocalError),
    Remote(RemoteError<Verifier>),
}

impl<Verifier> VerificationError<Verifier> {
    pub fn into_error<P: Protocol, S>(self) -> Error<P, Verifier, S> {
        match self {
            Self::Local(error) => Error::Local(error),
            Self::Remote(error) => Error::Remote(error),
        }
    }
}

impl<S, M> SignedMessage<S, M>
where
    M: Serialize,
{
    pub fn new<P: Protocol, Signer>(
        signer: &Signer,
        round_id: RoundId,
        message: M,
    ) -> Result<Self, LocalError>
    where
        Signer: DigestSigner<P::Digest, S>,
    {
        let metadata = MessageMetadata::new(round_id);
        let message_with_metadata = MessageWithMetadata { metadata, message };
        let message_bytes = P::serialize(&message_with_metadata)?;
        let digest = P::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        let signature = signer
            .try_sign_digest(digest)
            .map_err(|err| LocalError::new(format!("Failed to sign: {:?}", err)))?;
        Ok(Self {
            signature,
            message_with_metadata,
        })
    }

    pub(crate) fn metadata(&self) -> &MessageMetadata {
        &self.message_with_metadata.metadata
    }

    pub fn verify<P: Protocol, Verifier>(
        self,
        verifier: &Verifier,
    ) -> Result<VerifiedMessage<S, M>, VerificationError<Verifier>>
    where
        Verifier: Clone + DigestVerifier<P::Digest, S>,
    {
        let message_bytes =
            P::serialize(&self.message_with_metadata).map_err(VerificationError::Local)?;
        let digest = P::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        if verifier.verify_digest(digest, &self.signature).is_ok() {
            Ok(VerifiedMessage {
                signature: self.signature,
                message_with_metadata: self.message_with_metadata,
            })
        } else {
            Err(VerificationError::Remote(RemoteError::new(
                verifier.clone(),
                "Invalid signature".into(),
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedMessage<S, M> {
    signature: S,
    message_with_metadata: MessageWithMetadata<M>,
}

impl<S, M> VerifiedMessage<S, M> {
    pub fn round_id(&self) -> RoundId {
        self.message_with_metadata.metadata.round_id
    }

    pub fn payload(&self) -> &M {
        &self.message_with_metadata.message
    }

    pub fn into_unverified(self) -> SignedMessage<S, M> {
        SignedMessage {
            signature: self.signature,
            message_with_metadata: self.message_with_metadata,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MessageBundle<S> {
    direct_message: SignedMessage<S, DirectMessage>,
    echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
}

impl<S: PartialEq + Clone> MessageBundle<S> {
    pub fn new<P, Signer>(
        signer: &Signer,
        round_id: RoundId,
        direct_message: DirectMessage,
        echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
    ) -> Result<Self, LocalError>
    where
        P: Protocol,
        Signer: DigestSigner<P::Digest, S>,
    {
        let direct_message = SignedMessage::new::<P, _>(signer, round_id, direct_message)?;
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
    ) -> Result<VerifiedMessageBundle<Verifier, S>, VerificationError<Verifier>>
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

    pub fn from(&self) -> &Verifier {
        &self.from
    }

    pub fn direct_message(&self) -> &DirectMessage {
        &self.direct_message.payload()
    }

    pub fn into_unverified(
        self,
    ) -> (
        Option<SignedMessage<S, EchoBroadcast>>,
        SignedMessage<S, DirectMessage>,
    ) {
        let direct_message = self.direct_message.into_unverified();
        let echo_broadcast = self.echo_broadcast.map(|echo| echo.into_unverified());
        (echo_broadcast, direct_message)
    }

    pub fn echo_broadcast(&self) -> Option<&EchoBroadcast> {
        self.echo_broadcast.as_ref().map(|echo| echo.payload())
    }
}
