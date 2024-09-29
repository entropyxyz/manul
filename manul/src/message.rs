use serde::{Deserialize, Serialize};

use crate::error::{Error, LocalError, RemoteError};
use crate::round::{DirectMessage, EchoBroadcast, RoundId};
use crate::signing::{Digest, DigestSigner, DigestVerifier};
use crate::Protocol;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage<S, M> {
    signature: S,
    message: MessageWithMetadata<M>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageWithMetadata<M> {
    round_id: RoundId,
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
        let message = MessageWithMetadata { round_id, message };
        let message_bytes = P::serialize(&message)?;
        let digest = P::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        let signature = signer
            .try_sign_digest(digest)
            .map_err(|err| LocalError::new(format!("Failed to sign: {:?}", err)))?;
        Ok(Self { signature, message })
    }

    pub fn verify<P: Protocol, Verifier>(
        self,
        verifier: &Verifier,
    ) -> Result<VerifiedMessage<S, M>, VerificationError<Verifier>>
    where
        Verifier: Clone + DigestVerifier<P::Digest, S>,
    {
        let message_bytes = P::serialize(&self.message).map_err(VerificationError::Local)?;
        let digest = P::Digest::new_with_prefix(b"SignedMessage").chain_update(message_bytes);
        if verifier.verify_digest(digest, &self.signature).is_ok() {
            Ok(VerifiedMessage {
                signature: self.signature,
                message: self.message,
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
    message: MessageWithMetadata<M>,
}

impl<S, M> VerifiedMessage<S, M> {
    pub fn round_id(&self) -> RoundId {
        self.message.round_id
    }

    pub fn payload(&self) -> &M {
        &self.message.message
    }

    pub fn into_unverified(self) -> SignedMessage<S, M> {
        SignedMessage {
            signature: self.signature,
            message: self.message,
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
        if !echo_broadcast
            .as_ref()
            .map(|echo| echo.round_id() == direct_message.round_id())
            .unwrap_or(true)
        {
            return Err(VerificationError::Remote(RemoteError::new(
                verifier.clone(),
                "Mismatched round IDs".into(),
            )));
        }
        Ok(VerifiedMessageBundle {
            from: verifier.clone(),
            direct_message,
            echo_broadcast,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedMessageBundle<Verifier, S> {
    from: Verifier,
    direct_message: VerifiedMessage<S, DirectMessage>,
    echo_broadcast: Option<VerifiedMessage<S, EchoBroadcast>>,
}

impl<Verifier, S> VerifiedMessageBundle<Verifier, S> {
    pub fn round_id(&self) -> RoundId {
        self.direct_message.round_id()
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
