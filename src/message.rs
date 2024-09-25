use crate::error::RemoteError;
use crate::round::{DirectMessage, EchoBroadcast, RoundId};

#[derive(Debug, Clone)]
pub struct SignedMessage<I, M> {
    signature: I,
    message: MessageWithMetadata<M>,
}

impl<I: Clone, M> SignedMessage<I, M> {
    pub fn new(signer: &I, round_id: RoundId, message: M) -> Self {
        Self {
            signature: signer.clone(),
            message: MessageWithMetadata { round_id, message },
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessageWithMetadata<M> {
    round_id: RoundId,
    message: M,
}

impl<I: PartialEq, M> SignedMessage<I, M> {
    pub fn verify(self, id: &I) -> Result<VerifiedMessage<I, M>, RemoteError> {
        if &self.signature == id {
            Ok(VerifiedMessage {
                signature: self.signature,
                message: self.message,
            })
        } else {
            Err(RemoteError)
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedMessage<I, M> {
    signature: I,
    message: MessageWithMetadata<M>,
}

impl<I, M> VerifiedMessage<I, M> {
    pub fn round_id(&self) -> RoundId {
        self.message.round_id
    }

    pub fn payload(&self) -> &M {
        &self.message.message
    }

    pub fn into_unverified(self) -> SignedMessage<I, M> {
        SignedMessage {
            signature: self.signature,
            message: self.message,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MessageBundle<I> {
    direct_message: SignedMessage<I, DirectMessage>,
    echo_broadcast: Option<SignedMessage<I, EchoBroadcast>>,
}

impl<I: PartialEq + Clone> MessageBundle<I> {
    pub fn new(
        signer: &I,
        round_id: RoundId,
        direct_message: DirectMessage,
        echo_broadcast: Option<EchoBroadcast>,
    ) -> Self {
        let direct_message = SignedMessage::new(signer, round_id, direct_message);
        let echo_broadcast = echo_broadcast.map(|echo| SignedMessage::new(signer, round_id, echo));
        Self {
            direct_message,
            echo_broadcast,
        }
    }

    pub fn verify(self, id: &I) -> Result<VerifiedMessageBundle<I>, RemoteError> {
        let direct_message = self.direct_message.verify(id)?;
        let echo_broadcast = self
            .echo_broadcast
            .map(|echo| echo.verify(id))
            .transpose()?;
        if !echo_broadcast
            .as_ref()
            .map(|echo| echo.round_id() == direct_message.round_id())
            .unwrap_or(true)
        {
            return Err(RemoteError);
        }
        Ok(VerifiedMessageBundle {
            from: id.clone(),
            direct_message,
            echo_broadcast,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedMessageBundle<I> {
    from: I,
    direct_message: VerifiedMessage<I, DirectMessage>,
    echo_broadcast: Option<VerifiedMessage<I, EchoBroadcast>>,
}

impl<I> VerifiedMessageBundle<I> {
    pub fn round_id(&self) -> RoundId {
        self.direct_message.round_id()
    }

    pub fn from(&self) -> &I {
        &self.from
    }

    pub fn direct_message(&self) -> &DirectMessage {
        &self.direct_message.payload()
    }

    pub fn into_unverified(
        self,
    ) -> (
        Option<SignedMessage<I, EchoBroadcast>>,
        SignedMessage<I, DirectMessage>,
    ) {
        let direct_message = self.direct_message.into_unverified();
        let echo_broadcast = self.echo_broadcast.map(|echo| echo.into_unverified());
        (echo_broadcast, direct_message)
    }

    pub fn echo_broadcast(&self) -> Option<&EchoBroadcast> {
        self.echo_broadcast.as_ref().map(|echo| echo.payload())
    }
}
