use alloc::collections::BTreeMap;
use core::fmt::Debug;

use serde::Deserialize;

use crate::echo::EchoRoundMessage;
use crate::error::LocalError;
use crate::message::{MessageVerificationError, SignedMessage};
use crate::round::{
    DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError, MessageValidationError,
    ProtocolError,
};
use crate::transcript::Transcript;
use crate::{DigestVerifier, Protocol, ProtocolValidationError, RoundId};

#[derive(Debug, Clone)]
pub enum EvidenceError {
    Local(LocalError),
    InvalidEvidence(String),
}

impl From<MessageVerificationError> for EvidenceError {
    fn from(error: MessageVerificationError) -> Self {
        match error {
            MessageVerificationError::Local(error) => Self::Local(error),
            MessageVerificationError::InvalidSignature => {
                Self::InvalidEvidence("Invalid message signature".into())
            }
        }
    }
}

impl From<DirectMessageError> for EvidenceError {
    fn from(error: DirectMessageError) -> Self {
        Self::InvalidEvidence(format!("Failed to deserialize direct message: {:?}", error))
    }
}

impl From<MessageValidationError> for EvidenceError {
    fn from(error: MessageValidationError) -> Self {
        match error {
            MessageValidationError::Local(error) => Self::Local(error),
            MessageValidationError::Other(error) => Self::InvalidEvidence(error),
        }
    }
}

impl From<ProtocolValidationError> for EvidenceError {
    fn from(error: ProtocolValidationError) -> Self {
        match error {
            ProtocolValidationError::Local(error) => Self::Local(error),
            ProtocolValidationError::Other(error) => Self::InvalidEvidence(error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Evidence<P: Protocol, Verifier, S> {
    party: Verifier, // TOOD: should it be saved here?
    evidence: EvidenceEnum<P, S>,
}

impl<P, Verifier, S> Evidence<P, Verifier, S>
where
    P: Protocol,
    Verifier: Debug + Clone + Ord + for<'de> Deserialize<'de> + DigestVerifier<P::Digest, S>,
    S: Debug + Clone + for<'de> Deserialize<'de>,
{
    pub(crate) fn new_protocol_error(
        verifier: &Verifier,
        echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
        direct_message: SignedMessage<S, DirectMessage>,
        error: P::ProtocolError,
        transcript: &Transcript<P, Verifier, S>,
    ) -> Result<Self, LocalError> {
        let echo_broadcasts = error
            .required_echo_broadcasts()
            .iter()
            .map(|round_id| {
                transcript
                    .get_echo_broadcast(*round_id, verifier)
                    .map(|echo| (*round_id, echo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let direct_messages = error
            .required_direct_messages()
            .iter()
            .map(|round_id| {
                transcript
                    .get_direct_message(*round_id, verifier)
                    .map(|dm| (*round_id, dm))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let combined_echos = error
            .required_combined_echos()
            .iter()
            .map(|round_id| {
                transcript
                    .get_direct_message(round_id.echo(), verifier)
                    .map(|dm| (*round_id, dm))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Self {
            party: verifier.clone(),
            evidence: EvidenceEnum::Protocol(ProtocolEvidence {
                error,
                direct_message,
                echo_broadcast,
                direct_messages,
                echo_broadcasts,
                combined_echos,
            }),
        })
    }

    pub(crate) fn new_invalid_direct_message(
        verifier: &Verifier,
        round_id: RoundId,
        direct_message: SignedMessage<S, DirectMessage>,
        error: DirectMessageError,
    ) -> Self {
        Self {
            party: verifier.clone(),
            evidence: EvidenceEnum::InvalidDirectMessage(InvalidDirectMessageEvidence {
                round_id,
                direct_message,
                error,
                phantom: core::marker::PhantomData,
            }),
        }
    }

    pub(crate) fn new_invalid_echo_broadcast(
        message: SignedMessage<S, EchoBroadcast>,
        error: EchoBroadcastError,
    ) -> Self {
        unimplemented!()
    }

    pub fn verify(&self, party: &Verifier) -> Result<(), EvidenceError> {
        match &self.evidence {
            EvidenceEnum::Protocol(evidence) => evidence.verify(party),
            EvidenceEnum::InvalidDirectMessage(evidence) => evidence.verify(party),
        }
    }
}

#[derive(Debug, Clone)]
enum EvidenceEnum<P: Protocol, S> {
    Protocol(ProtocolEvidence<P, S>),
    InvalidDirectMessage(InvalidDirectMessageEvidence<P, S>),
}

#[derive(Debug, Clone)]
pub struct InvalidDirectMessageEvidence<P: Protocol, S> {
    round_id: RoundId,
    direct_message: SignedMessage<S, DirectMessage>,
    error: DirectMessageError,
    phantom: core::marker::PhantomData<P>,
}

impl<P, S> InvalidDirectMessageEvidence<P, S>
where
    P: Protocol,
    S: Clone,
{
    fn verify<Verifier>(&self, verifier: &Verifier) -> Result<(), EvidenceError>
    where
        Verifier: Debug + Clone + DigestVerifier<P::Digest, S>,
    {
        let verified_direct_message = self.direct_message.clone().verify::<P, _>(verifier)?;
        Ok(P::verify_direct_message_is_invalid(
            self.round_id,
            verified_direct_message.payload(),
        )?)
    }
}

#[derive(Debug, Clone)]
struct ProtocolEvidence<P: Protocol, S> {
    error: P::ProtocolError,
    direct_message: SignedMessage<S, DirectMessage>,
    echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
    direct_messages: BTreeMap<RoundId, SignedMessage<S, DirectMessage>>,
    echo_broadcasts: BTreeMap<RoundId, SignedMessage<S, EchoBroadcast>>,
    combined_echos: BTreeMap<RoundId, SignedMessage<S, DirectMessage>>,
}

impl<P, S> ProtocolEvidence<P, S>
where
    P: Protocol,
    S: Clone + for<'de> Deserialize<'de>,
{
    fn verify<Verifier>(&self, verifier: &Verifier) -> Result<(), EvidenceError>
    where
        Verifier: Debug + Clone + Ord + for<'de> Deserialize<'de> + DigestVerifier<P::Digest, S>,
    {
        let verified_direct_message = self
            .direct_message
            .clone()
            .verify::<P, _>(verifier)?
            .payload()
            .clone();

        let mut verified_direct_messages = BTreeMap::new();
        for (round_id, direct_message) in self.direct_messages.iter() {
            let verified_direct_message = direct_message.clone().verify::<P, _>(verifier)?;
            verified_direct_messages.insert(*round_id, verified_direct_message.payload().clone());
        }

        let verified_echo_broadcast = if let Some(echo) = self.echo_broadcast.as_ref() {
            Some(echo.clone().verify::<P, _>(verifier)?.payload().clone())
        } else {
            None
        };

        let mut verified_echo_broadcasts = BTreeMap::new();
        for (round_id, echo_broadcast) in self.echo_broadcasts.iter() {
            let verified_echo_broadcast = echo_broadcast.clone().verify::<P, _>(verifier)?;
            verified_echo_broadcasts.insert(*round_id, verified_echo_broadcast.payload().clone());
        }

        let mut combined_echos = BTreeMap::new();
        for (round_id, combined_echo) in self.combined_echos.iter() {
            let verified_combined_echo = combined_echo.clone().verify::<P, _>(verifier)?;
            let echo_set = DirectMessage::try_deserialize::<P, EchoRoundMessage<Verifier, S>>(
                verified_combined_echo.payload(),
            )?;

            let mut verified_echo_set = Vec::new();
            for (other_verifier, echo_broadcast) in echo_set.echo_messages.iter() {
                let verified_echo_broadcast =
                    echo_broadcast.clone().verify::<P, _>(other_verifier)?;
                verified_echo_set.push(verified_echo_broadcast.payload().clone());
            }
            combined_echos.insert(*round_id, verified_echo_set);
        }

        Ok(self.error.verify_messages_constitute_error(
            &verified_echo_broadcast,
            &verified_direct_message,
            &verified_echo_broadcasts,
            &verified_direct_messages,
            &combined_echos,
        )?)
    }
}
