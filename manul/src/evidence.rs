use alloc::collections::BTreeMap;
use core::fmt::Debug;

use serde::Deserialize;

use crate::echo::{EchoRoundError, EchoRoundMessage};
use crate::error::LocalError;
use crate::message::{MessageVerificationError, SignedMessage};
use crate::round::{
    DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError, MessageValidationError, ProtocolError,
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
            MessageVerificationError::InvalidSignature => Self::InvalidEvidence("Invalid message signature".into()),
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
    guilty_party: Verifier,
    description: String,
    evidence: EvidenceEnum<P, Verifier, S>,
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

        let description = format!("Protocol error: {:?}", error);

        Ok(Self {
            guilty_party: verifier.clone(),
            description,
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

    pub(crate) fn new_echo_round_error(
        verifier: &Verifier,
        direct_message: SignedMessage<S, DirectMessage>,
        error: EchoRoundError<Verifier>,
        transcript: &Transcript<P, Verifier, S>,
    ) -> Result<Self, LocalError> {
        let description = format!("{:?}", error);
        match error {
            EchoRoundError::InvalidEcho(from) => Ok(Self {
                guilty_party: verifier.clone(),
                description,
                evidence: EvidenceEnum::InvalidEchoPack(InvalidEchoPackEvidence {
                    direct_message,
                    invalid_echo_sender: from,
                    phantom: core::marker::PhantomData,
                }),
            }),
            EchoRoundError::InvalidBroadcast(from) => {
                // We could avoid all this if we attached the SignedMessage objects
                // directly to the error. But then it would have to be generic over `S`,
                // which the `Round` trait knows nothing about.
                let round_id = direct_message.metadata().round_id().non_echo();
                let we_received = transcript.get_echo_broadcast(round_id, &from)?;

                let deserialized = direct_message
                    .payload()
                    .try_deserialize::<P, EchoRoundMessage<Verifier, S>>()
                    .map_err(|error| {
                        LocalError::new(format!("Failed to deserialize the given direct message: {:?}", error))
                    })?;
                let echoed_to_us = deserialized.echo_messages.get(&from).ok_or_else(|| {
                    LocalError::new(format!(
                        "The echo message from {from:?} is missing from the echo packet"
                    ))
                })?;

                Ok(Self {
                    guilty_party: from,
                    description,
                    evidence: EvidenceEnum::MismatchedBroadcasts(MismatchedBroadcastsEvidence {
                        we_received,
                        echoed_to_us: echoed_to_us.clone(),
                        phantom: core::marker::PhantomData,
                    }),
                })
            }
        }
    }

    pub(crate) fn new_invalid_direct_message(
        verifier: &Verifier,
        direct_message: SignedMessage<S, DirectMessage>,
        error: DirectMessageError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: format!("{:?}", error),
            evidence: EvidenceEnum::InvalidDirectMessage(InvalidDirectMessageEvidence {
                direct_message,
                phantom: core::marker::PhantomData,
            }),
        }
    }

    pub(crate) fn new_invalid_echo_broadcast(
        verifier: &Verifier,
        echo_broadcast: SignedMessage<S, EchoBroadcast>,
        error: EchoBroadcastError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: format!("{:?}", error),
            evidence: EvidenceEnum::InvalidEchoBroadcast(InvalidEchoBroadcastEvidence {
                echo_broadcast,
                phantom: core::marker::PhantomData,
            }),
        }
    }

    pub fn guilty_party(&self) -> &Verifier {
        &self.guilty_party
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn verify(&self, party: &Verifier) -> Result<(), EvidenceError> {
        match &self.evidence {
            EvidenceEnum::Protocol(evidence) => evidence.verify(party),
            EvidenceEnum::InvalidDirectMessage(evidence) => evidence.verify(party),
            EvidenceEnum::InvalidEchoBroadcast(evidence) => evidence.verify(party),
            EvidenceEnum::InvalidEchoPack(evidence) => evidence.verify(party),
            EvidenceEnum::MismatchedBroadcasts(evidence) => evidence.verify(party),
        }
    }
}

#[derive(Debug, Clone)]
enum EvidenceEnum<P: Protocol, Verifier, S> {
    Protocol(ProtocolEvidence<P, S>),
    InvalidDirectMessage(InvalidDirectMessageEvidence<P, S>),
    InvalidEchoBroadcast(InvalidEchoBroadcastEvidence<P, S>),
    InvalidEchoPack(InvalidEchoPackEvidence<P, Verifier, S>),
    MismatchedBroadcasts(MismatchedBroadcastsEvidence<P, S>),
}

#[derive(Debug, Clone)]
pub struct InvalidEchoPackEvidence<P: Protocol, Verifier, S> {
    direct_message: SignedMessage<S, DirectMessage>,
    invalid_echo_sender: Verifier,
    phantom: core::marker::PhantomData<P>,
}

impl<P, Verifier, S> InvalidEchoPackEvidence<P, Verifier, S>
where
    P: Protocol,
    S: Clone + for<'de> Deserialize<'de>,
    Verifier: Debug + Clone + Ord + DigestVerifier<P::Digest, S> + for<'de> Deserialize<'de>,
{
    fn verify(&self, verifier: &Verifier) -> Result<(), EvidenceError> {
        let verified = self.direct_message.clone().verify::<P, _>(verifier)?;
        let deserialized = verified
            .payload()
            .try_deserialize::<P, EchoRoundMessage<Verifier, S>>()?;
        let invalid_echo = deserialized
            .echo_messages
            .get(&self.invalid_echo_sender)
            .ok_or_else(|| {
                EvidenceError::InvalidEvidence(format!(
                    "Did not find {:?} in the attached message",
                    self.invalid_echo_sender
                ))
            })?;

        let verified_echo = match invalid_echo.clone().verify::<P, _>(&self.invalid_echo_sender) {
            Ok(echo) => echo,
            Err(MessageVerificationError::Local(error)) => return Err(EvidenceError::Local(error)),
            // The message was indeed incorrectly signed - fault proven
            Err(MessageVerificationError::InvalidSignature) => return Ok(()),
        };

        // `from` sent us a correctly signed message but from another round or another session.
        // Provable fault of `from`.
        if verified_echo.metadata() != self.direct_message.metadata() {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "There is nothing wrong with the echoed message".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct MismatchedBroadcastsEvidence<P: Protocol, S> {
    we_received: SignedMessage<S, EchoBroadcast>,
    echoed_to_us: SignedMessage<S, EchoBroadcast>,
    phantom: core::marker::PhantomData<P>,
}

impl<P, S> MismatchedBroadcastsEvidence<P, S>
where
    P: Protocol,
    S: Clone,
{
    fn verify<Verifier>(&self, verifier: &Verifier) -> Result<(), EvidenceError>
    where
        Verifier: Debug + Clone + DigestVerifier<P::Digest, S>,
    {
        let we_received = self.we_received.clone().verify::<P, _>(verifier)?;
        let echoed_to_us = self.echoed_to_us.clone().verify::<P, _>(verifier)?;

        if we_received.metadata() == echoed_to_us.metadata() && we_received.payload() != echoed_to_us.payload() {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "The attached messages don't constitute malicious behavior".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct InvalidDirectMessageEvidence<P: Protocol, S> {
    direct_message: SignedMessage<S, DirectMessage>,
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
            self.direct_message.metadata().round_id(),
            verified_direct_message.payload(),
        )?)
    }
}

#[derive(Debug, Clone)]
pub struct InvalidEchoBroadcastEvidence<P: Protocol, S> {
    echo_broadcast: SignedMessage<S, EchoBroadcast>,
    phantom: core::marker::PhantomData<P>,
}

impl<P, S> InvalidEchoBroadcastEvidence<P, S>
where
    P: Protocol,
    S: Clone,
{
    fn verify<Verifier>(&self, verifier: &Verifier) -> Result<(), EvidenceError>
    where
        Verifier: Debug + Clone + DigestVerifier<P::Digest, S>,
    {
        let verified_echo_broadcast = self.echo_broadcast.clone().verify::<P, _>(verifier)?;
        Ok(P::verify_echo_broadcast_is_invalid(
            self.echo_broadcast.metadata().round_id(),
            verified_echo_broadcast.payload(),
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
        let session_id = self.direct_message.metadata().session_id();

        let verified_direct_message = self.direct_message.clone().verify::<P, _>(verifier)?.payload().clone();

        let mut verified_direct_messages = BTreeMap::new();
        for (round_id, direct_message) in self.direct_messages.iter() {
            let verified_direct_message = direct_message.clone().verify::<P, _>(verifier)?;
            let metadata = verified_direct_message.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_direct_messages.insert(*round_id, verified_direct_message.payload().clone());
        }

        let verified_echo_broadcast = if let Some(echo) = self.echo_broadcast.as_ref() {
            let metadata = echo.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != self.direct_message.metadata().round_id() {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            Some(echo.clone().verify::<P, _>(verifier)?.payload().clone())
        } else {
            None
        };

        let mut verified_echo_broadcasts = BTreeMap::new();
        for (round_id, echo_broadcast) in self.echo_broadcasts.iter() {
            let verified_echo_broadcast = echo_broadcast.clone().verify::<P, _>(verifier)?;
            let metadata = verified_echo_broadcast.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_echo_broadcasts.insert(*round_id, verified_echo_broadcast.payload().clone());
        }

        let mut combined_echos = BTreeMap::new();
        for (round_id, combined_echo) in self.combined_echos.iter() {
            let verified_combined_echo = combined_echo.clone().verify::<P, _>(verifier)?;
            let metadata = verified_combined_echo.metadata();
            if metadata.session_id() != session_id || metadata.round_id().non_echo() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            let echo_set =
                DirectMessage::try_deserialize::<P, EchoRoundMessage<Verifier, S>>(verified_combined_echo.payload())?;

            let mut verified_echo_set = Vec::new();
            for (other_verifier, echo_broadcast) in echo_set.echo_messages.iter() {
                let verified_echo_broadcast = echo_broadcast.clone().verify::<P, _>(other_verifier)?;
                let metadata = verified_echo_broadcast.metadata();
                if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                    return Err(EvidenceError::InvalidEvidence(
                        "Invalid attached message metadata".into(),
                    ));
                }
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
