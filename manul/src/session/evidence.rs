use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::{
    echo::{EchoRoundError, EchoRoundMessage, MismatchedBroadcastsError},
    message::{MessageVerificationError, MissingMessage, SignedMessage},
    session::SessionParameters,
    transcript::Transcript,
    LocalError,
};
use crate::{
    protocol::{
        Deserializer, DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError, MessageValidationError,
        NormalBroadcast, NormalBroadcastError, Protocol, ProtocolError, ProtocolMessagePart, ProtocolValidationError,
        RoundId,
    },
    utils::SerializableMap,
};

/// Possible errors when verifying [`Evidence`] (evidence of malicious behavior).
#[derive(Debug, Clone)]
pub enum EvidenceError {
    /// Indicates a runtime problem or a bug in the code.
    Local(LocalError),
    /// The evidence is improperly constructed
    ///
    /// This can indicate many things, such as: messages missing, invalid signatures, invalid messages,
    /// the messages not actually proving the malicious behavior.
    /// See the attached description for details.
    InvalidEvidence(String),
}

// Other nodes would send a signed message with the payload being either Some(...) or None.
// We expect the messages in the evidence only be the Some(...) ones, so if it's not the case, it's invalid evidence.
// It's hard to enforce statically since we have to keep the signed messages as they were created by remote nodes.
impl From<MissingMessage> for EvidenceError {
    fn from(_error: MissingMessage) -> Self {
        Self::InvalidEvidence("The signed message is missing the expected payload".into())
    }
}

impl From<MessageVerificationError> for EvidenceError {
    fn from(error: MessageVerificationError) -> Self {
        match error {
            MessageVerificationError::Local(error) => Self::Local(error),
            MessageVerificationError::InvalidSignature => Self::InvalidEvidence("Invalid message signature".into()),
            MessageVerificationError::SignatureMismatch => {
                Self::InvalidEvidence("The signature does not match the payload".into())
            }
        }
    }
}

impl From<NormalBroadcastError> for EvidenceError {
    fn from(error: NormalBroadcastError) -> Self {
        Self::InvalidEvidence(format!("Failed to deserialize normal brroadcast: {:?}", error))
    }
}

impl From<MessageValidationError> for EvidenceError {
    fn from(error: MessageValidationError) -> Self {
        match error {
            MessageValidationError::Local(error) => Self::Local(error),
            MessageValidationError::InvalidEvidence(error) => Self::InvalidEvidence(error),
        }
    }
}

impl From<ProtocolValidationError> for EvidenceError {
    fn from(error: ProtocolValidationError) -> Self {
        match error {
            ProtocolValidationError::Local(error) => Self::Local(error),
            ProtocolValidationError::InvalidEvidence(error) => Self::InvalidEvidence(error),
        }
    }
}

/// A self-contained evidence of malicious behavior by a node.
#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct Evidence<P: Protocol, SP: SessionParameters> {
    guilty_party: SP::Verifier,
    description: String,
    evidence: EvidenceEnum<P, SP>,
}

impl<P, SP> Evidence<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    pub(crate) fn new_protocol_error(
        verifier: &SP::Verifier,
        echo_broadcast: SignedMessage<EchoBroadcast>,
        normal_broadcast: SignedMessage<NormalBroadcast>,
        direct_message: SignedMessage<DirectMessage>,
        error: P::ProtocolError,
        transcript: &Transcript<P, SP>,
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

        let normal_broadcasts = error
            .required_normal_broadcasts()
            .iter()
            .map(|round_id| {
                transcript
                    .get_normal_broadcast(*round_id, verifier)
                    .map(|bc| (*round_id, bc))
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
                    .get_normal_broadcast(round_id.echo(), verifier)
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
                normal_broadcast,
                direct_messages: direct_messages.into(),
                echo_broadcasts: echo_broadcasts.into(),
                normal_broadcasts: normal_broadcasts.into(),
                combined_echos: combined_echos.into(),
            }),
        })
    }

    pub(crate) fn new_echo_round_error(
        verifier: &SP::Verifier,
        normal_broadcast: SignedMessage<NormalBroadcast>,
        error: EchoRoundError<SP::Verifier>,
    ) -> Result<Self, LocalError> {
        let description = format!("{:?}", error);
        match error {
            EchoRoundError::InvalidEcho(from) => Ok(Self {
                guilty_party: verifier.clone(),
                description,
                evidence: EvidenceEnum::InvalidEchoPack(InvalidEchoPackEvidence {
                    normal_broadcast,
                    invalid_echo_sender: from,
                }),
            }),
            EchoRoundError::MismatchedBroadcasts {
                guilty_party,
                error,
                we_received,
                echoed_to_us,
            } => Ok(Self {
                guilty_party,
                description,
                evidence: EvidenceEnum::MismatchedBroadcasts(MismatchedBroadcastsEvidence {
                    error,
                    we_received,
                    echoed_to_us,
                }),
            }),
        }
    }

    pub(crate) fn new_invalid_direct_message(
        verifier: &SP::Verifier,
        direct_message: SignedMessage<DirectMessage>,
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
        verifier: &SP::Verifier,
        echo_broadcast: SignedMessage<EchoBroadcast>,
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

    pub(crate) fn new_invalid_normal_broadcast(
        verifier: &SP::Verifier,
        normal_broadcast: SignedMessage<NormalBroadcast>,
        error: NormalBroadcastError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: format!("{:?}", error),
            evidence: EvidenceEnum::InvalidNormalBroadcast(InvalidNormalBroadcastEvidence {
                normal_broadcast,
                phantom: core::marker::PhantomData,
            }),
        }
    }

    /// Returns the verifier of the offending party.
    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    /// Returns a general description of the offense.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Attempts to verify that the attached data constitutes enough evidence
    /// to prove the malicious behavior.
    ///
    /// Returns `Ok(())` if it is the case.
    pub fn verify(&self, party: &SP::Verifier) -> Result<(), EvidenceError> {
        let deserializer = Deserializer::new::<SP::WireFormat>();
        match &self.evidence {
            EvidenceEnum::Protocol(evidence) => evidence.verify::<SP>(party, &deserializer),
            EvidenceEnum::InvalidDirectMessage(evidence) => evidence.verify::<SP>(party, &deserializer),
            EvidenceEnum::InvalidEchoBroadcast(evidence) => evidence.verify::<SP>(party, &deserializer),
            EvidenceEnum::InvalidNormalBroadcast(evidence) => evidence.verify::<SP>(party),
            EvidenceEnum::InvalidEchoPack(evidence) => evidence.verify(party, &deserializer),
            EvidenceEnum::MismatchedBroadcasts(evidence) => evidence.verify::<SP>(party),
        }
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
enum EvidenceEnum<P: Protocol, SP: SessionParameters> {
    Protocol(ProtocolEvidence<P>),
    InvalidDirectMessage(InvalidDirectMessageEvidence<P>),
    InvalidEchoBroadcast(InvalidEchoBroadcastEvidence<P>),
    InvalidNormalBroadcast(InvalidNormalBroadcastEvidence<P>),
    InvalidEchoPack(InvalidEchoPackEvidence<SP>),
    MismatchedBroadcasts(MismatchedBroadcastsEvidence),
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct InvalidEchoPackEvidence<SP: SessionParameters> {
    normal_broadcast: SignedMessage<NormalBroadcast>,
    invalid_echo_sender: SP::Verifier,
}

impl<SP> InvalidEchoPackEvidence<SP>
where
    SP: SessionParameters,
{
    fn verify(&self, verifier: &SP::Verifier, deserializer: &Deserializer) -> Result<(), EvidenceError> {
        let verified = self.normal_broadcast.clone().verify::<SP>(verifier)?;
        let deserialized = verified.payload().deserialize::<EchoRoundMessage<SP>>(deserializer)?;
        let invalid_echo = deserialized
            .echo_broadcasts
            .get(&self.invalid_echo_sender)
            .ok_or_else(|| {
                EvidenceError::InvalidEvidence(format!(
                    "Did not find {:?} in the attached message",
                    self.invalid_echo_sender
                ))
            })?;

        let verified_echo = match invalid_echo.clone().verify::<SP>(&self.invalid_echo_sender) {
            Ok(echo) => echo,
            Err(MessageVerificationError::Local(error)) => return Err(EvidenceError::Local(error)),
            // The message was indeed incorrectly signed - fault proven
            Err(MessageVerificationError::InvalidSignature) => return Ok(()),
            Err(MessageVerificationError::SignatureMismatch) => return Ok(()),
        };

        // `from` sent us a correctly signed message but from another round or another session.
        // Provable fault of `from`.
        if verified_echo.metadata() != self.normal_broadcast.metadata() {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "There is nothing wrong with the echoed message".into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchedBroadcastsEvidence {
    error: MismatchedBroadcastsError,
    we_received: SignedMessage<EchoBroadcast>,
    echoed_to_us: SignedMessage<EchoBroadcast>,
}

impl MismatchedBroadcastsEvidence {
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let we_received = self.we_received.clone().verify::<SP>(verifier)?;
        let echoed_to_us = self.echoed_to_us.clone().verify::<SP>(verifier)?;

        if we_received.metadata() == echoed_to_us.metadata() && we_received.payload() != echoed_to_us.payload() {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "The attached messages don't constitute malicious behavior".into(),
        ))
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct InvalidDirectMessageEvidence<P: Protocol> {
    direct_message: SignedMessage<DirectMessage>,
    phantom: core::marker::PhantomData<P>,
}

impl<P> InvalidDirectMessageEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier, deserializer: &Deserializer) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let verified_direct_message = self.direct_message.clone().verify::<SP>(verifier)?;
        Ok(P::verify_direct_message_is_invalid(
            deserializer,
            self.direct_message.metadata().round_id(),
            verified_direct_message.payload(),
        )?)
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct InvalidEchoBroadcastEvidence<P: Protocol> {
    echo_broadcast: SignedMessage<EchoBroadcast>,
    phantom: core::marker::PhantomData<P>,
}

impl<P> InvalidEchoBroadcastEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier, deserializer: &Deserializer) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let verified_echo_broadcast = self.echo_broadcast.clone().verify::<SP>(verifier)?;
        Ok(P::verify_echo_broadcast_is_invalid(
            deserializer,
            self.echo_broadcast.metadata().round_id(),
            verified_echo_broadcast.payload(),
        )?)
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct InvalidNormalBroadcastEvidence<P: Protocol> {
    normal_broadcast: SignedMessage<NormalBroadcast>,
    phantom: core::marker::PhantomData<P>,
}

impl<P> InvalidNormalBroadcastEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let verified_normal_broadcast = self.normal_broadcast.clone().verify::<SP>(verifier)?;
        Ok(P::verify_normal_broadcast_is_invalid(
            self.normal_broadcast.metadata().round_id(),
            verified_normal_broadcast.payload(),
        )?)
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
struct ProtocolEvidence<P: Protocol> {
    error: P::ProtocolError,
    direct_message: SignedMessage<DirectMessage>,
    echo_broadcast: SignedMessage<EchoBroadcast>,
    normal_broadcast: SignedMessage<NormalBroadcast>,
    direct_messages: SerializableMap<RoundId, SignedMessage<DirectMessage>>,
    echo_broadcasts: SerializableMap<RoundId, SignedMessage<EchoBroadcast>>,
    normal_broadcasts: SerializableMap<RoundId, SignedMessage<NormalBroadcast>>,
    combined_echos: SerializableMap<RoundId, SignedMessage<NormalBroadcast>>,
}

impl<P> ProtocolEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier, deserializer: &Deserializer) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let session_id = self.direct_message.metadata().session_id();

        let verified_direct_message = self.direct_message.clone().verify::<SP>(verifier)?.payload().clone();

        let mut verified_direct_messages = BTreeMap::new();
        for (round_id, direct_message) in self.direct_messages.iter() {
            let verified_direct_message = direct_message.clone().verify::<SP>(verifier)?;
            let metadata = verified_direct_message.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_direct_messages.insert(*round_id, verified_direct_message.payload().clone());
        }

        let verified_echo_broadcast = self.echo_broadcast.clone().verify::<SP>(verifier)?.payload().clone();
        if self.echo_broadcast.metadata().session_id() != session_id
            || self.echo_broadcast.metadata().round_id() != self.direct_message.metadata().round_id()
        {
            return Err(EvidenceError::InvalidEvidence(
                "Invalid attached message metadata".into(),
            ));
        }

        let verified_normal_broadcast = self.normal_broadcast.clone().verify::<SP>(verifier)?.payload().clone();
        if self.normal_broadcast.metadata().session_id() != session_id
            || self.normal_broadcast.metadata().round_id() != self.direct_message.metadata().round_id()
        {
            return Err(EvidenceError::InvalidEvidence(
                "Invalid attached message metadata".into(),
            ));
        }

        let mut verified_echo_broadcasts = BTreeMap::new();
        for (round_id, echo_broadcast) in self.echo_broadcasts.iter() {
            let verified_echo_broadcast = echo_broadcast.clone().verify::<SP>(verifier)?;
            let metadata = verified_echo_broadcast.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_echo_broadcasts.insert(*round_id, verified_echo_broadcast.payload().clone());
        }

        let mut verified_normal_broadcasts = BTreeMap::new();
        for (round_id, normal_broadcast) in self.normal_broadcasts.iter() {
            let verified_normal_broadcast = normal_broadcast.clone().verify::<SP>(verifier)?;
            let metadata = verified_normal_broadcast.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_normal_broadcasts.insert(*round_id, verified_normal_broadcast.payload().clone());
        }

        let mut combined_echos = BTreeMap::new();
        for (round_id, combined_echo) in self.combined_echos.iter() {
            let verified_combined_echo = combined_echo.clone().verify::<SP>(verifier)?;
            let metadata = verified_combined_echo.metadata();
            if metadata.session_id() != session_id || metadata.round_id().non_echo() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            let echo_set = verified_combined_echo
                .payload()
                .deserialize::<EchoRoundMessage<SP>>(deserializer)?;

            let mut verified_echo_set = Vec::new();
            for (other_verifier, echo_broadcast) in echo_set.echo_broadcasts.iter() {
                let verified_echo_broadcast = echo_broadcast.clone().verify::<SP>(other_verifier)?;
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
            deserializer,
            &verified_echo_broadcast,
            &verified_normal_broadcast,
            &verified_direct_message,
            &verified_echo_broadcasts,
            &verified_normal_broadcasts,
            &verified_direct_messages,
            &combined_echos,
        )?)
    }
}
