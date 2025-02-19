use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::{
    echo::{EchoRound, EchoRoundError, EchoRoundMessage},
    message::{MessageVerificationError, SignedMessageHash, SignedMessagePart},
    session::{SessionId, SessionParameters},
    transcript::Transcript,
    LocalError,
};
use crate::{
    protocol::{
        BoxedFormat, DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError, MessageValidationError,
        NormalBroadcast, NormalBroadcastError, Protocol, ProtocolError, ProtocolMessage, ProtocolMessagePart,
        ProtocolMessagePartHashable, ProtocolValidationError, RoundId,
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
        Self::InvalidEvidence(format!("Failed to deserialize normal broadcast: {:?}", error))
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
pub struct Evidence<P: Protocol<SP::Verifier>, SP: SessionParameters> {
    guilty_party: SP::Verifier,
    description: String,
    evidence: EvidenceEnum<P, SP>,
}

impl<P, SP> Evidence<P, SP>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    pub(crate) fn new_protocol_error(
        verifier: &SP::Verifier,
        echo_broadcast: SignedMessagePart<EchoBroadcast>,
        normal_broadcast: SignedMessagePart<NormalBroadcast>,
        direct_message: SignedMessagePart<DirectMessage>,
        error: P::ProtocolError,
        transcript: &Transcript<P, SP>,
    ) -> Result<Self, LocalError> {
        let required_messages = error.required_messages();

        let echo_broadcast = if required_messages.this_round.echo_broadcast {
            Some(echo_broadcast)
        } else {
            None
        };
        let normal_broadcast = if required_messages.this_round.normal_broadcast {
            Some(normal_broadcast)
        } else {
            None
        };
        let direct_message = if required_messages.this_round.direct_message {
            Some(direct_message)
        } else {
            None
        };

        let mut echo_broadcasts = BTreeMap::new();
        let mut normal_broadcasts = BTreeMap::new();
        let mut direct_messages = BTreeMap::new();
        if let Some(previous_rounds) = required_messages.previous_rounds {
            for (round_id, required) in previous_rounds {
                if required.echo_broadcast {
                    echo_broadcasts.insert(round_id.clone(), transcript.get_echo_broadcast(&round_id, verifier)?);
                }
                if required.normal_broadcast {
                    normal_broadcasts.insert(round_id.clone(), transcript.get_normal_broadcast(&round_id, verifier)?);
                }
                if required.direct_message {
                    direct_messages.insert(round_id.clone(), transcript.get_direct_message(&round_id, verifier)?);
                }
            }
        }

        let mut echo_hashes = BTreeMap::new();
        let mut other_echo_broadcasts = BTreeMap::new();
        if let Some(required_combined_echos) = required_messages.combined_echos {
            for round_id in required_combined_echos {
                echo_hashes.insert(
                    round_id.clone(),
                    transcript.get_normal_broadcast(&round_id.echo()?, verifier)?,
                );
                other_echo_broadcasts.insert(
                    round_id.clone(),
                    transcript.get_other_echo_broadcasts(&round_id, verifier)?.into(),
                );
            }
        }

        let description = format!("Protocol error: {error}");

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
                other_echo_broadcasts: other_echo_broadcasts.into(),
                echo_hashes: echo_hashes.into(),
            }),
        })
    }

    pub(crate) fn new_echo_round_error(
        verifier: &SP::Verifier,
        normal_broadcast: SignedMessagePart<NormalBroadcast>,
        error: EchoRoundError<SP::Verifier>,
    ) -> Result<Self, LocalError> {
        let description = format!("Echo round error: {}", error.description());
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
                we_received,
                echoed_to_us,
            } => Ok(Self {
                guilty_party,
                description,
                evidence: EvidenceEnum::MismatchedBroadcasts(MismatchedBroadcastsEvidence {
                    we_received,
                    echoed_to_us,
                }),
            }),
        }
    }

    pub(crate) fn new_invalid_direct_message(
        verifier: &SP::Verifier,
        direct_message: SignedMessagePart<DirectMessage>,
        error: DirectMessageError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: error.to_string(),
            evidence: EvidenceEnum::InvalidDirectMessage(InvalidDirectMessageEvidence(direct_message)),
        }
    }

    pub(crate) fn new_invalid_echo_broadcast(
        verifier: &SP::Verifier,
        echo_broadcast: SignedMessagePart<EchoBroadcast>,
        error: EchoBroadcastError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: error.to_string(),
            evidence: EvidenceEnum::InvalidEchoBroadcast(InvalidEchoBroadcastEvidence(echo_broadcast)),
        }
    }

    pub(crate) fn new_invalid_normal_broadcast(
        verifier: &SP::Verifier,
        normal_broadcast: SignedMessagePart<NormalBroadcast>,
        error: NormalBroadcastError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: error.to_string(),
            evidence: EvidenceEnum::InvalidNormalBroadcast(InvalidNormalBroadcastEvidence(normal_broadcast)),
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
    /// to prove the malicious behavior of [`Self::guilty_party`].
    ///
    /// Returns `Ok(())` if it is the case.
    pub fn verify(
        &self,
        associated_data: &<P::ProtocolError as ProtocolError<SP::Verifier>>::AssociatedData,
    ) -> Result<(), EvidenceError> {
        let format = BoxedFormat::new::<SP::WireFormat>();
        match &self.evidence {
            EvidenceEnum::Protocol(evidence) => evidence.verify::<SP>(&self.guilty_party, &format, associated_data),
            EvidenceEnum::InvalidDirectMessage(evidence) => evidence.verify::<P, SP>(&self.guilty_party, &format),
            EvidenceEnum::InvalidEchoBroadcast(evidence) => evidence.verify::<P, SP>(&self.guilty_party, &format),
            EvidenceEnum::InvalidNormalBroadcast(evidence) => evidence.verify::<P, SP>(&self.guilty_party, &format),
            EvidenceEnum::InvalidEchoPack(evidence) => evidence.verify(&self.guilty_party, &format),
            EvidenceEnum::MismatchedBroadcasts(evidence) => evidence.verify::<SP>(&self.guilty_party),
        }
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
enum EvidenceEnum<P: Protocol<SP::Verifier>, SP: SessionParameters> {
    Protocol(ProtocolEvidence<SP::Verifier, P>),
    InvalidDirectMessage(InvalidDirectMessageEvidence),
    InvalidEchoBroadcast(InvalidEchoBroadcastEvidence),
    InvalidNormalBroadcast(InvalidNormalBroadcastEvidence),
    InvalidEchoPack(InvalidEchoPackEvidence<SP>),
    MismatchedBroadcasts(MismatchedBroadcastsEvidence),
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
pub struct InvalidEchoPackEvidence<SP: SessionParameters> {
    normal_broadcast: SignedMessagePart<NormalBroadcast>,
    invalid_echo_sender: SP::Verifier,
}

impl<SP> InvalidEchoPackEvidence<SP>
where
    SP: SessionParameters,
{
    fn verify(&self, verifier: &SP::Verifier, format: &BoxedFormat) -> Result<(), EvidenceError> {
        let verified = self.normal_broadcast.clone().verify::<SP>(verifier)?;
        let deserialized = verified.payload().deserialize::<EchoRoundMessage<SP>>(format)?;
        let invalid_echo = deserialized
            .message_hashes
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
    we_received: SignedMessagePart<EchoBroadcast>,
    echoed_to_us: SignedMessageHash,
}

impl MismatchedBroadcastsEvidence {
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let we_received = self.we_received.clone().verify::<SP>(verifier)?;
        let echoed_to_us = self.echoed_to_us.clone().verify::<SP>(verifier)?;

        if we_received.metadata() == echoed_to_us.metadata() && !echoed_to_us.is_hash_of::<SP, _>(&self.we_received) {
            Ok(())
        } else {
            Err(EvidenceError::InvalidEvidence(
                "The attached messages don't constitute malicious behavior".into(),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidDirectMessageEvidence(SignedMessagePart<DirectMessage>);

impl InvalidDirectMessageEvidence {
    fn verify<P, SP>(&self, verifier: &SP::Verifier, format: &BoxedFormat) -> Result<(), EvidenceError>
    where
        P: Protocol<SP::Verifier>,
        SP: SessionParameters,
    {
        let verified_direct_message = self.0.clone().verify::<SP>(verifier)?;
        let payload = verified_direct_message.payload();

        if self.0.metadata().round_id().is_echo() {
            Ok(EchoRound::<P, SP>::verify_direct_message_is_invalid(payload)?)
        } else {
            Ok(P::verify_direct_message_is_invalid(
                format,
                self.0.metadata().round_id(),
                payload,
            )?)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidEchoBroadcastEvidence(SignedMessagePart<EchoBroadcast>);

impl InvalidEchoBroadcastEvidence {
    fn verify<P, SP>(&self, verifier: &SP::Verifier, format: &BoxedFormat) -> Result<(), EvidenceError>
    where
        P: Protocol<SP::Verifier>,
        SP: SessionParameters,
    {
        let verified_echo_broadcast = self.0.clone().verify::<SP>(verifier)?;
        let payload = verified_echo_broadcast.payload();

        if self.0.metadata().round_id().is_echo() {
            Ok(EchoRound::<P, SP>::verify_echo_broadcast_is_invalid(payload)?)
        } else {
            Ok(P::verify_echo_broadcast_is_invalid(
                format,
                self.0.metadata().round_id(),
                payload,
            )?)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidNormalBroadcastEvidence(SignedMessagePart<NormalBroadcast>);

impl InvalidNormalBroadcastEvidence {
    fn verify<P, SP>(&self, verifier: &SP::Verifier, format: &BoxedFormat) -> Result<(), EvidenceError>
    where
        P: Protocol<SP::Verifier>,
        SP: SessionParameters,
    {
        let verified_normal_broadcast = self.0.clone().verify::<SP>(verifier)?;
        let payload = verified_normal_broadcast.payload();

        if self.0.metadata().round_id().is_echo() {
            Ok(EchoRound::<P, SP>::verify_normal_broadcast_is_invalid(format, payload)?)
        } else {
            Ok(P::verify_normal_broadcast_is_invalid(
                format,
                self.0.metadata().round_id(),
                payload,
            )?)
        }
    }
}

#[derive_where::derive_where(Debug)]
#[derive(Clone, Serialize, Deserialize)]
struct ProtocolEvidence<Id: Debug + Clone + Ord, P: Protocol<Id>> {
    error: P::ProtocolError,
    direct_message: Option<SignedMessagePart<DirectMessage>>,
    echo_broadcast: Option<SignedMessagePart<EchoBroadcast>>,
    normal_broadcast: Option<SignedMessagePart<NormalBroadcast>>,
    direct_messages: SerializableMap<RoundId, SignedMessagePart<DirectMessage>>,
    echo_broadcasts: SerializableMap<RoundId, SignedMessagePart<EchoBroadcast>>,
    normal_broadcasts: SerializableMap<RoundId, SignedMessagePart<NormalBroadcast>>,
    other_echo_broadcasts: SerializableMap<RoundId, SerializableMap<Id, SignedMessagePart<EchoBroadcast>>>,
    echo_hashes: SerializableMap<RoundId, SignedMessagePart<NormalBroadcast>>,
}

fn verify_message_parts<SP, T>(
    verifier: &SP::Verifier,
    expected_session_id: &SessionId,
    message_parts: &SerializableMap<RoundId, SignedMessagePart<T>>,
) -> Result<BTreeMap<RoundId, T>, EvidenceError>
where
    SP: SessionParameters,
    T: Clone + ProtocolMessagePartHashable,
{
    let mut verified_parts = BTreeMap::new();
    for (round_id, message_part) in message_parts.iter() {
        let verified = message_part.clone().verify::<SP>(verifier)?;
        let metadata = verified.metadata();
        if metadata.session_id() != expected_session_id || metadata.round_id() != round_id {
            return Err(EvidenceError::InvalidEvidence(
                "Invalid attached message metadata".into(),
            ));
        }
        verified_parts.insert(round_id.clone(), verified.into_payload());
    }
    Ok(verified_parts)
}

fn verify_message_part<SP, T>(
    verifier: &SP::Verifier,
    expected_session_id: &SessionId,
    expected_round_id: &RoundId,
    message_part: &Option<SignedMessagePart<T>>,
) -> Result<T, EvidenceError>
where
    SP: SessionParameters,
    T: Clone + ProtocolMessagePartHashable,
{
    let verified_part = if let Some(message_part) = message_part {
        let metadata = message_part.metadata();
        if metadata.session_id() != expected_session_id || metadata.round_id() != expected_round_id {
            return Err(EvidenceError::InvalidEvidence(
                "Invalid attached message metadata".into(),
            ));
        }
        message_part.clone().verify::<SP>(verifier)?.into_payload()
    } else {
        T::none()
    };

    Ok(verified_part)
}

impl<Id, P> ProtocolEvidence<Id, P>
where
    Id: Debug + Clone + Ord,
    P: Protocol<Id>,
{
    fn verify<SP>(
        &self,
        verifier: &SP::Verifier,
        format: &BoxedFormat,
        associated_data: &<P::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), EvidenceError>
    where
        SP: SessionParameters<Verifier = Id>,
    {
        // Find the message part from the message that triggered the error
        // and use it as a source of RoundID and SessionID.
        // At least one part of that message will be required, as enforced by `RequiredMessageParts` invariant.
        let metadata = if let Some(message) = &self.direct_message {
            message.metadata()
        } else if let Some(message) = &self.echo_broadcast {
            message.metadata()
        } else if let Some(message) = &self.normal_broadcast {
            message.metadata()
        } else {
            return Err(EvidenceError::InvalidEvidence(
                "At least one part of the trigger message must be present".into(),
            ));
        };

        let session_id = metadata.session_id();
        let round_id = metadata.round_id();

        let direct_message = verify_message_part::<SP, _>(verifier, session_id, round_id, &self.direct_message)?;
        let echo_broadcast = verify_message_part::<SP, _>(verifier, session_id, round_id, &self.echo_broadcast)?;
        let normal_broadcast = verify_message_part::<SP, _>(verifier, session_id, round_id, &self.normal_broadcast)?;

        let mut direct_messages = verify_message_parts::<SP, _>(verifier, session_id, &self.direct_messages)?;
        let mut echo_broadcasts = verify_message_parts::<SP, _>(verifier, session_id, &self.echo_broadcasts)?;
        let mut normal_broadcasts = verify_message_parts::<SP, _>(verifier, session_id, &self.normal_broadcasts)?;

        let mut combined_echos = BTreeMap::new();
        for (round_id, echo_hashes) in self.echo_hashes.iter() {
            let metadata = echo_hashes.metadata();
            let main_round_id = metadata
                .round_id()
                .non_echo()
                .map_err(|_err| EvidenceError::InvalidEvidence("Invalid echo hash round ID".into()))?;
            if metadata.session_id() != session_id || &main_round_id != round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }

            let verified_echo_hashes = echo_hashes.clone().verify::<SP>(verifier)?;
            let echo_round_payload = verified_echo_hashes
                .payload()
                .deserialize::<EchoRoundMessage<SP>>(format)?;

            let signed_echo_broadcasts = self
                .other_echo_broadcasts
                .get(round_id)
                .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Missing {round_id} echo broadcasts")))?;

            let mut echo_messages = BTreeMap::new();
            for (other_verifier, echo_hash) in echo_round_payload.message_hashes.iter() {
                let metadata = echo_hash.metadata();
                if metadata.session_id() != session_id || metadata.round_id() != round_id {
                    return Err(EvidenceError::InvalidEvidence("Invalid echo hash metadata".into()));
                }

                let verified_echo_hash = echo_hash.clone().verify::<SP>(other_verifier)?;

                let echo_broadcast = signed_echo_broadcasts.get(other_verifier).ok_or_else(|| {
                    EvidenceError::InvalidEvidence(format!("Missing {round_id} echo broadcast from {other_verifier:?}"))
                })?;

                let metadata = echo_broadcast.metadata();
                if metadata.session_id() != session_id || metadata.round_id() != round_id {
                    return Err(EvidenceError::InvalidEvidence("Invalid echo broadcast metadata".into()));
                }

                if !verified_echo_hash.is_hash_of::<SP, _>(echo_broadcast) {
                    return Err(EvidenceError::InvalidEvidence(
                        "Mismatch between the echoed hash and the original echo broadcast".into(),
                    ));
                }

                let verified_echo_broadcast = echo_broadcast.clone().verify::<SP>(other_verifier)?;

                echo_messages.insert(other_verifier.clone(), verified_echo_broadcast.into_payload());
            }
            combined_echos.insert(round_id.clone(), echo_messages);
        }

        // Merge message parts

        let protocol_message = ProtocolMessage {
            echo_broadcast,
            normal_broadcast,
            direct_message,
        };

        let all_rounds = echo_broadcasts
            .keys()
            .cloned()
            .chain(normal_broadcasts.keys().cloned())
            .chain(direct_messages.keys().cloned())
            .collect::<BTreeSet<_>>();

        let mut previous_messages = BTreeMap::new();
        for round_id in all_rounds {
            let echo_broadcast = echo_broadcasts.remove(&round_id).unwrap_or(EchoBroadcast::none());
            let normal_broadcast = normal_broadcasts.remove(&round_id).unwrap_or(NormalBroadcast::none());
            let direct_message = direct_messages.remove(&round_id).unwrap_or(DirectMessage::none());
            let protocol_message = ProtocolMessage {
                echo_broadcast,
                normal_broadcast,
                direct_message,
            };
            previous_messages.insert(round_id, protocol_message);
        }

        Ok(self.error.verify_messages_constitute_error(
            format,
            verifier,
            session_id.as_ref(),
            associated_data,
            protocol_message,
            previous_messages,
            combined_echos,
        )?)
    }
}
