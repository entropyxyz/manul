use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{
    message::{MessageMetadata, MessageVerificationError, SignedMessageHash, SignedMessagePart},
    session::{EchoRoundInfo, SessionParameters},
    LocalError,
};
use crate::{
    protocol::{
        Artifact, BoxedFormat, BoxedReceiveError, BoxedRound, CommunicationInfo, DirectMessage, DynProtocolMessage,
        DynRound, EchoBroadcast, EchoRoundParticipation, EvidenceError, FinalizeOutcome, NoArtifact, NoMessage, NoType,
        NormalBroadcast, PartyId, Payload, Protocol, ProtocolMessagePart, RemoteError, TransitionInfo,
    },
    utils::{MapValues, SerializableMap},
};

/// An error that can occur on receiving a message during an echo round.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum EchoRoundError<Id> {
    /// The node who constructed the echoed message pack included an invalid message in it.
    ///
    /// This is the fault of the sender of the echo pack.
    ///
    /// The attached identifier points out the sender for whom the echoed message was invalid,
    /// to speed up the verification process.
    InvalidEcho(InvalidEchoError<Id>),
    /// The originally received message and the one received in the echo pack were both valid,
    /// but different.
    ///
    /// This is the fault of the sender of that specific broadcast.
    MismatchedBroadcasts(MismatchedBroadcastsError<Id>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InvalidEchoError<Id> {
    invalid_echo_sender: Id,
}

impl<Id: PartyId> InvalidEchoError<Id> {
    pub fn description(&self) -> String {
        "Invalid message received among the ones echoed".into()
    }

    pub fn verify_evidence<SP: SessionParameters<Verifier = Id>>(
        &self,
        metadata: &MessageMetadata,
        message: &EchoRoundMessage<SP::Verifier>,
    ) -> Result<(), EvidenceError> {
        let invalid_echo = message.message_hashes.get(&self.invalid_echo_sender).ok_or_else(|| {
            EvidenceError::InvalidEvidence(format!(
                "Did not find {:?} in the attached message",
                self.invalid_echo_sender
            ))
        })?;

        let verified_echo = match invalid_echo.clone().into_verified::<SP>(&self.invalid_echo_sender) {
            Ok(echo) => echo,
            Err(MessageVerificationError::Local(error)) => return Err(EvidenceError::Local(error)),
            // The message was indeed incorrectly signed - fault proven
            Err(MessageVerificationError::InvalidSignature) => return Ok(()),
            Err(MessageVerificationError::SignatureMismatch) => return Ok(()),
        };

        // `from` sent us a correctly signed message but from another round or another session.
        // Provable fault of `from`.
        if verified_echo.metadata() != metadata {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "There is nothing wrong with the echoed message".into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MismatchedBroadcastsError<Id> {
    guilty_party: Id,
    we_received: SignedMessagePart<EchoBroadcast>,
    echoed_to_us: SignedMessageHash,
}

impl<Id> MismatchedBroadcastsError<Id> {
    pub fn description(&self) -> String {
        "The echoed message is different from the originally received one".into()
    }

    pub fn guilty_party(&self) -> &Id {
        &self.guilty_party
    }

    pub fn verify_evidence<SP: SessionParameters<Verifier = Id>>(&self) -> Result<(), EvidenceError> {
        let we_received = self
            .we_received
            .clone()
            .into_verified::<SP>(&self.guilty_party)
            .map_err(MessageVerificationError::into_evidence_error)?;
        let echoed_to_us = self
            .echoed_to_us
            .clone()
            .into_verified::<SP>(&self.guilty_party)
            .map_err(MessageVerificationError::into_evidence_error)?;

        if we_received.metadata() == echoed_to_us.metadata() && !echoed_to_us.is_hash_of::<SP, _>(&self.we_received) {
            Ok(())
        } else {
            Err(EvidenceError::InvalidEvidence(
                "The attached messages don't constitute malicious behavior".into(),
            ))
        }
    }
}

#[derive(Debug, Clone)]
#[derive_where::derive_where(Serialize, Deserialize)]
pub(crate) struct EchoRoundMessage<Id: PartyId> {
    /// Signatures of echo broadcasts from respective nodes.
    pub(super) message_hashes: SerializableMap<Id, SignedMessageHash>,
}

/// Each protocol round can contain one `EchoRound` with "echo messages" that are sent to all
/// participants. The execution layer of the protocol guarantees that all participants have received
/// the messages.
#[derive_where::derive_where(Debug)]
pub(super) struct EchoRound<P: Protocol<SP::Verifier>, SP: SessionParameters> {
    verifier: SP::Verifier,
    echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
    echo_round_info: EchoRoundInfo<SP::Verifier>,
    communication_info: CommunicationInfo<SP::Verifier>,
    main_round: BoxedRound<SP::Verifier, P>,
    payloads: BTreeMap<SP::Verifier, Payload>,
    artifacts: BTreeMap<SP::Verifier, Artifact>,
}

impl<P, SP> EchoRound<P, SP>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    pub fn new(
        verifier: SP::Verifier,
        echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
        echo_round_info: EchoRoundInfo<SP::Verifier>,
        main_round: BoxedRound<SP::Verifier, P>,
        payloads: BTreeMap<SP::Verifier, Payload>,
        artifacts: BTreeMap<SP::Verifier, Artifact>,
    ) -> Self {
        debug!("{:?}: initialized echo round with {:?}", verifier, echo_round_info);

        let communication_info = CommunicationInfo {
            message_destinations: echo_round_info.message_destinations.clone(),
            expecting_messages_from: echo_round_info.expecting_messages_from.clone(),
            echo_round_participation: EchoRoundParticipation::Default,
        };

        Self {
            verifier,
            echo_broadcasts,
            echo_round_info,
            communication_info,
            main_round,
            payloads,
            artifacts,
        }
    }

    // Since the echo round doesn't have its own static round type, these methods live here.

    pub fn verify_direct_message_is_invalid(
        _format: &BoxedFormat,
        message: &DirectMessage,
    ) -> Result<(), EvidenceError> {
        // We don't send any direct messages in the echo round
        message.verify_is_some()
    }

    pub fn verify_echo_broadcast_is_invalid(
        _format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), EvidenceError> {
        // We don't send any echo broadcasts in the echo round
        message.verify_is_some()
    }

    pub fn verify_normal_broadcast_is_invalid(
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), EvidenceError> {
        message.verify_is_not::<EchoRoundMessage<SP::Verifier>>(format)
    }
}

impl<P, SP> DynRound<SP::Verifier> for EchoRound<P, SP>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    type Protocol = P;

    fn transition_info(&self) -> TransitionInfo {
        // We expect the echo round to be created internally from a regular round,
        // which cannot be an echo round.
        // Returning an error here would require allowing the trait method to fail,
        // which is not needed by any protocol implementors.
        self.main_round
            .as_ref()
            .transition_info()
            .echo()
            .expect("the main round is not an echo round")
    }

    fn communication_info(&self) -> CommunicationInfo<SP::Verifier> {
        self.communication_info.clone()
    }

    fn make_direct_message(
        &self,
        _rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        _destination: &SP::Verifier,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        Ok((
            DirectMessage::new(format, NoMessage::new())?,
            Artifact::new(NoArtifact::new()),
        ))
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut dyn CryptoRngCore,
        _format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        Ok(EchoBroadcast::none())
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        debug!("{:?}: making an echo round message", self.verifier);

        // Don't send our own message the second time
        let mut echo_broadcasts = self.echo_broadcasts.clone();
        if echo_broadcasts.remove(&self.verifier).is_none() {
            return Err(LocalError::new(format!(
                "Expected {:?} to be in the set of all echo messages",
                self.verifier
            )));
        }

        let message_hashes = echo_broadcasts
            .map_values(|echo_broadcast| echo_broadcast.to_signed_hash::<SP>())
            .into();

        let message = EchoRoundMessage::<SP::Verifier> { message_hashes };
        NormalBroadcast::new(format, message)
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &SP::Verifier,
        message: DynProtocolMessage,
    ) -> Result<Payload, BoxedReceiveError<SP::Verifier>> {
        debug!("{:?}: received an echo message from {:?}", self.verifier, from);

        message.echo_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;

        let message = message
            .normal_broadcast
            .deserialize::<EchoRoundMessage<SP::Verifier>>(format)?;

        // Check that the received message contains entries from `expected_echos`.
        // It is an unprovable fault.

        let mut expected_keys = self.echo_round_info.expected_echos.clone();

        // We don't expect the node to send its echo the second time.
        expected_keys.remove(from);

        let message_keys = message.message_hashes.keys().cloned().collect::<BTreeSet<_>>();

        let missing_keys = expected_keys.difference(&message_keys).collect::<Vec<_>>();
        if !missing_keys.is_empty() {
            return Err(BoxedReceiveError::Unprovable(RemoteError::new(format!(
                "Missing echoed messages from: {missing_keys:?}",
            ))));
        }

        let extra_keys = message_keys.difference(&expected_keys).collect::<Vec<_>>();
        if !extra_keys.is_empty() {
            return Err(BoxedReceiveError::Unprovable(RemoteError::new(format!(
                "Unexpected echoed messages from: {extra_keys:?}",
            ))));
        }

        // Check that every entry is equal to what we received previously (in the main round).
        // If there's a difference, it's a provable fault,
        // since we have both messages signed by `from`.

        for (sender, echo) in message.message_hashes.iter() {
            // We expect the key to be there since
            // `message.echo_broadcasts.keys()` is within `self.destinations`
            // which was constructed as `self.echo_broadcasts.keys()`.
            let previously_received_echo = self
                .echo_broadcasts
                .get(sender)
                .expect("the key is present by construction");

            let verified_echo = match echo.clone().into_verified::<SP>(sender) {
                Ok(echo) => echo,
                Err(MessageVerificationError::Local(error)) => return Err(error.into()),
                // This means `from` sent us an incorrectly signed message.
                // Provable fault of `from`.
                Err(MessageVerificationError::InvalidSignature) => {
                    return Err(BoxedReceiveError::Echo(Box::new(EchoRoundError::InvalidEcho(
                        InvalidEchoError {
                            invalid_echo_sender: sender.clone(),
                        },
                    ))))
                }
                Err(MessageVerificationError::SignatureMismatch) => {
                    return Err(BoxedReceiveError::Echo(Box::new(EchoRoundError::InvalidEcho(
                        InvalidEchoError {
                            invalid_echo_sender: sender.clone(),
                        },
                    ))))
                }
            };

            // `from` sent us a correctly signed message but from another round or another session.
            // Provable fault of `from`.
            if verified_echo.metadata() != previously_received_echo.metadata() {
                return Err(BoxedReceiveError::Echo(Box::new(EchoRoundError::InvalidEcho(
                    InvalidEchoError {
                        invalid_echo_sender: sender.clone(),
                    },
                ))));
            }

            // `sender` sent us and `from` messages with different payloads,
            // but with correct signatures and the same metadata.
            // Provable fault of `sender`.
            if !verified_echo.is_hash_of::<SP, _>(previously_received_echo) {
                return Err(BoxedReceiveError::Echo(Box::new(EchoRoundError::MismatchedBroadcasts(
                    MismatchedBroadcastsError {
                        guilty_party: sender.clone(),
                        we_received: previously_received_echo.clone(),
                        echoed_to_us: echo.clone(),
                    },
                ))));
            }
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        _payloads: BTreeMap<SP::Verifier, Payload>,
        _artifacts: BTreeMap<SP::Verifier, Artifact>,
    ) -> Result<FinalizeOutcome<SP::Verifier, Self::Protocol>, LocalError> {
        self.main_round
            .into_inner()
            .finalize(rng, self.payloads, self.artifacts)
    }
}
