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
    message::{MessageVerificationError, SignedMessageHash, SignedMessagePart},
    session::{SessionParameters},
    LocalError,
};
use crate::{
    protocol::{RoundCommunicationInfo, IdSet,
        Artifact, BoxedFormat, BoxedRound, CommunicationInfo, DirectMessage, EchoBroadcast,
        FinalizeOutcome, MessageValidationError, NormalBroadcast, Payload, Protocol, ProtocolMessage,
        ProtocolMessagePart, ReceiveError, Round, TransitionInfo,
    },
    utils::SerializableMap,
};

/// An error that can occur on receiving a message during an echo round.
#[derive(Debug)]
pub(crate) enum EchoRoundError<Id> {
    /// The node who constructed the echoed message pack included an invalid message in it.
    ///
    /// This is the fault of the sender of the echo pack.
    ///
    /// The attached identifier points out the sender for whom the echoed message was invalid,
    /// to speed up the verification process.
    InvalidEcho {
        // Even though this will be the same as the message sender, it is convenient to record it here
        // because of the way this error will be processed.
        guilty_party: Id,
        failed_for: Id,
    },
    /// The originally received message and the one received in the echo pack were both valid,
    /// but different.
    ///
    /// This is the fault of the sender of that specific broadcast.
    MismatchedBroadcasts {
        guilty_party: Id,
        we_received: SignedMessagePart<EchoBroadcast>,
        echoed_to_us: SignedMessageHash,
    },
}

impl<Id> EchoRoundError<Id> {
    pub(crate) fn description(&self) -> String {
        match self {
            Self::InvalidEcho { .. } => "Invalid message received among the ones echoed".into(),
            Self::MismatchedBroadcasts { .. } => {
                "The echoed message is different from the originally received one".into()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EchoRoundMessage<SP: SessionParameters> {
    /// Signatures of echo broadcasts from respective nodes.
    pub(super) message_hashes: SerializableMap<SP::Verifier, SignedMessageHash>,
}

/// Each protocol round can contain one `EchoRound` with "echo messages" that are sent to all
/// participants. The execution layer of the protocol guarantees that all participants have received
/// the messages.
#[derive_where::derive_where(Debug)]
pub struct EchoRound<P: Protocol<SP::Verifier>, SP: SessionParameters> {
    verifier: SP::Verifier,
    echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
    communication_info: CommunicationInfo<SP::Verifier>,
    expected_echos: IdSet<SP::Verifier>,
    banned_ids: BTreeSet<SP::Verifier>,
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
        communication_info: RoundCommunicationInfo<SP::Verifier>,
        expected_echos: IdSet<SP::Verifier>,
        banned_ids: BTreeSet<SP::Verifier>,
        main_round: BoxedRound<SP::Verifier, P>,
        payloads: BTreeMap<SP::Verifier, Payload>,
        artifacts: BTreeMap<SP::Verifier, Artifact>,
    ) -> Self {
        debug!("{:?}: initialized echo round with {:?} {:?}", verifier, communication_info, expected_echos);
        let communication_info = CommunicationInfo {
            main_round: communication_info,
            echo_round: None,
            expected_echos: None,
        };
        Self {
            verifier,
            echo_broadcasts,
            communication_info,
            expected_echos,
            banned_ids,
            main_round,
            payloads,
            artifacts,
        }
    }

    // Since the echo round doesn't have its own `Protocol`, these methods live here.

    pub fn verify_direct_message_is_invalid(message: &DirectMessage) -> Result<(), MessageValidationError> {
        // We don't send any direct messages in the echo round
        message.verify_is_some()
    }

    pub fn verify_echo_broadcast_is_invalid(message: &EchoBroadcast) -> Result<(), MessageValidationError> {
        // We don't send any echo broadcasts in the echo round
        message.verify_is_some()
    }

    pub fn verify_normal_broadcast_is_invalid(
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        message.verify_is_not::<EchoRoundMessage<SP>>(format)
    }
}

impl<P, SP> Round<SP::Verifier> for EchoRound<P, SP>
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
            .iter()
            .map(|(id, echo_broadcast)| (id.clone(), echo_broadcast.to_signed_hash::<SP>()))
            .collect::<BTreeMap<_, _>>()
            .into();

        let message = EchoRoundMessage::<SP> { message_hashes };
        NormalBroadcast::new(format, message)
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &SP::Verifier,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<SP::Verifier, Self::Protocol>> {
        debug!("{:?}: received an echo message from {:?}", self.verifier, from);

        message.echo_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;

        let message = message.normal_broadcast.deserialize::<EchoRoundMessage<SP>>(format)?;

        // Check that the received message contains entries from `expected_echos`.
        // Since we cannot guarantee the communication info for the echo round is in the associated data,
        // we cannot construct an evidence for this fault.

        let mut expected_keys = self.expected_echos.all().clone();

        // We don't expect the node to send its echo the second time.
        expected_keys.remove(from);

        let message_keys = message.message_hashes.keys().cloned().collect::<BTreeSet<_>>();

        let extra_keys = message_keys.difference(&expected_keys).collect::<Vec<_>>();
        if !extra_keys.is_empty() {
            return Err(ReceiveError::unprovable(format!(
                "Unexpected echoed messages from: {:?}",
                extra_keys
            )));
        }

        // Check that the echos we received, minus the banned IDs, constitute a quorum.
        // This is also unprovable since the information about the IDs we banned is not available to third parties.

        let expected_keys = message_keys.difference(&self.banned_ids).cloned().collect::<BTreeSet<_>>();
        if !self.expected_echos.is_quorum(&expected_keys) {
            return Err(ReceiveError::unprovable("Not enough echos to constitute a quorum"));
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

            let verified_echo = match echo.clone().verify::<SP>(sender) {
                Ok(echo) => echo,
                Err(MessageVerificationError::Local(error)) => return Err(error.into()),
                // This means `from` sent us an incorrectly signed message.
                // Provable fault of `from`.
                Err(MessageVerificationError::InvalidSignature) => {
                    return Err(EchoRoundError::InvalidEcho {
                        guilty_party: from.clone(),
                        failed_for: sender.clone(),
                    }
                    .into())
                }
                Err(MessageVerificationError::SignatureMismatch) => {
                    return Err(EchoRoundError::InvalidEcho {
                        guilty_party: from.clone(),
                        failed_for: sender.clone(),
                    }
                    .into())
                }
            };

            // `from` sent us a correctly signed message but from another round or another session.
            // Provable fault of `from`.
            if verified_echo.metadata() != previously_received_echo.metadata() {
                return Err(EchoRoundError::InvalidEcho {
                    guilty_party: from.clone(),
                    failed_for: sender.clone(),
                }
                .into());
            }

            // `sender` sent us and `from` messages with different payloads,
            // but with correct signatures and the same metadata.
            // Provable fault of `sender`.
            if !verified_echo.is_hash_of::<SP, _>(previously_received_echo) {
                return Err(EchoRoundError::MismatchedBroadcasts {
                    guilty_party: sender.clone(),
                    we_received: previously_received_echo.clone(),
                    echoed_to_us: echo.clone(),
                }
                .into());
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
            .into_boxed()
            .finalize(rng, self.payloads, self.artifacts)
    }
}
