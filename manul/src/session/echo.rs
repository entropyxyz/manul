use alloc::{
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
    message::{MessageVerificationError, SignedMessagePart},
    session::{EchoRoundInfo, SessionParameters},
    LocalError,
};
use crate::{
    protocol::{
        Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, FinalizeOutcome, MessageValidationError,
        NormalBroadcast, Payload, Protocol, ProtocolMessagePart, ReceiveError, Round, RoundId, Serializer,
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
    InvalidEcho(Id),
    /// The originally received message and the one received in the echo pack were both valid,
    /// but different.
    ///
    /// This is the fault of the sender of that specific broadcast.
    MismatchedBroadcasts {
        guilty_party: Id,
        error: MismatchedBroadcastsError,
        we_received: SignedMessagePart<EchoBroadcast>,
        echoed_to_us: SignedMessagePart<EchoBroadcast>,
    },
}

impl<Id> EchoRoundError<Id> {
    pub(crate) fn description(&self) -> String {
        match self {
            Self::InvalidEcho(_) => "Invalid message received among the ones echoed".into(),
            Self::MismatchedBroadcasts { .. } => {
                "The echoed message is different from the originally received one".into()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum MismatchedBroadcastsError {
    /// The originally received message and the echoed one had different payloads.
    DifferentPayloads,
    /// The originally received message and the echoed one had different signatures.
    DifferentSignatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EchoRoundMessage<SP: SessionParameters> {
    pub(super) echo_broadcasts: SerializableMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
}

/// Each protocol round can contain one `EchoRound` with "echo messages" that are sent to all
/// participants. The execution layer of the protocol guarantees that all participants have received
/// the messages.
#[derive_where::derive_where(Debug)]
pub struct EchoRound<P: Protocol<SP::Verifier>, SP: SessionParameters> {
    verifier: SP::Verifier,
    echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
    echo_round_info: EchoRoundInfo<SP::Verifier>,
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
        my_echo_broadcast: SignedMessagePart<EchoBroadcast>,
        echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
        echo_round_info: EchoRoundInfo<SP::Verifier>,
        main_round: BoxedRound<SP::Verifier, P>,
        payloads: BTreeMap<SP::Verifier, Payload>,
        artifacts: BTreeMap<SP::Verifier, Artifact>,
    ) -> Self {
        let mut echo_broadcasts = echo_broadcasts;
        echo_broadcasts.insert(verifier.clone(), my_echo_broadcast);

        debug!("{:?}: initialized echo round with {:?}", verifier, echo_round_info);
        Self {
            verifier,
            echo_broadcasts,
            echo_round_info,
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
        deserializer: &Deserializer,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        message.verify_is_not::<EchoRoundMessage<SP>>(deserializer)
    }
}

impl<P, SP> Round<SP::Verifier> for EchoRound<P, SP>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    type Protocol = P;

    fn id(&self) -> RoundId {
        self.main_round.id().echo()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        self.main_round.as_ref().possible_next_rounds()
    }

    fn message_destinations(&self) -> &BTreeSet<SP::Verifier> {
        &self.echo_round_info.message_destinations
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
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

        let message = EchoRoundMessage::<SP> {
            echo_broadcasts: echo_broadcasts.into(),
        };
        NormalBroadcast::new(serializer, message)
    }

    fn expecting_messages_from(&self) -> &BTreeSet<SP::Verifier> {
        &self.echo_round_info.expecting_messages_from
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &SP::Verifier,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<SP::Verifier, Self::Protocol>> {
        debug!("{:?}: received an echo message from {:?}", self.verifier, from);

        echo_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;

        let message = normal_broadcast.deserialize::<EchoRoundMessage<SP>>(deserializer)?;

        // Check that the received message contains entries from `expected_echos`.
        // It is an unprovable fault.

        let mut expected_keys = self.echo_round_info.expected_echos.clone();

        // We don't expect the node to send its echo the second time.
        expected_keys.remove(from);

        let message_keys = message.echo_broadcasts.keys().cloned().collect::<BTreeSet<_>>();

        let missing_keys = expected_keys.difference(&message_keys).collect::<Vec<_>>();
        if !missing_keys.is_empty() {
            return Err(ReceiveError::unprovable(format!(
                "Missing echoed messages from: {:?}",
                missing_keys
            )));
        }

        let extra_keys = message_keys.difference(&expected_keys).collect::<Vec<_>>();
        if !extra_keys.is_empty() {
            return Err(ReceiveError::unprovable(format!(
                "Unexpected echoed messages from: {:?}",
                extra_keys
            )));
        }

        // Check that every entry is equal to what we received previously (in the main round).
        // If there's a difference, it's a provable fault,
        // since we have both messages signed by `from`.

        for (sender, echo) in message.echo_broadcasts.iter() {
            // We expect the key to be there since
            // `message.echo_broadcasts.keys()` is within `self.destinations`
            // which was constructed as `self.echo_broadcasts.keys()`.
            let previously_received_echo = self
                .echo_broadcasts
                .get(sender)
                .expect("the key is present by construction");

            if echo == previously_received_echo {
                continue;
            }

            let verified_echo = match echo.clone().verify::<SP>(sender) {
                Ok(echo) => echo,
                Err(MessageVerificationError::Local(error)) => return Err(error.into()),
                // This means `from` sent us an incorrectly signed message.
                // Provable fault of `from`.
                Err(MessageVerificationError::InvalidSignature) => {
                    return Err(EchoRoundError::InvalidEcho(sender.clone()).into())
                }
                Err(MessageVerificationError::SignatureMismatch) => {
                    return Err(EchoRoundError::InvalidEcho(sender.clone()).into())
                }
            };

            // `from` sent us a correctly signed message but from another round or another session.
            // Provable fault of `from`.
            if verified_echo.metadata() != previously_received_echo.metadata() {
                return Err(EchoRoundError::InvalidEcho(sender.clone()).into());
            }

            // `sender` sent us and `from` messages with different payloads.
            // Provable fault of `sender`.
            if verified_echo.payload() != previously_received_echo.payload() {
                return Err(EchoRoundError::MismatchedBroadcasts {
                    guilty_party: sender.clone(),
                    error: MismatchedBroadcastsError::DifferentPayloads,
                    we_received: previously_received_echo.clone(),
                    echoed_to_us: echo.clone(),
                }
                .into());
            }

            // At this point, we know that the echoed broadcast is not identical to what we initially received,
            // but somehow they both have the correct metadata, and correct signatures.
            // Something strange is going on.
            return Err(EchoRoundError::MismatchedBroadcasts {
                guilty_party: sender.clone(),
                error: MismatchedBroadcastsError::DifferentSignatures,
                we_received: previously_received_echo.clone(),
                echoed_to_us: echo.clone(),
            }
            .into());
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<SP::Verifier, Payload>,
        _artifacts: BTreeMap<SP::Verifier, Artifact>,
    ) -> Result<FinalizeOutcome<SP::Verifier, Self::Protocol>, LocalError> {
        self.main_round
            .into_boxed()
            .finalize(rng, self.payloads, self.artifacts)
    }
}
