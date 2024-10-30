use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{
    message::{MessageVerificationError, SignedMessage},
    session::SessionParameters,
    LocalError,
};
use crate::{
    protocol::{
        Artifact, Deserializer, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, NormalBroadcast,
        ObjectSafeRound, Payload, Protocol, ProtocolMessagePart, ReceiveError, Round, RoundId, Serializer,
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
        we_received: SignedMessage<EchoBroadcast>,
        echoed_to_us: SignedMessage<EchoBroadcast>,
    },
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
    pub(crate) echo_broadcasts: SerializableMap<SP::Verifier, SignedMessage<EchoBroadcast>>,
}

/// Each protocol round can contain one `EchoRound` with "echo messages" that are sent to all
/// participants. The execution layer of the protocol guarantees that all participants have received
/// the messages.
#[derive(Debug)]
pub struct EchoRound<P, SP: SessionParameters> {
    verifier: SP::Verifier,
    echo_broadcasts: BTreeMap<SP::Verifier, SignedMessage<EchoBroadcast>>,
    destinations: BTreeSet<SP::Verifier>,
    expected_echos: BTreeSet<SP::Verifier>,
    main_round: Box<dyn ObjectSafeRound<SP::Verifier, Protocol = P>>,
    payloads: BTreeMap<SP::Verifier, Payload>,
    artifacts: BTreeMap<SP::Verifier, Artifact>,
}

impl<P, SP> EchoRound<P, SP>
where
    P: Protocol,
    SP: SessionParameters + Debug,
{
    pub fn new(
        verifier: SP::Verifier,
        my_echo_broadcast: SignedMessage<EchoBroadcast>,
        echo_broadcasts: BTreeMap<SP::Verifier, SignedMessage<EchoBroadcast>>,
        main_round: Box<dyn ObjectSafeRound<SP::Verifier, Protocol = P>>,
        payloads: BTreeMap<SP::Verifier, Payload>,
        artifacts: BTreeMap<SP::Verifier, Artifact>,
    ) -> Self {
        let destinations = echo_broadcasts.keys().cloned().collect::<BTreeSet<_>>();

        // Add our own echo message because we expect it to be sent back from other nodes.
        let mut expected_echos = destinations.clone();
        expected_echos.insert(verifier.clone());

        let mut echo_broadcasts = echo_broadcasts;
        echo_broadcasts.insert(verifier.clone(), my_echo_broadcast);

        debug!("{:?}: initialized echo round with {:?}", verifier, destinations);
        Self {
            verifier,
            echo_broadcasts,
            destinations,
            expected_echos,
            main_round,
            payloads,
            artifacts,
        }
    }
}

impl<P, SP> Round<SP::Verifier> for EchoRound<P, SP>
where
    P: 'static + Protocol,
    SP: 'static + SessionParameters + Debug,
{
    type Protocol = P;

    fn id(&self) -> RoundId {
        self.main_round.id().echo()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        self.main_round.possible_next_rounds()
    }

    fn message_destinations(&self) -> &BTreeSet<SP::Verifier> {
        &self.destinations
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
        &self.destinations
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

        // Check that the received message contains entries from `destinations` sans `from`
        // It is an unprovable fault.

        let mut expected_keys = self.expected_echos.clone();
        if !expected_keys.remove(from) {
            return Err(ReceiveError::local(format!(
                "The message sender {from:?} is missing from the expected senders {:?}",
                self.destinations
            )));
        }
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
    ) -> Result<FinalizeOutcome<SP::Verifier, Self::Protocol>, FinalizeError<Self::Protocol>> {
        self.main_round.finalize(rng, self.payloads, self.artifacts)
    }
}
