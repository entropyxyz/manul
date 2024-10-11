use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{LocalError, RemoteError};
use crate::message::{MessageVerificationError, SignedMessage};
use crate::round::{
    Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, Payload, Protocol,
    ReceiveError, Round, RoundId,
};
use crate::DigestVerifier;

#[derive(Debug)]
pub(crate) enum EchoRoundError<Id> {
    InvalidEcho(Id),
    InvalidBroadcast(Id),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoRoundMessage<I: Ord, S> {
    // TODO: use `Vec` to support more serializers?
    pub(crate) echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
}

pub struct EchoRound<P, I, S> {
    verifier: I,
    echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
    destinations: BTreeSet<I>,
    expected_echos: BTreeSet<I>,
    main_round: Box<dyn Round<I, Protocol = P>>,
    payloads: BTreeMap<I, Payload>,
    artifacts: BTreeMap<I, Artifact>,
}

impl<P: Protocol, I: Debug + Clone + Ord, S> EchoRound<P, I, S> {
    pub fn new(
        verifier: I,
        my_echo_message: SignedMessage<S, EchoBroadcast>,
        echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
        main_round: Box<dyn Round<I, Protocol = P>>,
        payloads: BTreeMap<I, Payload>,
        artifacts: BTreeMap<I, Artifact>,
    ) -> Self {
        let destinations = echo_messages.keys().cloned().collect::<BTreeSet<_>>();

        // Add our own echo message because we expect it to be sent back from other nodes.
        let mut expected_echos = destinations.clone();
        expected_echos.insert(verifier.clone());

        let mut echo_messages = echo_messages;
        echo_messages.insert(verifier.clone(), my_echo_message);

        debug!(
            "{:?}: initialized echo round with {:?}",
            verifier, destinations
        );
        Self {
            verifier,
            echo_messages,
            destinations,
            expected_echos,
            main_round,
            payloads,
            artifacts,
        }
    }
}

impl<P, I, S> Round<I> for EchoRound<P, I, S>
where
    P: 'static + Protocol,
    I: 'static
        + Debug
        + Clone
        + Ord
        + Serialize
        + for<'de> Deserialize<'de>
        + Eq
        + Send
        + Sync
        + DigestVerifier<P::Digest, S>,
    S: 'static + Debug + Clone + Serialize + for<'de> Deserialize<'de> + Eq + Send + Sync,
{
    type Protocol = P;

    fn id(&self) -> RoundId {
        self.main_round.id().echo()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        self.main_round.possible_next_rounds()
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.destinations
    }

    fn make_direct_message(
        &self,
        destination: &I,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        debug!(
            "{:?}: making echo round message for {:?}",
            self.verifier, destination
        );

        // Don't send our own message the second time
        let mut echo_messages = self.echo_messages.clone();
        if echo_messages.remove(&self.verifier).is_none() {
            return Err(LocalError::new(format!(
                "Expected {:?} to be in the set of all echo messages",
                self.verifier
            )));
        }

        let message = EchoRoundMessage { echo_messages };
        let dm = DirectMessage::new::<P, _>(&message)?;
        Ok((dm, Artifact::empty()))
    }

    fn receive_message(
        &self,
        from: &I,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        debug!(
            "{:?}: received an echo message from {:?}",
            self.verifier, from
        );

        let message = direct_message.try_deserialize::<P, EchoRoundMessage<I, S>>()?;

        // Check that the received message contains entries from `destinations` sans `from`
        // It is an unprovable fault.

        let mut expected_keys = self.expected_echos.clone();
        if !expected_keys.remove(from) {
            return Err(ReceiveError::Local(LocalError::new(format!(
                "The message sender {from:?} is missing from the expected senders {:?}",
                self.destinations
            ))));
        }
        let message_keys = message
            .echo_messages
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();

        let missing_keys = expected_keys.difference(&message_keys).collect::<Vec<_>>();
        if !missing_keys.is_empty() {
            return Err(ReceiveError::Unprovable(RemoteError::new(&format!(
                "Missing echoed messages from: {:?}",
                missing_keys
            ))));
        }

        let extra_keys = message_keys.difference(&expected_keys).collect::<Vec<_>>();
        if !extra_keys.is_empty() {
            return Err(ReceiveError::Unprovable(RemoteError::new(&format!(
                "Unexpected echoed messages from: {:?}",
                extra_keys
            ))));
        }

        // Check that every entry is equal to what we received previously (in the main round).
        // If there's a difference, it's a provable fault,
        // since we have both messages signed by `from`.

        for (sender, echo) in message.echo_messages.iter() {
            // We expect the key to be there since
            // `message.echo_messages.keys()` is within `self.destinations`
            // which was constructed as `self.echo_messages.keys()`.
            let previously_received_echo = self
                .echo_messages
                .get(sender)
                .expect("the key is present by construction");

            if echo == previously_received_echo {
                continue;
            }

            let verified_echo = match echo.clone().verify::<P, _>(sender) {
                Ok(echo) => echo,
                Err(MessageVerificationError::Local(error)) => {
                    return Err(ReceiveError::Local(error))
                }
                // This means `from` sent us an incorrectly signed message.
                // Provable fault of `from`.
                Err(MessageVerificationError::InvalidSignature) => {
                    return Err(ReceiveError::Echo(EchoRoundError::InvalidEcho(
                        sender.clone(),
                    )))
                }
            };

            // `from` sent us a correctly signed message but from another round or another session.
            // Provable fault of `from`.
            if verified_echo.metadata() != previously_received_echo.metadata() {
                return Err(ReceiveError::Echo(EchoRoundError::InvalidEcho(
                    sender.clone(),
                )));
            }

            // `sender` sent us and `from` messages with different payloads.
            // Provable fault of `sender`.
            if verified_echo.payload() != previously_received_echo.payload() {
                return Err(ReceiveError::Echo(EchoRoundError::InvalidBroadcast(
                    sender.clone(),
                )));
            }
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self: Box<Self>,
        _payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, FinalizeError<I, Self::Protocol>> {
        self.main_round.finalize(self.payloads, self.artifacts)
    }

    fn can_finalize(
        &self,
        payloads: &BTreeMap<I, Payload>,
        _artifacts: &BTreeMap<I, Artifact>,
    ) -> bool {
        self.message_destinations()
            .iter()
            .all(|id| payloads.contains_key(id))
    }
}
