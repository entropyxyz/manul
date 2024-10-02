use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::LocalError;
use crate::message::SignedMessage;
use crate::round::{
    Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, Payload, Protocol,
    ReceiveError, Round, RoundId,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoRoundMessage<I: Ord, S> {
    // TODO: use `Vec` to support more serializers?
    echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
}

pub struct EchoRound<P, I, S> {
    verifier: I,
    echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
    destinations: BTreeSet<I>,
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
        let destinations = echo_messages.keys().cloned().collect();

        // Add our own echo message because we expect it to be sent back from other nodes.
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
            main_round,
            payloads,
            artifacts,
        }
    }
}

impl<P, I, S> Round<I> for EchoRound<P, I, S>
where
    P: Protocol,
    I: Debug + Clone + Ord + Serialize + for<'de> Deserialize<'de> + Eq + Send + Sync,
    S: Debug + Clone + Serialize + for<'de> Deserialize<'de> + Eq + Send + Sync,
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
        let message = EchoRoundMessage {
            echo_messages: self.echo_messages.clone(),
        };
        let dm = DirectMessage::new::<P, _>(&message).unwrap();
        Ok((dm, Artifact::empty()))
    }

    fn receive_message(
        &self,
        from: &I,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Self::Protocol>> {
        debug!(
            "{:?}: received an echo message from {:?}",
            self.verifier, from
        );

        let message = direct_message
            .try_deserialize::<P, EchoRoundMessage<I, S>>()
            .unwrap();

        // Insert the `from`'s echo message to what we received.
        // It would be pointless to send it the second time,
        // But we need it included to compare with the full set of echo messages that we have.
        let mut echo_messages = message.echo_messages;
        echo_messages.insert(from.clone(), self.echo_messages[from].clone());

        /*
           TODO: better checks. Also, which failures would be provable?
           Which would require a correctness proof?

           Are there cases where there may be some missing entries, but it's fine because
           we only need a threshold of received messages? How do we handle this situation?

           Possible failures:
           - extra entry in the received message
           - missing entry in the received message
           - invalid signature in an entry in the received message
           - difference between messages or metadata in the entries for some verifier
        */
        if echo_messages != self.echo_messages {
            debug!(
                "{:?}: echo messages mismatch: {:?}, {:?}",
                self.verifier, echo_messages, self.echo_messages
            );
            return Err(ReceiveError::InvalidMessage(
                "Echo messages mismatch".into(),
            ));
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
