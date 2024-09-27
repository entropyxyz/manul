use alloc::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

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
    echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
    destinations: BTreeSet<I>,
    main_round: Box<dyn Round<I, Protocol = P>>,
    payloads: BTreeMap<I, Payload>,
    artifacts: BTreeMap<I, Artifact>,
}

impl<P: Protocol, I: Clone + Ord, S> EchoRound<P, I, S> {
    pub fn new(
        echo_messages: BTreeMap<I, SignedMessage<S, EchoBroadcast>>,
        main_round: Box<dyn Round<I, Protocol = P>>,
        payloads: BTreeMap<I, Payload>,
        artifacts: BTreeMap<I, Artifact>,
    ) -> Self {
        let destinations = echo_messages.keys().cloned().collect();
        Self {
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
    I: Clone + Ord + Serialize + for<'de> Deserialize<'de> + Eq,
    S: Clone + Serialize + for<'de> Deserialize<'de> + Eq,
{
    type Protocol = P;

    fn id(&self) -> RoundId {
        self.main_round.id().echo()
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.destinations
    }

    fn make_direct_message(
        &self,
        destination: &I,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
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
        let message = direct_message
            .try_deserialize::<P, EchoRoundMessage<I, S>>()
            .unwrap();

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
        if message.echo_messages != self.echo_messages {
            return Err(ReceiveError::InvalidMessage);
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self: Box<Self>,
        _payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, FinalizeError> {
        self.main_round.finalize(self.payloads, self.artifacts)
    }

    fn can_finalize(
        &self,
        payloads: &BTreeMap<I, Payload>,
        _artifacts: &BTreeMap<I, Artifact>,
    ) -> bool {
        payloads
            .keys()
            .all(|from| self.message_destinations().contains(from))
    }
}
