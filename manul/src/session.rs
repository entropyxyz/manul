use alloc::collections::{BTreeMap, BTreeSet};

use crate::error::{Evidence, LocalError, RemoteError};
use crate::message::{MessageBundle, SignedMessage, VerifiedMessageBundle};
use crate::round::{
    Artifact, DirectMessage, FirstRound, Payload, ProtocolError, ReceiveError, RoundId,
};
use crate::{Error, Protocol, Round};

pub struct Session<I, P> {
    my_id: I,
    round: Box<dyn Round<I, Protocol = P>>,
    messages: BTreeMap<RoundId, BTreeMap<I, SignedMessage<I, DirectMessage>>>,
}

pub enum RoundOutcome<I, P: Protocol> {
    Result(P::Result),
    AnotherRound { session: Session<I, P> },
}

impl<I: Clone + Eq + Ord, P: Protocol> Session<I, P> {
    pub fn new<R>(my_id: I, inputs: R::Inputs) -> Self
    where
        R: FirstRound<I> + Round<I, Protocol = P> + 'static,
    {
        let round = R::new(inputs).unwrap();
        Self {
            my_id,
            round: Box::new(round),
            messages: BTreeMap::new(),
        }
    }

    pub fn party_id(&self) -> I {
        unimplemented!()
    }

    pub fn message_destinations(&self) -> BTreeSet<I> {
        self.round.message_destinations()
    }

    pub fn make_message(
        &self,
        destination: &I,
    ) -> Result<(MessageBundle<I>, Artifact), LocalError> {
        let (direct_message, artifact) = self.round.make_direct_message(destination)?;
        let echo_broadcast = self.round.make_echo_broadcast()?;

        let bundle =
            MessageBundle::new(&self.my_id, self.round.id(), direct_message, echo_broadcast);

        Ok((bundle, artifact))
    }

    pub fn verify_message(
        &self,
        from: &I,
        message: MessageBundle<I>,
    ) -> Result<VerifiedMessageBundle<I>, RemoteError> {
        message.verify(from)
    }

    pub fn process_message(
        &self,
        message: VerifiedMessageBundle<I>,
    ) -> Result<ProcessedMessage, Error<I, P>> {
        match self.round.receive_message(
            message.from(),
            message.echo_broadcast().cloned(),
            message.direct_message().clone(),
        ) {
            Ok(payload) => Ok(ProcessedMessage { payload }),
            Err(error) => match error {
                ReceiveError::InvalidMessage => unimplemented!(),
                ReceiveError::Protocol(error) => {
                    let from = message.from().clone();
                    let (echo, dm) = message.into_unverified();
                    Err(Error::Protocol(self.prepare_evidence(&from, &dm, error)))
                }
            },
        }
    }

    pub fn make_accumulator(&self) -> RoundAccumulator {
        unimplemented!()
    }

    pub fn finalize_round(
        self,
        accum: RoundAccumulator,
    ) -> Result<RoundOutcome<I, P>, Error<I, P>> {
        unimplemented!()
    }

    fn prepare_evidence(
        &self,
        from: &I,
        message: &SignedMessage<I, DirectMessage>,
        error: P::ProtocolError,
    ) -> Evidence<I, P> {
        let rounds = error.required_rounds();

        let messages = rounds
            .iter()
            .map(|round| (*round, self.messages[round][from].clone()))
            .collect();

        Evidence {
            party: from.clone(),
            error,
            message: message.clone(),
            previous_messages: messages,
        }
    }
}

pub struct RoundAccumulator;

impl RoundAccumulator {
    pub fn add_artifact(&mut self, artifact: Artifact) {
        unimplemented!()
    }

    pub fn add_processed_message(&mut self, processed: ProcessedMessage) {
        unimplemented!()
    }
}

pub struct VerifiedMessage<I> {
    from: I,
}

pub struct ProcessedMessage {
    payload: Payload,
}
