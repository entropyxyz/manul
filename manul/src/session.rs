use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::echo::EchoRound;
use crate::error::{Evidence, LocalError, RemoteError};
use crate::message::{MessageBundle, SignedMessage, VerifiedMessageBundle};
use crate::round::{
    Artifact, DirectMessage, EchoBroadcast, FinalizeOutcome, FirstRound, Payload, ProtocolError,
    ReceiveError, RoundId,
};
use crate::signing::{DigestSigner, DigestVerifier, Keypair};
use crate::{Error, Protocol, Round};

pub struct Session<P, Signer, Verifier, S> {
    signer: Signer,
    verifier: Verifier,
    round: Box<dyn Round<Verifier, Protocol = P>>,
    message_destinations: BTreeSet<Verifier>,
    echo_message: Option<SignedMessage<S, EchoBroadcast>>,
    possible_next_rounds: BTreeSet<RoundId>,
    messages: BTreeMap<RoundId, BTreeMap<Verifier, SignedMessage<S, DirectMessage>>>,
}

pub enum RoundOutcome<P: Protocol, Signer, Verifier, S> {
    Result(P::Result),
    AnotherRound {
        session: Session<P, Signer, Verifier, S>,
        cached_messages: Vec<VerifiedMessageBundle<Verifier, S>>,
    },
}

impl<P, Signer, Verifier, S> Session<P, Signer, Verifier, S>
where
    P: Protocol + 'static,
    Signer: DigestSigner<P::Digest, S> + Keypair<VerifyingKey = Verifier>,
    Verifier: Debug
        + Clone
        + Eq
        + Ord
        + DigestVerifier<P::Digest, S>
        + 'static
        + Serialize
        + for<'de> Deserialize<'de>,
    S: Debug + Clone + Eq + 'static + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new<R>(signer: Signer, inputs: R::Inputs) -> Self
    where
        R: FirstRound<Verifier> + Round<Verifier, Protocol = P> + 'static,
    {
        let verifier = signer.verifying_key();
        let first_round = Box::new(R::new(verifier.clone(), inputs).unwrap());
        Self::new_for_next_round(signer, first_round)
    }

    fn new_for_next_round(signer: Signer, round: Box<dyn Round<Verifier, Protocol = P>>) -> Self {
        let verifier = signer.verifying_key();
        let echo_message = round
            .make_echo_broadcast()
            .map(|echo| SignedMessage::new::<P, _>(&signer, round.id(), echo.unwrap()));
        let message_destinations = round.message_destinations().clone();

        let possible_next_rounds = if echo_message.is_none() {
            debug!(
                "{:?}: no echo messages, possible next rounds: {:?}",
                verifier,
                round.possible_next_rounds()
            );
            round.possible_next_rounds()
        } else {
            debug!("{:?}: there are echo messages", verifier);
            BTreeSet::from([round.id().echo()])
        };

        Self {
            signer,
            verifier,
            round,
            echo_message,
            possible_next_rounds,
            message_destinations,
            messages: BTreeMap::new(),
        }
    }

    pub fn verifier(&self) -> Verifier {
        self.verifier.clone()
    }

    pub fn message_destinations(&self) -> &BTreeSet<Verifier> {
        &self.message_destinations
    }

    pub fn make_message(
        &self,
        destination: &Verifier,
    ) -> Result<(MessageBundle<S>, ProcessedArtifact<Verifier>), LocalError> {
        let (direct_message, artifact) = self.round.make_direct_message(destination)?;

        let bundle = MessageBundle::new::<P, _>(
            &self.signer,
            self.round.id(),
            direct_message,
            self.echo_message.clone(),
        );

        Ok((
            bundle,
            ProcessedArtifact {
                destination: destination.clone(),
                artifact,
            },
        ))
    }

    pub fn round_id(&self) -> RoundId {
        self.round.id()
    }

    pub fn preprocess_message(
        &self,
        accum: &mut RoundAccumulator<Verifier, S>,
        from: &Verifier,
        message: MessageBundle<S>,
    ) -> Result<Option<VerifiedMessageBundle<Verifier, S>>, RemoteError> {
        let message = message.verify::<P, _>(from)?;
        debug!(
            "{:?}: received {:?} message from {:?}",
            self.verifier(),
            message.round_id(),
            from
        );
        if self.possible_next_rounds.contains(&message.round_id()) {
            debug!(
                "{:?}: possible next rounds: {:?}",
                self.verifier, self.possible_next_rounds
            );
            debug!(
                "{:?}: caching message from {:?} for {:?}",
                self.verifier(),
                message.from(),
                message.round_id()
            );
            accum.cache_message(message);
            Ok(None)
        } else {
            Ok(Some(message))
        }
    }

    pub fn process_message(
        &self,
        message: VerifiedMessageBundle<Verifier, S>,
    ) -> Result<ProcessedMessage<Verifier, S>, Error<P, Verifier, S>> {
        match self.round.receive_message(
            message.from(),
            message.echo_broadcast().cloned(),
            message.direct_message().clone(),
        ) {
            Ok(payload) => Ok(ProcessedMessage {
                from: message.from().clone(),
                message,
                payload,
            }),
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

    pub fn make_accumulator(&self) -> RoundAccumulator<Verifier, S> {
        RoundAccumulator::new()
    }

    pub fn finalize_round(
        self,
        accum: RoundAccumulator<Verifier, S>,
    ) -> Result<RoundOutcome<P, Signer, Verifier, S>, Error<P, Verifier, S>> {
        let verifier = self.verifier().clone();
        if let Some(echo_message) = self.echo_message {
            let round = Box::new(EchoRound::new(
                verifier,
                echo_message,
                accum.echo_messages,
                self.round,
                accum.payloads,
                accum.artifacts,
            ));
            let cached_messages = filter_messages(accum.cached, round.id());
            let session = Session::new_for_next_round(self.signer, round);
            return Ok(RoundOutcome::AnotherRound {
                session,
                cached_messages,
            });
        }

        match self.round.finalize(accum.payloads, accum.artifacts) {
            Ok(result) => Ok(match result {
                FinalizeOutcome::Result(result) => RoundOutcome::Result(result),
                FinalizeOutcome::AnotherRound(round) => {
                    let cached_messages = filter_messages(accum.cached, round.id());
                    let session = Session::new_for_next_round(self.signer, round);
                    RoundOutcome::AnotherRound {
                        cached_messages,
                        session,
                    }
                }
            }),
            Err(error) => unimplemented!(),
        }
    }

    pub fn can_finalize(&self, accum: &RoundAccumulator<Verifier, S>) -> bool {
        self.round.can_finalize(&accum.payloads, &accum.artifacts)
    }

    fn prepare_evidence(
        &self,
        from: &Verifier,
        message: &SignedMessage<S, DirectMessage>,
        error: P::ProtocolError,
    ) -> Evidence<P, Verifier, S> {
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

pub struct RoundAccumulator<Verifier, S> {
    echo_messages: BTreeMap<Verifier, SignedMessage<S, EchoBroadcast>>,
    payloads: BTreeMap<Verifier, Payload>,
    artifacts: BTreeMap<Verifier, Artifact>,
    cached: BTreeMap<Verifier, BTreeMap<RoundId, VerifiedMessageBundle<Verifier, S>>>,
}

impl<Verifier: Debug + Clone + Ord, S> RoundAccumulator<Verifier, S> {
    pub fn new() -> Self {
        Self {
            echo_messages: BTreeMap::new(),
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            cached: BTreeMap::new(),
        }
    }

    pub fn add_artifact(&mut self, processed: ProcessedArtifact<Verifier>) {
        self.artifacts
            .insert(processed.destination, processed.artifact);
    }

    pub fn add_processed_message(&mut self, processed: ProcessedMessage<Verifier, S>) {
        let (echo_broadcast, direct_message) = processed.message.into_unverified();
        if let Some(echo) = echo_broadcast {
            self.echo_messages.insert(processed.from.clone(), echo);
        }
        self.payloads.insert(processed.from, processed.payload);
    }

    fn cache_message(&mut self, message: VerifiedMessageBundle<Verifier, S>) {
        if !self.cached.contains_key(message.from()) {
            self.cached.insert(message.from().clone(), BTreeMap::new());
        }
        self.cached
            .get_mut(message.from())
            .unwrap()
            .insert(message.round_id(), message);
    }
}

pub struct VerifiedMessage<Verifier> {
    from: Verifier,
}

pub struct ProcessedArtifact<Verifier> {
    destination: Verifier,
    artifact: Artifact,
}

pub struct ProcessedMessage<Verifier, S> {
    from: Verifier,
    message: VerifiedMessageBundle<Verifier, S>,
    payload: Payload,
}

fn filter_messages<Verifier, S>(
    messages: BTreeMap<Verifier, BTreeMap<RoundId, VerifiedMessageBundle<Verifier, S>>>,
    round_id: RoundId,
) -> Vec<VerifiedMessageBundle<Verifier, S>> {
    messages
        .into_values()
        .filter_map(|mut messages| messages.remove(&round_id))
        .collect()
}
