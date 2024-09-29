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
    pub fn new<R>(signer: Signer, inputs: R::Inputs) -> Result<Self, LocalError>
    where
        R: FirstRound<Verifier> + Round<Verifier, Protocol = P> + 'static,
    {
        let verifier = signer.verifying_key();
        let first_round = Box::new(R::new(verifier.clone(), inputs)?);
        Self::new_for_next_round(signer, first_round)
    }

    fn new_for_next_round(
        signer: Signer,
        round: Box<dyn Round<Verifier, Protocol = P>>,
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();
        let echo_message = round
            .make_echo_broadcast()
            .transpose()?
            .map(|echo| SignedMessage::new::<P, _>(&signer, round.id(), echo))
            .transpose()?;
        let message_destinations = round.message_destinations().clone();

        let possible_next_rounds = if echo_message.is_none() {
            round.possible_next_rounds()
        } else {
            BTreeSet::from([round.id().echo()])
        };

        Ok(Self {
            signer,
            verifier,
            round,
            echo_message,
            possible_next_rounds,
            message_destinations,
            messages: BTreeMap::new(),
        })
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
        )?;

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
    ) -> Result<Option<VerifiedMessageBundle<Verifier, S>>, Error<P, Verifier, S>> {
        // Quick preliminary checks, before we proceed with more expensive verification

        let checked_message = message.unify_metadata().ok_or_else(|| {
            Error::Remote(RemoteError::new(
                from.clone(),
                "Mismatched metadata in bundled messages".into(),
            ))
        })?;
        let message_round_id = checked_message.metadata().round_id();

        // TODO: check session ID here

        if message_round_id == self.round_id() {
            if accum.message_is_being_processed(from) {
                return Err(Error::Remote(RemoteError::new(
                    from.clone(),
                    format!("Message from {:?} is already being processed", from),
                )));
            }
        } else if self.possible_next_rounds.contains(&message_round_id) {
            if accum.message_is_cached(from, message_round_id) {
                return Err(Error::Remote(RemoteError::new(
                    from.clone(),
                    format!(
                        "Message from {:?} for {:?} is already cached",
                        from, message_round_id
                    ),
                )));
            }
        } else {
            return Err(Error::Remote(RemoteError::new(
                from.clone(),
                format!("Unexpected message round ID: {:?}", message_round_id),
            )));
        }

        // Verify the signature now

        let verified_message = checked_message
            .verify::<P, _>(from)
            .map_err(|err| err.into_error())?;
        debug!(
            "{:?}: received {:?} message from {:?}",
            self.verifier(),
            verified_message.metadata().round_id(),
            from
        );

        if message_round_id == self.round_id() {
            accum
                .mark_processing(&verified_message)
                .map_err(Error::Local)?;
            Ok(Some(verified_message))
        } else if self.possible_next_rounds.contains(&message_round_id) {
            debug!(
                "{:?}: caching message from {:?} for {:?}",
                self.verifier(),
                verified_message.from(),
                verified_message.metadata().round_id()
            );
            accum
                .cache_message(verified_message)
                .map_err(Error::Local)?;
            Ok(None)
        } else {
            // TODO: can we enforce it through types?
            unreachable!()
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
                ReceiveError::InvalidMessage(error) => unimplemented!(),
                ReceiveError::Protocol(error) => {
                    let from = message.from().clone();
                    let (echo, dm) = message.into_unverified();
                    Err(Error::Protocol(self.prepare_evidence(&from, &dm, error)))
                }
                ReceiveError::Local(error) => Err(Error::Local(error)),
                ReceiveError::Unprovable(error) => Err(Error::Remote(RemoteError::new(
                    message.from().clone(),
                    error,
                ))),
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
            let session = Session::new_for_next_round(self.signer, round).map_err(Error::Local)?;
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
                    let session =
                        Session::new_for_next_round(self.signer, round).map_err(Error::Local)?;
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
    processing: BTreeSet<Verifier>,
    echo_messages: BTreeMap<Verifier, SignedMessage<S, EchoBroadcast>>,
    payloads: BTreeMap<Verifier, Payload>,
    artifacts: BTreeMap<Verifier, Artifact>,
    cached: BTreeMap<Verifier, BTreeMap<RoundId, VerifiedMessageBundle<Verifier, S>>>,
}

impl<Verifier: Debug + Clone + Ord, S> RoundAccumulator<Verifier, S> {
    pub fn new() -> Self {
        Self {
            processing: BTreeSet::new(),
            echo_messages: BTreeMap::new(),
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            cached: BTreeMap::new(),
        }
    }

    fn message_is_being_processed(&self, from: &Verifier) -> bool {
        self.processing.contains(from)
    }

    fn message_is_cached(&self, from: &Verifier, round_id: RoundId) -> bool {
        if let Some(entry) = self.cached.get(from) {
            entry.contains_key(&round_id)
        } else {
            false
        }
    }

    fn mark_processing(
        &mut self,
        message: &VerifiedMessageBundle<Verifier, S>,
    ) -> Result<(), LocalError> {
        if !self.processing.insert(message.from().clone()) {
            Err(LocalError::new(format!(
                "A message from {:?} is already marked as being processed",
                message.from()
            )))
        } else {
            Ok(())
        }
    }

    pub fn add_artifact(
        &mut self,
        processed: ProcessedArtifact<Verifier>,
    ) -> Result<(), LocalError> {
        if self
            .artifacts
            .insert(processed.destination.clone(), processed.artifact)
            .is_some()
        {
            return Err(LocalError::new(format!(
                "Artifact for destination {:?} has already been recorded",
                processed.destination
            )));
        }
        Ok(())
    }

    pub fn add_processed_message(
        &mut self,
        processed: ProcessedMessage<Verifier, S>,
    ) -> Result<(), LocalError> {
        let (echo_broadcast, direct_message) = processed.message.into_unverified();
        if self.payloads.contains_key(&processed.from) {
            return Err(LocalError::new(format!(
                "A processed message from {:?} has already been recorded",
                processed.from
            )));
        }
        if let Some(echo) = echo_broadcast {
            self.echo_messages.insert(processed.from.clone(), echo);
        }
        self.payloads.insert(processed.from, processed.payload);
        Ok(())
    }

    fn cache_message(
        &mut self,
        message: VerifiedMessageBundle<Verifier, S>,
    ) -> Result<(), LocalError> {
        let from = message.from().clone();
        let round_id = message.metadata().round_id();
        let cached = self.cached.entry(from.clone()).or_insert(BTreeMap::new());
        if cached.insert(round_id, message).is_some() {
            return Err(LocalError::new(format!(
                "A message from for {:?} has already been cached",
                round_id
            )));
        }
        Ok(())
    }
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
