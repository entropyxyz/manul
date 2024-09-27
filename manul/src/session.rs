use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

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
    messages: BTreeMap<RoundId, BTreeMap<Verifier, SignedMessage<S, DirectMessage>>>,
}

pub enum RoundOutcome<P: Protocol, Signer, Verifier, S> {
    Result(P::Result),
    AnotherRound {
        session: Session<P, Signer, Verifier, S>,
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
    S: Clone + Eq + 'static + Serialize + for<'de> Deserialize<'de>,
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

        Self {
            signer,
            verifier,
            round,
            echo_message,
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

    pub fn verify_message(
        &self,
        from: &Verifier,
        message: MessageBundle<S>,
    ) -> Result<VerifiedMessageBundle<Verifier, S>, RemoteError> {
        message.verify::<P, _>(from)
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
        if let Some(echo_message) = self.echo_message {
            let echo_messages = accum.echo_messages.clone();
            let round = Box::new(EchoRound::new(
                echo_messages,
                self.round,
                accum.payloads,
                accum.artifacts,
            ));
            let session = Session::new_for_next_round(self.signer, round);
            return Ok(RoundOutcome::AnotherRound { session });
        }

        match self.round.finalize(accum.payloads, accum.artifacts) {
            Ok(result) => Ok(match result {
                FinalizeOutcome::Result(result) => RoundOutcome::Result(result),
                FinalizeOutcome::AnotherRound(round) => RoundOutcome::AnotherRound {
                    session: Session::new_for_next_round(self.signer, round),
                },
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
}

impl<Verifier: Clone + Ord, S> RoundAccumulator<Verifier, S> {
    pub fn new() -> Self {
        Self {
            echo_messages: BTreeMap::new(),
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    pub fn add_artifact(&mut self, processed: ProcessedArtifact<Verifier>) {
        self.artifacts
            .insert(processed.destination, processed.artifact);
    }

    pub fn add_processed_message(&mut self, processed: ProcessedMessage<Verifier, S>) {
        self.payloads.insert(processed.from, processed.payload);
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
