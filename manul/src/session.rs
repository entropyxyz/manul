use alloc::collections::{BTreeMap, BTreeSet};
use core::marker::PhantomData;

use crate::error::{Evidence, LocalError, RemoteError};
use crate::message::{MessageBundle, SignedMessage, VerifiedMessageBundle};
use crate::round::{
    Artifact, DirectMessage, FinalizeOutcome, FirstRound, Payload, ProtocolError, ReceiveError,
    RoundId,
};
use crate::signing::{DigestSigner, DigestVerifier, Keypair};
use crate::{Error, Protocol, Round};

pub struct Session<P, Signer, Verifier, S> {
    signer: Signer,
    verifier: Verifier,
    round: Box<dyn Round<Verifier, Protocol = P>>,
    messages: BTreeMap<RoundId, BTreeMap<Verifier, SignedMessage<S, DirectMessage>>>,
    phantom: PhantomData<S>,
}

pub enum RoundOutcome<P: Protocol, Signer, Verifier, S> {
    Result(P::Result),
    AnotherRound {
        session: Session<P, Signer, Verifier, S>,
    },
}

impl<P, Signer, Verifier, S> Session<P, Signer, Verifier, S>
where
    P: Protocol,
    Signer: DigestSigner<P::Digest, S> + Keypair<VerifyingKey = Verifier>,
    Verifier: Clone + Eq + Ord + DigestVerifier<P::Digest, S>,
    S: Clone + Eq,
{
    pub fn new<R>(signer: Signer, inputs: R::Inputs) -> Self
    where
        R: FirstRound<Verifier> + Round<Verifier, Protocol = P> + 'static,
    {
        let verifier = signer.verifying_key();
        let round = R::new(verifier.clone(), inputs).unwrap();
        Self {
            signer,
            verifier,
            round: Box::new(round),
            messages: BTreeMap::new(),
            phantom: PhantomData,
        }
    }

    pub fn verifier(&self) -> Verifier {
        self.verifier.clone()
    }

    pub fn message_destinations(&self) -> &BTreeSet<Verifier> {
        self.round.message_destinations()
    }

    pub fn make_message(
        &self,
        destination: &Verifier,
    ) -> Result<(MessageBundle<S>, ProcessedArtifact<Verifier>), LocalError> {
        let (direct_message, artifact) = self.round.make_direct_message(destination)?;
        let echo_broadcast = self.round.make_echo_broadcast()?;

        let bundle = MessageBundle::new::<P, _>(
            &self.signer,
            self.round.id(),
            direct_message,
            echo_broadcast,
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
    ) -> Result<ProcessedMessage<Verifier>, Error<P, Verifier, S>> {
        match self.round.receive_message(
            message.from(),
            message.echo_broadcast().cloned(),
            message.direct_message().clone(),
        ) {
            Ok(payload) => Ok(ProcessedMessage {
                from: message.from().clone(),
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

    pub fn make_accumulator(&self) -> RoundAccumulator<Verifier> {
        RoundAccumulator::new()
    }

    pub fn finalize_round(
        self,
        accum: RoundAccumulator<Verifier>,
    ) -> Result<RoundOutcome<P, Signer, Verifier, S>, Error<P, Verifier, S>> {
        match self.round.finalize(accum.payloads, accum.artifacts) {
            Ok(result) => Ok(match result {
                FinalizeOutcome::Result(result) => RoundOutcome::Result(result),
                FinalizeOutcome::AnotherRound(round) => RoundOutcome::AnotherRound {
                    session: Session {
                        signer: self.signer,
                        verifier: self.verifier,
                        round,
                        messages: BTreeMap::new(),
                        phantom: PhantomData,
                    },
                },
            }),
            Err(error) => unimplemented!(),
        }
    }

    pub fn can_finalize(&self, accum: &RoundAccumulator<Verifier>) -> bool {
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

pub struct RoundAccumulator<Verifier> {
    payloads: BTreeMap<Verifier, Payload>,
    artifacts: BTreeMap<Verifier, Artifact>,
}

impl<Verifier: Clone + Ord> RoundAccumulator<Verifier> {
    pub fn new() -> Self {
        Self {
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    pub fn add_artifact(&mut self, processed: ProcessedArtifact<Verifier>) {
        self.artifacts
            .insert(processed.destination, processed.artifact);
    }

    pub fn add_processed_message(&mut self, processed: ProcessedMessage<Verifier>) {
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

pub struct ProcessedMessage<Verifier> {
    from: Verifier,
    payload: Payload,
}
