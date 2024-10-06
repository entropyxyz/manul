use alloc::collections::BTreeMap;
use core::fmt::Debug;

use rand::Rng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::message::MessageBundle;
use crate::session::{RoundAccumulator, SessionReport};
use crate::signing::{DigestSigner, DigestVerifier, Keypair};
use crate::{FirstRound, LocalError, Protocol, RoundOutcome, Session};

pub enum RunOutcome<P: Protocol, Verifier, S> {
    Report(SessionReport<P, Verifier, S>),
    Stalled, // TODO: save the round ID at which the session stalled
}

impl<P: Protocol, Verifier, S> RunOutcome<P, Verifier, S> {
    pub fn unwrap_report(self) -> SessionReport<P, Verifier, S> {
        match self {
            Self::Report(report) => report,
            Self::Stalled => panic!("The run stalled"),
        }
    }
}

enum State<P: Protocol, Signer, Verifier, S> {
    InProgress {
        session: Session<P, Signer, Verifier, S>,
        accum: RoundAccumulator<P, Verifier, S>,
    },
    Finished(SessionReport<P, Verifier, S>),
}

struct Message<Verifier, S> {
    from: Verifier,
    to: Verifier,
    message: MessageBundle<S>,
}

fn propagate<P, Signer, Verifier, S>(
    session: Session<P, Signer, Verifier, S>,
    accum: RoundAccumulator<P, Verifier, S>,
) -> Result<(State<P, Signer, Verifier, S>, Vec<Message<Verifier, S>>), LocalError>
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
        + for<'de> Deserialize<'de>
        + Send
        + Sync,
    S: Debug + Clone + Eq + 'static + Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    let mut messages = Vec::new();

    let mut session = session;
    let mut accum = accum;

    let state = loop {
        if session.can_finalize(&accum) {
            debug!(
                "{:?}: finalizing {:?}",
                session.verifier(),
                session.round_id(),
            );
            match session.finalize_round(accum)? {
                RoundOutcome::Finished(report) => break State::Finished(report),
                RoundOutcome::AnotherRound {
                    session: new_session,
                    cached_messages,
                } => {
                    session = new_session;
                    accum = session.make_accumulator();

                    for message in cached_messages {
                        debug!(
                            "Delivering cached message from {:?} to {:?}",
                            message.from(),
                            session.verifier()
                        );
                        let processed = session.process_message(message)?;
                        session.add_processed_message(&mut accum, processed)?;
                    }
                }
            }
        } else {
            break State::InProgress { session, accum };
        }

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(destination)?;
            messages.push(Message {
                from: session.verifier().clone(),
                to: destination.clone(),
                message,
            });
            session.add_artifact(&mut accum, artifact)?;
        }
    };

    Ok((state, messages))
}

pub fn run_sync<R, Signer, Verifier, S>(
    rng: &mut impl RngCore,
    inputs: Vec<(Signer, R::Inputs)>,
) -> Result<BTreeMap<Verifier, RunOutcome<R::Protocol, Verifier, S>>, LocalError>
where
    R: FirstRound<Verifier> + 'static,
    Signer: DigestSigner<<R::Protocol as Protocol>::Digest, S> + Keypair<VerifyingKey = Verifier>,
    Verifier: Debug
        + Clone
        + Eq
        + Ord
        + DigestVerifier<<R::Protocol as Protocol>::Digest, S>
        + 'static
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync,
    S: Debug + Clone + Eq + 'static + Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    let mut messages = Vec::new();

    let mut states = BTreeMap::new();

    for (signer, inputs) in inputs {
        let verifier = signer.verifying_key();
        let session = Session::<R::Protocol, Signer, Verifier, S>::new::<R>(signer, inputs)?;
        let mut accum = session.make_accumulator();

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(destination)?;
            messages.push(Message {
                from: session.verifier().clone(),
                to: destination.clone(),
                message,
            });
            session.add_artifact(&mut accum, artifact)?;
        }

        let (state, new_messages) = propagate(session, accum)?;
        messages.extend(new_messages);
        states.insert(verifier, state);
    }

    let ids = states.keys().cloned().collect::<Vec<_>>();

    loop {
        // Pick a random message and deliver it
        let message_idx = rng.gen_range(0..messages.len());
        let message = messages.swap_remove(message_idx);

        debug!(
            "Delivering message from {:?} to {:?}",
            message.from, message.to
        );

        let state = states
            .remove(&message.to)
            .expect("the message destination is one of the sessions");
        let new_state = if let State::InProgress { session, accum } = state {
            let mut accum = accum;
            let preprocessed =
                session.preprocess_message(&mut accum, &message.from, message.message)?;

            if let Some(verified) = preprocessed {
                let processed = session.process_message(verified)?;
                session.add_processed_message(&mut accum, processed)?;
            }

            let (new_state, new_messages) = propagate(session, accum)?;
            messages.extend(new_messages);
            new_state
        } else {
            state
        };
        states.insert(message.to.clone(), new_state);

        if messages.is_empty() {
            break;
        }
    }

    let outcomes = states
        .into_iter()
        .map(|(verifier, state)| {
            let outcome = match state {
                State::InProgress { .. } => RunOutcome::Stalled,
                State::Finished(report) => RunOutcome::Report(report),
            };
            (verifier, outcome)
        })
        .collect();

    Ok(outcomes)
}
