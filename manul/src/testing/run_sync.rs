use alloc::collections::BTreeMap;
use core::fmt::Debug;

use rand::Rng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::message::MessageBundle;
use crate::session::RoundAccumulator;
use crate::signing::{DigestSigner, DigestVerifier, Keypair};
use crate::{Error, FirstRound, Protocol, RoundOutcome, Session};

#[derive(Debug, Clone)]
pub enum RunOutcome<P: Protocol, Verifier, S> {
    Result(P::Result),
    // TODO: inlcude the round ID where the error occurred
    Error(Error<P, Verifier, S>),
    Stalled,
}

enum State<P: Protocol, Signer, Verifier, S> {
    InProgress {
        session: Session<P, Signer, Verifier, S>,
        accum: RoundAccumulator<Verifier, S>,
    },
    Result(P::Result),
    // TODO: inlcude the round ID where the error occurred
    Error(Error<P, Verifier, S>),
}

struct Message<Verifier, S> {
    from: Verifier,
    to: Verifier,
    message: MessageBundle<S>,
}

fn propagate<P, Signer, Verifier, S>(
    session: Session<P, Signer, Verifier, S>,
    accum: RoundAccumulator<Verifier, S>,
) -> (State<P, Signer, Verifier, S>, Vec<Message<Verifier, S>>)
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
            match session.finalize_round(accum) {
                Ok(RoundOutcome::Result(result)) => break State::Result(result),
                Err(error) => break State::Error(error),
                Ok(RoundOutcome::AnotherRound {
                    session: new_session,
                    cached_messages,
                }) => {
                    session = new_session;
                    accum = session.make_accumulator();

                    for message in cached_messages {
                        debug!(
                            "Delivering cached message from {:?} to {:?}",
                            message.from(),
                            session.verifier()
                        );
                        let processed = session.process_message(message).unwrap();
                        accum.add_processed_message(processed);
                    }
                }
            }
        } else {
            break State::InProgress { session, accum };
        }

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(destination).unwrap();
            messages.push(Message {
                from: session.verifier().clone(),
                to: destination.clone(),
                message,
            });
            accum.add_artifact(artifact);
        }
    };

    (state, messages)
}

pub fn run_sync<R, Signer, Verifier, S>(
    rng: &mut impl RngCore,
    inputs: Vec<(Signer, R::Inputs)>,
) -> Result<BTreeMap<Verifier, RunOutcome<R::Protocol, Verifier, S>>, String>
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
        + for<'de> Deserialize<'de>,
    S: Debug + Clone + Eq + 'static + Serialize + for<'de> Deserialize<'de>,
{
    let mut messages = Vec::new();

    let mut states = inputs
        .into_iter()
        .map(|(signer, inputs)| {
            let verifier = signer.verifying_key();
            let session = Session::<R::Protocol, Signer, Verifier, S>::new::<R>(signer, inputs);
            let mut accum = session.make_accumulator();

            let destinations = session.message_destinations();
            for destination in destinations {
                let (message, artifact) = session.make_message(destination).unwrap();
                messages.push(Message {
                    from: session.verifier().clone(),
                    to: destination.clone(),
                    message,
                });
                accum.add_artifact(artifact);
            }

            let (state, new_messages) = propagate(session, accum);
            messages.extend(new_messages);
            (verifier, state)
        })
        .collect::<BTreeMap<_, _>>();

    let ids = states.keys().cloned().collect::<Vec<_>>();

    loop {
        // Pick a random message and deliver it
        let message_idx = rng.gen_range(0..messages.len());
        let message = messages.swap_remove(message_idx);

        debug!(
            "Delivering message from {:?} to {:?}",
            message.from, message.to
        );

        let state = states.remove(&message.to).unwrap();
        let new_state = if let State::InProgress { session, accum } = state {
            let mut accum = accum;
            let preprocessed = session
                .preprocess_message(&mut accum, &message.from, message.message)
                .unwrap();

            if let Some(verified) = preprocessed {
                let processed = session.process_message(verified).unwrap();
                accum.add_processed_message(processed);
            }

            let (new_state, new_messages) = propagate(session, accum);
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
                State::Result(result) => RunOutcome::Result(result),
                State::Error(error) => RunOutcome::Error(error),
            };
            (verifier, outcome)
        })
        .collect();

    Ok(outcomes)
}
