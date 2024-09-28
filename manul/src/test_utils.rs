use alloc::collections::BTreeMap;
use core::fmt::Debug;

use rand::Rng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

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

fn try_finalize<P, Signer, Verifier, S>(
    state: State<P, Signer, Verifier, S>,
) -> (
    bool,
    State<P, Signer, Verifier, S>,
    Vec<Message<Verifier, S>>,
)
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
    let (mut session, mut accum) = match state {
        State::InProgress { session, accum } => (session, accum),
        state => return (false, state, Vec::new()),
    };

    let mut state_changed = false;
    let mut messages = Vec::new();

    loop {
        (session, accum) = {
            if !session.can_finalize(&accum) {
                break;
            }

            let (session, cached_messages) = match session.finalize_round(accum) {
                Ok(RoundOutcome::Result(result)) => return (true, State::Result(result), messages),
                Err(error) => return (true, State::Error(error), messages),
                Ok(RoundOutcome::AnotherRound {
                    session,
                    cached_messages,
                }) => (session, cached_messages),
            };

            state_changed = true;
            let mut accum = session.make_accumulator();

            for message in cached_messages {
                let processed = session.process_message(message).unwrap();
            }

            let destinations = session.message_destinations();
            for destination in destinations.iter() {
                let (message, artifact) = session.make_message(destination).unwrap();
                messages.push(Message {
                    from: session.verifier().clone(),
                    to: destination.clone(),
                    message,
                });
                accum.add_artifact(artifact);
            }

            (session, accum)
        }
    }

    let new_state = State::InProgress { session, accum };
    (state_changed, new_state, messages)
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
            for destination in destinations.iter() {
                let (message, artifact) = session.make_message(destination).unwrap();
                messages.push(Message {
                    from: verifier.clone(),
                    to: destination.clone(),
                    message,
                });
                accum.add_artifact(artifact);
            }

            let state = State::InProgress { session, accum };
            (verifier, state)
        })
        .collect::<BTreeMap<_, _>>();

    let ids = states.keys().cloned().collect::<Vec<_>>();

    loop {
        // If there are no messages to deliver, check if any states can be finalized
        let mut states_changed = false;
        for id in ids.iter() {
            let state = states.remove(id).unwrap();
            let (state_changed, new_state, new_messages) = try_finalize(state);
            messages.extend(new_messages);
            states.insert(id.clone(), new_state);
            states_changed |= state_changed;
        }

        // If there were no changes of state, time to return results
        if !states_changed {
            break;
        }

        // Pick a random message and deliver it
        let message_idx = rng.gen_range(0..messages.len());
        let message = messages.swap_remove(message_idx);

        let state = states.get_mut(&message.to).unwrap();
        match state {
            State::InProgress {
                session,
                ref mut accum,
            } => {
                let preprocessed = session
                    .preprocess_message(accum, &message.from, message.message)
                    .unwrap();

                if let Some(verified) = preprocessed {
                    let processed = session.process_message(verified).unwrap();
                    accum.add_processed_message(processed);
                }
            }
            _ => (),
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
