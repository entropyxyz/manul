use alloc::{collections::BTreeMap, vec::Vec};

use rand::Rng;
use rand_core::CryptoRngCore;
use signature::Keypair;
use tracing::debug;

use crate::{
    protocol::{FirstRound, Protocol},
    session::{
        CanFinalize, LocalError, MessageBundle, RoundAccumulator, RoundOutcome, Session, SessionId, SessionParameters,
        SessionReport,
    },
};

enum State<P: Protocol, SP: SessionParameters> {
    InProgress {
        session: Session<P, SP>,
        accum: RoundAccumulator<P, SP>,
    },
    Finished(SessionReport<P, SP>),
}

struct Message<SP: SessionParameters> {
    from: SP::Verifier,
    to: SP::Verifier,
    message: MessageBundle,
}

#[allow(clippy::type_complexity)]
fn propagate<P, SP>(
    rng: &mut impl CryptoRngCore,
    session: Session<P, SP>,
    accum: RoundAccumulator<P, SP>,
) -> Result<(State<P, SP>, Vec<Message<SP>>), LocalError>
where
    P: 'static + Protocol,
    SP: 'static + SessionParameters,
{
    let mut messages = Vec::new();

    let mut session = session;
    let mut accum = accum;

    let state = loop {
        match session.can_finalize(&accum) {
            CanFinalize::Yes => {
                debug!("{:?}: finalizing {:?}", session.verifier(), session.round_id(),);
                match session.finalize_round(rng, accum)? {
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
                            let processed = session.process_message(rng, message);
                            session.add_processed_message(&mut accum, processed)?;
                        }
                    }
                }
            }
            CanFinalize::NotYet => break State::InProgress { session, accum },
            CanFinalize::Never => break State::Finished(session.terminate(accum)?),
        }

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(rng, destination)?;
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

/// Execute sessions for multiple nodes concurrently, given the the inputs
/// for the first round `R` and the signer for each node.
#[allow(clippy::type_complexity)]
pub fn run_sync<R, SP>(
    rng: &mut impl CryptoRngCore,
    inputs: Vec<(SP::Signer, R::Inputs)>,
) -> Result<BTreeMap<SP::Verifier, SessionReport<R::Protocol, SP>>, LocalError>
where
    R: 'static + FirstRound<SP::Verifier>,
    SP: 'static + SessionParameters,
{
    let session_id = SessionId::random(rng);

    let mut messages = Vec::new();
    let mut states = BTreeMap::new();

    for (signer, inputs) in inputs {
        let verifier = signer.verifying_key();
        let session = Session::<R::Protocol, SP>::new::<R>(rng, session_id.clone(), signer, inputs)?;
        let mut accum = session.make_accumulator();

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(rng, destination)?;
            messages.push(Message {
                from: session.verifier().clone(),
                to: destination.clone(),
                message,
            });
            session.add_artifact(&mut accum, artifact)?;
        }

        let (state, new_messages) = propagate(rng, session, accum)?;
        messages.extend(new_messages);
        states.insert(verifier, state);
    }

    loop {
        // Pick a random message and deliver it
        let message_idx = rng.gen_range(0..messages.len());
        let message = messages.swap_remove(message_idx);

        debug!("Delivering message from {:?} to {:?}", message.from, message.to);

        let state = states
            .remove(&message.to)
            .expect("the message destination is one of the sessions");
        let new_state = if let State::InProgress { session, accum } = state {
            let mut accum = accum;
            let preprocessed = session.preprocess_message(&mut accum, &message.from, message.message)?;

            if let Some(verified) = preprocessed {
                let processed = session.process_message(rng, verified);
                session.add_processed_message(&mut accum, processed)?;
            }

            let (new_state, new_messages) = propagate(rng, session, accum)?;
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

    let mut outcomes = BTreeMap::new();
    for (verifier, state) in states {
        let outcome = match state {
            State::InProgress { session, accum } => session.terminate(accum)?,
            State::Finished(report) => report,
        };
        outcomes.insert(verifier, outcome);
    }

    Ok(outcomes)
}
