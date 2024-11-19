use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

use rand::Rng;
use rand_core::CryptoRngCore;
use signature::Keypair;
use tracing::debug;
use tracing_subscriber::EnvFilter;

use crate::{
    protocol::{EntryPoint, Protocol},
    session::{
        CanFinalize, LocalError, Message, RoundAccumulator, RoundOutcome, Session, SessionId, SessionOutcome,
        SessionParameters, SessionReport,
    },
};

enum State<P: Protocol, SP: SessionParameters> {
    InProgress {
        session: Session<P, SP>,
        accum: RoundAccumulator<P, SP>,
    },
    Finished(SessionReport<P, SP>),
}

struct RoundMessage<SP: SessionParameters> {
    from: SP::Verifier,
    to: SP::Verifier,
    message: Message<SP::Verifier>,
}

#[allow(clippy::type_complexity)]
fn propagate<P, SP>(
    rng: &mut impl CryptoRngCore,
    session: Session<P, SP>,
    accum: RoundAccumulator<P, SP>,
) -> Result<(State<P, SP>, Vec<RoundMessage<SP>>), LocalError>
where
    P: Protocol,
    SP: SessionParameters,
{
    let mut messages = Vec::new();

    let mut session = session;
    let mut accum = accum;

    let state = loop {
        match session.can_finalize(&accum) {
            CanFinalize::Yes => {
                debug!("{:?}: finalizing {}", session.verifier(), session.round_id());
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
            CanFinalize::Never => break State::Finished(session.terminate_due_to_errors(accum)?),
        }

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(rng, destination)?;
            messages.push(RoundMessage {
                from: session.verifier().clone(),
                to: destination.clone(),
                message,
            });
            session.add_artifact(&mut accum, artifact)?;
        }
    };

    Ok((state, messages))
}

/// Execute sessions for multiple nodes concurrently,
/// given a vector of the signer and the entry point as a tuple for each node.
#[allow(clippy::type_complexity)]
pub fn run_sync<EP, SP>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, EP)>,
) -> Result<ExecutionResult<EP::Protocol, SP>, LocalError>
where
    EP: EntryPoint<SP::Verifier>,
    SP: SessionParameters,
{
    let session_id = SessionId::random::<SP>(rng);

    let mut messages = Vec::new();
    let mut states = BTreeMap::new();

    for (signer, entry_point) in entry_points {
        let verifier = signer.verifying_key();
        let session = Session::<_, SP>::new(rng, session_id.clone(), signer, entry_point)?;
        let mut accum = session.make_accumulator();

        let destinations = session.message_destinations();
        for destination in destinations {
            let (message, artifact) = session.make_message(rng, destination)?;
            messages.push(RoundMessage {
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

            if let Some(verified) = preprocessed.ok() {
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

    let mut reports = BTreeMap::new();
    for (verifier, state) in states {
        let report = match state {
            State::InProgress { session, accum } => session.terminate(accum)?,
            State::Finished(report) => report,
        };
        reports.insert(verifier, report);
    }

    Ok(ExecutionResult { reports })
}

/// Same as [`run_sync()`], but enables a [`tracing`] subscriber that prints the tracing events to stdout,
/// taking options from the environment variable `RUST_LOG` (see [`mod@tracing_subscriber::fmt`] for details).
#[allow(clippy::type_complexity)]
pub fn run_sync_with_tracing<EP, SP>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, EP)>,
) -> Result<ExecutionResult<EP::Protocol, SP>, LocalError>
where
    EP: EntryPoint<SP::Verifier>,
    SP: SessionParameters,
{
    // A subscriber that prints events to stdout
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::with_default(subscriber, || run_sync::<EP, SP>(rng, entry_points))
}

/// The result of a protocol execution on a set of nodes.
#[derive(Debug)]
pub struct ExecutionResult<P: Protocol, SP: SessionParameters> {
    pub reports: BTreeMap<SP::Verifier, SessionReport<P, SP>>,
}
impl<P, SP> ExecutionResult<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    pub fn results(self) -> Result<BTreeMap<SP::Verifier, P::Result>, String> {
        let mut report_strings = Vec::new();
        let mut results = BTreeMap::new();

        for (id, report) in self.reports.into_iter() {
            match report.outcome {
                SessionOutcome::Result(result) => {
                    results.insert(id, result);
                }
                _ => {
                    report_strings.push(format!("Id: {:?}\n{}", id, report.brief()));
                }
            }
        }

        if report_strings.is_empty() {
            Ok(results)
        } else {
            Err(report_strings.join("\n"))
        }
    }
}
