use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

use rand::Rng;
use rand_core::CryptoRngCore;
use signature::Keypair;
use tracing::{debug, info, trace, warn};

use crate::{
    protocol::{EntryPoint, Protocol},
    session::{
        CanFinalize, LocalError, Message, RoundAccumulator, RoundOutcome, Session, SessionId, SessionOutcome,
        SessionParameters, SessionReport,
    },
};

enum State<P: Protocol<SP::Verifier>, SP: SessionParameters> {
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

enum Messages<SP: SessionParameters> {
    /// For each node, if message A was sent before message B, it will be popped before message B as well.
    Ordered(BTreeMap<SP::Verifier, Vec<RoundMessage<SP>>>),
    /// The messages will be popped completely at random.
    Unordered(Vec<RoundMessage<SP>>),
}

impl<SP> Messages<SP>
where
    SP: SessionParameters,
{
    fn new(ordered: bool) -> Self {
        if ordered {
            Self::Ordered(BTreeMap::new())
        } else {
            Self::Unordered(Vec::new())
        }
    }

    /// Adds a message to the queue.
    fn push(&mut self, message: RoundMessage<SP>) {
        match self {
            Self::Ordered(m) => m.entry(message.from.clone()).or_insert(Vec::new()).push(message),
            Self::Unordered(v) => v.push(message),
        }
    }

    /// Adds a a vector of messages to the queue.
    fn extend(&mut self, messages: Vec<RoundMessage<SP>>) {
        for message in messages {
            self.push(message)
        }
    }

    /// Removes a random message from the queue and returns it.
    fn pop(&mut self, rng: &mut impl CryptoRngCore) -> RoundMessage<SP> {
        match self {
            Self::Ordered(m) => {
                let senders_num = m.len();
                let sender_idx = rng.gen_range(0..senders_num);
                let sender = m.keys().nth(sender_idx).expect("the entry exists").clone();

                let (message, is_empty) = {
                    let messages = m.get_mut(&sender).expect("the entry exists");
                    let message = messages.remove(0);
                    (message, messages.is_empty())
                };
                if is_empty {
                    m.remove(&sender);
                }
                message
            }
            Self::Unordered(v) => {
                let message_idx = rng.gen_range(0..v.len());
                v.swap_remove(message_idx)
            }
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Ordered(m) => m.is_empty(),
            Self::Unordered(v) => v.is_empty(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Ordered(m) => m.len(),
            Self::Unordered(v) => v.len(),
        }
    }
}

#[allow(clippy::type_complexity)]
fn propagate<P, SP>(
    rng: &mut impl CryptoRngCore,
    session: Session<P, SP>,
    accum: RoundAccumulator<P, SP>,
) -> Result<(State<P, SP>, Vec<RoundMessage<SP>>), LocalError>
where
    P: Protocol<SP::Verifier>,
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
                            let processed = session.process_message(message);
                            session.add_processed_message(&mut accum, processed)?;
                        }
                    }
                }
            }
            CanFinalize::NotYet => {
                trace!(
                    "[{:?}] Still in progress. Cannot finalize round {}",
                    session.verifier(),
                    session.round_id()
                );
                break State::InProgress { session, accum };
            }
            CanFinalize::Never => {
                trace!(
                    "[{:?}] Can't ever finalize. Terminating session due to errors",
                    session.verifier()
                );
                break State::Finished(session.terminate_due_to_errors(accum)?);
            }
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

/// Execute sessions for multiple nodes in a single thread,
/// given a vector of the signer and the entry point as a tuple for each node.
pub fn run_sync<EP, SP>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, EP)>,
) -> Result<ExecutionResult<EP::Protocol, SP>, LocalError>
where
    EP: EntryPoint<SP::Verifier>,
    SP: SessionParameters,
{
    let session_id = SessionId::random::<SP>(rng);

    let mut messages = Messages::new(true);
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
    let messages_len = messages.len();
    loop {
        // Pick a random message and deliver it
        let message = messages.pop(rng);

        debug!(
            "Delivering message from {:?} to {:?} ({}/{})",
            message.from,
            message.to,
            messages_len - messages.len(),
            messages_len
        );
        let state = states.remove(&message.to);
        if state.is_none() {
            warn!(
                "Expected the message destination {:?} to be one of the sessions",
                message.to
            );
            panic!("Expected the message destination to be one of the sessions",);
        }
        let state = state.unwrap();
        // .expect("Expected the message destination to be one of the sessions");
        let new_state = if let State::InProgress { session, accum } = state {
            let mut accum = accum;
            let preprocessed = session.preprocess_message(&mut accum, &message.from, message.message)?;

            if let Some(verified) = preprocessed.ok() {
                let processed = session.process_message(verified);
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
            trace!("All messages delivered, exiting loop");
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

/// The result of a protocol execution on a set of nodes.
#[derive(Debug)]
pub struct ExecutionResult<P: Protocol<SP::Verifier>, SP: SessionParameters> {
    /// Session reports from each node.
    pub reports: BTreeMap<SP::Verifier, SessionReport<P, SP>>,
}

impl<P, SP> ExecutionResult<P, SP>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    /// Attempts to extract the results from each session report.
    ///
    /// If any session did finish with a result, returns a string
    /// with a formatted description of outcomes for each session.
    pub fn results(self) -> Result<BTreeMap<SP::Verifier, P::Result>, String> {
        let mut report_strings = Vec::new();
        let mut results = BTreeMap::new();

        for (id, report) in self.reports.into_iter() {
            match report.outcome {
                SessionOutcome::Result(result) => {
                    results.insert(id, result);
                }
                _ => {
                    report_strings.push(format!("* Id: {:?}\n{}", id, report.brief()));
                }
            }
        }

        if report_strings.is_empty() {
            Ok(results)
        } else {
            Err(report_strings.join("\n\n"))
        }
    }
}
