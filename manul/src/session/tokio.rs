//! High-level API for executing sessions in `tokio` tasks.

use alloc::{format, sync::Arc, vec::Vec};

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use super::{
    message::Message,
    session::{CanFinalize, ProcessedArtifact, ProcessedMessage, RoundOutcome, Session, SessionId, SessionParameters},
    transcript::SessionReport,
    LocalError,
};
use crate::protocol::Protocol;

/// The outgoing message from a local session.
#[derive(Debug)]
pub struct MessageOut<SP: SessionParameters> {
    /// The session ID that created the message.
    ///
    /// Useful when there are several sessions running on a node, pushing messages into the same channel.
    pub session_id: SessionId,
    /// The verifying key of the party that created the message.
    ///
    /// Useful when there are several sessions running on a node, pushing messages into the same channel.
    pub from: SP::Verifier,
    /// The verifying key of the party the message is intended for.
    pub to: SP::Verifier,
    /// The message to be sent.
    ///
    /// Note that the caller is responsible for encrypting the message and attaching authentication info.
    pub message: Message<SP::Verifier>,
}

/// The incoming message from a remote session.
#[derive(Debug)]
pub struct MessageIn<SP: SessionParameters> {
    /// The verifying key of the party the message originated from.
    ///
    /// It is assumed that the message's authentication info has been checked at this point.
    pub from: SP::Verifier,
    /// The incoming message.
    pub message: Message<SP::Verifier>,
}

/// Executes the session waiting for the messages from the `rx` channel
/// and pushing outgoing messages into the `tx` channel.
pub async fn run_session<P, SP>(
    rng: &mut impl CryptoRngCore,
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<MessageIn<SP>>,
    cancellation: CancellationToken,
    session: Session<P, SP>,
) -> Result<SessionReport<P, SP>, LocalError>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    let mut session = session;
    // Some rounds can finalize early and put off sending messages to the next round. Such messages
    // will be stored here and applied after the messages for this round are sent.
    let mut cached_messages = Vec::new();

    let my_id = format!("{:?}", session.verifier());

    // Each iteration of the loop progresses the session as follows:
    //  - Send out messages as dictated by the session "destinations".
    //  - Apply any cached messages.
    //  - Enter a nested loop:
    //      - Try to finalize the session; if we're done, exit the inner loop.
    //      - Wait until we get an incoming message.
    //      - Process the message we received and continue the loop.
    //  - When all messages have been sent and received as specified by the protocol, finalize the
    //    round.
    //  - If the protocol outcome is a new round, go to the top of the loop and start over with a
    //    new session.
    loop {
        debug!("{my_id}: *** starting round {:?} ***", session.round_id());

        // This is kept in the main task since it's mutable,
        // and we don't want to bother with synchronization.
        let mut accum = session.make_accumulator();

        // Note: generating/sending messages and verifying newly received messages
        // can be done in parallel, with the results being assembled into `accum`
        // sequentially in the host task.

        let destinations = session.message_destinations();
        for destination in destinations.iter() {
            // In production usage, this will happen in a spawned task
            // (since it can take some time to create a message),
            // and the artifact will be sent back to the host task
            // to be added to the accumulator.
            let (message, artifact) = session.make_message(rng, destination)?;
            debug!("{my_id}: Sending a message to {destination:?}",);
            tx.send(MessageOut {
                session_id: session.session_id().clone(),
                from: session.verifier().clone(),
                to: destination.clone(),
                message,
            })
            .await
            .map_err(|err| {
                LocalError::new(format!(
                    "Failed to send a message from {:?} to {:?}: {err}",
                    session.verifier(),
                    destination
                ))
            })?;

            // This would happen in a host task
            session.add_artifact(&mut accum, artifact)?;
        }

        for preprocessed in cached_messages {
            // In production usage, this would happen in a spawned task and relayed back to the main task.
            debug!("{my_id}: Applying a cached message");
            let processed = session.process_message(preprocessed);

            // This would happen in a host task.
            session.add_processed_message(&mut accum, processed)?;
        }

        loop {
            match session.can_finalize(&accum) {
                CanFinalize::Yes => break,
                CanFinalize::NotYet => {}
                // Due to already registered invalid messages from nodes,
                // even if the remaining nodes send correct messages, it won't be enough.
                // Terminating.
                CanFinalize::Never => {
                    tracing::warn!("{my_id}: This session cannot ever be finalized. Terminating.");
                    return session.terminate_due_to_errors(accum);
                }
            }

            debug!("{my_id}: Waiting for a message");
            let message_in = tokio::select! {
                message_in = rx.recv() => {
                    message_in.ok_or_else(|| LocalError::new("The incoming message channel was closed unexpectedly"))?
                },
                _ = cancellation.cancelled() => {
                    return session.terminate_due_to_errors(accum);
                }
            };

            // Perform quick checks before proceeding with the verification.
            match session
                .preprocess_message(&mut accum, &message_in.from, message_in.message)?
                .ok()
            {
                Some(preprocessed) => {
                    // In production usage, this would happen in a separate task.
                    debug!("{my_id}: Applying a message from {:?}", message_in.from);
                    let processed = session.process_message(preprocessed);
                    // In production usage, this would be a host task.
                    session.add_processed_message(&mut accum, processed)?;
                }
                None => {
                    trace!("{my_id} Pre-processing complete. Current state: {accum:?}")
                }
            }
        }

        debug!("{my_id}: Finalizing the round");

        match session.finalize_round(rng, accum)? {
            RoundOutcome::Finished(report) => break Ok(report),
            RoundOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                session = new_session;
                cached_messages = new_cached_messages;
            }
        }
    }
}

/// Executes the session waiting for the messages from the `rx` channel
/// and pushing outgoing messages into the `tx` channel.
/// The messages are processed in parallel.
///
/// This function should be used if message creation and verification takes a significant amount of time,
/// to offset the parallelizing overhead.
/// Use [`tokio::run_async`](`crate::dev::tokio::run_async`) to benchmark your specific protocol.
pub async fn par_run_session<P, SP>(
    rng: &mut (impl 'static + Clone + CryptoRngCore + Send),
    tx: &mpsc::Sender<MessageOut<SP>>,
    rx: &mut mpsc::Receiver<MessageIn<SP>>,
    cancellation: CancellationToken,
    session: Session<P, SP>,
) -> Result<SessionReport<P, SP>, LocalError>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
    <SP as SessionParameters>::Signer: Send + Sync,
    <P as Protocol<SP::Verifier>>::ProtocolError: Send + Sync,
{
    let mut session = Arc::new(session);
    // Some rounds can finalize early and put off sending messages to the next round. Such messages
    // will be stored here and applied after the messages for this round are sent.
    let mut cached_messages = Vec::new();

    let my_id = format!("{:?}", session.verifier());

    // Each iteration of the loop progresses the session as follows:
    //  - Send out messages as dictated by the session "destinations".
    //  - Apply any cached messages.
    //  - Enter a nested loop:
    //      - Try to finalize the session; if we're done, exit the inner loop.
    //      - Wait until we get an incoming message.
    //      - Process the message we received and continue the loop.
    //  - When all messages have been sent and received as specified by the protocol, finalize the
    //    round.
    //  - If the protocol outcome is a new round, go to the top of the loop and start over with a
    //    new session.
    loop {
        debug!("{my_id}: *** starting round {:?} ***", session.round_id());

        let (processed_tx, mut processed_rx) = mpsc::channel::<ProcessedMessage<P, SP>>(100);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<(MessageOut<SP>, ProcessedArtifact<SP>)>(100);

        // This is kept in the main task since it's mutable,
        // and we don't want to bother with synchronization.
        let mut accum = session.make_accumulator();

        // Note: generating/sending messages and verifying newly received messages
        // can be done in parallel, with the results being assembled into `accum`
        // sequentially in the host task.

        let destinations = session.message_destinations();
        let mut message_creation_tasks = Vec::new();
        for destination in destinations {
            let session = session.clone();
            let my_id = my_id.clone();
            let outgoing_tx = outgoing_tx.clone();
            let destination = destination.clone();
            let mut task_rng = ChaCha20Rng::from_rng(rng.clone()).map_err(|_| LocalError::new("Can't fork the RNG"))?;
            let message_creation = tokio::task::spawn_blocking(move || {
                let (message, artifact) = session.make_message(&mut task_rng, &destination)?;
                debug!("{my_id}: Sending a message to {destination:?}",);
                let message_out = MessageOut {
                    session_id: session.session_id().clone(),
                    from: session.verifier().clone(),
                    to: destination.clone(),
                    message,
                };
                outgoing_tx.blocking_send((message_out, artifact)).map_err(|err| {
                    LocalError::new(format!(
                        "Failed to send a created message from {:?} to {:?}: {err}",
                        session.verifier(),
                        destination
                    ))
                })
            });
            message_creation_tasks.push(message_creation);
        }

        let mut message_processing_tasks = Vec::new();
        for preprocessed in cached_messages {
            let session = session.clone();
            let processed_tx = processed_tx.clone();
            let my_id = my_id.clone();
            let message_processing: JoinHandle<Result<(), LocalError>> = tokio::task::spawn_blocking(move || {
                debug!("{my_id}: Applying a cached message");
                let processed = session.process_message(preprocessed);
                processed_tx
                    .blocking_send(processed)
                    .map_err(|_err| LocalError::new("Failed to send a processed message"))
            });
            message_processing_tasks.push(message_processing);
        }

        let can_finalize = loop {
            match session.can_finalize(&accum) {
                CanFinalize::Yes => break true,
                CanFinalize::NotYet => {}
                // Due to already registered invalid messages from nodes,
                // even if the remaining nodes send correct messages, it won't be enough.
                // Terminating.
                CanFinalize::Never => break false,
            }

            tokio::select! {
                processed = processed_rx.recv() => {
                    let processed = processed.ok_or_else(|| LocalError::new("The processed message channel was closed unexpectedly"))?;
                    session.add_processed_message(&mut accum, processed)?;
                }
                outgoing = outgoing_rx.recv() => {
                    let (message_out, artifact) = outgoing.ok_or_else(|| LocalError::new("The outgoing message channel was closed unexpectedly"))?;

                    let from = message_out.from.clone();
                    let to = message_out.to.clone();
                    tx.send(message_out)
                    .await
                    .map_err(|err| {
                        LocalError::new(format!(
                            "Failed to send a message from {from:?} to {to:?}: {err}",
                        ))
                    })?;

                    session.add_artifact(&mut accum, artifact)?;
                }
                message_in = rx.recv() => {
                    let message_in = message_in.ok_or_else(|| LocalError::new("The incoming message channel was closed unexpectedly"))?;
                    match session
                        .preprocess_message(&mut accum, &message_in.from, message_in.message)?
                        .ok()
                    {
                        Some(preprocessed) => {
                            let session = session.clone();
                            let processed_tx = processed_tx.clone();
                            let my_id = my_id.clone();
                            let message_processing = tokio::task::spawn_blocking(move || {
                                debug!("{my_id}: Applying a message from {:?}", message_in.from);
                                let processed = session.process_message(preprocessed);
                                processed_tx.blocking_send(processed).map_err(|_err| {
                                    LocalError::new("Failed to send a processed message")
                                })
                            });
                            message_processing_tasks.push(message_processing);
                        }
                        None => {
                            trace!("{my_id} Pre-processing complete. Current state: {accum:?}")
                        }
                    }
                },
                _ = cancellation.cancelled() => {
                    break false;
                }
            }
        };

        debug!("{my_id}: Finalizing the round {}", session.round_id());

        // Join all the handles created in this iteration.

        for message_creation_task in message_creation_tasks {
            message_creation_task
                .await
                .map_err(|_err| LocalError::new("Failed to join a message creation task"))??;
        }

        for message_processing_task in message_processing_tasks {
            message_processing_task
                .await
                .map_err(|_err| LocalError::new("Failed to join a message processing task"))??;
        }

        // Drop our copies of `Sender`s to let the channels close.
        drop(outgoing_tx);
        drop(processed_tx);

        // Send all the remaining messages
        while let Some((message_out, artifact)) = outgoing_rx.recv().await {
            let from = message_out.from.clone();
            let to = message_out.to.clone();
            tx.send(message_out)
                .await
                .map_err(|err| LocalError::new(format!("Failed to send a message from {from:?} to {to:?}: {err}",)))?;

            session.add_artifact(&mut accum, artifact)?;
        }

        debug!("{my_id}: Sent out all remaining messages");

        let session_inner = Arc::into_inner(session)
            .ok_or_else(|| LocalError::new("There are still references to the session left"))?;

        if !can_finalize {
            return session_inner.terminate_due_to_errors(accum);
        }

        match session_inner.finalize_round(rng, accum)? {
            RoundOutcome::Finished(report) => return Ok(report),
            RoundOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                session = Arc::new(new_session);
                cached_messages = new_cached_messages;
            }
        }
    }
}
