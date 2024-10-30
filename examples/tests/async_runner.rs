extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use manul::{
    protocol::Protocol,
    session::{
        signature::Keypair, CanFinalize, LocalError, Message, RoundOutcome, Session, SessionId, SessionParameters,
        SessionReport,
    },
    testing::{BinaryFormat, TestSessionParams, TestSigner},
};
use manul_example::simple::{Inputs, Round1, SimpleProtocol};
use rand::Rng;
use rand_core::OsRng;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};
use tracing::{debug, trace};
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};

struct MessageOut<SP: SessionParameters> {
    from: SP::Verifier,
    to: SP::Verifier,
    message: Message<SP::Verifier>,
}

struct MessageIn<SP: SessionParameters> {
    from: SP::Verifier,
    message: Message<SP::Verifier>,
}

/// Runs a session. Simulates what each participating party would run as the protocol progresses.
async fn run_session<P, SP>(
    tx: mpsc::Sender<MessageOut<SP>>,
    rx: mpsc::Receiver<MessageIn<SP>>,
    session: Session<P, SP>,
) -> Result<SessionReport<P, SP>, LocalError>
where
    P: Protocol,
    SP: SessionParameters,
{
    let rng = &mut OsRng;

    let mut rx = rx;

    let mut session = session;
    // Some rounds can finalize early and put off sending messages to the next round. Such messages
    // will be stored here and applied after the messages for this round are sent.
    let mut cached_messages = Vec::new();

    let key = session.verifier();

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
        debug!("{key:?}: *** starting round {:?} ***", session.round_id());

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
            debug!("{key:?}: Sending a message to {destination:?}",);
            tx.send(MessageOut {
                from: key.clone(),
                to: destination.clone(),
                message,
            })
            .await
            .unwrap();

            // This would happen in a host task
            session.add_artifact(&mut accum, artifact)?;
        }

        for preprocessed in cached_messages {
            // In production usage, this would happen in a spawned task and relayed back to the main task.
            debug!("{key:?}: Applying a cached message");
            let processed = session.process_message(rng, preprocessed);

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
                    tracing::warn!("{key:?}: This session cannot ever be finalized. Terminating.");
                    return session.terminate(accum);
                }
            }

            debug!("{key:?}: Waiting for a message");
            let incoming = rx.recv().await.unwrap();

            // Perform quick checks before proceeding with the verification.
            match session.preprocess_message(&mut accum, &incoming.from, incoming.message)? {
                Some(preprocessed) => {
                    // In production usage, this would happen in a separate task.
                    debug!("{key:?}: Applying a message from {:?}", incoming.from);
                    let processed = session.process_message(rng, preprocessed);
                    // In production usage, this would be a host task.
                    session.add_processed_message(&mut accum, processed)?;
                }
                None => {
                    trace!("{key:?} Pre-processing complete. Current state: {accum:?}")
                }
            }
        }

        debug!("{key:?}: Finalizing the round");

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

async fn message_dispatcher<SP>(
    txs: BTreeMap<SP::Verifier, mpsc::Sender<MessageIn<SP>>>,
    rx: mpsc::Receiver<MessageOut<SP>>,
) where
    SP: SessionParameters,
{
    let mut rx = rx;
    let mut messages = Vec::<MessageOut<SP>>::new();
    loop {
        let msg = match rx.recv().await {
            Some(msg) => msg,
            None => break,
        };
        messages.push(msg);

        while let Ok(msg) = rx.try_recv() {
            messages.push(msg)
        }

        while !messages.is_empty() {
            // Pull a random message from the list,
            // to increase the chances that they are delivered out of order.
            let message_idx = rand::thread_rng().gen_range(0..messages.len());
            let outgoing = messages.swap_remove(message_idx);

            txs[&outgoing.to]
                .send(MessageIn {
                    from: outgoing.from,
                    message: outgoing.message,
                })
                .await
                .unwrap();

            // Give up execution so that the tasks could process messages.
            sleep(Duration::from_millis(0)).await;

            if let Ok(msg) = rx.try_recv() {
                messages.push(msg);
            };
        }
    }
}

async fn run_nodes<P, SP>(sessions: Vec<Session<P, SP>>) -> Vec<SessionReport<P, SP>>
where
    P: Protocol + Send,
    SP: SessionParameters,
    P::Result: Send,
    SP::Signer: Send,
{
    let num_parties = sessions.len();

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut<SP>>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn<SP>>(100));
    let (txs, rxs): (Vec<_>, Vec<_>) = channels.unzip();
    let tx_map = sessions
        .iter()
        .map(|session| session.verifier())
        .zip(txs.into_iter())
        .collect();

    let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles = rxs
        .into_iter()
        .zip(sessions.into_iter())
        .map(|(rx, session)| {
            let node_task = run_session(dispatcher_tx.clone(), rx, session);
            tokio::spawn(node_task)
        })
        .collect::<Vec<_>>();

    // Drop the last copy of the dispatcher's incoming channel so that it can finish.
    drop(dispatcher_tx);

    let mut results = Vec::with_capacity(num_parties);
    for handle in handles {
        results.push(handle.await.unwrap().unwrap());
    }

    dispatcher.await.unwrap();

    results
}

#[tokio::test]
async fn async_run() {
    // The kind of Session we need to run the `SimpleProtocol`.
    type SimpleSession = Session<SimpleProtocol, TestSessionParams<BinaryFormat>>;

    // Create 4 parties
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let session_id = SessionId::random::<TestSessionParams<BinaryFormat>>(&mut OsRng);

    // Create 4 `Session`s
    let sessions = signers
        .into_iter()
        .map(|signer| {
            let inputs = Inputs {
                all_ids: all_ids.clone(),
            };
            SimpleSession::new::<Round1<_>>(&mut OsRng, session_id.clone(), signer, inputs).unwrap()
        })
        .collect::<Vec<_>>();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init()
        .unwrap();

    // Run the protocol
    run_nodes(sessions).await;
}
