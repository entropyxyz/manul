extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use manul::{
    protocol::Protocol,
    session::{
        signature::Keypair, CanFinalize, LocalError, MessageBundle, RoundOutcome, Session, SessionId,
        SessionParameters, SessionReport,
    },
    testing::{Signer, TestingSessionParams, Verifier},
};
use manul_example::{
    simple::{Inputs, Round1},
    Bincode,
};
use rand::Rng;
use rand_core::OsRng;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};
use tracing::debug;
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};

struct MessageOut<SP: SessionParameters> {
    from: SP::Verifier,
    to: SP::Verifier,
    message: MessageBundle,
}

struct MessageIn<SP: SessionParameters> {
    from: SP::Verifier,
    message: MessageBundle,
}

async fn run_session<P, SP>(
    tx: mpsc::Sender<MessageOut<SP>>,
    rx: mpsc::Receiver<MessageIn<SP>>,
    session: Session<P, SP>,
) -> Result<SessionReport<P, SP>, LocalError>
where
    P: 'static + Protocol,
    SP: 'static + SessionParameters,
{
    let rng = &mut OsRng;

    let mut rx = rx;

    let mut session = session;
    let mut cached_messages = Vec::new();

    let key = session.verifier();

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
            debug!("{key:?}: sending a message to {destination:?}",);
            tx.send(MessageOut {
                from: key.clone(),
                to: destination.clone(),
                message,
            })
            .await
            .unwrap();

            // This will happen in a host task
            session.add_artifact(&mut accum, artifact)?;
        }

        for preprocessed in cached_messages {
            // In production usage, this will happen in a spawned task.
            debug!("{key:?}: applying a cached message");
            let processed = session.process_message(rng, preprocessed);

            // This will happen in a host task.
            session.add_processed_message(&mut accum, processed)?;
        }

        loop {
            match session.can_finalize(&accum) {
                CanFinalize::Yes => break,
                CanFinalize::NotYet => {}
                // Due to already registered invalid messages from nodes,
                // even if the remaining nodes send correct messages, it won't be enough.
                // Terminating.
                CanFinalize::Never => return session.terminate(accum),
            }

            debug!("{key:?}: waiting for a message");
            let incoming = rx.recv().await.unwrap();

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session.preprocess_message(&mut accum, &incoming.from, incoming.message)?;

            if let Some(preprocessed) = preprocessed {
                // In production usage, this will happen in a spawned task.
                debug!("{key:?}: applying a message from {:?}", incoming.from);
                let processed = session.process_message(rng, preprocessed);

                // This will happen in a host task.
                session.add_processed_message(&mut accum, processed)?;
            }
        }

        debug!("{key:?}: finalizing the round");

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
    P: 'static + Protocol + Send,
    SP: 'static + SessionParameters,
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

    // Drop the last copy of the dispatcher's incoming channel so that it could finish.
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
    let signers = (0..3).map(Signer::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let session_id = SessionId::random(&mut OsRng);
    let sessions = signers
        .into_iter()
        .map(|signer| {
            let inputs = Inputs {
                all_ids: all_ids.clone(),
            };
            Session::<_, TestingSessionParams<Bincode>>::new::<Round1<Verifier>>(
                &mut OsRng,
                session_id.clone(),
                signer,
                inputs,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init()
        .unwrap();

    run_nodes(sessions).await;
}
