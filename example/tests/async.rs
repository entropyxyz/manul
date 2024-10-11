extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use manul::{
    testing::{Signature, Signer, Verifier},
    CanFinalize, Keypair, LocalError, MessageBundle, Protocol, Round, RoundOutcome, Session,
    SessionReport,
};
use manul_example::simple::{Inputs, Round1};
use rand::Rng;
use rand_core::OsRng;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};
use tracing::debug;
use tracing_subscriber::{util::SubscriberInitExt, EnvFilter};

type MessageOut = (Verifier, Verifier, MessageBundle<Signature>);
type MessageIn = (Verifier, MessageBundle<Signature>);

async fn run_session<P>(
    tx: mpsc::Sender<MessageOut>,
    rx: mpsc::Receiver<MessageIn>,
    session: Session<P, Signer, Verifier, Signature>,
) -> Result<SessionReport<P, Verifier, Signature>, LocalError>
where
    P: Protocol + 'static,
    P::Digest: digest::Digest,
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
            tx.send((key, *destination, message)).await.unwrap();

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
                CanFinalize::Never => return Ok(session.terminate(accum)?),
            }

            debug!("{key:?}: waiting for a message");
            let (from, message) = rx.recv().await.unwrap();

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session.preprocess_message(&mut accum, &from, message)?;

            if let Some(preprocessed) = preprocessed {
                // In production usage, this will happen in a spawned task.
                debug!("{key:?}: applying a message from {from:?}");
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

async fn message_dispatcher(
    txs: BTreeMap<Verifier, mpsc::Sender<MessageIn>>,
    rx: mpsc::Receiver<MessageOut>,
) {
    let mut rx = rx;
    let mut messages = Vec::<MessageOut>::new();
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
            let (id_from, id_to, message) = messages.swap_remove(message_idx);

            txs[&id_to].send((id_from, message)).await.unwrap();

            // Give up execution so that the tasks could process messages.
            sleep(Duration::from_millis(0)).await;

            if let Ok(msg) = rx.try_recv() {
                messages.push(msg);
            };
        }
    }
}

async fn run_nodes<P>(
    sessions: Vec<Session<P, Signer, Verifier, Signature>>,
) -> Vec<SessionReport<P, Verifier, Signature>>
where
    P: Protocol + Send + 'static,
    P::Digest: digest::Digest,
    P::Result: Send,
{
    let num_parties = sessions.len();

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn>(100));
    let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
        channels.unzip();
    let tx_map = sessions
        .iter()
        .map(|session| session.verifier())
        .zip(txs.into_iter())
        .collect();

    let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles: Vec<
        tokio::task::JoinHandle<Result<SessionReport<P, Verifier, Signature>, LocalError>>,
    > = rxs
        .into_iter()
        .zip(sessions.into_iter())
        .map(|(rx, session)| {
            let node_task = run_session(dispatcher_tx.clone(), rx, session);
            tokio::spawn(node_task)
        })
        .collect();

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
    let signers = (0..3).map(|id| Signer::new(id)).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key().clone())
        .collect::<BTreeSet<_>>();
    let sessions = signers
        .into_iter()
        .map(|signer| {
            let inputs = Inputs {
                all_ids: all_ids.clone(),
            };
            Session::<
                    <Round1<Verifier> as Round<Verifier>>::Protocol,
                    Signer,
                    Verifier,
                    Signature,
                >::new::<Round1<Verifier>>(&mut OsRng, signer, inputs)
                .unwrap()
        })
        .collect::<Vec<_>>();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init()
        .unwrap();
    //tracing::subscriber::set_global_default(subscriber).unwrap();
    //.set_default();
    run_nodes(sessions).await;
}
