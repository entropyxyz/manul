extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use manul::{
    dev::{BinaryFormat, TestSessionParams, TestSigner},
    protocol::Protocol,
    session::{
        tokio::{run_session, MessageIn, MessageOut},
        Session, SessionId, SessionParameters, SessionReport,
    },
    signature::Keypair,
};
use manul_example::simple::{SimpleProtocol, SimpleProtocolEntryPoint};
use rand::Rng;
use rand_core::OsRng;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};

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
    P: Protocol<SP::Verifier> + Send,
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
        .map(|(mut rx, session)| {
            let tx = dispatcher_tx.clone();
            let node_task = async move { run_session(&mut OsRng, &tx, &mut rx, session).await };
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
            let entry_point = SimpleProtocolEntryPoint::new(all_ids.clone());
            SimpleSession::new(&mut OsRng, session_id.clone(), signer, entry_point).unwrap()
        })
        .collect::<Vec<_>>();

    // Run the protocol
    run_nodes(sessions).await;
}
