//! `tokio`-specific development utilities.

use alloc::{collections::BTreeMap, format, vec::Vec};

use rand::Rng;
use rand_core::CryptoRngCore;
use signature::Keypair;
use tokio::sync::mpsc;

use super::run_sync::ExecutionResult;
use crate::{
    protocol::{EntryPoint, Protocol},
    session::{
        tokio::{par_run_session, run_session, MessageIn, MessageOut},
        LocalError, Session, SessionId, SessionParameters,
    },
};

async fn message_dispatcher<SP>(
    rng: impl CryptoRngCore,
    txs: BTreeMap<SP::Verifier, mpsc::Sender<MessageIn<SP>>>,
    rx: mpsc::Receiver<MessageOut<SP>>,
) -> Result<(), LocalError>
where
    SP: SessionParameters,
{
    let mut rng = rng;

    let mut rx = rx;
    let mut messages = Vec::<MessageOut<SP>>::new();
    loop {
        let msg = match rx.recv().await {
            Some(msg) => msg,
            None => return Ok(()),
        };
        messages.push(msg);

        while let Ok(msg) = rx.try_recv() {
            messages.push(msg)
        }

        while !messages.is_empty() {
            // Pull a random message from the list,
            // to increase the chances that they are delivered out of order.
            let message_idx = rng.gen_range(0..messages.len());
            let outgoing = messages.swap_remove(message_idx);

            txs.get(&outgoing.to)
                .ok_or_else(|| {
                    LocalError::new(format!(
                        "Destination ({:?}) is missing in the map of channels",
                        outgoing.to
                    ))
                })?
                .send(MessageIn {
                    from: outgoing.from,
                    message: outgoing.message,
                })
                .await
                .map_err(|err| LocalError::new(format!("Could not sent an outgoing message: {err}")))?;

            // Give up execution so that the tasks could process messages.
            tokio::time::sleep(tokio::time::Duration::from_millis(0)).await;

            if let Ok(msg) = rx.try_recv() {
                messages.push(msg);
            };
        }
    }
}

/// Execute sessions for multiple nodes concurrently within a `tokio` runtime,
/// given a vector of the signer and the entry point as a tuple for each node.
///
/// If `offload_processing` is `true`, message creation and verification will be launched in separate tasks.
pub async fn run_async<EP, SP>(
    rng: &mut (impl 'static + CryptoRngCore + Clone + Send),
    entry_points: Vec<(SP::Signer, EP)>,
    offload_processing: bool,
) -> Result<ExecutionResult<EP::Protocol, SP>, LocalError>
where
    EP: EntryPoint<SP::Verifier>,
    SP: SessionParameters,
    SP::Signer: Send + Sync,
    <EP::Protocol as Protocol<SP::Verifier>>::ProtocolError: Send + Sync,
    <EP::Protocol as Protocol<SP::Verifier>>::Result: Send,
{
    let num_parties = entry_points.len();
    let session_id = SessionId::random::<SP>(rng);

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut<SP>>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn<SP>>(100));
    let (txs, rxs): (Vec<_>, Vec<_>) = channels.unzip();
    let tx_map = entry_points
        .iter()
        .map(|(signer, _entry_point)| signer.verifying_key())
        .zip(txs.into_iter())
        .collect();

    let dispatcher_task = message_dispatcher(rng.clone(), tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles = rxs
        .into_iter()
        .zip(entry_points.into_iter())
        .map(|(mut rx, (signer, entry_point))| {
            let tx = dispatcher_tx.clone();
            let mut rng = rng.clone();

            let session = Session::<_, SP>::new(&mut rng, session_id.clone(), signer, entry_point)?;
            let id = session.verifier().clone();

            let node_task = async move {
                if offload_processing {
                    par_run_session(&mut rng, &tx, &mut rx, session).await
                } else {
                    run_session(&mut rng, &tx, &mut rx, session).await
                }
            };
            Ok((id, tokio::spawn(node_task)))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    // Drop the last copy of the dispatcher's incoming channel so that it can finish.
    drop(dispatcher_tx);

    let mut reports = BTreeMap::new();
    for (id, handle) in handles {
        reports.insert(
            id.clone(),
            handle
                .await
                .map_err(|err| LocalError::new(format!("Could not join the task of {id:?}: {err}")))??,
        );
    }

    dispatcher
        .await
        .map_err(|err| LocalError::new(format!("Could not join the message dispatcher task: {err}")))??;

    Ok(ExecutionResult { reports })
}
