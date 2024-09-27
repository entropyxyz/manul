use alloc::collections::BTreeMap;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::signing::{DigestSigner, DigestVerifier, Keypair};
use crate::{Error, FirstRound, Protocol, RoundOutcome, Session};

#[derive(Debug, Clone)]
pub enum RunOutcome<P: Protocol, Verifier, S> {
    Result(P::Result),
    Error(Error<P, Verifier, S>),
}

pub fn run_sync<R, Signer, Verifier, S>(
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
    let mut sessions = inputs
        .into_iter()
        .map(|(signer, inputs)| {
            let verifier = signer.verifying_key();
            (
                verifier,
                Session::<R::Protocol, Signer, Verifier, S>::new::<R>(signer, inputs),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut results = BTreeMap::new();

    loop {
        let mut accums = sessions
            .iter()
            .map(|(id, session)| (id.clone(), session.make_accumulator()))
            .collect::<BTreeMap<_, _>>();

        // Generate messages
        let mut messages = sessions
            .keys()
            .map(|id| (id.clone(), BTreeMap::new()))
            .collect::<BTreeMap<_, _>>();
        for (id, session) in sessions.iter() {
            let destinations = session.message_destinations();
            for destination in destinations.iter() {
                let (message, artifact) = session.make_message(destination).unwrap();
                messages
                    .get_mut(&destination)
                    .unwrap()
                    .insert(id.clone(), message);
                accums.get_mut(id).unwrap().add_artifact(artifact);
            }
        }

        // Send out messages
        for (id, session) in sessions.iter() {
            for (from, message) in messages[id].iter() {
                let verified = session.verify_message(from, message.clone()).unwrap();
                let processed = session.process_message(verified).unwrap();
                accums.get_mut(id).unwrap().add_processed_message(processed);
            }
        }

        // Finalize
        let ids = sessions.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let accum = accums.remove(&id).unwrap();
            let session = sessions.remove(&id).unwrap();
            let result = session.finalize_round(accum);

            match result {
                Ok(result) => match result {
                    RoundOutcome::Result(result) => {
                        results.insert(id.clone(), RunOutcome::Result(result));
                    }
                    RoundOutcome::AnotherRound { session } => {
                        sessions.insert(id.clone(), session);
                    }
                },
                Err(result) => {
                    results.insert(id.clone(), RunOutcome::Error(result));
                }
            }
        }

        if sessions.is_empty() {
            return Ok(results);
        }
    }
}
