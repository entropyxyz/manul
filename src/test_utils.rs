use alloc::collections::BTreeMap;
use core::fmt::Debug;

use crate::{Error, FinalizeOutcome, FirstRound, Protocol, Round, Session};

pub fn run_sync<I, R, P>(
    inputs: BTreeMap<I, R::Inputs>,
) -> BTreeMap<I, Result<P::Result, Error<I, P>>>
where
    I: Debug + Clone + Eq + Ord,
    R: FirstRound<I> + Round<I, Protocol = P> + 'static,
    P: Protocol,
{
    let mut sessions = inputs
        .into_iter()
        .map(|(id, inputs)| (id.clone(), Session::<I, P>::new::<R>(id, inputs)))
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
                    FinalizeOutcome::Result(result) => {
                        results.insert(id.clone(), Ok(result));
                    }
                    FinalizeOutcome::AnotherRound { session } => {
                        sessions.insert(id.clone(), session);
                    }
                },
                Err(result) => {
                    results.insert(id.clone(), Err(result));
                }
            }
        }

        if sessions.is_empty() {
            return results;
        }
    }
}
