use core::fmt::Debug;

use manul::{
    testing::{round_override, RoundOverride, RoundWrapper},
    Artifact, DirectMessage, FirstRound, LocalError, Round,
};

use crate::simple::{Inputs, Round1};

#[derive(Debug, Clone, Copy)]
enum Behavior {
    Lawful,
    SerializedGarbage,
    AttributableFailure,
    //UnattributableFailure,
}

struct MaliciousRound1<Id> {
    round: Round1<Id>,
    behavior: Behavior,
}

struct MaliciousInputs<Id> {
    inputs: Inputs<Id>,
    behavior: Behavior,
}

impl<Id: Debug + Clone + Ord + Send + Sync> RoundWrapper<Id> for MaliciousRound1<Id> {
    type InnerRound = Round1<Id>;
    fn inner_round_ref(&self) -> &Self::InnerRound {
        &self.round
    }
    fn inner_round(self) -> Self::InnerRound {
        self.round
    }
}

impl<Id: Debug + Clone + Ord + Send + Sync> FirstRound<Id> for MaliciousRound1<Id> {
    type Inputs = MaliciousInputs<Id>;
    fn new(id: Id, inputs: Self::Inputs) -> Result<Self, LocalError> {
        let round = Round1::new(id, inputs.inputs)?;
        Ok(Self {
            round,
            behavior: inputs.behavior,
        })
    }
}

impl<Id: Debug + Clone + Ord + Send + Sync> RoundOverride<Id> for MaliciousRound1<Id> {
    fn make_direct_message(
        &self,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        if matches!(self.behavior, Behavior::SerializedGarbage) {
            let dm = DirectMessage::new::<<Self::InnerRound as Round<Id>>::Protocol, _>(&[99u8])
                .unwrap();
            Ok((dm, Artifact::empty()))
        /*} else if matches!(self.behavior, Behavior::AttributableFailure) {
        let message = Round1Message {
            my_position: self.round.context.ids_to_positions[&self.round.context.id],
            your_position: self.round.context.ids_to_positions[&self.round.context.id],
        };
        let dm = DirectMessage::new::<<Self::InnerRound as Round<Id>>::Protocol, _>(&message)?;
        Ok((dm, Artifact::empty()))*/
        } else {
            self.inner_round_ref().make_direct_message(destination)
        }
    }
}

round_override!(MaliciousRound1);

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::Keypair;
    use manul::{
        testing::{run_sync, RunOutcome, Signature, Signer, Verifier},
        Error,
    };
    use rand_core::OsRng;
    use tracing_subscriber::EnvFilter;

    use super::{Behavior, MaliciousInputs, MaliciousRound1};
    use crate::simple::Inputs;

    #[test]
    fn serialized_garbage() {
        let signers = (0..3).map(|id| Signer::new(id)).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key().clone())
            .collect::<BTreeSet<_>>();
        let inputs = Inputs { all_ids };

        let run_inputs = signers
            .iter()
            .enumerate()
            .map(|(idx, signer)| {
                let behavior = if idx == 0 {
                    Behavior::SerializedGarbage
                } else {
                    Behavior::Lawful
                };

                let malicious_inputs = MaliciousInputs {
                    inputs: inputs.clone(),
                    behavior,
                };
                (signer.clone(), malicious_inputs)
            })
            .collect::<Vec<_>>();

        let my_subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        let results = tracing::subscriber::with_default(my_subscriber, || {
            run_sync::<MaliciousRound1<Verifier>, Signer, Verifier, Signature>(
                &mut OsRng, run_inputs,
            )
            .unwrap()
        });

        match &results[&signers[0].verifying_key()] {
            RunOutcome::Error(Error::Protocol(evidence)) => {
                assert!(evidence.verify(&signers[0].verifying_key()));
            }
            _ => panic!(
                "Unexpected result: {:?}",
                results[&signers[0].verifying_key()]
            ),
        }

        assert!(matches!(
            results[&signers[1].verifying_key()],
            RunOutcome::Result(3)
        ));
        assert!(matches!(
            results[&signers[2].verifying_key()],
            RunOutcome::Result(3)
        ));
    }

    #[test]
    fn attributable_failure() {
        let signers = (0..3).map(|id| Signer::new(id)).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key().clone())
            .collect::<BTreeSet<_>>();
        let inputs = Inputs { all_ids };

        let run_inputs = signers
            .into_iter()
            .enumerate()
            .map(|(idx, signer)| {
                let behavior = if idx == 0 {
                    Behavior::AttributableFailure
                } else {
                    Behavior::Lawful
                };

                let malicious_inputs = MaliciousInputs {
                    inputs: inputs.clone(),
                    behavior,
                };
                (signer, malicious_inputs)
            })
            .collect::<Vec<_>>();

        let my_subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        let results = tracing::subscriber::with_default(my_subscriber, || {
            run_sync::<MaliciousRound1<Verifier>, Signer, Verifier, Signature>(
                &mut OsRng, run_inputs,
            )
            .unwrap()
        });

        for (_id, result) in results {
            assert!(matches!(result, RunOutcome::Result(_)));
            if let RunOutcome::Result(x) = result {
                assert_eq!(x, 0 + 1 + 2);
            }
        }
    }
}
