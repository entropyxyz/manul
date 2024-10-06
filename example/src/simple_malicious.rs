use alloc::collections::BTreeSet;
use core::fmt::Debug;

use manul::{
    testing::{round_override, run_sync, RoundOverride, RoundWrapper, Signature, Signer, Verifier},
    Artifact, DirectMessage, FirstRound, Keypair, LocalError, Round,
};
use rand_core::OsRng;
use tracing_subscriber::EnvFilter;

use crate::simple::{Inputs, Round1, Round1Message};

#[derive(Debug, Clone, Copy)]
enum Behavior {
    Lawful,
    SerializedGarbage,
    AttributableFailure,
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
        } else if matches!(self.behavior, Behavior::AttributableFailure) {
            let message = Round1Message {
                my_position: self.round.context.ids_to_positions[&self.round.context.id],
                your_position: self.round.context.ids_to_positions[&self.round.context.id],
            };
            let dm = DirectMessage::new::<<Self::InnerRound as Round<Id>>::Protocol, _>(&message)?;
            Ok((dm, Artifact::empty()))
        } else {
            self.inner_round_ref().make_direct_message(destination)
        }
    }
}

round_override!(MaliciousRound1);

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
    let mut reports = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<MaliciousRound1<Verifier>, Signer, Verifier, Signature>(&mut OsRng, run_inputs)
            .unwrap()
    });

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(!report1.provable_errors[&v0].verify(&v0).unwrap());
    assert!(!report2.provable_errors[&v0].verify(&v0).unwrap());
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
        .iter()
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
            (signer.clone(), malicious_inputs)
        })
        .collect::<Vec<_>>();

    let my_subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let mut reports = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<MaliciousRound1<Verifier>, Signer, Verifier, Signature>(&mut OsRng, run_inputs)
            .unwrap()
    });

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(report1.provable_errors[&v0].verify(&v0).unwrap());
    assert!(report2.provable_errors[&v0].verify(&v0).unwrap());
}
