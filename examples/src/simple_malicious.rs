use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use manul::{
    protocol::{
        Artifact, DirectMessage, FinalizeError, FinalizeOutcome, FirstRound, LocalError, Payload, ProtocolMessagePart,
        Round,
    },
    session::{signature::Keypair, Serializer},
    testing::{round_override, run_sync, RoundOverride, RoundWrapper, TestSessionParams, TestSigner, TestVerifier},
};
use rand_core::{CryptoRngCore, OsRng};
use tracing_subscriber::EnvFilter;

use crate::{
    simple::{Inputs, Round1, Round1Message, Round2, Round2Message},
    Binary,
};

#[derive(Debug, Clone, Copy)]
enum Behavior {
    Lawful,
    SerializedGarbage,
    AttributableFailure,
    AttributableFailureRound2,
}

struct MaliciousInputs<Id> {
    inputs: Inputs<Id>,
    behavior: Behavior,
}

#[derive(Debug)]
struct MaliciousRound1<Id> {
    round: Round1<Id>,
    behavior: Behavior,
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> RoundWrapper<Id> for MaliciousRound1<Id> {
    type InnerRound = Round1<Id>;
    fn inner_round_ref(&self) -> &Self::InnerRound {
        &self.round
    }
    fn inner_round(self) -> Self::InnerRound {
        self.round
    }
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> FirstRound<Id> for MaliciousRound1<Id> {
    type Inputs = MaliciousInputs<Id>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<Self, LocalError> {
        let round = Round1::new(rng, shared_randomness, id, inputs.inputs)?;
        Ok(Self {
            round,
            behavior: inputs.behavior,
        })
    }
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> RoundOverride<Id> for MaliciousRound1<Id> {
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &Id,
    ) -> Result<DirectMessage, LocalError> {
        if matches!(self.behavior, Behavior::SerializedGarbage) {
            DirectMessage::new(serializer, [99u8])
        } else if matches!(self.behavior, Behavior::AttributableFailure) {
            let message = Round1Message {
                my_position: self.round.context.ids_to_positions[&self.round.context.id],
                your_position: self.round.context.ids_to_positions[&self.round.context.id],
            };
            DirectMessage::new(serializer, message)
        } else {
            self.inner_round_ref().make_direct_message(rng, serializer, destination)
        }
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<
        FinalizeOutcome<Id, <<Self as RoundWrapper<Id>>::InnerRound as Round<Id>>::Protocol>,
        FinalizeError<<<Self as RoundWrapper<Id>>::InnerRound as Round<Id>>::Protocol>,
    > {
        let behavior = self.behavior;
        let outcome = self.inner_round().finalize(rng, payloads, artifacts)?;

        Ok(match outcome {
            FinalizeOutcome::Result(res) => FinalizeOutcome::Result(res),
            FinalizeOutcome::AnotherRound(another_round) => {
                let round2 = another_round.downcast::<Round2<Id>>().map_err(FinalizeError::Local)?;
                FinalizeOutcome::another_round(MaliciousRound2 {
                    round: round2,
                    behavior,
                })
            }
        })
    }
}

round_override!(MaliciousRound1);

#[derive(Debug)]
struct MaliciousRound2<Id> {
    round: Round2<Id>,
    behavior: Behavior,
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> RoundWrapper<Id> for MaliciousRound2<Id> {
    type InnerRound = Round2<Id>;
    fn inner_round_ref(&self) -> &Self::InnerRound {
        &self.round
    }
    fn inner_round(self) -> Self::InnerRound {
        self.round
    }
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> RoundOverride<Id> for MaliciousRound2<Id> {
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &Id,
    ) -> Result<DirectMessage, LocalError> {
        if matches!(self.behavior, Behavior::AttributableFailureRound2) {
            let message = Round2Message {
                my_position: self.round.context.ids_to_positions[&self.round.context.id],
                your_position: self.round.context.ids_to_positions[&self.round.context.id],
            };
            DirectMessage::new(serializer, message)
        } else {
            self.inner_round_ref().make_direct_message(rng, serializer, destination)
        }
    }
}

round_override!(MaliciousRound2);

#[test]
fn serialized_garbage() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
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
            (*signer, malicious_inputs)
        })
        .collect::<Vec<_>>();

    let my_subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let mut reports = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<MaliciousRound1<TestVerifier>, TestSessionParams<Binary>>(&mut OsRng, run_inputs).unwrap()
    });

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(report1.provable_errors[&v0].verify(&v0).is_ok());
    assert!(report2.provable_errors[&v0].verify(&v0).is_ok());
}

#[test]
fn attributable_failure() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
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
            (*signer, malicious_inputs)
        })
        .collect::<Vec<_>>();

    let my_subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let mut reports = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<MaliciousRound1<TestVerifier>, TestSessionParams<Binary>>(&mut OsRng, run_inputs).unwrap()
    });

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(report1.provable_errors[&v0].verify(&v0).is_ok());
    assert!(report2.provable_errors[&v0].verify(&v0).is_ok());
}

#[test]
fn attributable_failure_round2() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let inputs = Inputs { all_ids };

    let run_inputs = signers
        .iter()
        .enumerate()
        .map(|(idx, signer)| {
            let behavior = if idx == 0 {
                Behavior::AttributableFailureRound2
            } else {
                Behavior::Lawful
            };

            let malicious_inputs = MaliciousInputs {
                inputs: inputs.clone(),
                behavior,
            };
            (*signer, malicious_inputs)
        })
        .collect::<Vec<_>>();

    let my_subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let mut reports = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<MaliciousRound1<TestVerifier>, TestSessionParams<Binary>>(&mut OsRng, run_inputs).unwrap()
    });

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(report1.provable_errors[&v0].verify(&v0).is_ok());
    assert!(report2.provable_errors[&v0].verify(&v0).is_ok());
}
