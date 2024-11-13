use core::fmt::Debug;

use manul::{
    combinators::chain::{Chained, ChainedEntryPoint},
    protocol::PartyId,
};

use super::simple::{Inputs, Round1};

pub struct ChainedSimple;

#[derive(Debug)]
pub struct NewInputs<Id>(Inputs<Id>);

impl<'a, Id: PartyId> From<&'a NewInputs<Id>> for Inputs<Id> {
    fn from(source: &'a NewInputs<Id>) -> Self {
        source.0.clone()
    }
}

impl<Id: PartyId> From<(NewInputs<Id>, u8)> for Inputs<Id> {
    fn from(source: (NewInputs<Id>, u8)) -> Self {
        let (inputs, _result) = source;
        inputs.0
    }
}

impl<Id: PartyId> Chained<Id> for ChainedSimple {
    type Inputs = NewInputs<Id>;
    type EntryPoint1 = Round1<Id>;
    type EntryPoint2 = Round1<Id>;
}

pub type DoubleSimpleEntryPoint<Id> = ChainedEntryPoint<Id, ChainedSimple>;

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        session::{signature::Keypair, SessionOutcome},
        testing::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    };
    use rand_core::OsRng;
    use tracing_subscriber::EnvFilter;

    use super::{DoubleSimpleEntryPoint, NewInputs};
    use crate::simple::Inputs;

    #[test]
    fn round() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let inputs = signers
            .into_iter()
            .map(|signer| {
                (
                    signer,
                    NewInputs(Inputs {
                        all_ids: all_ids.clone(),
                    }),
                )
            })
            .collect::<Vec<_>>();

        let my_subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        let reports = tracing::subscriber::with_default(my_subscriber, || {
            run_sync::<DoubleSimpleEntryPoint<TestVerifier>, TestSessionParams<BinaryFormat>>(&mut OsRng, inputs)
                .unwrap()
        });

        for (_id, report) in reports {
            if let SessionOutcome::Result(result) = report.outcome {
                assert_eq!(result, 3); // 0 + 1 + 2
            } else {
                panic!("Session did not finish successfully");
            }
        }
    }
}
