use alloc::collections::BTreeSet;
use core::fmt::Debug;

use manul::{
    combinators::{
        chain::{Chain, ChainedJoin, ChainedProtocol, ChainedSplit},
        CombinatorEntryPoint,
    },
    protocol::{PartyId, Protocol},
};

use super::simple::{SimpleProtocol, SimpleProtocolEntryPoint};

/// A protocol that runs the [`SimpleProtocol`] twice, in sequence.
/// Illustrates the chain protocol combinator.
#[derive(Debug)]
pub struct DoubleSimpleProtocol;

impl ChainedProtocol for DoubleSimpleProtocol {
    type Protocol1 = SimpleProtocol;
    type Protocol2 = SimpleProtocol;
}

pub struct DoubleSimpleEntryPoint<Id> {
    all_ids: BTreeSet<Id>,
}

impl<Id: PartyId> DoubleSimpleEntryPoint<Id> {
    pub fn new(all_ids: BTreeSet<Id>) -> Self {
        Self { all_ids }
    }
}

impl<Id> CombinatorEntryPoint for DoubleSimpleEntryPoint<Id> {
    type Combinator = Chain;
}

impl<Id> ChainedSplit<Id> for DoubleSimpleEntryPoint<Id>
where
    Id: PartyId,
{
    type Protocol = DoubleSimpleProtocol;
    type EntryPoint = SimpleProtocolEntryPoint<Id>;
    fn make_entry_point1(self) -> (Self::EntryPoint, impl ChainedJoin<Id, Protocol = Self::Protocol>) {
        (
            SimpleProtocolEntryPoint::new(self.all_ids.clone()),
            DoubleSimpleProtocolTransition { all_ids: self.all_ids },
        )
    }
}

#[derive(Debug)]
struct DoubleSimpleProtocolTransition<Id> {
    all_ids: BTreeSet<Id>,
}

impl<Id> ChainedJoin<Id> for DoubleSimpleProtocolTransition<Id>
where
    Id: PartyId,
{
    type Protocol = DoubleSimpleProtocol;
    type EntryPoint = SimpleProtocolEntryPoint<Id>;
    fn make_entry_point2(self, _result: <SimpleProtocol as Protocol>::Result) -> Self::EntryPoint {
        SimpleProtocolEntryPoint::new(self.all_ids)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        dev::{run_sync_with_tracing, BinaryFormat, TestSessionParams, TestSigner},
        session::signature::Keypair,
    };
    use rand_core::OsRng;

    use super::DoubleSimpleEntryPoint;

    #[test]
    fn round() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| (signer, DoubleSimpleEntryPoint::new(all_ids.clone())))
            .collect::<Vec<_>>();

        let results = run_sync_with_tracing::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        for (_id, result) in results {
            assert_eq!(result, 3); // 0 + 1 + 2
        }
    }
}
