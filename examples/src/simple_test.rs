use alloc::collections::BTreeSet;

use core::marker::PhantomData;

use manul::{
    dev::{run_sync, BinaryFormat, ExtendableEntryPoint, RoundExtension, TestSessionParams, TestSigner, TestVerifier},
    protocol::{LocalError, PartyId},
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use test_log::test;

use crate::simple::{Round1, Round1Message, Round2, Round2Message, SimpleProtocolEntryPoint};

#[derive(Debug, Clone)]
struct Round1InvalidDirectMessage<Id>(PhantomData<Id>);

impl<Id> RoundExtension<Id> for Round1InvalidDirectMessage<Id>
where
    Id: PartyId,
{
    type Round = Round1<Id>;

    fn make_direct_message(
        &self,
        _rng: &mut dyn CryptoRngCore,
        round: &Self::Round,
        _destination: &Id,
    ) -> Result<Option<(Round1Message, ())>, LocalError> {
        Ok(Some((
            Round1Message {
                my_position: round.context.ids_to_positions[&round.context.id],
                your_position: round.context.ids_to_positions[&round.context.id],
            },
            (),
        )))
    }
}

#[test]
fn round1_attributable_failure() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .enumerate()
        .map(|(idx, signer)| {
            let entry_point = SimpleProtocolEntryPoint::new(all_ids.clone());
            let mut entry_point = ExtendableEntryPoint::new(entry_point);
            if idx == 0 {
                entry_point.extend(Round1InvalidDirectMessage::<TestVerifier>(PhantomData));
            }

            (*signer, entry_point)
        })
        .collect::<Vec<_>>();

    let mut reports = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .reports;

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(report1.provable_errors[&v0].verify(&()).is_ok());
    assert!(report2.provable_errors[&v0].verify(&()).is_ok());
}

#[derive(Debug, Clone)]
struct Round2InvalidDirectMessage<Id>(PhantomData<Id>);

impl<Id> RoundExtension<Id> for Round2InvalidDirectMessage<Id>
where
    Id: PartyId,
{
    type Round = Round2<Id>;

    fn make_direct_message(
        &self,
        _rng: &mut dyn CryptoRngCore,
        round: &Self::Round,
        _destination: &Id,
    ) -> Result<Option<(Round2Message, ())>, LocalError> {
        Ok(Some((
            Round2Message {
                my_position: round.context.ids_to_positions[&round.context.id],
                your_position: round.context.ids_to_positions[&round.context.id],
            },
            (),
        )))
    }
}

#[test]
fn round2_attributable_failure() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .enumerate()
        .map(|(idx, signer)| {
            let entry_point = SimpleProtocolEntryPoint::new(all_ids.clone());
            let mut entry_point = ExtendableEntryPoint::new(entry_point);
            if idx == 0 {
                entry_point.extend(Round2InvalidDirectMessage::<TestVerifier>(PhantomData));
            }

            (*signer, entry_point)
        })
        .collect::<Vec<_>>();

    let mut reports = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .reports;

    let v0 = signers[0].verifying_key();
    let v1 = signers[1].verifying_key();
    let v2 = signers[2].verifying_key();

    let _report0 = reports.remove(&v0).unwrap();
    let report1 = reports.remove(&v1).unwrap();
    let report2 = reports.remove(&v2).unwrap();

    assert!(report1.provable_errors[&v0].verify(&()).is_ok());
    assert!(report2.provable_errors[&v0].verify(&()).is_ok());
}
