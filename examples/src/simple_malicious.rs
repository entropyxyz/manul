use alloc::collections::BTreeSet;
use core::fmt::Debug;

use manul::{
    combinators::misbehave::{Misbehaving, MisbehavingEntryPoint},
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner},
    protocol::{
        Artifact, BoxedFormat, BoxedRound, DirectMessage, EntryPoint, LocalError, PartyId, ProtocolMessagePart,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use test_log::test;

use crate::simple::{Round1, Round1Message, Round2, Round2Message, SimpleProtocolEntryPoint};

#[derive(Debug, Clone, Copy)]
enum Behavior {
    SerializedGarbage,
    AttributableFailure,
    AttributableFailureRound2,
}

struct MaliciousLogic;

impl<Id: PartyId> Misbehaving<Id, Behavior> for MaliciousLogic {
    type EntryPoint = SimpleProtocolEntryPoint<Id>;

    fn modify_direct_message(
        _rng: &mut dyn CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &Behavior,
        format: &BoxedFormat,
        _destination: &Id,
        direct_message: DirectMessage,
        artifact: Option<Artifact>,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let dm = if round.id() == 1 {
            match behavior {
                Behavior::SerializedGarbage => DirectMessage::new(format, [99u8])?,
                Behavior::AttributableFailure => {
                    let round1 = round.downcast_static_ref::<Round1<Id>>()?;
                    let message = Round1Message {
                        my_position: round1.context.ids_to_positions[&round1.context.id],
                        your_position: round1.context.ids_to_positions[&round1.context.id],
                    };
                    DirectMessage::new(format, message)?
                }
                _ => direct_message,
            }
        } else if round.id() == 2 {
            match behavior {
                Behavior::AttributableFailureRound2 => {
                    let round2 = round.downcast_static_ref::<Round2<Id>>()?;
                    let message = Round2Message {
                        my_position: round2.context.ids_to_positions[&round2.context.id],
                        your_position: round2.context.ids_to_positions[&round2.context.id],
                    };
                    DirectMessage::new(format, message)?
                }
                _ => direct_message,
            }
        } else {
            direct_message
        };
        Ok((dm, artifact))
    }
}

type MaliciousEntryPoint<Id> = MisbehavingEntryPoint<Id, Behavior, MaliciousLogic>;

#[test]
fn serialized_garbage() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .enumerate()
        .map(|(idx, signer)| {
            let behavior = if idx == 0 {
                Some(Behavior::SerializedGarbage)
            } else {
                None
            };

            let entry_point = MaliciousEntryPoint::new(SimpleProtocolEntryPoint::new(all_ids.clone()), behavior);
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

#[test]
fn attributable_failure() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .enumerate()
        .map(|(idx, signer)| {
            let behavior = if idx == 0 {
                Some(Behavior::AttributableFailure)
            } else {
                None
            };

            let entry_point = MaliciousEntryPoint::new(SimpleProtocolEntryPoint::new(all_ids.clone()), behavior);
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

#[test]
fn attributable_failure_round2() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .enumerate()
        .map(|(idx, signer)| {
            let behavior = if idx == 0 {
                Some(Behavior::AttributableFailureRound2)
            } else {
                None
            };

            let entry_point = MaliciousEntryPoint::new(SimpleProtocolEntryPoint::new(all_ids.clone()), behavior);
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
