use alloc::collections::BTreeSet;

use manul::{
    combinators::misbehave::Misbehaving,
    dev::{
        check_evidence_with_behavior, check_invalid_message_evidence, BinaryFormat, CheckPart, TestSessionParams,
        TestSigner, TestVerifier,
    },
    protocol::{Artifact, BoxedFormat, BoxedRound, DirectMessage, EntryPoint, LocalError, ProtocolMessagePart},
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use test_log::test;

use crate::simple::{Round1, Round1Message, Round2, Round2Message, SimpleProtocolEntryPoint};

type Id = TestVerifier;
type EP = SimpleProtocolEntryPoint<Id>;
type SP = TestSessionParams<BinaryFormat>;

fn make_entry_points() -> Vec<(TestSigner, EP)> {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    signers
        .into_iter()
        .map(|signer| (signer, SimpleProtocolEntryPoint::new(all_ids.clone())))
        .collect()
}

fn check_evidence<M>(expected_description: &str) -> Result<(), LocalError>
where
    M: Misbehaving<Id, (), EntryPoint = EP>,
{
    check_evidence_with_behavior::<SP, M, _>(&mut OsRng, make_entry_points(), &(), &(), expected_description)
}

fn check_message(round_num: u8, part: CheckPart, expecting_a_message: bool) -> Result<(), LocalError> {
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        round_num,
        part,
        &(),
        expecting_a_message,
    )
}

#[test]
fn invalid_messages_r1() {
    check_message(1, CheckPart::EchoBroadcast, true).unwrap();
    check_message(1, CheckPart::NormalBroadcast, true).unwrap();
    check_message(1, CheckPart::DirectMessage, true).unwrap();
}

#[test]
fn invalid_messages_r2() {
    check_message(2, CheckPart::EchoBroadcast, false).unwrap();
    check_message(2, CheckPart::NormalBroadcast, false).unwrap();
    check_message(2, CheckPart::DirectMessage, true).unwrap();
}

#[test]
fn attributable_failure() -> Result<(), LocalError> {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = EP;

        fn modify_direct_message(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            if round.id() == 1 {
                let round1 = round.downcast_ref::<Round1<Id>>()?;
                let message = Round1Message {
                    my_position: round1.context.ids_to_positions[&round1.context.id],
                    your_position: round1.context.ids_to_positions[&round1.context.id],
                };
                let dm = DirectMessage::new(format, message)?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }
    }

    check_evidence::<Override>("Protocol error: Invalid position in Round 1")
}

#[test]
fn attributable_failure_round2() -> Result<(), LocalError> {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = EP;

        fn modify_direct_message(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            if round.id() == 2 {
                let round2 = round.downcast_ref::<Round2<Id>>()?;
                let message = Round2Message {
                    my_position: round2.context.ids_to_positions[&round2.context.id],
                    your_position: round2.context.ids_to_positions[&round2.context.id],
                };
                let dm = DirectMessage::new(format, message)?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }
    }

    check_evidence::<Override>("Protocol error: Invalid position in Round 2")
}
