use alloc::collections::BTreeSet;

use manul::{
    dev::{check_evidence_with_extension, BinaryFormat, RoundExtension, TestSessionParams, TestSigner, TestVerifier},
    protocol::{LocalError, PartyId},
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use test_log::test;

use crate::simple::{Round1, Round1Message, Round2, Round2Message, SimpleProtocolEntryPoint};

type Id = TestVerifier;
type SP = TestSessionParams<BinaryFormat>;
type EP = SimpleProtocolEntryPoint<Id>;

fn make_entry_points() -> (Vec<(TestSigner, EP)>, ()) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .into_iter()
        .map(|signer| (signer, SimpleProtocolEntryPoint::new(all_ids.clone())))
        .collect();

    (entry_points, ())
}

#[test]
fn round1_attributable_failure() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Round1InvalidDirectMessage;

    impl<Id> RoundExtension<Id> for Round1InvalidDirectMessage
    where
        Id: PartyId,
    {
        type Round = Round1<Id>;

        fn make_direct_message(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: &Self::Round,
            _destination: &Id,
        ) -> Result<(Round1Message, ()), LocalError> {
            let message = Round1Message {
                my_position: round.context.ids_to_positions[&round.context.id],
                your_position: round.context.ids_to_positions[&round.context.id],
            };
            Ok((message, ()))
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Round1InvalidDirectMessage,
        "(Round 1): Invalid position",
    )
}

#[test]
fn round2_attributable_failure() -> Result<(), LocalError> {
    #[derive(Debug, Clone)]
    struct Round2InvalidDirectMessage;

    impl<Id> RoundExtension<Id> for Round2InvalidDirectMessage
    where
        Id: PartyId,
    {
        type Round = Round2<Id>;

        fn make_direct_message(
            &self,
            _rng: &mut impl CryptoRngCore,
            round: &Self::Round,
            _destination: &Id,
        ) -> Result<(Round2Message, ()), LocalError> {
            let message = Round2Message {
                my_position: round.context.ids_to_positions[&round.context.id],
                your_position: round.context.ids_to_positions[&round.context.id],
            };
            Ok((message, ()))
        }
    }

    check_evidence_with_extension::<SP, _>(
        &mut OsRng,
        make_entry_points(),
        Round2InvalidDirectMessage,
        "(Round 2): Invalid position",
    )
}
