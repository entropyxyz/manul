use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt::Debug;

use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::{
    protocol::*,
    session::{signature::Keypair, SessionOutcome},
    testing::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
};

#[derive(Debug)]
struct PartialEchoProtocol;

impl Protocol for PartialEchoProtocol {
    type Result = ();
    type ProtocolError = PartialEchoProtocolError;
    type CorrectnessProof = ();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialEchoProtocolError;

impl ProtocolError for PartialEchoProtocolError {
    fn description(&self) -> String {
        format!("{:?}", self)
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _echo_broadcast: &EchoBroadcast,
        _normal_broadcast: &NormalBroadcast,
        _direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
struct Inputs<Id> {
    message_destinations: Vec<Id>,
    expecting_messages_from: Vec<Id>,
    echo_round_participation: EchoRoundParticipation<Id>,
}

#[derive(Debug)]
struct Round1<Id> {
    id: Id,
    message_destinations: BTreeSet<Id>,
    expecting_messages_from: BTreeSet<Id>,
    echo_round_participation: EchoRoundParticipation<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Round1Echo<Id> {
    sender: Id,
}

impl<Id: PartyId + Serialize + for<'de> Deserialize<'de>> EntryPoint<Id> for Round1<Id> {
    type Inputs = Inputs<Id>;
    type Protocol = PartialEchoProtocol;
    fn new(
        _rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let message_destinations = BTreeSet::from_iter(inputs.message_destinations);
        let expecting_messages_from = BTreeSet::from_iter(inputs.expecting_messages_from);
        Ok(BoxedRound::new_dynamic(Self {
            id,
            message_destinations,
            expecting_messages_from,
            echo_round_participation: inputs.echo_round_participation,
        }))
    }
}

impl<Id: PartyId + Serialize + for<'de> Deserialize<'de>> Round<Id> for Round1<Id> {
    type Protocol = PartialEchoProtocol;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.message_destinations
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.expecting_messages_from
    }

    fn echo_round_participation(&self) -> EchoRoundParticipation<Id> {
        self.echo_round_participation.clone()
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        if self.message_destinations.is_empty() {
            Ok(EchoBroadcast::none())
        } else {
            EchoBroadcast::new(
                serializer,
                Round1Echo {
                    sender: self.id.clone(),
                },
            )
        }
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        normal_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;

        if self.expecting_messages_from.is_empty() {
            echo_broadcast.assert_is_none()?;
        } else {
            let echo = echo_broadcast.deserialize::<Round1Echo<Id>>(deserializer)?;
            assert_eq!(&echo.sender, from);
            assert!(self.expecting_messages_from.contains(from));
        }

        Ok(Payload::new(()))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>> {
        Ok(FinalizeOutcome::Result(()))
    }
}

#[test]
fn partial_echo() {
    let signers = (0..5).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();

    // Nodes 0, 1 send an echo broadcast to nodes 1, 2, 3
    // The echo round happens between the nodes 1, 2, 3
    // Node 0 only sends the broadcasts, but doesn't receive any, so it skips the echo round
    // Node 4 doesn't send or receive any broadcasts, so it skips the echo round

    let node0 = (
        signers[0],
        Inputs {
            message_destinations: [ids[1], ids[2], ids[3]].into(),
            expecting_messages_from: [].into(),
            echo_round_participation: EchoRoundParticipation::Send,
        },
    );
    let node1 = (
        signers[1],
        Inputs {
            message_destinations: [ids[2], ids[3]].into(),
            expecting_messages_from: [ids[0]].into(),
            echo_round_participation: EchoRoundParticipation::Default,
        },
    );
    let node2 = (
        signers[2],
        Inputs {
            message_destinations: [].into(),
            expecting_messages_from: [ids[0], ids[1]].into(),
            echo_round_participation: EchoRoundParticipation::Receive {
                echo_targets: BTreeSet::from([ids[1], ids[3]]),
            },
        },
    );
    let node3 = (
        signers[3],
        Inputs {
            message_destinations: [].into(),
            expecting_messages_from: [ids[0], ids[1]].into(),
            echo_round_participation: EchoRoundParticipation::Receive {
                echo_targets: BTreeSet::from([ids[1], ids[2]]),
            },
        },
    );
    let node4 = (
        signers[4],
        Inputs {
            message_destinations: [].into(),
            expecting_messages_from: [].into(),
            echo_round_participation: EchoRoundParticipation::<TestVerifier>::Default,
        },
    );

    let inputs = vec![node0, node1, node2, node3, node4];

    let my_subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let reports = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<Round1<TestVerifier>, TestSessionParams<BinaryFormat>>(&mut OsRng, inputs).unwrap()
    });

    for (_id, report) in reports {
        assert!(matches!(report.outcome, SessionOutcome::Result(_)));
    }
}
