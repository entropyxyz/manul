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
    session::signature::Keypair,
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
    id: Id,
    message_destinations: BTreeSet<Id>,
    expecting_messages_from: BTreeSet<Id>,
    echo_round_participation: EchoRoundParticipation<Id>,
}

#[derive(Debug)]
struct Round1<Id> {
    inputs: Inputs<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Round1Echo<Id> {
    sender: Id,
}

impl<Id: PartyId + Serialize + for<'de> Deserialize<'de>> EntryPoint<Id> for Inputs<Id> {
    type Protocol = PartialEchoProtocol;
    fn make_round(
        self,
        _rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        _id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        Ok(BoxedRound::new_dynamic(Round1 { inputs: self }))
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
        &self.inputs.message_destinations
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.inputs.expecting_messages_from
    }

    fn echo_round_participation(&self) -> EchoRoundParticipation<Id> {
        self.inputs.echo_round_participation.clone()
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        if self.inputs.message_destinations.is_empty() {
            Ok(EchoBroadcast::none())
        } else {
            EchoBroadcast::new(
                serializer,
                Round1Echo {
                    sender: self.inputs.id.clone(),
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

        if self.inputs.expecting_messages_from.is_empty() {
            echo_broadcast.assert_is_none()?;
        } else {
            let echo = echo_broadcast.deserialize::<Round1Echo<Id>>(deserializer)?;
            assert_eq!(&echo.sender, from);
            assert!(self.inputs.expecting_messages_from.contains(from));
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
            id: signers[0].verifying_key(),
            message_destinations: BTreeSet::from([ids[1], ids[2], ids[3]]),
            expecting_messages_from: BTreeSet::new(),
            echo_round_participation: EchoRoundParticipation::Send,
        },
    );
    let node1 = (
        signers[1],
        Inputs {
            id: signers[1].verifying_key(),
            message_destinations: BTreeSet::from([ids[2], ids[3]]),
            expecting_messages_from: BTreeSet::from([ids[0]]),
            echo_round_participation: EchoRoundParticipation::Default,
        },
    );
    let node2 = (
        signers[2],
        Inputs {
            id: signers[2].verifying_key(),
            message_destinations: BTreeSet::new(),
            expecting_messages_from: BTreeSet::from([ids[0], ids[1]]),
            echo_round_participation: EchoRoundParticipation::Receive {
                echo_targets: BTreeSet::from([ids[1], ids[3]]),
            },
        },
    );
    let node3 = (
        signers[3],
        Inputs {
            id: signers[3].verifying_key(),
            message_destinations: BTreeSet::new(),
            expecting_messages_from: BTreeSet::from([ids[0], ids[1]]),
            echo_round_participation: EchoRoundParticipation::Receive {
                echo_targets: BTreeSet::from([ids[1], ids[2]]),
            },
        },
    );
    let node4 = (
        signers[4],
        Inputs {
            id: signers[4].verifying_key(),
            message_destinations: BTreeSet::new(),
            expecting_messages_from: BTreeSet::new(),
            echo_round_participation: EchoRoundParticipation::<TestVerifier>::Default,
        },
    );

    let entry_points = vec![node0, node1, node2, node3, node4];

    let my_subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    let _results = tracing::subscriber::with_default(my_subscriber, || {
        run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap()
    });
}
