use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};

use crate::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        BoxedRound, BoxedRoundInfo, CommunicationInfo, EchoRoundParticipation, EntryPoint, FinalizeOutcome, LocalError,
        NoMessage, NoProtocolErrors, NoProvableErrors, PartyId, Protocol, ReceiveError, RoundId, StaticProtocolMessage,
        StaticRound, TransitionInfo,
    },
    signature::Keypair,
};

#[derive(Debug)]
struct PartialEchoProtocol<Id>(PhantomData<Id>);

impl<Id: PartyId> Protocol<Id> for PartialEchoProtocol<Id> {
    type Result = ();
    type SharedData = ();
    type ProtocolError = NoProtocolErrors;

    fn round_info(round_id: &RoundId) -> Option<BoxedRoundInfo<Id, Self>> {
        match round_id {
            round_id if round_id == &RoundId::new(1) => Some(BoxedRoundInfo::new::<Round1<Id>>()),
            _ => None,
        }
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
    type Protocol = PartialEchoProtocol<Id>;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        _rng: &mut dyn CryptoRngCore,
        _shared_randomness: &[u8],
        _id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        Ok(BoxedRound::new_static(Round1 { inputs: self }))
    }
}

impl<Id: PartyId + Serialize + for<'de> Deserialize<'de>> StaticRound<Id> for Round1<Id> {
    type Protocol = PartialEchoProtocol<Id>;
    type ProvableError = NoProvableErrors<Self>;

    type DirectMessage = NoMessage;
    type NormalBroadcast = NoMessage;
    type EchoBroadcast = Round1Echo<Id>;

    type Payload = ();
    type Artifact = ();

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(1)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo {
            message_destinations: self.inputs.message_destinations.clone(),
            expecting_messages_from: self.inputs.expecting_messages_from.clone(),
            echo_round_participation: self.inputs.echo_round_participation.clone(),
        }
    }

    fn make_echo_broadcast(&self, _rng: &mut dyn CryptoRngCore) -> Result<Option<Self::EchoBroadcast>, LocalError> {
        Ok(if self.inputs.message_destinations.is_empty() {
            None
        } else {
            Some(Round1Echo {
                sender: self.inputs.id.clone(),
            })
        })
    }

    fn receive_message(
        &self,
        from: &Id,
        message: StaticProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self::Protocol>> {
        if self.inputs.expecting_messages_from.is_empty() {
            panic!("Message received when none was expected, this would be a provable offense");
        } else {
            let echo = message.echo_broadcast;
            assert_eq!(&echo.sender, from);
            assert!(self.inputs.expecting_messages_from.contains(from));
        }

        Ok(())
    }

    fn finalize(
        self,
        _rng: &mut dyn CryptoRngCore,
        _payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
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

    let _results = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();
}
