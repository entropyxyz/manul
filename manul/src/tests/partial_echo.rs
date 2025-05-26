use alloc::{
    boxed::Box,
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
        Artifact, BoxedFormat, BoxedRound, CommunicationInfo, DirectMessage, EchoBroadcast, EchoRoundParticipation,
        EntryPoint, FinalizeOutcome, LocalError, MessageValidationError, NoProtocolErrors, NormalBroadcast, PartyId,
        Payload, Protocol, ProtocolMessage, ProtocolMessagePart, ReceiveError, Round, RoundId, TransitionInfo,
    },
    signature::Keypair,
};

#[derive(Debug)]
struct PartialEchoProtocol<Id>(PhantomData<Id>);

impl<Id: PartyId> Protocol<Id> for PartialEchoProtocol<Id> {
    type Result = ();
    type ProtocolError = NoProtocolErrors;

    fn verify_direct_message_is_invalid(
        _format: &BoxedFormat,
        _round_id: &RoundId,
        _message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }

    fn verify_echo_broadcast_is_invalid(
        _format: &BoxedFormat,
        _round_id: &RoundId,
        _message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }

    fn verify_normal_broadcast_is_invalid(
        _format: &BoxedFormat,
        _round_id: &RoundId,
        _message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
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
        Ok(BoxedRound::new(Round1 { inputs: self }))
    }
}

impl<Id: PartyId + Serialize + for<'de> Deserialize<'de>> Round<Id> for Round1<Id> {
    type Protocol = PartialEchoProtocol<Id>;

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

    fn make_echo_broadcast(
        &self,
        _rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        if self.inputs.message_destinations.is_empty() {
            Ok(EchoBroadcast::none())
        } else {
            EchoBroadcast::new(
                format,
                Round1Echo {
                    sender: self.inputs.id.clone(),
                },
            )
        }
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;

        if self.inputs.expecting_messages_from.is_empty() {
            message.echo_broadcast.assert_is_none()?;
        } else {
            let echo = message.echo_broadcast.deserialize::<Round1Echo<Id>>(format)?;
            assert_eq!(&echo.sender, from);
            assert!(self.inputs.expecting_messages_from.contains(from));
        }

        Ok(Payload::new(()))
    }

    fn finalize(
        self: Box<Self>,
        _rng: &mut dyn CryptoRngCore,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
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
