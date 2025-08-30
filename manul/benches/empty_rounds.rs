extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use criterion::{criterion_group, criterion_main, Criterion};
use manul::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner},
    protocol::{
        Artifact, BoxedFormat, BoxedRound, BoxedRoundInfo, CommunicationInfo, DirectMessage, EchoBroadcast, EntryPoint,
        FinalizeOutcome, LocalError, NoProtocolErrors, PartyId, Payload, Protocol, ProtocolMessage,
        ProtocolMessagePart, ReceiveError, Round, RoundId, TransitionInfo,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct EmptyProtocol;

impl<Id> Protocol<Id> for EmptyProtocol {
    type Result = ();
    type ProtocolError = NoProtocolErrors;
    fn round_info(_round_id: &RoundId) -> Option<BoxedRoundInfo<Id, Self>> {
        unimplemented!()
    }
}

#[derive(Debug)]
struct EmptyRound<Id> {
    round_counter: u8,
    inputs: Inputs<Id>,
}

#[derive(Debug, Clone)]
struct Inputs<Id> {
    rounds_num: u8,
    echo: bool,
    other_ids: BTreeSet<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Round1DirectMessage;

#[derive(Debug, Serialize, Deserialize)]
struct Round1EchoBroadcast;

struct Round1Payload;

struct Round1Artifact;

impl<Id: PartyId> EntryPoint<Id> for Inputs<Id> {
    type Protocol = EmptyProtocol;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        _rng: &mut dyn CryptoRngCore,
        _shared_randomness: &[u8],
        _id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        Ok(BoxedRound::new_dynamic(EmptyRound {
            round_counter: 1,
            inputs: self,
        }))
    }
}

impl<Id: PartyId> Round<Id> for EmptyRound<Id> {
    type Protocol = EmptyProtocol;

    fn transition_info(&self) -> TransitionInfo {
        if self.inputs.rounds_num == self.round_counter {
            TransitionInfo::new_linear_terminating(self.round_counter)
        } else {
            TransitionInfo::new_linear(self.round_counter)
        }
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.inputs.other_ids)
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        if self.inputs.echo {
            EchoBroadcast::new(format, Round1EchoBroadcast)
        } else {
            Ok(EchoBroadcast::none())
        }
    }

    fn make_direct_message(
        &self,
        _rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        _destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let dm = DirectMessage::new(format, Round1DirectMessage)?;
        let artifact = Artifact::new(Round1Artifact);
        Ok((dm, Some(artifact)))
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        _from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        if self.inputs.echo {
            let _echo_broadcast = message.echo_broadcast.deserialize::<Round1EchoBroadcast>(format)?;
        } else {
            message.echo_broadcast.assert_is_none()?;
        }
        message.normal_broadcast.assert_is_none()?;
        let _direct_message = message.direct_message.deserialize::<Round1DirectMessage>(format)?;
        Ok(Payload::new(Round1Payload))
    }

    fn finalize(
        self: Box<Self>,
        _rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        for payload in payloads.into_values() {
            let _payload = payload.downcast::<Round1Payload>()?;
        }
        for artifact in artifacts.into_values() {
            let _artifact = artifact.downcast::<Round1Artifact>()?;
        }

        if self.round_counter == self.inputs.rounds_num {
            Ok(FinalizeOutcome::Result(()))
        } else {
            let round = BoxedRound::new_dynamic(EmptyRound {
                round_counter: self.round_counter + 1,
                inputs: self.inputs,
            });
            Ok(FinalizeOutcome::AnotherRound(round))
        }
    }
}

fn bench_empty_rounds(c: &mut Criterion) {
    // Benchmarks a full run of a protocol with rounds that do nothing but send and receive empty messages.
    // This serves as an "integration" benchmark for the whole `Session`.
    // Necessarily includes the overhead of `run_sync()` as well.

    let mut group = c.benchmark_group("Empty rounds");

    let nodes = 25;
    let rounds_num = 5;

    let signers = (0..nodes).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points_no_echo = signers
        .iter()
        .cloned()
        .map(|signer| {
            let mut other_ids = all_ids.clone();
            other_ids.remove(&signer.verifying_key());
            (
                signer,
                Inputs {
                    rounds_num,
                    other_ids,
                    echo: false,
                },
            )
        })
        .collect::<Vec<_>>();

    group.bench_function("25 nodes, 5 rounds, no echo", |b| {
        b.iter(|| {
            assert!(
                run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points_no_echo.clone())
                    .unwrap()
                    .results()
                    .is_ok()
            )
        })
    });

    let entry_points_echo = signers
        .iter()
        .cloned()
        .map(|signer| {
            let mut other_ids = all_ids.clone();
            other_ids.remove(&signer.verifying_key());
            (
                signer,
                Inputs {
                    rounds_num,
                    other_ids,
                    echo: true,
                },
            )
        })
        .collect::<Vec<_>>();

    group.sample_size(30);

    group.bench_function("25 nodes, 5 rounds, echo each round", |b| {
        b.iter(|| {
            assert!(
                run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points_echo.clone())
                    .unwrap()
                    .results()
                    .is_ok()
            )
        })
    });

    group.finish()
}

criterion_group!(benches, bench_empty_rounds,);
criterion_main!(benches);
