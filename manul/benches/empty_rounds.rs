extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use criterion::{criterion_group, criterion_main, Criterion};
use manul::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner},
    protocol::{
        Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
        NormalBroadcast, PartyId, Payload, Protocol, ProtocolMessagePart, ReceiveError, Round, RoundId, Serializer,
    },
    session::signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct EmptyProtocol;

impl Protocol for EmptyProtocol {
    type Result = ();
    type ProtocolError = ();
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
    fn make_round(
        self,
        _rng: &mut impl CryptoRngCore,
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

    fn id(&self) -> RoundId {
        RoundId::new(self.round_counter)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        if self.inputs.rounds_num == self.round_counter {
            BTreeSet::new()
        } else {
            [RoundId::new(self.round_counter + 1)].into()
        }
    }

    fn may_produce_result(&self) -> bool {
        self.inputs.rounds_num == self.round_counter
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.inputs.other_ids
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        if self.inputs.echo {
            EchoBroadcast::new(serializer, Round1EchoBroadcast)
        } else {
            Ok(EchoBroadcast::none())
        }
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        _destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let dm = DirectMessage::new(serializer, Round1DirectMessage)?;
        let artifact = Artifact::new(Round1Artifact);
        Ok((dm, Some(artifact)))
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        _from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        if self.inputs.echo {
            let _echo_broadcast = echo_broadcast.deserialize::<Round1EchoBroadcast>(deserializer)?;
        } else {
            echo_broadcast.assert_is_none()?;
        }
        normal_broadcast.assert_is_none()?;
        let _direct_message = direct_message.deserialize::<Round1DirectMessage>(deserializer)?;
        Ok(Payload::new(Round1Payload))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        for payload in payloads.into_values() {
            let _payload = payload.try_to_typed::<Round1Payload>()?;
        }
        for artifact in artifacts.into_values() {
            let _artifact = artifact.try_to_typed::<Round1Artifact>()?;
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

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.inputs.other_ids
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
