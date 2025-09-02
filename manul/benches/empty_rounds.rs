extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use criterion::{criterion_group, criterion_main, Criterion};
use manul::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner},
    protocol::{
        BoxedRound, CommunicationInfo, EntryPoint, FinalizeOutcome, LocalError, NoMessage, NoProtocolErrors, PartyId,
        Protocol, ProtocolMessage, ReceiveError, Round, RoundId, RoundInfo, TransitionInfo,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct EmptyProtocol;

impl<Id> Protocol<Id> for EmptyProtocol {
    type Result = ();
    type SharedData = ();
    fn round_info(_round_id: &RoundId) -> Option<RoundInfo<Id, Self>> {
        unimplemented!()
    }
}

#[derive(Debug)]
struct EmptyRound<Id> {
    round_counter: u8,
    inputs: Inputs<Id>,
}

#[derive(Debug)]
struct EmptyRoundWithEcho<Id> {
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
        _rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        _id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        if self.echo {
            Ok(BoxedRound::new(EmptyRoundWithEcho {
                round_counter: 1,
                inputs: self,
            }))
        } else {
            Ok(BoxedRound::new(EmptyRound {
                round_counter: 1,
                inputs: self,
            }))
        }
    }
}

impl<Id: PartyId> Round<Id> for EmptyRound<Id> {
    type Protocol = EmptyProtocol;

    type ProtocolError = NoProtocolErrors<Self>;
    type EchoBroadcast = Round1EchoBroadcast;
    type NormalBroadcast = NoMessage;
    type DirectMessage = Round1DirectMessage;
    type Payload = Round1Payload;
    type Artifact = Round1Artifact;

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

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _destination: &Id,
    ) -> Result<(Self::DirectMessage, Self::Artifact), LocalError> {
        Ok((Round1DirectMessage, Round1Artifact))
    }

    fn receive_message(
        &self,
        _from: &Id,
        _message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        Ok(Round1Payload)
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        if self.round_counter == self.inputs.rounds_num {
            Ok(FinalizeOutcome::Result(()))
        } else {
            let round = BoxedRound::new(EmptyRound {
                round_counter: self.round_counter + 1,
                inputs: self.inputs,
            });
            Ok(FinalizeOutcome::AnotherRound(round))
        }
    }
}

impl<Id: PartyId> Round<Id> for EmptyRoundWithEcho<Id> {
    type Protocol = EmptyProtocol;

    type ProtocolError = NoProtocolErrors<Self>;
    type EchoBroadcast = Round1EchoBroadcast;
    type NormalBroadcast = NoMessage;
    type DirectMessage = Round1DirectMessage;
    type Payload = Round1Payload;
    type Artifact = Round1Artifact;

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

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        Ok(Round1EchoBroadcast)
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _destination: &Id,
    ) -> Result<(Self::DirectMessage, Self::Artifact), LocalError> {
        Ok((Round1DirectMessage, Round1Artifact))
    }

    fn receive_message(
        &self,
        _from: &Id,
        _message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        Ok(Round1Payload)
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        if self.round_counter == self.inputs.rounds_num {
            Ok(FinalizeOutcome::Result(()))
        } else {
            let round = BoxedRound::new(EmptyRound {
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
