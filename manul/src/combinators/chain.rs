/*!
A combinator representing two protocols as a new protocol that, when executed,
executes the two inner protocols in sequence, feeding the result of the first protocol
into the inputs of the second protocol.

For the session level users (that is, the ones executing the protocols)
the new protocol is a single entity with its own [`Protocol`](`crate::protocol::Protocol`) type
and an [`EntryPoint`](`crate::protocol::EntryPoint`) type.

For example, imagine we have a `ProtocolA` with an entry point `EntryPointA`, inputs `InputsA`,
two rounds, `RA1` and `RA2`, and the result `ResultA`;
and similarly a `ProtocolB` with an entry point `EntryPointB`, inputs `InputsB`,
two rounds, `RB1` and `RB2`, and the result `ResultB`.

Then the chained protocol will provide `ProtocolC: Protocol` and `EntryPointC: EntryPoint`,
the user will define `InputsC` for the new protocol, and the execution will look like:
- `InputsA` is created from `InputsC` via the user-defined `From` impl;
- `EntryPointA` is initialized with `InputsA`;
- `RA1` is executed;
- `RA2` is executed, producing `ResultA`;
- `InputsB` is created from `ResultA` and `InputsC` via the user-defined `From` impl;
- `RB1` is executed;
- `RB2` is executed, producing `ResultB` (which is also the result of `ChainedProtocol`).

If the execution happens in a [`Session`](`crate::session::Session`), and there is an error at any point,
a regular evidence or correctness proof are created using the corresponding types from the new `ProtocolC`.

The usage is as follows.

1. Define an input type for the new joined protocol.
   Most likely it will be a union between inputs of the first and the second protocol.

2. Implement [`Chained`] for a type of your choice. Usually it will be an empty token type.
   You will have to specify the entry points of the two protocols,
   and the [`From`] conversions from the new input type to the inputs of both entry points
   (see the corresponding associated type bounds).

3. The entry point for the new protocol will be [`ChainedEntryPoint`] parametrized with
   the type implementing [`Chained`] from step 2.

4. The [`Protocol`](`crate::protocol::Protocol`)-implementing type for the new protocol will be
   [`ChainedProtocol`] parametrized with the type implementing [`Chained`] from the step 2.
*/

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::protocol::*;

/// A trait defining two protocols executed sequentially.
pub trait Chained<Id>: 'static
where
    Id: PartyId,
{
    /// The inputs of the new chained protocol.
    type Inputs: Send + Sync + Debug;

    /// The entry point of the first protocol.
    type EntryPoint1: EntryPoint<Id, Inputs: for<'a> From<&'a Self::Inputs>>;

    /// The entry point of the second protocol.
    type EntryPoint2: EntryPoint<
        Id,
        Inputs: From<(
            Self::Inputs,
            <<Self::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::Result,
        )>,
    >;
}

/// The protocol error type for the chained protocol.
#[derive_where::derive_where(Debug, Clone)]
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "
    <<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError: Serialize,
    <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError: Serialize,
"))]
#[serde(bound(deserialize = "
    <<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError: for<'x> Deserialize<'x>,
    <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError: for<'x> Deserialize<'x>,
"))]
pub enum ChainedProtocolError<Id: PartyId, C: Chained<Id>> {
    /// A protocol error from the first protocol.
    Protocol1(<<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError),
    /// A protocol error from the second protocol.
    Protocol2(<<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError),
}

impl<Id, C> ChainedProtocolError<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    fn from_protocol1(err: <<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError) -> Self {
        Self::Protocol1(err)
    }

    fn from_protocol2(err: <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::ProtocolError) -> Self {
        Self::Protocol2(err)
    }
}

impl<Id, C> ProtocolError for ChainedProtocolError<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    fn description(&self) -> String {
        match self {
            Self::Protocol1(err) => format!("Protocol1: {}", err.description()),
            Self::Protocol2(err) => format!("Protocol2: {}", err.description()),
        }
    }

    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        let (protocol_num, round_ids) = match self {
            Self::Protocol1(err) => (1, err.required_direct_messages()),
            Self::Protocol2(err) => (2, err.required_direct_messages()),
        };
        round_ids
            .into_iter()
            .map(|round_id| round_id.group_under(protocol_num))
            .collect()
    }

    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        let (protocol_num, round_ids) = match self {
            Self::Protocol1(err) => (1, err.required_echo_broadcasts()),
            Self::Protocol2(err) => (2, err.required_echo_broadcasts()),
        };
        round_ids
            .into_iter()
            .map(|round_id| round_id.group_under(protocol_num))
            .collect()
    }

    fn required_normal_broadcasts(&self) -> BTreeSet<RoundId> {
        let (protocol_num, round_ids) = match self {
            Self::Protocol1(err) => (1, err.required_normal_broadcasts()),
            Self::Protocol2(err) => (2, err.required_normal_broadcasts()),
        };
        round_ids
            .into_iter()
            .map(|round_id| round_id.group_under(protocol_num))
            .collect()
    }

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        let (protocol_num, round_ids) = match self {
            Self::Protocol1(err) => (1, err.required_combined_echos()),
            Self::Protocol2(err) => (2, err.required_combined_echos()),
        };
        round_ids
            .into_iter()
            .map(|round_id| round_id.group_under(protocol_num))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_messages_constitute_error(
        &self,
        deserializer: &Deserializer,
        echo_broadcast: &EchoBroadcast,
        normal_broadcast: &NormalBroadcast,
        direct_message: &DirectMessage,
        echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        direct_messages: &BTreeMap<RoundId, DirectMessage>,
        combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        // TODO: the cloning can be avoided if instead we provide a reference to some "transcript API",
        // and can replace it here with a proxy that will remove nesting from round ID's.
        let echo_broadcasts = echo_broadcasts
            .clone()
            .into_iter()
            .map(|(round_id, v)| round_id.ungroup().map(|round_id| (round_id, v)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let normal_broadcasts = normal_broadcasts
            .clone()
            .into_iter()
            .map(|(round_id, v)| round_id.ungroup().map(|round_id| (round_id, v)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let direct_messages = direct_messages
            .clone()
            .into_iter()
            .map(|(round_id, v)| round_id.ungroup().map(|round_id| (round_id, v)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let combined_echos = combined_echos
            .clone()
            .into_iter()
            .map(|(round_id, v)| round_id.ungroup().map(|round_id| (round_id, v)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        match self {
            Self::Protocol1(err) => err.verify_messages_constitute_error(
                deserializer,
                echo_broadcast,
                normal_broadcast,
                direct_message,
                &echo_broadcasts,
                &normal_broadcasts,
                &direct_messages,
                &combined_echos,
            ),
            Self::Protocol2(err) => err.verify_messages_constitute_error(
                deserializer,
                echo_broadcast,
                normal_broadcast,
                direct_message,
                &echo_broadcasts,
                &normal_broadcasts,
                &direct_messages,
                &combined_echos,
            ),
        }
    }
}

/// The correctness proof type for the chained protocol.
#[derive_where::derive_where(Debug, Clone)]
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "
    <<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof: Serialize,
    <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof: Serialize,
"))]
#[serde(bound(deserialize = "
    <<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof: for<'x> Deserialize<'x>,
    <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof: for<'x> Deserialize<'x>,
"))]
pub enum ChainedCorrectnessProof<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    /// A correctness proof from the first protocol.
    Protocol1(<<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof),
    /// A correctness proof from the second protocol.
    Protocol2(<<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof),
}

impl<Id, C> ChainedCorrectnessProof<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    fn from_protocol1(proof: <<C::EntryPoint1 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof) -> Self {
        Self::Protocol1(proof)
    }

    fn from_protocol2(proof: <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::CorrectnessProof) -> Self {
        Self::Protocol2(proof)
    }
}

impl<Id, C> CorrectnessProof for ChainedCorrectnessProof<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
}

/// The protocol resulting from chaining two sub-protocols as described by `C`.
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct ChainedProtocol<Id: PartyId, C: Chained<Id>>(PhantomData<fn((Id, C)) -> (Id, C)>);

impl<Id, C> Protocol for ChainedProtocol<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    type Result = <<C::EntryPoint2 as EntryPoint<Id>>::Protocol as Protocol>::Result;
    type ProtocolError = ChainedProtocolError<Id, C>;
    type CorrectnessProof = ChainedCorrectnessProof<Id, C>;
}

/// The entry point of the chained protocol.
#[derive_where::derive_where(Debug)]
pub struct ChainedEntryPoint<Id: PartyId, C: Chained<Id>> {
    state: ChainState<Id, C>,
}

#[derive_where::derive_where(Debug)]
enum ChainState<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    Protocol1 {
        round: BoxedRound<Id, <C::EntryPoint1 as EntryPoint<Id>>::Protocol>,
        shared_randomness: Box<[u8]>,
        id: Id,
        inputs: C::Inputs,
    },
    Protocol2(BoxedRound<Id, <C::EntryPoint2 as EntryPoint<Id>>::Protocol>),
}

impl<Id, C> EntryPoint<Id> for ChainedEntryPoint<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    type Inputs = C::Inputs;
    type Protocol = ChainedProtocol<Id, C>;

    fn entry_round() -> RoundId {
        <C::EntryPoint1 as EntryPoint<Id>>::entry_round().group_under(1)
    }

    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let round = C::EntryPoint1::new(rng, shared_randomness, id.clone(), (&inputs).into())?;
        let round = ChainedEntryPoint {
            state: ChainState::Protocol1 {
                shared_randomness: shared_randomness.into(),
                id,
                inputs,
                round,
            },
        };
        Ok(BoxedRound::new_object_safe(round))
    }
}

impl<Id, C> ObjectSafeRound<Id> for ChainedEntryPoint<Id, C>
where
    Id: PartyId,
    C: Chained<Id>,
{
    type Protocol = ChainedProtocol<Id, C>;

    fn id(&self) -> RoundId {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().id().group_under(1),
            ChainState::Protocol2(round) => round.as_ref().id().group_under(2),
        }
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => {
                let mut next_rounds = round
                    .as_ref()
                    .possible_next_rounds()
                    .into_iter()
                    .map(|round_id| round_id.group_under(1))
                    .collect::<BTreeSet<_>>();

                // If there are no next rounds, this is the result round.
                // This means that in the chain the next round will be the entry round of the second protocol.
                if next_rounds.is_empty() {
                    next_rounds.insert(C::EntryPoint2::entry_round().group_under(2));
                }
                next_rounds
            }
            ChainState::Protocol2(round) => round
                .as_ref()
                .possible_next_rounds()
                .into_iter()
                .map(|round_id| round_id.group_under(2))
                .collect(),
        }
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().message_destinations(),
            ChainState::Protocol2(round) => round.as_ref().message_destinations(),
        }
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => {
                round
                    .as_ref()
                    .make_direct_message(rng, serializer, deserializer, destination)
            }
            ChainState::Protocol2(round) => {
                round
                    .as_ref()
                    .make_direct_message(rng, serializer, deserializer, destination)
            }
        }
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
    ) -> Result<EchoBroadcast, LocalError> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().make_echo_broadcast(rng, serializer, deserializer),
            ChainState::Protocol2(round) => round.as_ref().make_echo_broadcast(rng, serializer, deserializer),
        }
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        serializer: &Serializer,
        deserializer: &Deserializer,
    ) -> Result<NormalBroadcast, LocalError> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().make_normal_broadcast(rng, serializer, deserializer),
            ChainState::Protocol2(round) => round.as_ref().make_normal_broadcast(rng, serializer, deserializer),
        }
    }

    fn receive_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => match round.as_ref().receive_message(
                rng,
                deserializer,
                from,
                echo_broadcast,
                normal_broadcast,
                direct_message,
            ) {
                Ok(payload) => Ok(payload),
                Err(err) => Err(err.map(ChainedProtocolError::from_protocol1)),
            },
            ChainState::Protocol2(round) => match round.as_ref().receive_message(
                rng,
                deserializer,
                from,
                echo_broadcast,
                normal_broadcast,
                direct_message,
            ) {
                Ok(payload) => Ok(payload),
                Err(err) => Err(err.map(ChainedProtocolError::from_protocol2)),
            },
        }
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>> {
        match self.state {
            ChainState::Protocol1 {
                round,
                id,
                inputs,
                shared_randomness,
            } => match round.into_boxed().finalize(rng, payloads, artifacts) {
                Ok(FinalizeOutcome::Result(result)) => {
                    let mut boxed_rng = BoxedRng(rng);
                    let round = C::EntryPoint2::new(&mut boxed_rng, &shared_randomness, id, (inputs, result).into())?;

                    Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_object_safe(
                        ChainedEntryPoint::<Id, C> {
                            state: ChainState::Protocol2(round),
                        },
                    )))
                }
                Ok(FinalizeOutcome::AnotherRound(round)) => Ok(FinalizeOutcome::AnotherRound(
                    BoxedRound::new_object_safe(ChainedEntryPoint::<Id, C> {
                        state: ChainState::Protocol1 {
                            shared_randomness,
                            id,
                            inputs,
                            round,
                        },
                    }),
                )),
                Err(FinalizeError::Local(err)) => Err(FinalizeError::Local(err)),
                Err(FinalizeError::Unattributable(proof)) => Err(FinalizeError::Unattributable(
                    ChainedCorrectnessProof::from_protocol1(proof),
                )),
            },
            ChainState::Protocol2(round) => match round.into_boxed().finalize(rng, payloads, artifacts) {
                Ok(FinalizeOutcome::Result(result)) => Ok(FinalizeOutcome::Result(result)),
                Ok(FinalizeOutcome::AnotherRound(round)) => Ok(FinalizeOutcome::AnotherRound(
                    BoxedRound::new_object_safe(ChainedEntryPoint::<Id, C> {
                        state: ChainState::Protocol2(round),
                    }),
                )),
                Err(FinalizeError::Local(err)) => Err(FinalizeError::Local(err)),
                Err(FinalizeError::Unattributable(proof)) => Err(FinalizeError::Unattributable(
                    ChainedCorrectnessProof::from_protocol2(proof),
                )),
            },
        }
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().expecting_messages_from(),
            ChainState::Protocol2(round) => round.as_ref().expecting_messages_from(),
        }
    }
}
