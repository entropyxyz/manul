/*!
A combinator representing two protocols as a new protocol that, when executed,
executes the two inner protocols in sequence, feeding the result of the first protocol
into the inputs of the second protocol.

For the session level users (that is, the ones executing the protocols)
the new protocol is a single entity with its own [`Protocol`](`crate::protocol::Protocol`)-implementing type
and an [`EntryPoint`](`crate::protocol::EntryPoint`)-implementing type.

For example, imagine we have a `ProtocolA` with an entry point `EntryPointA`,
two rounds, `RA1` and `RA2`, and the result `ResultA`;
and similarly a `ProtocolB` with an entry point `EntryPointB`,
two rounds, `RB1` and `RB2`, and the result `ResultB`.

Then the chained protocol will have a `ProtocolC: Protocol` type and an `EntryPointC: EntryPoint` type,
and the execution will look like:
- `EntryPointC` is initialized by the user with whatever constructor it may have;
- Internally, `EntryPointA` is created from `EntryPointC` using the [`ChainedSplit`] implementation
  provided by the protocol author;
- `RA1` is executed;
- `RA2` is executed, producing `ResultA`;
- Internally, `EntryPointB` is created from `ResultA` and the data created in [`ChainedSplit::make_entry_point1`]
  using the [`ChainedJoin`] implementation provided by the protocol author;
- `RB1` is executed;
- `RB2` is executed, producing `ResultB` (which is also the result of `ProtocolC`).

If the execution happens in a [`Session`](`crate::session::Session`), and there is an error at any point,
a regular evidence or correctness proof are created using the corresponding types from the new `ProtocolC`.

Usage:

1. Implement [`ChainedProtocol`] for a type of your choice. Usually it will be a ZST.
   You will have to specify the two protocol types you want to chain.

2. Implement the marker trait [`ChainedMarker`] for this type. This will activate the blanket implementation
   of [`Protocol`](`crate::protocol::Protocol`) for it.
   The marker trait is needed to disambiguate different generic blanket implementations.

3. Define an entry point type for the new joined protocol.
   Most likely it will contain a union between the required data for the entry point
   of the first and the second protocol.

4. Implement [`ChainedSplit`] and [`ChainedJoin`] for the new entry point.

5. Implement the marker trait [`ChainedMarker`] for this type.
   Same as with the protocol, this is needed to disambiguate different generic blanket implementations.
*/

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::protocol::{
    Artifact, BoxedRng, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EchoRoundParticipation, EntryPoint,
    FinalizeOutcome, LocalError, NormalBroadcast, ObjectSafeRound, PartyId, Payload, Protocol, ProtocolError,
    ProtocolValidationError, ReceiveError, RoundId, Serializer,
};

/// A marker trait that is used to disambiguate blanket trait implementations for [`Protocol`] and [`EntryPoint`].
pub trait ChainedMarker {}

/// A trait defining two protocols executed sequentially.
pub trait ChainedProtocol<Id>: 'static + Debug {
    /// The protcol that is executed first.
    type Protocol1: Protocol<Id>;

    /// The protcol that is executed second.
    type Protocol2: Protocol<Id>;
}

/// The protocol error type for the chained protocol.
#[derive_where::derive_where(Debug, Clone)]
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "
    <C::Protocol1 as Protocol<Id>>::ProtocolError: Serialize,
    <C::Protocol2 as Protocol<Id>>::ProtocolError: Serialize,
"))]
#[serde(bound(deserialize = "
    <C::Protocol1 as Protocol<Id>>::ProtocolError: for<'x> Deserialize<'x>,
    <C::Protocol2 as Protocol<Id>>::ProtocolError: for<'x> Deserialize<'x>,
"))]
pub enum ChainedProtocolError<Id, C>
where
    C: ChainedProtocol<Id>,
{
    /// A protocol error from the first protocol.
    Protocol1(<C::Protocol1 as Protocol<Id>>::ProtocolError),
    /// A protocol error from the second protocol.
    Protocol2(<C::Protocol2 as Protocol<Id>>::ProtocolError),
}

impl<Id, C> ChainedProtocolError<Id, C>
where
    C: ChainedProtocol<Id>,
{
    fn from_protocol1(err: <C::Protocol1 as Protocol<Id>>::ProtocolError) -> Self {
        Self::Protocol1(err)
    }

    fn from_protocol2(err: <C::Protocol2 as Protocol<Id>>::ProtocolError) -> Self {
        Self::Protocol2(err)
    }
}

impl<Id, C> ProtocolError<Id> for ChainedProtocolError<Id, C>
where
    C: ChainedProtocol<Id>,
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
        guilty_party: &Id,
        shared_randomness: &[u8],
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
                guilty_party,
                shared_randomness,
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
                guilty_party,
                shared_randomness,
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

impl<Id, C> Protocol<Id> for C
where
    Id: 'static,
    C: ChainedProtocol<Id> + ChainedMarker,
{
    type Result = <C::Protocol2 as Protocol<Id>>::Result;
    type ProtocolError = ChainedProtocolError<Id, C>;
}

/// A trait defining how the entry point for the whole chained protocol
/// will be split into the entry point for the first protocol, and a piece of data
/// that, along with the first protocol's result, will be used to create the entry point for the second protocol.
pub trait ChainedSplit<Id: PartyId> {
    /// The chained protocol this trait belongs to.
    type Protocol: ChainedProtocol<Id> + ChainedMarker;

    /// The first protocol's entry point.
    type EntryPoint: EntryPoint<Id, Protocol = <Self::Protocol as ChainedProtocol<Id>>::Protocol1>;

    /// Creates the first protocol's entry point and the data for creating the second entry point.
    fn make_entry_point1(self) -> (Self::EntryPoint, impl ChainedJoin<Id, Protocol = Self::Protocol>);
}

/// A trait defining how the data created in [`ChainedSplit::make_entry_point1`]
/// will be joined with the result of the first protocol to create an entry point for the second protocol.
pub trait ChainedJoin<Id: PartyId>: 'static + Debug + Send + Sync {
    /// The chained protocol this trait belongs to.
    type Protocol: ChainedProtocol<Id> + ChainedMarker;

    /// The second protocol's entry point.
    type EntryPoint: EntryPoint<Id, Protocol = <Self::Protocol as ChainedProtocol<Id>>::Protocol2>;

    /// Creates the second protocol's entry point using the first protocol's result.
    fn make_entry_point2(
        self,
        result: <<Self::Protocol as ChainedProtocol<Id>>::Protocol1 as Protocol<Id>>::Result,
    ) -> Self::EntryPoint;
}

impl<Id, T> EntryPoint<Id> for T
where
    Id: PartyId,
    T: ChainedSplit<Id> + ChainedMarker,
{
    type Protocol = T::Protocol;

    fn entry_round() -> RoundId {
        <T as ChainedSplit<Id>>::EntryPoint::entry_round().group_under(1)
    }

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let (entry_point, transition) = self.make_entry_point1();
        let round = entry_point.make_round(rng, shared_randomness, id)?;
        let chained_round = ChainedRound {
            state: ChainState::Protocol1 {
                id: id.clone(),
                shared_randomness: shared_randomness.into(),
                transition,
                round,
            },
        };
        Ok(BoxedRound::new_object_safe(chained_round))
    }
}

#[derive(Debug)]
struct ChainedRound<Id, T>
where
    Id: PartyId,
    T: ChainedJoin<Id>,
{
    state: ChainState<Id, T>,
}

#[derive_where::derive_where(Debug)]
enum ChainState<Id, T>
where
    Id: PartyId,
    T: ChainedJoin<Id>,
{
    Protocol1 {
        id: Id,
        round: BoxedRound<Id, <T::Protocol as ChainedProtocol<Id>>::Protocol1>,
        shared_randomness: Box<[u8]>,
        transition: T,
    },
    Protocol2(BoxedRound<Id, <T::Protocol as ChainedProtocol<Id>>::Protocol2>),
}

impl<Id, T> ObjectSafeRound<Id> for ChainedRound<Id, T>
where
    Id: PartyId,
    T: ChainedJoin<Id>,
{
    type Protocol = T::Protocol;

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

                if round.as_ref().may_produce_result() {
                    tracing::debug!("Adding {}", T::EntryPoint::entry_round().group_under(2));
                    next_rounds.insert(T::EntryPoint::entry_round().group_under(2));
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

    fn may_produce_result(&self) -> bool {
        match &self.state {
            ChainState::Protocol1 { .. } => false,
            ChainState::Protocol2(round) => round.as_ref().may_produce_result(),
        }
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().message_destinations(),
            ChainState::Protocol2(round) => round.as_ref().message_destinations(),
        }
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().expecting_messages_from(),
            ChainState::Protocol2(round) => round.as_ref().expecting_messages_from(),
        }
    }

    fn echo_round_participation(&self) -> EchoRoundParticipation<Id> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().echo_round_participation(),
            ChainState::Protocol2(round) => round.as_ref().echo_round_participation(),
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
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        match self.state {
            ChainState::Protocol1 {
                id,
                round,
                transition,
                shared_randomness,
            } => match round.into_boxed().finalize(rng, payloads, artifacts)? {
                FinalizeOutcome::Result(result) => {
                    let mut boxed_rng = BoxedRng(rng);
                    let entry_point2 = transition.make_entry_point2(result);
                    let round = entry_point2.make_round(&mut boxed_rng, &shared_randomness, &id)?;

                    Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_object_safe(
                        ChainedRound::<Id, T> {
                            state: ChainState::Protocol2(round),
                        },
                    )))
                }
                FinalizeOutcome::AnotherRound(round) => Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_object_safe(
                    ChainedRound::<Id, T> {
                        state: ChainState::Protocol1 {
                            id,
                            shared_randomness,
                            round,
                            transition,
                        },
                    },
                ))),
            },
            ChainState::Protocol2(round) => match round.into_boxed().finalize(rng, payloads, artifacts)? {
                FinalizeOutcome::Result(result) => Ok(FinalizeOutcome::Result(result)),
                FinalizeOutcome::AnotherRound(round) => Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_object_safe(
                    ChainedRound::<Id, T> {
                        state: ChainState::Protocol2(round),
                    },
                ))),
            },
        }
    }
}
