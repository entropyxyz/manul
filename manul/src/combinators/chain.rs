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

6. [`ChainedAssociatedData`] is the structure used to supply associated data
   when verifying evidence from the chained protocol.
*/

use alloc::{boxed::Box, collections::BTreeMap, format};
use core::fmt::{self, Debug};

use rand_core::CryptoRngCore;

use crate::protocol::{
    Artifact, BoxedFormat, BoxedRound, BoxedRoundInfo, CommunicationInfo, DirectMessage, EchoBroadcast, EntryPoint,
    FinalizeOutcome, LocalError, MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError,
    ProtocolMessage, ProtocolValidationError, ReceiveError, RequiredMessages, Round, RoundId, RoundInfo,
    TransitionInfo,
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
#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub enum ChainedProtocolError<Id, C>
where
    C: ChainedProtocol<Id>,
{
    /// A protocol error from the first protocol.
    Protocol1(<C::Protocol1 as Protocol<Id>>::ProtocolError),
    /// A protocol error from the second protocol.
    Protocol2(<C::Protocol2 as Protocol<Id>>::ProtocolError),
}

impl<Id, C> fmt::Display for ChainedProtocolError<Id, C>
where
    C: ChainedProtocol<Id>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Protocol1(err) => write!(f, "Protocol 1: {err}"),
            Self::Protocol2(err) => write!(f, "Protocol 2: {err}"),
        }
    }
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

/// Associated data for verification of malicious behavior evidence in the chained protocol.
#[derive_where::derive_where(Debug)]
pub struct ChainedAssociatedData<Id, C>
where
    C: ChainedProtocol<Id>,
{
    /// Associated data for the errors in the first protocol.
    pub protocol1: <<C::Protocol1 as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    /// Associated data for the errors in the second protocol.
    pub protocol2: <<C::Protocol2 as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
}

impl<Id, C> ProtocolError<Id> for ChainedProtocolError<Id, C>
where
    C: ChainedProtocol<Id>,
{
    type AssociatedData = ChainedAssociatedData<Id, C>;

    fn required_messages(&self) -> RequiredMessages {
        let (protocol_num, required_messages) = match self {
            Self::Protocol1(err) => (1, err.required_messages()),
            Self::Protocol2(err) => (2, err.required_messages()),
        };

        let previous_rounds = required_messages.previous_rounds.map(|previous_rounds| {
            previous_rounds
                .into_iter()
                .map(|(round_id, required)| (round_id.group_under(protocol_num), required))
                .collect()
        });

        let combined_echos = required_messages.combined_echos.map(|combined_echos| {
            combined_echos
                .into_iter()
                .map(|round_id| round_id.group_under(protocol_num))
                .collect()
        });

        RequiredMessages {
            this_round: required_messages.this_round,
            previous_rounds,
            combined_echos,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_messages_constitute_error(
        &self,
        format: &BoxedFormat,
        guilty_party: &Id,
        shared_randomness: &[u8],
        associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        let previous_messages = previous_messages
            .into_iter()
            .map(|(round_id, message)| round_id.split_group().map(|(_group_num, round_id)| (round_id, message)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let combined_echos = combined_echos
            .into_iter()
            .map(|(round_id, message)| round_id.split_group().map(|(_group_num, round_id)| (round_id, message)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        match self {
            Self::Protocol1(err) => err.verify_messages_constitute_error(
                format,
                guilty_party,
                shared_randomness,
                &associated_data.protocol1,
                message,
                previous_messages,
                combined_echos,
            ),
            Self::Protocol2(err) => err.verify_messages_constitute_error(
                format,
                guilty_party,
                shared_randomness,
                &associated_data.protocol2,
                message,
                previous_messages,
                combined_echos,
            ),
        }
    }
}

#[derive_where::derive_where(Debug)]
struct RoundInfoWrapper1<Id: 'static, P: ChainedProtocol<Id> + ChainedMarker>(BoxedRoundInfo<Id, P::Protocol1>);

impl<Id, P> RoundInfo<Id> for RoundInfoWrapper1<Id, P>
where
    P: ChainedProtocol<Id> + ChainedMarker,
{
    type Protocol = P;

    fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        let (group, round_id) = round_id.split_group()?;
        if group != 1 {
            return Err(MessageValidationError::Local(LocalError::new(format!(
                "Expected round ID from group 1, got {round_id}"
            ))));
        }
        self.0
            .as_ref()
            .verify_direct_message_is_invalid(&round_id, format, message, &associated_data.protocol1)
    }

    fn verify_echo_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &EchoBroadcast,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        let (group, round_id) = round_id.split_group()?;
        if group != 1 {
            return Err(MessageValidationError::Local(LocalError::new(format!(
                "Expected round ID from group 1, got {round_id}"
            ))));
        }
        self.0
            .as_ref()
            .verify_echo_broadcast_is_invalid(&round_id, format, message, &associated_data.protocol1)
    }

    fn verify_normal_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &NormalBroadcast,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        let (group, round_id) = round_id.split_group()?;
        if group != 1 {
            return Err(MessageValidationError::Local(LocalError::new(format!(
                "Expected round ID from group 1, got {round_id}"
            ))));
        }
        self.0
            .as_ref()
            .verify_normal_broadcast_is_invalid(&round_id, format, message, &associated_data.protocol1)
    }
}

#[derive_where::derive_where(Debug)]
struct RoundInfoWrapper2<Id: 'static, P: ChainedProtocol<Id> + ChainedMarker>(BoxedRoundInfo<Id, P::Protocol2>);

impl<Id, P> RoundInfo<Id> for RoundInfoWrapper2<Id, P>
where
    P: ChainedProtocol<Id> + ChainedMarker,
{
    type Protocol = P;

    fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        let (group, round_id) = round_id.split_group()?;
        if group != 2 {
            return Err(MessageValidationError::Local(LocalError::new(format!(
                "Expected round ID from group 2, got {round_id}"
            ))));
        }
        self.0
            .as_ref()
            .verify_direct_message_is_invalid(&round_id, format, message, &associated_data.protocol2)
    }

    fn verify_echo_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &EchoBroadcast,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        let (group, round_id) = round_id.split_group()?;
        if group != 2 {
            return Err(MessageValidationError::Local(LocalError::new(format!(
                "Expected round ID from group 2, got {round_id}"
            ))));
        }
        self.0
            .as_ref()
            .verify_echo_broadcast_is_invalid(&round_id, format, message, &associated_data.protocol2)
    }

    fn verify_normal_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &NormalBroadcast,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        let (group, round_id) = round_id.split_group()?;
        if group != 2 {
            return Err(MessageValidationError::Local(LocalError::new(format!(
                "Expected round ID from group 2, got {round_id}"
            ))));
        }
        self.0
            .as_ref()
            .verify_normal_broadcast_is_invalid(&round_id, format, message, &associated_data.protocol2)
    }
}

impl<Id, C> Protocol<Id> for C
where
    Id: 'static,
    C: ChainedProtocol<Id> + ChainedMarker,
{
    type Result = <C::Protocol2 as Protocol<Id>>::Result;
    type ProtocolError = ChainedProtocolError<Id, C>;

    fn round_info(round_id: &RoundId) -> Option<BoxedRoundInfo<Id, Self>> {
        let (group, round_id) = round_id.split_group().ok()?;
        if group == 1 {
            let round_info = C::Protocol1::round_info(&round_id)?;
            Some(BoxedRoundInfo::new_obj(Box::new(RoundInfoWrapper1(round_info))))
        } else if group == 2 {
            let round_info = C::Protocol2::round_info(&round_id)?;
            Some(BoxedRoundInfo::new_obj(Box::new(RoundInfoWrapper2(round_info))))
        } else {
            None
        }
    }
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

    fn entry_round_id() -> RoundId {
        <T as ChainedSplit<Id>>::EntryPoint::entry_round_id().group_under(1)
    }

    fn make_round(
        self,
        rng: &mut dyn CryptoRngCore,
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
        Ok(BoxedRound::new_dynamic(chained_round))
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

impl<Id, T> Round<Id> for ChainedRound<Id, T>
where
    Id: PartyId,
    T: ChainedJoin<Id>,
{
    type Protocol = T::Protocol;

    fn transition_info(&self) -> TransitionInfo {
        match &self.state {
            ChainState::Protocol1 { round, .. } => {
                let mut tinfo = round.as_ref().transition_info().group_under(1);
                if tinfo.may_produce_result {
                    tinfo.may_produce_result = false;
                    tinfo.children.insert(T::EntryPoint::entry_round_id().group_under(2));
                }
                tinfo
            }
            ChainState::Protocol2(round) => round.as_ref().transition_info().group_under(2),
        }
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().communication_info(),
            ChainState::Protocol2(round) => round.as_ref().communication_info(),
        }
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().make_direct_message(rng, format, destination),
            ChainState::Protocol2(round) => round.as_ref().make_direct_message(rng, format, destination),
        }
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().make_echo_broadcast(rng, format),
            ChainState::Protocol2(round) => round.as_ref().make_echo_broadcast(rng, format),
        }
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => round.as_ref().make_normal_broadcast(rng, format),
            ChainState::Protocol2(round) => round.as_ref().make_normal_broadcast(rng, format),
        }
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        match &self.state {
            ChainState::Protocol1 { round, .. } => match round.as_ref().receive_message(format, from, message) {
                Ok(payload) => Ok(payload),
                Err(err) => Err(err.map(ChainedProtocolError::from_protocol1)),
            },
            ChainState::Protocol2(round) => match round.as_ref().receive_message(format, from, message) {
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
                    let entry_point2 = transition.make_entry_point2(result);
                    let round = entry_point2.make_round(rng, &shared_randomness, &id)?;
                    let chained_round = ChainedRound::<Id, T> {
                        state: ChainState::Protocol2(round),
                    };
                    Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(chained_round)))
                }
                FinalizeOutcome::AnotherRound(round) => {
                    let chained_round = ChainedRound::<Id, T> {
                        state: ChainState::Protocol1 {
                            id,
                            shared_randomness,
                            round,
                            transition,
                        },
                    };
                    Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(chained_round)))
                }
            },
            ChainState::Protocol2(round) => match round.into_boxed().finalize(rng, payloads, artifacts)? {
                FinalizeOutcome::Result(result) => Ok(FinalizeOutcome::Result(result)),
                FinalizeOutcome::AnotherRound(round) => {
                    let chained_round = ChainedRound::<Id, T> {
                        state: ChainState::Protocol2(round),
                    };
                    Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(chained_round)))
                }
            },
        }
    }
}
