use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use manul::protocol::{
    BoxedFormat, BoxedRound, BoxedRoundInfo, CommunicationInfo, EchoBroadcast, EntryPoint, EvidenceMessages,
    FinalizeOutcome, LocalError, NoMessage, PartyId, Protocol, ProtocolError, ProtocolMessage, ProtocolMessagePart,
    ProtocolValidationError, ProvableError, ReceiveError, RequiredMessageParts, RequiredMessages, RoundId,
    StaticProtocolMessage, StaticRound, TransitionInfo,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug)]
pub struct SimpleProtocol;

#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
/// An example error.
pub enum SimpleProtocolError {
    /// Invalid position in Round 1.
    Round1InvalidPosition,
    /// Invalid position in Round 2.
    Round2InvalidPosition,
}

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Round1ProvableError;

impl<Id: PartyId> ProvableError<Id> for Round1ProvableError {
    type Round = Round1<Id>;
    fn required_previous_messages(&self) -> RequiredMessages {
        RequiredMessages::new(RequiredMessageParts::direct_message(), None, None)
    }
    fn verify_evidence(
        &self,
        _from: &Id,
        _shared_randomness: &[u8],
        _shared_data: &<<Self::Round as StaticRound<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<Id, Self::Round>,
    ) -> std::result::Result<(), ProtocolValidationError> {
        let _message: Round1Message = messages.direct_message()?;
        // Message contents would be checked here
        Ok(())
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Round2ProvableError;

impl<Id: PartyId> ProvableError<Id> for Round2ProvableError {
    type Round = Round2<Id>;
    fn required_previous_messages(&self) -> RequiredMessages {
        RequiredMessages::new(
            RequiredMessageParts::direct_message(),
            Some([(1.into(), RequiredMessageParts::direct_message())].into()),
            Some([1.into()].into()),
        )
    }
    fn verify_evidence(
        &self,
        _from: &Id,
        _shared_randomness: &[u8],
        _shared_data: &<<Self::Round as StaticRound<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<Id, Self::Round>,
    ) -> std::result::Result<(), ProtocolValidationError> {
        let _r2_message: Round2Message = messages.direct_message()?;
        let _r1_echos: BTreeMap<Id, Round1Echo> = messages.combined_echos::<Round1<Id>>(1)?;
        // Message contents would be checked here
        Ok(())
    }
}

impl<Id> ProtocolError<Id> for SimpleProtocolError {
    type AssociatedData = ();

    fn required_messages(&self) -> RequiredMessages {
        match self {
            Self::Round1InvalidPosition => RequiredMessages::new(RequiredMessageParts::direct_message(), None, None),
            Self::Round2InvalidPosition => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
                Some([(1.into(), RequiredMessageParts::direct_message())].into()),
                Some([1.into()].into()),
            ),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        format: &BoxedFormat,
        _guilty_party: &Id,
        _shared_randomness: &[u8],
        _associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        _previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        match self {
            SimpleProtocolError::Round1InvalidPosition => {
                let _message = message.direct_message.deserialize::<Round1Message>(format)?;
                // Message contents would be checked here
                Ok(())
            }
            SimpleProtocolError::Round2InvalidPosition => {
                let _r1_message = message.direct_message.deserialize::<Round1Message>(format)?;
                let r1_echos_serialized = combined_echos
                    .get(&1.into())
                    .ok_or_else(|| LocalError::new("Could not find combined echos for Round 1"))?;

                // Deserialize the echos
                let _r1_echos = r1_echos_serialized
                    .iter()
                    .map(|(_id, echo)| echo.deserialize::<Round1Echo>(format))
                    .collect::<Result<Vec<_>, _>>()?;

                // Message contents would be checked here
                Ok(())
            }
        }
    }
}

impl<Id: PartyId> Protocol<Id> for SimpleProtocol {
    type Result = u8;
    type SharedData = ();
    type ProtocolError = SimpleProtocolError;
    fn round_info(round_id: &RoundId) -> Option<BoxedRoundInfo<Id, Self>> {
        match round_id {
            _ if round_id == 1 => Some(BoxedRoundInfo::new::<Round1<Id>>()),
            _ if round_id == 2 => Some(BoxedRoundInfo::new::<Round2<Id>>()),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Context<Id> {
    pub(crate) id: Id,
    pub(crate) other_ids: BTreeSet<Id>,
    pub(crate) ids_to_positions: BTreeMap<Id, u8>,
}

#[derive(Debug)]
pub(crate) struct Round1<Id> {
    pub(crate) context: Context<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Round1Message {
    pub(crate) my_position: u8,
    pub(crate) your_position: u8,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Round1Echo {
    my_position: u8,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Round1Broadcast {
    x: u8,
    my_position: u8,
}

pub(crate) struct Round1Payload {
    x: u8,
}

#[derive(Debug, Clone)]
pub struct SimpleProtocolEntryPoint<Id> {
    all_ids: BTreeSet<Id>,
}

impl<Id: PartyId> SimpleProtocolEntryPoint<Id> {
    pub fn new(all_ids: BTreeSet<Id>) -> Self {
        Self { all_ids }
    }
}

impl<Id: PartyId> EntryPoint<Id> for SimpleProtocolEntryPoint<Id> {
    type Protocol = SimpleProtocol;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        _rng: &mut dyn CryptoRngCore,
        _shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        // Just some numbers associated with IDs to use in the dummy protocol.
        // They will be the same on each node since IDs are ordered.
        let ids_to_positions = self
            .all_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| (id.clone(), idx as u8))
            .collect::<BTreeMap<_, _>>();

        let mut ids = self.all_ids;
        ids.remove(id);

        Ok(BoxedRound::new_static(Round1 {
            context: Context {
                id: id.clone(),
                other_ids: ids,
                ids_to_positions,
            },
        }))
    }
}

impl<Id: PartyId> StaticRound<Id> for Round1<Id> {
    type Protocol = SimpleProtocol;
    type ProvableError = Round1ProvableError;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear(1)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    type NormalBroadcast = Round1Broadcast;
    type EchoBroadcast = Round1Echo;
    type DirectMessage = Round1Message;

    type Payload = Round1Payload;
    type Artifact = ();

    fn make_normal_broadcast(&self, _rng: &mut dyn CryptoRngCore) -> Result<Option<Self::NormalBroadcast>, LocalError> {
        debug!("{:?}: making normal broadcast", self.context.id);
        Ok(Some(Round1Broadcast {
            x: 0,
            my_position: self.context.ids_to_positions[&self.context.id],
        }))
    }

    fn make_echo_broadcast(&self, _rng: &mut dyn CryptoRngCore) -> Result<Option<Self::EchoBroadcast>, LocalError> {
        debug!("{:?}: making echo broadcast", self.context.id);
        Ok(Some(Round1Echo {
            my_position: self.context.ids_to_positions[&self.context.id],
        }))
    }

    fn make_direct_message(
        &self,
        _rng: &mut dyn CryptoRngCore,
        destination: &Id,
    ) -> Result<Option<(Self::DirectMessage, Self::Artifact)>, LocalError> {
        debug!("{:?}: making direct message for {:?}", self.context.id, destination);
        let message = Round1Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        Ok(Some((message, ())))
    }

    fn receive_message(
        &self,
        from: &Id,
        message: StaticProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);
        let message = message.direct_message;

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::protocol(SimpleProtocolError::Round1InvalidPosition));
        }
        Ok(Round1Payload { x: message.my_position })
    }

    fn finalize(
        self,
        _rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        debug!(
            "{:?}: finalizing with messages from {:?}",
            self.context.id,
            payloads.keys().cloned().collect::<Vec<_>>()
        );

        let sum =
            self.context.ids_to_positions[&self.context.id] + payloads.values().map(|payload| payload.x).sum::<u8>();

        let round2 = BoxedRound::new_static(Round2 {
            round1_sum: sum,
            context: self.context,
        });
        Ok(FinalizeOutcome::AnotherRound(round2))
    }
}

#[derive(Debug)]
pub(crate) struct Round2<Id> {
    round1_sum: u8,
    pub(crate) context: Context<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Round2Message {
    pub(crate) my_position: u8,
    pub(crate) your_position: u8,
}

impl<Id: PartyId> StaticRound<Id> for Round2<Id> {
    type Protocol = SimpleProtocol;
    type ProvableError = Round2ProvableError;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(2)
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        CommunicationInfo::regular(&self.context.other_ids)
    }

    type DirectMessage = Round2Message;
    type EchoBroadcast = NoMessage;
    type NormalBroadcast = NoMessage;

    type Payload = Round1Payload;
    type Artifact = ();

    fn make_direct_message(
        &self,
        _rng: &mut dyn CryptoRngCore,
        destination: &Id,
    ) -> Result<Option<(Self::DirectMessage, Self::Artifact)>, LocalError> {
        debug!("{:?}: making direct message for {:?}", self.context.id, destination);

        let message = Round2Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        Ok(Some((message, ())))
    }

    fn receive_message(
        &self,
        from: &Id,
        message: StaticProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        let message = message.direct_message;

        debug!("{:?}: received message: {:?}", self.context.id, message);

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::protocol(SimpleProtocolError::Round2InvalidPosition));
        }

        Ok(Round1Payload { x: message.my_position })
    }

    fn finalize(
        self,
        _rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        _artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        debug!(
            "{:?}: finalizing with messages from {:?}",
            self.context.id,
            payloads.keys().cloned().collect::<Vec<_>>()
        );

        let sum =
            self.context.ids_to_positions[&self.context.id] + payloads.values().map(|payload| payload.x).sum::<u8>();

        Ok(FinalizeOutcome::Result(sum + self.round1_sum))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner},
        signature::Keypair,
    };
    use rand_core::OsRng;
    use test_log::test;

    use super::SimpleProtocolEntryPoint;

    #[test]
    fn round() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| (signer, SimpleProtocolEntryPoint::new(all_ids.clone())))
            .collect::<Vec<_>>();

        let results = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        for (_id, result) in results {
            assert_eq!(result, 6); // (0 + 1 + 2) * 2
        }
    }
}
