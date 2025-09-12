//! The simple.rs protocol is a basic example demonstrating the manul framework. It's a two-round protocol:
//!
//!  1. Commit: Each participant generates a random 32-byte value and broadcasts its SHA256 hash.
//!  2. Reveal: Each participant broadcasts their original random value.
//!
//! Finally, every participant verifies that the revealed values match the commitments from the first round.
//! If all checks pass, the protocol succeeds and outputs the collected random values.
//!
//! This example showcases a commit-reveal scheme, a fundamental cryptographic pattern.

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use manul::{
    protocol::{
        BoxedRound, CommunicationInfo, EntryPoint, EvidenceError, EvidenceMessages, FinalizeOutcome, LocalError,
        NoMessage, PartyId, Protocol, ProtocolError, ProtocolMessage, ReceiveError, RequiredMessageParts,
        RequiredMessages, Round, RoundId, RoundInfo, TransitionInfo,
    },
    utils::Without,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug)]
pub struct SimpleProtocol;

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Round1ProtocolError;

impl<Id: PartyId> ProtocolError<Id> for Round1ProtocolError {
    type Round = Round1<Id>;
    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        RequiredMessages::new(RequiredMessageParts::direct_message(), None, None)
    }
    fn verify_evidence(
        &self,
        _round_id: &RoundId,
        _from: &Id,
        _shared_randomness: &[u8],
        _shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<Id, Self::Round>,
    ) -> Result<(), EvidenceError> {
        let _message: Round1Message = messages.direct_message()?;
        // This method should check that the message content is indeed erroneous in some way,
        // according to the protocol rules. To do this, the method has access to the public shared
        // data and the list of required messages sent by `_from` as returned by `required_messages()`.
        //
        // If the message does contain errors and constitutes valid evidence of some sort of misbehaviour
        // (malicious or not), return `()`, otherwise the evidence is invalid, and the return value is a
        //  variant of `EvidenceError`.
        Ok(())
    }
    fn description(&self) -> String {
        "Invalid position".into()
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Round2ProtocolError;

impl<Id: PartyId> ProtocolError<Id> for Round2ProtocolError {
    type Round = Round2<Id>;
    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        RequiredMessages::new(
            RequiredMessageParts::direct_message(),
            Some([(1.into(), RequiredMessageParts::direct_message())].into()),
            Some([1.into()].into()),
        )
    }
    fn verify_evidence(
        &self,
        _round_id: &RoundId,
        _from: &Id,
        _shared_randomness: &[u8],
        _shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<Id, Self::Round>,
    ) -> Result<(), EvidenceError> {
        let _r2_message: Round2Message = messages.direct_message()?;
        let _r1_echos: BTreeMap<Id, Round1Echo> = messages.combined_echos::<Round1<Id>>(1)?;
        // Test the message contents here. See the comment in `verify_evidence()` above.
        Ok(())
    }
    fn description(&self) -> String {
        "Invalid position".into()
    }
}

impl<Id: PartyId> Protocol<Id> for SimpleProtocol {
    type Result = u8;
    type SharedData = ();
    fn round_info(round_id: &RoundId) -> Option<RoundInfo<Id, Self>> {
        match round_id {
            _ if round_id == 1 => Some(RoundInfo::new::<Round1<Id>>()),
            _ if round_id == 2 => Some(RoundInfo::new::<Round2<Id>>()),
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
        _rng: &mut impl CryptoRngCore,
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

        Ok(BoxedRound::new(Round1 {
            context: Context {
                id: id.clone(),
                other_ids: self.all_ids.clone().without(id),
                ids_to_positions,
            },
        }))
    }
}

impl<Id: PartyId> Round<Id> for Round1<Id> {
    type Protocol = SimpleProtocol;
    type ProtocolError = Round1ProtocolError;

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

    fn make_normal_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::NormalBroadcast, LocalError> {
        debug!("{:?}: making normal broadcast", self.context.id);
        Ok(Round1Broadcast {
            x: 0,
            my_position: self.context.ids_to_positions[&self.context.id],
        })
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::EchoBroadcast, LocalError> {
        debug!("{:?}: making echo broadcast", self.context.id);
        Ok(Round1Echo {
            my_position: self.context.ids_to_positions[&self.context.id],
        })
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(Self::DirectMessage, Self::Artifact), LocalError> {
        debug!("{:?}: making direct message for {:?}", self.context.id, destination);
        let message = Round1Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        Ok((message, ()))
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);
        let message = message.direct_message;

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::Protocol(Round1ProtocolError));
        }
        Ok(Round1Payload { x: message.my_position })
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
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

        let round2 = BoxedRound::new(Round2 {
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

impl<Id: PartyId> Round<Id> for Round2<Id> {
    type Protocol = SimpleProtocol;
    type ProtocolError = Round2ProtocolError;

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
        _rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(Self::DirectMessage, Self::Artifact), LocalError> {
        debug!("{:?}: making direct message for {:?}", self.context.id, destination);

        let message = Round2Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        Ok((message, ()))
    }

    fn receive_message(
        &self,
        from: &Id,
        message: ProtocolMessage<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        let message = message.direct_message;

        debug!("{:?}: received message: {:?}", self.context.id, message);

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::Protocol(Round2ProtocolError));
        }

        Ok(Round1Payload { x: message.my_position })
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
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
