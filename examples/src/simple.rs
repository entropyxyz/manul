use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use manul::{protocol::*, session::Format};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::format::Binary;

#[derive(Debug)]
pub struct SimpleProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimpleProtocolError {
    Round1InvalidPosition,
    Round2InvalidPosition,
}

impl ProtocolError for SimpleProtocolError {
    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        match self {
            Self::Round1InvalidPosition => BTreeSet::new(),
            Self::Round2InvalidPosition => [RoundId::new(1)].into(),
        }
    }

    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn required_normal_broadcasts(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        match self {
            Self::Round1InvalidPosition => BTreeSet::new(),
            Self::Round2InvalidPosition => [RoundId::new(1)].into(),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        deserializer: &Deserializer,
        _echo_broadcast: &EchoBroadcast,
        _normal_broadcast: &NormalBroadcast,
        direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        match self {
            SimpleProtocolError::Round1InvalidPosition => {
                let _message = direct_message.deserialize::<Round1Message>(deserializer)?;
                // Message contents would be checked here
                Ok(())
            }
            SimpleProtocolError::Round2InvalidPosition => {
                let _r1_message = direct_message.deserialize::<Round1Message>(deserializer)?;
                let r1_echos_serialized = combined_echos
                    .get(&RoundId::new(1))
                    .ok_or_else(|| LocalError::new("Could not find combined echos for Round 1"))?;

                // Deserialize the echos
                let _r1_echos = r1_echos_serialized
                    .iter()
                    .map(|echo| echo.deserialize::<Round1Echo>(deserializer))
                    .collect::<Result<Vec<_>, _>>()?;

                // Message contents would be checked here
                Ok(())
            }
        }
    }
}

impl Protocol for SimpleProtocol {
    type Result = u8;
    type ProtocolError = SimpleProtocolError;
    type CorrectnessProof = ();

    fn verify_direct_message_is_invalid(
        deserializer: &Deserializer,
        round_id: RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == RoundId::new(1) => message.verify_is_not::<Round1Message>(deserializer),
            r if r == RoundId::new(2) => message.verify_is_not::<Round2Message>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }

    fn verify_echo_broadcast_is_invalid(
        deserializer: &Deserializer,
        round_id: RoundId,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == RoundId::new(1) => message.verify_is_some(),
            r if r == RoundId::new(2) => message.verify_is_not::<Round2Message>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Inputs<Id> {
    pub all_ids: BTreeSet<Id>,
}

#[derive(Debug)]
pub(crate) struct Context<Id> {
    pub(crate) id: Id,
    pub(crate) other_ids: BTreeSet<Id>,
    pub(crate) ids_to_positions: BTreeMap<Id, u8>,
}

#[derive(Debug)]
pub struct Round1<Id> {
    pub(crate) context: Context<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Round1Message {
    pub(crate) my_position: u8,
    pub(crate) your_position: u8,
}

#[derive(Serialize, Deserialize)]
struct Round1Echo {
    my_position: u8,
}

#[derive(Serialize, Deserialize)]
struct Round1Broadcast {
    x: u8,
    my_position: u8,
}

struct Round1Payload {
    x: u8,
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> FirstRound<Id> for Round1<Id> {
    type Inputs = Inputs<Id>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<Self, LocalError> {
        // Just some numbers associated with IDs to use in the dummy protocol.
        // They will be the same on each node since IDs are ordered.
        let ids_to_positions = inputs
            .all_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| (id.clone(), idx as u8))
            .collect::<BTreeMap<_, _>>();

        let mut ids = inputs.all_ids;
        ids.remove(&id);

        Ok(Self {
            context: Context {
                id,
                other_ids: ids,
                ids_to_positions,
            },
        })
    }
}

impl<Id> Round<Id> for Round1<Id>
where
    Id: 'static + Debug + Clone + Ord + Send + Sync,
{
    type Protocol = SimpleProtocol;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [RoundId::new(2)].into()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_normal_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<NormalBroadcast, LocalError> {
        debug!("{:?}: making normal broadcast", self.context.id);

        let message = Round1Broadcast {
            x: 0,
            my_position: self.context.ids_to_positions[&self.context.id],
        };
        Binary::serialize(message).map(NormalBroadcast::from_bytes)
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<EchoBroadcast, LocalError> {
        debug!("{:?}: making echo broadcast", self.context.id);

        let message = Round1Echo {
            my_position: self.context.ids_to_positions[&self.context.id],
        };
        Binary::serialize(message).map(EchoBroadcast::from_bytes)
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<DirectMessage, LocalError> {
        debug!("{:?}: making direct message for {:?}", self.context.id, destination);

        let message = Round1Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        Binary::serialize(message).map(DirectMessage::from_bytes)
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        let _echo = echo_broadcast.deserialize::<Round1Echo>(deserializer)?;
        let _normal = normal_broadcast.deserialize::<Round1Broadcast>(deserializer)?;
        let message = direct_message.deserialize::<Round1Message>(deserializer)?;

        debug!("{:?}: received message: {:?}", self.context.id, message);

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::protocol(SimpleProtocolError::Round1InvalidPosition));
        }

        Ok(Payload::new(Round1Payload { x: message.my_position }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>> {
        debug!(
            "{:?}: finalizing with messages from {:?}",
            self.context.id,
            payloads.keys().cloned().collect::<Vec<_>>()
        );

        let typed_payloads = payloads
            .into_values()
            .map(|payload| payload.try_to_typed::<Round1Payload>())
            .collect::<Result<Vec<_>, _>>()?;
        let sum = self.context.ids_to_positions[&self.context.id]
            + typed_payloads.iter().map(|payload| payload.x).sum::<u8>();

        let round2 = Round2 {
            round1_sum: sum,
            context: self.context,
        };
        Ok(FinalizeOutcome::another_round(round2))
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
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

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> Round<Id> for Round2<Id> {
    type Protocol = SimpleProtocol;

    fn id(&self) -> RoundId {
        RoundId::new(2)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<DirectMessage, LocalError> {
        debug!("{:?}: making direct message for {:?}", self.context.id, destination);

        let message = Round2Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        Binary::serialize(message).map(DirectMessage::from_bytes)
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &Id,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        echo_broadcast.assert_is_none()?;
        normal_broadcast.assert_is_none()?;

        let message = direct_message.deserialize::<Round1Message>(deserializer)?;

        debug!("{:?}: received message: {:?}", self.context.id, message);

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::protocol(SimpleProtocolError::Round2InvalidPosition));
        }

        Ok(Payload::new(Round1Payload { x: message.my_position }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>> {
        debug!(
            "{:?}: finalizing with messages from {:?}",
            self.context.id,
            payloads.keys().cloned().collect::<Vec<_>>()
        );

        let typed_payloads = payloads
            .into_values()
            .map(|payload| payload.try_to_typed::<Round1Payload>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(FinalizeError::Local)?;
        let sum = self.context.ids_to_positions[&self.context.id]
            + typed_payloads.iter().map(|payload| payload.x).sum::<u8>();

        if sum != self.round1_sum {
            return Err(FinalizeError::Unattributable(()));
        }

        Ok(FinalizeOutcome::Result(sum))
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        session::{signature::Keypair, SessionOutcome},
        testing::{run_sync, TestSessionParams, TestSigner, TestVerifier},
    };
    use rand_core::OsRng;
    use tracing_subscriber::EnvFilter;

    use super::{Inputs, Round1};
    use crate::Binary;

    #[test]
    fn round() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let inputs = signers
            .into_iter()
            .map(|signer| {
                (
                    signer,
                    Inputs {
                        all_ids: all_ids.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();

        let my_subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        let reports = tracing::subscriber::with_default(my_subscriber, || {
            run_sync::<Round1<TestVerifier>, TestSessionParams<Binary>>(&mut OsRng, inputs).unwrap()
        });

        for (_id, report) in reports {
            if let SessionOutcome::Result(result) = report.outcome {
                assert_eq!(result, 3); // 0 + 1 + 2
            } else {
                panic!("Session did not finish successfully");
            }
        }
    }
}
