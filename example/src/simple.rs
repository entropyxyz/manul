use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use manul::*;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use tracing::debug;

#[derive(Debug)]
pub struct SimpleProtocol;

#[derive(Debug, Clone)]
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

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        match self {
            Self::Round1InvalidPosition => BTreeSet::new(),
            Self::Round2InvalidPosition => [RoundId::new(1)].into(),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        _echo_broadcast: &Option<EchoBroadcast>,
        direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        // TODO: how can we make it easier for the user to write these?
        match self {
            SimpleProtocolError::Round1InvalidPosition => {
                let _message = direct_message.try_deserialize::<SimpleProtocol, Round1Message>()?;
                // Message contents would be checked here
                Ok(())
            }
            SimpleProtocolError::Round2InvalidPosition => {
                let _r1_message =
                    direct_message.try_deserialize::<SimpleProtocol, Round1Message>()?;
                let r1_echos_serialized = combined_echos
                    .get(&RoundId::new(1))
                    .ok_or_else(|| LocalError::new("Could not find combined echos for Round 1"))?;

                // Deserialize the echos
                let _r1_echos = r1_echos_serialized
                    .iter()
                    .map(|echo| echo.try_deserialize::<SimpleProtocol, Round1Echo>())
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

    type Digest = Sha3_256;

    fn serialize<T: Serialize>(value: &T) -> Result<Box<[u8]>, LocalError> {
        bincode::serde::encode_to_vec(value, bincode::config::standard())
            .map(|vec| vec.into())
            .map_err(|err| LocalError::new(err.to_string()))
    }

    fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, DeserializationError> {
        bincode::serde::decode_borrowed_from_slice(bytes, bincode::config::standard())
            .map_err(|err| DeserializationError::new(err.to_string()))
    }

    fn verify_direct_message_is_invalid(
        round_id: RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        // TODO: how can we make it easier for the user to write these?
        if round_id == RoundId::new(1) {
            return message.verify_is_invalid::<Self, Round1Message>();
        }
        Err(MessageValidationError::Other("Invalid round number".into()))?
    }
}

#[derive(Debug, Clone)]
pub struct Inputs<Id> {
    pub all_ids: BTreeSet<Id>,
}

pub(crate) struct Context<Id> {
    pub(crate) id: Id,
    pub(crate) other_ids: BTreeSet<Id>,
    pub(crate) ids_to_positions: BTreeMap<Id, u8>,
}

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

struct Round1Payload {
    x: u8,
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> FirstRound<Id> for Round1<Id> {
    type Inputs = Inputs<Id>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        _session_id: &SessionId,
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

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> Round<Id> for Round1<Id> {
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

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Result<EchoBroadcast, LocalError>> {
        debug!("{:?}: making echo broadcast", self.context.id);

        let message = Round1Echo {
            my_position: self.context.ids_to_positions[&self.context.id],
        };

        Some(EchoBroadcast::new::<SimpleProtocol, _>(&message))
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        debug!(
            "{:?}: making direct message for {:?}",
            self.context.id, destination
        );

        let message = Round1Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        let dm = DirectMessage::new::<SimpleProtocol, _>(&message)?;
        let artifact = Artifact::empty();
        Ok((dm, artifact))
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &Id,
        _echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        let message = direct_message.try_deserialize::<SimpleProtocol, Round1Message>()?;

        debug!("{:?}: received message: {:?}", self.context.id, message);

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::protocol(
                SimpleProtocolError::Round1InvalidPosition,
            ));
        }

        Ok(Payload::new(Round1Payload {
            x: message.my_position,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Id, Self::Protocol>> {
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

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Result<EchoBroadcast, LocalError>> {
        debug!("{:?}: making echo broadcast", self.context.id);

        let message = Round1Echo {
            my_position: self.context.ids_to_positions[&self.context.id],
        };

        Some(EchoBroadcast::new::<SimpleProtocol, _>(&message))
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        debug!(
            "{:?}: making direct message for {:?}",
            self.context.id, destination
        );

        let message = Round1Message {
            my_position: self.context.ids_to_positions[&self.context.id],
            your_position: self.context.ids_to_positions[destination],
        };
        let dm = DirectMessage::new::<SimpleProtocol, _>(&message)?;
        let artifact = Artifact::empty();
        Ok((dm, artifact))
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &Id,
        _echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        let message = direct_message.try_deserialize::<SimpleProtocol, Round1Message>()?;

        debug!("{:?}: received message: {:?}", self.context.id, message);

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::protocol(
                SimpleProtocolError::Round2InvalidPosition,
            ));
        }

        Ok(Payload::new(Round1Payload {
            x: message.my_position,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Id, Self::Protocol>> {
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

    use manul::testing::{run_sync, Signature, Signer, Verifier};
    use manul::{Keypair, SessionOutcome};
    use rand_core::OsRng;
    use tracing_subscriber::EnvFilter;

    use super::{Inputs, Round1};

    #[test]
    fn round() {
        let signers = (0..3).map(Signer::new).collect::<Vec<_>>();
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
            run_sync::<Round1<Verifier>, Signer, Verifier, Signature>(&mut OsRng, inputs).unwrap()
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
