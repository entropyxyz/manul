use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use manul::*;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use tracing::debug;

#[derive(Debug)]
struct SimpleProtocol;

#[derive(Debug, Clone)]
struct SimpleProtocolError;

impl ProtocolError for SimpleProtocolError {
    fn verify(
        &self,
        _message: &DirectMessage,
        _messages: &BTreeMap<RoundId, DirectMessage>,
    ) -> bool {
        true
    }
}

impl Protocol for SimpleProtocol {
    type Result = u8;
    type ProtocolError = SimpleProtocolError;
    type CorrectnessProof = ();

    type SerializationError = bincode::error::EncodeError;
    type DeserializationError = bincode::error::DecodeError;

    type Digest = Sha3_256;

    fn serialize<T: Serialize>(value: &T) -> Result<Box<[u8]>, Self::SerializationError> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).map(|vec| vec.into())
    }

    fn deserialize<T: for<'de> Deserialize<'de>>(
        bytes: &[u8],
    ) -> Result<T, Self::DeserializationError> {
        bincode::serde::decode_borrowed_from_slice(bytes, bincode::config::standard())
    }
}

struct Inputs<Id> {
    all_ids: BTreeSet<Id>,
}

struct Context<Id> {
    id: Id,
    other_ids: BTreeSet<Id>,
    ids_to_positions: BTreeMap<Id, u8>,
}

struct Round1<Id> {
    context: Context<Id>,
}

#[derive(Serialize, Deserialize)]
struct Round1Message {
    my_position: u8,
    your_position: u8,
}

#[derive(Serialize, Deserialize)]
struct Round1Echo {
    my_position: u8,
}

struct Round1Payload {
    x: u8,
}

impl<Id: Debug + Clone + Ord> FirstRound<Id> for Round1<Id> {
    type Inputs = Inputs<Id>;
    fn new(id: Id, inputs: Self::Inputs) -> Result<Self, LocalError> {
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

impl<Id: Debug + Clone + Ord> Round<Id> for Round1<Id> {
    type Protocol = SimpleProtocol;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(&self) -> Option<Result<EchoBroadcast, LocalError>> {
        debug!("{:?}: making echo broadcast", self.context.id);

        let message = Round1Echo {
            my_position: self.context.ids_to_positions[&self.context.id],
        };
        let echo = EchoBroadcast::new::<SimpleProtocol, _>(&message).unwrap();
        Some(Ok(echo))
    }

    fn make_direct_message(
        &self,
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
        let dm = DirectMessage::new::<SimpleProtocol, _>(&message).unwrap();
        let artifact = Artifact::empty();
        Ok((dm, artifact))
    }

    fn receive_message(
        &self,
        from: &Id,
        _echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Self::Protocol>> {
        debug!("{:?}: receiving message from {:?}", self.context.id, from);

        let message = direct_message
            .try_deserialize::<SimpleProtocol, Round1Message>()
            .map_err(|_| ReceiveError::InvalidMessage)?;

        if self.context.ids_to_positions[&self.context.id] != message.your_position {
            return Err(ReceiveError::Protocol(SimpleProtocolError));
        }

        Ok(Payload::new(Round1Payload {
            x: message.my_position,
        }))
    }

    fn finalize(
        self: Box<Self>,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError> {
        debug!(
            "{:?}: finalizing with messages from {:?}",
            self.context.id,
            payloads.keys().cloned().collect::<Vec<_>>()
        );

        let typed_payloads = payloads
            .into_values()
            .map(|payload| payload.try_to_typed::<Round1Payload>().unwrap())
            .collect::<Vec<_>>();
        let sum = self.context.ids_to_positions[&self.context.id]
            + typed_payloads.iter().map(|payload| payload.x).sum::<u8>();
        Ok(FinalizeOutcome::Result(sum))
    }

    fn can_finalize(
        &self,
        payloads: &BTreeMap<Id, Payload>,
        _artifacts: &BTreeMap<Id, Artifact>,
    ) -> bool {
        self.context
            .other_ids
            .iter()
            .all(|id| payloads.contains_key(id))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::testing::{run_sync, RunOutcome, Signature, Signer, Verifier};
    use manul::Keypair;
    use rand_core::OsRng;
    use tracing_subscriber::EnvFilter;

    use super::{Inputs, Round1};

    #[test]
    fn round() {
        let signers = (0..3).map(|id| Signer::new(id)).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key().clone())
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
        let results = tracing::subscriber::with_default(my_subscriber, || {
            run_sync::<Round1<Verifier>, Signer, Verifier, Signature>(&mut OsRng, inputs).unwrap()
        });

        for (_id, result) in results {
            assert!(matches!(result, RunOutcome::Result(_)));
            if let RunOutcome::Result(x) = result {
                assert_eq!(x, 0 + 1 + 2);
            }
        }
    }
}
