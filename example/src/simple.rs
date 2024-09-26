use alloc::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::VerifyingKey;
use manul::*;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

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

struct Inputs {
    all_ids: BTreeSet<VerifyingKey>,
}

struct Context {
    id: VerifyingKey,
    other_ids: BTreeSet<VerifyingKey>,
    ids_to_positions: BTreeMap<VerifyingKey, u8>,
}

struct Round1 {
    context: Context,
}

#[derive(Serialize, Deserialize)]
struct Round1Message {
    my_position: u8,
    your_position: u8,
}

struct Round1Payload {
    x: u8,
}

impl FirstRound<VerifyingKey> for Round1 {
    type Inputs = Inputs;
    fn new(id: VerifyingKey, inputs: Self::Inputs) -> Result<Self, LocalError> {
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

impl Round<VerifyingKey> for Round1 {
    type Protocol = SimpleProtocol;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn message_destinations(&self) -> &BTreeSet<VerifyingKey> {
        &self.context.other_ids
    }

    fn make_direct_message(
        &self,
        destination: &VerifyingKey,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
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
        _from: &VerifyingKey,
        _echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Self::Protocol>> {
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
        payloads: BTreeMap<VerifyingKey, Payload>,
        _artifacts: BTreeMap<VerifyingKey, Artifact>,
    ) -> Result<FinalizeOutcome<VerifyingKey, Self::Protocol>, FinalizeError> {
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
        payloads: &BTreeMap<VerifyingKey, Payload>,
        _artifacts: &BTreeMap<VerifyingKey, Artifact>,
    ) -> bool {
        payloads
            .keys()
            .all(|from| self.context.other_ids.contains(from))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use manul::test_utils::{run_sync, RunOutcome};
    use rand_core::OsRng;

    use super::{Inputs, Round1};

    #[test]
    fn round() {
        let signers = (0..3)
            .map(|_| SigningKey::random(&mut OsRng))
            .collect::<Vec<_>>();
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

        let results = run_sync::<Round1, SigningKey, VerifyingKey, Signature>(inputs).unwrap();
        for (_id, result) in results {
            assert!(matches!(result, RunOutcome::Result(_)));
            if let RunOutcome::Result(x) = result {
                assert_eq!(x, 0 + 1 + 2);
            }
        }
    }
}
