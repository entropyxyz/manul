use alloc::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::VerifyingKey;
use manul::*;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

struct Round1;

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

impl FirstRound<VerifyingKey> for Round1 {
    type Inputs = ();
    fn new(_inputs: Self::Inputs) -> Result<Self, LocalError> {
        Ok(Self)
    }
}

impl Round<VerifyingKey> for Round1 {
    type Protocol = SimpleProtocol;

    fn id(&self) -> RoundId {
        1
    }

    fn message_destinations(&self) -> BTreeSet<VerifyingKey> {
        BTreeSet::from([])
    }

    fn make_direct_message(
        &self,
        _destination: &VerifyingKey,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        let dm = DirectMessage::new::<SimpleProtocol, _>(&[1u8, 2, 3]).unwrap();
        let artifact = Artifact::empty();
        Ok((dm, artifact))
    }

    fn receive_message(
        &self,
        _from: &VerifyingKey,
        _echo_broadcast: Option<EchoBroadcast>,
        _direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Self::Protocol>> {
        Ok(Payload(Box::new(1)))
    }

    fn finalize(
        self: Box<Self>,
        _payloads: BTreeMap<VerifyingKey, Payload>,
        _artifacts: BTreeMap<VerifyingKey, Artifact>,
    ) -> Result<FinalizeOutcome<VerifyingKey, Self::Protocol>, FinalizeError> {
        Ok(FinalizeOutcome::Result(1))
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use manul::test_utils::{run_sync, RunOutcome};
    use rand_core::OsRng;

    use super::Round1;

    #[test]
    fn round() {
        let signers = (0..3)
            .map(|_| SigningKey::random(&mut OsRng))
            .collect::<Vec<_>>();
        let inputs = signers
            .into_iter()
            .map(|signer| (signer, ()))
            .collect::<Vec<_>>();

        let results = run_sync::<Round1, SigningKey, VerifyingKey, Signature>(inputs).unwrap();
        for (_id, result) in results {
            assert!(matches!(result, RunOutcome::Result(_)));
        }
    }
}
