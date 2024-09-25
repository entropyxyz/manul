use alloc::collections::{BTreeMap, BTreeSet};

use manul::*;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct Id(u8);

struct Round1;

#[derive(Debug)]
struct MyProto;

#[derive(Debug, Clone)]
struct MyProtoError;

impl ProtocolError for MyProtoError {
    fn verify(
        &self,
        _message: &DirectMessage,
        _messages: &BTreeMap<RoundId, DirectMessage>,
    ) -> bool {
        true
    }
}

impl Protocol for MyProto {
    type Result = u8;
    type ProtocolError = MyProtoError;
    type CorrectnessProof = ();
}

impl FirstRound<Id> for Round1 {
    type Inputs = ();
    fn new(_inputs: Self::Inputs) -> Result<Self, LocalError> {
        Ok(Self)
    }
}

impl Round<Id> for Round1 {
    type Protocol = MyProto;

    fn id(&self) -> RoundId {
        1
    }

    fn message_destinations(&self) -> BTreeSet<Id> {
        BTreeSet::from([Id(2)])
    }

    fn make_direct_message(
        &self,
        _destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        let dm = DirectMessage(vec![1, 2, 3].into());
        let artifact = Artifact::empty();
        Ok((dm, artifact))
    }

    fn receive_message(
        &self,
        _from: &Id,
        _echo_broadcast: Option<EchoBroadcast>,
        _direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Self::Protocol>> {
        Ok(Payload(Box::new(1)))
    }

    fn finalize(
        self: Box<Self>,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError> {
        Ok(FinalizeOutcome::Result(1))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use manul::test_utils::{run_sync, RunOutcome};

    use super::{Id, Round1};

    #[test]
    fn round() {
        let results = run_sync::<Id, Round1>(BTreeMap::from([(Id(1), ()), (Id(2), ())])).unwrap();
        for (_id, result) in results {
            assert!(matches!(result, RunOutcome::Result(_)));
        }
    }
}
