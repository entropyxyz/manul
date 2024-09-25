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

#[test]
fn round() {
    let r1 = Round1;

    let boxed_r1: Box<dyn Round<Id, Protocol = MyProto>> = Box::new(r1);
    let _result = boxed_r1.finalize(BTreeMap::new(), BTreeMap::new());
}
