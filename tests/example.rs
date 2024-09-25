extern crate alloc;

use alloc::collections::BTreeMap;

use manul::*;

struct Id(u8);

struct Round1;

struct MyProto;

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
    type Success = u8;
    type ProtocolError = MyProtoError;
    type CorrectnessProof = ();
}

impl Round<Id> for Round1 {
    type Protocol = MyProto;

    fn id(&self) -> RoundId {
        1
    }

    fn message_destinations(&self) -> Vec<Id> {
        vec![Id(2)]
    }

    fn make_direct_message(&self, destination: &Id) -> DirectMessage {
        DirectMessage(vec![1, 2, 3].into())
    }

    fn verify_message(
        &self,
        from: &Id,
        message: &DirectMessage,
    ) -> Result<Payload, VerificationError<Self::Protocol>> {
        Ok(Payload(Box::new(1)))
    }

    fn round_num(&self) -> u8 {
        1
    }

    fn finalize(self: Box<Self>) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError> {
        Ok(FinalizeOutcome::Result(1))
    }
}

#[test]
fn round() {
    let r1 = Round1;

    let boxed_r1: Box<dyn Round<Id, Protocol = MyProto>> = Box::new(r1);
    let _result = boxed_r1.finalize();
}
