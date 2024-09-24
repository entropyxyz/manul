use alloc::collections::BTreeMap;

use crate::message::SignedDirectMessage;
use crate::round::{Protocol, ProtocolError, RoundId};

pub struct LocalError;

pub enum Error<I, P: Protocol> {
    Local,
    Remote,
    Protocol(Evidence<I, P>),
}

pub struct Evidence<I, P: Protocol> {
    pub party: I,
    pub error: P::ProtocolError,
    pub message: SignedDirectMessage<I>,
    pub previous_messages: BTreeMap<RoundId, SignedDirectMessage<I>>,
}

impl<I: PartialEq + Clone, P: Protocol> Evidence<I, P> {
    pub fn verify(&self) -> bool {
        let verified_messages = self
            .previous_messages
            .iter()
            .map(|(round, message)| (*round, message.clone().verify(&self.party).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let message = self.message.clone().verify(&self.party).unwrap();

        self.error.verify(&message, &verified_messages)
    }
}
