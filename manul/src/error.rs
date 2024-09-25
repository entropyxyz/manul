use alloc::collections::BTreeMap;

use crate::message::SignedMessage;
use crate::round::{DirectMessage, Protocol, ProtocolError, RoundId};

#[derive(Debug, Clone)]
pub struct LocalError;

#[derive(Debug, Clone)]
pub struct RemoteError;

#[derive(Debug, Clone)]
pub enum Error<I, P: Protocol> {
    Local,
    Remote,
    Protocol(Evidence<I, P>),
}

#[derive(Debug, Clone)]
pub struct Evidence<I, P: Protocol> {
    pub party: I,
    pub error: P::ProtocolError,
    pub message: SignedMessage<I, DirectMessage>,
    pub previous_messages: BTreeMap<RoundId, SignedMessage<I, DirectMessage>>,
}

impl<I: PartialEq + Clone, P: Protocol> Evidence<I, P> {
    pub fn verify(&self) -> bool {
        let verified_messages = self
            .previous_messages
            .iter()
            .map(|(round, message)| {
                (
                    *round,
                    message
                        .clone()
                        .verify(&self.party)
                        .unwrap()
                        .payload()
                        .clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let message = self
            .message
            .clone()
            .verify(&self.party)
            .unwrap()
            .payload()
            .clone();

        self.error.verify(&message, &verified_messages)
    }
}
