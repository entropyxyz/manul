use alloc::collections::BTreeMap;

use crate::message::SignedMessage;
use crate::round::{DirectMessage, Protocol, ProtocolError, RoundId};
use crate::signing::DigestVerifier;

#[derive(Debug, Clone)]
pub struct LocalError;

#[derive(Debug, Clone)]
pub struct RemoteError;

#[derive(Debug, Clone)]
pub enum Error<P: Protocol, Verifier, S> {
    Local,
    Remote,
    Protocol(Evidence<P, Verifier, S>),
}

#[derive(Debug, Clone)]
pub struct Evidence<P: Protocol, Verifier, S> {
    pub party: Verifier,
    pub error: P::ProtocolError,
    pub message: SignedMessage<S, DirectMessage>,
    pub previous_messages: BTreeMap<RoundId, SignedMessage<S, DirectMessage>>,
}

impl<P, Verifier, S> Evidence<P, Verifier, S>
where
    P: Protocol,
    Verifier: PartialEq + Clone + DigestVerifier<P::Digest, S>,
    S: Clone,
{
    pub fn verify(&self) -> bool {
        let verified_messages = self
            .previous_messages
            .iter()
            .map(|(round, message)| {
                (
                    *round,
                    message
                        .clone()
                        .verify::<P, _>(&self.party)
                        .unwrap()
                        .payload()
                        .clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let message = self
            .message
            .clone()
            .verify::<P, _>(&self.party)
            .unwrap()
            .payload()
            .clone();

        self.error.verify(&message, &verified_messages)
    }
}
