use alloc::collections::BTreeMap;
use core::fmt::Debug;

use crate::message::SignedMessage;
use crate::round::{DirectMessage, Protocol, ProtocolError, RoundId};
use crate::signing::DigestVerifier;

#[derive(Debug, Clone)]
pub struct LocalError(String);

impl LocalError {
    pub fn new(message: String) -> Self {
        Self(message)
    }
}

#[derive(Debug, Clone)]
pub struct RemoteError<Verifier> {
    party: Verifier,
    error: String,
}

impl<Verifier> RemoteError<Verifier> {
    pub fn new(party: Verifier, error: String) -> Self {
        Self { party, error }
    }
}

#[derive(Debug, Clone)]
pub enum Error<P: Protocol, Verifier, S> {
    Local(LocalError),
    Remote(RemoteError<Verifier>),
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
    Verifier: Debug + PartialEq + Clone + DigestVerifier<P::Digest, S>,
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
