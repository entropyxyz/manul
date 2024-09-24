use alloc::collections::{BTreeMap, BTreeSet};

use crate::error::{Evidence, LocalError};
use crate::message::{MessageBundle, SignedDirectMessage, SignedEchoBroadcast};
use crate::round::{Artifact, Payload, ProtocolError, RoundId, VerificationError};
use crate::{Error, Protocol, Round};

pub struct Session<I, P> {
    my_id: I,
    round: Box<dyn Round<I, Protocol = P>>,
    messages: BTreeMap<RoundId, BTreeMap<I, SignedDirectMessage<I>>>,
}

impl<I: Clone + PartialEq + Ord, P: Protocol> Session<I, P> {
    pub fn new<R>(my_id: I, round: R) -> Self
    where
        R: Round<I, Protocol = P> + 'static,
    {
        Self {
            my_id,
            round: Box::new(round),
            messages: BTreeMap::new(),
        }
    }

    pub fn message_destinations(&self) -> BTreeSet<I> {
        self.round.message_destinations()
    }

    pub fn make_message(
        &self,
        destination: &I,
    ) -> Result<(MessageBundle<I>, Artifact), LocalError> {
        let (message, artifact) = self.round.make_direct_message(destination)?;
        let signed_direct_message = SignedDirectMessage {
            signature: self.my_id.clone(),
            message,
        };

        let signed_echo_broadcast =
            self.round
                .make_echo_broadcast()?
                .map(|echo| SignedEchoBroadcast {
                    signature: self.my_id.clone(),
                    message: echo,
                });

        let bundle = MessageBundle {
            round_id: self.round.id(),
            direct_message: signed_direct_message,
            echo_broadcast: signed_echo_broadcast,
        };

        Ok((bundle, artifact))
    }

    pub fn verify_message(
        &self,
        from: &I,
        message: &MessageBundle<I>,
    ) -> Result<Payload, Error<I, P>> {
        let verified_direct_message = message.direct_message.clone().verify(from).unwrap();
        let verified_echo_broadcast = message
            .echo_broadcast
            .as_ref()
            .map(|echo| echo.clone().verify(from).unwrap());
        match self
            .round
            .verify_message(from, &verified_echo_broadcast, &verified_direct_message)
        {
            Ok(payload) => Ok(payload),
            Err(error) => {
                match error {
                    VerificationError::InvalidMessage => unimplemented!(),
                    VerificationError::Protocol(error) => Err(Error::Protocol(
                        self.prepare_evidence(from, &message.direct_message, error),
                    )),
                }
            }
        }
    }

    fn prepare_evidence(
        &self,
        from: &I,
        message: &SignedDirectMessage<I>,
        error: P::ProtocolError,
    ) -> Evidence<I, P> {
        let rounds = error.required_rounds();

        let messages = rounds
            .iter()
            .map(|round| (*round, self.messages[round][from].clone()))
            .collect();

        Evidence {
            party: from.clone(),
            error,
            message: message.clone(),
            previous_messages: messages,
        }
    }
}
