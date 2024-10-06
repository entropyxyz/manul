use alloc::collections::BTreeMap;
use core::fmt::Debug;

use crate::error::LocalError;
use crate::message::SignedMessage;
use crate::round::{DirectMessage, EchoBroadcast, ProtocolError};
use crate::transcript::Transcript;
use crate::{DigestVerifier, Protocol, RoundId};

#[derive(Debug, Clone)]
pub struct Evidence<P: Protocol, Verifier, S> {
    party: Verifier, // TOOD: should it be saved here?
    evidence: EvidenceEnum<P, S>,
}

impl<P, Verifier, S> Evidence<P, Verifier, S>
where
    P: Protocol,
    Verifier: Debug + Clone + Ord + DigestVerifier<P::Digest, S>,
    S: Debug + Clone,
{
    pub(crate) fn new_protocol_error(
        verifier: &Verifier,
        echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
        direct_message: SignedMessage<S, DirectMessage>,
        error: P::ProtocolError,
        transcript: &Transcript<P, Verifier, S>,
    ) -> Result<Self, LocalError> {
        let echo_broadcasts = error
            .required_echo_broadcasts()
            .iter()
            .map(|round_id| {
                transcript
                    .get_echo_broadcast(*round_id, verifier)
                    .map(|echo| (*round_id, echo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let direct_messages = error
            .required_direct_messages()
            .iter()
            .map(|round_id| {
                transcript
                    .get_direct_message(*round_id, verifier)
                    .map(|dm| (*round_id, dm))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Self {
            party: verifier.clone(),
            evidence: EvidenceEnum::Protocol(ProtocolEvidence {
                error,
                direct_message,
                echo_broadcast,
                direct_messages,
                echo_broadcasts,
            }),
        })
    }

    pub(crate) fn new_invalid_direct_message(
        message: SignedMessage<S, DirectMessage>,
        error: String,
    ) -> Self {
        unimplemented!()
    }

    pub(crate) fn new_invalid_echo_broadcast(
        message: SignedMessage<S, EchoBroadcast>,
        error: String,
    ) -> Self {
        unimplemented!()
    }

    // TODO: return an enum instead of `bool` to avoid confusion?
    // `true` means: evidence is self-consistent and proves the guilt,
    // `false` means: evidence is not self-consistent, or forged.
    pub fn verify(&self, party: &Verifier) -> Result<bool, LocalError> {
        match &self.evidence {
            EvidenceEnum::Protocol(evidence) => evidence.verify(party),
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Clone)]
enum EvidenceEnum<P: Protocol, S> {
    Protocol(ProtocolEvidence<P, S>),
    InvalidMessage(InvalidMessageEvidence<P, S>),
}

#[derive(Debug, Clone)]
pub struct InvalidMessageEvidence<P: Protocol, S> {
    pub message: SignedMessage<S, DirectMessage>,
    pub phantom: core::marker::PhantomData<P>,
}

impl<P, S> InvalidMessageEvidence<P, S>
where
    P: Protocol,
{
    fn verify<Verifier>(&self, verifier: &Verifier) -> bool
    where
        Verifier: Debug + Clone + DigestVerifier<P::Digest, S>,
    {
        true
    }
}

#[derive(Debug, Clone)]
struct ProtocolEvidence<P: Protocol, S> {
    error: P::ProtocolError,
    direct_message: SignedMessage<S, DirectMessage>,
    echo_broadcast: Option<SignedMessage<S, EchoBroadcast>>,
    direct_messages: BTreeMap<RoundId, SignedMessage<S, DirectMessage>>,
    echo_broadcasts: BTreeMap<RoundId, SignedMessage<S, EchoBroadcast>>,
}

impl<P, S> ProtocolEvidence<P, S>
where
    P: Protocol,
    S: Clone,
{
    fn verify<Verifier>(&self, verifier: &Verifier) -> Result<bool, LocalError>
    where
        Verifier: Debug + Clone + DigestVerifier<P::Digest, S>,
    {
        let verified_direct_message = match self.direct_message.clone().verify::<P, _>(verifier)? {
            Some(message) => message.payload().clone(),
            None => return Ok(false),
        };

        let mut verified_direct_messages = BTreeMap::new();
        for (round_id, direct_message) in self.direct_messages.iter() {
            let verified_direct_message = match direct_message.clone().verify::<P, _>(verifier)? {
                Some(message) => message,
                None => return Ok(false),
            };
            verified_direct_messages.insert(*round_id, verified_direct_message.payload().clone());
        }

        let verified_echo_broadcast = if let Some(echo) = self.echo_broadcast.as_ref() {
            match echo.clone().verify::<P, _>(verifier)? {
                Some(message) => Some(message.payload().clone()),
                None => return Ok(false),
            }
        } else {
            None
        };

        let mut verified_echo_broadcasts = BTreeMap::new();
        for (round_id, echo_broadcast) in self.echo_broadcasts.iter() {
            let verified_echo_broadcast = match echo_broadcast.clone().verify::<P, _>(verifier)? {
                Some(message) => message,
                None => return Ok(false),
            };
            verified_echo_broadcasts.insert(*round_id, verified_echo_broadcast.payload().clone());
        }

        Ok(self.error.verify(
            &verified_echo_broadcast,
            &verified_direct_message,
            &verified_echo_broadcasts,
            &verified_direct_messages,
        ))
    }
}
