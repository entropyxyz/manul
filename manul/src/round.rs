use alloc::collections::{BTreeMap, BTreeSet};
use core::any::Any;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::error::LocalError;

pub enum ReceiveError<P: Protocol> {
    InvalidMessage,
    Protocol(P::ProtocolError),
}

pub enum FinalizeOutcome<I, P: Protocol> {
    AnotherRound(Box<dyn Round<I, Protocol = P>>),
    Result(P::Result),
}

pub enum FinalizeError {}

pub type RoundId = u8;

pub trait Protocol: Debug {
    type Result;
    type ProtocolError: ProtocolError;
    type CorrectnessProof;
    type SerializationError: serde::ser::Error;
    type DeserializationError: serde::de::Error;

    // TODO: should we take inputs by value?
    fn serialize<T: Serialize>(value: &T) -> Result<Box<[u8]>, Self::SerializationError>;
    fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, Self::DeserializationError>;
}

pub trait ProtocolError: Debug + Clone {
    fn required_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn verify(&self, message: &DirectMessage, messages: &BTreeMap<RoundId, DirectMessage>) -> bool;
}

#[derive(Debug, Clone)]
pub struct DirectMessage(Box<[u8]>);

impl DirectMessage {
    pub fn new<P: Protocol, T: Serialize>(message: &T) -> Result<Self, P::SerializationError> {
        P::serialize(message).map(Self)
    }

    pub fn try_deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(&self) -> Result<T, P::DeserializationError> {
        P::deserialize(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct EchoBroadcast(pub Box<[u8]>);

pub struct Payload(pub Box<dyn Any>);

pub struct Artifact(pub Box<dyn Any>);

impl Artifact {
    pub fn new<T: 'static>(artifact: T) -> Self {
        Self(Box::new(artifact))
    }

    pub fn empty() -> Self {
        Self::new(())
    }
}

pub trait FirstRound<I>: Round<I> + Sized {
    type Inputs;
    fn new(inputs: Self::Inputs) -> Result<Self, LocalError>;
}

pub trait Round<I> {
    type Protocol: Protocol;

    fn id(&self) -> RoundId;
    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn message_destinations(&self) -> BTreeSet<I>;
    fn make_direct_message(&self, destination: &I)
        -> Result<(DirectMessage, Artifact), LocalError>;
    fn make_echo_broadcast(&self) -> Result<Option<EchoBroadcast>, LocalError> {
        Ok(None)
    }

    fn receive_message(
        &self,
        from: &I,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Self::Protocol>>;

    fn finalize(
        self: Box<Self>,
        payloads: BTreeMap<I, Payload>,
        artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, FinalizeError>;
}
