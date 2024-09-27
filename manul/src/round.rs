use alloc::collections::{BTreeMap, BTreeSet};
use core::any::Any;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::error::LocalError;
use crate::serde_bytes;
use crate::signing::Digest;

pub enum ReceiveError<P: Protocol> {
    InvalidMessage,
    Protocol(P::ProtocolError),
}

pub enum FinalizeOutcome<I, P: Protocol> {
    AnotherRound(Box<dyn Round<I, Protocol = P>>),
    Result(P::Result),
}

pub enum FinalizeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundId {
    round_num: u8,
    is_echo: bool,
}

impl RoundId {
    pub fn new(round_num: u8) -> Self {
        Self {
            round_num,
            is_echo: false,
        }
    }

    pub(crate) fn echo(&self) -> Self {
        Self {
            round_num: self.round_num,
            is_echo: true,
        }
    }
}

pub trait Protocol: Debug {
    type Result;
    type ProtocolError: ProtocolError;
    type CorrectnessProof;
    type SerializationError: serde::ser::Error;
    type DeserializationError: serde::de::Error;
    type Digest: Digest;

    // TODO: should we take inputs by value?
    fn serialize<T: Serialize>(value: &T) -> Result<Box<[u8]>, Self::SerializationError>;
    fn deserialize<T: for<'de> Deserialize<'de>>(
        bytes: &[u8],
    ) -> Result<T, Self::DeserializationError>;
}

pub trait ProtocolError: Debug + Clone {
    fn required_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn verify(&self, message: &DirectMessage, messages: &BTreeMap<RoundId, DirectMessage>) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage(#[serde(with = "serde_bytes")] Box<[u8]>);

impl DirectMessage {
    pub fn new<P: Protocol, T: Serialize>(message: &T) -> Result<Self, P::SerializationError> {
        P::serialize(message).map(Self)
    }

    pub fn try_deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<T, P::DeserializationError> {
        P::deserialize(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoBroadcast(#[serde(with = "serde_bytes")] Box<[u8]>);

impl EchoBroadcast {
    pub fn new<P: Protocol, T: Serialize>(message: &T) -> Result<Self, P::SerializationError> {
        P::serialize(message).map(Self)
    }

    pub fn try_deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<T, P::DeserializationError> {
        P::deserialize(&self.0)
    }
}

pub struct Payload(pub Box<dyn Any>);

impl Payload {
    pub fn new<T: 'static>(payload: T) -> Self {
        Self(Box::new(payload))
    }

    pub fn empty() -> Self {
        Self::new(())
    }

    pub fn try_to_typed<T: 'static>(self) -> Result<T, String> {
        Ok(*(self
            .0
            .downcast::<T>()
            .map_err(|_| format!("Failed to downcast into {}", core::any::type_name::<T>()))?))
    }
}

pub struct Artifact(pub Box<dyn Any>);

impl Artifact {
    pub fn new<T: 'static>(artifact: T) -> Self {
        Self(Box::new(artifact))
    }

    pub fn empty() -> Self {
        Self::new(())
    }

    pub fn try_to_typed<T: 'static>(self) -> Result<T, String> {
        Ok(*(self
            .0
            .downcast::<T>()
            .map_err(|_| format!("Failed to downcast into {}", core::any::type_name::<T>()))?))
    }
}

pub trait FirstRound<I>: Round<I> + Sized {
    type Inputs;
    fn new(id: I, inputs: Self::Inputs) -> Result<Self, LocalError>;
}

pub trait Round<I> {
    type Protocol: Protocol;

    fn id(&self) -> RoundId;
    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn message_destinations(&self) -> &BTreeSet<I>;
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

    // Do we need to take `artifacts` here? Can we just judge by payloads?
    fn can_finalize(
        &self,
        payloads: &BTreeMap<I, Payload>,
        artifacts: &BTreeMap<I, Artifact>,
    ) -> bool;
}
