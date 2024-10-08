use alloc::collections::{BTreeMap, BTreeSet};
use core::any::Any;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::error::{LocalError, RemoteError};
use crate::serde_bytes;
use crate::signing::Digest;

pub(crate) enum EchoRoundError {
    MessageMismatch,
}

pub enum ReceiveError<P: Protocol> {
    Local(LocalError),
    InvalidDirectMessage(DirectMessageError),
    InvalidEchoBroadcast(EchoBroadcastError),
    Protocol(P::ProtocolError),
    Unprovable(RemoteError),
    #[allow(private_interfaces)]
    Echo(EchoRoundError),
}

impl<P: Protocol> From<DirectMessageError> for ReceiveError<P> {
    fn from(error: DirectMessageError) -> Self {
        Self::InvalidDirectMessage(error)
    }
}

impl<P: Protocol> From<EchoBroadcastError> for ReceiveError<P> {
    fn from(error: EchoBroadcastError) -> Self {
        Self::InvalidEchoBroadcast(error)
    }
}

pub enum FinalizeOutcome<I, P: Protocol> {
    AnotherRound(Box<dyn Round<I, Protocol = P>>),
    Result(P::Result),
}

pub enum FinalizeError<I, P: Protocol> {
    Local(LocalError),
    // TODO: need another type of P::FinalizeError, since this won't have an associated message
    // when constructing the evidence
    //Protocol { party: I, error: P::ProtocolError },
    Unattributable(P::CorrectnessProof),
    Unprovable { party: I, error: RemoteError },
}

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
        // If this panic happens, there is something wrong with the internal logic
        // of managing echo-broadcast rounds.
        if self.is_echo {
            panic!("This is already an echo round ID");
        }
        Self {
            round_num: self.round_num,
            is_echo: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MessageValidationError {
    Local(LocalError),
    Deserialization(DeserializationError),
}

#[derive(Debug, Clone)]
pub struct DeserializationError(String);

impl DeserializationError {
    pub fn new(message: String) -> Self {
        Self(message)
    }
}

impl From<LocalError> for MessageValidationError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}

pub trait Protocol: Debug + Sized {
    type Result;
    type ProtocolError: ProtocolError;
    type CorrectnessProof: Send;
    type Digest: Digest;

    // TODO: should we take inputs by value?
    fn serialize<T: Serialize>(value: &T) -> Result<Box<[u8]>, LocalError>;
    // TODO: should this be generic on 'de instead?
    fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, DeserializationError>;

    fn validate_direct_message(
        round_id: RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::Local(LocalError::new(format!(
            "There are no direct messages in {round_id:?}"
        ))))
    }
}

#[derive(Debug, Clone)]
pub enum ProtocolValidationError {
    Local(LocalError),
    ValidEvidence,
}

// If fail to deserialize a message when validating the evidence
// it means that the evidence is invalid - a deserialization error would have been
// processed separately, generating its own evidence.
impl From<DirectMessageError> for ProtocolValidationError {
    fn from(error: DirectMessageError) -> Self {
        Self::Local(LocalError::new(format!(
            "Failed to deserialize direct message: {error:?}"
        )))
    }
}

pub trait ProtocolError: Debug + Clone + Send {
    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn verify(
        &self,
        echo_broadcast: &Option<EchoBroadcast>,
        direct_message: &DirectMessage,
        echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        direct_messages: &BTreeMap<RoundId, DirectMessage>,
    ) -> Result<(), ProtocolValidationError>;
}

#[derive(Debug, Clone)]
pub struct DirectMessageError(DeserializationError);

#[derive(Debug, Clone)]
pub struct EchoBroadcastError(DeserializationError);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage(#[serde(with = "serde_bytes")] Box<[u8]>);

impl DirectMessage {
    pub fn new<P: Protocol, T: Serialize>(message: &T) -> Result<Self, LocalError> {
        P::serialize(message).map(Self)
    }

    pub fn validate<P: Protocol, T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<(), MessageValidationError> {
        self.try_deserialize::<P, T>()
            .map_err(|err| MessageValidationError::Deserialization(err.0))?;
        Ok(())
    }

    pub fn try_deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<T, DirectMessageError> {
        P::deserialize(&self.0).map_err(DirectMessageError)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EchoBroadcast(#[serde(with = "serde_bytes")] Box<[u8]>);

impl EchoBroadcast {
    pub fn new<P: Protocol, T: Serialize>(message: &T) -> Result<Self, LocalError> {
        P::serialize(message).map(Self)
    }

    pub fn try_deserialize<P: Protocol, T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<T, EchoBroadcastError> {
        P::deserialize(&self.0).map_err(EchoBroadcastError)
    }
}

pub struct Payload(pub Box<dyn Any + Send + Sync>);

impl Payload {
    pub fn new<T: 'static + Send + Sync>(payload: T) -> Self {
        Self(Box::new(payload))
    }

    pub fn empty() -> Self {
        Self::new(())
    }

    pub fn try_to_typed<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self.0.downcast::<T>().map_err(|_| {
            LocalError::new(format!(
                "Failed to downcast into {}",
                core::any::type_name::<T>()
            ))
        })?))
    }
}

pub struct Artifact(pub Box<dyn Any + Send + Sync>);

impl Artifact {
    pub fn new<T: 'static + Send + Sync>(artifact: T) -> Self {
        Self(Box::new(artifact))
    }

    pub fn empty() -> Self {
        Self::new(())
    }

    pub fn try_to_typed<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self.0.downcast::<T>().map_err(|_| {
            LocalError::new(format!(
                "Failed to downcast into {}",
                core::any::type_name::<T>()
            ))
        })?))
    }
}

pub trait FirstRound<I>: Round<I> + Sized {
    type Inputs;
    fn new(id: I, inputs: Self::Inputs) -> Result<Self, LocalError>;
}

pub trait Round<I>: Send + Sync {
    type Protocol: Protocol;

    fn id(&self) -> RoundId;
    fn possible_next_rounds(&self) -> BTreeSet<RoundId>;

    fn message_destinations(&self) -> &BTreeSet<I>;
    fn make_direct_message(&self, destination: &I)
        -> Result<(DirectMessage, Artifact), LocalError>;
    fn make_echo_broadcast(&self) -> Option<Result<EchoBroadcast, LocalError>> {
        None
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
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, FinalizeError<I, Self::Protocol>>;

    // Do we need to take `artifacts` here? Can we just judge by payloads?
    fn can_finalize(
        &self,
        payloads: &BTreeMap<I, Payload>,
        artifacts: &BTreeMap<I, Artifact>,
    ) -> bool;
}
