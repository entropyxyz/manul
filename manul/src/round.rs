use alloc::collections::{BTreeMap, BTreeSet};
use core::any::Any;
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::echo::EchoRoundError;
use crate::error::{LocalError, RemoteError};
use crate::object_safe::{ObjectSafeRound, ObjectSafeRoundWrapper};
use crate::serde_bytes;
use crate::session::SessionId;
use crate::signing::Digest;

pub struct ReceiveError<Id, P: Protocol>(pub(crate) ReceiveErrorType<Id, P>);

pub(crate) enum ReceiveErrorType<Id, P: Protocol> {
    Local(LocalError),
    InvalidDirectMessage(DirectMessageError),
    InvalidEchoBroadcast(EchoBroadcastError),
    Protocol(P::ProtocolError),
    Unprovable(RemoteError),
    // Note that this variant should not be instantiated by the user (a protocol author),
    // so this whole enum is crate-private and the variants are created
    // via constructors and From impls.
    Echo(EchoRoundError<Id>),
}

impl<Id, P: Protocol> ReceiveError<Id, P> {
    pub fn local(message: impl Into<String>) -> Self {
        Self(ReceiveErrorType::Local(LocalError::new(message.into())))
    }

    pub fn unprovable(message: impl Into<String>) -> Self {
        Self(ReceiveErrorType::Unprovable(RemoteError::new(
            message.into(),
        )))
    }

    pub fn protocol(error: P::ProtocolError) -> Self {
        Self(ReceiveErrorType::Protocol(error))
    }
}

impl<Id, P: Protocol> From<LocalError> for ReceiveError<Id, P> {
    fn from(error: LocalError) -> Self {
        Self(ReceiveErrorType::Local(error))
    }
}

impl<Id, P: Protocol> From<RemoteError> for ReceiveError<Id, P> {
    fn from(error: RemoteError) -> Self {
        Self(ReceiveErrorType::Unprovable(error))
    }
}

impl<Id, P: Protocol> From<EchoRoundError<Id>> for ReceiveError<Id, P> {
    fn from(error: EchoRoundError<Id>) -> Self {
        Self(ReceiveErrorType::Echo(error))
    }
}

impl<Id, P: Protocol> From<DirectMessageError> for ReceiveError<Id, P> {
    fn from(error: DirectMessageError) -> Self {
        Self(ReceiveErrorType::InvalidDirectMessage(error))
    }
}

impl<Id, P: Protocol> From<EchoBroadcastError> for ReceiveError<Id, P> {
    fn from(error: EchoBroadcastError) -> Self {
        Self(ReceiveErrorType::InvalidEchoBroadcast(error))
    }
}

pub enum FinalizeOutcome<Id, P: Protocol> {
    AnotherRound(AnotherRound<Id, P>),
    Result(P::Result),
}

impl<Id: 'static, P: Protocol + 'static> FinalizeOutcome<Id, P> {
    pub fn another_round(round: impl Round<Id, Protocol = P>) -> Self {
        Self::AnotherRound(AnotherRound::new(round))
    }
}

// We do not want to expose `ObjectSafeRound` to the user, so it is hidden in a struct.
pub struct AnotherRound<Id, P: Protocol>(Box<dyn ObjectSafeRound<Id, Protocol = P>>);

impl<Id: 'static, P: Protocol + 'static> AnotherRound<Id, P> {
    pub fn new(round: impl Round<Id, Protocol = P>) -> Self {
        Self(Box::new(ObjectSafeRoundWrapper::new(round)))
    }

    pub(crate) fn into_boxed(self) -> Box<dyn ObjectSafeRound<Id, Protocol = P>> {
        self.0
    }

    pub fn downcast<T: Round<Id>>(self) -> Result<T, LocalError> {
        self.0.downcast::<T>()
    }

    pub fn try_downcast<T: Round<Id>>(self) -> Result<T, Self> {
        self.0.try_downcast::<T>().map_err(Self)
    }
}

pub enum FinalizeError<Id, P: Protocol> {
    Local(LocalError),
    Unattributable(P::CorrectnessProof),
    Unprovable { party: Id, error: RemoteError },
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

    pub(crate) fn non_echo(&self) -> Self {
        // If this panic happens, there is something wrong with the internal logic
        // of managing echo-broadcast rounds.
        if !self.is_echo {
            panic!("This is already an non-echo round ID");
        }
        Self {
            round_num: self.round_num,
            is_echo: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MessageValidationError {
    Local(LocalError),
    Other(String),
}

/// Deserialization error: {0}
#[derive(displaydoc::Display, Debug, Clone)]
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

    fn verify_direct_message_is_invalid(
        round_id: RoundId,
        #[allow(unused_variables)] message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::Other(format!(
            "There are no direct messages in {round_id:?}"
        )))
    }

    fn verify_echo_broadcast_is_invalid(
        round_id: RoundId,
        #[allow(unused_variables)] message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        Err(MessageValidationError::Other(format!(
            "There are no echo broadcasts in {round_id:?}"
        )))
    }
}

#[derive(Debug, Clone)]
pub enum ProtocolValidationError {
    Local(LocalError),
    Other(String),
}

// If fail to deserialize a message when validating the evidence
// it means that the evidence is invalid - a deserialization error would have been
// processed separately, generating its own evidence.
impl From<DirectMessageError> for ProtocolValidationError {
    fn from(error: DirectMessageError) -> Self {
        Self::Other(format!("Failed to deserialize direct message: {error:?}"))
    }
}

impl From<EchoBroadcastError> for ProtocolValidationError {
    fn from(error: EchoBroadcastError) -> Self {
        Self::Other(format!("Failed to deserialize echo broadcast: {error:?}"))
    }
}

impl From<LocalError> for ProtocolValidationError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}

pub trait ProtocolError: Debug + Clone + Send {
    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }
    fn verify_messages_constitute_error(
        &self,
        echo_broadcast: &Option<EchoBroadcast>,
        direct_message: &DirectMessage,
        echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        direct_messages: &BTreeMap<RoundId, DirectMessage>,
        combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError>;
}

/// An error deserializing a direct message: {0}
#[derive(displaydoc::Display, Debug, Clone)]
pub struct DirectMessageError(DeserializationError);

/// An error deserializing an echo broadcast: {0}
#[derive(displaydoc::Display, Debug, Clone)]
pub struct EchoBroadcastError(DeserializationError);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage(#[serde(with = "serde_bytes")] Box<[u8]>);

impl DirectMessage {
    pub fn new<P: Protocol, T: Serialize>(message: &T) -> Result<Self, LocalError> {
        P::serialize(message).map(Self)
    }

    pub fn verify_is_invalid<P: Protocol, T: for<'de> Deserialize<'de>>(
        &self,
    ) -> Result<(), MessageValidationError> {
        if self.try_deserialize::<P, T>().is_err() {
            Ok(())
        } else {
            Err(MessageValidationError::Other(
                "Message deserialized successfully".into(),
            ))
        }
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

pub trait FirstRound<Id: 'static>: Round<Id> + Sized {
    type Inputs;
    fn new(
        rng: &mut impl CryptoRngCore,
        session_id: &SessionId,
        id: Id,
        inputs: Self::Inputs,
    ) -> Result<Self, LocalError>;
}

pub trait Round<Id>: 'static + Send + Sync {
    type Protocol: Protocol;

    fn id(&self) -> RoundId;

    fn possible_next_rounds(&self) -> BTreeSet<RoundId>;

    fn message_destinations(&self) -> &BTreeSet<Id>;

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError>;

    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
    ) -> Option<Result<EchoBroadcast, LocalError>> {
        None
    }

    fn receive_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &Id,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>>;

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Id, Self::Protocol>>;

    fn expecting_messages_from(&self) -> &BTreeSet<Id>;
}
