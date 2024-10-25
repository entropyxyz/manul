use alloc::{format, string::String};
use core::fmt::Debug;

use super::round::Protocol;
use crate::session::EchoRoundError;

/// An error indicating a local problem, most likely a misuse of the API or a bug in the code.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Local error: {0}")]
pub struct LocalError(String);

impl LocalError {
    /// Creates a new error from anything castable to string.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// An error indicating a problem whose reason is another node sending invalid data.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Remote error: {0}")]
pub struct RemoteError(String);

impl RemoteError {
    /// Creates a new error from anything castable to string.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// An error that can be returned from [`Round::receive_message`](`super::Round::receive_message`).
#[derive(Debug)]
pub struct ReceiveError<Id, P: Protocol>(pub(crate) ReceiveErrorType<Id, P>);

#[derive(Debug)]
pub(crate) enum ReceiveErrorType<Id, P: Protocol> {
    /// A local error, indicating an implemenation bug or a misuse by the upper layer.
    Local(LocalError),
    /// The given direct message cannot be deserialized.
    InvalidDirectMessage(DirectMessageError),
    /// The given echo broadcast cannot be deserialized.
    InvalidEchoBroadcast(EchoBroadcastError),
    /// A provable error occurred.
    Protocol(P::ProtocolError),
    /// An unprovable error occurred.
    Unprovable(RemoteError),
    // Note that this variant should not be instantiated by the user (a protocol author),
    // so this whole enum is crate-private and the variants are created
    // via constructors and From impls.
    /// An echo round error occurred.
    Echo(EchoRoundError<Id>),
}

impl<Id, P: Protocol> ReceiveError<Id, P> {
    /// A local error, indicating an implemenation bug or a misuse by the upper layer.
    pub fn local(message: impl Into<String>) -> Self {
        Self(ReceiveErrorType::Local(LocalError::new(message.into())))
    }

    /// An unprovable error occurred.
    pub fn unprovable(message: impl Into<String>) -> Self {
        Self(ReceiveErrorType::Unprovable(RemoteError::new(message.into())))
    }

    /// A provable error occurred.
    pub fn protocol(error: P::ProtocolError) -> Self {
        Self(ReceiveErrorType::Protocol(error))
    }
}

impl<Id, P> From<LocalError> for ReceiveError<Id, P>
where
    P: Protocol,
{
    fn from(error: LocalError) -> Self {
        Self(ReceiveErrorType::Local(error))
    }
}

impl<Id, P> From<RemoteError> for ReceiveError<Id, P>
where
    P: Protocol,
{
    fn from(error: RemoteError) -> Self {
        Self(ReceiveErrorType::Unprovable(error))
    }
}

impl<Id, P> From<EchoRoundError<Id>> for ReceiveError<Id, P>
where
    P: Protocol,
{
    fn from(error: EchoRoundError<Id>) -> Self {
        Self(ReceiveErrorType::Echo(error))
    }
}

impl<Id, P> From<DirectMessageError> for ReceiveError<Id, P>
where
    P: Protocol,
{
    fn from(error: DirectMessageError) -> Self {
        Self(ReceiveErrorType::InvalidDirectMessage(error))
    }
}

impl<Id, P> From<EchoBroadcastError> for ReceiveError<Id, P>
where
    P: Protocol,
{
    fn from(error: EchoBroadcastError) -> Self {
        Self(ReceiveErrorType::InvalidEchoBroadcast(error))
    }
}

/// An error that can occur during [`Round::finalize`](`super::Round::finalize`).
#[derive(Debug)]
pub enum FinalizeError<P: Protocol> {
    /// A local error, usually indicating a bug in the implementation.
    Local(LocalError),
    /// An unattributable error, with an attached proof that this node performed its duties correctly.
    Unattributable(P::CorrectnessProof),
}

impl<P: Protocol> From<LocalError> for FinalizeError<P> {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}

/// An error that can occur during the validation of an evidence of an invalid message.
#[derive(Debug, Clone)]
pub enum MessageValidationError {
    /// Indicates a local problem, usually a bug in the library code.
    Local(LocalError),
    /// Indicates a problem with the evidence, for example the given round not sending such messages,
    /// or the message actually deserializing successfully.
    InvalidEvidence(String),
}

/// An error that can be returned during deserialization error.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Deserialization error: {0}")]
pub struct DeserializationError(String);

impl DeserializationError {
    /// Creates a new deserialization error.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<LocalError> for MessageValidationError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}

/// An error that can occur during the validation of an evidence of a protocol error.
#[derive(Debug, Clone)]
pub enum ProtocolValidationError {
    /// Indicates a local problem, usually a bug in the library code.
    Local(LocalError),
    /// Indicates a problem with the evidence, for example missing messages,
    /// or messages that cannot be deserialized.
    InvalidEvidence(String),
}

// If fail to deserialize a message when validating the evidence
// it means that the evidence is invalid - a deserialization error would have been
// processed separately, generating its own evidence.
impl From<DirectMessageError> for ProtocolValidationError {
    fn from(error: DirectMessageError) -> Self {
        Self::InvalidEvidence(format!("Failed to deserialize direct message: {error:?}"))
    }
}

impl From<EchoBroadcastError> for ProtocolValidationError {
    fn from(error: EchoBroadcastError) -> Self {
        Self::InvalidEvidence(format!("Failed to deserialize echo broadcast: {error:?}"))
    }
}

impl From<LocalError> for ProtocolValidationError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}

/// An error during deserialization of a direct message.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Direct message error: {0}")]
pub struct DirectMessageError(DeserializationError);

impl DirectMessageError {
    pub(crate) fn new(error: DeserializationError) -> Self {
        Self(error)
    }
}

/// An error during deserialization of an echo broadcast.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Echo broadcast error: {0}")]
pub struct EchoBroadcastError(DeserializationError);

impl EchoBroadcastError {
    pub(crate) fn new(error: DeserializationError) -> Self {
        Self(error)
    }
}
