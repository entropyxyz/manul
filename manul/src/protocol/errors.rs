use alloc::string::String;
use core::fmt::Debug;

use super::round::Round;

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
pub enum ReceiveError<Id, R: Round<Id> + ?Sized> {
    /// A local error, indicating an implemenation bug or a misuse by the upper layer.
    Local(LocalError),
    /// A provable error occurred.
    Protocol(R::ProtocolError),
    /// An unprovable error occurred.
    Unprovable(RemoteError),
}

impl<Id, R> ReceiveError<Id, R>
where
    R: Round<Id>,
{
    pub(crate) fn map<NR, F>(self, f: F) -> ReceiveError<Id, NR>
    where
        F: Fn(R::ProtocolError) -> NR::ProtocolError,
        NR: Round<Id>,
    {
        match self {
            Self::Local(err) => ReceiveError::Local(err),
            Self::Unprovable(err) => ReceiveError::Unprovable(err),
            Self::Protocol(err) => ReceiveError::Protocol(f(err)),
        }
    }
}

impl<Id, R> From<LocalError> for ReceiveError<Id, R>
where
    R: Round<Id>,
{
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}

impl<Id, R> From<RemoteError> for ReceiveError<Id, R>
where
    R: Round<Id>,
{
    fn from(error: RemoteError) -> Self {
        Self::Unprovable(error)
    }
}
