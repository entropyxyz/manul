use alloc::string::String;
use core::fmt::Debug;

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
