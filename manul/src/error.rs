use core::fmt::Debug;

/// Local error: {0}
#[derive(displaydoc::Display, Debug, Clone)]
pub struct LocalError(String);

impl LocalError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Remote error: {0}
#[derive(displaydoc::Display, Debug, Clone)]
pub struct RemoteError(String);

impl RemoteError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
