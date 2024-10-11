use core::fmt::Debug;

#[derive(Debug, Clone)]
pub struct LocalError(String);

impl LocalError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Debug, Clone)]
pub struct RemoteError(String);

impl RemoteError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
