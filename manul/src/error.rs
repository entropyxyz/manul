use core::fmt::Debug;

#[derive(Debug, Clone)]
pub struct LocalError(String);

impl LocalError {
    pub fn new(message: String) -> Self {
        Self(message)
    }
}

#[derive(Debug, Clone)]
pub struct RemoteError(String);

impl RemoteError {
    pub fn new(message: &str) -> Self {
        Self(message.into())
    }
}
