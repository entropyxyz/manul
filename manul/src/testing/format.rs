use alloc::{boxed::Box, string::ToString};

use serde::Serialize;

use crate::{protocol::LocalError, session::Format};

/// A binary format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct Binary;

impl Format for Binary {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError> {
        postcard::to_allocvec(&value)
            .map(|vec| vec.into())
            .map_err(|err| LocalError::new(err.to_string()))
    }

    type Des<'de> = postcard::Deserializer<'de, postcard::de_flavors::Slice<'de>>;

    fn deserializer<'de>(bytes: &'de [u8]) -> Self::Des<'de>
    where
        for<'a> &'a mut Self::Des<'de>: serde::Deserializer<'de>,
    {
        postcard::Deserializer::from_flavor(postcard::de_flavors::Slice::new(bytes))
    }
}
