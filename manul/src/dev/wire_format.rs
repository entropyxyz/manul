use alloc::{boxed::Box, string::ToString};

use serde::Serialize;
use serde_persistent_deserializer::{AsTransientDeserializer, PersistentDeserializer};

use crate::{protocol::LocalError, session::WireFormat};

/// A binary format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct BinaryFormat;

/// A wrapper for a Postcard deserializer.
#[allow(missing_debug_implementations)]
pub struct PostcardDeserializer<'de>(postcard::Deserializer<'de, postcard::de_flavors::Slice<'de>>);

impl<'de> AsTransientDeserializer<'de> for PostcardDeserializer<'de> {
    type Error = postcard::Error;

    fn as_transient_deserializer<'a>(&'a mut self) -> impl serde::Deserializer<'de, Error = Self::Error> {
        &mut self.0
    }
}

impl WireFormat for BinaryFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError> {
        postcard::to_allocvec(&value)
            .map(|vec| vec.into())
            .map_err(|err| LocalError::new(err.to_string()))
    }

    type Deserializer<'de> = PersistentDeserializer<PostcardDeserializer<'de>>;

    fn deserializer(bytes: &[u8]) -> Self::Deserializer<'_> {
        let flavor = postcard::de_flavors::Slice::new(bytes);
        let deserializer = postcard::Deserializer::from_flavor(flavor);
        PersistentDeserializer::new(PostcardDeserializer(deserializer))
    }
}

/// A human-readable format to use in tests.
#[derive(Debug, Clone, Copy)]
pub struct HumanReadableFormat;

/// A wrapper for a JSON deserializer.
#[allow(missing_debug_implementations)]
pub struct JSONDeserializer<'de>(serde_json::Deserializer<serde_json::de::SliceRead<'de>>);

impl<'de> AsTransientDeserializer<'de> for JSONDeserializer<'de> {
    type Error = serde_json::Error;

    fn as_transient_deserializer<'a>(&'a mut self) -> impl serde::Deserializer<'de, Error = Self::Error> {
        &mut self.0
    }
}

impl WireFormat for HumanReadableFormat {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError> {
        serde_json::to_vec(&value)
            .map(|vec| vec.into())
            .map_err(|err| LocalError::new(err.to_string()))
    }

    type Deserializer<'de> = PersistentDeserializer<JSONDeserializer<'de>>;

    fn deserializer(bytes: &[u8]) -> Self::Deserializer<'_> {
        let deserializer = serde_json::Deserializer::from_slice(bytes);
        PersistentDeserializer::new(JSONDeserializer(deserializer))
    }
}
