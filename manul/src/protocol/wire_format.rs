use alloc::{boxed::Box, format, string::String};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::{protocol::LocalError, session::WireFormat};

/// An error that can be returned during deserialization.
#[derive(displaydoc::Display, Debug, Clone)]
#[displaydoc("Error deserializing into {target_type}: {message}")]
pub(crate) struct DeserializationError {
    target_type: String,
    message: String,
}

impl DeserializationError {
    /// Creates a new deserialization error.
    pub fn new<T>(message: impl Into<String>) -> Self {
        Self {
            target_type: core::any::type_name::<T>().into(),
            message: message.into(),
        }
    }
}

trait DynSerializer: Debug {
    fn serialize(&self, value: Box<dyn erased_serde::Serialize>) -> Result<Box<[u8]>, LocalError>;
}

// `fn(F)` makes the type `Send` + `Sync` even if `F` isn't.
#[derive(Debug)]
struct SerializerObject<F: WireFormat>(PhantomData<fn() -> F>);

impl<F: WireFormat> DynSerializer for SerializerObject<F> {
    fn serialize(&self, value: Box<dyn erased_serde::Serialize>) -> Result<Box<[u8]>, LocalError> {
        F::serialize(&value)
    }
}

// `fn(F)` makes the type `Send` + `Sync` even if `F` isn't.
#[derive(Debug)]
struct DeserializerFactoryObject<F>(PhantomData<fn() -> F>);

trait DynDeserializerFactory: Debug {
    fn make_erased_deserializer<'de>(&self, bytes: &'de [u8]) -> Box<dyn erased_serde::Deserializer<'de> + 'de>;
}

impl<F> DynDeserializerFactory for DeserializerFactoryObject<F>
where
    F: WireFormat,
{
    fn make_erased_deserializer<'de>(&self, bytes: &'de [u8]) -> Box<dyn erased_serde::Deserializer<'de> + 'de> {
        let deserializer = F::deserializer(bytes);
        Box::new(<dyn erased_serde::Deserializer<'_>>::erase(deserializer))
    }
}

/// A serializer/deserializer for protocol messages.
#[derive(Debug)]
pub(crate) struct BoxedFormat {
    serializer: Box<dyn DynSerializer + Send + Sync>,
    deserializer_factory: Box<dyn DynDeserializerFactory + Send + Sync>,
}

impl BoxedFormat {
    pub fn new<F: WireFormat>() -> Self {
        Self {
            serializer: Box::new(SerializerObject::<F>(PhantomData)),
            deserializer_factory: Box::new(DeserializerFactoryObject::<F>(PhantomData)),
        }
    }

    /// Serializes a `serde`-serializable object.
    pub fn serialize<T>(&self, value: T) -> Result<Box<[u8]>, LocalError>
    where
        T: 'static + Serialize,
    {
        let boxed_value: Box<dyn erased_serde::Serialize> = Box::new(value);
        self.serializer.serialize(boxed_value)
    }

    /// Deserializes a `serde`-deserializable object.
    pub fn deserialize<'de, T>(&self, bytes: &'de [u8]) -> Result<T, DeserializationError>
    where
        T: Deserialize<'de>,
    {
        let mut deserializer = self.deserializer_factory.make_erased_deserializer(bytes);
        erased_serde::deserialize::<T>(&mut deserializer)
            .map_err(|err| DeserializationError::new::<T>(format!("{err:?}")))
    }
}

#[cfg(test)]
mod tests {
    use impls::impls;

    use super::BoxedFormat;

    #[test]
    fn test_concurrency_bounds() {
        assert!(impls!(BoxedFormat: Send));
        assert!(impls!(BoxedFormat: Sync));
    }
}
