use alloc::{boxed::Box, format};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::errors::{DeserializationError, LocalError};
use crate::session::WireFormat;

trait ObjectSafeSerializer: Debug {
    fn serialize(&self, value: Box<dyn erased_serde::Serialize>) -> Result<Box<[u8]>, LocalError>;
}

// `fn(F)` makes the type `Send` + `Sync` even if `F` isn't.
#[derive(Debug)]
struct SerializerWrapper<F: WireFormat>(PhantomData<fn(F)>);

impl<F: WireFormat> ObjectSafeSerializer for SerializerWrapper<F> {
    fn serialize(&self, value: Box<dyn erased_serde::Serialize>) -> Result<Box<[u8]>, LocalError> {
        F::serialize(&value)
    }
}

// `fn(F)` makes the type `Send` + `Sync` even if `F` isn't.
#[derive(Debug)]
struct DeserializerFactoryWrapper<F>(PhantomData<fn(F)>);

trait ObjectSafeDeserializerFactory: Debug {
    fn make_erased_deserializer<'de>(&self, bytes: &'de [u8]) -> Box<dyn erased_serde::Deserializer<'de> + 'de>;
}

impl<F> ObjectSafeDeserializerFactory for DeserializerFactoryWrapper<F>
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
pub struct BoxedFormat {
    serializer: Box<dyn ObjectSafeSerializer + Send + Sync>,
    deserializer_factory: Box<dyn ObjectSafeDeserializerFactory + Send + Sync>,
}

impl BoxedFormat {
    pub(crate) fn new<F: WireFormat>() -> Self {
        Self {
            serializer: Box::new(SerializerWrapper::<F>(PhantomData)),
            deserializer_factory: Box::new(DeserializerFactoryWrapper::<F>(PhantomData)),
        }
    }

    /// Serializes a `serde`-serializable object.
    pub(crate) fn serialize<T>(&self, value: T) -> Result<Box<[u8]>, LocalError>
    where
        T: 'static + Serialize,
    {
        let boxed_value: Box<dyn erased_serde::Serialize> = Box::new(value);
        self.serializer.serialize(boxed_value)
    }

    /// Deserializes a `serde`-deserializable object.
    pub(crate) fn deserialize<'de, T>(&self, bytes: &'de [u8]) -> Result<T, DeserializationError>
    where
        T: Deserialize<'de>,
    {
        let mut deserializer = self.deserializer_factory.make_erased_deserializer(bytes);
        erased_serde::deserialize::<T>(&mut deserializer)
            .map_err(|err| DeserializationError::new(format!("Deserialization error: {err:?}")))
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
