use alloc::{boxed::Box, format};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::errors::{DeserializationError, LocalError};
use crate::session::WireFormat;

// Serialization

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

/// A serializer for protocol messages.
#[derive(Debug)]
pub struct Serializer(Box<dyn ObjectSafeSerializer + Send + Sync>);

impl Serializer {
    pub(crate) fn new<F: WireFormat>() -> Self {
        Self(Box::new(SerializerWrapper::<F>(PhantomData)))
    }

    /// Serializes a `serde`-serializable object.
    pub fn serialize<T>(&self, value: T) -> Result<Box<[u8]>, LocalError>
    where
        T: 'static + Serialize,
    {
        let boxed_value: Box<dyn erased_serde::Serialize> = Box::new(value);
        self.0.serialize(boxed_value)
    }
}

// Deserialization

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

/// A deserializer for protocol messages.
#[derive(Debug)]
pub struct Deserializer(Box<dyn ObjectSafeDeserializerFactory + Send + Sync>);

impl Deserializer {
    pub(crate) fn new<F>() -> Self
    where
        F: WireFormat,
    {
        Self(Box::new(DeserializerFactoryWrapper::<F>(PhantomData)))
    }

    /// Deserializes a `serde`-deserializable object.
    pub fn deserialize<'de, T>(&self, bytes: &'de [u8]) -> Result<T, DeserializationError>
    where
        T: Deserialize<'de>,
    {
        let mut deserializer = self.0.make_erased_deserializer(bytes);
        erased_serde::deserialize::<T>(&mut deserializer)
            .map_err(|err| DeserializationError::new(format!("Deserialization error: {err:?}")))
    }
}

#[cfg(test)]
mod tests {
    use impls::impls;

    use super::{Deserializer, Serializer};

    #[test]
    fn test_concurrency_bounds() {
        assert!(impls!(Serializer: Send));
        assert!(impls!(Serializer: Sync));
        assert!(impls!(Deserializer: Send));
        assert!(impls!(Deserializer: Sync));
    }
}
