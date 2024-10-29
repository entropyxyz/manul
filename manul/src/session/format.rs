use alloc::{boxed::Box, format};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::protocol::{DeserializationError, LocalError};

/// A (de)serializer that will be used for the protocol messages.
pub trait Format: 'static + Send + Sync + Debug {
    /// Serializes the given object into a bytestring.
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError>;

    /// The deserializer type.
    type Des<'de>: 'de;

    /// Creates a `serde` deserializer given a bytestring.
    fn deserializer<'de>(bytes: &'de [u8]) -> Self::Des<'de>
    where
        for<'a> &'a mut Self::Des<'de>: serde::Deserializer<'de>;
}

// Serialization

trait ObjectSafeSerializer: Debug {
    fn serialize(&self, value: Box<dyn erased_serde::Serialize>) -> Result<Box<[u8]>, LocalError>;
}

/// A serializer for protocol messages.
#[derive(Debug)]
pub struct Serializer(Box<dyn ObjectSafeSerializer + Send + Sync>);

impl Serializer {
    /// Serializes a `serde`-serializable object.
    pub fn serialize<T: Serialize + 'static>(&self, value: T) -> Result<Box<[u8]>, LocalError> {
        let boxed_value: Box<dyn erased_serde::Serialize> = Box::new(value);
        self.0.serialize(boxed_value)
    }
}

// Deserialization

#[derive(Debug)]
struct DeserializerFactoryWrapper<F>(PhantomData<F>);

trait ObjectSafeDeserializerFactory: Debug {
    fn make_deserializer<'de>(&self, bytes: &'de [u8]) -> Box<dyn ObjectSafeDeserializer<'de> + 'de>;
}

impl<F> ObjectSafeDeserializerFactory for DeserializerFactoryWrapper<F>
where
    F: Format,
    for<'a, 'de> &'a mut F::Des<'de>: serde::Deserializer<'de>,
{
    fn make_deserializer<'de>(&self, bytes: &'de [u8]) -> Box<dyn ObjectSafeDeserializer<'de> + 'de> {
        let deserializer = F::deserializer(bytes);
        Box::new(deserializer)
    }
}

trait ObjectSafeDeserializer<'de> {
    fn get_erased<'s>(&'s mut self) -> Box<dyn erased_serde::Deserializer<'de> + 's>
    where
        'de: 's;
}

impl<'de, D: 'de> ObjectSafeDeserializer<'de> for D
where
    for<'any> &'any mut D: serde::Deserializer<'de>,
{
    fn get_erased<'s>(&'s mut self) -> Box<dyn erased_serde::Deserializer<'de> + 's>
    where
        'de: 's,
    {
        Box::new(<dyn erased_serde::Deserializer<'_>>::erase(self))
    }
}

/// A deserializer for protocol messages.
#[derive(Debug)]
pub struct Deserializer(Box<dyn ObjectSafeDeserializerFactory + Send + Sync>);

impl Deserializer {
    pub(crate) fn new<F>() -> Self
    where
        F: Format,
        for<'a, 'de> &'a mut F::Des<'de>: serde::Deserializer<'de>,
    {
        Self(Box::new(DeserializerFactoryWrapper(PhantomData)))
    }

    /// Deserializes a `serde`-deserializable object.
    pub fn deserialize<'de, T>(&self, bytes: &'de [u8]) -> Result<T, DeserializationError>
    where
        T: Deserialize<'de>,
    {
        let mut deserializer = self.0.make_deserializer(bytes);
        let mut erased = deserializer.get_erased();
        erased_serde::deserialize::<T>(&mut erased)
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
