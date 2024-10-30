use alloc::{boxed::Box, format};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::protocol::{DeserializationError, LocalError};

/*
Why the asymmetry between serialization and deserialization?

If we had a method returning an object of a type implementing `serde::Serializer`,
we could organize the serialization in the same way as deserialization.
But libraries generally expose `T where &mut T: Serializer`,
and it's tricky to write a similar persistent wrapper as we do for the deserializer
(see https://github.com/fjarri/serde-persistent-deserializer/issues/2).

So for serialization we have to instead type-erase the value itself and pass it somewhere
where the serializer type is known (`ObjectSafeSerializer::serialize()` impl);
but for the deserialization we instead type-erase the deserializer and pass it somewhere
the type of the target value is known (`Deserializer::deserialize()`).

One consequence of this is the `'static` requirement for the serialized type,
because we have to put the value in a box;
if we could instead type-erase the serializer, we wouldn't need that.
*/

/// A (de)serializer that will be used for the protocol messages.
pub trait WireFormat: 'static + Send + Sync + Debug {
    /// Serializes the given object into a bytestring.
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError>;

    /// The deserializer type.
    type Deserializer<'de>: serde::Deserializer<'de>;

    /// Creates a `serde` deserializer given a bytestring.
    fn deserializer(bytes: &[u8]) -> Self::Deserializer<'_>;

    // A helper method for use on the session level when both `WireFormat` and `T` are known at the same point.

    /// Deserializes the given bytestring into `T`.
    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, DeserializationError> {
        let deserializer = Self::deserializer(bytes);
        T::deserialize(deserializer).map_err(|err| DeserializationError::new(format!("Deserialization error: {err:?}")))
    }
}
