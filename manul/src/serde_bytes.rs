//! A simple helper to support serialization of `Box<[u8]>` in `serde`.

use core::fmt;

use serde::{de, Deserializer, Serializer};

// A type of a trait alias, to work around https://github.com/rust-lang/rust/issues/113517
// If not for that issue, we could just use `TryFrom<&'a [u8]>` directly in the bounds.
pub(crate) trait TryFromBytes<'a, E>: TryFrom<&'a [u8], Error = E> {}

struct BoxVisitor;

impl<'de> de::Visitor<'de> for BoxVisitor {
    type Value = Box<[u8]>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a bytestring")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.into())
    }
}

/// A helper function that will serialize a byte array efficiently
/// depending on whether the target format is text or binary based.
pub(crate) fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_bytes(obj.as_ref())
}

/// A helper function that will deserialize from a byte array,
/// matching the format used by [`serde_serialize`].
pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Box<[u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(BoxVisitor)
}
