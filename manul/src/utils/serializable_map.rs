use alloc::{collections::BTreeMap, format};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
    ops::Deref,
};

use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A wrapper for [`BTreeMap`](`alloc::collections::BTreeMap`)
/// that allows it to be serialized in a wider range of formats.
///
/// Some serialization formats/implementations (e.g. `serde_asn1_der`) do not support serializing maps.
/// This implementation serializes maps as sequences of key/value pairs,
/// and checks for duplicate keys on deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializableMap<K, V>(BTreeMap<K, V>);

impl<K, V> From<BTreeMap<K, V>> for SerializableMap<K, V> {
    fn from(source: BTreeMap<K, V>) -> Self {
        Self(source)
    }
}

impl<K, V> Deref for SerializableMap<K, V> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> Serialize for SerializableMap<K, V>
where
    K: Serialize,
    V: Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // TODO: an error here can be covered by a custom `Serializer`,
        // but that's a lot of extra code to test just one line.
        // Is there an easier way?
        // Alternatively, we wait until `#[coverage]` is stabilized.
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for e in self.0.iter() {
            seq.serialize_element(&e)?;
        }
        seq.end()
    }
}

struct MapVisitor<K, V>(PhantomData<(K, V)>);

impl<'de, K, V> Visitor<'de> for MapVisitor<K, V>
where
    K: Debug + Clone + Ord + Deserialize<'de>,
    V: Deserialize<'de>,
{
    type Value = SerializableMap<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("A map serialized as a list of pairs")
    }

    fn visit_seq<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: SeqAccess<'de>,
    {
        let mut map = SerializableMap(BTreeMap::new());

        while let Some((key, value)) = access.next_element::<(K, V)>()? {
            // This clone, and the consequent `Debug` bound on the impl can be removed
            // when `BTreeMap::try_insert()` is stabilized.
            // Or we could call `BTreeMap::contains()` first, but it's more expensive than cloning a key
            // (which will be short).
            let key_clone = key.clone();
            if map.0.insert(key, value).is_some() {
                return Err(de::Error::custom(format!("Duplicate key: {key_clone:?}")));
            }
        }

        Ok(map)
    }
}

impl<'de, K, V> Deserialize<'de> for SerializableMap<K, V>
where
    K: Debug + Clone + Ord + Deserialize<'de>,
    V: Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(MapVisitor::<K, V>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::{vec, vec::Vec};

    use serde::{Deserialize, Serialize};

    use super::SerializableMap;

    fn asn1_serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
        serde_asn1_der::to_vec(value).map_err(|err| err.to_string())
    }

    fn asn1_deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, String> {
        serde_asn1_der::from_bytes(bytes).map_err(|err| err.to_string())
    }

    fn json_serialize<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap()
    }

    fn json_deserialize<'de, T: Deserialize<'de>>(string: &'de str) -> Result<T, String> {
        serde_json::from_str::<T>(string).map_err(|err| err.to_string())
    }

    #[test]
    fn roundtrip() {
        let map = SerializableMap::<u8, u8>(BTreeMap::from([(120, 130), (140, 150)]));
        let map_serialized = asn1_serialize(&map).unwrap();
        let map_back = asn1_deserialize(&map_serialized).unwrap();
        assert_eq!(map, map_back);
    }

    #[test]
    fn representation() {
        // Test that the map is represented identically to a vector of tuples in the serialized data.
        let map = SerializableMap::<u8, u8>(BTreeMap::from([(120, 130), (140, 150)]));
        let map_as_vec = vec![(120u8, 130u8), (140, 150)];
        let map_serialized = asn1_serialize(&map).unwrap();
        let map_as_vec_serialized = asn1_serialize(&map_as_vec).unwrap();
        assert_eq!(map_serialized, map_as_vec_serialized);
    }

    #[test]
    fn duplicate_key() {
        let map_as_vec = vec![(120u8, 130u8), (120, 150)];
        let map_serialized = asn1_serialize(&map_as_vec).unwrap();
        assert_eq!(
            asn1_deserialize::<SerializableMap<u8, u8>>(&map_serialized).unwrap_err(),
            "Serde error: Duplicate key: 120"
        );
    }

    #[test]
    fn serialize_error() {
        // Coverage for possible errors during serialization.
        // ASN.1 cannot serialize BTreeMap, so we will use it to trigger an error.
        let map = SerializableMap(BTreeMap::from([(1u8, BTreeMap::from([(2u8, 3u8)]))]));
        assert!(asn1_serialize(&map)
            .unwrap_err()
            .starts_with("Unsupported Maps variants are not supported by this implementation"));
    }

    #[test]
    fn unexpected_sequence_element() {
        // The deserializer will encounter an integer where it expects a tuple.
        let not_map_serialized = asn1_serialize(&[1u64, 2u64]).unwrap();
        assert!(asn1_deserialize::<SerializableMap<u8, u8>>(&not_map_serialized)
            .unwrap_err()
            .contains("Invalid encoding DER object is not a valid sequence"),);
    }

    #[test]
    fn unexpected_type() {
        // Have to use JSON and not ASN1 here because `serde_asn1_der` doesn't seem to trigger `Visitor::expecting()`.
        let not_map_serialized = json_serialize(&1);
        assert_eq!(
            json_deserialize::<SerializableMap<u8, u8>>(&not_map_serialized).unwrap_err(),
            "invalid type: integer `1`, expected A map serialized as a list of pairs at line 1 column 1"
        );
    }
}
