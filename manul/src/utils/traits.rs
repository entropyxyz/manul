use alloc::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    format,
};

use crate::protocol::{EvidenceError, LocalError};

/// Implemented by collections allowing removal of a specific item.
pub trait Without<T> {
    /// Returns `self` with `item` removed.
    fn without(self, item: &T) -> Self;
}

impl<T: Ord> Without<T> for BTreeSet<T> {
    fn without(self, item: &T) -> Self {
        let mut set = self;
        set.remove(item);
        set
    }
}

impl<K: Ord, V> Without<K> for BTreeMap<K, V> {
    /// Returns `self` with the pair corresponding to the key `item` removed.
    fn without(self, item: &K) -> Self {
        let mut map = self;
        map.remove(item);
        map
    }
}

/// Implemented by map-like collections allowing mapping over values.
pub trait MapValues<OldV, NewV> {
    /// The type of the resulting map.
    type Result;

    /// Map over values of `self`, consuming it and returning the modified collection.
    fn map_values<F>(self, f: F) -> Self::Result
    where
        F: Fn(OldV) -> NewV;
}

/// Implemented by map-like collections allowing mapping over values.
pub trait MapValuesRef<OldV, NewV> {
    /// The type of the resulting map.
    type Result;

    /// Map over values of `self`, returning a new collection.
    fn map_values_ref<F>(&self, f: F) -> Self::Result
    where
        F: Fn(&OldV) -> NewV;
}

impl<K: Ord, OldV, NewV> MapValues<OldV, NewV> for BTreeMap<K, OldV> {
    type Result = BTreeMap<K, NewV>;

    fn map_values<F>(self, f: F) -> Self::Result
    where
        F: Fn(OldV) -> NewV,
    {
        self.into_iter().map(|(key, value)| (key, f(value))).collect()
    }
}

impl<K: Ord + Clone, OldV, NewV> MapValuesRef<OldV, NewV> for BTreeMap<K, OldV> {
    type Result = BTreeMap<K, NewV>;

    fn map_values_ref<F>(&self, f: F) -> Self::Result
    where
        F: Fn(&OldV) -> NewV,
    {
        self.iter().map(|(key, value)| (key.clone(), f(value))).collect()
    }
}

/// Returns an error if `condition` is false.
///
/// A shortcut to use in evidence checking logic.
pub fn verify_that(condition: bool) -> Result<(), EvidenceError> {
    if condition {
        Ok(())
    } else {
        Err(EvidenceError::InvalidEvidence(
            "the reported error cannot be reproduced".into(),
        ))
    }
}

/// A helper trait for map lookup in the context of protocol rounds.
pub trait GetOrLocalError<K, V> {
    /// Try to get the value by `key`; if not found, treat as a [`LocalError`].
    fn get_or_local_error(&self, container: &str, key: &K) -> Result<&V, LocalError>;
}

impl<K: Ord + Debug, V> GetOrLocalError<K, V> for BTreeMap<K, V> {
    fn get_or_local_error(&self, container: &str, key: &K) -> Result<&V, LocalError> {
        self.get(key)
            .ok_or_else(|| LocalError::new(format!("Key {key:?} not found in {container}")))
    }
}

/// A helper trait for map lookup in the context of evidence verification.
pub trait GetOrInvalidEvidence<K, V> {
    /// Try to get the value by `key`; if not found, treat as an invalid evidence.
    fn get_or_invalid_evidence(&self, container: &str, key: &K) -> Result<&V, EvidenceError>;
}

impl<K: Ord + Debug, V> GetOrInvalidEvidence<K, V> for BTreeMap<K, V> {
    fn get_or_invalid_evidence(&self, container: &str, key: &K) -> Result<&V, EvidenceError> {
        self.get(key)
            .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Key {key:?} not found in {container}")))
    }
}
