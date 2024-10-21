use manul::{
    protocol::{DeserializationError, LocalError},
    session::Format,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Bincode;

impl Format for Bincode {
    fn serialize<T: Serialize>(value: T) -> Result<Box<[u8]>, LocalError> {
        bincode::serde::encode_to_vec(value, bincode::config::standard())
            .map(|vec| vec.into())
            .map_err(|err| LocalError::new(err.to_string()))
    }

    fn deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, DeserializationError> {
        bincode::serde::decode_borrowed_from_slice(bytes, bincode::config::standard())
            .map_err(|err| DeserializationError::new(err.to_string()))
    }
}
