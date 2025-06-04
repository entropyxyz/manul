//! Assorted utilities.

mod serializable_map;
mod traits;
mod type_id;

pub use serializable_map::SerializableMap;
pub use traits::{MapValues, MapValuesRef, Without};

pub(crate) use type_id::DynTypeId;
