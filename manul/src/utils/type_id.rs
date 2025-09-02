use core::any::TypeId;

/// A dyn safe trait to get the type's ID.
pub(crate) trait DynTypeId: 'static {
    /// Returns the type ID of the implementing type.
    fn get_type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }
}

impl<T: 'static> DynTypeId for T {}
