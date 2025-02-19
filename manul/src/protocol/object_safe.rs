use alloc::{boxed::Box, format};

use super::{
    errors::LocalError,
    round::{PartyId, Protocol, Round},
    round_id::RoundId,
};

/// A wrapped new round that may be returned by [`Round::finalize`]
/// or [`EntryPoint::make_round`](`crate::protocol::EntryPoint::make_round`).
#[derive_where::derive_where(Debug)]
pub struct BoxedRound<Id: PartyId, P: Protocol<Id>>(Box<dyn Round<Id, Protocol = P>>);

impl<Id: PartyId, P: Protocol<Id>> BoxedRound<Id, P> {
    /// Wraps an object implementing the dynamic round trait ([`Round`](`crate::protocol::Round`)).
    pub fn new_dynamic<R: Round<Id, Protocol = P>>(round: R) -> Self {
        Self(Box::new(round))
    }

    pub(crate) fn as_ref(&self) -> &dyn Round<Id, Protocol = P> {
        self.0.as_ref()
    }

    pub(crate) fn into_boxed(self) -> Box<dyn Round<Id, Protocol = P>> {
        self.0
    }

    fn boxed_type_is<T: 'static>(&self) -> bool {
        core::any::TypeId::of::<T>() == self.0.get_type_id()
    }

    /// Attempts to extract an object of a concrete type, preserving the original on failure.
    pub fn try_downcast<T: Round<Id>>(self) -> Result<T, Self> {
        if self.boxed_type_is::<T>() {
            // Safety: This is safe since we just checked that we are casting to the correct type.
            let boxed_downcast = unsafe { Box::<T>::from_raw(Box::into_raw(self.0) as *mut T) };
            Ok(*boxed_downcast)
        } else {
            Err(self)
        }
    }

    /// Attempts to extract an object of a concrete type.
    ///
    /// Fails if the wrapped type is not `T`.
    pub fn downcast<T: Round<Id>>(self) -> Result<T, LocalError> {
        self.try_downcast()
            .map_err(|_| LocalError::new(format!("Failed to downcast into type {}", core::any::type_name::<T>())))
    }

    /// Attempts to provide a reference to an object of a concrete type.
    ///
    /// Fails if the wrapped type is not `T`.
    pub fn downcast_ref<T: Round<Id>>(&self) -> Result<&T, LocalError> {
        if self.boxed_type_is::<T>() {
            let ptr: *const dyn Round<Id, Protocol = P> = self.0.as_ref();
            // Safety: This is safe since we just checked that we are casting to the correct type.
            Ok(unsafe { &*(ptr as *const T) })
        } else {
            Err(LocalError::new(format!(
                "Failed to downcast into type {}",
                core::any::type_name::<T>()
            )))
        }
    }

    /// Returns the round's ID.
    pub fn id(&self) -> RoundId {
        // This constructs a new `TransitionInfo` object, so calling this method inside `Session`
        // has mild performance drawbacks.
        // This is mostly exposed for the sake of users writing `Misbehave` impls for testing.
        self.0.transition_info().id()
    }
}
