/// A marker trait for protocol combinators.
pub trait Combinator {}

/// Marks an entry point for a protocol combinator result, so that [`EntryPoint`](`crate::protocol::EntryPoint`)
/// can be derived automatically for it.
pub trait CombinatorEntryPoint {
    /// The type of the combinator.
    type Combinator: Combinator;
}
