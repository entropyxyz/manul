/*!
Utilities for testing protocols.

The [`TestSessionParams`] provides an implementation of the
[`SessionParameters`](crate::session::SessionParameters) trait,
which in turn is used to setup [`Session`](crate::session::Session)s to drive the protocol.

The [`run_sync()`] method is helpful to execute a protocol synchronously and collect the outcomes.
*/

mod run_sync;
mod session_parameters;
mod wire_format;

pub use run_sync::{run_sync, run_sync_with_tracing};
pub use session_parameters::{TestHasher, TestSessionParams, TestSignature, TestSigner, TestVerifier};
pub use wire_format::{BinaryFormat, HumanReadableFormat};
