/*!
Utilities for testing protocols.

The [`TestSessionParams`] provides an implementation of the
[`SessionParameters`](crate::session::SessionParameters) trait,
which in turn is used to setup [`Session`](crate::session::Session)s to drive the protocol.

The [`run_sync()`] method is helpful to execute a protocol synchronously and collect the outcomes.
*/

mod extend;
mod run_sync;
mod session_parameters;
mod wire_format;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use extend::{ExtendableEntryPoint, RoundExtension};
pub use run_sync::{run_sync, ExecutionResult};
pub use session_parameters::{TestHasher, TestSessionParams, TestSignature, TestSigner, TestVerifier};
pub use wire_format::{BinaryFormat, HumanReadableFormat};
