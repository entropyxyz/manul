/*!
Utilities for testing protocols.

The [`TestSessionParams`] provides an implementation of the
[`SessionParameters`](crate::session::SessionParameters) trait,
which in turn is used to setup [`Session`](crate::session::Session)s to drive the protocol.

The [`run_sync()`] method is helpful to execute a protocol synchronously and collect the outcomes.
*/

mod misbehave;
mod run_sync;
mod session_parameters;
mod wire_format;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use misbehave::{
    check_evidence_with_behavior, check_invalid_message_evidence, run_with_one_malicious_party, CheckPart,
};
pub use run_sync::{run_sync, ExecutionResult};
pub use session_parameters::{TestHasher, TestSessionParams, TestSignature, TestSigner, TestVerifier};
pub use wire_format::{BinaryFormat, HumanReadableFormat};
