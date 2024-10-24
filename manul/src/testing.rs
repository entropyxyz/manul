/*!
Utilities for testing protocols.

When testing round based protocols it can be complicated to "inject" the proper faults into the
process, e.g. to emulate a malicious participant. This module provides facilities to make this
easier, by providing a [`RoundOverride`] type along with a [`round_override`] macro.

The [`TestSessionParams`] provides an implementation of the [`SessionParameters`](crate::session::SessionParameters) trait,
which in turn is used to setup [`Session`](crate::session::Session)s to drive the protocol.

The [`run_sync`] method is helpful to execute a protocol synchronously and collect the outcomes.
*/

mod identity;
mod macros;
mod run_sync;

pub use identity::{TestHasher, TestSessionParams, TestSignature, TestSigner, TestVerifier};
pub use macros::{round_override, RoundOverride, RoundWrapper};
pub use run_sync::run_sync;
