use digest::generic_array::typenum;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::session::{SessionParameters, WireFormat};

/// A simple signer for testing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestSigner(u8);

/// A verifier corresponding to [`TestSigner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestVerifier(u8);

/// A signature produced by [`TestSigner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TestSignature {
    signed_by: u8,
    randomness: u64,
}

impl TestSigner {
    /// Creates a new signer for testing purposes.
    pub fn new(id: u8) -> Self {
        Self(id)
    }
}

impl<D: digest::Digest> signature::RandomizedDigestSigner<D, TestSignature> for TestSigner {
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        _digest: D,
    ) -> Result<TestSignature, signature::Error> {
        Ok(TestSignature {
            signed_by: self.0,
            randomness: rng.next_u64(),
        })
    }
}

impl signature::Keypair for TestSigner {
    type VerifyingKey = TestVerifier;

    fn verifying_key(&self) -> Self::VerifyingKey {
        TestVerifier(self.0)
    }
}

impl<D: digest::Digest> signature::DigestVerifier<D, TestSignature> for TestVerifier {
    fn verify_digest(&self, _digest: D, signature: &TestSignature) -> Result<(), signature::Error> {
        if self.0 == signature.signed_by {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

/// A very simple hasher for testing purposes.
/// Not in any way secure.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestHasher {
    cursor: usize,
    buffer: [u8; 32],
}

impl digest::HashMarker for TestHasher {}

impl digest::Update for TestHasher {
    fn update(&mut self, data: &[u8]) {
        // A very simple algorithm for testing, just xor the data in buffer-sized chunks.
        for byte in data {
            *self.buffer.get_mut(self.cursor).expect("index within bounds") ^= byte;
            self.cursor = (self.cursor + 1) % 32;
        }
    }
}

impl digest::FixedOutput for TestHasher {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        AsMut::<[u8]>::as_mut(out).copy_from_slice(&self.buffer)
    }
}

impl digest::OutputSizeUser for TestHasher {
    type OutputSize = typenum::U8;
}

/// An implementation of [`SessionParameters`] using the testing signer/verifier types.
#[derive(Debug, Clone, Copy)]
pub struct TestSessionParams<S>(core::marker::PhantomData<S>);

impl<F: WireFormat> SessionParameters for TestSessionParams<F> {
    type Signer = TestSigner;
    type Verifier = TestVerifier;
    type Signature = TestSignature;
    type Digest = TestHasher;
    type WireFormat = F;
}

#[cfg(test)]
mod tests {
    use impls::impls;

    use super::TestHasher;

    #[test]
    fn test_hasher_bounds() {
        assert!(impls!(TestHasher: digest::Digest));
    }
}
