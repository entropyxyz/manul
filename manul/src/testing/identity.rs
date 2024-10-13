use digest::generic_array::typenum;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

/// A simple signer for testing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signer(u8);

/// A verifier corresponding to [`Signer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Verifier(u8);

/// A signature produced by [`Signer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature {
    signed_by: u8,
    randomness: u64,
}

impl Signer {
    /// Creates a new signer.
    pub fn new(id: u8) -> Self {
        Self(id)
    }
}

impl<D: digest::Digest> signature::RandomizedDigestSigner<D, Signature> for Signer {
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        _digest: D,
    ) -> Result<Signature, signature::Error> {
        Ok(Signature {
            signed_by: self.0,
            randomness: rng.next_u64(),
        })
    }
}

impl signature::Keypair for Signer {
    type VerifyingKey = Verifier;

    fn verifying_key(&self) -> Self::VerifyingKey {
        Verifier(self.0)
    }
}

impl<D: digest::Digest> signature::DigestVerifier<D, Signature> for Verifier {
    fn verify_digest(&self, _digest: D, signature: &Signature) -> Result<(), signature::Error> {
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
pub struct Hasher {
    cursor: usize,
    buffer: [u8; 32],
}

impl digest::HashMarker for Hasher {}

impl digest::Update for Hasher {
    fn update(&mut self, data: &[u8]) {
        // A very simple algorithm for testing, just xor the data in buffer-sized chunks.
        for byte in data {
            *self.buffer.get_mut(self.cursor).expect("index within bounds") ^= byte;
            self.cursor = (self.cursor + 1) % 32;
        }
    }
}

impl digest::FixedOutput for Hasher {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        AsMut::<[u8]>::as_mut(out).copy_from_slice(&self.buffer)
    }
}

impl digest::OutputSizeUser for Hasher {
    type OutputSize = typenum::U8;
}

#[cfg(test)]
mod tests {
    use impls::impls;

    use super::Hasher;

    #[test]
    fn test_hasher_bounds() {
        assert!(impls!(Hasher: digest::Digest));
    }
}
