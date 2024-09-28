use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signer(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Verifier(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature {
    signed_by: u8,
    randomness: u64,
}

impl Signer {
    pub fn new(id: u8) -> Self {
        Self(id)
    }

    pub fn as_integer(&self) -> u8 {
        self.0
    }
}

impl<D: digest::Digest> signature::DigestSigner<D, Signature> for Signer {
    fn try_sign_digest(&self, _digest: D) -> Result<Signature, signature::Error> {
        Ok(Signature {
            signed_by: self.0,
            randomness: OsRng.next_u64(),
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
