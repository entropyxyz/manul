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

// If `rustcrypto-traits` is not enabled, we can directly implement our traits for the testing Signers/Verifiers.
// If it is, it will conflict with the generic impls for RustCrypto traits
// (because they declare, basically, "if a RustCrypto trait is implemented for this, then our house trait is too").
// So in this case we need to implement RustCrypto traits instead,
// and rely on generic impls to implement the house traits.

#[cfg(not(feature = "rustcrypto-traits"))]
mod house_trait_impls {

    use rand_core::CryptoRngCore;

    use crate::session::{Digest, DigestVerifier, Keypair, RandomizedDigestSigner};

    use super::{Signature, Signer, Verifier};

    impl<D: Digest> RandomizedDigestSigner<D, Signature> for Signer {
        type Error = ();
        fn try_sign_digest_with_rng(&self, rng: &mut impl CryptoRngCore, _digest: D) -> Result<Signature, Self::Error> {
            Ok(Signature {
                signed_by: self.0,
                randomness: rng.next_u64(),
            })
        }
    }

    impl Keypair for Signer {
        type VerifyingKey = Verifier;

        fn verifying_key(&self) -> Self::VerifyingKey {
            Verifier(self.0)
        }
    }

    impl<D: Digest> DigestVerifier<D, Signature> for Verifier {
        type Error = ();
        fn verify_digest(&self, _digest: D, signature: &Signature) -> Result<(), Self::Error> {
            if self.0 == signature.signed_by {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}

#[cfg(feature = "rustcrypto-traits")]
mod rustcrypto_trait_impls {

    use rand_core::CryptoRngCore;

    use super::{Signature, Signer, Verifier};

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
}
