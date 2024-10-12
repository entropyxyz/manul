use core::fmt::Debug;

use rand_core::CryptoRngCore;

pub trait Digest {
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self;
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;
}

pub trait RandomizedDigestSigner<D: Digest, S> {
    type Error: Debug;
    fn try_sign_digest_with_rng(&self, rng: &mut impl CryptoRngCore, digest: D) -> Result<S, Self::Error>;
}

pub trait Keypair {
    type VerifyingKey: Clone;

    fn verifying_key(&self) -> Self::VerifyingKey;
}

pub trait DigestVerifier<D: Digest, S> {
    type Error: Debug;
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Self::Error>;
}
