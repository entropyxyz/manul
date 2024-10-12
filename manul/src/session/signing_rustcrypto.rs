use super::signing::{Digest, DigestVerifier, Keypair, RandomizedDigestSigner};

use rand_core::CryptoRngCore;

impl<T> Digest for T
where
    T: digest::Digest,
{
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        <T as digest::Digest>::new_with_prefix(data)
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        <T as digest::Digest>::chain_update(self, data)
    }
}

impl<T, D, S> RandomizedDigestSigner<D, S> for T
where
    T: signature::RandomizedDigestSigner<D, S>,
    D: digest::Digest,
{
    type Error = signature::Error;
    fn try_sign_digest_with_rng(&self, rng: &mut impl CryptoRngCore, digest: D) -> Result<S, Self::Error> {
        <T as signature::RandomizedDigestSigner<D, S>>::try_sign_digest_with_rng(self, rng, digest)
    }
}

impl<T, D, S> DigestVerifier<D, S> for T
where
    T: signature::DigestVerifier<D, S>,
    D: digest::Digest,
{
    type Error = signature::Error;
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Self::Error> {
        <T as signature::DigestVerifier<D, S>>::verify_digest(self, digest, signature)
    }
}

impl<T> Keypair for T
where
    T: signature::Keypair,
{
    type VerifyingKey = <T as signature::Keypair>::VerifyingKey;
    fn verifying_key(&self) -> Self::VerifyingKey {
        <T as signature::Keypair>::verifying_key(self)
    }
}
