use core::fmt::Debug;

pub trait Digest {
    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self;
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;
}

pub trait DigestSigner<D: Digest, S> {
    type Error: Debug;
    fn try_sign_digest(&self, digest: D) -> Result<S, Self::Error>;
}

pub trait Keypair {
    type VerifyingKey: Clone;

    fn verifying_key(&self) -> Self::VerifyingKey;
}

pub trait DigestVerifier<D: Digest, S> {
    type Error: Debug;
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Self::Error>;
}

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

impl<T, D, S> DigestSigner<D, S> for T
where
    T: signature::DigestSigner<D, S>,
    D: digest::Digest,
{
    type Error = signature::Error;
    fn try_sign_digest(&self, digest: D) -> Result<S, Self::Error> {
        <T as signature::DigestSigner<D, S>>::try_sign_digest(self, digest)
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
