use crate::{object, rsa::SignatureAlgorithm, Client};
use rsa::{
    pkcs1v15::{RsaSignatureAssociatedOid, Signature, VerifyingKey},
    RsaPublicKey,
};
use signature::Error;
use spki::{AlgorithmIdentifier, SignatureAlgorithmIdentifier};
use std::marker::PhantomData;

/// RSA signature provider for yubihsm-client
pub struct Signer<S>
where
    S: SignatureAlgorithm,
{
    /// YubiHSM client.
    client: Client,

    /// ID of an ECDSA key to perform signatures with.
    signing_key_id: object::Id,

    /// Verifying key which corresponds to this signer.
    verifying_key: VerifyingKey<S>,

    /// Algorithm used when signing messages
    _algorithm: PhantomData<S>,
}

impl<S> Signer<S>
where
    S: SignatureAlgorithm,
{
    /// Create a new YubiHSM-backed RSA-PSS signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        let public_key = client
            .get_public_key(signing_key_id)?
            .rsa()
            .ok_or_else(Error::new)?;

        let verifying_key = VerifyingKey::<S>::new(public_key);

        Ok(Self {
            client,
            signing_key_id,
            verifying_key,
            _algorithm: PhantomData,
        })
    }

    /// Return the RSA public key used by this signer
    pub fn public_key(&self) -> RsaPublicKey {
        let verifying_key = self.verifying_key.clone();
        verifying_key.into()
    }
}

impl<S> signature::Signer<Signature> for Signer<S>
where
    S: SignatureAlgorithm,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        self.client
            .sign_rsa_pkcs1v15::<S>(self.signing_key_id, msg)?
            .as_slice()
            .try_into()
    }
}

impl<S> signature::Keypair for Signer<S>
where
    S: SignatureAlgorithm,
{
    type VerifyingKey = VerifyingKey<S>;

    fn verifying_key(&self) -> VerifyingKey<S> {
        self.verifying_key.clone()
    }
}

impl<S> SignatureAlgorithmIdentifier for Signer<S>
where
    S: SignatureAlgorithm + RsaSignatureAssociatedOid,
{
    type Params = <VerifyingKey<S> as SignatureAlgorithmIdentifier>::Params;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        <VerifyingKey<S> as SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;
}
