use crate::{object, rsa::SignatureAlgorithm, Client};
use digest::Digest;
use rsa::{
    pss::{get_default_pss_signature_algo_id, Signature, VerifyingKey},
    traits::PublicKeyParts,
    RsaPublicKey,
};
use signature::Error;
use spki::{der::oid::AssociatedOid, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};
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

    /// Salt length used when signing messages
    salt_len: Option<u16>,

    /// Algorithm used when signing messages
    _algorithm: PhantomData<S>,
}

impl<S> Signer<S>
where
    S: SignatureAlgorithm,
{
    fn create_with_salt(
        client: Client,
        signing_key_id: object::Id,
        salt_len: Option<u16>,
    ) -> Result<Self, Error> {
        let public_key = client
            .get_public_key(signing_key_id)?
            .rsa()
            .ok_or_else(Error::new)?;

        let verifying_key = if let Some(salt_len) = salt_len {
            let verifying_key = VerifyingKey::<S>::new_with_salt_len(public_key, salt_len.into());

            // Ensure the salt_len is within the bounds
            let klen = verifying_key.as_ref().n_bits_precision() / 8;
            let digest_len =
                u32::try_from(<S as Digest>::output_size()).expect("No digest can span 32bits");
            if u32::from(salt_len) > klen - digest_len - 2 {
                return Err(Error::new());
            }

            verifying_key
        } else {
            VerifyingKey::<S>::new(public_key)
        };

        Ok(Self {
            client,
            signing_key_id,
            verifying_key,
            salt_len,
            _algorithm: PhantomData,
        })
    }

    /// Create a new YubiHSM-backed RSA-PSS signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        Self::create_with_salt(client, signing_key_id, None)
    }

    /// Create a new YubiHSM-backed RSA-PSS signer
    pub fn create_with_salt_len(
        client: Client,
        signing_key_id: object::Id,
        salt_len: u16,
    ) -> Result<Self, Error> {
        Self::create_with_salt(client, signing_key_id, Some(salt_len))
    }

    /// Return the RSA public key used by this signer
    pub fn public_key(&self) -> RsaPublicKey {
        let verifying_key = self.verifying_key.clone();
        verifying_key.into()
    }

    /// Return the RSASSA-PSS verifier attached to the key of this instance
    pub fn verifying_key(&self) -> VerifyingKey<S> {
        self.verifying_key.clone()
    }
}

impl<S> signature::Signer<Signature> for Signer<S>
where
    S: SignatureAlgorithm,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        self.client
            .sign_rsa_pss::<S>(self.signing_key_id, msg, self.salt_len)?
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

impl<S> DynSignatureAlgorithmIdentifier for Signer<S>
where
    S: SignatureAlgorithm + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        get_default_pss_signature_algo_id::<S>()
    }
}
