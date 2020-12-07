//! ECDSA provider for the YubiHSM 2 crate (supporting NIST P-256 and secp256k1).
//!
//! To enable secp256k1 support, build with the `secp256k1` cargo feature enabled.

use super::{algorithm::CurveAlgorithm, NistP256, NistP384};
use crate::{object, Client};
use ::ecdsa::{
    elliptic_curve::{
        consts::{U1, U32},
        generic_array::ArrayLength,
        sec1::{self, UncompressedPointSize, UntaggedPointSize},
        weierstrass::{point, Curve},
    },
    Signature,
};
use signature::digest::Digest;
use signature::{DigestSigner, Error};
use std::ops::Add;

#[cfg(feature = "secp256k1")]
use super::Secp256k1;

/// ECDSA signature provider for yubihsm-client
#[derive(signature::Signer)]
pub struct Signer<C>
where
    C: Curve + CurveAlgorithm + point::Compression,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// YubiHSM client
    client: Client,

    /// ID of an ECDSA key to perform signatures with
    signing_key_id: object::Id,

    /// Public key associated with the private key in the YubiHSM
    public_key: sec1::EncodedPoint<C>,
}

impl<C> Signer<C>
where
    C: Curve + CurveAlgorithm + point::Compression,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Create a new YubiHSM-backed ECDSA signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        let public_key = client
            .get_public_key(signing_key_id)?
            .ecdsa()
            .ok_or_else(Error::new)?;

        Ok(Self {
            client,
            signing_key_id,
            public_key,
        })
    }

    /// Create an ECDSA signature from the provided digest
    fn sign_ecdsa_digest<D: Digest>(&self, digest: D) -> Result<Vec<u8>, Error> {
        self.client
            .sign_ecdsa_prehash_raw(self.signing_key_id, digest.finalize().as_slice())
            .map_err(Error::from_source)
    }

    /// Get the public key for the YubiHSM-backed private key.
    pub fn public_key(&self) -> &sec1::EncodedPoint<C> {
        &self.public_key
    }
}

impl<C> From<&Signer<C>> for sec1::EncodedPoint<C>
where
    Self: Clone,
    C: Curve + CurveAlgorithm + point::Compression,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn from(signer: &Signer<C>) -> sec1::EncodedPoint<C> {
        signer.public_key().clone()
    }
}

impl<D> DigestSigner<D, Signature<NistP256>> for Signer<NistP256>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-sized P-256 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Signature<NistP256>, Error> {
        let sig = self.sign_ecdsa_digest(digest)?;
        Signature::from_asn1(&sig)
    }
}

impl<D> DigestSigner<D, Signature<NistP384>> for Signer<NistP384>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-sized P-384 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Signature<NistP384>, Error> {
        let sig = self.sign_ecdsa_digest(digest)?;
        Signature::from_asn1(&sig)
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, Signature<Secp256k1>> for Signer<Secp256k1>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-size secp256k1 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Signature<Secp256k1>, Error> {
        let mut signature = self
            .sign_ecdsa_digest(digest)
            .and_then(|sig| Signature::from_asn1(&sig))?;

        // Low-S normalize per BIP 0062: Dealing with Malleability:
        // <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki>
        signature.normalize_s()?;
        Ok(signature)
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, k256::ecdsa::recoverable::Signature> for Signer<Secp256k1>
where
    D: Digest<OutputSize = U32> + Clone + Default,
{
    /// Compute an Ethereum-style ECDSA/secp256k1 signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<k256::ecdsa::recoverable::Signature, Error> {
        let pk = k256::ecdsa::VerifyingKey::from_encoded_point(&self.public_key)?;
        let sig = self.try_sign_digest(digest.clone())?;
        k256::ecdsa::recoverable::Signature::from_digest_trial_recovery(&pk, digest, &sig)
    }
}
