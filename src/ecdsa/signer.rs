//! ECDSA provider for the YubiHSM 2 crate (supporting NIST P-256 and secp256k1).
//!
//! To enable secp256k1 support, build with the `secp256k1` cargo feature enabled.

use super::{algorithm::CurveAlgorithm, NistP256, NistP384};
use crate::{object, Client};
use ecdsa::{
    elliptic_curve::{
        consts::U32,
        generic_array::ArrayLength,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, FieldSize, PointCompression, PrimeCurve, ProjectiveArithmetic,
    },
    Signature, SignatureSize, VerifyingKey,
};
use signature::{digest::Digest, hazmat::PrehashSigner, DigestSigner, Error, Keypair};
use std::ops::Add;

#[cfg(feature = "secp256k1")]
use super::Secp256k1;
#[cfg(feature = "secp256k1")]
use signature::digest::FixedOutput;

/// ECDSA signature provider for yubihsm-client
#[derive(signature::Signer)]
pub struct Signer<C>
where
    C: PrimeCurve + CurveAlgorithm + PointCompression + ProjectiveArithmetic,
    FieldSize<C>: sec1::ModulusSize,
{
    /// YubiHSM client.
    client: Client,

    /// ID of an ECDSA key to perform signatures with.
    signing_key_id: object::Id,

    /// Verifying key which corresponds to this signer.
    verifying_key: VerifyingKey<C>,

    /// Public key associated with the private key in the YubiHSM.
    // TODO(tarcieri): remove this in favor of `verifying_key` in the next breaking release
    public_key: sec1::EncodedPoint<C>,
}

impl<C> Signer<C>
where
    C: PrimeCurve + CurveAlgorithm + PointCompression + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: sec1::ModulusSize,
{
    /// Create a new YubiHSM-backed ECDSA signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        let public_key = client
            .get_public_key(signing_key_id)?
            .ecdsa::<C>()
            .ok_or_else(Error::new)?;

        let verifying_key = VerifyingKey::<C>::from_encoded_point(&public_key)?;

        Ok(Self {
            client,
            signing_key_id,
            verifying_key,
            public_key,
        })
    }

    /// Get the public key for the YubiHSM-backed private key.
    pub fn public_key(&self) -> &sec1::EncodedPoint<C> {
        &self.public_key
    }
}

impl<C> AsRef<VerifyingKey<C>> for Signer<C>
where
    C: PrimeCurve + CurveAlgorithm + PointCompression + ProjectiveArithmetic,
    FieldSize<C>: sec1::ModulusSize,
{
    fn as_ref(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }
}

impl<C> From<&Signer<C>> for sec1::EncodedPoint<C>
where
    Self: Clone,
    C: PrimeCurve + CurveAlgorithm + PointCompression + ProjectiveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldSize<C>: sec1::ModulusSize,
{
    fn from(signer: &Signer<C>) -> sec1::EncodedPoint<C> {
        signer.public_key().clone()
    }
}

impl<C> Keypair<Signature<C>> for Signer<C>
where
    C: PrimeCurve + CurveAlgorithm + PointCompression + ProjectiveArithmetic,
    FieldSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    type VerifyingKey = VerifyingKey<C>;
}

impl<C> PrehashSigner<Signature<C>> for Signer<C>
where
    C: PrimeCurve + CurveAlgorithm + PointCompression + ProjectiveArithmetic,
    FieldSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
    ecdsa::der::MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<ecdsa::der::MaxOverhead> + ArrayLength<u8>,
{
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature<C>, Error> {
        self.client
            .sign_ecdsa_prehash_raw(self.signing_key_id, prehash)
            .map_err(Error::from_source)
            .and_then(|der| Signature::from_der(&der))
    }
}

impl<D> DigestSigner<D, Signature<NistP256>> for Signer<NistP256>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-sized P-256 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Signature<NistP256>, Error> {
        self.sign_prehash(&digest.finalize())
    }
}

impl<D> DigestSigner<D, Signature<NistP384>> for Signer<NistP384>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-sized P-384 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Signature<NistP384>, Error> {
        self.sign_prehash(&digest.finalize())
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, Signature<Secp256k1>> for Signer<Secp256k1>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-size secp256k1 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Signature<Secp256k1>, Error> {
        let signature = self.sign_prehash(&digest.finalize())?;

        // Low-S normalize per BIP 0062: Dealing with Malleability:
        // <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki>
        Ok(signature.normalize_s().unwrap_or(signature))
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, k256::ecdsa::recoverable::Signature> for Signer<Secp256k1>
where
    D: Digest<OutputSize = U32> + Clone + Default + FixedOutput,
{
    /// Compute an Ethereum-style ECDSA/secp256k1 signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<k256::ecdsa::recoverable::Signature, Error> {
        let pk = k256::ecdsa::VerifyingKey::from_encoded_point(&self.public_key)?;
        let sig = self.try_sign_digest(digest.clone())?;
        k256::ecdsa::recoverable::Signature::from_digest_trial_recovery(&pk, digest, &sig)
    }
}
