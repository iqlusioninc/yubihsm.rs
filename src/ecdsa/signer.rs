//! ECDSA provider for the YubiHSM 2 crate (supporting NIST P-256 and secp256k1).
//!
//! To enable secp256k1 support, build with the `secp256k1` cargo feature enabled.

use crate::{ecdsa::algorithm::CurveAlgorithm, object, Client};
#[cfg(feature = "secp256k1")]
use signatory::ecdsa::{curve::Secp256k1, generic_array::GenericArray};
use signatory::{
    ecdsa::{
        curve::{CompressedPointSize, Curve, NistP256, NistP384, UncompressedPointSize},
        generic_array::{
            typenum::{U1, U32, U48},
            ArrayLength,
        },
        Asn1Signature, FixedSignature, PublicKey,
    },
    public_key::PublicKeyed,
    signature::{DigestSigner, Error, Signature},
};
use signature::digest::Digest;
use std::{marker::PhantomData, ops::Add};

/// ECDSA signature provider for yubihsm-client
#[derive(signature::Signer)]
pub struct Signer<C: Curve> {
    /// YubiHSM client
    client: Client,

    /// ID of an ECDSA key to perform signatures with
    signing_key_id: object::Id,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C> Signer<C>
where
    C: Curve + CurveAlgorithm,
    <C::ScalarSize as Add>::Output: Add<U1> + ArrayLength<u8>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Create a new YubiHSM-backed ECDSA signer
    pub fn create(client: Client, signing_key_id: object::Id) -> Result<Self, Error> {
        let signer = Self {
            client,
            signing_key_id,
            curve: PhantomData,
        };

        // Ensure the signing_key_id slot contains a valid ECDSA public key
        signer.public_key()?;

        Ok(signer)
    }
}

impl<C> PublicKeyed<PublicKey<C>> for Signer<C>
where
    C: Curve + CurveAlgorithm,
    <C::ScalarSize as Add>::Output: Add<U1> + ArrayLength<u8>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<C>, Error> {
        let public_key = self.client.get_public_key(self.signing_key_id)?;
        public_key.ecdsa().ok_or_else(Error::new)
    }
}

impl<D> DigestSigner<D, Asn1Signature<NistP256>> for Signer<NistP256>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute an ASN.1 DER-encoded P-256 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Asn1Signature<NistP256>, Error> {
        self.sign_nistp256_asn1(digest)
    }
}

impl<D> DigestSigner<D, FixedSignature<NistP256>> for Signer<NistP256>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-sized P-256 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<FixedSignature<NistP256>, Error> {
        Ok(FixedSignature::from(&self.sign_nistp256_asn1(digest)?))
    }
}

impl<D> DigestSigner<D, Asn1Signature<NistP384>> for Signer<NistP384>
where
    D: Digest<OutputSize = U48> + Default,
{
    /// Compute an ASN.1 DER-encoded P-384 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Asn1Signature<NistP384>, Error> {
        self.sign_nistp384_asn1(digest)
    }
}

impl<D> DigestSigner<D, FixedSignature<NistP384>> for Signer<NistP384>
where
    D: Digest<OutputSize = U48> + Default,
{
    /// Compute a fixed-sized P-384 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<FixedSignature<NistP384>, Error> {
        Ok(FixedSignature::from(&self.sign_nistp384_asn1(digest)?))
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, Asn1Signature<Secp256k1>> for Signer<Secp256k1>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute an ASN.1 DER-encoded secp256k1 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<Asn1Signature<Secp256k1>, Error> {
        let asn1_sig = self.sign_secp256k1(digest)?.serialize_der();
        Ok(Asn1Signature::from_bytes(&asn1_sig).unwrap())
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, FixedSignature<Secp256k1>> for Signer<Secp256k1>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-size secp256k1 ECDSA signature of the given digest
    fn try_sign_digest(&self, digest: D) -> Result<FixedSignature<Secp256k1>, Error> {
        let fixed_sig =
            GenericArray::clone_from_slice(&self.sign_secp256k1(digest)?.serialize_compact());

        Ok(FixedSignature::from(fixed_sig))
    }
}

impl Signer<NistP256> {
    /// Compute an ASN.1 DER signature over P-256
    fn sign_nistp256_asn1<D>(&self, digest: D) -> Result<Asn1Signature<NistP256>, Error>
    where
        D: Digest<OutputSize = U32> + Default,
    {
        let signature = self
            .client
            .sign_ecdsa(self.signing_key_id, digest.result().as_slice())?;

        Asn1Signature::from_bytes(signature.as_ref())
    }
}

impl Signer<NistP384> {
    /// Compute an ASN.1 DER signature over P-384
    fn sign_nistp384_asn1<D>(&self, digest: D) -> Result<Asn1Signature<NistP384>, Error>
    where
        D: Digest<OutputSize = U48> + Default,
    {
        let signature = self
            .client
            .sign_ecdsa(self.signing_key_id, digest.result().as_slice())?;

        Asn1Signature::from_bytes(signature.as_ref())
    }
}

#[cfg(feature = "secp256k1")]
impl Signer<Secp256k1> {
    /// Compute either an ASN.1 DER or fixed-sized signature using libsecp256k1
    fn sign_secp256k1<D>(&self, digest: D) -> Result<secp256k1::Signature, Error>
    where
        D: Digest<OutputSize = U32> + Default,
    {
        // Sign the data using the YubiHSM, producing an ASN.1 DER encoded signature
        let raw_sig = self
            .client
            .sign_ecdsa(self.signing_key_id, digest.result().as_slice())?;

        // Parse the signature using libsecp256k1
        let mut sig = secp256k1::Signature::from_der_lax(raw_sig.as_ref()).unwrap();

        // Normalize the signature to a "low S" form. libsecp256k1 will only
        // accept signatures for which s is in the lower half of the field range.
        // The signatures produced by the YubiHSM do not have this property, so
        // we normalize them to maximize compatibility with secp256k1
        // applications (e.g. Bitcoin).
        sig.normalize_s();

        Ok(sig)
    }
}
