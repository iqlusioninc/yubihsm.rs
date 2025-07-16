//! ECDSA provider for the YubiHSM 2 crate (supporting NIST P-256 and secp256k1).
//!
//! To enable secp256k1 support, build with the `secp256k1` cargo feature enabled.

use super::{algorithm::CurveAlgorithm, NistP256, NistP384, NistP521};
use crate::{object, Client};
use ecdsa::{
    der,
    elliptic_curve::{
        array::ArraySize,
        point::PointCompression,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, CurveArithmetic, FieldBytesSize,
    },
    hazmat::DigestAlgorithm,
    EcdsaCurve, Signature, VerifyingKey,
};
use signature::{digest::Digest, hazmat::PrehashSigner, DigestSigner, Error, KeypairRef};
use spki::{
    der::AnyRef, AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier,
};
use std::ops::Add;

#[cfg(feature = "secp256k1")]
use super::{secp256k1::RecoveryId, Secp256k1};

/// ECDSA signature provider for yubihsm-client
pub struct Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    FieldBytesSize<C>: sec1::ModulusSize,
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
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    C: CurveAlgorithm + PointCompression,
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

impl<C> Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    FieldBytesSize<C>: sec1::ModulusSize,
    der::MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArraySize,
{
    fn sign_prehash_ecdsa(&self, prehash: &[u8]) -> Result<Signature<C>, Error> {
        self.client
            .sign_ecdsa_prehash_raw(self.signing_key_id, prehash)
            .map_err(Error::from_source)
            .and_then(|der| Signature::from_der(&der))
    }
}

impl<C> AsRef<VerifyingKey<C>> for Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn as_ref(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }
}

impl<C> From<&Signer<C>> for sec1::EncodedPoint<C>
where
    Self: Clone,
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    C: CurveAlgorithm + PointCompression,
{
    fn from(signer: &Signer<C>) -> sec1::EncodedPoint<C> {
        signer.public_key().clone()
    }
}

impl<C> KeypairRef for Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type VerifyingKey = VerifyingKey<C>;
}

macro_rules! impl_signer {
    ($curve:ty) => {
        impl PrehashSigner<Signature<$curve>> for Signer<$curve> {
            /// Compute a fixed-size ECDSA signature of a digest output.
            fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature<$curve>, Error> {
                self.sign_prehash_ecdsa(prehash)
            }
        }

        impl DigestSigner<<$curve as DigestAlgorithm>::Digest, Signature<$curve>>
            for Signer<$curve>
        {
            /// Compute a fixed-sized ECDSA signature of the given digest
            fn try_sign_digest(
                &self,
                digest: <$curve as DigestAlgorithm>::Digest,
            ) -> Result<Signature<$curve>, Error> {
                self.sign_prehash(&digest.finalize())
            }
        }
    };
}

impl_signer!(NistP256);
impl_signer!(NistP384);
impl_signer!(NistP521);

#[cfg(feature = "secp256k1")]
impl PrehashSigner<Signature<Secp256k1>> for Signer<Secp256k1> {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature<Secp256k1>, Error> {
        let signature = self.sign_prehash_ecdsa(prehash)?;
        // Low-S normalize per BIP 0062: Dealing with Malleability:
        // <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki>
        Ok(signature.normalize_s())
    }
}

#[cfg(feature = "secp256k1")]
impl PrehashSigner<(Signature<Secp256k1>, RecoveryId)> for Signer<Secp256k1> {
    /// Compute a fixed-size secp256k1 ECDSA signature of a digest output along with the recovery
    /// ID.
    fn sign_prehash(&self, prehash: &[u8]) -> Result<(Signature<Secp256k1>, RecoveryId), Error> {
        let signature = self.sign_prehash(prehash)?;
        let recovery_id =
            RecoveryId::trial_recovery_from_prehash(&self.verifying_key, prehash, &signature)?;
        Ok((signature, recovery_id))
    }
}

#[cfg(feature = "secp256k1")]
impl DigestSigner<<Secp256k1 as DigestAlgorithm>::Digest, Signature<Secp256k1>>
    for Signer<Secp256k1>
{
    /// Compute a fixed-size secp256k1 ECDSA signature of the given digest
    fn try_sign_digest(
        &self,
        digest: <Secp256k1 as DigestAlgorithm>::Digest,
    ) -> Result<Signature<Secp256k1>, Error> {
        self.sign_prehash(&digest.finalize())
    }
}

#[cfg(feature = "secp256k1")]
impl DigestSigner<<Secp256k1 as DigestAlgorithm>::Digest, (Signature<Secp256k1>, RecoveryId)>
    for Signer<Secp256k1>
{
    /// Compute a fixed-size secp256k1 ECDSA signature of the given digest along with the recovery
    /// ID.
    fn try_sign_digest(
        &self,
        digest: <Secp256k1 as DigestAlgorithm>::Digest,
    ) -> Result<(Signature<Secp256k1>, RecoveryId), Error> {
        self.sign_prehash(&digest.finalize())
    }
}

impl<C> DigestSigner<C::Digest, der::Signature<C>> for Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    C: DigestAlgorithm,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    der::MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<der::MaxOverhead> + ArraySize,
    Self: DigestSigner<C::Digest, Signature<C>>,
{
    fn try_sign_digest(&self, digest: C::Digest) -> Result<der::Signature<C>, Error> {
        DigestSigner::<C::Digest, Signature<C>>::try_sign_digest(self, digest).map(Into::into)
    }
}

impl<C> SignatureAlgorithmIdentifier for Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
    Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = <VerifyingKey<C> as SignatureAlgorithmIdentifier>::Params;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        <VerifyingKey<C> as SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;
}

impl<C, S> ::signature::Signer<S> for Signer<C>
where
    C: EcdsaCurve + CurveArithmetic,
    FieldBytesSize<C>: sec1::ModulusSize,
    S: signature::PrehashSignature,
    Self: DigestSigner<S::Digest, S>,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<S> {
        self.try_sign_digest(S::Digest::new_with_prefix(msg))
    }
}
