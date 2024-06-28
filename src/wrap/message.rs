//! Wrap messages

use super::nonce::{self, Nonce};
use super::{Algorithm, Error, ErrorKind};
use crate::{
    algorithm, asymmetric,
    ecdsa::algorithm::CurveAlgorithm,
    object,
    serialization::{deserialize, serialize},
    wrap, Capability, Domain,
};
use aes::cipher::Unsigned;
use ccm::aead::Aead;
use ecdsa::{
    elliptic_curve::{
        sec1::{ModulusSize, ValidatePublicKey},
        FieldBytesSize, SecretKey,
    },
    PrimeCurve,
};
use num_traits::cast::FromPrimitive;
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    BigUint, RsaPrivateKey,
};
use serde::{Deserialize, Serialize};

/// Wrap wessage (encrypted HSM object or arbitrary data) encrypted under a wrap key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    /// Nonce used to encrypt the wrapped data
    pub nonce: Nonce,

    /// Ciphertext of the encrypted object
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Load a `Message` from a byte vector
    pub fn from_vec(mut vec: Vec<u8>) -> Result<Self, Error> {
        if vec.len() < nonce::SIZE {
            fail!(
                ErrorKind::LengthInvalid,
                "message must be at least {}-bytes",
                nonce::SIZE
            );
        }

        let ciphertext = vec.split_off(nonce::SIZE);
        let nonce = vec.as_ref();

        Ok(Self::new(nonce, ciphertext))
    }

    /// Create a new `Message`
    pub fn new<N, V>(nonce: N, ciphertext: V) -> Self
    where
        N: Into<Nonce>,
        V: Into<Vec<u8>>,
    {
        Self {
            nonce: nonce.into(),
            ciphertext: ciphertext.into(),
        }
    }

    /// Convert this message into a byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl Into<Vec<u8>> for Message {
    fn into(self) -> Vec<u8> {
        let Message {
            nonce,
            mut ciphertext,
        } = self;

        let mut vec = Vec::with_capacity(nonce::SIZE + ciphertext.len());
        vec.extend_from_slice(nonce.as_ref());
        vec.append(&mut ciphertext);
        vec
    }
}

impl Message {
    /// Decrypt the [`Message`] with the provided [`wrap::Key`]
    pub fn decrypt(&self, key: &wrap::Key) -> Result<Plaintext, Error> {
        let cipher: super::key::AesCcm = key.into();
        let plaintext = cipher
            .decrypt(&self.nonce.to_nonce(), &*self.ciphertext)
            .unwrap();

        let plaintext = deserialize(&plaintext).unwrap();
        Ok(plaintext)
    }
}

/// Plaintext message to be encrypted under a wrap key
#[derive(Serialize, Deserialize)]
pub struct Plaintext {
    /// Algorithm used for wrapping this message
    pub algorithm: Algorithm,
    /// Information about the object being wrapped
    pub object_info: wrap::Info,
    /// Payload of the plaintext
    pub data: Vec<u8>,
}

impl Plaintext {
    /// Wrapped the plaintext under a wrapping key
    pub fn encrypt(&self, key: &super::Key) -> Result<Message, Error> {
        if self.algorithm.key_len() != key.key_len() {
            fail!(
                ErrorKind::AlgorithmMismatch,
                "Expected wrapping key with length {expected} but got {len}",
                expected = self.algorithm.key_len(),
                len = key.key_len()
            );
        }

        let cipher: super::key::AesCcm = key.into();
        let nonce = Nonce::generate();
        let wire = serialize(&self).unwrap();
        let ciphertext = cipher.encrypt(&nonce.to_nonce(), wire.as_slice()).unwrap();

        Ok(Message { nonce, ciphertext })
    }

    /// Return the ecdsa key of this [`Plaintext`] if it was an EC key.
    pub fn ecdsa<C>(&self) -> Option<SecretKey<C>>
    where
        C: PrimeCurve + CurveAlgorithm + ValidatePublicKey,
        FieldBytesSize<C>: ModulusSize + Unsigned,
    {
        if let algorithm::Algorithm::Asymmetric(alg) = self.object_info.algorithm {
            if C::asymmetric_algorithm() == alg {
                let mut reader = SliceReader(&self.data);

                SecretKey::<C>::from_slice(reader.read(FieldBytesSize::<C>::USIZE)?).ok()
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Build a [`Plaintext`] from an [`RsaPrivateKey`].
    pub fn from_ecdsa<C>(
        algorithm: Algorithm,
        object_id: object::Id,
        capabilities: Capability,
        domains: Domain,
        label: object::Label,
        key: SecretKey<C>,
    ) -> Result<Self, Error>
    where
        C: PrimeCurve + CurveAlgorithm,
        FieldBytesSize<C>: ModulusSize + Unsigned,
    {
        let asym_algorithm = C::asymmetric_algorithm();

        let object_info = wrap::Info {
            capabilities,
            object_id,
            length: 0,
            domains,
            object_type: object::Type::AsymmetricKey,
            algorithm: algorithm::Algorithm::Asymmetric(asym_algorithm),
            sequence: 0,
            origin: object::Origin::Imported,
            label,
        };

        let data = key.to_bytes().as_slice().to_vec();

        Ok(Self {
            algorithm,
            object_info,
            data,
        })
    }

    /// Return the rsa key of this [`Plaintext`] if it was an RSA key.
    pub fn rsa(&self) -> Option<RsaPrivateKey> {
        let (component_size, modulus_size) = match self.object_info.algorithm {
            algorithm::Algorithm::Asymmetric(asymmetric::Algorithm::Rsa2048) => (128, 256),
            algorithm::Algorithm::Asymmetric(asymmetric::Algorithm::Rsa3072) => (192, 384),
            algorithm::Algorithm::Asymmetric(asymmetric::Algorithm::Rsa4096) => (256, 512),
            _ => return None,
        };

        let mut reader = SliceReader(&self.data);

        let p = BigUint::from_bytes_be(reader.read(component_size)?);
        let q = BigUint::from_bytes_be(reader.read(component_size)?);
        let _dp = BigUint::from_bytes_be(reader.read(component_size)?);
        let _dq = BigUint::from_bytes_be(reader.read(component_size)?);
        let _qinv = BigUint::from_bytes_be(reader.read(component_size)?);
        let _n = BigUint::from_bytes_be(reader.read(modulus_size)?);
        const EXP: u64 = 65537;
        let e = BigUint::from_u64(EXP).expect("invalid static exponent");

        let private_key = RsaPrivateKey::from_p_q(p, q, e).ok()?;

        Some(private_key)
    }

    /// Build a [`Plaintext`] from an [`RsaPrivateKey`].
    pub fn from_rsa(
        algorithm: Algorithm,
        object_id: object::Id,
        capabilities: Capability,
        domains: Domain,
        label: object::Label,
        mut key: RsaPrivateKey,
    ) -> Result<Self, Error> {
        let mut object_info = wrap::Info {
            capabilities,
            object_id,
            length: 0,
            domains,
            object_type: object::Type::AsymmetricKey,
            algorithm: algorithm::Algorithm::Asymmetric(
                // This is rewritten a couple lines below
                asymmetric::Algorithm::Rsa2048,
            ),
            sequence: 0,
            origin: object::Origin::Imported,
            label,
        };

        object_info.algorithm = match key.size() {
            256 => algorithm::Algorithm::Asymmetric(asymmetric::Algorithm::Rsa2048),
            384 => algorithm::Algorithm::Asymmetric(asymmetric::Algorithm::Rsa3072),
            512 => algorithm::Algorithm::Asymmetric(asymmetric::Algorithm::Rsa4096),
            other => fail!(
                ErrorKind::UnsupportedKeySize,
                "RSA key size {} is not supported",
                other
            ),
        };

        // Make sure we have qinv, dp and dq
        key.precompute()
            .map_err(|_| format_err!(ErrorKind::RsaPrecomputeFailed, "Rsa precompute failed"))?;

        let primes = key.primes();
        if primes.len() != 2 {
            fail!(ErrorKind::InvalidPrimes, "multi-primes is not supported");
        }

        let p = &primes[0];
        let q = &primes[1];

        let mut data = Vec::new();
        data.extend_from_slice(&p.to_bytes_be());
        data.extend_from_slice(&q.to_bytes_be());
        // Unwrap here is okay, we have ownership of the key and we already precomputed the values.
        data.extend_from_slice(&key.dp().unwrap().to_bytes_be());
        data.extend_from_slice(&key.dq().unwrap().to_bytes_be());
        // TODO: the second unwrap for int -> uint conversion is unfortunate.
        data.extend_from_slice(&key.qinv().unwrap().to_biguint().unwrap().to_bytes_be());
        data.extend_from_slice(&key.n().to_bytes_be());

        object_info.length = data.len() as u16;

        Ok(Self {
            algorithm,
            object_info,
            data,
        })
    }
}

/// Support structure to read from a slice like a reader
struct SliceReader<'a>(&'a [u8]);

impl<'a> SliceReader<'a> {
    #[inline]
    fn read(&mut self, len: usize) -> Option<&'a [u8]> {
        if len > self.0.len() {
            None
        } else {
            let (out, new) = self.0.split_at(len);
            self.0 = new;
            Some(out)
        }
    }
}
