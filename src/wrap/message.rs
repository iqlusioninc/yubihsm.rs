//! Wrap messages

use super::nonce::{self, Nonce};
use super::{Algorithm, Error, ErrorKind};
use crate::{
    algorithm, asymmetric,
    ecdsa::algorithm::CurveAlgorithm,
    serialization::{deserialize, serialize},
    wrap,
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
use num_bigint::traits::ModInverse;
use num_traits::{cast::FromPrimitive, identities::One};
use rsa::{BigUint, RsaPrivateKey};
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

#[derive(Serialize, Deserialize)]
pub struct Plaintext {
    pub alg_id: Algorithm,
    pub object_info: wrap::Info,
    pub data: Vec<u8>,
}

impl Plaintext {
    pub fn encrypt(&self, key: &super::Key) -> Result<Message, Error> {
        let cipher: super::key::AesCcm = key.into();
        let nonce = Nonce::generate();
        let wire = serialize(&self).unwrap();
        let ciphertext = cipher.encrypt(&nonce.to_nonce(), wire.as_slice()).unwrap();

        Ok(Message { nonce, ciphertext })
    }

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
        let dp = BigUint::from_bytes_be(reader.read(component_size)?);
        let dq = BigUint::from_bytes_be(reader.read(component_size)?);
        let _qinv = BigUint::from_bytes_be(reader.read(component_size)?);
        let n = BigUint::from_bytes_be(reader.read(modulus_size)?);
        const EXP: u64 = 65537;
        let e = BigUint::from_u64(EXP).expect("invalid static exponent");

        let d = e
            .clone()
            .mod_inverse((dp - BigUint::one()) * (dq - BigUint::one()))?
            .to_biguint()?;

        let private_key = RsaPrivateKey::from_components(n, e, d, vec![p, q]).ok()?;
        Some(private_key)
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
