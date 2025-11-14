//! Wrap Keys for making encrypted backups of keys within the HSM, so they can be
//! imported into other devices.
//!
//! The `wrap::Key` builder type is presently only used by `yubihsm::setup`
//! functionality.

// TODO(tarcieri): use this for `yubihsm::client::put_wrap_key` in general?

use crate::{client, device, object, wrap, Capability, Client, Domain};
use aes::{Aes128, Aes192, Aes256};
use ccm::{
    aead::{inout::InOutBuf, TagPosition},
    consts::{U13, U16},
    AeadCore, AeadInOut, Ccm, KeyInit,
};
use rand_core::RngCore;
use std::fmt::{self, Debug};
use zeroize::{Zeroize, Zeroizing};

pub(super) type Aes128Ccm = Ccm<Aes128, U16, U13>;
pub(super) type Aes192Ccm = Ccm<Aes192, U16, U13>;
pub(super) type Aes256Ccm = Ccm<Aes256, U16, U13>;

pub(super) enum AesCcm {
    Aes128(Aes128Ccm),
    Aes192(Aes192Ccm),
    Aes256(Aes256Ccm),
}

impl AesCcm {
    fn from_bytes(bytes: &[u8]) -> Self {
        match bytes.len() {
            16 => Self::Aes128(Aes128Ccm::new_from_slice(bytes).unwrap()),
            24 => Self::Aes192(Aes192Ccm::new_from_slice(bytes).unwrap()),
            32 => Self::Aes256(Aes256Ccm::new_from_slice(bytes).unwrap()),
            len => panic!("unexpected length for aesccm {len}"),
        }
    }
}

impl From<&Key> for AesCcm {
    fn from(key: &Key) -> Self {
        Self::from_bytes(&key.data)
    }
}

impl AeadCore for AesCcm {
    type NonceSize = U13;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for AesCcm {
    fn encrypt_inout_detached(
        &self,
        nonce: &ccm::Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<ccm::Tag<Self::TagSize>, ccm::Error> {
        match self {
            Self::Aes128(inner) => inner.encrypt_inout_detached(nonce, associated_data, buffer),
            Self::Aes192(inner) => inner.encrypt_inout_detached(nonce, associated_data, buffer),
            Self::Aes256(inner) => inner.encrypt_inout_detached(nonce, associated_data, buffer),
        }
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &ccm::Nonce<Self::NonceSize>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &ccm::Tag<Self::TagSize>,
    ) -> Result<(), ccm::Error> {
        match self {
            Self::Aes128(inner) => {
                inner.decrypt_inout_detached(nonce, associated_data, buffer, tag)
            }
            Self::Aes192(inner) => {
                inner.decrypt_inout_detached(nonce, associated_data, buffer, tag)
            }
            Self::Aes256(inner) => {
                inner.decrypt_inout_detached(nonce, associated_data, buffer, tag)
            }
        }
    }
}

/// Wrap key to import into the device
#[derive(Clone)]
pub struct Key {
    /// Object parameters
    pub(crate) import_params: object::put::Params,

    /// Delegated capabilities apply to objects imported by this key
    pub(crate) delegated_capabilities: Capability,

    /// Key bytes
    pub(crate) data: Vec<u8>,
}

impl Key {
    /// Generate a random wrap key with the given key size.
    pub fn generate_random(key_id: object::Id, algorithm: wrap::Algorithm) -> Self {
        let mut bytes = Zeroizing::new(vec![0u8; algorithm.key_len()]);
        let mut rng = rand::rng();
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(key_id, &bytes).unwrap()
    }

    /// Create a new `wrap::Key` instance. Must be 16, 24, or 32-bytes long.
    pub fn from_bytes(key_id: object::Id, bytes: &[u8]) -> Result<Self, device::Error> {
        let alg = match bytes.len() {
            16 => wrap::Algorithm::Aes128Ccm,
            24 => wrap::Algorithm::Aes192Ccm,
            32 => wrap::Algorithm::Aes256Ccm,
            other => fail!(
                device::ErrorKind::WrongLength,
                "expected 16, 24, or 32-byte wrap key (got {})",
                other
            ),
        };

        let object_params = object::put::Params::new(key_id, alg.into());

        Ok(Self {
            import_params: object_params,
            delegated_capabilities: Default::default(),
            data: bytes.to_vec(),
        })
    }

    /// Set the object label on this key
    pub fn label(mut self, label: object::Label) -> Self {
        self.import_params.label = label;
        self
    }

    /// Set the domains this wrap key can be used in (default: all)
    pub fn domains(mut self, domains: Domain) -> Self {
        self.import_params.domains = domains;
        self
    }

    /// Set the capabilities of this key (what it can be used for)
    pub fn capabilities(mut self, capabilities: Capability) -> Self {
        self.import_params.capabilities = capabilities;
        self
    }

    /// Set the delegated capabilities of this key (what capabilities it can
    /// set on imported objects)
    pub fn delegated_capabilities(mut self, capabilities: Capability) -> Self {
        self.delegated_capabilities = capabilities;
        self
    }

    /// Create this key within the HSM
    pub fn create(&self, client: &Client) -> Result<(), client::Error> {
        let algorithm = self.import_params.algorithm.wrap().unwrap();

        client.put_wrap_key(
            self.import_params.id,
            self.import_params.label.clone(),
            self.import_params.domains,
            self.import_params.capabilities,
            self.delegated_capabilities,
            algorithm,
            self.data.clone(),
        )?;

        Ok(())
    }

    /// Return the length of the key
    pub fn key_len(&self) -> usize {
        self.data.len()
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Avoid leaking secrets in debug messages
        write!(
            f,
            "yubihsm:wrap::Key {{ import_params: {:?}, delegated_capabilities: {:?}, data: ... }}",
            self.import_params, self.delegated_capabilities
        )
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
