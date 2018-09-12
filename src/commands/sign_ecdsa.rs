//! Compute an ECDSA signature with the given key ID.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Data_Ecdsa.html>
//!
//! ## secp256k1 notes
//!
//! The YubiHSM2 does not produce signatures in "low S" form, which is expected
//! for most cryptocurrency applications (the typical use case for secp256k1).
//!
//! If your application demands this (e.g. Bitcoin), you'll need to normalize
//! the signatures. One option for this is the `secp256k1` crate's
//! [Signature::normalize_s] function.
//!
//! The [signatory-yubihsm] crate automatically normalizes secp256k1 ECDSA
//! signatures to "low S" form. Consider using that if you'd like a ready-made
//! solution for cryptocurrency applications.
//!
//! [Signature::normalize_s]: https://docs.rs/secp256k1/latest/secp256k1/struct.Signature.html#method.normalize_s
//! [signatory-yubihsm]: https://docs.rs/signatory-yubihsm/latest/signatory_yubihsm/ecdsa/struct.ECDSASigner.html

use super::{Command, Response};
#[cfg(not(feature = "usb"))]
use adapters::http::HttpAdapter;
#[cfg(feature = "usb")]
use adapters::usb::UsbAdapter;
use adapters::Adapter;
#[cfg(all(feature = "mockhsm", not(feature = "doc")))]
use mockhsm::MockAdapter;
use session::{Session, SessionError};
#[cfg(all(
    feature = "sha2",
    any(feature = "doc", not(feature = "mockhsm"))
))]
use sha2::{Digest, Sha256};
use {CommandType, ObjectId};

// Hax: specialize `sign_ecdsa_sha256` to a particular adapter type
// as a workaround for the MockHsm presenting a different API than the YubiHSM2
// TODO: find a better solution than this
#[cfg(not(feature = "usb"))]
#[allow(dead_code)]
type AdapterType = HttpAdapter;
#[cfg(feature = "usb")]
#[allow(dead_code)]
type AdapterType = UsbAdapter;

/// Compute an ECDSA signature of the given raw digest (i.e. a precomputed SHA-256 digest)
pub fn sign_ecdsa_raw_digest<A, T>(
    session: &mut Session<A>,
    key_id: ObjectId,
    digest: T,
) -> Result<ECDSASignature, SessionError>
where
    A: Adapter,
    T: Into<Vec<u8>>,
{
    session.send_command(SignDataECDSACommand {
        key_id,
        digest: digest.into(),
    })
}

/// Compute an ECDSA signature of the SHA-256 hash of the given data with the given key ID
#[cfg(all(
    feature = "sha2",
    any(feature = "doc", not(feature = "mockhsm"))
))]
pub fn sign_ecdsa_sha256(
    session: &mut Session<AdapterType>,
    key_id: ObjectId,
    data: &[u8],
) -> Result<ECDSASignature, SessionError> {
    sign_ecdsa_raw_digest(session, key_id, Sha256::digest(data).as_slice())
}

/// Compute an ECDSA signature of the SHA-256 hash of the given data with the given key ID
// NOTE: this version is enabled when we compile with MockHsm support
#[cfg(all(feature = "mockhsm", not(feature = "doc")))]
pub fn sign_ecdsa_sha256(
    session: &mut Session<MockAdapter>,
    key_id: ObjectId,
    data: &[u8],
) -> Result<ECDSASignature, SessionError> {
    // When using the MockHsm, pass the unhashed raw message. This is because *ring* does not (yet)
    // provide an API for signing a raw digest. See: https://github.com/briansmith/ring/issues/253
    session.send_command(SignDataECDSACommand {
        key_id,
        digest: data.into(),
    })
}

/// Request parameters for `commands::sign_ecdsa*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataECDSACommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignDataECDSACommand {
    type ResponseType = ECDSASignature;
}

/// ECDSA signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct ECDSASignature(pub Vec<u8>);

impl Response for ECDSASignature {
    const COMMAND_TYPE: CommandType = CommandType::SignDataECDSA;
}

// TODO: use clippy's scoped lints once they work on stable
#[allow(
    unknown_lints,
    renamed_and_removed_lints,
    len_without_is_empty
)]
impl ECDSASignature {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the signature
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for ECDSASignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for ECDSASignature {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
