//! Response from `CommandType::GenAsymmetricKey`

use ObjectId;
use byteorder::{BigEndian, ByteOrder};
#[cfg(feature = "mockhsm")]
use byteorder::WriteBytesExt;
use failure::Error;
use super::{CommandType, Response};

/// Response from `CommandType::GenAsymmetricKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
#[derive(Debug)]
pub struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::GenAsymmetricKey;

    /// Parse response from HSM
    // TODO: procedurally generate this
    fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() != 2 {
            bail!("invalid response length {} (expected {})", bytes.len(), 2);
        }

        Ok(Self {
            key_id: BigEndian::read_u16(&bytes),
        })
    }

    /// Serialize data
    // TODO: procedurally generate this
    #[cfg(feature = "mockhsm")]
    fn into_vec(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(2);
        data.write_u16::<BigEndian>(self.key_id).unwrap();
        data
    }
}
