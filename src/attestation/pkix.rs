#![allow(missing_docs)]
//! Yubico extensions for attestation of asymmetric keys in the YubiHSM.

use std::string::FromUtf8Error;

use der::{
    self,
    asn1::{BitString, OctetString},
    oid::AssociatedOid,
    Error, Sequence,
};
use spki::ObjectIdentifier;
use x509_cert::{
    ext::{AsExtension, Extension},
    name::Name,
};

use crate::{capability, device, domain, object};

pub const YUBICO_FIRMWARE_VERSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.1");
pub const YUBICO_SERIAL_NUMBER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.2");
pub const YUBICO_ORIGIN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.3");
pub const YUBICO_DOMAIN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.4");
pub const YUBICO_CAPABILITY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.5");
pub const YUBICO_OBJECT_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.6");
pub const YUBICO_LABEL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.4.9");

/// Firmware version of the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FirmwareVersion {
    pub fw_version: OctetString,
}

impl TryFrom<&device::Info> for FirmwareVersion {
    type Error = Error;

    fn try_from(info: &device::Info) -> Result<Self, Self::Error> {
        let fw_version = OctetString::new(vec![
            info.major_version,
            info.minor_version,
            info.build_version,
        ])?;

        Ok(Self { fw_version })
    }
}

impl AssociatedOid for FirmwareVersion {
    const OID: ObjectIdentifier = YUBICO_FIRMWARE_VERSION;
}

impl AsExtension for FirmwareVersion {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

/// Serial number of the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Serial {
    pub serial: u32,
}

impl From<&device::Info> for Serial {
    fn from(info: &device::Info) -> Self {
        let serial = info.serial_number.0;
        Self { serial }
    }
}

impl AssociatedOid for Serial {
    const OID: ObjectIdentifier = YUBICO_SERIAL_NUMBER;
}

impl AsExtension for Serial {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

/// Origin of the object on the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Origin {
    pub origin: BitString,
}

impl TryFrom<object::Origin> for Origin {
    type Error = Error;
    fn try_from(origin: object::Origin) -> Result<Self, Self::Error> {
        let origin = BitString::new(0, vec![origin.to_u8()])?;
        Ok(Self { origin })
    }
}

impl AssociatedOid for Origin {
    const OID: ObjectIdentifier = YUBICO_ORIGIN;
}

impl AsExtension for Origin {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

/// Domain of the object on the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Domain {
    pub domain: BitString,
}

impl TryFrom<domain::Domain> for Domain {
    type Error = Error;
    fn try_from(domain: domain::Domain) -> Result<Self, Self::Error> {
        let domain = BitString::new(0, domain.bits().to_be_bytes())?;
        Ok(Self { domain })
    }
}

impl AssociatedOid for Domain {
    const OID: ObjectIdentifier = YUBICO_DOMAIN;
}

impl AsExtension for Domain {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

/// Capability of the object on the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Capability {
    pub capability: BitString,
}

impl TryFrom<capability::Capability> for Capability {
    type Error = Error;
    fn try_from(cap: capability::Capability) -> Result<Self, Self::Error> {
        let capability = BitString::new(0, cap.bits().to_be_bytes())?;
        Ok(Self { capability })
    }
}

impl AssociatedOid for Capability {
    const OID: ObjectIdentifier = YUBICO_CAPABILITY;
}

impl AsExtension for Capability {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

/// ID of the object on the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ObjectId {
    pub id: u16,
}

impl AssociatedOid for ObjectId {
    const OID: ObjectIdentifier = YUBICO_OBJECT_ID;
}

impl AsExtension for ObjectId {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

/// Label of the object on the YubiHSM.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Label {
    pub label: String,
}

impl TryFrom<&object::Label> for Label {
    type Error = FromUtf8Error;
    fn try_from(label: &object::Label) -> Result<Self, Self::Error> {
        let label = String::from_utf8(label.0.to_vec())?
            .trim_end_matches('\0')
            .to_string();
        Ok(Self { label })
    }
}

impl AssociatedOid for Label {
    const OID: ObjectIdentifier = YUBICO_LABEL;
}

impl AsExtension for Label {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use der::Encode;
    use hex_literal::hex;

    use super::*;
    use crate::device;

    #[test]
    fn test_serialize_ext() {
        let info = device::Info {
            major_version: 2,
            minor_version: 2,
            build_version: 0,
            serial_number: device::SerialNumber::from_str("0018952406").unwrap(),
            log_store_capacity: 0,
            log_store_used: 0,
            algorithms: vec![],
        };

        let fwv = FirmwareVersion::try_from(&info).unwrap();

        assert_eq!(
            fwv.fw_version.to_der().unwrap(),
            vec![0x04u8, 0x03, 0x02, 0x02, 0x00]
        );

        let serial = Serial::from(&info);

        assert_eq!(
            serial.to_der().unwrap(),
            vec![0x30u8, 0x06, 0x02, 0x04, 0x01, 0x21, 0x30, 0xd6]
        );

        let origin = object::Origin::Generated;
        let origin = Origin::try_from(origin).unwrap();

        assert_eq!(
            origin.origin.to_der().unwrap(),
            vec![0x03u8, 0x02, 0x00, 0x01]
        );

        let domain = domain::Domain::DOM1;
        let domain = Domain::try_from(domain).unwrap();

        assert_eq!(
            domain.domain.to_der().unwrap(),
            vec![0x03u8, 0x03, 0x00, 0x00, 0x01]
        );

        let cap = capability::Capability::DECRYPT_OAEP;
        let cap = Capability::try_from(cap).unwrap();

        assert_eq!(
            cap.capability.to_der().unwrap(),
            vec![0x03u8, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00]
        );

        let id = ObjectId { id: 0x0f };

        assert_eq!(id.id.to_der().unwrap(), vec![0x02u8, 0x01, 0x0f]);

        let label = object::Label::from_str("management: local import").unwrap();
        let label = Label::try_from(&label).unwrap();

        assert_eq!(
            label.label.to_der().unwrap(),
            hex!("0C186D616E6167656D656E743A206C6F63616C20696D706F7274")
        );
    }
}
