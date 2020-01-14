//! Logical partitions within the HSM, allowing several applications to share the device.

#![allow(missing_docs)]

mod error;

pub use self::error::{Error, ErrorKind};

use anomaly::fail;
use bitflags::bitflags;
use serde::{de, ser, Deserialize, Serialize};
use std::fmt;

/// All domains as an array of bitflag types
pub const DOMAINS: [Domain; 16] = [
    Domain::DOM1,
    Domain::DOM2,
    Domain::DOM3,
    Domain::DOM4,
    Domain::DOM5,
    Domain::DOM6,
    Domain::DOM7,
    Domain::DOM8,
    Domain::DOM9,
    Domain::DOM10,
    Domain::DOM11,
    Domain::DOM12,
    Domain::DOM13,
    Domain::DOM14,
    Domain::DOM15,
    Domain::DOM16,
];

bitflags! {
    /// Logical partition within the `YubiHSM 2`, allowing several clients
    /// to access the same device but access controlled on a domain-by-domain
    /// basis. For more information, see the Yubico documentation:
    ///
    /// <https://developers.yubico.com/YubiHSM2/Concepts/Domain.html>
    pub struct Domain: u16 {
        const DOM1 = 0x0001;
        const DOM2 = 0x0002;
        const DOM3 = 0x0004;
        const DOM4 = 0x0008;
        const DOM5 = 0x0010;
        const DOM6 = 0x0020;
        const DOM7 = 0x0040;
        const DOM8 = 0x0080;
        const DOM9 = 0x0100;
        const DOM10 = 0x0200;
        const DOM11 = 0x0400;
        const DOM12 = 0x0800;
        const DOM13 = 0x1000;
        const DOM14 = 0x2000;
        const DOM15 = 0x4000;
        const DOM16 = 0x8000;
    }
}

impl Domain {
    /// Get the `Domain` object corresponding to the given-numbered domain
    /// e.g. `Domain::at(1)` returns `Domain::DOM1`.
    pub fn at(index: usize) -> Result<Self, Error> {
        match index {
            1..=16 => Ok(DOMAINS[index - 1]),
            _ => fail!(
                ErrorKind::DomainInvalid,
                "invalid domain: {} (valid domains are 1-16)",
                index
            ),
        }
    }
}

impl Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_u16(self.bits())
    }
}

impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> Result<Domain, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct DomainVisitor;

        impl<'de> de::Visitor<'de> for DomainVisitor {
            type Value = Domain;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("2-bytes containing domain bitflags")
            }

            fn visit_u16<E>(self, value: u16) -> Result<Domain, E>
            where
                E: de::Error,
            {
                Domain::from_bits(value).ok_or_else(|| E::custom("invalid domain bitflags"))
            }
        }

        deserializer.deserialize_u16(DomainVisitor)
    }
}
