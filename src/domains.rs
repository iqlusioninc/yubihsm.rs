// Apparently bitflags isn't clippy-safe
#![allow(unknown_lints, redundant_field_names, suspicious_arithmetic_impl, missing_docs)]

use std::fmt;

use serde::ser::{Serialize, Serializer};
use serde::de::{self, Deserialize, Deserializer, Visitor};

bitflags! {
    /// Logical partition within the `YubiHSM2`, allowing several clients
    /// to access the same device but access controlled on a domain-by-domain
    /// basis. For more information, see the Yubico documentation:
    ///
    /// <https://developers.yubico.com/YubiHSM2/Concepts/Domain.html>
    pub struct Domains: u16 {
        const DOMAIN_1 = 0x0001;
        const DOMAIN_2 = 0x0002;
        const DOMAIN_3 = 0x0004;
        const DOMAIN_4 = 0x0008;
        const DOMAIN_5 = 0x0010;
        const DOMAIN_6 = 0x0020;
        const DOMAIN_7 = 0x0040;
        const DOMAIN_8 = 0x0080;
        const DOMAIN_9 = 0x0100;
        const DOMAIN_10 = 0x0200;
        const DOMAIN_11 = 0x0400;
        const DOMAIN_12 = 0x0800;
        const DOMAIN_13 = 0x1000;
        const DOMAIN_14 = 0x2000;
        const DOMAIN_15 = 0x4000;
        const DOMAIN_16 = 0x8000;
    }
}

impl Serialize for Domains {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.bits())
    }
}

impl<'de> Deserialize<'de> for Domains {
    fn deserialize<D>(deserializer: D) -> Result<Domains, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DomainsVisitor;

        impl<'de> Visitor<'de> for DomainsVisitor {
            type Value = Domains;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("2-bytes containing domain bitflags")
            }

            fn visit_u16<E>(self, value: u16) -> Result<Domains, E>
            where
                E: de::Error,
            {
                Domains::from_bits(value).ok_or_else(|| E::custom("invalid domain bitflags"))
            }
        }

        deserializer.deserialize_u16(DomainsVisitor)
    }
}
