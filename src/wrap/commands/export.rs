//! Export an encrypted object from the `YubiHSM 2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrapped.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
    wrap,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedCommand {
    /// ID of the wrap key to encrypt the object with
    pub wrap_key_id: object::Id,

    /// Type of object to be wrapped
    pub object_type: object::Type,

    /// Object ID of the object to be exported (in encrypted form)
    pub object_id: object::Id,

    /// Export ED25519 key with its seed. Default is not to.
    #[serde(skip_serializing_if = "Seed::is_exclude", with = "seed")]
    pub include_seed: Seed,
}

impl Command for ExportWrappedCommand {
    type ResponseType = ExportWrappedResponse;
}

/// Response from `command::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedResponse(pub(crate) wrap::Message);

impl Response for ExportWrappedResponse {
    const COMMAND_CODE: command::Code = command::Code::ExportWrapped;
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) enum Seed {
    #[default]
    Exclude,
    Include,
}

impl Seed {
    fn is_exclude(&self) -> bool {
        matches!(self, Self::Exclude)
    }
}

mod seed {
    use core::fmt;

    use serde::{
        de::{self, Deserializer, Error, Unexpected, Visitor},
        ser::Serializer,
    };

    use super::Seed;

    pub(super) fn serialize<S>(value: &Seed, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Seed::Exclude => serializer.serialize_unit(),
            Seed::Include => serializer.serialize_u8(1),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Seed, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SeedVisitor;

        impl<'de> Visitor<'de> for SeedVisitor {
            type Value = Seed;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an optional single bytes (value 1) or empty")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let value = if let Some(value) = seq.next_element::<u8>()? {
                    if value == 1 {
                        Seed::Include
                    } else {
                        return Err(A::Error::invalid_value(
                            Unexpected::Unsigned(value.into()),
                            &self,
                        ));
                    }
                } else {
                    return Ok(Seed::Exclude);
                };

                if seq.next_element::<u8>()?.is_some() {
                    Err(A::Error::custom(
                        "no value is expected after include_seed".to_string(),
                    ))
                } else {
                    Ok(value)
                }
            }
        }

        deserializer.deserialize_seq(SeedVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::serialization::{deserialize, serialize};

    use super::*;

    #[test]
    fn seed_serialization() {
        let mut value = ExportWrappedCommand {
            wrap_key_id: 0,
            object_type: object::Type::Opaque,
            object_id: 0,
            include_seed: Seed::Exclude,
        };
        assert_eq!(
            serialize(&value).unwrap(),
            vec![
                0, 0, // wrap key id
                1, // object_type
                0, 0 // object_id
            ]
        );
        value.include_seed = Seed::Include;
        assert_eq!(
            serialize(&value).unwrap(),
            vec![
                0, 0, // wrap key id
                1, // object_type
                0, 0, // object_id
                1  // include_seed
            ]
        );

        assert_eq!(
            deserialize::<ExportWrappedCommand>(&[
                0, 0, // wrap key id
                1, // object_type
                0, 0 // object_id
            ])
            .unwrap()
            .include_seed,
            Seed::Exclude
        );
        assert_eq!(
            deserialize::<ExportWrappedCommand>(&[
                0, 0, // wrap key id
                1, // object_type
                0, 0, // object_id
                1, // include_seed
            ])
            .unwrap()
            .include_seed,
            Seed::Include
        );
    }
}
