//! Macros used internally within this crate

/// Implement serde serializers for an algorithm type
macro_rules! impl_algorithm_serializers {
    ($alg:ident) => {
        impl ::serde::Serialize for $alg {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_u8(self.to_u8())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $alg {
            fn deserialize<D: ::serde::de::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$alg, D::Error> {
                use serde::de::{self, Visitor};
                use std::fmt;

                struct AlgorithmVisitor;

                impl<'de> Visitor<'de> for AlgorithmVisitor {
                    type Value = $alg;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        // TODO: customize this per algorithm
                        formatter.write_str("an unsigned tag byte")
                    }

                    fn visit_u8<E: de::Error>(self, value: u8) -> Result<$alg, E> {
                        $alg::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
                    }
                }

                deserializer.deserialize_u8(AlgorithmVisitor)
            }
        }
    };
}
