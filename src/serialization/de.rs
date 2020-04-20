//! Serde-powered deserializer for `YubiHSM` messages

use super::error::Error;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use std::io::Read;

/// Deserializer for `YubiHSM` messages, which reads from a reader object
pub struct Deserializer<R: Read> {
    reader: R,
}

impl<R: Read> Deserializer<R> {
    pub fn new(reader: R) -> Self {
        Deserializer { reader }
    }
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for &'a mut Deserializer<R> {
    type Error = Error;

    #[inline]
    fn deserialize_any<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_bool<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    #[inline]
    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        let mut byte = [0u8];
        self.reader.read_exact(&mut byte)?;
        visitor.visit_u8(byte[0])
    }

    #[inline]
    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        let mut bytes = [0u8; 2];
        self.reader.read_exact(&mut bytes)?;
        visitor.visit_u16(u16::from_be_bytes(bytes))
    }

    #[inline]
    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        let mut bytes = [0u8; 4];
        self.reader.read_exact(&mut bytes)?;
        visitor.visit_u32(u32::from_be_bytes(bytes))
    }

    #[inline]
    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        let mut bytes = [0u8; 8];
        self.reader.read_exact(&mut bytes)?;
        visitor.visit_u64(u64::from_be_bytes(bytes))
    }

    #[inline]
    fn deserialize_i8<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    #[inline]
    fn deserialize_i16<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    #[inline]
    fn deserialize_i32<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    #[inline]
    fn deserialize_i64<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    #[inline]
    fn deserialize_f32<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    #[inline]
    fn deserialize_f64<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_char<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_str<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_string<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_bytes<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_byte_buf<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_enum<V>(
        self,
        _enum: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        struct Access<'a, R: Read> {
            deserializer: &'a mut Deserializer<R>,
            len: usize,
        }

        impl<'de, 'a, 'b: 'a, R: Read> SeqAccess<'de> for Access<'a, R> {
            type Error = Error;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
            where
                T: DeserializeSeed<'de>,
            {
                if self.len == 0 {
                    return Ok(None);
                }

                self.len -= 1;
                let value = DeserializeSeed::deserialize(seed, &mut *self.deserializer)?;
                Ok(Some(value))
            }

            fn size_hint(&self) -> Option<usize> {
                Some(self.len)
            }
        }

        visitor.visit_seq(Access {
            deserializer: self,
            len,
        })
    }

    fn deserialize_option<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        // SeqAccess which consumes the remainder of the message
        struct Access<'a, R: Read> {
            deserializer: &'a mut Deserializer<R>,
        }

        impl<'de, 'a, 'b: 'a, R: Read> SeqAccess<'de> for Access<'a, R> {
            type Error = Error;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Error>
            where
                T: DeserializeSeed<'de>,
            {
                Ok(DeserializeSeed::deserialize(seed, &mut *self.deserializer).ok())
            }

            fn size_hint(&self) -> Option<usize> {
                None
            }
        }

        visitor.visit_seq(Access { deserializer: self })
    }

    fn deserialize_map<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_struct<V>(
        self,
        _name: &str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(fields.len(), visitor)
    }

    fn deserialize_identifier<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn deserialize_newtype_struct<V>(self, _name: &str, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_ignored_any<V>(self, _: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        unimplemented!();
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<'de, 'a, R: Read> serde::de::VariantAccess<'de> for &'a mut Deserializer<R> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        unimplemented!();
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, _seed: T) -> Result<T::Value, Error> {
        unimplemented!();
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, _: V) -> Result<V::Value, Error> {
        unimplemented!();
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        unimplemented!();
    }
}
