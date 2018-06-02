//! Serde-powered serializer for `YubiHSM` messages

use std::io::Write;
use std::u32;

use byteorder::{BigEndian, WriteBytesExt};
use serde;
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};

use super::error::SerializationError;

/// Serializer for `YubiHSM` messages
pub(crate) struct Serializer<W> {
    writer: W,
}

impl<W: Write> Serializer<W> {
    pub fn new(w: W) -> Serializer<W> {
        Serializer { writer: w }
    }
}

impl<'a, W: Write> serde::Serializer for &'a mut Serializer<W> {
    type Ok = ();
    type Error = SerializationError;
    type SerializeSeq = SerializeHelper<'a, W>;
    type SerializeTuple = SerializeHelper<'a, W>;
    type SerializeTupleStruct = SerializeHelper<'a, W>;
    type SerializeTupleVariant = SerializeHelper<'a, W>;
    type SerializeMap = SerializeHelper<'a, W>;
    type SerializeStruct = SerializeHelper<'a, W>;
    type SerializeStructVariant = SerializeHelper<'a, W>;

    fn serialize_unit(self) -> Result<(), SerializationError> {
        Ok(())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<(), SerializationError> {
        Ok(())
    }

    fn serialize_bool(self, _: bool) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_u8(self, v: u8) -> Result<(), SerializationError> {
        self.writer.write_u8(v).map_err(Into::into)
    }

    fn serialize_u16(self, v: u16) -> Result<(), SerializationError> {
        self.writer.write_u16::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_u32(self, v: u32) -> Result<(), SerializationError> {
        self.writer.write_u32::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_u64(self, v: u64) -> Result<(), SerializationError> {
        self.writer.write_u64::<BigEndian>(v).map_err(Into::into)
    }

    fn serialize_i8(self, _: i8) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_i16(self, _: i16) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_i32(self, _: i32) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_i64(self, _: i64) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_f32(self, _: f32) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_f64(self, _: f64) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_str(self, _: &str) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_char(self, _: char) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<(), SerializationError> {
        self.writer.write_all(v).map_err(Into::into)
    }

    fn serialize_none(self) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn serialize_some<T: ?Sized>(self, _v: &T) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        unimplemented!();
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, SerializationError> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, SerializationError> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, SerializationError> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, SerializationError> {
        unimplemented!();
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, SerializationError> {
        unimplemented!();
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, SerializationError> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, SerializationError> {
        unimplemented!();
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), SerializationError>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), SerializationError>
    where
        T: serde::Serialize + ?Sized,
    {
        unimplemented!();
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<(), SerializationError> {
        unimplemented!();
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

pub(crate) struct SerializeHelper<'a, W: 'a> {
    ser: &'a mut Serializer<W>,
}

impl<'a, W: Write> SerializeSeq for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<'a, W: Write> SerializeTuple for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<'a, W: Write> SerializeTupleStruct for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<'a, W: Write> SerializeTupleVariant for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<'a, W: Write> SerializeMap for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_key<K: ?Sized>(&mut self, value: &K) -> Result<(), SerializationError>
    where
        K: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn serialize_value<V: ?Sized>(&mut self, value: &V) -> Result<(), SerializationError>
    where
        V: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<'a, W: Write> SerializeStruct for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_field<T: ?Sized>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<'a, W: Write> SerializeStructVariant for SerializeHelper<'a, W> {
    type Ok = ();
    type Error = SerializationError;

    #[inline]
    fn serialize_field<T: ?Sized>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), SerializationError>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), SerializationError> {
        Ok(())
    }
}
