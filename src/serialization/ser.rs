//! Serde-powered serializer for `YubiHSM` messages

use super::error::Error;
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use std::io::Write;

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
    type Error = Error;
    type SerializeSeq = SerializeHelper<'a, W>;
    type SerializeTuple = SerializeHelper<'a, W>;
    type SerializeTupleStruct = SerializeHelper<'a, W>;
    type SerializeTupleVariant = SerializeHelper<'a, W>;
    type SerializeMap = SerializeHelper<'a, W>;
    type SerializeStruct = SerializeHelper<'a, W>;
    type SerializeStructVariant = SerializeHelper<'a, W>;

    fn serialize_unit(self) -> Result<(), Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        Ok(())
    }

    fn serialize_bool(self, _: bool) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        self.writer.write_all(&[v]).map_err(Into::into)
    }

    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        self.writer.write_all(&v.to_be_bytes()).map_err(Into::into)
    }

    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        self.writer.write_all(&v.to_be_bytes()).map_err(Into::into)
    }

    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        self.writer.write_all(&v.to_be_bytes()).map_err(Into::into)
    }

    fn serialize_i8(self, _: i8) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_i16(self, _: i16) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_i32(self, _: i32) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_i64(self, _: i64) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_f32(self, _: f32) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_f64(self, _: f64) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_str(self, _: &str) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_char(self, _: char) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        self.writer.write_all(v).map_err(Into::into)
    }

    fn serialize_none(self) -> Result<(), Error> {
        unimplemented!();
    }

    fn serialize_some<T>(self, _v: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        unimplemented!();
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        unimplemented!();
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        unimplemented!();
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Ok(SerializeHelper { ser: self })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        unimplemented!();
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<(), Error>
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
    ) -> Result<(), Error>
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
    ) -> Result<(), Error> {
        unimplemented!();
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

pub(crate) struct SerializeHelper<'a, W> {
    ser: &'a mut Serializer<W>,
}

impl<W: Write> SerializeSeq for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> SerializeTuple for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> SerializeTupleStruct for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> SerializeTupleVariant for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> SerializeMap for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_key<K>(&mut self, value: &K) -> Result<(), Error>
    where
        K: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn serialize_value<V>(&mut self, value: &V) -> Result<(), Error>
    where
        V: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> SerializeStruct for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<W: Write> SerializeStructVariant for SerializeHelper<'_, W> {
    type Ok = ();
    type Error = Error;

    #[inline]
    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Error>
    where
        T: serde::Serialize + ?Sized,
    {
        value.serialize(&mut *self.ser)
    }

    #[inline]
    fn end(self) -> Result<(), Error> {
        Ok(())
    }
}
