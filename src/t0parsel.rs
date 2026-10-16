//! wire format codec for "wis:" messages.
//!
//! supports f64, u64, string, bytes, single byte, and bool.
//! all numeric types use big-endian hex representation.
//! all errors are returned as static string slices.
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::integer_division)]
//#![deny(clippy::expect_used)]
#![deny(clippy::unreachable)]
#![deny(clippy::todo)]
#![deny(clippy::float_cmp)]
#![forbid(unsafe_code)]
use std::collections::HashSet;

use crate::checked_cast;

/// possible field values.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// 64‑bit floating point number.
    Float(f64),
    /// 64‑bit unsigned integer.
    Unsigned(u64),
    /// utf-8 string.
    String(String),
    /// arbitrary byte vector.
    Bytes(Box<[u8]>),
    /// single byte.
    Byte(u8),
    /// boolean.
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq)]
/// a named field with its value.
pub struct Field {
    ///
    pub name: String,
    ///
    pub value: Value,
}

/// main codec for the "wis:" wire format.
pub struct Codec;

impl Codec {
    // ---------- parsing ----------

    /// parses a string into a vector of fields.
    pub fn parse(input: &str) -> Result<Box<[Field]>, String> {
        if !input.starts_with("wis:") {
            return Err("message must start with 'wis:' prefix".to_string());
        }
        let fields_part = &input[4..];
        if fields_part.is_empty() {
            return Err("empty fields list after 'wis:'".to_string());
        }

        let mut fields = Vec::new();
        let mut used_names = HashSet::new();

        for segment in fields_part.split(';') {
            if segment.is_empty() {
                continue;
            }
            let field = Self::parse_field(segment)?;
            if !used_names.insert(field.name.clone()) {
                return Err("duplicate field name".to_string());
            }
            fields.push(field);
        }

        if fields.is_empty() {
            return Err("empty fields list after 'wis:'".to_string());
        }

        Ok(fields.into_boxed_slice())
    }

    /// parses a single "name@type_hexvalue" segment.
    fn parse_field(segment: &str) -> Result<Field, String> {
        let (name, rest) = segment
            .split_once('@')
            .ok_or("invalid field format: missing '@'")?;
        if name.is_empty() {
            return Err("field name cannot be empty".to_string());
        }
        let (type_tag, hex_val) = rest
            .split_once('_')
            .ok_or("invalid field format: missing '_'")?;
        if hex_val.is_empty() {
            return Err("field value cannot be empty".to_string());
        }
        let value = Self::parse_value(type_tag, hex_val)?;
        Ok(Field {
            name: name.to_string(),
            value,
        })
    }

    /// dispatches value parsing based on the type tag.
    fn parse_value(typ: &str, hex_val: &str) -> Result<Value, String> {
        match typ {
            "ff" => Self::parse_f64(hex_val),
            "uu" => Self::parse_u64(hex_val),
            "ss" => Self::parse_string(hex_val),
            "bb" => Self::parse_bytes(hex_val),
            "b" => Self::parse_byte(hex_val),
            "t" => Self::parse_bool(hex_val),
            _ => Err("invalid type specifier: expected ff, uu, ss, bb, b, or t".to_string()),
        }
    }

    fn parse_f64(hex_val: &str) -> Result<Value, String> {
        if hex_val.len() != 16 {
            return Err("f64 value must be exactly 16 hex chars (8 bytes)".to_string());
        }
        let bytes = Self::hex_decode(hex_val)?;
        let arr = bytes
            .try_into()
            .map_err(|_| "invalid byte length for f64")?;
        Ok(Value::Float(f64::from_be_bytes(arr)))
    }

    fn parse_u64(hex_val: &str) -> Result<Value, String> {
        let len = hex_val.len();
        if !(2..=16).contains(&len) || !len.is_multiple_of(2) {
            return Err(
                "u64 hex length must be between 2 and 16 chars (1-8 bytes) and even".to_string(),
            );
        }
        let bytes = Self::hex_decode(hex_val)?;
        if bytes.len() > 8 {
            return Err("u64 value too large (more than 8 bytes)".to_string());
        }
        let mut padded = [0u8; 8];
        let start_idx = 8usize
            .checked_sub(bytes.len())
            .ok_or("overflow: bytes.len() > 8")?;
        let dest_slice = padded.get_mut(start_idx..).ok_or("invalid padding range")?;
        dest_slice.copy_from_slice(&bytes);
        Ok(Value::Unsigned(u64::from_be_bytes(padded)))
    }
    fn parse_string(hex_val: &str) -> Result<Value, String> {
        if hex_val.is_empty() || !hex_val.len().is_multiple_of(2) {
            return Err("string hex must be non‑empty and have even length".to_string());
        }
        let bytes = Self::hex_decode(hex_val)?;
        let s = String::from_utf8(bytes).map_err(|_| "invalid utf-8 sequence")?;
        if s.is_empty() {
            return Err("decoded string cannot be empty".to_string());
        }
        Ok(Value::String(s))
    }

    fn parse_bytes(hex_val: &str) -> Result<Value, String> {
        if hex_val.is_empty() || !hex_val.len().is_multiple_of(2) {
            return Err("bytes hex must be non‑empty and have even length".to_string());
        }
        let bytes = Self::hex_decode(hex_val)?;
        if bytes.is_empty() {
            return Err("byte array cannot be empty".to_string());
        }
        Ok(Value::Bytes(bytes.into_boxed_slice()))
    }

    fn parse_byte(hex_val: &str) -> Result<Value, String> {
        if hex_val.len() != 2 {
            return Err("single byte must be exactly 2 hex chars".to_string());
        }
        let bytes = Self::hex_decode(hex_val)?;
        let byte_val = *bytes.first().ok_or("empty bytes after decode")?;
        Ok(Value::Byte(byte_val))
    }
    fn parse_bool(hex_val: &str) -> Result<Value, String> {
        match hex_val.to_ascii_lowercase().as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err("boolean value must be 'true' or 'false'".to_string()),
        }
    }

    /// manual hex decoder (no external crates).
    fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("hex string must have even length".to_string());
        }
        let mut out = Vec::with_capacity(
            s.len()
                .checked_div(2)
                .expect("division by zero in s.len() / 2"),
        );
        let mut chars = s.as_bytes().iter();
        while let (Some(&hi), Some(&lo)) = (chars.next(), chars.next()) {
            let h = Self::hex_digit(hi).ok_or("invalid hex digit")?;
            let l = Self::hex_digit(lo).ok_or("invalid hex digit")?;
            out.push((h << 4) | l);
        }
        Ok(out)
    }

    fn hex_digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|val| val.checked_add(10)),
            b'A'..=b'F' => c.checked_sub(b'A').and_then(|val| val.checked_add(10)),
            _ => None,
        }
    }

    // ---------- serialisation ----------

    /// converts a slice of fields into a wire string.
    pub fn serialize(fields: &[Field]) -> Result<String, String> {
        if fields.is_empty() {
            return Err("empty fields list".to_string());
        }
        let mut used_names = HashSet::new();
        let mut parts = Vec::with_capacity(fields.len());
        for field in fields {
            if field.name.is_empty() {
                return Err("field name cannot be empty".to_string());
            }
            if !used_names.insert(&field.name) {
                return Err("duplicate field name".to_string());
            }
            let value_part = Self::serialize_value(&field.value)?;
            parts.push(format!("{}@{}", field.name, value_part));
        }
        Ok(format!("wis:{}", parts.join(";")))
    }

    fn serialize_value(val: &Value) -> Result<String, String> {
        match val {
            Value::Float(f) => {
                let bytes = f.to_be_bytes();
                Ok(format!("ff_{}", Self::hex_encode(&bytes)))
            },
            Value::Unsigned(u) => {
                let bytes = Self::u64_to_min_bytes(*u);
                if bytes.is_empty() {
                    return Err("empty unsigned value".to_string());
                }
                Ok(format!("uu_{}", Self::hex_encode(&bytes)))
            },
            Value::String(s) => {
                if s.is_empty() {
                    return Err("empty string value".to_string());
                }
                Ok(format!("ss_{}", Self::hex_encode(s.as_bytes())))
            },
            Value::Bytes(b) => {
                if b.is_empty() {
                    return Err("empty byte array".to_string());
                }
                Ok(format!("bb_{}", Self::hex_encode(b)))
            },
            Value::Byte(b) => Ok(format!("b_{}", Self::hex_encode(&[*b]))),
            Value::Bool(b) => {
                let s = if *b { "true" } else { "false" };
                Ok(format!("t_{}", s))
            },
        }
    }

    /// converts a u64 to its minimal big-endian representation (no leading zero bytes).
    fn u64_to_min_bytes(n: u64) -> Vec<u8> {
        if n == 0 {
            return vec![0];
        }
        let leading = checked_cast!(n.leading_zeros() => usize, expect "Leading zeros conversion to usize failed")
    .checked_div(8)
    .expect("division by zero in leading / 8");
        let be_bytes = n.to_be_bytes();
        be_bytes.get(leading..).unwrap_or(&[]).to_vec()
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_hex_encode(bytes: &[u8]) -> String {
        Self::hex_encode(bytes)
    }
    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(
            bytes
                .len()
                .checked_mul(2)
                .expect("overflow in bytes.len() * 2"),
        );
        for &b in bytes {
            let high = HEX
                .get(checked_cast!(b >> 4 => usize, expect "High nibble index conversion failed"))
                .copied()
                .unwrap_or(b'0');
            let low = HEX
                .get(checked_cast!(b & 0x0f => usize, expect "Low nibble index conversion failed"))
                .copied()
                .unwrap_or(b'0');
            out.push(checked_cast!(high => char, expect "ASCII byte to char conversion failed"));
            out.push(checked_cast!(low => char, expect "ASCII byte to char conversion failed"));
        }
        out
    }
}
