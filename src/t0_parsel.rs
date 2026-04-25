//! wire format codec for "wis:" messages.
//!
//! supports f64, u64, string, bytes, single byte, and bool.
//! all numeric types use big-endian hex representation.
//! all errors are returned as static string slices.
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]

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
    pub fn parse(input: &str) -> Result<Box<[Field]>, &'static str> {
        if !input.starts_with("wis:") {
            return Err("message must start with 'wis:' prefix");
        }
        let fields_part = &input[4..];
        if fields_part.is_empty() {
            return Err("empty fields list after 'wis:'");
        }

        let mut fields = Vec::new();
        let mut used_names = HashSet::new();

        for segment in fields_part.split(';') {
            if segment.is_empty() {
                continue;
            }
            let field = Self::parse_field(segment)?;
            if !used_names.insert(field.name.clone()) {
                return Err("duplicate field name");
            }
            fields.push(field);
        }

        if fields.is_empty() {
            return Err("empty fields list after 'wis:'");
        }

        Ok(fields.into_boxed_slice())
    }

    /// parses a single "name@type_hexvalue" segment.
    fn parse_field(segment: &str) -> Result<Field, &'static str> {
        let (name, rest) = segment
            .split_once('@')
            .ok_or("invalid field format: missing '@'")?;
        if name.is_empty() {
            return Err("field name cannot be empty");
        }
        let (type_tag, hex_val) = rest
            .split_once('_')
            .ok_or("invalid field format: missing '_'")?;
        if hex_val.is_empty() {
            return Err("field value cannot be empty");
        }
        let value = Self::parse_value(type_tag, hex_val)?;
        Ok(Field {
            name: name.to_string(),
            value,
        })
    }

    /// dispatches value parsing based on the type tag.
    fn parse_value(typ: &str, hex_val: &str) -> Result<Value, &'static str> {
        match typ {
            "ff" => Self::parse_f64(hex_val),
            "uu" => Self::parse_u64(hex_val),
            "ss" => Self::parse_string(hex_val),
            "bb" => Self::parse_bytes(hex_val),
            "b" => Self::parse_byte(hex_val),
            "t" => Self::parse_bool(hex_val),
            _ => Err("invalid type specifier: expected ff, uu, ss, bb, b, or t"),
        }
    }

    fn parse_f64(hex_val: &str) -> Result<Value, &'static str> {
        if hex_val.len() != 16 {
            return Err("f64 value must be exactly 16 hex chars (8 bytes)");
        }
        let bytes = Self::hex_decode(hex_val)?;
        let arr = bytes
            .try_into()
            .map_err(|_| "invalid byte length for f64")?;
        Ok(Value::Float(f64::from_be_bytes(arr)))
    }

    fn parse_u64(hex_val: &str) -> Result<Value, &'static str> {
        let len = hex_val.len();
        if !(2..=16).contains(&len) || !len.is_multiple_of(2) {
            return Err("u64 hex length must be between 2 and 16 chars (1-8 bytes) and even");
        }
        let bytes = Self::hex_decode(hex_val)?;
        if bytes.len() > 8 {
            return Err("u64 value too large (more than 8 bytes)");
        }
        let mut padded = [0u8; 8];
        let start_idx = 8 - bytes.len();
        let dest_slice = padded.get_mut(start_idx..).ok_or("invalid padding range")?;
        dest_slice.copy_from_slice(&bytes);
        Ok(Value::Unsigned(u64::from_be_bytes(padded)))
    }
    fn parse_string(hex_val: &str) -> Result<Value, &'static str> {
        if hex_val.is_empty() || !hex_val.len().is_multiple_of(2) {
            return Err("string hex must be non‑empty and have even length");
        }
        let bytes = Self::hex_decode(hex_val)?;
        let s = String::from_utf8(bytes).map_err(|_| "invalid utf-8 sequence")?;
        if s.is_empty() {
            return Err("decoded string cannot be empty");
        }
        Ok(Value::String(s))
    }

    fn parse_bytes(hex_val: &str) -> Result<Value, &'static str> {
        if hex_val.is_empty() || !hex_val.len().is_multiple_of(2) {
            return Err("bytes hex must be non‑empty and have even length");
        }
        let bytes = Self::hex_decode(hex_val)?;
        if bytes.is_empty() {
            return Err("byte array cannot be empty");
        }
        Ok(Value::Bytes(bytes.into_boxed_slice()))
    }

    fn parse_byte(hex_val: &str) -> Result<Value, &'static str> {
        if hex_val.len() != 2 {
            return Err("single byte must be exactly 2 hex chars");
        }
        let bytes = Self::hex_decode(hex_val)?;
        let byte_val = *bytes.first().ok_or("empty bytes after decode")?;
        Ok(Value::Byte(byte_val))
    }
    fn parse_bool(hex_val: &str) -> Result<Value, &'static str> {
        match hex_val.to_ascii_lowercase().as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err("boolean value must be 'true' or 'false'"),
        }
    }

    /// manual hex decoder (no external crates).
    fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if !s.len().is_multiple_of(2) {
            return Err("hex string must have even length");
        }
        let mut out = Vec::with_capacity(s.len() / 2);
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
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    // ---------- serialisation ----------

    /// converts a slice of fields into a wire string.
    pub fn serialize(fields: &[Field]) -> Result<String, &'static str> {
        if fields.is_empty() {
            return Err("empty fields list");
        }
        let mut used_names = HashSet::new();
        let mut parts = Vec::with_capacity(fields.len());
        for field in fields {
            if field.name.is_empty() {
                return Err("field name cannot be empty");
            }
            if !used_names.insert(&field.name) {
                return Err("duplicate field name");
            }
            let value_part = Self::serialize_value(&field.value)?;
            parts.push(format!("{}@{}", field.name, value_part));
        }
        Ok(format!("wis:{}", parts.join(";")))
    }

    fn serialize_value(val: &Value) -> Result<String, &'static str> {
        match val {
            Value::Float(f) => {
                let bytes = f.to_be_bytes();
                Ok(format!("ff_{}", Self::hex_encode(&bytes)))
            },
            Value::Unsigned(u) => {
                let bytes = Self::u64_to_min_bytes(*u);
                if bytes.is_empty() {
                    return Err("empty unsigned value");
                }
                Ok(format!("uu_{}", Self::hex_encode(&bytes)))
            },
            Value::String(s) => {
                if s.is_empty() {
                    return Err("empty string value");
                }
                Ok(format!("ss_{}", Self::hex_encode(s.as_bytes())))
            },
            Value::Bytes(b) => {
                if b.is_empty() {
                    return Err("empty byte array");
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
            / 8;
        let be_bytes = n.to_be_bytes();
        be_bytes.get(leading..).unwrap_or(&[]).to_vec()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
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
//=======================================================================================================================================================================
#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_valid_full_example() {
        let input = "wis:name@ss_6e656564746f6b696c6c;data@ff_12ad34ff56784500;bakka@b_fd;bmamm@\
                     bb_aabbccdd0e;leen@uu_abcef0;isok@t_false";
        let fields = Codec::parse(input).unwrap();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].name, "name");
        assert_eq!(fields[0].value, Value::String("needtokill".to_string()));
        assert_eq!(fields[1].name, "data");
        let data_bytes = [0x12, 0xad, 0x34, 0xff, 0x56, 0x78, 0x45, 0x00];
        assert_eq!(
            fields[1].value,
            Value::Float(f64::from_be_bytes(data_bytes))
        );
        assert_eq!(fields[2].value, Value::Byte(0xfd));
        assert_eq!(
            fields[3].value,
            Value::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd, 0x0e].into_boxed_slice())
        );
        assert_eq!(fields[4].value, Value::Unsigned(0xabcef0));
        assert_eq!(fields[5].value, Value::Bool(false));
    }

    #[test]
    fn roundtrip_all_types() {
        let original = vec![
            Field {
                name: "f".to_string(),
                value: Value::Float(3.14115),
            },
            Field {
                name: "u".to_string(),
                value: Value::Unsigned(0xdeadbeef),
            },
            Field {
                name: "s".to_string(),
                value: Value::String("hello 🦀".to_string()),
            },
            Field {
                name: "b".to_string(),
                value: Value::Bytes(vec![0x01, 0x02, 0x03].into_boxed_slice()),
            },
            Field {
                name: "byte".to_string(),
                value: Value::Byte(0xff),
            },
            Field {
                name: "bool".to_string(),
                value: Value::Bool(true),
            },
        ];
        let ser = Codec::serialize(&original).unwrap();
        let parsed = Codec::parse(&ser).unwrap();
        assert_eq!(original.into_boxed_slice(), parsed);
    }

    #[test]
    fn roundtrip_u64_boundaries() {
        let cases = [0u64, 1, 255, 0xffff, 0x123456789abcdef, u64::MAX];
        for &u in &cases {
            let fields = vec![Field {
                name: "u".to_string(),
                value: Value::Unsigned(u),
            }];
            let ser = Codec::serialize(&fields).unwrap();
            let parsed = Codec::parse(&ser).unwrap();
            assert_eq!(parsed[0].value, Value::Unsigned(u));
        }
    }

    #[test]
    fn roundtrip_f64_special() {
        let specials = [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0, -0.0];
        for &f in &specials {
            let fields = vec![Field {
                name: "f".to_string(),
                value: Value::Float(f),
            }];
            let ser = Codec::serialize(&fields).unwrap();
            let parsed = Codec::parse(&ser).unwrap();
            let parsed_val = match &parsed[0].value {
                Value::Float(v) => *v,
                _ => panic!(),
            };
            if f.is_nan() {
                assert!(parsed_val.is_nan());
            } else {
                assert_eq!(parsed_val, f);
            }
        }
    }

    #[test]
    fn u64_minimal_encoding() {
        let fields = vec![Field {
            name: "u".to_string(),
            value: Value::Unsigned(0x123),
        }];
        let ser = Codec::serialize(&fields).unwrap();
        assert!(ser.contains("uu_0123"));
        let parsed = Codec::parse(&ser).unwrap();
        assert_eq!(parsed[0].value, Value::Unsigned(0x123));
    }

    #[test]
    fn leading_trailing_semicolons_ignored() {
        let input = "wis:;a@b_01;;b@b_02;";
        let fields = Codec::parse(input).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "a");
        assert_eq!(fields[1].name, "b");
    }

    #[test]
    fn bool_case_insensitive() {
        let input = "wis:ok@t_TruE;no@t_FaLsE";
        let fields = Codec::parse(input).unwrap();
        assert_eq!(fields[0].value, Value::Bool(true));
        assert_eq!(fields[1].value, Value::Bool(false));
    }

    #[test]
    fn hex_uppercase_accepted() {
        let input = "wis:u@uu_DEADBEEF";
        let fields = Codec::parse(input).unwrap();
        assert_eq!(fields[0].value, Value::Unsigned(0xdeadbeef));
    }

    #[test]
    fn empty_byte_array_not_allowed_in_serialize() {
        let fields = vec![Field {
            name: "b".to_string(),
            value: Value::Bytes(vec![].into_boxed_slice()),
        }]
        .into_boxed_slice();
        let err = Codec::serialize(&fields).unwrap_err();
        assert_eq!(err, "empty byte array");
    }

    #[test]
    fn empty_string_not_allowed_in_serialize() {
        let fields = vec![Field {
            name: "s".to_string(),
            value: Value::String("".to_string()),
        }];
        let err = Codec::serialize(&fields).unwrap_err();
        assert_eq!(err, "empty string value");
    }

    #[test]
    fn parse_error_missing_prefix() {
        let err = Codec::parse("foo:abc").unwrap_err();
        assert_eq!(err, "message must start with 'wis:' prefix");
    }

    #[test]
    fn parse_error_empty_after_prefix() {
        let err = Codec::parse("wis:").unwrap_err();
        assert_eq!(err, "empty fields list after 'wis:'");
    }

    #[test]
    fn parse_error_no_at() {
        let err = Codec::parse("wis:nameff_1234").unwrap_err();
        assert_eq!(err, "invalid field format: missing '@'");
    }

    #[test]
    fn parse_error_no_underscore() {
        let err = Codec::parse("wis:name@ff1234").unwrap_err();
        assert_eq!(err, "invalid field format: missing '_'");
    }

    #[test]
    fn parse_error_empty_field_name() {
        let err = Codec::parse("wis:@ff_1234567890abcdef").unwrap_err();
        assert_eq!(err, "field name cannot be empty");
    }

    #[test]
    fn parse_error_empty_value() {
        let err = Codec::parse("wis:name@ff_").unwrap_err();
        assert_eq!(err, "field value cannot be empty");
    }

    #[test]
    fn parse_error_duplicate_name() {
        let input = "wis:a@b_01;a@b_02";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "duplicate field name");
    }

    #[test]
    fn parse_error_invalid_type() {
        let input = "wis:x@xx_1234";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(
            err,
            "invalid type specifier: expected ff, uu, ss, bb, b, or t"
        );
    }

    #[test]
    fn parse_error_f64_wrong_len() {
        let input = "wis:x@ff_1234";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "f64 value must be exactly 16 hex chars (8 bytes)");
    }

    #[test]
    fn parse_error_u64_too_short() {
        let input = "wis:x@uu_1";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(
            err,
            "u64 hex length must be between 2 and 16 chars (1-8 bytes) and even"
        );
    }

    #[test]
    fn parse_error_u64_too_long() {
        let input = "wis:x@uu_0123456789abcdef01";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(
            err,
            "u64 hex length must be between 2 and 16 chars (1-8 bytes) and even"
        );
    }

    #[test]
    fn parse_error_u64_odd_length() {
        let input = "wis:x@uu_123";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(
            err,
            "u64 hex length must be between 2 and 16 chars (1-8 bytes) and even"
        );
    }

    #[test]
    fn parse_error_u64_overflow() {
        let input = "wis:x@uu_0123456789abcdef12";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(
            err,
            "u64 hex length must be between 2 and 16 chars (1-8 bytes) and even"
        );
    }

    #[test]
    fn parse_error_string_invalid_utf8() {
        let input = "wis:s@ss_ff";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "invalid utf-8 sequence");
    }

    #[test]
    fn parse_error_string_empty_after_decode() {
        let input = "wis:s@ss_";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "field value cannot be empty");
    }

    #[test]
    fn parse_error_bytes_odd_length() {
        let input = "wis:b@bb_123";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "bytes hex must be non‑empty and have even length");
    }

    #[test]
    fn parse_error_bytes_empty() {
        let input = "wis:b@bb_";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "field value cannot be empty");
    }

    #[test]
    fn parse_error_byte_wrong_len() {
        let input = "wis:b@b_123";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "single byte must be exactly 2 hex chars");
    }

    #[test]
    fn parse_error_bool_invalid() {
        let input = "wis:b@t_yeah";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "boolean value must be 'true' or 'false'");
    }

    #[test]
    fn parse_error_hex_invalid_char() {
        let input = "wis:x@ff_zzzzzzzzzzzzzzzz";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "invalid hex digit");
    }

    #[test]
    fn parse_error_hex_odd_length_general() {
        let input = "wis:x@ff_123";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "f64 value must be exactly 16 hex chars (8 bytes)");
    }

    #[test]
    fn serialize_error_empty_fields() {
        let err = Codec::serialize(&[]).unwrap_err();
        assert_eq!(err, "empty fields list");
    }

    #[test]
    fn serialize_error_empty_field_name() {
        let fields = vec![Field {
            name: "".to_string(),
            value: Value::Byte(0),
        }];
        let err = Codec::serialize(&fields).unwrap_err();
        assert_eq!(err, "field name cannot be empty");
    }

    #[test]
    fn serialize_error_duplicate_name() {
        let fields = vec![
            Field {
                name: "a".to_string(),
                value: Value::Byte(1),
            },
            Field {
                name: "a".to_string(),
                value: Value::Byte(2),
            },
        ];
        let err = Codec::serialize(&fields).unwrap_err();
        assert_eq!(err, "duplicate field name");
    }

    #[test]
    fn very_long_string_and_bytes() {
        let long_str = "x".repeat(1000);
        let hex_long = Codec::hex_encode(long_str.as_bytes());
        let input = format!("wis:data@ss_{}", hex_long);
        let fields = Codec::parse(&input).unwrap();
        assert_eq!(fields[0].value, Value::String(long_str));
    }

    #[test]
    fn very_long_bytes() {
        let long_bytes = vec![0xab; 500];
        let hex_long = Codec::hex_encode(&long_bytes);
        let input = format!("wis:data@bb_{}", hex_long);
        let fields = Codec::parse(&input).unwrap();
        assert_eq!(fields[0].value, Value::Bytes(long_bytes.into_boxed_slice()));
    }

    #[test]
    fn multiple_fields_with_same_name_after_error() {
        let input = "wis:a@b_01;a@b_02;b@b_03";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "duplicate field name");
    }

    #[test]
    fn zero_u64_encoding() {
        let fields = vec![Field {
            name: "z".to_string(),
            value: Value::Unsigned(0),
        }];
        let ser = Codec::serialize(&fields).unwrap();
        assert!(ser.contains("uu_00"));
        let parsed = Codec::parse(&ser).unwrap();
        assert_eq!(parsed[0].value, Value::Unsigned(0));
    }

    #[test]
    fn f64_infinity_roundtrip() {
        let fields = vec![Field {
            name: "inf".to_string(),
            value: Value::Float(f64::INFINITY),
        }];
        let ser = Codec::serialize(&fields).unwrap();
        let parsed = Codec::parse(&ser).unwrap();
        assert_eq!(parsed[0].value, Value::Float(f64::INFINITY));
    }

    #[test]
    fn f64_negative_zero_roundtrip() {
        let fields = vec![Field {
            name: "negzero".to_string(),
            value: Value::Float(-0.0),
        }];
        let ser = Codec::serialize(&fields).unwrap();
        let parsed = Codec::parse(&ser).unwrap();
        assert_eq!(parsed[0].value, Value::Float(-0.0));
    }

    #[test]
    fn parse_extra_semicolons_only() {
        let input = "wis:;;";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "empty fields list after 'wis:'");
    }

    #[test]
    fn parse_field_with_extra_underscores_in_hex() {
        let input = "wis:test@ss_aa_bb_";
        let err = Codec::parse(input).unwrap_err();
        assert_eq!(err, "invalid hex digit");
    }
}
