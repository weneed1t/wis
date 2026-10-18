use crate::t0parsel::*;

mod tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::float_cmp)]
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
