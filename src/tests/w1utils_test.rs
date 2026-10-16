use crate::w1utils::*;

mod tests_float_to_u32_scaled {
    use super::*;

    #[test]
    fn test_float_to_u32_scaled_edges() {
        assert_eq!(float_to_u32_scaled(0.0), Ok(0));

        assert_eq!(float_to_u32_scaled(1.0), Ok(u32::MAX));
    }

    #[test]
    fn test_float_to_u32_scaled_middle() {
        assert_eq!(float_to_u32_scaled(0.5), Ok(2_147_483_648));
    }

    #[test]
    fn test_float_to_u32_scaled_out_of_bounds() {
        assert!(float_to_u32_scaled(-0.0001).is_err());
        assert!(float_to_u32_scaled(1.0001).is_err());
    }

    #[test]
    fn test_float_to_u32_scaled_nan() {
        assert!(float_to_u32_scaled(f32::NAN).is_err());
    }
}

mod tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]

    use super::*;

    #[test]
    fn test_bytes_to_u64() {
        // Test cases with valid byte arrays
        let test_cases = vec![
            (vec![0x01], 0x0000000000000001),
            (vec![0x01, 0x00], 0x0000000000000100),
            (vec![0x00, 0x01, 0x02, 0x03], 0x0000000000010203),
            (vec![0x00, 0x01, 0x02, 0x03, 0x04], 0x0000000001020304),
            (
                vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                0x0102030405060708,
            ),
        ];

        for (bytes, expected) in test_cases {
            let result = bytes_to_u64(&bytes);
            assert!(result.is_ok(), "Failed to convert bytes to u64");
            assert_eq!(
                result.unwrap(),
                expected,
                "Conversion result does not match expected value"
            );
        }

        // Test cases with invalid byte arrays
        let invalid_cases = vec![
            vec![],     // Empty array
            vec![0; 9], // Array longer than 8 bytes
        ];

        for bytes in invalid_cases {
            let result = bytes_to_u64(&bytes);
            assert!(result.is_err(), "Expected error for invalid input");
        }
    }

    #[test]
    fn test_u64_to_1_8bytes() {
        // Test cases with valid byte arrays
        let test_cases = vec![
            (0x0000000000000001, vec![0x01]),
            (0x0000000000000100, vec![0x01, 0x00]),
            (0x0000000000010203, vec![0x00, 0x01, 0x02, 0x03]),
            (0x0000000001020304, vec![0x00, 0x01, 0x02, 0x03, 0x04]),
            (
                0x0102030405060708,
                vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            ),
        ];

        for (num, expected) in test_cases {
            let mut bytes = vec![0; expected.len()];
            let result = u64_to_1_8bytes(num, &mut bytes);
            assert!(result.is_ok(), "Failed to convert u64 to bytes");
            assert_eq!(
                bytes, expected,
                "Conversion result does not match expected value"
            );
        }

        // Test cases with invalid byte arrays
        let invalid_cases = vec![
            vec![],     // Empty array
            vec![0; 9], // Array longer than 8 bytes
        ];

        for mut bytes in invalid_cases {
            let result = u64_to_1_8bytes(0x0102030405060708, &mut bytes);
            assert!(result.is_err(), "Expected error for invalid input");
        }
    }

    #[test]
    fn test_round_trip_conversion() {
        // Test round-trip conversion for different lengths
        let test_cases = vec![
            (0x0000000000000001, 1),
            (0x0000000000000100, 2),
            (0x0000000001020300, 4),
            (0x0000000102030400, 5),
            (0x0102030405060708, 8),
        ];

        for (num, len) in test_cases {
            // Convert u64 to bytes
            let mut bytes = vec![0; len];
            let result = u64_to_1_8bytes(num, &mut bytes);
            assert!(result.is_ok(), "Failed to convert u64 to bytes");

            // Convert bytes back to u64
            let result = bytes_to_u64(&bytes);
            assert!(result.is_ok(), "Failed to convert bytes to u64");
            assert_eq!(result.unwrap(), num, "Round-trip conversion failed");
        }
    }
}

mod length_tests {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_exact_length_match() {
        let mut data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let lengths = [4, 1, 2, 2];
        let result = split_by_lengths(&mut data, &lengths, false);
        assert!(result.is_ok());
        let slices = result.unwrap();
        assert_eq!(slices.len(), 4);
        assert_eq!(slices[0], &mut [1, 2, 3, 4]);
        assert_eq!(slices[1], &mut [5]);
        assert_eq!(slices[2], &mut [6, 7]);
        assert_eq!(slices[3], &mut [8, 9]);
    }

    #[test]
    fn test_absolute_mode_adjustment() {
        let mut data = [1, 2, 3, 4, 5];
        let lengths = [2, 5, 3]; // Total exceeds data length
        let result = split_by_lengths(&mut data, &lengths, true);
        assert!(result.is_ok());
        let slices = result.unwrap();
        assert_eq!(slices.len(), 2); // Adjusted to fit
        assert_eq!(slices[0], &mut [1, 2]);
        assert_eq!(slices[1], &mut [3, 4, 5]);
    }

    #[test]
    fn test_length_overflow_error() {
        let mut data = [1, 2, 3];
        let lengths = [1, usize::MAX];
        let result = split_by_lengths(&mut data, &lengths, false);
        assert_eq!(result, Err("length overflow".to_string()));
    }

    #[test]
    fn test_length_mismatch_error() {
        let mut data = [1, 2, 3];
        let lengths = [1, 1]; // Sum < data.len()
        let result = split_by_lengths(&mut data, &lengths, false);
        assert_eq!(result, Err("total lengths != data length".to_string()));
    }

    #[test]
    fn test_empty_data() {
        let mut data: [i32; 0] = [];
        let lengths = [];
        let result = split_by_lengths(&mut data, &lengths, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}

mod position_tests {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_valid_positions() {
        let mut data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let positions = [4, 5, 7];
        let result = split_by_positions(&mut data, &positions, false);
        assert!(result.is_ok());
        let slices = result.unwrap();
        assert_eq!(slices.len(), 4);
        assert_eq!(slices[0], &mut [1, 2, 3, 4]);
        assert_eq!(slices[1], &mut [5]);
        assert_eq!(slices[2], &mut [6, 7]);
        assert_eq!(slices[3], &mut [8, 9]);
    }

    #[test]
    fn test_absolute_mode_with_out_of_bounds() {
        let mut data = [1, 2, 3, 4, 5];
        let positions = [2, 6]; // 6 is out of bounds
        let result = split_by_positions(&mut data, &positions, true);
        assert!(result.is_ok());
        let slices = result.unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0], &mut [1, 2]);
        assert_eq!(slices[1], &mut [3, 4, 5]);
    }

    #[test]
    fn test_non_increasing_positions_error() {
        let mut data = [1, 2, 3];
        let positions = [2, 1]; // Not increasing
        let result = split_by_positions(&mut data, &positions, false);
        assert_eq!(result, Err("positions not strictly increasing".to_string()));
    }

    #[test]
    fn test_out_of_bounds_error() {
        let mut data = [1, 2, 3];
        let positions = [1, 5]; // 5 is out of bounds
        let result = split_by_positions(&mut data, &positions, false);
        assert_eq!(result, Err("position exceeds data length".to_string()));
    }

    #[test]
    fn test_empty_data_with_positions() {
        let mut data: [i32; 0] = [];
        let positions = [];
        let result = split_by_positions(&mut data, &positions, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_single_position() {
        let mut data = [1, 2, 3, 4];
        let positions = [2];
        let result = split_by_positions(&mut data, &positions, false);
        assert!(result.is_ok());
        let slices = result.unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0], &mut [1, 2]);
        assert_eq!(slices[1], &mut [3, 4]);
    }
}

mod tests_f32 {
    #![allow(clippy::float_cmp)]
    #![allow(clippy::as_conversions)]
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ f32 to/from bytes conversion tests                                        │
    // └────────────────────────────────────────────────────────────────────────────┘

    #[test]
    fn f32_to_bytes_be_roundtrip() {
        let test_values = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            3.14119,
            -3.14259,
            f32::MAX,
            f32::MIN,
            f32::INFINITY,
            f32::NEG_INFINITY,
            f32::EPSILON,
        ];

        for &original in &test_values {
            let mut bytes = [0u8; 4];
            f32_to_bytes_be(original, &mut bytes);
            let restored = bytes_to_f32_be(&bytes);

            // compare using bit patterns for NaN handling
            if original.is_nan() {
                assert!(restored.is_nan(), "NaN should remain NaN");
            } else {
                assert_eq!(
                    original, restored,
                    "roundtrip failed for value: {}",
                    original
                );
            }
        }
    }

    #[test]
    fn f32_to_bytes_be_correct_endianness() {
        let value = 1.0_f32;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(value, &mut bytes);

        // IEEE 754 representation of 1.0 in big endian: 0x3f800000
        // bytes should be [0x3f, 0x80, 0x00, 0x00]
        assert_eq!(
            bytes,
            [0x3f, 0x80, 0x00, 0x00],
            "big endian representation of 1.0 is incorrect"
        );
    }

    #[test]
    fn f32_to_bytes_be_zero() {
        let value = 0.0_f32;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(value, &mut bytes);

        // positive zero: 0x00000000
        assert_eq!(
            bytes,
            [0x00, 0x00, 0x00, 0x00],
            "zero representation incorrect"
        );
    }

    #[test]
    fn f32_to_bytes_be_negative_zero() {
        let value = -0.0_f32;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(value, &mut bytes);

        // negative zero: 0x80000000 in big endian
        assert_eq!(
            bytes,
            [0x80, 0x00, 0x00, 0x00],
            "negative zero representation incorrect"
        );
    }

    #[test]
    fn f32_to_bytes_be_pi() {
        let value = std::f32::consts::PI;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(value, &mut bytes);

        // known value for debugging, but we'll just verify roundtrip
        let restored = bytes_to_f32_be(&bytes);
        assert!(
            (value - restored).abs() < f32::EPSILON,
            "PI conversion failed"
        );
    }

    #[test]
    fn bytes_to_f32_be_nan_handling() {
        // NaN has multiple representations, test that it stays NaN
        let nan = f32::NAN;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(nan, &mut bytes);
        let restored = bytes_to_f32_be(&bytes);

        assert!(restored.is_nan(), "NaN should remain NaN after conversion");
    }

    #[test]
    fn f32_to_bytes_be_infinity() {
        let inf = f32::INFINITY;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(inf, &mut bytes);
        let restored = bytes_to_f32_be(&bytes);

        assert!(
            restored.is_infinite() && restored.is_sign_positive(),
            "positive infinity lost"
        );
    }

    #[test]
    fn f32_to_bytes_be_neg_infinity() {
        let neg_inf = f32::NEG_INFINITY;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(neg_inf, &mut bytes);
        let restored = bytes_to_f32_be(&bytes);

        assert!(
            restored.is_infinite() && restored.is_sign_negative(),
            "negative infinity lost"
        );
    }

    #[test]
    fn f32_to_bytes_be_max_min() {
        // test maximum finite value
        let max_val = f32::MAX;
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(max_val, &mut bytes);
        let restored = bytes_to_f32_be(&bytes);
        assert_eq!(max_val, restored, "f32::MAX conversion failed");

        // test minimum finite value
        let min_val = f32::MIN;
        f32_to_bytes_be(min_val, &mut bytes);
        let restored = bytes_to_f32_be(&bytes);
        assert_eq!(min_val, restored, "f32::MIN conversion failed");
    }

    #[test]
    fn f32_to_bytes_be_subnormal_numbers() {
        // test smallest positive subnormal number
        let smallest = f32::from_bits(1); // smallest positive subnormal
        let mut bytes = [0u8; 4];
        f32_to_bytes_be(smallest, &mut bytes);
        let restored = bytes_to_f32_be(&bytes);
        assert_eq!(
            smallest.to_bits(),
            restored.to_bits(),
            "subnormal number conversion failed"
        );
    }

    #[test]
    fn f32_to_bytes_be_buffer_modification() {
        let value = 42.0_f32;
        let mut bytes = [0xFFu8; 4]; // fill with garbage
        f32_to_bytes_be(value, &mut bytes);

        // verify that all bytes were overwritten
        let restored = bytes_to_f32_be(&bytes);
        assert_eq!(value, restored, "buffer should be completely overwritten");
    }

    // property-based test using quickcheck (if you want to add quickcheck dependency)
    /*

    mod quickcheck_tests {
        use super::*;
        use quickcheck::quickcheck;

        quickcheck! {
            fn f32_roundtrip_property(x: f32) -> bool {
                let mut bytes = [0u8; 4];
                f32_to_bytes_be(x, &mut bytes);
                let y = bytes_to_f32_be(&bytes);

                if x.is_nan() {
                    y.is_nan()
                } else {
                    x == y
                }
            }
        }
    }
    */
    pub fn ema(state: &mut (f64, f64), alpha: f64, new_value: f64) -> f64 {
        let (prev_avg, count) = state;

        if *count == 0.0 {
            // first value - initialize
            *prev_avg = new_value;
            *count = 1.0;
        } else {
            // EMA formula: avg = alpha * new_value + (1 - alpha) * prev_avg
            *prev_avg = alpha * new_value + (1.0 - alpha) * *prev_avg;
            *count += 1.0;
        }

        *prev_avg
    }

    #[test]
    fn n2() {
        // инициализируем состояние: (предыдущее среднее, счётчик)
        let mut state = (0.0, 0.0);
        let alpha = 0.3; // коэффициент сглаживания (0.0 < alpha < 1.0)

        let values = [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0];

        let a: f64 = values.iter().sum();

        for &v in &values {
            let ema = ema(&mut state, alpha, v);
            println!("value: {:4}, ema: {:.2}", v, ema);
        }
        println!("value: {:4}, ema: {:.2}", a / values.len() as f64, 0);
    }
}

mod tests_ema {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::float_cmp)]

    use super::*;

    #[test]
    fn test_ema_initialization() {
        let mut ema = Ema::new(9); // alpha = 2 / (9 + 1) = 0.2
        let first_val = 10.0;
        let result = shadow_ema_next(&mut ema, first_val);

        assert!(ema.f_is_initialized());
        assert_eq!(result, first_val);
        assert_eq!(ema.get(), first_val);
    }

    #[test]
    fn test_ema_mathematics() {
        let mut ema = Ema::new(3);

        ema.next(10.0);

        let res2 = ema.next(20.0);
        assert_eq!(res2, 15.0);

        let res3 = ema.next(30.0);
        assert_eq!(res3, 22.5);
    }

    #[test]
    fn test_ema_get_without_update() {
        let mut ema = Ema::new(10);
        ema.next(100.0);
        let val_before = ema.get();
        let val_after = ema.get();

        assert_eq!(val_before, val_after);
        assert_eq!(val_after, 100.0);
    }

    #[test]
    fn test_ema_alpha_calculation() {
        let ema = Ema::new(1); // alpha = 2 / (1 + 1) = 1.0
        assert_eq!(ema.f_alpha(), 1.0);

        let ema_large = Ema::new(199); // alpha = 2 / 200 = 0.01
        assert!((ema_large.f_alpha() - 0.01).abs() < f64::EPSILON);
    }

    fn shadow_ema_next(ema: &mut Ema, val: f64) -> f64 {
        ema.next(val)
    }

    #[test]
    fn test_nan_protection() {
        let mut ema = Ema::new(10);
        ema.next(42.0);

        let last_valid = ema.get();
        // передаем NaN
        let result = ema.next(f64::NAN);

        assert_eq!(result, last_valid);
        assert!(!result.is_nan());
    }

    #[test]
    fn test_infinity_protection() {
        let mut ema = Ema::new(10);
        ema.next(100.0);

        let last_valid = ema.get();
        ema.next(f64::INFINITY);
        ema.next(f64::NEG_INFINITY);

        assert_eq!(ema.get(), last_valid);
    }

    #[test]
    fn test_uninitialized_with_garbage() {
        let mut ema = Ema::new(10);

        ema.next(f64::NAN);
        assert!(!ema.f_is_initialized());

        ema.next(10.0);
        assert!(ema.f_is_initialized());
        assert_eq!(ema.get(), 10.0);
    }

    #[test]
    fn test_large_values_stability() {
        let mut ema = Ema::new(2); // alpha = 0.666...
        ema.next(f64::MAX / 2.0);

        let result = ema.next(f64::MAX / 4.0);
        assert!(result.is_finite());
        assert!(result > 0.0);
    }

    #[test]
    fn test_zero_window() {
        let mut ema = Ema::new(0); // alpha = 2.0 / (0 + 1) = 2.0
        ema.next(10.0);
        let res = ema.next(20.0);

        assert!(res.is_finite());
    }
}

// ============================================================================
// harsh test suite – trying to break the code in every possible way
// ============================================================================

mod tests_safe_buffer {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn new_buffer_is_empty() {
        let buf = SafeBuffer::new(10);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.get(), &[]);
    }

    #[test]
    fn write_full_capacity() {
        let mut buf = SafeBuffer::new(5);
        buf.write(b"hello");
        assert_eq!(buf.get(), b"hello");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn write_less_than_capacity() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"hi");
        assert_eq!(buf.get(), b"hi");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn write_empty_slice() {
        let mut buf = SafeBuffer::new(5);
        assert_eq!(buf.capacity(), 5);
        buf.write(b"abc");
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_empty());
        buf.write(b"");
        assert_eq!(buf.get(), b"");
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        // next write after empty works
        buf.write(b"de");
        assert_eq!(buf.get(), b"de");
    }

    #[test]
    #[should_panic(expected = "input too large for buffer")]
    fn write_panics_when_input_exceeds_capacity() {
        let mut buf = SafeBuffer::new(3);
        assert_eq!(buf.capacity(), 3);
        buf.write(b"four");
    }

    #[test]
    fn modify_within_bounds() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"abcdefgh");
        buf.modify(2, b"12");
        assert_eq!(buf.get(), b"ab12efgh");
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn modify_at_start() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"hello");
        buf.modify(0, b"HE");
        assert_eq!(buf.get(), b"HEllo");
    }

    #[test]
    fn modify_at_end() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"hello");
        buf.modify(4, b"!");
        assert_eq!(buf.get(), b"hell!");
    }

    #[test]
    fn modify_with_empty_data_does_nothing() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"abc");
        buf.modify(1, b"");
        assert_eq!(buf.get(), b"abc");
        assert_eq!(buf.len(), 3);
    }

    #[test]
    #[should_panic(expected = "modify range out of bounds")]
    fn modify_panics_when_offset_beyond_len() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"abc");
        buf.modify(3, b"d"); // offset == len -> end = 4 > len=3
    }

    #[test]
    #[should_panic(expected = "modify range out of bounds")]
    fn modify_panics_when_end_exceeds_len() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"abc");
        buf.modify(2, b"de"); // offset=2, len=2 -> end=4 > 3
    }

    #[test]
    fn get_mut_allows_in_place_modification() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"abcdef");
        {
            let slice = buf.get_mut();
            slice[2..5].copy_from_slice(b"XYZ");
        }
        assert_eq!(buf.get(), b"abXYZf");
    }

    #[test]
    fn get_mut_respects_current_len() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"short");
        let slice = buf.get_mut();
        assert_eq!(slice.len(), 5);
        // trying to access beyond len is a compile-time or runtime panic (slice bounds)
    }

    #[test]
    fn clear_makes_buffer_empty() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"data");
        assert_eq!(buf.len(), 4);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.get(), b"");
        // writing after clear works
        buf.write(b"new");
        assert_eq!(buf.get(), b"new");
    }

    #[test]
    fn clear_does_not_affect_subsequent_write() {
        let mut buf = SafeBuffer::new(10);
        assert_eq!(buf.capacity(), 10);
        buf.write(b"one");
        buf.clear();
        buf.write(b"two");
        assert_eq!(buf.get(), b"two");
    }

    #[test]
    fn multiple_writes_never_leak_old_data_via_get() {
        let mut buf = SafeBuffer::new(30);
        assert_eq!(buf.capacity(), 30);
        buf.write(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); // 30 bytes
        assert_eq!(buf.get().len(), 30);
        buf.write(b"bbb");
        assert_eq!(buf.get(), b"bbb");
        buf.write(b"c");
        assert_eq!(buf.get(), b"c");
        buf.write(b"");
        assert_eq!(buf.get(), b"");
    }

    #[test]
    fn zero_capacity_buffer() {
        let mut buf = SafeBuffer::new(0);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.get(), b"");
        buf.write(b""); // ok
        assert_eq!(buf.len(), 0);
        // get_mut returns empty slice
        assert_eq!(buf.get_mut(), b"");
        // modify would panic because len is 0
        // write with any non-empty panics
    }

    #[test]
    #[should_panic(expected = "input too large for buffer")]
    fn zero_capacity_write_panics_on_non_empty() {
        let mut buf = SafeBuffer::new(0);
        assert_eq!(buf.capacity(), 0);
        buf.write(b"x");
    }

    #[test]
    fn one_byte_buffer_edge_cases() {
        let mut buf = SafeBuffer::new(1);

        assert_eq!(buf.capacity(), 1);
        buf.write(b"a");
        assert_eq!(buf.get(), b"a");
        buf.modify(0, b"b");
        assert_eq!(buf.get(), b"b");
        buf.write(b"");
        assert_eq!(buf.get(), b"");
        buf.write(b"c");
        assert_eq!(buf.get(), b"c");
        // modify with offset 0 and length 1 works
        buf.modify(0, b"d");
        assert_eq!(buf.get(), b"d");
        // modify beyond bounds panics
    }

    #[test]
    #[should_panic(expected = "modify range out of bounds")]
    fn one_byte_modify_out_of_bounds() {
        let mut buf = SafeBuffer::new(1);
        buf.write(b"a");
        buf.modify(1, b"b"); // offset == len -> end=2 > len=1
    }

    #[test]
    fn get_mut_after_clear_returns_empty() {
        let mut buf = SafeBuffer::new(5);
        assert_eq!(buf.capacity(), 5);
        buf.write(b"data");
        buf.clear();
        assert_eq!(buf.get_mut(), b"");
    }

    #[test]
    fn write_then_get_mut_then_write_works() {
        let mut buf = SafeBuffer::new(10);
        assert_eq!(buf.capacity(), 10);
        buf.write(b"first");
        {
            let _ = buf.get_mut(); // immutable borrow? actually mutable but dropped
        }
        buf.write(b"second"); // works because previous mutable borrow ended
        assert_eq!(buf.get(), b"second");
    }

    #[test]
    fn modify_does_not_change_len() {
        let mut buf = SafeBuffer::new(10);
        assert_eq!(buf.capacity(), 10);
        buf.write(b"123456");
        assert_eq!(buf.len(), 6);
        buf.modify(0, b"ab");
        assert_eq!(buf.len(), 6);
        buf.modify(4, b"xy");
        assert_eq!(buf.len(), 6);
    }

    #[test]
    fn get_and_get_mut_are_consistent() {
        let mut buf = SafeBuffer::new(10);
        buf.write(b"rust");
        assert_eq!(buf.get(), b"rust");
        buf.get_mut()[2] = b'p';
        assert_eq!(buf.get(), b"rupt");
    }
}

mod test_mod_onsert_bits {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    use super::*;

    #[test]
    fn test_invalid_len_zero() {
        let data = [0xFF, 0xFF];
        let result = extract_bits(&data, 0, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "len> 32 bits or len == 0");
    }

    #[test]
    fn test_invalid_len_too_large() {
        let data = [0xFF, 0xFF];
        let result = extract_bits(&data, 0, 33);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "len> 32 bits or len == 0");
    }

    #[test]
    fn test_out_of_bounds_end_pos() {
        let data = [0b11110000]; // 8 бит
        let result = extract_bits(&data, 0, 9);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "end_pos > output.len() * 8");
    }

    #[test]
    fn test_out_of_bounds_start_pos() {
        let data = [0b11110000];
        let result = extract_bits(&data, 8, 1); // pos == 8 (первый бит за пределами)
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "end_pos > output.len() * 8");
    }

    #[test]
    fn test_empty_data() {
        let data = [];
        let result = extract_bits(&data, 0, 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "end_pos > output.len() * 8");
    }

    #[test]
    fn test_overflow_pos_len() {
        let data = [0xFF; 100];
        let pos = usize::MAX - 10;
        let len = 32;
        extract_bits(&data, pos, len).err().unwrap();
    }

    #[test]
    fn test_extract_single_bit() {
        let data = [0b10000000];
        assert_eq!(extract_bits(&data, 0, 1), Ok(1));
        let data = [0b01000000];
        assert_eq!(extract_bits(&data, 1, 1), Ok(1));
        let data = [0b00000001];
        assert_eq!(extract_bits(&data, 7, 1), Ok(1));
        let data = [0b00000000];
        assert_eq!(extract_bits(&data, 0, 1), Ok(0));
    }

    #[test]
    fn test_extract_multiple_bits_same_byte() {
        let data = [0b10110010];
        assert_eq!(extract_bits(&data, 0, 4), Ok(0b1011));

        assert_eq!(extract_bits(&data, 2, 4), Ok(0b1100));
        assert_eq!(extract_bits(&data, 4, 4), Ok(0b0010));
    }

    #[test]
    fn test_extract_across_byte_boundary() {
        let data = [0b11001100, 0b00110011];
        assert_eq!(extract_bits(&data, 4, 7), Ok(0b1100001));
        assert_eq!(extract_bits(&data, 0, 16), Ok(0b1100110000110011));
    }

    #[test]
    fn test_extract_all_ones() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(extract_bits(&data, 0, 32), Ok(u32::MAX));
        assert_eq!(extract_bits(&data, 7, 25), Ok((1 << 25) - 1));
    }

    #[test]
    fn test_boundary_conditions() {
        let data = [0b00000001];

        assert_eq!(extract_bits(&data, 7, 1), Ok(1));

        assert!(extract_bits(&data, 7, 2).is_err());
    }

    #[test]
    fn test_big_endian_order() {
        let data = [0b10101010];

        assert_eq!(extract_bits(&data, 0, 4), Ok(0b1010));
        assert_eq!(extract_bits(&data, 4, 4), Ok(0b1010));

        let data2 = [0b11110000, 0b00001111];

        assert_eq!(extract_bits(&data2, 0, 8), Ok(240));

        assert_eq!(extract_bits(&data2, 8, 8), Ok(15));

        assert_eq!(extract_bits(&data2, 4, 8), Ok(0));
    }
}

mod test_mod_insert {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    use super::*;

    fn reference_insert_bits(output: &mut [u8], pos: usize, len: u8, input: u32) {
        let len = len as usize;
        let mask = if len == 32 { !0u32 } else { (1u32 << len) - 1 };
        let bits = input & mask;
        for i in pos..pos + len {
            let byte_idx = i >> 3;
            let bit_offset = 7 - (i & 7);
            let bit = (bits >> (len - 1 - (i - pos))) & 1;
            if bit == 1 {
                output[byte_idx] |= 1 << bit_offset;
            } else {
                output[byte_idx] &= !(1 << bit_offset);
            }
        }
    }

    fn extract_bits_from_output(data: &[u8], pos: usize, len: u8) -> u32 {
        let mut res = 0u32;
        for i in pos..pos + len as usize {
            let byte_idx = i >> 3;
            let bit_offset = 7 - (i & 7);
            let bit = (data[byte_idx] >> bit_offset) & 1;
            res = (res << 1) | bit as u32;
        }
        res
    }

    struct Lcg {
        state: u64,
    }
    impl Lcg {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }
        fn next(&mut self) -> u64 {
            self.state = self
                .state
                .wrapping_mul(48271)
                .wrapping_rem(2u64.pow(31) - 1);
            self.state
        }
        fn gen_range(&mut self, low: usize, high: usize) -> usize {
            low + (self.next() as usize) % (high - low)
        }
        fn gen_byte(&mut self) -> u8 {
            (self.next() % 256) as u8
        }
    }

    #[test]
    fn test_invalid_len_zero() {
        let mut data = [0u8; 4];
        let result = insert_bits(&mut data, 0, 0, 0x1234);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "len> 32 bits or len == 0");
    }

    #[test]
    fn test_invalid_len_too_large() {
        let mut data = [0u8; 4];
        let result = insert_bits(&mut data, 0, 33, 0x1234);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "len> 32 bits or len == 0");
    }

    #[test]
    fn test_overflow_pos_len() {
        let mut data = [0u8; 4];
        let pos = usize::MAX - 10;
        let len = 20;
        let result = insert_bits(&mut data, pos, len, 0x1234);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "overflow in pos + len");
    }

    #[test]
    fn test_out_of_bounds_end_pos() {
        let mut data = [0u8; 4];
        let result = insert_bits(&mut data, 0, 33, 0x1234);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "len> 32 bits or len == 0");

        let result = insert_bits(&mut data, 30, 5, 0x1234);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "end_pos > output.len() * 8");
    }

    #[test]
    fn test_out_of_bounds_start_pos() {
        let mut data = [0u8; 4];
        let result = insert_bits(&mut data, 32, 1, 0x1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "end_pos > output.len() * 8");
    }

    #[test]
    fn test_empty_output() {
        let mut data = [];
        let result = insert_bits(&mut data, 0, 1, 0x1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "end_pos > output.len() * 8");
    }

    #[test]
    fn test_insert_single_bit() {
        let mut data = [0u8; 1];

        insert_bits(&mut data, 0, 1, 0b1).unwrap();
        assert_eq!(data[0], 0b10000000);

        insert_bits(&mut data, 1, 1, 0b0).unwrap();
        assert_eq!(data[0], 0b10000000);

        let mut data2 = [0u8; 1];
        insert_bits(&mut data2, 7, 1, 0b1).unwrap();
        assert_eq!(data2[0], 0b00000001);
    }

    #[test]
    fn test_insert_multiple_bits_same_byte() {
        let mut data = [0u8; 1];

        insert_bits(&mut data, 0, 4, 0b1011).unwrap();
        assert_eq!(data[0], 0b10110000);

        data = [0u8; 1];
        insert_bits(&mut data, 2, 4, 0b1011).unwrap();

        assert_eq!(data[0], 0b00101100);
    }

    #[test]
    fn test_insert_across_byte_boundary() {
        let mut data = [0u8; 2];

        let input = 0b1100110011u32;
        insert_bits(&mut data, 4, 10, input).unwrap();
        let extracted = extract_bits_from_output(&data, 4, 10);
        assert_eq!(extracted, input & ((1 << 10) - 1));
    }

    #[test]
    fn test_insert_full_32_bits() {
        let mut data = [0u8; 4];
        let input = 0x12345678;
        insert_bits(&mut data, 0, 32, input).unwrap();
        let extracted = extract_bits_from_output(&data, 0, 32);
        assert_eq!(extracted, input);
    }

    #[test]
    fn test_insert_does_not_affect_other_bits() {
        let mut data = [0b11111111u8; 2];

        insert_bits(&mut data, 0, 4, 0b0000).unwrap();
        assert_eq!(data[0], 0b00001111);
        assert_eq!(data[1], 0b11111111);

        let mut data = [0b00000000u8; 2];
        insert_bits(&mut data, 12, 4, 0b1111).unwrap();

        assert_eq!(data[1], 0b00001111);
    }

    #[test]
    fn test_insert_extract_roundtrip() {
        let data = [0u8; 8];
        for pos in [0, 3, 7, 8, 13, 31] {
            for len in [1, 4, 8, 16, 24, 32] {
                if pos + len as usize > 64 {
                    continue;
                }
                for input in [0, 1, 0xAAAAAAAA, 0x55555555, 0xFFFFFFFF, 0x12345678] {
                    let input_masked = input & (!0u32 >> (32 - len));
                    let mut local_data = data;
                    insert_bits(&mut local_data, pos, len, input).unwrap();
                    let extracted = extract_bits_from_output(&local_data, pos, len);
                    assert_eq!(
                        extracted, input_masked,
                        "pos={}, len={}, input={:#x}",
                        pos, len, input
                    );
                }
            }
        }
    }

    #[test]
    fn test_random_against_reference() {
        let mut rng = Lcg::new(123456789);
        for _ in 0..1000 {
            let data_len = rng.gen_range(1, 20);
            let mut data = vec![0u8; data_len];

            for byte in &mut data {
                *byte = rng.gen_byte();
            }
            let max_bits = data_len * 8;
            let pos = rng.gen_range(0, max_bits);
            let max_len = (max_bits - pos).min(32);
            if max_len == 0 {
                continue;
            }
            let len = rng.gen_range(1, max_len + 1) as u8;
            let input = rng.next() as u32;

            let mut test_data = data.clone();
            let result = insert_bits(&mut test_data, pos, len, input);
            assert!(result.is_ok());
            let mut ref_data = data;
            reference_insert_bits(&mut ref_data, pos, len, input);
            assert_eq!(
                test_data, ref_data,
                "pos={}, len={}, input={:#x}",
                pos, len, input
            );
        }
    }

    #[test]
    fn test_stress_large_buffer() {
        let mut rng = Lcg::new(987654321);
        for _ in 0..500 {
            let data_len = rng.gen_range(100, 1000);
            let mut data = vec![0u8; data_len];
            let max_bits = data_len * 8;
            let pos = rng.gen_range(0, max_bits);
            let max_len = (max_bits - pos).min(32);
            if max_len == 0 {
                continue;
            }
            let len = rng.gen_range(1, max_len + 1) as u8;
            let input = rng.next() as u32;
            let mut reference = data.clone();
            reference_insert_bits(&mut reference, pos, len, input);
            let result = insert_bits(&mut data, pos, len, input);
            assert!(result.is_ok());
            assert_eq!(data, reference);
        }
    }

    #[test]
    fn test_boundary_positions() {
        let mut data = [0u8; 4];
        for pos in [0, 8, 16, 24] {
            let input = 0b10101010;
            insert_bits(&mut data, pos, 8, input).unwrap();
            let extracted = extract_bits_from_output(&data, pos, 8);
            assert_eq!(extracted, input);
            data = [0u8; 4];
        }
    }

    #[test]
    fn test_mask_input() {
        let mut data = [0u8; 4];
        let input = 0xFFFFFFFF;

        insert_bits(&mut data, 0, 1, input).unwrap();
        let extracted = extract_bits_from_output(&data, 0, 1);
        assert_eq!(extracted, 1);

        let mut data = [0u8; 4];
        insert_bits(&mut data, 0, 32, input).unwrap();
        let extracted = extract_bits_from_output(&data, 0, 32);
        assert_eq!(extracted, input);

        let mut data = [0u8; 4];
        insert_bits(&mut data, 0, 16, input).unwrap();
        let extracted = extract_bits_from_output(&data, 0, 16);
        assert_eq!(extracted, input & 0xFFFF);
    }
}

mod tests_check_probability {
    use super::*;

    #[test]
    fn test_check_probability_zero() {
        assert!(!check_probability(0, 0));
        assert!(!check_probability(0, 1));
        assert!(!check_probability(0, u32::MAX));
    }

    #[test]
    fn test_check_probability_max() {
        assert!(check_probability(u32::MAX, 0));
        assert!(check_probability(u32::MAX, 2_147_483_648));
        assert!(check_probability(u32::MAX, u32::MAX));
    }

    #[test]
    fn test_check_probability_half() {
        let half = 2_147_483_648;
        assert!(check_probability(half, 0));
        assert!(check_probability(half, 2_147_483_647));
        assert!(!check_probability(half, 2_147_483_648));
        assert!(!check_probability(half, u32::MAX));
    }

    #[test]
    fn test_check_probability_distribution() {
        #![allow(clippy::as_conversions)]
        #![allow(clippy::integer_division)]
        let scaled_prob = 3_006_477_107;
        let mut true_count = 0;
        let total_iterations = 10_000;

        for i in 0..total_iterations {
            #[allow(clippy::arithmetic_side_effects)]
            let fake_random = (i as u64 * (u32::MAX as u64 / total_iterations as u64)) as u32;

            if check_probability(scaled_prob, fake_random) {
                #[allow(clippy::arithmetic_side_effects)]
                {
                    true_count += 1;
                }
            }
        }

        let percentage = (true_count * 100) / total_iterations;
        //assert!()
        assert!((69..=71).contains(&percentage));
    }
}

mod tests_fuck_coeff_of_rand_pack_trim {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // Helper to check that the result is always within [1, max_len] when Ok.
    fn assert_valid_result(result: Result<usize, String>, max_len: usize) {
        if max_len == 0 {
            assert_eq!(result, Err("max_len must be greater than 0".to_string()));
        } else {
            let val = result.unwrap();
            assert!(
                val >= 1 && val <= max_len,
                "value {} out of range [1, {}]",
                val,
                max_len
            );
        }
    }

    #[test]
    fn test_edge_cases() {
        // max_len == 0 always errors
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&0, &10, &50, &100, false),
            Err("max_len must be greater than 0".to_string())
        );
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&0, &0, &0, &0, true),
            Err("max_len must be greater than 0".to_string())
        );

        // rand_range == 0 -> no adjustment
        for no_trim in [false, true] {
            let result = fuck_coeff_of_rand_pack_trim(&200, &100, &123, &0, no_trim).unwrap();
            // Since half_range=0 and random_offset=0, result should be payload_len clamped.
            assert_eq!(result, 100); // 100 <= 200
            let result = fuck_coeff_of_rand_pack_trim(&200, &250, &123, &0, no_trim).unwrap();
            assert_eq!(result, 200); // clamped to max
        }

        // payload_len == 0 (should become at least 1)
        for no_trim in [false, true] {
            let result = fuck_coeff_of_rand_pack_trim(&200, &0, &50, &100, no_trim).unwrap();
            assert!((1..=200).contains(&result));
        }

        // rand_num == 0 -> random_offset = 0, so only subtraction may occur (if no_trim=false)
        let result = fuck_coeff_of_rand_pack_trim(&200, &100, &0, &100, false).unwrap();
        // half_range=50, random_offset=0, base=100-50=50, result=50
        assert_eq!(result, 50);
        let result = fuck_coeff_of_rand_pack_trim(&200, &10, &0, &100, false).unwrap();
        // half_range=50, payload_len<50 => deficit=40, random_offset=0 <= deficit => adjusted=0 => clamp to 1
        assert_eq!(result, 1);
        let result = fuck_coeff_of_rand_pack_trim(&200, &100, &0, &100, true).unwrap();
        // no_trim=true => payload_len + 0 = 100
        assert_eq!(result, 100);

        // rand_range > max_len -> capped to max_len
        let result = fuck_coeff_of_rand_pack_trim(&10, &5, &999, &1000, false).unwrap();
        // range = 10, half_range=5, random_offset = 999%10 = 9, base = 5-5 =0 => adjusted=0+9=9 => result=9 (<=10)
        assert!((1..=10).contains(&result));
    }

    #[test]
    fn test_invariants_with_loops() {
        // Fixed parameters for exhaustive check
        let max_len_values = [1, 5, 10, 100, 1000];
        let payload_values = [0, 1, 5, 50, 100, 500, 999, 1000];
        let rand_num_values = [0, 1, 5, 10, 50, 100, 200, 500, 999, 1000];
        let rand_range_values = [0, 1, 5, 10, 50, 100, 200, 500, 1000, 2000];
        let no_trim_values = [false, true];

        for &max_len in &max_len_values {
            for &payload_len in &payload_values {
                for &rand_num in &rand_num_values {
                    for &rand_range in &rand_range_values {
                        for &no_trim in &no_trim_values {
                            let result = fuck_coeff_of_rand_pack_trim(
                                &max_len,
                                &payload_len,
                                &rand_num,
                                &rand_range,
                                no_trim,
                            );
                            assert_valid_result(result, max_len);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_no_trim_never_decreases() {
        // For no_trim=true, result must be >= payload_len (unless payload_len > max_len, then clamped)
        for max_len in [10, 50, 100] {
            for payload_len in 0..=max_len {
                for rand_num in 0..=20 {
                    for rand_range in 0..=10 {
                        let result = fuck_coeff_of_rand_pack_trim(
                            &max_len,
                            &payload_len,
                            &rand_num,
                            &rand_range,
                            true,
                        )
                        .unwrap();
                        // Since no_trim=true, result can only increase (or stay same) up to max_len.
                        // But if payload_len > max_len? We never pass that, but if we do, it clamps.
                        // Here we have payload_len <= max_len, so result >= payload_len.
                        assert!(
                            result >= payload_len,
                            "result {} < payload_len {}",
                            result,
                            payload_len
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_trim_allows_decrease() {
        // For no_trim=false, result can be less than payload_len, but never below 1.
        for max_len in [10, 50, 100] {
            for payload_len in 1..=max_len {
                for rand_num in 0..=20 {
                    for rand_range in 1..=10 {
                        let result = fuck_coeff_of_rand_pack_trim(
                            &max_len,
                            &payload_len,
                            &rand_num,
                            &rand_range,
                            false,
                        )
                        .unwrap();
                        // No specific lower bound except 1, but we can check that it's within range.
                        assert!(result >= 1 && result <= max_len);
                    }
                }
            }
        }
    }

    #[test]
    fn test_max_len_clamping() {
        // When payload_len is huge, result should be clamped to max_len.
        let huge = usize::MAX;
        for no_trim in [false, true] {
            let result = fuck_coeff_of_rand_pack_trim(&100, &huge, &123, &50, no_trim).unwrap();
            assert_eq!(result, 100); // clamped
        }
        // When payload_len + random_offset overflows, saturating_add prevents overflow.
        let result = fuck_coeff_of_rand_pack_trim(&100, &huge, &huge, &10, true).unwrap();
        assert_eq!(result, 100); // saturated to max
    }

    #[test]
    fn test_original_examples() {
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&200, &100, &50, &100, false),
            Ok(100)
        );
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&200, &10, &50, &100, false),
            Ok(10)
        );
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&200, &10, &60, &100, false),
            Ok(20)
        );
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&200, &10, &50, &100, true),
            Ok(60)
        );
        assert_eq!(
            fuck_coeff_of_rand_pack_trim(&0, &10, &50, &100, false),
            Err("max_len must be greater than 0".to_string())
        );
    }
}

mod tests_trimm {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]

    use super::*;

    #[test]
    fn test_pad_round_trip_matrix() {
        struct TestCase {
            name: &'static str,
            initial_data: Vec<u8>,
            pad_pos: usize,
            expected_maker_success: bool,
            expected_trim_len: usize,
        }

        let cases = [
            TestCase {
                name: "Normal padding with zeros (inversion to 0xFF)",
                initial_data: vec![0x01, 0x02, 0x00, 0xAA, 0xBB, 0xCC],
                pad_pos: 3,
                expected_maker_success: true,
                expected_trim_len: 3,
            },
            TestCase {
                name: "Padding with 0xFF byte (inversion to 0x00)",
                initial_data: vec![0x55, 0x66, 0xFF, 0x11, 0x22],
                pad_pos: 3,
                expected_maker_success: true,
                expected_trim_len: 3,
            },
            TestCase {
                name: "Minimum working array (length 2, pad_pos 1)",
                initial_data: vec![0xAA, 0x00],
                pad_pos: 1,
                expected_maker_success: true,
                expected_trim_len: 1,
            },
            TestCase {
                name: "Padding on the very last byte",
                initial_data: vec![0x01, 0x02, 0x03, 0x04],
                pad_pos: 3,
                expected_maker_success: true,
                expected_trim_len: 3,
            },
            // --- EXTREME BYTE VALUES ---
            TestCase {
                name: "Alternating bits 0xAA (10101010) -> inversion to 0x55 (01010101)",
                initial_data: vec![0xAA, 0x00, 0x00],
                pad_pos: 1,
                expected_maker_success: true,
                expected_trim_len: 1,
            },
            // --- ERRORS AND FAILURES (Invalid pad_pos) ---
            TestCase {
                name: "Error: pad_pos is 0 (no useful byte behind)",
                initial_data: vec![0x01, 0x02, 0x03],
                pad_pos: 0,
                expected_maker_success: false,
                expected_trim_len: 3, // Trim will return full length because the structure marker was not created
            },
            TestCase {
                name: "Error: pad_pos out of array bounds",
                initial_data: vec![0x01, 0x02],
                pad_pos: 5,
                expected_maker_success: false,
                expected_trim_len: 2,
            },
            TestCase {
                name: "Error: pad_pos equals exactly array length (no room for padding)",
                initial_data: vec![0x01, 0x02, 0x03],
                pad_pos: 3,
                expected_maker_success: false,
                expected_trim_len: 3,
            },
            // --- MONOTONIC AND UNIFORM ARRAYS ---
            TestCase {
                name: "Array entirely of 0x00",
                initial_data: vec![0x00, 0x00, 0x00, 0x00],
                pad_pos: 2,
                expected_maker_success: true,
                expected_trim_len: 2,
            },
            TestCase {
                name: "Array entirely of 0xFF",
                initial_data: vec![0xFF, 0xFF, 0xFF, 0xFF],
                pad_pos: 2,
                expected_maker_success: true,
                expected_trim_len: 2,
            },
        ];

        // One loop performs verification of the entire data matrix
        for case in cases {
            let mut buffer = case.initial_data.clone();

            // 1. Test pad_maker
            let maker_res = pad_maker(&mut buffer, case.pad_pos);
            assert_eq!(
                maker_res, case.expected_maker_success,
                "FAIL [pad_maker]: {}",
                case.name
            );

            if case.expected_maker_success {
                let last_data_byte = case.initial_data[case.pad_pos - 1];
                let expected_pad_byte = !last_data_byte;

                for &byte in &buffer[case.pad_pos..] {
                    assert_eq!(
                        byte, expected_pad_byte,
                        "FAIL [padding content]: {} (byte is {:#X?}, expected {:#X?})",
                        case.name, byte, expected_pad_byte
                    );
                }
            }

            let trimmed_len = pad_trim(&buffer);
            assert_eq!(
                trimmed_len, case.expected_trim_len,
                "FAIL [pad_trim]: {}",
                case.name
            );
        }
    }

    #[test]
    fn test_pad_trim_on_corrupted_data() {
        struct CorruptedCase {
            name: &'static str,
            data: Vec<u8>,
            expected_len: usize,
        }

        let cases = [
            CorruptedCase {
                name: "Empty array",
                data: vec![],
                expected_len: 0,
            },
            CorruptedCase {
                name: "Array of 1 byte (incomplete structure)",
                data: vec![0x01],
                expected_len: 1,
            },
            CorruptedCase {
                name: "Corrupted padding tail (last byte modified)",
                data: vec![0x01, 0x02, 0x00, 0xFF, 0xFF, 0xEE], // Expected pure 0xFF at the end
                expected_len: 6, // Should return full_len because structure is broken
            },
            CorruptedCase {
                name: "Padding exists but no inverted boundary byte",
                data: vec![0x55, 0x55, 0x55, 0xFF, 0xFF, 0xFF], // Expected boundary 0x00 before 0xFF
                expected_len: 6,
            },
        ];

        for case in cases {
            assert_eq!(
                pad_trim(&case.data),
                case.expected_len,
                "FAIL [corrupted]: {}",
                case.name
            );
        }
    }
}

mod tests_vec_padd {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    use super::*;

    #[test]
    fn test_vec_padding_matrix() {
        struct TestCase {
            name: &'static str,
            initial_data: Vec<u8>,
            pad_count: usize,
            expected_maker_success: bool,
            expected_final_len: usize,
        }

        let cases = [
            // --- Standard Scenarios ---
            TestCase {
                name: "Standard zero byte inversion (0x00 -> 0xFF padding)",
                initial_data: vec![0x01, 0x02, 0x00],
                pad_count: 3,
                expected_maker_success: true,
                expected_final_len: 3,
            },
            TestCase {
                name: "Standard max byte inversion (0xFF -> 0x00 padding)",
                initial_data: vec![0x55, 0x66, 0xFF],
                pad_count: 2,
                expected_maker_success: true,
                expected_final_len: 3,
            },
            // --- Constraint Limits (0 pad_count) ---
            TestCase {
                name: "Error constraint: pad_count is 0",
                initial_data: vec![0x01, 0x02, 0x03],
                pad_count: 0,
                expected_maker_success: false,
                expected_final_len: 3, // Remains unmodified
            },
            // --- Edge Cases for Empty State ---
            TestCase {
                name: "Error constraint: empty vector with valid pad_count",
                initial_data: vec![],
                pad_count: 5,
                expected_maker_success: false,
                expected_final_len: 0,
            },
            // --- Alternating Bit Extremes ---
            TestCase {
                name: "Bit pattern 0xAA (10101010) -> inverts to 0x55 (01010101)",
                initial_data: vec![0xAA],
                pad_count: 4,
                expected_maker_success: true,
                expected_final_len: 1,
            },
            // --- Monolithic/Uniform Arrays ---
            TestCase {
                name: "Vector completely consisting of 0x00",
                initial_data: vec![0x00, 0x00, 0x00],
                pad_count: 3,
                expected_maker_success: true,
                expected_final_len: 3,
            },
            TestCase {
                name: "Vector completely consisting of 0xFF",
                initial_data: vec![0xFF, 0xFF, 0xFF],
                pad_count: 1,
                expected_maker_success: true,
                expected_final_len: 3,
            },
        ];

        for case in cases {
            let mut buffer = case.initial_data.clone();

            // 1. Verify pad_maker_vec execution status
            let maker_res = pad_maker_vec(&mut buffer, case.pad_count);
            assert_eq!(
                maker_res, case.expected_maker_success,
                "FAIL [pad_maker_vec]: {}",
                case.name
            );

            // If maker was successful, explicitly check the pushed content
            if case.expected_maker_success {
                let original_len = case.initial_data.len();
                let expected_total_len = original_len + case.pad_count;

                assert_eq!(
                    buffer.len(),
                    expected_total_len,
                    "FAIL [total length match]: {}",
                    case.name
                );

                let last_payload_byte = case.initial_data[original_len - 1];
                let expected_pad_byte = !last_payload_byte;

                for &pushed_byte in &buffer[original_len..] {
                    assert_eq!(
                        pushed_byte, expected_pad_byte,
                        "FAIL [padding byte corruption]: {} (got {:#X?}, expected {:#X?})",
                        case.name, pushed_byte, expected_pad_byte
                    );
                }
            }

            // 2. Verify pad_trim_vec recovery capability (Round-trip check)
            pad_trim_vec(&mut buffer);
            assert_eq!(
                buffer.len(),
                case.expected_final_len,
                "FAIL [pad_trim_vec recovery]: {}",
                case.name
            );
        }
    }

    #[test]
    fn test_vec_trim_corrupted_data() {
        struct CorruptedCase {
            name: &'static str,
            data: Vec<u8>,
            expected_len: usize,
        }

        let cases = [
            CorruptedCase {
                name: "Completely empty vector handling",
                data: vec![],
                expected_len: 0,
            },
            CorruptedCase {
                name: "Single byte vector handling",
                data: vec![0x01],
                expected_len: 1,
            },
            CorruptedCase {
                name: "Corrupted padding tail (last byte mutated)",
                data: vec![0x01, 0x02, 0x00, 0xFF, 0xFF, 0xEE], // Expected pure 0xFF
                expected_len: 6, // Aborts truncation, keeps full size
            },
            CorruptedCase {
                name: "Valid tail padding but missing the inversion boundary marker",
                data: vec![0x55, 0x55, 0x55, 0xFF, 0xFF, 0xFF], // Missing 0x00 boundary
                expected_len: 6,                                // Aborts truncation
            },
        ];

        for mut case in cases {
            pad_trim_vec(&mut case.data);
            assert_eq!(
                case.data.len(),
                case.expected_len,
                "FAIL [corrupted validation]: {}",
                case.name
            );
        }
    }
}
