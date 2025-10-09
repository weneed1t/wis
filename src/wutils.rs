pub enum WNotification {
    CriticalErrorKillConnect(&'static str),
    WarningNonCirtical(&'static str),
}

impl PartialEq for WNotification {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                WNotification::CriticalErrorKillConnect(_),
                WNotification::CriticalErrorKillConnect(_),
            ) => true,
            (WNotification::WarningNonCirtical(_), WNotification::WarningNonCirtical(_)) => true,
            _ => false,
        }
    }
}

pub fn bytes_to_u64(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.len() > 8 || bytes.len() == 0 {
        return Err("bytes.len() must be between 1 and 8");
    }

    let mut buffer = [0u8; 8];
    buffer[8 - bytes.len()..].copy_from_slice(bytes);

    Ok(u64::from_be_bytes(buffer))
}

pub fn u64_to_1_8bytes(num: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
    if bytes.len() > 8 || bytes.len() == 0 {
        return Err("bytes.len() > 8 ||bytes.len() ==0");
    }

    let buffer = num.to_be_bytes();
    bytes.copy_from_slice(&buffer[&buffer.len() - bytes.len()..]);
    return Ok(());
}

pub fn add_u64_i64(a: u64, b: i64) -> Result<u64, &'static str> {
    if b >= 0 {
        a.checked_add(b as u64)
            .ok_or("overflow occurred adding positive")
    } else {
        a.checked_sub(b.wrapping_abs() as u64)
            .ok_or("anderflow occurred  subtracting absolute")
    }
}

pub fn extract_bits(data: &[u8], pos: usize, len: u8) -> Result<u32, &'static str> {
    if len == 0 || len > 32 {
        return Err("len> 32 bits or len == 0");
    }
    let end_pos: usize = pos + len as usize;

    if end_pos > data.len() * 8 {
        return Err("end_pos > output.len() * 8");
    }

    // init the result variable
    let mut result: u32 = 0;

    for i in pos..end_pos {
        let byte_index: usize = i / 8; // Byte index
        let bit_offset: usize = 7 - (i % 8); // Bit offset (big-endian)
                                             // extract the bit from the byte
        let bit: u8 = (data[byte_index] >> bit_offset) & 1;
        // add the bit to the result
        result = (result << 1) | (bit as u32);
    }

    Ok(result)
}

pub fn insert_bits(output: &mut [u8], pos: usize, len: u8, input: u32) -> Result<(), &'static str> {
    if len == 0 || len > 32 {
        return Err("len> 32 bits or len == 0");
    }
    let end_pos: usize = pos + len as usize;

    if end_pos > output.len() * 8 {
        return Err("end_pos > output.len() * 8");
    }
    // extract the lowest len bits from the input
    let mask: u32 = 0xFFFFFFFF >> (32 - len);
    let bits_to_insert: u32 = input & mask;

    for i in pos..end_pos {
        let byte_indx: usize = i / 8; // Byte index
        let bit_offst: usize = 7 - (i % 8); // Bit offset (big-endian)
                                            // extract the current bit from the input bits
        let bit: u32 = (bits_to_insert >> (end_pos - i - 1)) & 1;
        if bit == 1 {
            output[byte_indx] |= 1 << bit_offst; // set the bit
        } else {
            output[byte_indx] &= !(1 << bit_offst); // clear the bit
        }
    }

    Ok(())
}

pub fn len_byte_maximal_capacyty_cheak(len: usize) -> (u64, usize) {
    if len > 7 {
        return (!0_u64, 64);
    }
    let t = len << 3;
    (!((!0_u64) << t), t)
}

/// Splits a mutable slice into sub-slices based on lengths
///
/// # Arguments
/// * `data` - mutable slice to split
/// * `lengths` - array of lengths for each sub-slice
/// * `absolute` - if true, ignores length mismatches and returns what fits
///
/// # Returns
/// * `Ok(Vec<&mut [T]>)` - vector of mutable sub-slices
/// * `Err(&'static str)` - error message if lengths don't match and absolute is false
///
/// # Examples
/// ```
/// let mut data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let lengths = [4, 1, 2, 2];
/// let result = wisleess2::wutils::split_by_lengths(&mut data, &lengths, false);
/// // Returns Ok([[1,2,3,4], [5], [6,7], [8,9]])
/// ```
pub fn split_by_lengths<'a, T>(
    data: &'a mut [T],
    lengths: &[usize],
    absolute: bool,
) -> Result<Vec<&'a mut [T]>, &'static str> {
    let total: usize = data.len();
    let mut remaining_data: &'a mut [T] = data;
    let mut result: Vec<&mut [T]> = Vec::with_capacity(lengths.len() + 1);

    if absolute {
        for &len in lengths {
            if remaining_data.is_empty() {
                break;
            }
            let take: usize = len.min(remaining_data.len());
            let (slice, rest) = remaining_data.split_at_mut(take);
            result.push(slice);
            remaining_data = rest;
        }
        if !remaining_data.is_empty() {
            result.push(remaining_data);
        }
        Ok(result)
    } else {
        let mut sum: usize = 0;
        for &len in lengths {
            sum = sum.checked_add(len).ok_or("length overflow")?;
        }
        if sum != total {
            return Err("total lengths != data length");
        }

        for &len in lengths {
            let (slice, rest) = remaining_data.split_at_mut(len);
            result.push(slice);
            remaining_data = rest;
        }
        Ok(result)
    }
}

/// Splits a mutable slice into sub-slices based on lengths
///
/// # Arguments
/// * `data` - mutable slice to split
/// * `lengths` - array of lengths for each sub-slice
/// * `absolute` - if true, ignores length mismatches and returns what fits
///
/// # Returns
/// * `Ok(Vec<&mut [T]>)` - vector of mutable sub-slices
/// * `Err(&'static str)` - error message if lengths don't match and absolute is false
///
/// # Examples
/// ```
/// let mut data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let lengths = [4, 1, 2, 2];
/// let result = wisleess2::wutils::split_by_lengths(&mut data, &lengths, false).unwrap();
/// assert_eq!(result.len(), 4);
/// ```
pub fn split_by_positions<'a, T>(
    data: &'a mut [T],
    positions: &[usize],
    absolute: bool,
) -> Result<Vec<&'a mut [T]>, &'static str> {
    let total = data.len();
    let mut remaining_data: &'a mut [T] = data;
    let mut result: Vec<&mut [T]> = Vec::with_capacity(positions.len() + 1);
    let mut last_pos: usize = 0;

    for &pos in positions {
        if pos <= last_pos {
            return Err("positions not strictly increasing");
        }
        if pos > total {
            if absolute {
                break;
            } else {
                return Err("position exceeds data length");
            }
        }
        let len = pos - last_pos;
        let (slice, rest) = remaining_data.split_at_mut(len);
        result.push(slice);
        remaining_data = rest;
        last_pos = pos;
    }
    if !remaining_data.is_empty() {
        result.push(remaining_data);
    }
    Ok(result)
}

fn u32_compress_tou16(num: u32) -> u16 {
    let mut t1s = 0;

    for x in 0..32 {
        if 1 == (num >> (32 - x)) & 1 {
            t1s = x;
            break;
        }
    }

    if t1s > 21 {
        return num as u16;
    }
    let mask = 0xFF_FF_FF_FFu32;

    let shif = ((mask >> (t1s + 10)) & num) as f32;

    //let t1 =

    t1s as u16
}

pub fn u32_to_u16_lossy(x: u32) -> u16 {
    (x / 0xFF_FF) as u16
}

pub fn u16_to_u32_approx(x: u16) -> u32 {
    x as u32 * 0xFF_FF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_num() {
        assert_eq!(u32_to_u16_lossy(4253465437), 64903);
        assert!(u16_to_u32_approx(u32_to_u16_lossy(4253465437)).abs_diff(4253465437) < 48000);
    }

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

#[cfg(test)]
mod length_tests {
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
        assert_eq!(result, Err("length overflow"));
    }

    #[test]
    fn test_length_mismatch_error() {
        let mut data = [1, 2, 3];
        let lengths = [1, 1]; // Sum < data.len()
        let result = split_by_lengths(&mut data, &lengths, false);
        assert_eq!(result, Err("total lengths != data length"));
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

#[cfg(test)]
mod position_tests {
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
        assert_eq!(result, Err("positions not strictly increasing"));
    }

    #[test]
    fn test_out_of_bounds_error() {
        let mut data = [1, 2, 3];
        let positions = [1, 5]; // 5 is out of bounds
        let result = split_by_positions(&mut data, &positions, false);
        assert_eq!(result, Err("position exceeds data length"));
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

    use std::time;
    #[test]
    fn test_a_time() {
        let ts = time::Instant::now();

        let mut x: f64 = 0.0;

        for _ in 0..100_000_000 {
            x += ts.elapsed().as_secs_f64();
        }

        println!(
            "{}                   {}",
            100_000_000.0 / ts.elapsed().as_micros() as f64,
            x
        );
        assert!(false);
    }
}
