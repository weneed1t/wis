use crate::EXPCP;

/*
pub enum WNotification {
    CriticalErrorKillConnect(&'static str),
    WarningNonCirtical(&'static str),
}

impl PartialEq for WNotification {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (
                Self::CriticalErrorKillConnect(_),
                Self::CriticalErrorKillConnect(_)
            ) | (Self::WarningNonCirtical(_), Self::WarningNonCirtical(_))
        )
    }
}
*/

/// a fixed-size buffer that stores only the last written data.
/// when writing a new block, old data becomes inaccessible, even if the new block is shorter.
pub struct SafeBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> SafeBuffer<N> {
    /// creates a new empty buffer.
    pub fn new() -> Self {
        Self {
            data: [0; N],
            len: 0,
        }
    }

    /// writes new data, completely replacing the content.
    /// panics if `input` is longer than n.
    pub fn write(&mut self, input: &[u8]) {
        assert!(input.len() <= N, "input too large for buffer");
        self.data[..input.len()].copy_from_slice(input);
        self.len = input.len();
    }

    /// returns a slice with the actual data (exactly `len` bytes).
    pub fn get(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// modifies a part of the already written data.
    /// panics if the range `offset..offset+new_data.len()` exceeds `self.len`.
    pub fn modify(&mut self, offset: usize, new_data: &[u8]) {
        let end = offset + new_data.len();
        assert!(end <= self.len, "modify range out of bounds");
        self.data[offset..end].copy_from_slice(new_data);
    }

    /// returns a mutable slice for modifying data (only within the written length).
    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// returns the current length of written data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// logically clears the buffer (physical bytes remain but are inaccessible).
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

pub fn bytes_to_u64(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.len() > 8 || bytes.is_empty() {
        return Err("bytes.len() must be between 1 and 8");
    }

    let mut buffer = [0u8; 8];
    buffer[8 - bytes.len()..].copy_from_slice(bytes);

    Ok(u64::from_be_bytes(buffer))
}

pub fn u64_to_1_8bytes(num: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
    if bytes.len() > 8 || bytes.is_empty() {
        return Err("bytes.len() > 8 ||bytes.len() ==0");
    }

    let buffer: [u8; 8] = num.to_be_bytes();
    bytes.copy_from_slice(&buffer[buffer.len() - bytes.len()..]);
    Ok(())
}

pub fn add_u64_i64(
    a: u64,
    b: i64,
    zero_if_in_sub_a_less_than_b: bool,
) -> Result<u64, &'static str> {
    if b >= 0 {
        a.checked_add(b as u64)
            .ok_or("overflow occurred adding positive")
    } else {
        a.checked_sub(b.wrapping_abs() as u64).map_or(
            if zero_if_in_sub_a_less_than_b {
                Ok(0)
            } else {
                Err("underflow occurred subtracting absolute")
            },
            Ok,
        )
        //.ok_or("anderflow occurred  subtracting absolute")
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

pub fn len_byte_maximal_capacity_check(len: usize) -> (u64, usize) {
    if len > 7 {
        return (!0_u64, 64);
    }
    let t = len << 3;
    (!((!0_u64) << t), t)
}

/// # Examples
/// ```
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x00), 1);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF), 1);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF), 2);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x01_00), 2);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF_FF), 3);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x01_00_00), 3);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF_FF_FF), 4);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x01_00_00_00), 4);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF_FF_FF_FF), 5);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x01_00_00_00_00), 5);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF_FF_FF_FF_FF), 6);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x01_00_00_00_00_00), 6);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF_FF_FF_FF_FF_FF), 7);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x01_00_00_00_00_00_00), 7);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0xFF_FF_FF_FF_FF_FF_FF_FF), 8);
/// assert_eq!(wisleess2::wutils::len_u64_as_bytes(0x10_FF_FF_FF_FF_FF_FF_FF), 8);
/// ```
pub fn len_u64_as_bytes(num: u64) -> usize {
    if 0b1u64 << (1 << 3) > num {
        return 1;
    }
    if 0b1u64 << (2 << 3) > num {
        return 2;
    }
    if 0b1u64 << (3 << 3) > num {
        return 3;
    }
    if 0b1u64 << (4 << 3) > num {
        return 4;
    }
    if 0b1u64 << (5 << 3) > num {
        return 5;
    }
    if 0b1u64 << (6 << 3) > num {
        return 6;
    }
    if 0b1u64 << (7 << 3) > num {
        return 7;
    }
    8
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
///
/// let mut data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let lengths = [4, 1, 2, 2];
/// let result = wisleess2::wutils::split_by_lengths(&mut data, &lengths, false).unwrap();
/// assert_eq!(result[0],[1,2,3,4]);
/// assert_eq!(result[1],[5]);
/// assert_eq!(result[2],[6,7]);
/// assert_eq!(result[3],[8,9]);
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

pub fn u32_to_u16_lossy(x: u32) -> u16 {
    (x / 0xFF_FF) as u16
}

pub fn u16_to_u32_approx(x: u16) -> u32 {
    x as u32 * 0xFF_FF
}

/// convert f32 to 4 bytes (big endian)
pub fn f32_to_bytes_be(value: f32, mass: &mut [u8; 4]) {
    mass.copy_from_slice(&value.to_be_bytes());
}

/// convert 4 bytes (big endian) to f32
pub fn bytes_to_f32_be(bytes: &[u8; 4]) -> f32 {
    f32::from_be_bytes(*bytes)
}

pub fn smpp_no_crypt_hash128(input: &[u64]) -> (u64, u64) {
    //first 120 nums if pi
    //14159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664
    //in hex
    //1675A9A76415868856888B17FDA2E98A87A642C4D875556B7D2BFA90587B274F1836F302CCCE330FCAADB99DCBA6F119508
    if usize::MAX > u64::MAX as usize {
        panic!("usize::MAX>u64::MAX");
    };
    let mut startparams = [
        0x1675A9A764158688u64,
        0x56888B17FDA2E98Au64,
        0x87A642C4D875556Bu64,
        0x7D2BFA90587B274Fu64,
        //0x1836F302CCCE330Fu64,
        //0xCAADB99DCBA6F119u64, //508
    ];

    fn proc_ha(temp: &mut [u64; 4], xx: u64, ii: usize, d_temp: &mut u64) {
        // Some primes between 2^63 and 2^64 for various uses.
        //Stolen from city.cc by Google
        let k0 = 0xc3a5c85c97cb3127u64;

        temp[(ii + 2) & 0b11] ^= xx.rotate_left(37);
        //mix Threefish modif
        temp[(ii + 2) & 0b11] = temp[(ii + 2) & 0b11].wrapping_add(temp[ii & 0b11]); //add (c+=a)
        temp[ii & 0b11] = temp[ii & 0b11].rotate_left(59); //ror ( a )
        temp[(ii + 2) & 0b11] = temp[(ii + 2) & 0b11].wrapping_mul(k0); //mul ( c )
        temp[ii & 0b11] ^= temp[(ii + 2) & 0b11]; //xor (a^= c)
        //mix end
        temp[ii & 0b11] = temp[ii & 0b11].wrapping_add(xx); // ( a+= x)

        temp[(ii + 1) & 0b11] = temp[(ii + 1) & 0b11].rotate_left(25);

        *d_temp ^= temp[(ii + 1) & 0b11];
        *d_temp = d_temp.rotate_left(4);
        // ror ( b )
    }
    let mut ii: usize = 0;
    let mut d_temp = 0xFF_FF_FF_FF_FF_FF_FF_FFu64;
    for x in input {
        proc_ha(&mut startparams, *x, ii, &mut d_temp);
        ii += 1;
    }

    for x in ii..EXPCP!(ii.checked_add(7), "ii + 7 overflow") {
        proc_ha(&mut startparams, x as u64, ii, &mut d_temp);
    }

    (
        (startparams[0] ^ startparams[1]).wrapping_add(d_temp), //+
        (startparams[2] ^ startparams[3]).wrapping_sub(d_temp), //-
    )
}

/// exponential moving average (ema) state
/// uses constant memory regardless of window size
pub struct Ema {
    alpha: f64,
    current_avg: f64,
    is_initialized: bool,
}

impl Ema {
    /// creates a new ema filter
    /// n - the virtual window size (period)
    pub fn new(n: usize) -> Self {
        Self {
            alpha: 2.0 / (n as f64 + 1.0),
            current_avg: 0.0,
            is_initialized: false,
        }
    }

    /// updates the average with a new value and returns it
    /// uses the formula: s = s_prev + alpha * (x - s_prev)
    pub fn next(&mut self, value: f64) -> f64 {
        if value.is_nan() || value.is_infinite() {
            return self.current_avg;
        }

        if !self.is_initialized {
            self.current_avg = value;
            self.is_initialized = true;
        } else {
            self.current_avg += self.alpha * (value - self.current_avg);
        }
        self.current_avg
    }

    /// returns the current average value without updating it
    pub fn get(&self) -> f64 {
        self.current_avg
    }
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

    /*
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
    }*/
}

#[cfg(test)]
mod tests_f32 {
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
            3.14159,
            -3.14159,
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
    #[cfg(test)]
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

#[cfg(test)]
mod tests_ema {
    use super::*;

    #[test]
    fn test_ema_initialization() {
        let mut ema = Ema::new(9); // alpha = 2 / (9 + 1) = 0.2
        let first_val = 10.0;
        let result = shadow_ema_next(&mut ema, first_val);

        assert!(ema.is_initialized);
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
        assert_eq!(ema.alpha, 1.0);

        let ema_large = Ema::new(199); // alpha = 2 / 200 = 0.01
        assert!((ema_large.alpha - 0.01).abs() < f64::EPSILON);
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
        assert!(!ema.is_initialized);

        ema.next(10.0);
        assert!(ema.is_initialized);
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

#[cfg(test)]
mod tests_safe_buffer {
    use super::*;

    #[test]
    fn new_buffer_is_empty() {
        let buf = SafeBuffer::<10>::new();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.get(), &[]);
    }

    #[test]
    fn write_full_capacity() {
        let mut buf = SafeBuffer::<5>::new();
        buf.write(b"hello");
        assert_eq!(buf.get(), b"hello");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn write_less_than_capacity() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"hi");
        assert_eq!(buf.get(), b"hi");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn write_overwrites_previous_data_completely() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"first long");
        assert_eq!(buf.get(), b"first long");
        buf.write(b"short");
        assert_eq!(buf.get(), b"short");
        assert_eq!(buf.len(), 5);
        // even though underlying bytes at positions 5..9 still contain 'long',
        // they are not exposed
        assert_eq!(&buf.data[5..9], b"long"); // direct access for test only
        assert_eq!(buf.get(), b"short");
    }

    #[test]
    fn write_empty_slice() {
        let mut buf = SafeBuffer::<5>::new();
        buf.write(b"abc");
        assert_eq!(buf.len(), 3);
        buf.write(b"");
        assert_eq!(buf.get(), b"");
        assert_eq!(buf.len(), 0);
        // next write after empty works
        buf.write(b"de");
        assert_eq!(buf.get(), b"de");
    }

    #[test]
    #[should_panic(expected = "input too large for buffer")]
    fn write_panics_when_input_exceeds_capacity() {
        let mut buf = SafeBuffer::<3>::new();
        buf.write(b"four");
    }

    #[test]
    fn modify_within_bounds() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"abcdefgh");
        buf.modify(2, b"12");
        assert_eq!(buf.get(), b"ab12efgh");
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn modify_at_start() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"hello");
        buf.modify(0, b"HE");
        assert_eq!(buf.get(), b"HEllo");
    }

    #[test]
    fn modify_at_end() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"hello");
        buf.modify(4, b"!");
        assert_eq!(buf.get(), b"hell!");
    }

    #[test]
    fn modify_with_empty_data_does_nothing() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"abc");
        buf.modify(1, b"");
        assert_eq!(buf.get(), b"abc");
        assert_eq!(buf.len(), 3);
    }

    #[test]
    #[should_panic(expected = "modify range out of bounds")]
    fn modify_panics_when_offset_beyond_len() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"abc");
        buf.modify(3, b"d"); // offset == len -> end = 4 > len=3
    }

    #[test]
    #[should_panic(expected = "modify range out of bounds")]
    fn modify_panics_when_end_exceeds_len() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"abc");
        buf.modify(2, b"de"); // offset=2, len=2 -> end=4 > 3
    }

    #[test]
    fn get_mut_allows_in_place_modification() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"abcdef");
        {
            let slice = buf.get_mut();
            slice[2..5].copy_from_slice(b"XYZ");
        }
        assert_eq!(buf.get(), b"abXYZf");
    }

    #[test]
    fn get_mut_respects_current_len() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"short");
        let slice = buf.get_mut();
        assert_eq!(slice.len(), 5);
        // trying to access beyond len is a compile-time or runtime panic (slice bounds)
    }

    #[test]
    fn clear_makes_buffer_empty() {
        let mut buf = SafeBuffer::<10>::new();
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
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"one");
        buf.clear();
        buf.write(b"two");
        assert_eq!(buf.get(), b"two");
    }

    #[test]
    fn multiple_writes_never_leak_old_data_via_get() {
        let mut buf = SafeBuffer::<30>::new();
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
        let mut buf = SafeBuffer::<0>::new();
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
        let mut buf = SafeBuffer::<0>::new();
        buf.write(b"x");
    }

    #[test]
    fn one_byte_buffer_edge_cases() {
        let mut buf = SafeBuffer::<1>::new();
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
        let mut buf = SafeBuffer::<1>::new();
        buf.write(b"a");
        buf.modify(1, b"b"); // offset == len -> end=2 > len=1
    }

    #[test]
    fn get_mut_after_clear_returns_empty() {
        let mut buf = SafeBuffer::<5>::new();
        buf.write(b"data");
        buf.clear();
        assert_eq!(buf.get_mut(), b"");
    }

    #[test]
    fn write_then_get_mut_then_write_works() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"first");
        {
            let _ = buf.get_mut(); // immutable borrow? actually mutable but dropped
        }
        buf.write(b"second"); // works because previous mutable borrow ended
        assert_eq!(buf.get(), b"second");
    }

    #[test]
    fn modify_does_not_change_len() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"123456");
        assert_eq!(buf.len(), 6);
        buf.modify(0, b"ab");
        assert_eq!(buf.len(), 6);
        buf.modify(4, b"xy");
        assert_eq!(buf.len(), 6);
    }

    #[test]
    fn get_and_get_mut_are_consistent() {
        let mut buf = SafeBuffer::<10>::new();
        buf.write(b"rust");
        assert_eq!(buf.get(), b"rust");
        buf.get_mut()[2] = b'p';
        assert_eq!(buf.get(), b"rupr");
    }
}
