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

use crate::{EXPCP, checked_cast};

/// a fixed-size buffer that stores only the last written data.
/// when writing a new block, old data becomes inaccessible, even if the new block is
/// shorter.
#[derive(Debug, Clone, PartialEq)]
pub struct SafeBuffer {
    data: Box<[u8]>,
    len: usize,
}

impl SafeBuffer {
    /// creates a new empty buffer.
    pub fn new(siz: usize) -> Self {
        Self {
            data: vec![0; siz].into_boxed_slice(),
            len: 0,
        }
    }

    /// writes new data, completely replacing the content.
    /// panics if `input` is longer than n.
    pub fn write(&mut self, input: &[u8]) {
        EXPCP!(
            if input.len() <= self.data.len() {
                Some(())
            } else {
                None
            },
            "input too large for buffer"
        );
        let dst = EXPCP!(
            self.data.get_mut(..input.len()),
            "failed to get input range"
        );
        dst.copy_from_slice(input);
        self.len = input.len();
    }
    ///capacity
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// returns a slice with the actual data (exactly `len` bytes).
    pub fn get(&self) -> &[u8] {
        EXPCP!(self.data.get(..self.len), "failed to get data range")
    }

    /// modifies a part of the already written data.
    /// panics if the range `offset..offset+new_data.len()` exceeds `self.len`.
    pub fn modify(&mut self, offset: usize, new_data: &[u8]) {
        let end = offset
            .checked_add(new_data.len())
            .expect("overflow in offset + new_data.len()");
        EXPCP!(
            if end <= self.len { Some(()) } else { None },
            "modify range out of bounds"
        );
        let dst = EXPCP!(self.data.get_mut(offset..end), "failed to get modify range");
        dst.copy_from_slice(new_data);
    }

    /// returns a mutable slice for modifying data (only within the written length).
    pub fn get_mut(&mut self) -> &mut [u8] {
        EXPCP!(
            self.data.get_mut(..self.len),
            "failed to get mutable data range"
        )
    }

    /// returns the current length of written data.
    pub fn len(&self) -> usize {
        self.len
    }
    /// if len == 0 0 -> true
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// logically clears the buffer (physical bytes remain but are inaccessible).
    pub fn clear(&mut self) {
        self.len = 0;
    }
}
///array to be u64
pub fn bytes_to_u64(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() > 8 || bytes.is_empty() {
        return Err("bytes.len() must be between 1 and 8".to_string());
    }
    let padding = 8usize
        .checked_sub(bytes.len())
        .expect("subtraction underflow: bytes.len() > 8");
    let mut buffer = [0u8; 8];
    let dst = buffer
        .get_mut(padding..)
        .ok_or("failed to get buffer range")?;
    dst.copy_from_slice(bytes);

    Ok(u64::from_be_bytes(buffer))
}
///be u64 to array
pub fn u64_to_1_8bytes(num: u64, bytes: &mut [u8]) -> Result<(), String> {
    if bytes.len() > 8 || bytes.is_empty() {
        return Err("bytes.len() > 8 ||bytes.len() ==0".to_string());
    }

    let buffer: [u8; 8] = num.to_be_bytes();
    let remaining = buffer
        .len()
        .checked_sub(bytes.len())
        .expect("subtraction underflow: buffer.len() < bytes.len()");
    let src = buffer
        .get(remaining..)
        .ok_or("failed to get source range")?;
    bytes.copy_from_slice(src);
    Ok(())
}
/// a (+ or -) b  = u64
pub fn add_u64_i64(a: u64, b: i64, zero_if_in_sub_a_less_than_b: bool) -> Result<u64, String> {
    if b >= 0 {
        a.checked_add(checked_cast!(b.wrapping_abs() => u64, err "b.wrapping_abs() conversion to u64 failed")?)
            .ok_or("overflow occurred adding positive".to_string())
    } else {
        a.checked_sub(checked_cast!(b.wrapping_abs() => u64, err "b.wrapping_abs() conversion to u64 failed")?).map_or(
            if zero_if_in_sub_a_less_than_b {
                Ok(0)
            } else {
                Err("underflow occurred subtracting absolute".to_string())
            },
            Ok,
        )
        //.ok_or("anderflow occurred  subtracting absolute")
    }
}
///insert_bits
pub fn extract_bits(data: &[u8], pos: usize, len: u8) -> Result<u32, String> {
    if len == 0 || len > 32 {
        return Err("len> 32 bits or len == 0".to_string());
    }
    let len_usize = checked_cast!(len => usize, err "len conversion to usize failed")?;
    let end_pos = pos.checked_add(len_usize).ok_or("overflow in pos + len")?;

    if end_pos > data.len() << 3 {
        return Err("end_pos > output.len() * 8".to_string());
    }

    // init the result variable
    let mut result: u32 = 0;

    for i in pos..end_pos {
        let byte_index: usize = i >> 3; // Byte index
        let bit_index = i & 0b111;
        let bit_offset = 7usize
            .checked_sub(bit_index)
            .ok_or("subtraction underflow: bit_index > 7")?; // Bit offset (big-endian)
        // extract the bit from the byte
        let byte1 = data.get(byte_index).ok_or("failed to get byte from data")?;
        let bit: u8 = (*byte1 >> bit_offset) & 1;
        // add the bit to the result
        result = (result << 1) | checked_cast!(bit => u32, err "bit conversion to u32 failed")?;
    }

    Ok(result)
}
///This is a remnant from the old version of the algorithm;
///it inserts the first len bits into the [u8] array starting at position pos (not in
/// bytes, but in bits!).
pub fn insert_bits(output: &mut [u8], pos: usize, len: u8, input: u32) -> Result<(), String> {
    if len == 0 || len > 32 {
        return Err("len> 32 bits or len == 0".to_string());
    }
    let len_usize = checked_cast!(len => usize, err "len conversion to usize failed")?;
    let end_pos = pos.checked_add(len_usize).ok_or("overflow in pos + len")?;

    if end_pos > output.len() << 3 {
        return Err("end_pos > output.len() * 8".to_string());
    }
    // extract the lowest len bits from the input
    let mask = 0xFFFFFFFFu32
        .checked_shr(
            32u32
                .checked_sub(checked_cast!(len =>u32,err "len conversion to u32 failed")?)
                .ok_or("len > 32")?,
        )
        .ok_or("shift overflow")?;
    let bits_to_insert: u32 = input & mask;

    for i in pos..end_pos {
        let byte_indx: usize = i >> 3; // Byte index
        let bit_index = i & 0b111;
        let bit_offst = 7usize
            .checked_sub(bit_index)
            .ok_or("bit_index out of range (must be 0-7)")?;
        // extract the current bit from the input bits
        let shift = end_pos
            .checked_sub(i)
            .ok_or("shift underflow: end_pos < i")?
            .checked_sub(1)
            .ok_or("shift underflow: end_pos == i")?;
        let bit: u32 = (bits_to_insert >> shift) & 1;
        let out_byte = output
            .get_mut(byte_indx)
            .ok_or("failed to get mutable byte from output")?;
        if bit == 1 {
            *out_byte |= 1 << bit_offst;
        } else {
            *out_byte &= !(1 << bit_offst);
        }
    }

    Ok(())
}

/// Fills the rest of the slice starting from `pad_pos` with the bitwise NOT
/// of the last payload byte.
///
/// Returns `true` on success, or `false` if indexes are invalid or no space is left.
///
pub fn pad_maker(arr: &mut [u8], pad_pos: usize) -> bool {
    let last_pos = if let Some(x) = pad_pos.checked_sub(1) {
        x
    } else {
        return false;
    };

    let last_byte = !if let Some(x) = arr.get(last_pos) {
        *x
    } else {
        return false;
    };

    if let Some(x) = arr.get_mut(pad_pos..) {
        if x.is_empty() {
            return false;
        }
        x.fill(last_byte);
    } else {
        return false;
    }

    true
}

/// Trims the padding applied by `pad_maker` and returns the original payload length.
///
/// Scans backwards from the end. If the padding structure is broken or missing,
/// it safely returns the full length of the input slice (`arr.len()`).
///
pub fn pad_trim(arr: &[u8]) -> usize {
    let total_len = arr.len();

    let target_pad_byte = match arr.last() {
        Some(&byte) => byte,
        None => return 0,
    };

    let expected_last_data_byte = !target_pad_byte;

    for (i, &current_byte) in arr.iter().enumerate().rev().skip(1) {
        if current_byte == expected_last_data_byte {
            return i.saturating_add(1);
        }

        if current_byte != target_pad_byte {
            return total_len;
        }
    }

    total_len
}

/// Appends `pad_pos` bytes to the end of the vector, using the inversion of the last byte.
/// If `pad_add == 0`, no alignment is required, the function returns `false`.
pub fn pad_maker_vec(arr: &mut Vec<u8>, pad_add: usize) -> bool {
    // If nothing needs to be added, return false as per condition
    if pad_add == 0 {
        return false;
    }

    // Get the last byte of the current data.
    // If the vector is empty, we cannot invert, return false.
    let last_byte = match arr.last() {
        Some(&byte) => !byte, // Invert bits
        None => return false,
    };

    arr.resize(arr.len().saturating_add(pad_add), last_byte);
    true
}

/// Determines the real data size, strips the padding and truncates the vector.
pub fn pad_trim_vec(arr: &mut Vec<u8>) {
    // Safely get the very last padding byte
    let target_pad_byte = match arr.last() {
        Some(&byte) => byte,
        None => return, // Vector is empty, nothing to truncate
    };

    let expected_last_data_byte = !target_pad_byte;

    // Search for the padding boundary from the end of the array
    for (i, &current_byte) in arr.iter().enumerate().rev().skip(1) {
        if current_byte == expected_last_data_byte {
            // Found the inverted byte — this is the end of real data.
            // i.saturating_add(1) gives the exact payload length.
            arr.truncate(i.saturating_add(1));
            return;
        }

        if current_byte != target_pad_byte {
            // Padding structure is corrupted, do not modify the vector
            return;
        }
    }
}

///converts a byte to a number that fits within the maximum capacity of that word
pub fn len_byte_maximal_capacity_check(len: usize) -> (u64, usize) {
    if len > 7 {
        return (!0_u64, 64);
    }
    let t = len << 3;
    (!((!0_u64) << t), t)
}

/// # Examples
/// ```
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x00), 1);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF), 1);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF), 2);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x01_00), 2);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF_FF), 3);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x01_00_00), 3);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF_FF_FF), 4);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x01_00_00_00), 4);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF_FF_FF_FF), 5);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x01_00_00_00_00), 5);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF_FF_FF_FF_FF), 6);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x01_00_00_00_00_00), 6);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF_FF_FF_FF_FF_FF), 7);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x01_00_00_00_00_00_00), 7);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0xFF_FF_FF_FF_FF_FF_FF_FF), 8);
/// assert_eq!(wis::w1utils::len_u64_as_bytes(0x10_FF_FF_FF_FF_FF_FF_FF), 8);
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
/// let result = wis::w1utils::split_by_lengths(&mut data, &lengths, false).unwrap();
/// assert_eq!(result[0],[1,2,3,4]);
/// assert_eq!(result[1],[5]);
/// assert_eq!(result[2],[6,7]);
/// assert_eq!(result[3],[8,9]);
/// ```
pub fn split_by_lengths<'a, T>(
    data: &'a mut [T],
    lengths: &[usize],
    absolute: bool,
) -> Result<Vec<&'a mut [T]>, String> {
    let total: usize = data.len();
    let mut remaining_data: &'a mut [T] = data;
    let capacity = lengths
        .len()
        .checked_add(1)
        .ok_or("overflow in lengths.len() + 1")?;
    let mut result: Vec<&mut [T]> = Vec::with_capacity(capacity);

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
            return Err("total lengths != data length".to_string());
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
/// let result = wis::w1utils::split_by_lengths(&mut data, &lengths, false).unwrap();
/// assert_eq!(result.len(), 4);
/// ```
pub fn split_by_positions<'a, T>(
    data: &'a mut [T],
    positions: &[usize],
    absolute: bool,
) -> Result<Vec<&'a mut [T]>, String> {
    let total = data.len();
    let mut remaining_data: &'a mut [T] = data;
    let capacity = positions
        .len()
        .checked_add(1)
        .ok_or("overflow in positions.len() + 1")?;
    let mut result: Vec<&mut [T]> = Vec::with_capacity(capacity);
    let mut last_pos: usize = 0;

    for &pos in positions {
        if pos <= last_pos {
            return Err("positions not strictly increasing".to_string());
        }
        if pos > total {
            if absolute {
                break;
            } else {
                return Err("position exceeds data length".to_string());
            }
        }
        let len = pos
            .checked_sub(last_pos)
            .ok_or("subtraction underflow: pos < last_pos")?;
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

/// convert f32 to 4 bytes (big endian)
pub fn f32_to_bytes_be(value: f32, mass: &mut [u8; 4]) {
    mass.copy_from_slice(&value.to_be_bytes());
}

/// convert 4 bytes (big endian) to f32
pub fn bytes_to_f32_be(bytes: &[u8; 4]) -> f32 {
    f32::from_be_bytes(*bytes)
}

#[inline]
///whether the generated random number falls within the range of successful outcomes
pub const fn check_probability(scaled_prob: u32, random_val: u32) -> bool {
    // 1. If the probability is 100%, then any random number returns true
    if scaled_prob == u32::MAX {
        return true;
    }

    // 2. For all other cases (including 0) strict comparison works perfectly
    random_val < scaled_prob
}

/// exponential moving average (ema) state
/// uses constant memory regardless of window size
pub struct Ema {
    alpha: f64,
    current_avg: f64,
    is_initialized: bool,
}

impl Ema {
    #[cfg(test)]
    pub fn f_is_initialized(&self) -> bool {
        self.is_initialized
    }
    #[cfg(test)]
    pub fn f_current_avg(&self) -> f64 {
        self.current_avg
    }
    #[cfg(test)]
    pub fn f_alpha(&self) -> f64 {
        self.alpha
    }

    /// creates a new ema filter
    /// n - the virtual window size (period)
    pub fn new(n: usize) -> Self {
        Self {
            //Damn, it's not implemented for f64 either, damn it
            #[allow(clippy::as_conversions)]
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

/// Safely converts f64 from the range [0.0; 1.0] to [0; u32::MAX]
pub fn float_to_u32_scaled(val: f32) -> Result<u32, String> {
    // Check the incoming bounds and NaN just in case
    if !(0.0..=1.0).contains(&val) || val.is_nan() {
        return Err("Value out of range [0.0, 1.0] or NaN".to_string());
    }

    #[allow(clippy::as_conversions)]
    let max_f32 = u32::MAX as f32;

    // Multiply the coefficient by the maximum value u32
    let scaled = val * max_f32;

    // Round to the nearest integer and convert to u32
    #[allow(clippy::as_conversions)]
    let result = scaled.round() as u32;

    Ok(result)
}

/// Computes a new packet length based on random adjustment and trimming policy.
///
/// # Arguments
/// * `max_len` – absolute upper bound for the packet length (must be > 0).
/// * `payload_len` – current packet length.
/// * `rand_num` – a pseudo‑random number used to generate the adjustment.
/// * `rand_range` – controls the maximum possible adjustment magnitude.
/// * `no_trim` – if `true`, the length can only be increased; if `false`, it can go up or down.
///
/// # Returns
/// `Ok(usize)` with the adjusted length, clamped to `[1, max_len]`.
/// Returns an error if `max_len` is zero.
pub fn fuck_coeff_of_rand_pack_trim(
    max_len: &usize,
    payload_len: &usize,
    rand_num: &usize,
    rand_range: &usize,
    no_trim: bool,
) -> Result<usize, String> {
    // Reject zero maximum, as it would make all lengths invalid.
    if *max_len == 0 {
        return Err("max_len must be greater than 0".to_string());
    }

    // Effective range cannot exceed the maximum length.
    let range = if rand_range > max_len {
        max_len
    } else {
        rand_range
    };

    // Half of the range (used to lower the length when trimming is allowed).
    // `checked_div` returns `None` only when dividing by zero, which cannot happen
    // because `range` is zero only when `rand_range` is zero, but division by zero
    // is still safe – we handle it with `unwrap_or(0)`.
    let half_range = range.checked_div(2).unwrap_or(0);
    // Random offset within the effective range.
    let random_offset = rand_num.checked_rem(*range).unwrap_or(0);

    let adjusted = if no_trim {
        // Can only grow: add the random offset, saturating on overflow.
        payload_len.saturating_add(random_offset)
    } else {
        // Can both shrink and grow.
        if *payload_len >= half_range {
            // Safe subtraction because payload_len >= half_range.
            let base = payload_len.saturating_sub(half_range);
            base.saturating_add(random_offset)
        } else {
            // payload_len < half_range, so we compute the deficit.
            let deficit = half_range.saturating_sub(*payload_len);
            if random_offset <= deficit {
                // The resulting length would be <= 0, so we later clamp it to 1.
                0
            } else {
                // Positive difference, safe with saturating_sub.
                random_offset.saturating_sub(deficit)
            }
        }
    };

    // Ensure the result is at least 1.
    let result = if adjusted == 0 { 1 } else { adjusted };

    // Clamp to the absolute maximum.
    let result = if result > *max_len { *max_len } else { result };

    Ok(result)
}
