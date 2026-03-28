use std::ops::BitXor;

const CHUNK_SIZE: usize = 64;
const WORDS_PER_CHUNK: usize = CHUNK_SIZE / 4;

const DOUBLE_WIS_INIT_ROUNDS: usize = 4;
const DOUBLE_WIS_TAG_ROUNDS: usize = 4;
const DOUBLE_WIS_CHIP_ROUNDS: usize = 10;
const WIS_STR_INIT_4_BYTES1: u32 = 0x57697327; //"Wis'" in utf8
const WIS_STR_INIT_4_BYTES2: u32 = 0x61_64656c; //"adel" in utf8

#[cfg(test)]
use std::sync::{Mutex, OnceLock};
#[cfg(test)]
static TEST_VEC_HASH: OnceLock<Mutex<Vec<Vec<u32>>>> = OnceLock::new();
#[cfg(test)]
static TEST_VEC_HASH_AFT: OnceLock<Mutex<Vec<Vec<u32>>>> = OnceLock::new();
#[cfg(test)]
static TEST_VEC_ENC: OnceLock<Mutex<Vec<Vec<u32>>>> = OnceLock::new();
#[cfg(test)]
fn test_vec_hash() -> &'static Mutex<Vec<Vec<u32>>> {
    TEST_VEC_HASH.get_or_init(|| Mutex::new(Vec::new()))
}
#[cfg(test)]
fn test_vec_hash_aft() -> &'static Mutex<Vec<Vec<u32>>> {
    TEST_VEC_HASH_AFT.get_or_init(|| Mutex::new(Vec::new()))
}
#[cfg(test)]
fn test_vec_enc() -> &'static Mutex<Vec<Vec<u32>>> {
    TEST_VEC_ENC.get_or_init(|| Mutex::new(Vec::new()))
}

//===============================================================
/// Splits a `u64` into two `u32` values representing the high (most significant) and low
/// (least significant) parts.
///
/// The function returns a tuple `(high, low)`, where:
/// - `high` is obtained by shifting the input right by 32 bits (`value >> 32`).
/// - `low` is the lower 32 bits obtained by casting to `u32` (`value as u32`).
///
/// This operation is purely arithmetic and independent of the target's endianness.

#[inline]
fn split_u64_to_u32_be_shift(value: u64) -> (u32, u32) {
    let high = (value >> 32) as u32;
    let low = value as u32;
    (high, low)
}
//===============================================================

/// Converts a byte array of length `NBYTES` into an array of `NU32` big‑endian `u32`
/// values.
///
/// The byte array is interpreted as a sequence of 4‑byte chunks, each converted to a
/// `u32` using big‑endian byte order (`from_be_bytes`). The number of bytes must be
/// exactly `NU32 * 4`, otherwise the function panics with a message explaining the
/// required relation.
///
/// # Panics
///
/// Panics if `NBYTES != NU32 * 4`. The panic message is:
/// `"NBYTES must equal NU32 * 4"`.
#[inline]
fn bytes_to_words<const NU32: usize, const NBYTES: usize>(bytes: &[u8; NBYTES]) -> [u32; NU32] {
    assert_eq!(NBYTES, NU32 * 4, "NBYTES must equal NU32 * 4");
    std::array::from_fn(|i| {
        let offset = i * 4;
        // SAFETY: `offset..offset+4` is always within bounds because of the assertion above.
        let chunk: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap();
        u32::from_be_bytes(chunk)
    })
}
#[inline]

/// Writes an array of `u32` values into a byte array as big‑endian bytes.
///
/// Each `u32` is converted to its big‑endian byte representation (`to_be_bytes`) and
/// copied into the destination byte slice at the appropriate offset. The total number
/// of bytes written is `NU32 * 4`, which must exactly match the size of the destination
/// array `NBYTES`.
///
/// # Panics
///
/// Panics if `NBYTES != NU32 * 4`. The panic message is `"assertion failed: NBYTES ==
/// NU32 * 4"`. (If a custom message is desired, it can be added as a second argument to
/// `assert_eq!`.)
///
/// # Examples
fn write_words_to_bytes<const NU32: usize, const NBYTES: usize>(
    words: &[u32; NU32],
    bytes: &mut [u8; NBYTES],
) {
    assert_eq!(NBYTES, NU32 * 4, "assertion failed: NBYTES == NU32 * 4");

    for (i, &word) in words.iter().enumerate() {
        let offset = i * 4;
        bytes[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
}

/// splits a mutable array of u32 into two halves and xors the first half with the second
/// half in place.
///
/// the function takes an array of length `nu32` (must be even) and divides it into two
/// halves of equal length `nu32out = nu32 / 2`. it then applies an element‑wise xor
/// between the two halves, storing the result in the first half. the second half remains
/// unchanged. the first half is returned as a mutable reference to a fixed‑size array.
///
/// # panics
///
/// panics in debug mode (or if assertions are enabled) when:
/// - `nu32` is not even, with the message "NU32 must be even".
/// - `nu32out` is not exactly `nu32 / 2`, with the message "NU32OUT must be half of
///   NU32".
/// also panics if the internal conversion from slice to array fails – this should never
/// happen because the lengths are guaranteed by the assertions.
pub fn hash_mid_xor<const NU32: usize, const NU32OUT: usize>(
    state_hash: &mut [u32; NU32],
) -> &mut [u32; NU32OUT] {
    assert_eq!(NU32 % 2, 0, "NU32 must be even");
    assert_eq!(NU32OUT, NU32 / 2, "NU32OUT must be half of NU32");

    let (left, right) = state_hash.split_at_mut(NU32OUT);

    // convert the mutable left slice to a mutable array reference
    let left_array: &mut [u32; NU32OUT] = left.try_into().expect("left half length mismatch");
    // convert the mutable right slice to an immutable array reference via a reborrow
    let right_array: &[u32; NU32OUT] = (&*right).try_into().expect("right half length mismatch");

    xor_vec::<u32, NU32OUT>(left_array, right_array);

    left_array
}
/// Converts a byte array of length `NBYTES` into an array of `NU32` big-endian `u32`
/// values.
///
/// The byte array is interpreted as a sequence of 4-byte chunks, each converted to a
/// `u32` using big‑endian byte order (`from_be_bytes`). The number of bytes must be
/// exactly `NU32 * 4`, otherwise the function panics.
///
/// # Panics
///
/// Panics if `NBYTES != NU32 * 4` (the assertion is active in debug builds and can be
/// disabled in release builds, but it's recommended to always keep it for correctness).
fn add_vec<const N: usize>(v1: &mut [u32; N], v2: &[u32; N]) {
    v1.iter_mut()
        .zip(v2.iter())
        .for_each(|(a, b)| *a = a.wrapping_add(*b));
}
/// Performs element-wise XOR between two arrays, storing the result in the first array.
///
/// For each index `i`, computes `v1[i] = v1[i] ^ v2[i]`. The operation is performed
/// in‑place on `v1`; `v2` is left unchanged. The function is generic over the element
/// type `T`, which must implement `Copy` and the bitwise XOR operator `BitXor<Output =
/// T>`.
fn xor_vec<T, const N: usize>(v1: &mut [T; N], v2: &[T; N])
where
    T: Copy + BitXor<Output = T>,
{
    v1.iter_mut().zip(v2.iter()).for_each(|(a, b)| *a = *a ^ *b);
}

/// zeroes the rightmost `n_bytes` bytes of a slice of `u32` words, interpreting the data
/// in big-endian order.
///
/// the function modifies the slice in place. each `u32` is treated as a 4-byte big-endian
/// value, so the rightmost bytes correspond to the least significant bytes of the last
/// words. the operation is performed using bit masks to avoid byte-by-byte conversion.
///
/// # panics
///
/// panics if `n_bytes` exceeds the total number of bytes in the slice (`data.len() * 4`).
pub fn zero_right_bytes_be(data: &mut [u32], n_bytes: usize) {
    let total_bytes = data.len() << 2;
    assert!(n_bytes <= total_bytes, "n_bytes exceeds total bytes");

    let full_words = n_bytes >> 2; // number of whole u32 to zero
    let partial_bytes = n_bytes & 0b11; // remaining bytes in the next word

    // zero complete words from the end
    if full_words > 0 {
        let start = data.len() - full_words;
        data[start..].fill(0);
    }

    // zero partial bytes in the word just before the full ones
    if partial_bytes > 0 {
        let idx = data.len() - full_words - 1; // index of the word to partially zero
        // mask that preserves the high (4 - partial_bytes) bytes and zeros the low partial_bytes
        let mask = !((1u32 << (partial_bytes << 3)) - 1);
        data[idx] &= mask;
    }
}

macro_rules! wis_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        //$a = $a.wrapping_add($b);
        $a = $b.wrapping_add($a.rotate_left($d & 0b11111));
        $d ^= $a;
        $d = $d.rotate_left(1_6);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(8);
        //$c = $c.wrapping_add($d);
        $c = $d.wrapping_add($c.rotate_left($b & 0b11111));
        $b ^= $c;
        $b = $b.rotate_left(7);
    };
}

pub fn wis_process_block(state: &mut [u32; WORDS_PER_CHUNK], double_rounds: usize) {
    for _ in 0..double_rounds {
        wis_round!(state[0], state[4], state[8], state[12]); // Column 0
        wis_round!(state[1], state[5], state[9], state[13]); // Column 1
        wis_round!(state[2], state[6], state[10], state[14]); // Column 2
        wis_round!(state[3], state[7], state[11], state[15]); // Column 3

        wis_round!(state[0], state[5], state[10], state[15]); // Diagonal 1 (main diagonal)
        wis_round!(state[1], state[6], state[11], state[12]); // Diagonal 2
        wis_round!(state[2], state[7], state[8], state[13]); // Diagonal 3
        wis_round!(state[3], state[4], state[9], state[14]); // Diagonal 4
    }
}

/// # example
/// ```
/// let mut data = vec![0u8; 128];
/// process_in_place(&mut data, |words| {
///     for w in words.iter_mut() {
///         *w = w.wrapping_add(1);
///     }
/// });
/// ```
pub fn process_in_place<F>(data: &mut [u8], mut process: F)
where
    F: FnMut(&mut [u32; WORDS_PER_CHUNK], usize, Option<usize>),
{
    let mut chunks = data.chunks_exact_mut(CHUNK_SIZE);

    for chunk in chunks.by_ref() {
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk
            .try_into()
            .expect("A chunk is always exactly CHUNK_SIZE bytes");
        let mut words = bytes_to_words(chunk_array);
        process(&mut words, CHUNK_SIZE, None);
        write_words_to_bytes(&words, chunk_array);
    }

    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; CHUNK_SIZE];
        buf[..remainder.len()].copy_from_slice(remainder);

        let mut words = bytes_to_words(&buf);
        process(
            &mut words,
            remainder.len(),
            Some(CHUNK_SIZE.checked_sub(remainder.len()).expect(
                "This is an impossible condition, since CHUNK_SIZE must always be greater than \
                 remainder",
            )),
        );
        write_words_to_bytes(&words, &mut buf);

        remainder.copy_from_slice(&buf[..remainder.len()]);
    }
}

pub fn wis_key_set<'a>(key8: &'a [u8; 32], nonce: &[u8; 16]) -> [u32; 16] {
    let mut key_state = [0; WORDS_PER_CHUNK];

    /*
    |-----------------------------------|
    | nonce1 | nonce2 | nonce3 | nonce4 |
    |-----------------------------------|
    |key32_1 |key32_2 |key32_3 |key32_4 |
    |-----------------------------------|
    |key32_5 |key32_6 |key32_7 |key32_8 |
    |-----------------------------------|
    |  wis1  |  wis2  |  crt1  |  crt2  |
    |-----------------------------------|
    */
    //let a = (0..32).map(|x| x as u8).collect();

    key_state[..4].clone_from_slice(&bytes_to_words::<4, 16>(nonce));

    key_state[4..4 + 8].clone_from_slice(&bytes_to_words::<8, 32>(key8));

    key_state[12] = WIS_STR_INIT_4_BYTES1;

    key_state[13] = WIS_STR_INIT_4_BYTES2;

    #[cfg(test)]
    {
        let op = [
            "nonce 1-4:   ",
            "key 1-4:     ",
            "key 5-8:     ",
            "w 1-2|ct1-2: ",
        ];

        let a = (0..32).map(|x| x as u8).collect::<Vec<u8>>();
        if key8.eq(a.as_slice()) {
            let ctr2 = split_u64_to_u32_be_shift(0x11_22_33_44_55_66_77_88);
            key_state[14] ^= ctr2.0;
            key_state[15] ^= ctr2.1;
            println!("");
            println!("WADE KEY STATE:");
            for i in 0..16 {
                if 0 == i % 4 {
                    println!("");
                    println!("");
                    print!("{:?} | ", op[i / 4]);
                }
                print!("{:08X} | ", key_state[i]);
            }
            let test_var = [
                0xF0F1F2F3,
                0xF4F5F6F7,
                0xF8F9FAFB,
                0xFCFDFEFF,
                0x00010203,
                0x04050607,
                0x08090A0B,
                0x0C0D0E0F,
                0x10111213,
                0x14151617,
                0x18191A1B,
                0x1C1D1E1F,
                0x57697327,
                0x6164656C,
                0x11223344,
                0x55667788u32,
            ];
            assert_eq!(test_var, key_state);
            println!("");
        }
    }
    //
    //

    wis_process_block(&mut key_state, DOUBLE_WIS_INIT_ROUNDS); //init

    key_state
}

fn enc_progress(
    plaintext: &mut [u32; WORDS_PER_CHUNK],
    key: &[u32; WORDS_PER_CHUNK],
    counter: u64,
) {
    let ctr2 = split_u64_to_u32_be_shift(counter);

    let mut temp = key.clone();
    temp[14] ^= ctr2.0;
    temp[15] ^= ctr2.1;

    #[cfg(test)]
    {
        let mut vec = test_vec_enc().lock().unwrap();
        vec.push(plaintext.to_vec());
    }

    wis_process_block(&mut temp, DOUBLE_WIS_CHIP_ROUNDS); //get state
    add_vec::<WORDS_PER_CHUNK>(&mut temp, key); //key + mix
    xor_vec::<u32, WORDS_PER_CHUNK>(plaintext, &mut temp); // = plaintext ^ (key + mix)
}

fn hash_progress(
    plaintext: &mut [u32; WORDS_PER_CHUNK],
    key: &[u32; WORDS_PER_CHUNK],
    hash: &mut [u32; WORDS_PER_CHUNK],
) {
    #[cfg(test)]
    {
        let mut vec = test_vec_hash().lock().unwrap();
        vec.push(plaintext.to_vec());
    }

    xor_vec::<u32, WORDS_PER_CHUNK>(hash, plaintext); //  = hash ^ (plaintext ^ (key + mix))
    wis_process_block(hash, DOUBLE_WIS_TAG_ROUNDS); // hash mix
    add_vec::<WORDS_PER_CHUNK>(hash, key); //hash  = key + (hash mix)

    #[cfg(test)]
    {
        let mut vec = test_vec_hash_aft().lock().unwrap();
        vec.push(hash.to_vec());
    }
}

pub fn encrypt(
    plaintext: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], &'static str> {
    let mut ctr: u64 = 0;
    let mut state_hash = [0; 16];

    if plaintext.len() > u64::MAX as usize {
        return Err("plaintext.len() > u64::MAX as usize; len() is to big");
    }

    let state_key = wis_key_set(key, nonce);
    state_hash.copy_from_slice(&state_key);

    process_in_place(plaintext, |block, adder, trim| {
        #[cfg(test)]
        {
            test_vec_hash().lock().unwrap().clear();
            test_vec_hash_aft().lock().unwrap().clear();
            test_vec_enc().lock().unwrap().clear();
        }

        enc_progress(block, &state_key, ctr);

        if let Some(ttt) = trim {
            zero_right_bytes_be(block, ttt)
        }

        hash_progress(block, &state_key, &mut state_hash);
        //

        ctr = ctr.checked_add(adder as u64).expect(
            "counter overflow during addition, if you see this, it means the program is not \
             working correctly, since there should have already been an overflow check in the \
             code before this",
        );
    });

    let hash = hash_mid_xor::<16, 8>(&mut state_hash);

    let mut hash8 = [0u8; 32];

    write_words_to_bytes::<8, 32>(hash, &mut hash8);

    Ok(hash8)
    //Ok(state_hash[])
}

pub fn decrypt(
    plaintext: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], &'static str> {
    let mut ctr: u64 = 0;
    let mut state_hash = [0; 16];

    if plaintext.len() > u64::MAX as usize {
        return Err("plaintext.len() > u64::MAX as usize; len() is to big");
    }

    let state_key = wis_key_set(key, nonce);
    state_hash.copy_from_slice(&state_key);

    process_in_place(plaintext, |block, adder, _| {
        //

        hash_progress(block, &state_key, &mut state_hash);
        enc_progress(block, &state_key, ctr);

        //

        ctr = ctr.checked_add(adder as u64).expect(
            "counter overflow during addition, if you see this, it means the program is not \
             working correctly, since there should have already been an overflow check in the \
             code before this",
        );
    });

    let hash = hash_mid_xor::<16, 8>(&mut state_hash);

    let mut hash8 = [0u8; 32];

    write_words_to_bytes::<8, 32>(hash, &mut hash8);

    Ok(hash8)
    //Ok(state_hash[])
}

#[cfg(test)]
mod tests_proc {

    use super::*;

    // Helper to convert a slice of u32 to little‑endian bytes.
    fn u32s_to_le_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|&w| w.to_le_bytes()).collect()
    }
    fn u32s_to_be_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|&w| w.to_be_bytes()).collect()
    }

    // Identity transformation: does nothing.
    fn identity(_words: &mut [u32; WORDS_PER_CHUNK], _: usize, _: Option<usize>) {}

    // Adds 1 to each u32.
    fn add_one(words: &mut [u32; WORDS_PER_CHUNK], _: usize, _: Option<usize>) {
        for w in words.iter_mut() {
            *w = w.wrapping_add(0x01_01_01_01);
        }
    }
    fn add_ottf(words: &mut [u32; WORDS_PER_CHUNK], _: usize, _: Option<usize>) {
        for w in words.iter_mut() {
            *w = w.wrapping_add(0x04_03_02_01);
        }
    }

    // Bitwise NOT.
    fn bitwise_not(words: &mut [u32; WORDS_PER_CHUNK], _: usize, _: Option<usize>) {
        for w in words.iter_mut() {
            *w = !*w;
        }
    }

    #[test]
    fn empty_slice() {
        let mut data: Vec<u8> = vec![];
        process_in_place(&mut data, identity);
        assert_eq!(data, vec![]);
    }

    #[test]
    fn exactly_one_chunk() {
        // 64 bytes of increasing values.
        let input: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let mut data = input.clone();

        // Process with add_one.
        process_in_place(&mut data, add_one);

        // Compute expected: convert to u32, add one, convert back.
        let mut words = [0u32; WORDS_PER_CHUNK];
        for (i, word) in words.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        }
        add_one(&mut words, 1, None);
        let expected = u32s_to_le_bytes(&words);

        assert_eq!(data, expected);
    }

    #[test]
    fn multiple_chunks() {
        // 3 full chunks (192 bytes)
        let input: Vec<u8> = (0..192).map(|i| i as u8).collect();

        let input_test: Vec<u8> = (0..192).map(|i| ((i / 4) + 1) * 4 as u8).collect();

        let mut data = input.clone();

        let ds = &mut [0; 13];

        process_in_place(ds, add_ottf);
        process_in_place(&mut data, add_ottf);

        assert_eq!(
            *ds,
            [4, 3, 2, 1, 4, 3, 2, 1, 4, 3, 2, 1, 4],
            "Order is not be endian"
        );


        // Compute expected chunk by chunk.
        let mut expected = Vec::with_capacity(192);
        for chunk_start in (0..192).step_by(64) {
            let mut words = [0u32; WORDS_PER_CHUNK];
            for (i, word) in words.iter_mut().enumerate() {
                let offset = chunk_start + i * 4;
                *word = u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap());
            }
            add_ottf(&mut words, 1, None);
            expected.extend(u32s_to_be_bytes(&words));
        }

        assert_eq!(data, expected);
        assert_eq!(input_test, data, "Order is not be endian");
    }

    #[test]
    fn remainder_less_than_64() {
        // 64 + 32 = 96 bytes → one full chunk + 32‑byte remainder.
        let input: Vec<u8> = (0..96).map(|i| i as u8).collect();
        let mut data = input.clone();

        process_in_place(&mut data, bitwise_not);

        // Compute expected.
        let mut expected = Vec::with_capacity(96);

        // First full chunk.
        let mut words_full = [0u32; WORDS_PER_CHUNK];
        for (i, word) in words_full.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        }
        bitwise_not(&mut words_full, 1, None);
        expected.extend(u32s_to_le_bytes(&words_full));

        // Remainder: pad to 64 bytes with zeros.
        let mut padded = [0u8; 64];
        padded[..32].copy_from_slice(&input[64..96]);

        let mut words_rem = [0u32; WORDS_PER_CHUNK];
        for (i, word) in words_rem.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(padded[offset..offset + 4].try_into().unwrap());
        }
        bitwise_not(&mut words_rem, 1, None);
        // Convert back to bytes, then take only the first 32 bytes.
        let rem_bytes = u32s_to_le_bytes(&words_rem);
        expected.extend(&rem_bytes[..32]);

        assert_eq!(data, expected);
    }

    #[test]
    fn remainder_exact_multiple() {
        // Already covered by multiple_chunks, but we can also test with 128 bytes.
        let input: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let mut data = input.clone();

        process_in_place(&mut data, identity);

        // Identity should leave data unchanged.
        assert_eq!(data, input);
    }

    #[test]
    fn zero_length_remainder() {
        // Exactly 64 bytes, remainder length 0.
        let input: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let mut data = input.clone();

        process_in_place(&mut data, add_one);

        let mut words = [0u32; WORDS_PER_CHUNK];
        for (i, word) in words.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
        }
        add_one(&mut words, 1, None);
        let expected = u32s_to_le_bytes(&words);

        assert_eq!(data, expected);
    }

    #[test]
    fn closure_call_count() {
        use std::cell::RefCell;
        use std::rc::Rc;

        // Track number of calls.
        let calls = Rc::new(RefCell::new(0));
        let input: Vec<u8> = (0..192).map(|i| i as u8).collect(); // 3 full chunks
        let mut data = input.clone();

        {
            let calls = calls.clone();
            process_in_place(&mut data, move |_, _, _| {
                *calls.borrow_mut() += 1;
            });
        }

        // Should be called exactly 3 times (once per full chunk).
        assert_eq!(*calls.borrow(), 3);
    }

    #[test]
    fn closure_call_count_with_remainder() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let calls = Rc::new(RefCell::new(0));
        let input: Vec<u8> = (0..100).map(|i| i as u8).collect(); // 1 full chunk + 36 bytes remainder
        let mut data = input.clone();

        {
            let calls = calls.clone();
            process_in_place(&mut data, move |_, _, _| {
                *calls.borrow_mut() += 1;
            });
        }

        // Should be called 2 times: one full chunk, then remainder.
        assert_eq!(*calls.borrow(), 2);
    }

    #[test]
    fn no_panic_on_any_length() {
        for len in 0..300 {
            let mut data = vec![0u8; len];
            // Using identity closure should never panic.
            process_in_place(&mut data, identity);
        }
    }

}

#[cfg(test)]
mod wdel {

    use super::*;

    #[test]
    fn t1() {
        let k: Vec<u8> = (0..32).map(|x| x as u8).collect();
        let n: Vec<u8> = (0xF0..0xF0 + 16).map(|x| x as u8).collect();
        let te = wis_key_set(&k[..].try_into().expect(""), &n[..].try_into().unwrap());

        for i in 0..16 {
            print!("{:08X} ", te[i]);
        }

        let te_test = [
            0x9A165F11,
            0xB5889C74,
            0xAC3048F0,
            0x807ECBC4,
            0x3B6ADFDD,
            0x54C94AC5,
            0xAEF81C1E,
            0x2A935C2F,
            0xC328886D,
            0x272CFA84,
            0x8413ECC4,
            0xA9ED4B41,
            0x53A28FD9,
            0x7D69D533,
            0x85010B14,
            0xEB1435BAu32,
        ];

        assert_eq!(te, te_test);
    }

    #[test]
    fn t2() {
        let mut data: Vec<u8> = (0..211).map(|i| i).collect::<Vec<_>>();

        let key: Vec<u8> = (0..32).map(|_| 0).collect::<Vec<_>>();

        let nonce: Vec<u8> = (0..32).map(|_| 0).collect::<Vec<_>>();

        let x = encrypt(
            &mut data,
            key[..32].try_into().unwrap(),
            nonce[..16].try_into().unwrap(),
        )
        .unwrap();

        to_hex(&data);
        println!();
        to_hex(&x);

        let y = decrypt(
            &mut data,
            key[..32].try_into().unwrap(),
            nonce[..16].try_into().unwrap(),
        )
        .unwrap();
        // to_hex(&y);
        // println!();
        // to_hex(&data);

        assert_eq!(y, x);
    }

    #[test]
    fn t3_bad_check() {
        let mut ctrma = 0;

        for yy in 0..311u32 {
            let mut data: Vec<u8> = (0..yy).map(|i| i as u8).collect::<Vec<_>>();

            let key: Vec<u8> = (0..32).map(|i| i + 1).collect::<Vec<_>>();

            let nonce: Vec<u8> = (0..32).map(|i| i + 1).collect::<Vec<_>>();

            let x = encrypt(
                &mut data,
                key[..32].try_into().unwrap(),
                nonce[..16].try_into().unwrap(),
            )
            .unwrap();

            for ii in 0..data.len() {
                ctrma += ii as usize;
                let mut data2 = data.clone();

                data2[ii] = !data2[ii];

                let y = decrypt(
                    &mut data2,
                    key[..32].try_into().unwrap(),
                    nonce[..16].try_into().unwrap(),
                )
                .unwrap();

                assert_ne!(x, y);
            }

            let y = decrypt(
                &mut data,
                key[..32].try_into().unwrap(),
                nonce[..16].try_into().unwrap(),
            )
            .unwrap();

            assert_eq!(y, x);
        }

        println!("{}", ctrma);
    }
    ///"{:02X} "
    fn to_hex<T: std::fmt::UpperHex>(he: &[T]) {
        print!("Hex: ");
        for item in he {
            match std::mem::size_of::<T>() {
                1 => print!("{:02X} ", item),
                4 => print!("{:08X} ", item),
                _ => print!("{:X} ", item),
            }
        }
        println!();
    }
}

#[cfg(test)]
mod tests_split {
    use super::*;

    #[test]
    fn test_hash_mid_xor_8_4() {
        let mut data = [1, 2, 3, 4, 5, 6, 7, 8];
        let expected = [1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8];
        let result = hash_mid_xor::<8, 4>(&mut data);
        assert_eq!(result, &expected);
        // the second half should remain unchanged
        assert_eq!(&data[4..], [5, 6, 7, 8]);
    }

    #[test]
    fn test_hash_mid_xor_16_8() {
        let mut data = [0u32; 16];
        for i in 0..16 {
            data[i] = i as u32;
        }
        let expected: [u32; 8] = (0..8)
            .map(|i| i ^ (i + 8))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let result = hash_mid_xor::<16, 8>(&mut data);
        assert_eq!(result, &expected);
    }

    #[test]
    fn test_hash_mid_xor_2_1() {
        let mut data = [42, 24];
        let result = hash_mid_xor::<2, 1>(&mut data);
        assert_eq!(result, &[42 ^ 24]);
        assert_eq!(data[1], 24);
    }

    #[test]
    fn test_hash_mid_xor_64_32() {
        let mut data = [0u32; 64];
        for i in 0..64 {
            data[i] = i as u32;
        }
        let expected: [u32; 32] = (0..32)
            .map(|i| i ^ (i + 32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let result = hash_mid_xor::<64, 32>(&mut data);
        assert_eq!(result, &expected);
    }

    #[test]
    fn test_reference_points_to_same_memory() {
        let mut data = [1, 2, 3, 4, 5, 6, 7, 8];
        let original_ptr = &mut data as *mut [u32; 8];
        let result = hash_mid_xor::<8, 4>(&mut data);
        let result_ptr = result as *mut [u32; 4];
        assert_eq!(result_ptr as *const (), original_ptr as *const ());
    }

    #[test]
    #[should_panic(expected = "NU32 must be even")]
    fn test_odd_nu32_panics() {
        let mut data = [1, 2, 3];
        hash_mid_xor::<3, 1>(&mut data);
    }

    #[test]
    #[should_panic(expected = "NU32OUT must be half of NU32")]
    fn test_wrong_nu32out_panics() {
        let mut data = [1, 2, 3, 4];
        hash_mid_xor::<4, 3>(&mut data);
    }
}

#[cfg(test)]
mod tests_b_to_w {
    use super::*;

    #[test]
    fn zero_elements() {
        // NU32 = 0, NBYTES = 0 should work.
        let bytes: [u8; 0] = [];
        let words = bytes_to_words::<0, 0>(&bytes);
        assert_eq!(words, []);
    }

    #[test]
    fn one_element() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        let words = bytes_to_words::<1, 4>(&bytes);
        assert_eq!(words, [0x01020304]);
    }

    #[test]
    fn two_elements() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let words = bytes_to_words::<2, 8>(&bytes);
        assert_eq!(words, [0x12345678, 0x9ABCDEF0]);
    }

    #[test]
    fn multiple_elements() {
        // 4 u32 → 16 bytes, fill with a pattern.
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = i as u8;
        }
        let words = bytes_to_words::<4, 16>(&bytes);
        // big‑endian: first u32 from bytes[0..4] = 0x00010203
        assert_eq!(words, [0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F]);
    }

    #[test]
    #[should_panic(expected = "NBYTES must equal NU32 * 4")]
    fn mismatched_sizes() {
        // NU32 = 2, NBYTES = 7 (should be 8)
        let bytes = [0u8; 7];
        let _ = bytes_to_words::<2, 7>(&bytes);
    }

    #[test]
    #[should_panic(expected = "NBYTES must equal NU32 * 4")]
    fn zero_nu32_nonzero_bytes() {
        // NU32 = 0, NBYTES > 0 → invalid
        let bytes = [0u8; 4];
        let _ = bytes_to_words::<0, 4>(&bytes);
    }
}

#[cfg(test)]
mod tests_split_u64 {
    use super::*;

    #[test]
    fn zero() {
        assert_eq!(split_u64_to_u32_be_shift(0), (0, 0));
    }

    #[test]
    fn small_number() {
        assert_eq!(split_u64_to_u32_be_shift(0x1234), (0, 0x1234));
    }

    #[test]
    fn max_low() {
        assert_eq!(split_u64_to_u32_be_shift(0xFFFFFFFF), (0, 0xFFFFFFFF));
    }

    #[test]
    fn only_high() {
        assert_eq!(
            split_u64_to_u32_be_shift(0x1234567800000000),
            (0x12345678, 0)
        );
    }

    #[test]
    fn both_halves_filled() {
        let value = 0xDEADBEEF_CAFEBABE;
        let (high, low) = split_u64_to_u32_be_shift(value);
        assert_eq!(high, 0xDEADBEEF);
        assert_eq!(low, 0xCAFEBABE);
    }

    #[test]
    fn max_value() {
        assert_eq!(split_u64_to_u32_be_shift(u64::MAX), (u32::MAX, u32::MAX));
    }

    #[test]
    fn alternating_pattern() {
        let value = 0xAAAAAAAA_BBBBBBBB;
        let (high, low) = split_u64_to_u32_be_shift(value);
        assert_eq!(high, 0xAAAAAAAA);
        assert_eq!(low, 0xBBBBBBBB);
    }
}

#[cfg(test)]
mod tests_write {
    use super::*;

    #[test]
    fn zero_elements() {
        let words: [u32; 0] = [];
        let mut bytes: [u8; 0] = [];
        write_words_to_bytes::<0, 0>(&words, &mut bytes);
        // nothing to assert, just no panic
    }

    #[test]
    fn one_element() {
        let words = [0x01020304];
        let mut bytes = [0u8; 4];
        write_words_to_bytes::<1, 4>(&words, &mut bytes);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn two_elements() {
        let words = [0x12345678, 0x9ABCDEF0];
        let mut bytes = [0u8; 8];
        write_words_to_bytes::<2, 8>(&words, &mut bytes);
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    }

    #[test]
    fn multiple_elements() {
        let words = [0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F];
        let mut bytes = [0u8; 16];
        write_words_to_bytes::<4, 16>(&words, &mut bytes);
        let expected: [u8; 16] = (0..16).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(bytes, expected);
    }

    #[test]
    #[should_panic(expected = "assertion failed: NBYTES == NU32 * 4")]
    fn mismatched_sizes_too_few_bytes() {
        let words = [0u32; 2]; // needs 8 bytes
        let mut bytes = [0u8; 7];
        write_words_to_bytes::<2, 7>(&words, &mut bytes);
    }

    #[test]
    #[should_panic(expected = "assertion failed: NBYTES == NU32 * 4")]
    fn mismatched_sizes_too_many_bytes() {
        let words = [0u32; 2]; // needs 8 bytes
        let mut bytes = [0u8; 9];
        write_words_to_bytes::<2, 9>(&words, &mut bytes);
    }

    #[test]
    #[should_panic(expected = "assertion failed: NBYTES == NU32 * 4")]
    fn zero_words_nonzero_bytes() {
        let words: [u32; 0] = [];
        let mut bytes = [0u8; 4];
        write_words_to_bytes::<0, 4>(&words, &mut bytes);
    }
}

#[cfg(test)]
mod tests_add_vec {
    use super::*;

    #[test]
    fn zero_length() {
        let mut v1: [u32; 0] = [];
        let v2: [u32; 0] = [];
        add_vec(&mut v1, &v2);
        // nothing to assert, just no panic
    }

    #[test]
    fn simple_addition() {
        let mut v1 = [1, 2, 3, 4];
        let v2 = [5, 6, 7, 8];
        add_vec(&mut v1, &v2);
        assert_eq!(v1, [6, 8, 10, 12]);
    }

    #[test]
    fn with_zeros() {
        let mut v1 = [10, 20, 30];
        let v2 = [0, 0, 0];
        add_vec(&mut v1, &v2);
        assert_eq!(v1, [10, 20, 30]);
    }

    #[test]
    fn with_max_values() {
        let mut v1 = [u32::MAX, u32::MAX, 100];
        let v2 = [1, 0, u32::MAX];
        add_vec(&mut v1, &v2);
        assert_eq!(v1, [0, u32::MAX, 99]);
    }

    #[test]
    fn large_n() {
        const N: usize = 100;
        let mut v1 = [0u32; N];
        let v2 = [1u32; N];
        add_vec(&mut v1, &v2);
        assert_eq!(v1, [1u32; N]);
    }

    #[test]
    fn v2_unchanged() {
        let mut v1 = [1, 2, 3];
        let v2 = [4, 5, 6];
        let v2_copy = v2;
        add_vec(&mut v1, &v2);
        assert_eq!(v2, v2_copy);
    }
}

#[cfg(test)]
mod tests_xor_vec {
    use std::ops::BitXor;

    use super::*;

    #[test]
    fn zero_length() {
        let mut v1: [u8; 0] = [];
        let v2: [u8; 0] = [];
        xor_vec(&mut v1, &v2);
        // nothing to assert, just no panic
    }

    #[test]
    fn simple_u32() {
        let mut v1 = [0b1100, 0b1010];
        let v2 = [0b1010, 0b1100];
        xor_vec(&mut v1, &v2);
        assert_eq!(v1, [0b0110, 0b0110]);
    }

    #[test]
    fn simple_u8() {
        let mut v1 = [0xFFu8, 0x00u8];
        let v2 = [0x0Fu8, 0xF0u8];
        xor_vec(&mut v1, &v2);
        assert_eq!(v1, [0xF0u8, 0xF0u8]);
    }

    #[test]
    fn identity_xor() {
        let mut v1 = [0x1234u16, 0x5678u16];
        let v2 = [0x0000u16, 0x0000u16];
        xor_vec(&mut v1, &v2);
        assert_eq!(v1, [0x1234, 0x5678]);
    }

    #[test]
    fn self_xor() {
        let mut v1 = [0x1234u16, 0x5678u16];
        let v2 = v1; // copy
        xor_vec(&mut v1, &v2);
        assert_eq!(v1, [0x0000, 0x0000]);
    }

    #[test]
    fn v2_unchanged() {
        let mut v1 = [1, 2, 3];
        let v2 = [4, 5, 6];
        let v2_copy = v2;
        xor_vec(&mut v1, &v2);
        assert_eq!(v2, v2_copy);
    }

    // Custom type that implements Copy and BitXor
    #[derive(Copy, Clone, PartialEq, Debug)]
    struct Custom(u32);
    impl BitXor for Custom {
        type Output = Self;
        fn bitxor(self, rhs: Self) -> Self {
            Custom(self.0 ^ rhs.0)
        }
    }

    #[test]
    fn custom_type() {
        let mut v1 = [Custom(1), Custom(2)];
        let v2 = [Custom(3), Custom(1)];
        xor_vec(&mut v1, &v2);
        assert_eq!(v1, [Custom(1 ^ 3), Custom(2 ^ 1)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_none() {
        let mut data = [1, 2, 3];
        zero_right_bytes_be(&mut data, 0);
        assert_eq!(data, [1, 2, 3]);
    }

    #[test]
    fn zero_one_byte() {
        let mut data = [0x12345678, 0x9ABCDEF0];
        zero_right_bytes_be(&mut data, 1);
        // last byte of the last word becomes 0 (lowest byte of 0x9ABCDEF0 → 0xF0 → 0)
        assert_eq!(data, [0x12345678, 0x9ABCDE00]);
    }

    #[test]
    fn zero_two_bytes() {
        let mut data = [0x12345678, 0x9ABCDEF0];
        zero_right_bytes_be(&mut data, 2);
        assert_eq!(data, [0x12345678, 0x9ABC0000]);
    }

    #[test]
    fn zero_three_bytes() {
        let mut data = [0x12345678, 0x9ABCDEF0];
        zero_right_bytes_be(&mut data, 3);
        assert_eq!(data, [0x12345678, 0x9A000000]);
    }

    #[test]
    fn zero_four_bytes() {
        let mut data = [0x12345678, 0x9ABCDEF0];
        zero_right_bytes_be(&mut data, 4);
        assert_eq!(data, [0x12345678, 0x00000000]);
    }

    #[test]
    fn zero_five_bytes() {
        let mut data = [0x12345678, 0x9ABCDEF0, 0xDEADBEEF];
        zero_right_bytes_be(&mut data, 5);
        // 5 bytes: one full word (last) + 1 byte from previous word
        assert_eq!(data, [0x12345678, 0x9ABCDE00, 0x00000000]);
    }

    #[test]
    fn zero_all_bytes() {
        let mut data = [0x12345678, 0x9ABCDEF0];
        zero_right_bytes_be(&mut data, 8);
        assert_eq!(data, [0x00000000, 0x00000000]);
    }

    #[test]
    fn zero_example_from_description() {
        let mut data = [
            0x1B6BD6DE, 0x0C6444CA, 0x838181F0, 0x9AFDB683, 0x401499AC, 0x86FD856E, 0x828D9E3B,
            0xBBE71234, 0xDEADBEEF, 0xCAFEBABE,
        ];
        zero_right_bytes_be(&mut data, 10);
        let expected = [
            0x1B6BD6DE, 0x0C6444CA, 0x838181F0, 0x9AFDB683, 0x401499AC, 0x86FD856E, 0x828D9E3B,
            0xBBE70000, 0x00000000, 0x00000000,
        ];
        assert_eq!(data, expected);
    }

    #[test]
    fn zero_cross_word_boundary() {
        let mut data = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
        zero_right_bytes_be(&mut data, 6);
        // 6 bytes = 1 full word + 2 bytes from previous word
        assert_eq!(data, [0xFFFFFFFF, 0xFFFF0000, 0x00000000]);
    }

    #[test]
    #[should_panic(expected = "n_bytes exceeds total bytes")]
    fn zero_too_many_bytes() {
        let mut data = [1, 2];
        zero_right_bytes_be(&mut data, 9);
    }
}
