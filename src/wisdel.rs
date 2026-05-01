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

use std::ops::BitXor;

use crate::{EXPCP, checked_cast};
const CHUNK_SIZE: usize = 64;
const WORDS_PER_CHUNK: usize = match CHUNK_SIZE.checked_div(4) {
    Some(val) => val,
    None => panic!("Division by zero in CHUNK_SIZE / 4"),
};

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

/// # Non‑standard, unverified cipher
///
/// **WARNING:** This `encrypt` function implements a custom, non‑standard AEAD cipher
/// based on the internal `WIS` block algorithm. **It has not undergone any rigorous
/// cryptanalysis** and should **never** be used in production or security‑sensitive
/// environments. Use only for educational or research purposes.
///
/// ## Overview
///
/// The function performs **authenticated encryption with associated data** (AEAD)
/// **in‑place** on the `plaintext` buffer. It returns a 256‑bit authentication tag.
///
/// ## How it works
///
/// ### 1. Initialisation
/// - `state_key = wis_key_set(key, nonce)` – generates an internal key state of 16 words
///   (64 bytes) from the 256‑bit `key` and 128‑bit `nonce`. Uses `wis_process_block` with
///   **4 rounds**.
/// - `state_hash = state_key` – initial hash state for authentication.
/// - Block counter `ctr = 0`.
///
/// ### 2. Associated data (`head`) – authentication only
/// - `head` is **not encrypted** but is authenticated.
/// - Each 64‑byte chunk is converted to 16 big‑endian `u32` words.
/// - For each chunk, `hash_progress`:
///   - XORs the current hash with the chunk: `hash ^= chunk`.
///   - Applies `wis_process_block` (**4 rounds**) to the hash.
///   - Adds `state_key` (component‑wise addition modulo 2³²).
///
/// ### 3. Payload encryption and authentication (`plaintext`)
/// - Data is split into 64‑byte chunks (last may be shorter).
/// - For each chunk:
///   - **Encryption** (`enc_progress`):
///     - Mixes the counter `ctr` into a copy of `state_key` (XOR into words 14 and 15).
///     - Applies `wis_process_block` with **10 rounds** to generate keystream.
///     - Adds the original `state_key` (addition).
///     - XORs with plaintext → produces ciphertext.
///   - If the last chunk is incomplete, excess bytes in the final word are **zeroed**
///     (`zero_right_bytes_be`) to avoid affecting the hash.
///   - **Authentication** (`hash_progress`): same as for `head`, but now on the
///     **ciphertext** chunk.
///   - `ctr` is incremented by the number of bytes processed.
///
/// ### 4. Lengths are authenticated
/// - A 64‑byte block is constructed containing the lengths of `head` and `plaintext`
///   (each 64 bits, big‑endian).
/// - This block is also passed through `hash_progress`.
///
/// ### 5. Final compression
/// - The 16‑word hash state is split into two halves; the left half is replaced by the
///   XOR of the left and right halves.
/// - The resulting 8 words (256 bits) are converted to a byte array – this is the
///   **authentication tag**.
///
/// ## Features & properties
/// - **In‑place encryption** – the passed `plaintext` slice is mutated into ciphertext.
/// - **Associated data support** – `head` is authenticated but not encrypted.
/// - **Block size** – 64 bytes (16 × 32‑bit words). All internal operations use
///   **big‑endian** byte order.
/// - **Nonce** – 128 bits; affects only the initial key state; the block counter always
///   starts at zero.
/// - **Safe arithmetic** – the code avoids panics from indexing, division, etc., by using
///   `checked_*` and wrapping addition.
/// - **Test harness** – under `#[cfg(test)]` intermediate vectors are stored for
///   verification.
///
/// ## Critical warnings for use
/// - **Never reuse a `(key, nonce)` pair** – this would break security completely
///   (keystream reuse, tag forgery).
/// - **This is not a standard cipher** – no third‑party cryptanalysis has been done.
/// - **Potential panics** – some operations use `EXPCP!` (expect) and may panic if
///   invariants are violated.
/// - **Timing side‑channels** – not hardened; conditional branches may leak information.
/// - **Only 64‑bit total length allowed** – messages longer than `u64::MAX` bytes are
///   rejected.
///
/// # Returns
/// A 256‑bit authentication tag (`[u8; 32]`).
pub fn encrypt(
    head: Option<&[u8]>,
    plaintext: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], &'static str> {
    let mut ctr: u64 = 0;
    let mut state_hash = [0; 16];

    if plaintext.len()
        > checked_cast!(u64::MAX => usize, err "u64::MAX to usize conversion failed")?
    {
        return Err("plaintext.len() > u64::MAX as usize; len() is to big");
    }

    let state_key = wis_key_set(key, nonce);
    state_hash.copy_from_slice(&state_key);

    //hash of head  only
    if let Some(hea) = head {
        process_in_place_no_mut(hea, |block, _, _| {
            hash_progress(block, &state_key, &mut state_hash);
        });
    }

    //enc + hash payload
    process_in_place(plaintext, |block, adder, t| {
        //in test
        #[cfg(test)]
        {
            #![allow(clippy::indexing_slicing)]
            #![allow(clippy::unwrap_used)]
            test_vec_hash().lock().unwrap().clear();
            test_vec_hash_aft().lock().unwrap().clear();
            test_vec_enc().lock().unwrap().clear();
        }

        enc_progress(block, &state_key, ctr);

        if let Some(tt) = t {
            zero_right_bytes_be(block, tt);
        }

        hash_progress(block, &state_key, &mut state_hash);
        //

        ctr = EXPCP!(
            ctr.checked_add(checked_cast!(adder => u64, expect "adder conversion to u64 failed")),
            "counter overflow during addition, if you see this, it means the program is not \
             working correctly, since there should have already been an overflow check in the \
             code before this"
        );
    });

    {
        let mut lens = [0; 16];

        (lens[2], lens[3]) = split_u64_to_u32_be_shift(
            checked_cast!(plaintext.len() =>u64, expect "plaintext.len() =>u64 errs"),
        );

        (lens[0], lens[1]) = split_u64_to_u32_be_shift(
            checked_cast!(head.unwrap_or(&[]).len() =>u64, expect "head.unwrap_or(&[]).len() =>u64 errs"),
        );

        hash_progress(&lens, &state_key, &mut state_hash);
    }

    let hash = hash_mid_xor::<16, 8>(&mut state_hash);

    let mut hash8 = [0u8; 32];

    write_words_to_bytes::<8, 32>(hash, &mut hash8);

    Ok(hash8)
    //Ok(state_hash[])
}

/// # Non‑standard, unverified cipher
/// ## The full description is in the documentation for the [*pub fn encrypt function*].
pub fn decrypt(
    head: Option<&[u8]>,
    plaintext: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], &'static str> {
    let mut ctr: u64 = 0;
    let mut state_hash = [0; 16];

    if plaintext.len()
        > checked_cast!(u64::MAX => usize, err "u64::MAX to usize conversion failed")?
    {
        return Err("plaintext.len() > u64::MAX as usize; len() is to big");
    }

    let state_key = wis_key_set(key, nonce);
    state_hash.copy_from_slice(&state_key);

    //hash of head  only
    if let Some(hea) = head {
        process_in_place_no_mut(hea, |block, _, _| {
            hash_progress(block, &state_key, &mut state_hash);
        });
    }

    process_in_place(plaintext, |block, adder, _| {
        //

        hash_progress(block, &state_key, &mut state_hash);
        enc_progress(block, &state_key, ctr);

        //

        ctr = EXPCP!(
            ctr.checked_add(checked_cast!(adder => u64, expect "adder conversion to u64 failed")),
            "counter overflow during addition, if you see this, it means the program is not \
             working correctly, since there should have already been an overflow check in the \
             code before this"
        );
    });

    //+ len head + len payloag
    {
        let mut lens = [0; 16];

        (lens[2], lens[3]) = split_u64_to_u32_be_shift(
            checked_cast!(plaintext.len() =>u64, expect "plaintext.len() =>u64 errs"),
        );

        (lens[0], lens[1]) = split_u64_to_u32_be_shift(
            checked_cast!(head.unwrap_or(&[]).len() =>u64, expect "head.unwrap_or(&[]).len() =>u64 errs"),
        );

        hash_progress(&lens, &state_key, &mut state_hash);
    }

    let hash = hash_mid_xor::<16, 8>(&mut state_hash);

    let mut hash8 = [0u8; 32];

    write_words_to_bytes::<8, 32>(hash, &mut hash8);

    Ok(hash8)
    //Ok(state_hash[])
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
    let high = checked_cast!(value >> 32 => u32, expect "high part conversion to u32 failed");
    let low = checked_cast!(0xFF_FF_FF_FF&value => u32, expect "low part conversion to u32 failed");
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
fn bytes_to_words<const NU32: usize, const NBYTES: usize>(bytes: &[u8; NBYTES]) -> [u32; NU32] {
    assert_eq!(
        NBYTES,
        NU32.checked_mul(4).expect("overflow in NU32 * 4"),
        "NBYTES must equal NU32 * 4"
    );
    std::array::from_fn(|i| {
        let offset = i.checked_mul(4).expect("overflow in i * 4");
        let end = offset.checked_add(4).expect("overflow in offset + 4");
        // SAFETY: `offset..offset+4` is always within bounds because of the assertion above.
        let chunk: [u8; 4] = bytes[offset..end]
            .try_into()
            .expect("let chunk: [u8; 4] = bytes[offset..offset + 4] if out of range");
        u32::from_be_bytes(chunk)
    })
}
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
    assert_eq!(
        NBYTES,
        NU32.checked_mul(4).expect("overflow in NU32 * 4"),
        "assertion failed: NBYTES == NU32 * 4"
    );

    for (i, &word) in words.iter().enumerate() {
        let offset = i.checked_mul(4).expect("overflow in i * 4");
        let end = offset.checked_add(4).expect("overflow in offset + 4");
        bytes[offset..end].copy_from_slice(&word.to_be_bytes());
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
    assert_eq!(
        NU32OUT,
        NU32.checked_div(2).expect("division by zero in NU32 / 2"),
        "NU32OUT must be half of NU32"
    );

    let (left, right) = state_hash
        .split_at_mut_checked(NU32OUT)
        .expect("split_at_mut_checked mistake");

    // convert the mutable left slice to a mutable array reference
    let left_array: &mut [u32; NU32OUT] = EXPCP!(left.try_into(), "left half length mismatch");
    // convert the mutable right slice to an immutable array reference via a reborrow
    let right_array: &[u32; NU32OUT] = EXPCP!((&*right).try_into(), "right half length mismatch");

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
        let start = data
            .len()
            .checked_sub(full_words)
            .expect("subtraction underflow: data.len() < full_words");
        EXPCP!(data.get_mut(start..), "failed to get mutable range").fill(0);
    }

    // zero partial bytes in the word just before the full ones
    if partial_bytes > 0 {
        let idx = data
            .len()
            .checked_sub(full_words)
            .expect("data.len() >= full_words")
            .checked_sub(1)
            .expect("data.len() - full_words >= 1"); // index of the word to partially zero
        // mask that preserves the high (4 - partial_bytes) bytes and zeros the low partial_bytes
        const PARTIAL_BYTES_MASKS: [u32; 5] = [!0u32, !0xFF, !0xFFFF, !0xFF_FFFF, !0xFFFF_FFFF];

        let mask = *PARTIAL_BYTES_MASKS
            .get(partial_bytes)
            .expect("partial_bytes must be in 0..=4");
        *EXPCP!(data.get_mut(idx), "failed to get mutable byte at index") &= mask;
    }
}

macro_rules! chacha_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(1_6);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b);
        $d ^= $a;
        $d = $d.rotate_left(8);
        $c = $c.wrapping_add($d);
        $b ^= $c;
        $b = $b.rotate_left(7);
    };
}

fn wis_process_block(state: &mut [u32; WORDS_PER_CHUNK], double_rounds: usize) {
    for _ in 0..double_rounds {
        chacha_round!(state[0], state[4], state[8], state[12]); // Column 0
        chacha_round!(state[1], state[5], state[9], state[13]); // Column 1
        chacha_round!(state[2], state[6], state[10], state[14]); // Column 2
        chacha_round!(state[3], state[7], state[11], state[15]); // Column 3

        chacha_round!(state[0], state[5], state[10], state[15]); // Diagonal 1 (main diagonal)
        chacha_round!(state[1], state[6], state[11], state[12]); // Diagonal 2
        chacha_round!(state[2], state[7], state[8], state[13]); // Diagonal 3
        chacha_round!(state[3], state[4], state[9], state[14]); // Diagonal 4
    }
}

/// process_in_place
pub fn process_in_place<F>(data: &mut [u8], mut process: F)
where
    F: FnMut(&mut [u32; WORDS_PER_CHUNK], usize, Option<usize>),
{
    let mut chunks = data.chunks_exact_mut(CHUNK_SIZE);

    for chunk in chunks.by_ref() {
        let chunk_array: &mut [u8; CHUNK_SIZE] = EXPCP!(
            chunk.try_into(),
            "A chunk is always exactly CHUNK_SIZE bytes"
        );
        let mut words = bytes_to_words(chunk_array);
        process(&mut words, CHUNK_SIZE, None);
        write_words_to_bytes(&words, chunk_array);
    }

    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; CHUNK_SIZE];
        EXPCP!(buf.get_mut(..remainder.len()), "failed to get buffer range")
            .copy_from_slice(remainder);

        let mut words = bytes_to_words(&buf);

        let trim = EXPCP!(
            CHUNK_SIZE.checked_sub(remainder.len()),
            "This is an impossible condition, since CHUNK_SIZE must always be greater than \
             remainder"
        );

        process(&mut words, remainder.len(), Some(trim));

        write_words_to_bytes(&words, &mut buf);

        let src = EXPCP!(buf.get(..remainder.len()), "failed to get source range");
        remainder.copy_from_slice(src);
    }
}

/// process_in_place_no_mut
fn process_in_place_no_mut<F>(data: &[u8], mut process: F)
where
    F: FnMut(&[u32; WORDS_PER_CHUNK], usize, Option<usize>),
{
    let mut chunks = data.chunks_exact(CHUNK_SIZE);

    for chunk in chunks.by_ref() {
        let chunk_array: &[u8; CHUNK_SIZE] = EXPCP!(
            chunk.try_into(),
            "A chunk is always exactly CHUNK_SIZE bytes"
        );
        let words = bytes_to_words(chunk_array);
        process(&words, CHUNK_SIZE, None);
    }

    let remainder = chunks.remainder();

    if !remainder.is_empty() {
        let mut buf = [0u8; CHUNK_SIZE];
        EXPCP!(buf.get_mut(..remainder.len()), "failed to get buffer range")
            .copy_from_slice(remainder);

        let words = bytes_to_words(&buf);

        let trim = EXPCP!(
            CHUNK_SIZE.checked_sub(remainder.len()),
            "This is an impossible condition, since CHUNK_SIZE must always be greater than \
             remainder"
        );
        process(&words, remainder.len(), Some(trim));
    }
}

///set key
fn wis_key_set(key8: &[u8; 32], nonce: &[u8; 16]) -> [u32; 16] {
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

    //This is test code; since this is an internal state, it was decided to insert the test
    // directly into the code.
    #[cfg(test)]
    {
        #![allow(clippy::arithmetic_side_effects)]
        #![allow(clippy::integer_division)]
        let op = [
            "nonce 1-4:   ",
            "key 1-4:     ",
            "key 5-8:     ",
            "w 1-2|ct1-2: ",
        ];

        let a = (0..32)
            .map(|x| checked_cast!(x => u8, expect "x conversion to u8 failed"))
            .collect::<Vec<u8>>();
        if key8.eq(a.as_slice()) {
            let ctr2 = split_u64_to_u32_be_shift(0x11_22_33_44_55_66_77_88);
            key_state[14] ^= ctr2.0;
            key_state[15] ^= ctr2.1;
            println!("-------------------");
            println!("WADE KEY STATE:");
            for i in 0..16 {
                if 0 == i % 4 {
                    println!("\n");
                    print!("{:?} | ", EXPCP!(op.get(i / 4), "failed to get op element"));
                }
                print!(
                    "{:08X} | ",
                    EXPCP!(key_state.get(i), "failed to get key_state element")
                );
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
            println!("-------------------");
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

    let mut temp = *key;
    temp[14] ^= ctr2.0;
    temp[15] ^= ctr2.1;

    #[cfg(test)]
    {
        #![allow(clippy::indexing_slicing)]
        #![allow(clippy::unwrap_used)]
        let mut vec = test_vec_enc().lock().unwrap();
        vec.push(plaintext.to_vec());
    }

    wis_process_block(&mut temp, DOUBLE_WIS_CHIP_ROUNDS); //get state
    add_vec::<WORDS_PER_CHUNK>(&mut temp, key); //key + mix
    xor_vec::<u32, WORDS_PER_CHUNK>(plaintext, &temp); // = plaintext ^ (key + mix)
}

fn hash_progress(
    plaintext: &[u32; WORDS_PER_CHUNK],
    key: &[u32; WORDS_PER_CHUNK],
    hash: &mut [u32; WORDS_PER_CHUNK],
) {
    #[cfg(test)]
    {
        #![allow(clippy::indexing_slicing)]
        #![allow(clippy::unwrap_used)]
        let mut vec = test_vec_hash().lock().unwrap();
        vec.push(plaintext.to_vec());
    }

    xor_vec::<u32, WORDS_PER_CHUNK>(hash, plaintext); //  = hash ^ (plaintext ^ (key + mix))
    wis_process_block(hash, DOUBLE_WIS_TAG_ROUNDS); // hash mix
    add_vec::<WORDS_PER_CHUNK>(hash, key); //hash  = key + (hash mix)

    #[cfg(test)]
    {
        #![allow(clippy::indexing_slicing)]
        #![allow(clippy::unwrap_used)]
        let mut vec = test_vec_hash_aft().lock().unwrap();
        vec.push(hash.to_vec());
    }
}

#[cfg(test)]
mod tests_proc {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    //#![allow(clippy::expect_used)]
    #![allow(clippy::unreachable)]
    #![allow(clippy::todo)]
    #![allow(clippy::float_cmp)]
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
    fn identity_mm(_words: &[u32; WORDS_PER_CHUNK], _: usize, _: Option<usize>) {}
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
        #![allow(clippy::arithmetic_side_effects)]
        #![allow(clippy::integer_division)]
        // 3 full chunks (192 bytes)
        let input: Vec<u8> = (0..192).map(|i| i as u8).collect();

        let input_test: Vec<u8> = (0..192).map(|i| ((i / 4) + 1) * 4).collect();

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
    /*
        #[test]
        fn test_usize_usize_as_u64_be_16_bytes() {
            let a = 0xFF_BB_CC_DD_EE_AA_10_09usize;
            let b = 0x08_07_06_05_06_05_03_02usize;

            let exib = [
                0xFF, 0xBB, 0xCC, 0xDD, 0xEE, 0xAA, 0x10, 0x09, 0x08, 0x07, 0x06, 0x05, 0x06, 0x05,
                0x03, 0x02, 0, 0, 0, 0, 0, 0, 0,
            ];

            let mut exib_m = [0; 23];

            usize_usize_as_u64_be_16_bytes(&a, &b, &mut exib_m);

            assert_eq!(exib, exib_m);
        }
    */
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
        let calls1 = Rc::new(RefCell::new(0));
        let calls2 = Rc::new(RefCell::new(0));

        let input: Vec<u8> = (0..192).map(|i| i as u8).collect(); // 3 full chunks
        let mut data1 = input.clone();
        let data2 = input.clone();

        {
            let calls1 = calls1.clone();
            process_in_place(&mut data1, move |_, _, _| {
                *calls1.borrow_mut() += 1;
            });

            let calls2 = calls2.clone();
            process_in_place_no_mut(&data2, move |_, _, _| {
                *calls2.borrow_mut() += 1;
            });
        }

        // Should be called exactly 3 times (once per full chunk).
        assert_eq!(*calls1.borrow(), 3);
        assert_eq!(*calls1.borrow(), *calls2.borrow());
    }

    #[test]
    fn closure_call_count_with_remainder() {
        use std::cell::RefCell;
        use std::rc::Rc;

        for leeen in (0..500).step_by(7) {
            let calls1 = Rc::new(RefCell::new(0));
            let calls2 = Rc::new(RefCell::new(0));

            let calls1_t = Rc::new(RefCell::new(0));
            let calls2_t = Rc::new(RefCell::new(0));

            let calls1_l = Rc::new(RefCell::new(0));
            let calls2_l = Rc::new(RefCell::new(0));
            let input: Vec<u8> = (0..leeen).map(|i| i as u8).collect(); // 1 full chunk + 36 bytes remainder
            let mut data1 = input.clone();
            let data2 = input.clone();
            let mut vee_no_mut = vec![];
            let mut vee_mut = vec![];
            //
            let vee_no_mut_r = &mut vee_no_mut;
            let vee_mut_r = &mut vee_mut;

            {
                let calls1 = calls1.clone();
                let calls1_l = calls1_l.clone();
                let calls1_t = calls1_t.clone();
                process_in_place(&mut data1, move |a, l, t| {
                    if let Some(tt) = t {
                        *calls1_t.borrow_mut() += (*calls1.borrow() + 1) * (tt + 1);
                    }
                    *calls1_l.borrow_mut() += l;
                    vee_mut_r.append(&mut a.to_vec());

                    *calls1.borrow_mut() += 1;
                });
                let calls2 = calls2.clone();
                let calls2_l = calls2_l.clone();
                let calls2_t = calls2_t.clone();
                process_in_place_no_mut(&data2, move |a, l, t| {
                    if let Some(tt) = t {
                        *calls2_t.borrow_mut() += (*calls2.borrow() + 1) * (tt + 1);
                    }

                    *calls2_l.borrow_mut() += l;
                    vee_no_mut_r.append(&mut a.to_vec());

                    *calls2.borrow_mut() += 1;
                });
            }

            assert_eq!(vee_mut, vee_no_mut);
            // Should be called 2 times: one full chunk, then remainder.

            let ctr = (leeen / CHUNK_SIZE) + if leeen % CHUNK_SIZE == 0 { 0 } else { 1 };
            assert_eq!((*calls1.borrow()), ctr);

            assert_eq!(*calls1.borrow(), *calls2.borrow());
            assert_eq!(*calls1_l.borrow(), *calls2_l.borrow());
            assert_eq!(*calls1_t.borrow(), *calls2_t.borrow());

            //println!("{:?}", vee_no_mut);
        }
    }

    #[test]
    fn no_panic_on_any_length() {
        for len in 0..300 {
            let mut data = vec![0u8; len];
            let data1 = vec![0u8; len];
            // Using identity closure should never panic.
            process_in_place(&mut data, identity);

            process_in_place_no_mut(&data1, identity_mm);
        }
    }
}

#[cfg(test)]
mod wdel {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    //#![allow(clippy::expect_used)]
    #![allow(clippy::unreachable)]
    #![allow(clippy::todo)]
    #![allow(clippy::float_cmp)]

    use super::*;

    #[test]
    fn t1_key_set() {
        let k: Vec<u8> = (0..32).map(|x| x as u8).collect();
        let n: Vec<u8> = (0xF0..0xF0 + 16).map(|x| x as u8).collect();
        let te = wis_key_set(&k[..].try_into().unwrap(), &n[..].try_into().unwrap());
        println!("/*MIX:*/ let te_test = [");
        for x in te.iter() {
            print!("0x{:08X} ,", *x);
        }
        println!("];//MIX_end:");

        let te_test = [
            0x1ACEE879, 0xA1CE0F6C, 0x8E892B60, 0x9AE3B2CD, 0x7158920C, 0x38250ABA, 0x54C7A9C2,
            0x63104893, 0xC32B1729, 0xF95D78E8, 0xBDF41CEE, 0xDFAA7F2A, 0x1987F682, 0x98CA9F20,
            0x04F917D3, 0xD0CD2148,
        ];

        assert_eq!(te, te_test);
    }

    #[test]
    fn t2_test_vald() {
        for payloade in [0, 1, 10, CHUNK_SIZE, 100, 211, 777, 999] {
            for heade in [
                None,
                Some(1),
                Some(11),
                Some(CHUNK_SIZE),
                Some(99),
                Some(111),
                Some(1231),
            ] {
                let mut data = vec![0; payloade + heade.unwrap_or(0)];

                for xx in data.iter_mut().enumerate() {
                    *xx.1 = xx.0 as u8;
                }

                let head_pay = data.split_at_mut(heade.unwrap_or(0));

                let head_in: Option<&[u8]> = if heade.is_some() {
                    Some(head_pay.0)
                } else {
                    None
                };

                let key: Vec<u8> = (0..32).map(|_| 0).collect::<Vec<_>>();

                let nonce: Vec<u8> = (0..32).map(|_| 0).collect::<Vec<_>>();

                let x = encrypt(
                    head_in,
                    head_pay.1,
                    key[..32].try_into().unwrap(),
                    nonce[..16].try_into().unwrap(),
                )
                .unwrap();

                println!("HEAD");
                to_hex(head_pay.0);
                println!("PAYOAD");
                to_hex(head_pay.1);
                println!("TAG");
                to_hex(&x);

                let y = decrypt(
                    head_in,
                    head_pay.1,
                    key[..32].try_into().unwrap(),
                    nonce[..16].try_into().unwrap(),
                )
                .unwrap();
                // to_hex(&y);
                // println!();
                // to_hex(&data);

                assert_eq!(y, x);
            }
        }
    }

    #[test]
    fn t3_bad_check() {
        let mut ctrma = 0;

        for yy in (0..200u32).step_by(3) {
            let mut data: Vec<u8> = (0..yy).map(|i| i as u8).collect::<Vec<_>>();

            let key: Vec<u8> = (0..32).map(|i| i + 1).collect::<Vec<_>>();

            let nonce: Vec<u8> = (0..32).map(|i| i + 1).collect::<Vec<_>>();

            let head: Vec<u8> = (0..yy).map(|i| (i / 3) as u8).collect::<Vec<_>>();

            let x = encrypt(
                Some(&head),
                &mut data,
                key[..32].try_into().unwrap(),
                nonce[..16].try_into().unwrap(),
            )
            .unwrap();

            for ii in (0..data.len()).step_by(3) {
                ctrma += ii;
                let mut data2 = data.clone();

                data2[ii] = !data2[ii];

                let y = decrypt(
                    Some(&head),
                    &mut data2,
                    key[..32].try_into().unwrap(),
                    nonce[..16].try_into().unwrap(),
                )
                .unwrap();

                assert_ne!(x, y);
            }

            for ii in (0..head.len()).step_by(3) {
                ctrma += ii;
                let mut head = head.clone();

                head[ii] = !head[ii];

                let y = decrypt(
                    Some(&head),
                    &mut data.clone(),
                    key[..32].try_into().unwrap(),
                    nonce[..16].try_into().unwrap(),
                )
                .unwrap();

                assert_ne!(x, y);
            }

            let y = decrypt(
                Some(&head),
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
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
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
        for x in data.iter_mut().enumerate() {
            *x.1 = x.0 as u32;
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
        for x in data.iter_mut().enumerate() {
            *x.1 = x.0 as u32;
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
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
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
        for x in bytes.iter_mut().enumerate() {
            *x.1 = x.0 as u8;
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
    #![allow(clippy::as_conversions)]
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
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
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
    #![allow(clippy::as_conversions)]
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
    #![allow(clippy::as_conversions)]
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
    #![allow(clippy::as_conversions)]
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
