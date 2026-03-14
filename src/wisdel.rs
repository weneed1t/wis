use std::ops::BitXor;

const CHUNK_SIZE: usize = 64;
const WORDS_PER_CHUNK: usize = CHUNK_SIZE / 4;

const DOUBLE_WIS_INIT_ROUNDS: usize = 4;
const DOUBLE_WIS_TAG_ROUNDS: usize = 4;
const DOUBLE_WIS_CHIP_ROUNDS: usize = 10;
const WIS_STR_INIT_4_BYTES1: u32 = 0x57697327; //"Wis'" in utf8
const WIS_STR_INIT_4_BYTES2: u32 = 0x61_64656c; //"adel" in utf8

//===============================================================

fn split_u64_to_u32_be_shift(value: u64) -> (u32, u32) {
    let high = (value >> 32) as u32;
    let low = value as u32;
    (high, low)
}
//===============================================================

#[inline]
fn bytes_to_words<const NU32: usize, const NBYTES: usize>(bytes: &[u8; NBYTES]) -> [u32; NU32] {
    assert_eq!(NBYTES, NU32 * 4);
    std::array::from_fn(|i| {
        let offset = i * 4;
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    })
}
#[inline]
fn write_words_to_bytes<const NU32: usize, const NBYTES: usize>(
    words: &[u32; NU32],
    bytes: &mut [u8; NBYTES],
) {
    assert_eq!(NBYTES, NU32 * 4);

    for (i, &word) in words.iter().enumerate() {
        let offset = i * 4;
        bytes[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
}

fn add_vec<const N: usize>(v1: &mut [u32; N], v2: &[u32; N]) {
    v1.iter_mut()
        .zip(v2.iter())
        .for_each(|(a, b)| *a = a.wrapping_add(*b));
}

fn xor_vec<T, const N: usize>(v1: &mut [T; N], v2: &[T; N])
where
    T: Copy + BitXor<Output = T>,
{
    v1.iter_mut().zip(v2.iter()).for_each(|(a, b)| *a = *a ^ *b);
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
    F: FnMut(&mut [u32; WORDS_PER_CHUNK], usize),
{
    let mut chunks = data.chunks_exact_mut(CHUNK_SIZE);

    for chunk in chunks.by_ref() {
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk
            .try_into()
            .expect("A chunk is always exactly CHUNK_SIZE bytes");
        let mut words = bytes_to_words(chunk_array);
        process(&mut words, CHUNK_SIZE);
        write_words_to_bytes(&words, chunk_array);
    }

    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; CHUNK_SIZE];
        buf[..remainder.len()].copy_from_slice(remainder);

        let mut words = bytes_to_words(&buf);
        process(&mut words, remainder.len());
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
        }
    }
    //
    //

    wis_process_block(&mut key_state, DOUBLE_WIS_INIT_ROUNDS); //init

    key_state
}

fn enc(
    plaintext: &mut [u32; WORDS_PER_CHUNK],
    key: &[u32; WORDS_PER_CHUNK],
    hash: &mut [u32; WORDS_PER_CHUNK],
    counter: u64,
) {
    let mut temp = [0; WORDS_PER_CHUNK];

    let ctr2 = split_u64_to_u32_be_shift(counter);

    temp.copy_from_slice(key);
    temp[14] ^= ctr2.0;
    temp[15] ^= ctr2.1;

    wis_process_block(&mut temp, DOUBLE_WIS_CHIP_ROUNDS); //get state

    add_vec::<WORDS_PER_CHUNK>(&mut temp, key); //key + mix

    xor_vec::<u32, WORDS_PER_CHUNK>(plaintext, &temp); // = plaintext ^ (key + mix)

    xor_vec::<u32, WORDS_PER_CHUNK>(hash, plaintext); //  = hash ^ (plaintext ^ (key + mix))

    wis_process_block(hash, DOUBLE_WIS_TAG_ROUNDS); // hash mix

    add_vec::<WORDS_PER_CHUNK>(hash, key); //hash  = key + (hash mix)
}

pub fn encrypt(
    plaintext: &mut [u8],
    key: &[u8; 32],
    nonce: &[u8; 16],
) -> Result<[u8; 32], &'static str> {
    let mut ctr = 0;
    let mut state_hash = [0; 16];

    if plaintext.len() > u64::MAX as usize {
        return Err("plaintext.len() > u64::MAX as usize; len() is to big");
    }

    let state_key = wis_key_set(key, nonce);
    state_hash.copy_from_slice(&state_key);

    process_in_place(plaintext, |block, adder| {
        enc(block, &state_key, &mut state_hash, ctr);
        ctr = ctr.checked_add(adder as u64).expect(
            "counter overflow during addition, if you see this, it means the program is not \
             working correctly, since there should have already been an overflow check in the \
             code before this",
        );
    });

    let one_two_side_hash = state_hash.split_at_mut(16);

    xor_vec::<u32, 16>(
        &mut one_two_side_hash
            .0
            .try_into()
            .expect("impossible program state, lengths must be constant equal to 16"),
        &one_two_side_hash
            .1
            .try_into()
            .expect("impossible program state, lengths must be constant equal to 16"),
    );

    //let exi_hash = write_words_to_bytes(words, bytes);

    Err("")
    //Ok(state_hash[])
}

#[cfg(test)]
mod tests {

    use super::*;

    // Helper to convert a slice of u32 to little‑endian bytes.
    fn u32s_to_le_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|&w| w.to_le_bytes()).collect()
    }
    fn u32s_to_be_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|&w| w.to_be_bytes()).collect()
    }

    // Identity transformation: does nothing.
    fn identity(_words: &mut [u32; WORDS_PER_CHUNK], _: usize) {}

    // Adds 1 to each u32.
    fn add_one(words: &mut [u32; WORDS_PER_CHUNK], _: usize) {
        for w in words.iter_mut() {
            *w = w.wrapping_add(0x01_01_01_01);
        }
    }
    fn add_ottf(words: &mut [u32; WORDS_PER_CHUNK], _: usize) {
        for w in words.iter_mut() {
            *w = w.wrapping_add(0x04_03_02_01);
        }
    }

    // Bitwise NOT.
    fn bitwise_not(words: &mut [u32; WORDS_PER_CHUNK], _: usize) {
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
        add_one(&mut words, 1);
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

        //println!("{:?}", ds);
        //return;

        // Compute expected chunk by chunk.
        let mut expected = Vec::with_capacity(192);
        for chunk_start in (0..192).step_by(64) {
            let mut words = [0u32; WORDS_PER_CHUNK];
            for (i, word) in words.iter_mut().enumerate() {
                let offset = chunk_start + i * 4;
                *word = u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap());
            }
            add_ottf(&mut words, 1);
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
        bitwise_not(&mut words_full, 1);
        expected.extend(u32s_to_le_bytes(&words_full));

        // Remainder: pad to 64 bytes with zeros.
        let mut padded = [0u8; 64];
        padded[..32].copy_from_slice(&input[64..96]);

        let mut words_rem = [0u32; WORDS_PER_CHUNK];
        for (i, word) in words_rem.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(padded[offset..offset + 4].try_into().unwrap());
        }
        bitwise_not(&mut words_rem, 1);
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
        add_one(&mut words, 1);
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
            process_in_place(&mut data, move |_, _| {
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
            process_in_place(&mut data, move |_, _| {
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
    /*
    DEPRECATED TEST!!!  NI USE!
    #[test]
    fn multiple_chunks_check_be_endian() {
        // 3 full chunks (192 bytes)
        let mut input: Vec<u8> = (0..192).map(|i| i as u8).collect();

        let mut t2: Vec<u8> = (0..13).map(|i| 0 as u8).collect();
        let mut input1: Vec<u8> = (0..70).map(|i| i as u8).collect();

        let mut input2: Vec<u8> = (70..99).map(|i| i as u8).collect();

        let mut input3: Vec<u8> = (99..192).map(|i| i as u8).collect();
        process_in_place(&mut t2, add_ottf);
        process_in_place(&mut input1, add_ottf);
        process_in_place(&mut input2, add_ottf);
        process_in_place(&mut input3, add_ottf);
        process_in_place(&mut input, add_ottf);

        let mut he2 = vec![];
        he2.append(&mut input1);
        he2.append(&mut input2);
        he2.append(&mut input3);

        assert_eq!(he2.len(), input.len());

        for (i, (x, y)) in he2.iter().zip(input.iter()).enumerate() {
            println!("{i:>3} | {:>3} {:>3}  {:>3} ", *x, *y, *y == *x);
        }

        assert_eq!(he2, input);

        println!("{:?}", t2);
        println!("{:?}", input1);
        println!("{:?}", input2);
        println!("{:?}", input3);
        println!("{:?}", input);

        return;
    }

    */
}

#[cfg(test)]
mod wdel {
    use super::*;

    #[test]
    fn t1() {
        let k: Vec<u8> = (0..32).map(|x| x as u8).collect();
        let n: Vec<u8> = (0xF0..0xF0 + 16).map(|x| x as u8).collect();
        wis_key_set(&k[..].try_into().expect(""), &n[..].try_into().expect(""));
    }

    #[test]
    fn t2() {
        let k: Vec<u8> = (0..32).map(|x| x as u8).collect();
        let n: Vec<u8> = (0xF0..0xF0 + 16).map(|x| x as u8).collect();
        wis_key_set(&k[..].try_into().expect(""), &n[..].try_into().expect(""));
    }
}
