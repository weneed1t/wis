use std::ops::BitXor;

const CHUNK_SIZE: usize = 64;
const WORDS_PER_CHUNK: usize = CHUNK_SIZE / 4;

const DOUBLE_WIS_INIT_ROUNDS: usize = 4;
const DOUBLE_WIS_TAG_ROUNDS: usize = 4;
const DOUBLE_WIS_CHIP_ROUNDS: usize = 10;
const WIS_STR_INIT_4_BYTES1: u32 = 0x57697327; //"Wis'" in utf8
const WIS_STR_INIT_4_BYTES2: u32 = 0x61_64656c; //"adel" in utf8

macro_rules! wis_shift_left_2 {
    // aka x * 4
    ($x:expr) => {{ $x << 2 }};
}

macro_rules! wis_shift_left_6 {
    // aka x * 64
    ($x:expr) => {{ $x << 6 }};
}
//be careful! , when using on big-endian change the function to_be_bytes() and
// from_le_bytes(...)
//===============================================================

macro_rules! wis_u32_to_bytes {
    ($value:expr) => {{ $value.to_be_bytes() }};
}

macro_rules! wis_bytes_to_u32 {
    ($bytes:expr) => {{ u32::from_be_bytes($bytes) }};
}

fn split_u64_to_u32_be_shift(value: u64) -> (u32, u32) {
    let high = (value >> 32) as u32;
    let low = value as u32;
    (high.to_be(), low.to_be())
}
//===============================================================

#[inline]
fn bytes_to_words(bytes: &[u8; CHUNK_SIZE]) -> [u32; WORDS_PER_CHUNK] {
    std::array::from_fn(|i| {
        let offset = i * 4;
        u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("диапазон всегда ровно 4 байта"),
        )
    })
}

#[inline]
fn write_words_to_bytes(words: &[u32; WORDS_PER_CHUNK], bytes: &mut [u8; CHUNK_SIZE]) {
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

pub fn wis_key_set(_key8: &[u8; 32], _nonce: &[u8; WORDS_PER_CHUNK]) {
    let mut key_state = [0; WORDS_PER_CHUNK];

    ///////// wis_u8s_to_u32s(nonce, 4, &mut key_state[0..4]);
    key_state[12] = WIS_STR_INIT_4_BYTES1;

    key_state[13] = WIS_STR_INIT_4_BYTES2;

    key_state[14] = WIS_STR_INIT_4_BYTES1; //Instead of a counter
    key_state[15] = WIS_STR_INIT_4_BYTES2; //Instead of a counter

    /////// wis_u8s_to_u32s(key8, 8, &mut key_state[4..12]);

    //wis_process_block(&mut key_state, DOUBLE_WIS_INIT_ROUNDS); //init

    let mut adder: u32 = 0;

    for x in key_state[0..15].iter() {
        adder = adder.wrapping_add(*x);
        adder = adder.rotate_left(3);
    }
    if 0 == adder {
        adder = 1;
    }

    println!();
}

pub fn _encrypt(
    key: &[u32; WORDS_PER_CHUNK],
    _start_counter: usize,
    plaintext: &mut [u32; WORDS_PER_CHUNK],
) {
    let stream = [0; 64];
    let plaintext_len: usize = plaintext.len();
    let round_bloks: usize = plaintext_len / plaintext_len;
    let _tail_p = plaintext_len % 64;

    for mut index in 0..round_bloks {
        index = wis_shift_left_6!(index);

        let _steam_32 = *key;

        //wis_process_block(&mut steam_32, 21);

        for (ptb, s) in plaintext[index..index + 64].iter_mut().zip(stream.iter()) {
            *ptb ^= *s;
        }

        //+=1
    }
}

pub fn _1encrypt(
    key: &[u32; WORDS_PER_CHUNK],
    temp: &mut [u32; WORDS_PER_CHUNK],
    counter: u64,
    plaintext: &mut [u32; WORDS_PER_CHUNK],
    hash: &mut [u32; WORDS_PER_CHUNK],
) {
    temp.copy_from_slice(key);
    let ctr2 = split_u64_to_u32_be_shift(counter);

    temp[14] ^= ctr2.0;
    temp[15] ^= ctr2.1;

    wis_process_block(temp, DOUBLE_WIS_CHIP_ROUNDS); //get state

    add_vec::<WORDS_PER_CHUNK>(temp, key); //key + mix

    xor_vec::<u32, WORDS_PER_CHUNK>(temp, plaintext); // enc

    xor_vec::<u32, WORDS_PER_CHUNK>(hash, plaintext); // enc xor temp hash

    wis_process_block(hash, DOUBLE_WIS_TAG_ROUNDS); // progress hash 

    add_vec::<WORDS_PER_CHUNK>(hash, key); //hash add key 
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
    F: FnMut(&mut [u32; WORDS_PER_CHUNK]),
{
    let mut chunks = data.chunks_exact_mut(CHUNK_SIZE);

    for chunk in chunks.by_ref() {
        let chunk_array: &mut [u8; CHUNK_SIZE] = chunk
            .try_into()
            .expect("A chunk is always exactly CHUNK_SIZE bytes");
        let mut words = bytes_to_words(chunk_array);
        process(&mut words);
        write_words_to_bytes(&words, chunk_array);
    }

    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; CHUNK_SIZE];
        buf[..remainder.len()].copy_from_slice(remainder);

        let mut words = bytes_to_words(&buf);
        process(&mut words);
        write_words_to_bytes(&words, &mut buf);

        remainder.copy_from_slice(&buf[..remainder.len()]);
    }
}

pub struct WisDel {
    key: [u32; WORDS_PER_CHUNK],
    counter: u64,
    hash: [u32; WORDS_PER_CHUNK],
}

impl WisDel {
    fn enc(&mut self, plaintext: &mut [u32; WORDS_PER_CHUNK]) {
        let mut temp = [0; WORDS_PER_CHUNK];

        let ctr2 = split_u64_to_u32_be_shift(self.counter);

        temp.copy_from_slice(&self.key);
        temp[14] ^= ctr2.0;
        temp[15] ^= ctr2.1;

        wis_process_block(&mut temp, DOUBLE_WIS_CHIP_ROUNDS); //get state

        add_vec::<WORDS_PER_CHUNK>(&mut temp, &self.key); //key + mix

        xor_vec::<u32, WORDS_PER_CHUNK>(plaintext, &temp); // enc

        xor_vec::<u32, WORDS_PER_CHUNK>(&mut self.hash, plaintext); // enc xor temp hash

        wis_process_block(&mut self.hash, DOUBLE_WIS_TAG_ROUNDS); // progress hash 

        add_vec::<WORDS_PER_CHUNK>(&mut self.hash, &self.key); //hash add key 

        self.counter = self.counter.checked_add(1).expect(
            "counter overflow That's not possible because there should be an overflow check in \
             the code before that! If you see this, it means someone has messed up the code!",
        );
    }

    pub fn encrypt(&mut self, plaintext: &mut [u8]) -> Result<(), &'static str> {
        let _ = self
            .counter
            .checked_add(
                (if plaintext.len() > u64::MAX as usize {
                    return Err("plaintext.len() > u64::MAX as usize; len() is to big");
                } else {
                    plaintext.len() as u64
                } / 64)
                    .checked_add(1) //+1 because / 64 doesn't take the remainder into account
                    .ok_or("1221")?,
            )
            .ok_or("21")?;

        process_in_place(plaintext, |block| self.enc(block));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to convert a slice of u32 to little‑endian bytes.
    fn u32s_to_le_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|&w| w.to_le_bytes()).collect()
    }

    // Identity transformation: does nothing.
    fn identity(_words: &mut [u32; WORDS_PER_CHUNK]) {}

    // Adds 1 to each u32.
    fn add_one(words: &mut [u32; WORDS_PER_CHUNK]) {
        for w in words.iter_mut() {
            *w = w.wrapping_add(0x01_01_01_01);
        }
    }

    // Bitwise NOT.
    fn bitwise_not(words: &mut [u32; WORDS_PER_CHUNK]) {
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
        add_one(&mut words);
        let expected = u32s_to_le_bytes(&words);

        assert_eq!(data, expected);
    }

    #[test]
    fn multiple_chunks() {
        // 3 full chunks (192 bytes)
        let input: Vec<u8> = (0..192).map(|i| i as u8).collect();
        let mut data = input.clone();

        process_in_place(&mut data, add_one);

        // Compute expected chunk by chunk.
        let mut expected = Vec::with_capacity(192);
        for chunk_start in (0..192).step_by(64) {
            let mut words = [0u32; WORDS_PER_CHUNK];
            for (i, word) in words.iter_mut().enumerate() {
                let offset = chunk_start + i * 4;
                *word = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap());
            }
            add_one(&mut words);
            expected.extend(u32s_to_le_bytes(&words));
        }

        assert_eq!(data, expected);
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
        bitwise_not(&mut words_full);
        expected.extend(u32s_to_le_bytes(&words_full));

        // Remainder: pad to 64 bytes with zeros.
        let mut padded = [0u8; 64];
        padded[..32].copy_from_slice(&input[64..96]);

        let mut words_rem = [0u32; WORDS_PER_CHUNK];
        for (i, word) in words_rem.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(padded[offset..offset + 4].try_into().unwrap());
        }
        bitwise_not(&mut words_rem);
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
        add_one(&mut words);
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
            process_in_place(&mut data, move |_| {
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
            process_in_place(&mut data, move |_| {
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
    fn no_panic_on_any_length() {
        let mut a = vec![0; 1024];

        let mut enc = WisDel {
            key: [0; 16],
            counter: 00,
            hash: [0; 16],
        };

        enc.encrypt(&mut a[..]).unwrap();

        println!("{:?}", a);
    }
}
