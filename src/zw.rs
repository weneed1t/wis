use std::ops::BitXor;
const DOUBLE_WIS_INIT_ROUNDS: usize = 4;
const DOUBLE_WIS_CHIP_ROUNDS: usize = 10;
const WIS_STR_INIT_4_BYTES1: u32 = 0x57697327; //"Wis'" in utf8
const WIS_STR_INIT_4_BYTES2: u32 = 0x6164656c; //"adel" in utf8

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
fn wis_32s_to_u8s(input: &[u32], len: usize, output: &mut [u8]) {
    for i in 0..len {
        let bytes = wis_u32_to_bytes!(input[i]);
        let start = wis_shift_left_2!(i);
        output[start..start + 4].copy_from_slice(&bytes);
    }
}

#[inline]
fn wis_u8s_to_u32s(input: &[u8], len: usize, output: &mut [u32]) {
    for i in 0..len {
        let start = wis_shift_left_2!(i);
        let end = start + 4;
        let bytes = &input[start..end];
        output[i] = wis_bytes_to_u32!([bytes[0], bytes[1], bytes[2], bytes[3]]);
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
        $d = $d.rotate_left(16);
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

pub fn wis_process_block(state: &mut [u32; 16], double_rounds: usize) {
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

pub fn wis_key_set(key8: &[u8; 32], nonce: &[u8; 16]) {
    let mut key_state = [0; 16];

    wis_u8s_to_u32s(nonce, 4, &mut key_state[0..4]);
    key_state[12] = WIS_STR_INIT_4_BYTES1;

    key_state[13] = WIS_STR_INIT_4_BYTES2;

    key_state[14] = WIS_STR_INIT_4_BYTES1; //Instead of a counter
    key_state[15] = WIS_STR_INIT_4_BYTES2; //Instead of a counter

    wis_u8s_to_u32s(key8, 8, &mut key_state[4..12]);

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

pub fn _encrypt(key: &[u32; 16], _start_counter: usize, plaintext: &mut [u32; 16]) {
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
    key: &[u32; 16],
    temp: &mut [u32; 16],
    counter: u64,
    plaintext: &mut [u32; 16],
    hash: &mut [u32; 16],
) {
    temp.copy_from_slice(key);
    let ctr2 = split_u64_to_u32_be_shift(counter);

    temp[14] ^= ctr2.0;

    temp[14] ^= ctr2.1;
    wis_process_block(&mut *temp, DOUBLE_WIS_CHIP_ROUNDS);

    add_vec::<16>(temp, key);

    xor_vec::<u32, 16>(temp, plaintext);

    xor_vec::<u32, 16>(hash, plaintext);

    wis_process_block(&mut *hash, DOUBLE_WIS_INIT_ROUNDS);

    add_vec::<16>(hash, key);
}
