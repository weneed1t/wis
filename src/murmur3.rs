//! MurmurHash3 implementation in pure Rust.

#![allow(clippy::unreadable_literal)]
//#![allow(clippy::identity_op)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]

/// 128‑bit x64 version (output as two `u64`).
pub fn murmurhash3_x64_128(key: &[u8], seed: u32) -> [u64; 2] {
    let data = key;
    let len = data.len();
    let nblocks = len / 16;

    let mut h1 = seed as u64;
    let mut h2 = seed as u64;

    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;

    // Body: process 16‑byte blocks in little‑endian order
    let blocks = data.get(..nblocks * 16).expect("'this is not a real state");
    for chunk in blocks.chunks_exact(16) {
        let k1 = u64::from_le_bytes([
            *chunk.first().expect("'this is not a real state"),
            *chunk.get(1).expect("'this is not a real state"),
            *chunk.get(2).expect("'this is not a real state"),
            *chunk.get(3).expect("'this is not a real state"),
            *chunk.get(4).expect("'this is not a real state"),
            *chunk.get(5).expect("'this is not a real state"),
            *chunk.get(6).expect("'this is not a real state"),
            *chunk.get(7).expect("'this is not a real state"),
        ]);
        let k2 = u64::from_le_bytes([
            *chunk.get(8).expect("'this is not a real state"),
            *chunk.get(9).expect("'this is not a real state"),
            *chunk.get(10).expect("'this is not a real state"),
            *chunk.get(11).expect("'this is not a real state"),
            *chunk.get(12).expect("'this is not a real state"),
            *chunk.get(13).expect("'this is not a real state"),
            *chunk.get(14).expect("'this is not a real state"),
            *chunk.get(15).expect("'this is not a real state"),
        ]);

        let k1 = k1.wrapping_mul(C1);
        let k1 = k1.rotate_left(31);
        let k1 = k1.wrapping_mul(C2);
        h1 ^= k1;

        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729);

        let k2 = k2.wrapping_mul(C2);
        let k2 = k2.rotate_left(33);
        let k2 = k2.wrapping_mul(C1);
        h2 ^= k2;

        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
    }

    // Tail: handle remaining 1‑15 bytes with fallthrough behaviour
    let tail = data.get(nblocks * 16..).expect("'this is not a real state");
    let rem = len & 15;

    let mut k1 = 0u64;
    let mut k2 = 0u64;

    // k2 (bytes 8‑15)
    if rem >= 15 {
        k2 ^= (*tail.get(14).expect("'this is not a real state") as u64) << 48;
    }
    if rem >= 14 {
        k2 ^= (*tail.get(13).expect("'this is not a real state") as u64) << 40;
    }
    if rem >= 13 {
        k2 ^= (*tail.get(12).expect("'this is not a real state") as u64) << 32;
    }
    if rem >= 12 {
        k2 ^= (*tail.get(11).expect("'this is not a real state") as u64) << 24;
    }
    if rem >= 11 {
        k2 ^= (*tail.get(10).expect("'this is not a real state") as u64) << 16;
    }
    if rem >= 10 {
        k2 ^= (*tail.get(9).expect("'this is not a real state") as u64) << 8;
    }
    if rem >= 9 {
        k2 ^= *tail.get(8).expect("'this is not a real state") as u64;
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
    }
    // k1 (bytes 0‑7)
    if rem >= 8 {
        k1 ^= (*tail.get(7).expect("'this is not a real state") as u64) << 56;
    }
    if rem >= 7 {
        k1 ^= (*tail.get(6).expect("'this is not a real state") as u64) << 48;
    }
    if rem >= 6 {
        k1 ^= (*tail.get(5).expect("'this is not a real state") as u64) << 40;
    }
    if rem >= 5 {
        k1 ^= (*tail.get(4).expect("'this is not a real state") as u64) << 32;
    }
    if rem >= 4 {
        k1 ^= (*tail.get(3).expect("'this is not a real state") as u64) << 24;
    }
    if rem >= 3 {
        k1 ^= (*tail.get(2).expect("'this is not a real state") as u64) << 16;
    }
    if rem >= 2 {
        k1 ^= (*tail.get(1).expect("'this is not a real state") as u64) << 8;
    }
    if rem >= 1 {
        k1 ^= *tail.first().expect("'this is not a real state") as u64;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    // Finalization
    h1 ^= len as u64;
    h2 ^= len as u64;

    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    [h1.swap_bytes(), h2.swap_bytes()]
}
// -----------------------------------------------------------------------------
// Helper functions (inline for performance)
// -----------------------------------------------------------------------------
#[inline(always)]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    k
}

// -----------------------------------------------------------------------------
// Tests (matches known vectors from the original C++ version)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x64_128() {
        let data = b"";
        let h = murmurhash3_x64_128(data, 0);
        assert_eq!(h, [0, 0]);

        let data = b"The quick brown fox jumps over";
        let h = murmurhash3_x64_128(data, 0);

        assert_eq!(h, [0x5d_6a_1c_6f_e0_74_ac_89, 0x03_bf_8e_0c_89_71_d2_4d]);

        let data = b"One day, a bald guy walked into a barber shop, and the barber asked him, 'Dude, have you lost your mind?'";
        let h = murmurhash3_x64_128(data, 111222333);
        assert_eq!(h, [0xcd09ca6b9708ba18, 0x90a95616b0eba379]);
    }
}
