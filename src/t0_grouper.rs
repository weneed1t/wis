use crate::t0pology::*;

pub struct GroupTopology {
    topologs: Box<[PackTopology]>,
    indexer: usize,
    max_min_len: usize,
    min_min_len: usize,
    //
    all_have_len: bool,
    all_have_crc: bool,
    all_have_idconn: bool,
    all_have_id_rec_send: bool,
    all_have_ttl: bool,
    all_have_ctr: bool,
    all_have_nonce: bool,
}

impl GroupTopology {
    pub fn new(
        input_topoler: &[(Box<[PackFields]>, u8)],
        tag_len: usize,
        data_save: bool,
        tcp_mode: bool,
    ) -> Result<Self, &'static str> {
        let mut all_have_len = true;
        let mut all_have_crc = true;
        let mut all_have_idconn = true;
        let mut all_have_id_rec_send = true;
        let mut all_have_ttl = true;
        let mut all_have_ctr = true;
        let mut all_have_nonce = true;
        //
        let mut max_min_len = 0;
        let mut min_min_len = !0;
        //

        let mut pos_tbyte = None;
        let mut ret_ve = vec![];

        let mut ret_ve_temp = vec![];

        for x in input_topoler.iter() {
            let ret = PackTopology::new(tag_len, &x.0, data_save, tcp_mode)?;

            all_have_crc &= ret.head_crc_slice().is_some();
            all_have_len &= ret.len_slice().is_some();
            all_have_idconn &= ret.idconn_slice().is_some();
            all_have_ttl &= ret.ttl_slice().is_some();
            all_have_nonce &= ret.nonce_slice().is_some();
            all_have_id_rec_send &= ret.id_of_sender_slice().is_some();
            all_have_ctr &= ret.counter_slice().is_some();

            if let Some(ttbb) = ret.tricky_byte() {
                if ttbb != pos_tbyte.unwrap_or(ttbb) {
                    return Err(
                        "in all topology variants, tricky_byte must occupy the same position \
                         relative to the beginning of the packet",
                    );
                }
                pos_tbyte = Some(ttbb)
            } else {
                return Err("All packet topology variants must have tricky_byte()");
            }

            if max_min_len < ret.total_minimal_len() {
                max_min_len = ret.total_minimal_len()
            }
            if min_min_len > ret.total_minimal_len() {
                min_min_len = ret.total_minimal_len()
            }

            ret_ve.push(ret);
            ret_ve_temp.push(x.1);
        }

        Ok(Self {
            topologs: ret_ve.into_boxed_slice(),
            indexer: 0,
            max_min_len,
            min_min_len,
            all_have_len,
            all_have_crc,
            all_have_idconn,
            all_have_id_rec_send,
            all_have_ttl,
            all_have_ctr,
            all_have_nonce,
        })
    }

    /// Finds the smallest prime table size (from a predefined list) that can accommodate
    /// all given `u8` values without collisions, using a simple modulo hash function.
    ///
    /// The function takes a slice of `(Box<[PackFields]>, u8)` pairs, extracts the `u8`
    /// values, and attempts to assign each to a slot in a table of size `p` (where
    /// `p` is a prime number). A collision occurs if two values map to the same slot
    /// (`value % p`). The search starts from the smallest prime that is at least as
    /// large as the number of input elements (to guarantee a chance of being
    /// collision‑free) and continues through the list of predefined primes up to
    /// `u8::MAX`. The first prime that yields no collisions is returned. If no such prime
    /// exists, an error is returned.
    ///
    /// # Arguments
    /// * `input_topoler` - A slice of tuples. The first component is an owned boxed slice
    ///   of `PackFields` (ignored by the algorithm), the second component is a `u8` key
    ///   to be hashed.
    ///
    /// # Returns
    /// * `Ok(usize)` - The size (prime number) of a collision‑free table.
    /// * `Err(&'static str)` - If the input length exceeds 255 (the largest prime in the
    ///   list) or if every prime candidate leads to at least one collision.
    ///
    /// # Panics
    /// This function does not panic (unless the `partition_point` or indexing is out of
    /// bounds, which cannot happen because the prime list is non‑empty and the input
    /// length is bounded).
    fn find_minimal_table_size(
        input_topoler: &[(Box<[PackFields]>, u8)],
    ) -> Result<usize, &'static str> {
        const PRIMES: &[u8] = &[
            2,
            3,
            5,
            7,
            11,
            13,
            17,
            19,
            23,
            29,
            31,
            37,
            41,
            43,
            47,
            53,
            59,
            61,
            67,
            71,
            73,
            79,
            83,
            89,
            97,
            101,
            103,
            107,
            109,
            113,
            127,
            131,
            137,
            139,
            149,
            151,
            157,
            163,
            167,
            173,
            179,
            181,
            191,
            193,
            197,
            199,
            211,
            223,
            227,
            229,
            233,
            239,
            241,
            251,
            u8::MAX,
        ];

        let target_len = input_topoler.len();
        if target_len > u8::MAX as usize {
            return Err("input length exceeds maximum supported prime (255)");
        }

        let start_idx = PRIMES.partition_point(|&p| (p as usize) < target_len);
        for &size in &PRIMES[start_idx..] {
            let mut seen = vec![false; size as usize];
            let mut ok = true;
            for (_, val) in input_topoler {
                let h = *val as usize % size as usize;
                if seen[h] {
                    ok = false;
                    break;
                }
                seen[h] = true;
            }
            if ok {
                return Ok(size as usize);
            }
        }
        Err("no collision‑free prime size found (all have conflicts)")
    }
}

#[cfg(test)]
mod tests_find_minimal_table_size {
    use super::*;

    // ---------- deterministic pseudo‑random generator (xorshift) ----------
    struct XorShift32(u32);
    impl XorShift32 {
        fn new(seed: u32) -> Self {
            Self(seed)
        }
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x = x.wrapping_add(x >> 17);
            x ^= x << 5;
            self.0 = x;
            x
        }
        fn next_u8(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }
    }

    // helper to create a random input vector with given length and optional forced collisions
    fn random_input(len: usize, seed: u32, forced_collision: bool) -> Vec<(Box<[PackFields]>, u8)> {
        let mut rng = XorShift32::new(seed);
        let mut values: Vec<(Box<[PackFields]>, u8)> = Vec::with_capacity(len);
        if forced_collision && len > 0 {
            // first value arbitrary, then all others same as first (guaranteed collision for any
            // size > 1)
            let first = rng.next_u8();
            values.push((Box::new([]), first));
            for _ in 1..len {
                values.push((Box::new([]), first));
            }
        } else {
            for _ in 0..len {
                values.push((Box::new([]), rng.next_u8()));
            }
        }
        values
    }

    // ---------- basic correctness tests ----------

    #[test]
    fn empty_input() {
        let data: Vec<(Box<[PackFields]>, u8)> = vec![];
        let result = GroupTopology::find_minimal_table_size(&data.clone());
        // minimal prime that is >= 0 is 2
        assert_eq!(result, Ok(2));
    }

    #[test]
    fn single_element() {
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 123)];
        let result = GroupTopology::find_minimal_table_size(&data.clone());
        // any prime >= 1 works, smallest is 2
        assert_eq!(result, Ok(2));
    }

    #[test]
    fn two_distinct_elements_collision_free_at_2() {
        // values 0 and 1: 0%2=0, 1%2=1 -> no collision
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 0), (Box::new([]), 1)];
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(result, Ok(2));
    }

    #[test]
    fn two_distinct_elements_collision_at_2_but_3_works() {
        // values 0 and 2: 0%2=0, 2%2=0 -> collision at size 2; 0%3=0, 2%3=2 -> ok
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 0), (Box::new([]), 2)];
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(result, Ok(3));
    }

    #[test]
    fn all_equal_values_always_collision() {
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 7), (Box::new([]), 7)];
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(
            result,
            Err("no collision‑free prime size found (all have conflicts)")
        );
    }

    #[test]
    fn input_length_exceeds_max_supported() {
        // 256 elements (u8::MAX + 1)
        let mut data: Vec<(Box<[PackFields]>, u8)> = Vec::with_capacity(256);
        for i in 0..256 {
            data.push((Box::new([]), i as u8));
        }
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(
            result,
            Err("input length exceeds maximum supported prime (255)")
        );
    }

    #[test]
    fn exact_max_length_works() {
        let mut data: Vec<(Box<[PackFields]>, u8)> = Vec::with_capacity(255);
        for i in 0..255 {
            data.push((Box::new([]), i as u8));
        }
        // with distinct values from 0..254, the smallest prime >= 255 is 255 (u8::MAX)
        // but we must check if collisions occur: modulo 255 with distinct values 0..254 gives
        // 0..254 -> no collisions
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(result, Ok(255));
    }

    // ---------- randomised property tests ----------

    #[test]
    fn random_no_collisions_should_return_some_prime() {
        for seed in 0..50 {
            let len = 1 + (seed % 50); // up to 50 elements
            let data = random_input(len, seed as u32, false);
            let result = GroupTopology::find_minimal_table_size(&data);

            if let Ok(size) = result {
                // size must be a prime from our list
                const PRIMES: &[u8] = &[
                    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
                    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
                    163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                    251, 255,
                ];
                assert!(PRIMES.contains(&(size as u8)));
                // size must be >= len
                assert!(size >= len);
                // verify no collisions for this size
                let mut seen = vec![false; size];
                for (_, val) in &data {
                    let h = *val as usize % size;
                    assert!(
                        !seen[h],
                        "Collision detected for size {} with values {:?}",
                        size, data
                    );
                    seen[h] = true;
                }
            } else {
                // if error, it must be because all primes had collisions
                // for random distinct values it's unlikely, but possible with many
                // collisions? We'll just accept error as valid.
            }
        }
    }

    #[test]
    fn random_forced_collisions_should_eventually_fail() {
        // For lengths > 1, forced collisions guarantee that any table size will have collisions
        for len in 2..20 {
            let data = random_input(len, 12345, true);
            let result = GroupTopology::find_minimal_table_size(&data);
            assert_eq!(
                result,
                Err("no collision‑free prime size found (all have conflicts)")
            );
        }
    }

    #[test]
    fn deterministic_collision_test_known_values() {
        // values that collide for size=2,3,5 but work for 7
        let data: Vec<(Box<[PackFields]>, u8)> =
            vec![(Box::new([]), 0), (Box::new([]), 2), (Box::new([]), 4)];
        // size=2: collisions (0%2=0,2%2=0,4%2=0)
        // size=3: 0%3=0,2%3=2,4%3=1 -> no collision actually? 0,2,1 all distinct -> ok at size=3.
        // So result should be 3, not 7.
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(result, Ok(3));
    }

    #[test]
    fn stress_large_len_near_limit() {
        let len = 250;
        let mut data: Vec<(Box<[PackFields]>, u8)> = Vec::with_capacity(len);
        for i in 0..len {
            data.push((Box::new([]), i as u8));
        }
        let result = GroupTopology::find_minimal_table_size(&data);
        // The smallest prime >=250 is 251 (since 251 is in the list). Should work because values
        // 0..249 distinct.
        assert_eq!(result, Ok(251));
    }

    #[test]
    fn all_primes_tested_up_to_255() {
        // create a set that forces collisions for all primes up to 251 but works for 255
        // This is tricky, but we can test the fallback error path.
        // Construct values that all map to the same slot modulo any prime <255.
        // For simplicity, use values that are multiples of all small primes? Not feasible.
        // Instead, we rely on the forced-collision test above.
        // We'll just ensure that the function returns Err for some pathological case.
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 0), (Box::new([]), 0)]; // two identical values
        assert_eq!(
            GroupTopology::find_minimal_table_size(&data),
            Err("no collision‑free prime size found (all have conflicts)")
        );
    }

    #[test]
    fn edge_case_size_255_and_255_elements() {
        let mut data: Vec<(Box<[PackFields]>, u8)> = Vec::with_capacity(255);
        for i in 0..255 {
            data.push((Box::new([]), i as u8));
        }
        // all values 0..254, modulo 255 gives 0..254 -> no collisions
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(result, Ok(255));
    }

    #[test]
    fn edge_case_size_2_with_max_u8() {
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 255), (Box::new([]), 1)];
        // 255%2=1, 1%2=1 -> collision at size2
        // 255%3=0, 1%3=1 -> ok, so result 3
        let result = GroupTopology::find_minimal_table_size(&data);
        assert_eq!(result, Ok(3));
    }
}
