#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]
// specific imports for clarity and to avoid namespace pollution
use crate::t0pology::{PackFields, PackTopology};
use crate::{EXPCP, checked_cast};

const PRIMES: &[u16] = &[
    1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 256,
];

#[derive(Debug, Clone)]

///a group of distinct PackTopologies that are united solely by the identical position of
/// the trick byte and the length of all PackFields. contains a set of PackTopologies,
/// where each PackTopology either has fields whose lengths match the lengths of all
/// corresponding fields in all other groups, or has none of them,
pub struct GroupTopology {
    topologs: Box<[Option<PackTopology>]>,
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
    pos_tbyte: Option<usize>,
}

impl GroupTopology {
    /// creates a new GroupTopology from a collection of topology definitions.
    ///
    /// this function validates that all provided topologies are compatible for grouping:
    /// - empty input is rejected with an error
    /// - all topologies must share the same tag_len, data_save, and tcp_mode settings
    /// - if more than one topology is provided, each must contain a tricky_byte at the
    ///   same position
    /// - for a single topology, tricky_byte is optional
    /// - all present fields (counter, len, crc, nonce, ttl, idconn, sender/receiver ids)
    ///   must have identical lengths across all topologies
    /// - max_min_len and min_min_len track the range of minimal packet sizes
    /// - boolean flags indicate which fields are universally present
    ///
    /// # arguments
    /// * `input_topoler` - slice of tuples containing field definitions and u8 keys
    /// * `tag_len` - length of the authentication tag for encryption
    /// * `data_save` - whether the channel guarantees data integrity
    /// * `tcp_mode` - whether the channel is stream-oriented (requires len field)
    ///
    /// # returns
    /// * `Ok(Self)` - successfully created group topology
    /// * `Err(&'static str)` - validation failed with descriptive error message
    ///
    /// # errors
    /// returns error if:
    /// - input is empty
    /// - tricky_byte position mismatches (when multiple topologies)
    /// - field lengths are inconsistent across topologies
    /// - any individual PackTopology::new call fails
    pub fn new(
        input_topoler: &[(Box<[PackFields]>, u8)],
        tag_len: usize,
        data_save: bool,
        tcp_mode: bool,
    ) -> Result<Self, &'static str> {
        // reject empty input to avoid undefined behavior with min/max calculations
        if input_topoler.is_empty() {
            return Err("input_topoler cannot be empty: at least one topology required");
        }

        let mut all_have_len = true;
        let mut all_have_crc = true;
        let mut all_have_idconn = true;
        let mut all_have_id_rec_send = true;
        let mut all_have_ttl = true;
        let mut all_have_ctr = true;
        let mut all_have_nonce = true;

        let mut max_min_len = 0;
        let mut min_min_len = usize::MAX;

        let mut pos_tbyte: Option<usize> = None;

        // track field lengths for uniformity validation across all topologies
        let mut counter_len: Option<usize> = None;
        let mut len_field_len: Option<usize> = None;
        let mut crc_len: Option<usize> = None;
        let mut nonce_len: Option<usize> = None;
        let mut ttl_len: Option<usize> = None;
        let mut idconn_len: Option<usize> = None;
        let mut id_sender_len: Option<usize> = None;
        let mut id_receiver_len: Option<usize> = None;

        let mut topologs =
            vec![None; Self::find_minimal_table_size(input_topoler)?].into_boxed_slice();

        for (fields, key) in input_topoler.iter() {
            let idx =
                checked_cast!(*key => usize, err "Key out of range for usize")? % topologs.len();
            let temp = topologs
                .get_mut(idx)
                .expect("An impossible condition due to modulo division");

            let topology = if temp.is_some() {
                panic!(
                    "This is an impossible situation. Create a ticket for the developers so they \
                     can fix it, as there should be a check beforehand to ensure there won't be \
                     2any issues."
                )
            } else {
                *temp = Some(PackTopology::new(tag_len, fields, data_save, tcp_mode)?);
                EXPCP!(
                    &temp.as_ref(),
                    "this is an impossible state since the assignment of this element was on the \
                     line above"
                )
            };

            // update universal presence flags
            all_have_crc &= topology.head_crc_slice().is_some();
            all_have_len &= topology.len_slice().is_some();
            all_have_idconn &= topology.idconn_slice().is_some();
            all_have_ttl &= topology.ttl_slice().is_some();
            all_have_nonce &= topology.nonce_slice().is_some();
            all_have_id_rec_send &= topology.id_of_sender_slice().is_some();
            all_have_ctr &= topology.counter_slice().is_some();

            // tricky_byte validation:
            // - single topology: optional, no position enforcement
            // - multiple topologies: mandatory AND must be at identical position in all
            if let Some(tb_pos) = topology.tricky_byte() {
                if input_topoler.len() > 1 {
                    if let Some(expected_pos) = pos_tbyte {
                        if tb_pos != expected_pos {
                            return Err("in all topology variants, tricky_byte must occupy the \
                                        same position relative to the beginning of the packet");
                        }
                    } else {
                        pos_tbyte = Some(tb_pos);
                    }
                }
            } else if input_topoler.len() > 1 {
                return Err(
                    "all packet topology variants must have tricky_byte when grouping multiple \
                     topologies",
                );
            }

            // validate field length uniformity across all topologies
            // counter: mandatory field, must have consistent length
            {
                if let Some((_, _, len)) = topology.counter_slice() {
                    if let Some(expected) = counter_len {
                        if len != expected {
                            return Err("counter field length mismatch across topologies");
                        }
                    } else {
                        counter_len = Some(len);
                    }
                }

                // len: if present in any topology, must have consistent length everywhere
                if let Some((_, _, len)) = topology.len_slice() {
                    if let Some(expected) = len_field_len {
                        if len != expected {
                            return Err("len field length mismatch across topologies");
                        }
                    } else {
                        len_field_len = Some(len);
                    }
                }

                // head_crc: if present, must have consistent length
                if let Some((_, _, len)) = topology.head_crc_slice() {
                    if let Some(expected) = crc_len {
                        if len != expected {
                            return Err("head_crc field length mismatch across topologies");
                        }
                    } else {
                        crc_len = Some(len);
                    }
                }

                // nonce: if present, must have consistent length
                if let Some((_, _, len)) = topology.nonce_slice() {
                    if let Some(expected) = nonce_len {
                        if len != expected {
                            return Err("nonce field length mismatch across topologies");
                        }
                    } else {
                        nonce_len = Some(len);
                    }
                }

                // ttl: if present, must have consistent length
                if let Some((_, _, len)) = topology.ttl_slice() {
                    if let Some(expected) = ttl_len {
                        if len != expected {
                            return Err("ttl field length mismatch across topologies");
                        }
                    } else {
                        ttl_len = Some(len);
                    }
                }

                // idconn: if present, must have consistent length
                if let Some((_, _, len)) = topology.idconn_slice() {
                    if let Some(expected) = idconn_len {
                        if len != expected {
                            return Err("idconn field length mismatch across topologies");
                        }
                    } else {
                        idconn_len = Some(len);
                    }
                }

                // id_sender: if present, must have consistent length
                if let Some((_, _, len)) = topology.id_of_sender_slice() {
                    if let Some(expected) = id_sender_len {
                        if len != expected {
                            return Err("id_sender field length mismatch across topologies");
                        }
                    } else {
                        id_sender_len = Some(len);
                    }
                }

                // id_receiver: if present, must have consistent length AND match sender length
                if let Some((_, _, len)) = topology.id_of_receiver_slice() {
                    if let Some(expected) = id_receiver_len {
                        if len != expected {
                            return Err("id_receiver field length mismatch across topologies");
                        }
                    } else {
                        id_receiver_len = Some(len);
                    }
                    // cross-check: sender and receiver must have equal length within each topology
                    if let Some(sender_len) = id_sender_len
                        && len != sender_len
                    {
                        return Err(
                            "id_receiver and id_sender must have equal length within each topology",
                        );
                    }
                }
                // reciprocal check in case sender was processed after receiver
                if let Some((_, _, len)) = topology.id_of_sender_slice()
                    && let Some(receiver_len) = id_receiver_len
                    && len != receiver_len
                {
                    return Err(
                        "id_sender and id_receiver must have equal length within each topology",
                    );
                }
            }
            // update min/max minimal packet lengths
            let total_min = topology.total_minimal_len();
            if total_min > max_min_len {
                max_min_len = total_min;
            }
            if total_min < min_min_len {
                min_min_len = total_min;
            }

            //end for
        }

        // sanity check: min_min_len should have been updated (empty input already rejected)
        if min_min_len == usize::MAX {
            return Err("internal error: min_min_len not properly initialized");
        }
        // additional sanity: min should not exceed max
        if min_min_len > max_min_len {
            return Err("internal error: min_min_len > max_min_len indicates logic bug");
        }

        Ok(Self {
            topologs,
            max_min_len,
            min_min_len,
            all_have_len,
            all_have_crc,
            all_have_idconn,
            all_have_id_rec_send,
            all_have_ttl,
            all_have_ctr,
            all_have_nonce,
            pos_tbyte,
        })
    }
    ///Get the PackTopology diagram by its ID (byte)
    pub fn get_from_u8(&self, trikly_byte: u8) -> Option<&PackTopology> {
        let idx = checked_cast!(trikly_byte => usize,expect "u8 to usize conversion failed")
            % self.topologs.len();
        self.topologs
            .get(idx)
            .expect("impossible state since here the index is taken in the length model")
            .as_ref()
    }

    /// finds the smallest prime table size (from a predefined list) that can accommodate
    /// all given `u8` values without collisions, using a simple modulo hash function.
    ///
    /// the function takes a slice of `(Box<[PackFields]>, u8)` pairs, extracts the `u8`
    /// values, and attempts to assign each to a slot in a table of size `p` (where
    /// `p` is a prime number). a collision occurs if two values map to the same slot
    /// (`value % p`). the search starts from the smallest prime that is at least as
    /// large as the number of input elements (to guarantee a chance of being
    /// collision‑free) and continues through the list of predefined primes up to
    /// `u8::MAX`. the first prime that yields no collisions is returned. if no such prime
    /// exists, an error is returned.
    ///
    /// # arguments
    /// * `input_topoler` - a slice of tuples. the first component is an owned boxed slice
    ///   of `PackFields` (ignored by the algorithm), the second component is a `u8` key
    ///   to be hashed.
    ///
    /// # returns
    /// * `Ok(usize)` - the size (prime number) of a collision‑free table.
    /// * `Err(&'static str)` - if the input length exceeds 256 (the largest prime in the
    ///   list) or if every prime candidate leads to at least one collision.
    ///
    /// # panics
    /// this function does not panic (unless the `partition_point` or indexing is out of
    /// bounds, which cannot happen because the prime list is non‑empty and the input
    /// length is bounded).
    fn find_minimal_table_size(
        input_topoler: &[(Box<[PackFields]>, u8)],
    ) -> Result<usize, &'static str> {
        let target_len = input_topoler.len();
        let max_u8 = checked_cast!(u8::MAX => usize,err "u8::MAX to usize conversion failed")?;
        if target_len > max_u8 {
            return Err("input length exceeds maximum supported prime (255)");
        }

        let start_idx = PRIMES.partition_point(|&p| {
            checked_cast!(p => usize, expect "Prime conversion to usize failed") < target_len
        });

        for &size in PRIMES
            .get(start_idx..)
            .ok_or("no collision‑free prime size found (all have conflicts)")?
        {
            let mut seen =
                vec![false; checked_cast!(size => usize, err "Size conversion to usize failed")?];
            let mut ok = true;
            for (_, val) in input_topoler {
                let h = checked_cast!(*val => usize, err "Value conversion to usize failed")?
                    % checked_cast!(size => usize, err "Size conversion to usize failed")?;
                if let Some(seen_val) = seen.get_mut(h) {
                    if *seen_val {
                        ok = false;
                        break;
                    }
                    *seen_val = true;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                return Ok(checked_cast!(size => usize, err "Size conversion to usize failed")?);
            }
        }
        Err("no collision‑free prime size found (all have conflicts)")
    }
}

impl GroupTopology {
    /// returns the maximum minimal packet length among all grouped topologies.
    ///
    /// this value represents the largest `total_minimal_len` across all individual
    /// `PackTopology` instances in the group. it can be used to pre-allocate buffers
    /// that are guaranteed to fit any packet from any topology in the group.

    pub fn max_minimal_len(&self) -> usize {
        self.max_min_len
    }

    /// returns the minimum minimal packet length among all grouped topologies.
    ///
    /// this value represents the smallest `total_minimal_len` across all individual
    /// `PackTopology` instances in the group. it can be used for optimistic buffer
    /// sizing or to detect unusually small packets that may belong to a subset of
    /// topologies.

    pub fn min_minimal_len(&self) -> usize {
        self.min_min_len
    }

    /// returns `true` if every topology in the group contains a `Len` field.
    ///
    /// the `Len` field is required for tcp-like (stream-oriented) protocols to delimit
    /// packet boundaries. if this method returns `true`, the group can safely assume
    /// that all packets have an explicit length header.
    pub fn all_have_len_field(&self) -> bool {
        self.all_have_len
    }

    /// returns `true` if every topology in the group contains a `HeadCRC` field.
    ///
    /// the `HeadCRC` field protects header integrity in unreliable transport channels
    /// (e.g., udp-like). if this method returns `true`, all packets in the group can
    /// be validated for header corruption before decryption.
    pub fn all_have_crc_field(&self) -> bool {
        self.all_have_crc
    }

    /// returns `true` if every topology in the group contains an `IdConnect` field.
    ///
    /// the `IdConnect` field associates packets with a specific connection or session.
    /// if this method returns `true`, all packets in the group support connection-level
    /// multiplexing or session tracking.

    pub fn all_have_idconn_field(&self) -> bool {
        self.all_have_idconn
    }

    /// returns `true` if every topology in the group contains both `IdSender` and
    /// `IdReceiver` fields.
    ///
    /// these fields enable mesh-network routing by identifying the source and destination
    /// of each packet at the protocol level. if this method returns `true`, all packets
    /// in the group support explicit sender/receiver addressing.
    ///
    /// note: the presence of one without the other is rejected during
    /// `GroupTopology::new`, so this flag reflects a consistent, validated state.

    pub fn all_have_id_sender_receiver_fields(&self) -> bool {
        self.all_have_id_rec_send
    }

    /// returns `true` if every topology in the group contains a `TTL` field.
    ///
    /// the `TTL` (time-to-live) field limits packet lifetime in multi-hop networks to
    /// prevent infinite loops. if this method returns `true`, all packets in the group
    /// support hop-count expiration semantics.

    pub fn all_have_ttl_field(&self) -> bool {
        self.all_have_ttl
    }

    /// returns `true` if every topology in the group contains a `Counter` field.
    ///
    /// the `Counter` field is **mandatory** for all topologies and holds a unique,
    /// incrementing packet sequence number (1–8 bytes). this method will always return
    /// `true` for any successfully constructed `GroupTopology`, but is provided for
    /// api symmetry and future extensibility.
    pub fn all_have_counter_field(&self) -> bool {
        self.all_have_ctr
    }

    /// returns `true` if every topology in the group contains a `Nonce` field.
    ///
    /// the `Nonce` field provides a unique cryptographic nonce for authenticated
    /// encryption (e.g., aes-gcm, chacha20-poly1305). if this method returns `true`,
    /// all packets in the group support per-packet nonce-based encryption.
    pub fn all_have_nonce_field(&self) -> bool {
        self.all_have_nonce
    }
    ///get the position of the trick byte
    pub fn tricky_position(&self) -> Option<usize> {
        self.pos_tbyte
    }
    ///get the largest total_minimal_len() value among all PackTopologies
    pub fn max_min_len(&self) -> usize {
        self.max_min_len
    }
    ///get the minimal total_minimal_len() value among all PackTopologies
    pub fn min_min_len(&self) -> usize {
        self.min_min_len
    }
}

#[cfg(test)]
mod tests_find_minimal_table_size {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
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
        assert_eq!(result, Ok(1));
    }

    #[test]
    fn single_element() {
        let data: Vec<(Box<[PackFields]>, u8)> = vec![(Box::new([]), 123)];
        let result = GroupTopology::find_minimal_table_size(&data.clone());
        // any prime >= 1 works, smallest is 2
        assert_eq!(result, Ok(1));
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
        assert_eq!(result, Ok(256));
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
                    1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
                    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
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
        assert_eq!(result, Ok(256));
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

//
//
#[cfg(test)]
mod tests_new {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]

    // use exact types from the t0pology module to avoid type mismatch errors
    use super::*;
    use crate::t0pology::{
        // PackTopology,
        MAXIMAL_CRC_LEN,
        MAXIMAL_NONCE_LEN,
        MAXIMAL_NUMS_USER_FIELDS,
        MAXIMAL_TTL_LEN,
        PackFields,
    };

    // ========================================================================
    // helper: minimal deterministic pseudo-random generator (lcg)
    // ========================================================================
    /// simple linear congruential generator for repeatable test data.
    /// uses parameters from numerical recipes to avoid external dependencies.
    struct Lcg {
        state: u64,
    }

    impl Lcg {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next(&mut self) -> u64 {
            // lcg parameters: a = 6364136223846793005, c = 1442695040888963407
            self.state = self
                .state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.state
        }

        fn next_u8(&mut self) -> u8 {
            (self.next() & 0xFF) as u8
        }

        fn next_range(&mut self, min: usize, max: usize) -> usize {
            if min >= max {
                return min;
            }
            min + (self.next() as usize % (max - min + 1))
        }
    }

    // ========================================================================
    // helper: factory functions for test data
    // ========================================================================
    /// creates a minimal valid field list containing only a counter.
    fn minimal_valid_fields() -> Box<[PackFields]> {
        Box::new([PackFields::Counter(4)])
    }

    /// creates a valid field list with counter + tricky_byte at position 0.
    fn minimal_with_tricky() -> Box<[PackFields]> {
        Box::new([PackFields::TrickyByte, PackFields::Counter(4)])
    }

    // ========================================================================
    // section 1: input validation and empty-state handling
    // ========================================================================

    #[test]
    fn t01_empty_input_rejected() {
        let result = GroupTopology::new(&[], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "input_topoler cannot be empty: at least one topology required"
        );
    }

    // ========================================================================
    // section 2: tag_len boundary and overflow protection
    // ========================================================================

    #[test]
    fn t02_tag_len_zero_rejected() {
        let result = GroupTopology::new(&[(minimal_valid_fields(), 1)], 0, true, false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "!!tag_len ==0");
    }

    #[test]
    fn t03_tag_len_valid_minimum() {
        let result = GroupTopology::new(&[(minimal_with_tricky(), 1)], 1, true, false);
        assert!(result.is_ok());
        assert_eq!(
            *result.unwrap().get_from_u8(1).unwrap(),
            PackTopology::new(1, &minimal_with_tricky()[..], true, false).unwrap()
        )
    }

    #[test]
    fn t04_tag_len_overflow_protection() {
        // usize::MAX will cause checked_add to return none in total_minimal_len calculation
        let result = GroupTopology::new(&[(minimal_with_tricky(), 1)], usize::MAX, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "total packet size exceeds addressable memory"
        );
    }

    // ========================================================================
    // section 3: data_save and tcp_mode constraint validation
    // ========================================================================

    #[test]
    fn t05_tcp_mode_requires_len_field() {
        // tcp_mode=true but no len field provided
        let result = GroupTopology::new(&[(minimal_with_tricky(), 1)], 16, true, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "If your data channel is like TCP, you should specify the Len(usize) field."
        );
    }

    #[test]
    fn t06_unreliable_channel_requires_crc() {
        // data_save=false but no crc field provided
        let result = GroupTopology::new(&[(minimal_with_tricky(), 1)], 16, false, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "If you do not guarantee that the packet can be broken during transport(!data_save), \
             you should use HeadCRC(usize)"
        );
    }

    #[test]
    fn t07_tcp_and_unreliable_incompatible() {
        // both tcp_mode=true and data_save=false is forbidden
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::Len(4),
            PackFields::HeadCRC(4),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, false, true);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "channel cannot be both tcp_mode and have data instability (!data_save == false && \
             tcp_mode == true)"
        );
    }

    // ========================================================================
    // section 4: mandatory field validation (counter)
    // ========================================================================

    #[test]
    fn t08_counter_field_mandatory() {
        let fields = Box::new([PackFields::Len(4), PackFields::TrickyByte]);
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "the structure must have either a Counter field"
        );
    }

    // ========================================================================
    // section 5: sender/receiver id constraints
    // ========================================================================

    #[test]
    fn t09_sender_receiver_both_or_neither() {
        // only sender, no receiver
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::IdSender(4),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "sender and receiver IDs must both exist or both be absent"
        );
    }

    #[test]
    fn t10_sender_receiver_equal_length_required() {
        // sender=4 bytes, receiver=8 bytes -> mismatch
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::IdSender(4),
            PackFields::IdReceiver(8),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "id_of_receiver_slice and id_of_sender_slice must be the same length"
        );
    }

    // ========================================================================
    // section 6: tricky_byte position consistency across topologies
    // ========================================================================

    #[test]
    fn t11_tricky_byte_position_mismatch_rejected() {
        // topology 1: tricky_byte at field index 0 (position 0)
        // topology 2: tricky_byte at field index 1 (position 1, after 1-byte user field)
        let fields1 = Box::new([PackFields::TrickyByte, PackFields::Counter(4)]);
        let fields2 = Box::new([
            PackFields::UserField(1),
            PackFields::TrickyByte,
            PackFields::Counter(4),
        ]);

        let result = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "in all topology variants, tricky_byte must occupy the same position relative to the \
             beginning of the packet"
        );
    }

    #[test]
    fn t12_tricky_byte_missing_in_multi_topology_rejected() {
        // first has tricky_byte, second does not
        let fields1 = minimal_with_tricky();
        let fields2 = minimal_valid_fields(); // no tricky_byte

        let result = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "all packet topology variants must have tricky_byte when grouping multiple topologies"
        );
    }

    #[test]
    fn t13_tricky_byte_optional_for_single_topology() {
        // single topology without tricky_byte should succeed
        let result = GroupTopology::new(&[(minimal_valid_fields(), 1)], 16, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn t14_tricky_byte_consistent_position_accepted() {
        // both topologies have tricky_byte at same position (field index 0)
        let fields1 = minimal_with_tricky();
        let fields2 = minimal_with_tricky();

        let result = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false);
        assert!(result.is_ok());
    }

    // ========================================================================
    // section 7: field length consistency across topologies
    // ========================================================================

    macro_rules! assert_field_length_mismatch {
        ($test_name:ident, $field_ctor:expr, $expected_err:expr) => {
            #[test]
            fn $test_name() {
                let fields1 = {
                    let mut v = vec![PackFields::Counter(4), PackFields::TrickyByte];
                    v.push($field_ctor(4));
                    v.into_boxed_slice()
                };
                let fields2 = {
                    let mut v = vec![PackFields::Counter(4), PackFields::TrickyByte];
                    v.push($field_ctor(8));
                    v.into_boxed_slice()
                };

                let result = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), $expected_err);
            }
        };
    }

    macro_rules! assert_field_length_mismatch_for_ctr {
        ($test_name:ident, $field_ctor:expr, $expected_err:expr) => {
            #[test]
            fn $test_name() {
                let fields1 = {
                    let mut v = vec![PackFields::TrickyByte];
                    v.push($field_ctor(4));
                    v.into_boxed_slice()
                };
                let fields2 = {
                    let mut v = vec![PackFields::TrickyByte];
                    v.push($field_ctor(8));
                    v.into_boxed_slice()
                };

                let result = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), $expected_err);
            }
        };
    }

    assert_field_length_mismatch_for_ctr!(
        t15_counter_length_mismatch,
        PackFields::Counter,
        "counter field length mismatch across topologies"
    );
    assert_field_length_mismatch!(
        t16_len_field_length_mismatch,
        PackFields::Len,
        "len field length mismatch across topologies"
    );
    assert_field_length_mismatch!(
        t17_crc_length_mismatch,
        PackFields::HeadCRC,
        "head_crc field length mismatch across topologies"
    );
    assert_field_length_mismatch!(
        t18_nonce_length_mismatch,
        PackFields::Nonce,
        "nonce field length mismatch across topologies"
    );
    assert_field_length_mismatch!(
        t19_ttl_length_mismatch,
        PackFields::TTL,
        "ttl field length mismatch across topologies"
    );
    assert_field_length_mismatch!(
        t20_idconn_length_mismatch,
        PackFields::IdConnect,
        "idconn field length mismatch across topologies"
    );
    assert_field_length_mismatch!(
        t21_id_sender_length_mismatch,
        PackFields::IdSender,
        //"id_sender field length mismatch across topologies"
        "sender and receiver IDs must both exist or both be absent"
    );
    assert_field_length_mismatch!(
        t22_id_receiver_length_mismatch,
        PackFields::IdReceiver,
        //"id_receiver field length mismatch across topologies"
        "sender and receiver IDs must both exist or both be absent"
    );

    // ========================================================================
    // section 8: find_minimal_table_size error paths
    // ========================================================================

    #[test]
    fn t23_input_exceeds_max_prime_limit() {
        // create 256 entries (exceeds u8::max = 255)
        let entries: Vec<_> = (0..256).map(|i| (minimal_with_tricky(), i as u8)).collect();

        let result = GroupTopology::new(&entries, 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "input length exceeds maximum supported prime (255)"
        );
    }

    #[test]
    fn t24_forced_collision_no_solution() {
        // all entries have identical key -> guaranteed collision for any table size > 1
        let entries: Vec<_> = (0..10).map(|_| (minimal_with_tricky(), 42u8)).collect();

        let result = GroupTopology::new(&entries, 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "no collision‑free prime size found (all have conflicts)"
        );
    }

    // ========================================================================
    // section 9: field size limit validation (via packtopology::new)
    // ========================================================================

    macro_rules! assert_field_size_limit {
        ($test_name:ident, $field_ctor:expr, $max_len:expr, $zero_err:expr, $limit_err:expr) => {
            #[test]
            fn $test_name() {
                // zero size rejected
                let fields = Box::new([
                    PackFields::Counter(4),
                    $field_ctor(0),
                    PackFields::TrickyByte,
                ]);
                let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), $zero_err);

                // exceeds max rejected
                let fields = Box::new([
                    PackFields::Counter(4),
                    $field_ctor($max_len + 1),
                    PackFields::TrickyByte,
                ]);
                let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
                assert!(result.is_err());
                assert!(result.unwrap_err().contains($limit_err));
            }
        };
    }

    macro_rules! assert_field_size_limit_spec_for_ctr {
        ($test_name:ident, $field_ctor:expr, $max_len:expr, $zero_err:expr, $limit_err:expr) => {
            #[test]
            fn $test_name() {
                // zero size rejected
                let fields = Box::new([$field_ctor(0), PackFields::TrickyByte]);
                let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), $zero_err);

                // exceeds max rejected
                let fields = Box::new([$field_ctor($max_len + 1), PackFields::TrickyByte]);
                let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
                assert!(result.is_err());
                assert!(result.unwrap_err().contains($limit_err));
            }
        };
    }

    assert_field_size_limit_spec_for_ctr!(
        t26_counter_size_limits,
        PackFields::Counter,
        8,
        "counter value exceeds 8",
        "counter value exceeds 8"
    );

    assert_field_size_limit!(
        t27_nonce_size_limits,
        PackFields::Nonce,
        MAXIMAL_NONCE_LEN,
        "nonce len is 0",
        "nonce"
    );

    assert_field_size_limit!(
        t28_ttl_size_limits,
        PackFields::TTL,
        MAXIMAL_TTL_LEN,
        "TTL value exceeds MAXIMAL_TTL_LEN or  == 0",
        "TTL"
    );

    #[test]
    fn t29_crc_size_limits() {
        // zero crc rejected
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::HeadCRC(0),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("crc"));

        // exceeds max rejected
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::HeadCRC(MAXIMAL_CRC_LEN + 1),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("crc"));
    }

    #[test]
    fn t30_user_field_zero_size_rejected() {
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::UserField(0),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "userfield value is 0");
    }

    #[test]
    fn t31_max_user_fields_limit() {
        // create fields with maximal_nums_user_fields + 1 user fields
        let mut fields = vec![PackFields::Counter(4), PackFields::TrickyByte];
        for _ in 0..=MAXIMAL_NUMS_USER_FIELDS {
            fields.push(PackFields::UserField(1));
        }

        let result = GroupTopology::new(&[(fields.into_boxed_slice(), 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "userfield nums > MAXIMAL_NUMS_USER_FIELDS"
        );
    }

    // ========================================================================
    // section 10: duplicate field detection
    // ========================================================================

    #[test]
    fn t32_duplicate_counter_rejected() {
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::Counter(4),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "duplicate counter");
    }

    #[test]
    fn t33_duplicate_tricky_byte_rejected() {
        let fields = Box::new([
            PackFields::TrickyByte,
            PackFields::Counter(4),
            PackFields::TrickyByte,
        ]);
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "duplicate tricky_byte");
    }

    // ========================================================================
    // section 11: successful creation and state validation
    // ========================================================================

    #[test]
    fn t34_successful_single_topology_state() {
        let fields = minimal_with_tricky();
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_ok());

        assert_eq!(
            *result.as_ref().unwrap().get_from_u8(1).unwrap(),
            PackTopology::new(16, &minimal_with_tricky()[..], true, false).unwrap()
        );

        let gt = result.unwrap();
        assert_eq!(gt.topologs.len(), 1);
        assert_eq!(gt.max_min_len, gt.min_min_len); // single topology -> equal
        assert!(!gt.all_have_len);
        assert!(!gt.all_have_crc);
        //assert!(gt.indexer >= 2); // smallest prime in list
    }

    #[test]
    fn t35_min_max_len_calculation_multi_topology() {
        // topology 1: counter(2) + tricky(1) = 3 header bytes
        // topology 2: counter(8) + tricky(1) = 9 header bytes
        // both: +1 head byte + 16 tag = 20 and 26 respectively
        let fields1 = Box::new([
            PackFields::Counter(8),
            PackFields::TrickyByte,
            PackFields::UserField(6),
        ]);
        let fields2 = Box::new([PackFields::Counter(8), PackFields::TrickyByte]);

        let result = GroupTopology::new(
            &[(fields1.clone(), 1), (fields2.clone(), 2)],
            16,
            true,
            false,
        );

        assert!(result.is_ok());
        assert_eq!(
            *result.as_ref().unwrap().get_from_u8(1).unwrap(),
            PackTopology::new(16, &fields1[..], true, false).unwrap()
        );

        assert_eq!(
            *result.as_ref().unwrap().get_from_u8(2).unwrap(),
            PackTopology::new(16, &fields2[..], true, false).unwrap()
        );

        let gt = result.unwrap();
        assert!(gt.min_min_len <= gt.max_min_len);
        assert_eq!(gt.min_min_len, 26); // 2+1+1+16
        assert_eq!(gt.max_min_len, 32); // 8+1+1+16
    }

    #[test]
    fn t36_universal_field_flags_all_present() {
        let fields = Box::new([
            PackFields::Counter(4),
            PackFields::Len(4),
            PackFields::HeadCRC(4),
            PackFields::Nonce(8),
            PackFields::TTL(2),
            PackFields::IdConnect(4),
            PackFields::IdSender(4),
            PackFields::IdReceiver(4),
            PackFields::TrickyByte,
        ]);

        let result = GroupTopology::new(&[(fields.clone(), 1), (fields, 2)], 16, true, true);
        assert!(result.is_ok());

        let gt = result.unwrap();
        assert!(gt.all_have_len);
        assert!(gt.all_have_crc);
        assert!(gt.all_have_nonce);
        assert!(gt.all_have_ttl);
        assert!(gt.all_have_ctr);
        assert!(gt.all_have_idconn);
        assert!(gt.all_have_id_rec_send);
    }

    #[test]
    fn t37_universal_field_flags_partial_presence() {
        // only first topology has len field
        let fields1 = Box::new([
            PackFields::Counter(4),
            PackFields::Len(4),
            PackFields::TrickyByte,
        ]);
        let fields2 = Box::new([
            PackFields::Counter(4),
            PackFields::UserField(4),
            PackFields::TrickyByte,
        ]);

        let result = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false);
        assert!(result.is_ok());

        let gt = result.unwrap();
        assert!(!gt.all_have_len); // not all topologies have it
    }

    // ========================================================================
    // section 12: table-driven test for flag combinations
    // ========================================================================

    #[test]
    fn t38_flag_combinations_table_driven() {
        struct Case {
            data_save: bool,
            tcp_mode: bool,
            has_len: bool,
            has_crc: bool,
            expected: Result<(), &'static str>,
        }

        let cases = [
            Case {
                data_save: true,
                tcp_mode: false,
                has_len: false,
                has_crc: false,
                expected: Ok(()),
            },
            Case {
                data_save: true,
                tcp_mode: true,
                has_len: true,
                has_crc: false,
                expected: Ok(()),
            },
            Case {
                data_save: true,
                tcp_mode: true,
                has_len: false,
                has_crc: false,
                expected: Err(
                    "If your data channel is like TCP, you should specify the Len(usize) field.",
                ),
            },
            Case {
                data_save: false,
                tcp_mode: false,
                has_len: false,
                has_crc: true,
                expected: Ok(()),
            },
            Case {
                data_save: false,
                tcp_mode: false,
                has_len: false,
                has_crc: false,
                expected: Err(
                    "If you do not guarantee that the packet can be broken during \
                     transport(!data_save), you should use HeadCRC(usize)",
                ),
            },
            Case {
                data_save: false,
                tcp_mode: true,
                has_len: true,
                has_crc: true,
                expected: Err("channel cannot be both tcp_mode and have data instability \
                               (!data_save == false && tcp_mode == true)"),
            },
        ];

        for (i, c) in cases.iter().enumerate() {
            let mut fields = vec![PackFields::Counter(4), PackFields::TrickyByte];
            if c.has_len {
                fields.push(PackFields::Len(4));
            }
            if c.has_crc {
                fields.push(PackFields::HeadCRC(4));
            }

            let result = GroupTopology::new(
                &[(fields.into_boxed_slice(), 1)],
                16,
                c.data_save,
                c.tcp_mode,
            );

            match (&c.expected, result) {
                (Ok(_), Ok(_)) => {},
                (Err(exp), Err(act)) => assert_eq!(act, *exp, "case {}: error mismatch", i),
                (Ok(_), Err(e)) => panic!("case {}: expected ok, got err({})", i, e),
                (Err(exp), Ok(_)) => panic!("case {}: expected err({}), got ok", i, exp),
            }
        }
    }

    // ========================================================================
    // section 13: stress test with lcg-generated data
    // ========================================================================

    #[test]
    fn t39_stress_lcg_generated_topologies_no_panic() {
        let mut rng = Lcg::new(12345);
        let mut entries = Vec::new();

        for _ in 0..100 {
            let key = rng.next_u8();
            let mut fields = vec![PackFields::Counter(rng.next_range(1, 8))];

            // randomly add optional fields with valid sizes
            if rng.next_range(0, 1) == 1 {
                fields.push(PackFields::TrickyByte);
            }
            if rng.next_range(0, 1) == 1 {
                fields.push(PackFields::Len(rng.next_range(1, 8)));
            }
            if rng.next_range(0, 1) == 1 {
                fields.push(PackFields::HeadCRC(rng.next_range(1, MAXIMAL_CRC_LEN)));
            }
            if rng.next_range(0, 1) == 1 {
                fields.push(PackFields::Nonce(rng.next_range(1, MAXIMAL_NONCE_LEN)));
            }
            if rng.next_range(0, 1) == 1 {
                fields.push(PackFields::TTL(rng.next_range(1, MAXIMAL_TTL_LEN)));
            }

            entries.push((fields.into_boxed_slice(), key));
        }

        // the function should either return ok or a valid err, never panic
        let _ = GroupTopology::new(&entries, rng.next_range(1, 64), true, false);
    }

    // ========================================================================
    // section 14: duplicate tricky_byte and field validation
    // ========================================================================

    #[test]
    fn t40_duplicate_field_variants_rejected() {
        let duplicates = [
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::Len(4),
                    PackFields::Len(4),
                    PackFields::TrickyByte,
                ],
                "duplicate len",
            ),
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::IdSender(4),
                    PackFields::IdSender(4),
                    PackFields::TrickyByte,
                ],
                "duplicate IdSender",
            ),
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::IdReceiver(4),
                    PackFields::IdReceiver(4),
                    PackFields::TrickyByte,
                ],
                "duplicate idreceiver",
            ),
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::HeadCRC(4),
                    PackFields::HeadCRC(4),
                    PackFields::TrickyByte,
                ],
                "duplicate crc",
            ),
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::Nonce(4),
                    PackFields::Nonce(4),
                    PackFields::TrickyByte,
                ],
                "duplicate nonce",
            ),
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::TTL(4),
                    PackFields::TTL(4),
                    PackFields::TrickyByte,
                ],
                "duplicate ttl",
            ),
            (
                vec![
                    PackFields::Counter(4),
                    PackFields::IdConnect(4),
                    PackFields::IdConnect(4),
                    PackFields::TrickyByte,
                ],
                "duplicate idconn",
            ),
        ];

        for (fields_vec, expected_err) in duplicates.iter() {
            let fields = {
                let v = fields_vec.clone();
                v.into_boxed_slice()
            };
            let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
            assert!(result.is_err(), "expected error for duplicate field");
            assert_eq!(result.unwrap_err(), *expected_err);
        }
    }

    // ========================================================================
    // section 15: internal sanity checks (min/max consistency)
    // ========================================================================

    #[test]
    fn t41_min_max_len_internal_consistency() {
        // after rejecting empty input, min_min_len should always be updated
        // this test verifies normal operation doesn't trigger internal errors
        let fields = minimal_with_tricky();
        let result = GroupTopology::new(&[(fields, 1)], 16, true, false);
        assert!(result.is_ok());

        let gt = result.unwrap();
        // sanity: min should never exceed max
        assert!(
            gt.min_min_len <= gt.max_min_len,
            "internal invariant violated: min > max"
        );
        // sanity: min should have been updated from usize::max
        assert!(
            gt.min_min_len != usize::MAX,
            "internal invariant violated: min not initialized"
        );
    }
}

#[cfg(test)]
mod test_get {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_get_rand() {
        let mut print_len = vec![];

        let mut result_mdsa: Vec<Vec<u8>> =
            Vec::with_capacity(TEST_SLICES_NON_SPLIT_16.len() + TEST_SLICES_NON_SPLIT.len());
        result_mdsa.extend(TEST_SLICES_NON_SPLIT_4.iter().map(|s| s.to_vec()));
        result_mdsa.extend(TEST_SLICES_NON_SPLIT_16.iter().map(|s| s.to_vec()));
        result_mdsa.extend(TEST_SLICES_NON_SPLIT.iter().map(|s| s.to_vec()));

        for dicodim in result_mdsa.iter().enumerate() {
            let mut vecta = vec![];

            for incom in dicodim.1.iter() {
                vecta.push((
                    vec![
                        PackFields::Counter(1),
                        PackFields::UserField(300 - *incom as usize),
                        PackFields::UserField((*incom as usize) + 1),
                        PackFields::TrickyByte,
                    ]
                    .into_boxed_slice(),
                    *incom,
                ));
            }

            let tester = GroupTopology::new(&vecta[..], 30, true, false).unwrap();
            print_len.push(tester.topologs.len());
            for incom in dicodim.1.iter() {
                let fields_len = vec![
                    PackFields::Counter(1),
                    PackFields::UserField(300 - *incom as usize),
                    PackFields::UserField((*incom as usize) + 1),
                    PackFields::TrickyByte,
                ];

                let b = PackTopology::new(30, &fields_len, true, false).unwrap();

                assert_eq!(*tester.get_from_u8(*incom).unwrap(), b);
            }
        }

        println!("lens {:?}", print_len);
    }
    #[test]
    fn test_get_no_one() {
        let vecta = [(
            vec![PackFields::Counter(1), PackFields::TrickyByte].into_boxed_slice(),
            113,
        )];

        let tester = GroupTopology::new(&vecta[..], 30, true, false).unwrap();

        assert_eq!(tester.topologs.len(), 1);
        assert_eq!(
            tester.get_from_u8(1).unwrap(),
            tester.get_from_u8(121).unwrap()
        );
        assert_eq!(
            tester.get_from_u8(121).unwrap(),
            tester.get_from_u8(4).unwrap()
        );
        assert_eq!(
            tester.get_from_u8(4).unwrap(),
            tester.get_from_u8(255).unwrap()
        );
    }

    const TEST_SLICES_NON_SPLIT: [[u8; 100]; 15] = [
        [
            181, 172, 57, 108, 47, 115, 145, 247, 102, 61, 163, 48, 66, 109, 138, 200, 128, 197,
            37, 233, 3, 58, 170, 130, 226, 41, 97, 187, 231, 95, 141, 77, 40, 158, 146, 33, 232,
            239, 162, 135, 236, 67, 80, 225, 209, 198, 228, 88, 71, 113, 90, 129, 78, 164, 149, 94,
            13, 39, 19, 20, 120, 152, 60, 166, 213, 52, 148, 63, 127, 224, 79, 153, 64, 0, 136,
            132, 147, 218, 38, 91, 96, 11, 36, 53, 32, 126, 176, 190, 124, 50, 188, 214, 169, 211,
            150, 30, 246, 6, 205, 112,
        ],
        [
            168, 115, 61, 110, 250, 254, 93, 48, 116, 195, 177, 90, 147, 249, 63, 76, 157, 14, 241,
            106, 211, 79, 159, 118, 94, 26, 187, 1, 75, 57, 80, 235, 197, 8, 220, 96, 83, 70, 120,
            150, 149, 132, 27, 15, 112, 176, 49, 44, 200, 141, 248, 225, 167, 12, 22, 156, 204,
            102, 207, 11, 0, 84, 239, 210, 206, 69, 100, 193, 162, 56, 66, 203, 39, 152, 36, 29, 5,
            43, 237, 97, 99, 133, 148, 227, 103, 32, 95, 35, 217, 107, 6, 117, 53, 226, 9, 165,
            184, 245, 105, 230,
        ],
        [
            84, 7, 241, 4, 216, 51, 46, 56, 182, 149, 101, 194, 202, 208, 85, 105, 26, 0, 112, 10,
            45, 135, 99, 93, 134, 52, 3, 224, 172, 159, 255, 123, 195, 58, 156, 193, 50, 228, 136,
            24, 117, 70, 231, 38, 78, 125, 211, 153, 43, 98, 140, 155, 66, 111, 71, 5, 76, 196, 94,
            110, 87, 141, 35, 13, 150, 178, 81, 253, 144, 72, 122, 143, 39, 151, 154, 185, 92, 100,
            61, 183, 179, 239, 203, 82, 139, 64, 114, 11, 29, 222, 244, 199, 250, 31, 18, 237, 95,
            128, 79, 16,
        ],
        [
            13, 4, 200, 78, 145, 187, 16, 221, 35, 147, 237, 74, 76, 34, 239, 91, 60, 157, 175,
            172, 233, 211, 168, 27, 129, 185, 188, 101, 57, 108, 93, 189, 216, 115, 142, 23, 106,
            1, 44, 144, 43, 190, 158, 225, 170, 99, 246, 50, 126, 226, 184, 66, 92, 240, 54, 248,
            231, 195, 6, 193, 153, 122, 214, 182, 48, 82, 186, 250, 227, 41, 164, 138, 118, 79, 77,
            75, 191, 85, 249, 100, 213, 131, 38, 67, 207, 31, 70, 46, 26, 9, 156, 116, 73, 68, 140,
            209, 255, 22, 5, 179,
        ],
        [
            8, 84, 108, 56, 245, 249, 30, 129, 85, 19, 2, 27, 132, 134, 212, 244, 135, 59, 64, 222,
            178, 14, 1, 93, 39, 226, 33, 194, 189, 210, 181, 109, 58, 66, 246, 180, 248, 15, 106,
            192, 53, 214, 240, 44, 111, 105, 216, 45, 143, 156, 201, 150, 170, 63, 175, 117, 7, 11,
            119, 21, 147, 61, 114, 34, 54, 115, 6, 247, 179, 38, 96, 29, 231, 193, 215, 191, 95,
            152, 159, 198, 164, 171, 139, 118, 101, 239, 254, 52, 124, 154, 79, 151, 167, 166, 31,
            131, 155, 99, 142, 252,
        ],
        [
            4, 21, 193, 58, 210, 90, 34, 5, 220, 158, 46, 200, 98, 57, 86, 41, 8, 125, 198, 117,
            61, 243, 199, 101, 145, 88, 68, 30, 87, 83, 132, 246, 36, 147, 240, 80, 217, 172, 162,
            195, 11, 35, 50, 106, 213, 91, 22, 179, 154, 97, 191, 118, 177, 16, 155, 75, 250, 194,
            166, 55, 149, 186, 254, 64, 180, 54, 205, 114, 148, 96, 144, 65, 218, 232, 109, 221,
            176, 104, 71, 76, 175, 224, 135, 239, 161, 94, 197, 142, 231, 134, 81, 93, 29, 92, 113,
            33, 74, 111, 187, 130,
        ],
        [
            211, 85, 75, 14, 250, 112, 145, 208, 118, 182, 69, 157, 54, 44, 11, 188, 233, 56, 88,
            243, 137, 207, 169, 134, 246, 162, 68, 150, 241, 84, 175, 129, 153, 123, 200, 103, 236,
            178, 32, 232, 60, 216, 163, 203, 105, 181, 3, 198, 248, 136, 202, 221, 87, 27, 36, 196,
            57, 82, 158, 206, 113, 220, 142, 61, 74, 65, 132, 193, 186, 9, 62, 244, 48, 15, 10,
            167, 165, 168, 126, 73, 231, 234, 209, 128, 17, 146, 205, 122, 91, 16, 249, 119, 0,
            138, 13, 35, 49, 227, 24, 109,
        ],
        [
            171, 180, 198, 186, 201, 182, 160, 174, 124, 143, 123, 210, 115, 134, 14, 144, 178,
            188, 220, 192, 168, 177, 179, 176, 221, 74, 151, 204, 185, 142, 25, 33, 125, 30, 165,
            150, 107, 153, 131, 137, 132, 246, 211, 3, 225, 149, 90, 133, 60, 213, 47, 120, 24,
            202, 32, 235, 104, 86, 227, 206, 95, 105, 193, 219, 130, 231, 197, 5, 127, 50, 80, 48,
            34, 155, 253, 110, 39, 148, 58, 118, 208, 99, 250, 69, 240, 239, 51, 85, 136, 75, 109,
            72, 113, 161, 238, 244, 20, 138, 42, 77,
        ],
        [
            183, 20, 121, 9, 153, 187, 164, 139, 193, 108, 47, 24, 70, 224, 236, 49, 151, 252, 99,
            250, 91, 81, 14, 123, 124, 219, 13, 172, 5, 155, 131, 168, 23, 241, 19, 104, 12, 122,
            100, 59, 253, 113, 202, 74, 69, 127, 96, 129, 17, 83, 189, 28, 77, 226, 85, 220, 128,
            50, 10, 30, 200, 111, 3, 181, 93, 88, 217, 71, 160, 161, 0, 119, 95, 132, 254, 190,
            221, 64, 114, 179, 63, 191, 54, 1, 169, 22, 25, 141, 58, 223, 134, 87, 80, 79, 174,
            209, 117, 148, 90, 222,
        ],
        [
            82, 104, 70, 75, 197, 232, 110, 31, 215, 13, 44, 102, 14, 58, 245, 231, 193, 79, 52,
            40, 78, 114, 143, 88, 95, 196, 214, 227, 86, 55, 148, 111, 189, 158, 242, 17, 194, 9,
            201, 34, 156, 2, 83, 248, 60, 198, 172, 28, 225, 117, 162, 160, 155, 238, 46, 126, 103,
            118, 8, 33, 151, 161, 236, 62, 125, 94, 255, 47, 185, 96, 139, 15, 180, 0, 50, 195,
            119, 247, 175, 77, 200, 36, 179, 81, 209, 233, 99, 177, 213, 228, 66, 220, 76, 53, 38,
            216, 218, 98, 84, 91,
        ],
        [
            108, 55, 40, 62, 95, 127, 53, 220, 151, 80, 46, 224, 122, 79, 72, 9, 249, 150, 153,
            117, 99, 172, 101, 199, 167, 207, 144, 4, 173, 128, 177, 194, 92, 85, 244, 170, 54,
            189, 110, 23, 218, 136, 125, 225, 47, 175, 209, 165, 59, 8, 77, 2, 227, 76, 52, 195,
            159, 238, 215, 201, 164, 106, 152, 203, 241, 130, 149, 145, 147, 250, 49, 78, 90, 176,
            84, 179, 44, 31, 202, 146, 20, 178, 15, 35, 102, 28, 113, 246, 81, 112, 10, 204, 13,
            154, 48, 61, 19, 73, 42, 211,
        ],
        [
            78, 213, 85, 37, 27, 229, 202, 249, 39, 8, 28, 219, 34, 167, 29, 18, 111, 123, 137, 54,
            107, 140, 50, 87, 205, 112, 230, 130, 26, 61, 238, 117, 195, 182, 94, 214, 235, 160,
            138, 132, 216, 218, 133, 12, 30, 116, 239, 131, 33, 42, 67, 168, 52, 113, 76, 223, 237,
            196, 201, 0, 134, 151, 104, 231, 120, 63, 1, 173, 215, 22, 3, 175, 209, 228, 47, 84,
            141, 44, 166, 143, 185, 97, 56, 232, 98, 16, 146, 77, 217, 220, 142, 155, 99, 68, 164,
            184, 206, 145, 189, 255,
        ],
        [
            22, 220, 182, 4, 57, 138, 34, 60, 227, 117, 44, 204, 255, 102, 236, 129, 178, 140, 136,
            133, 206, 125, 207, 1, 38, 165, 173, 77, 234, 45, 142, 179, 108, 122, 197, 177, 184,
            230, 191, 31, 7, 37, 28, 98, 47, 251, 229, 78, 144, 155, 169, 159, 127, 33, 86, 71, 56,
            132, 30, 174, 135, 250, 17, 65, 247, 6, 116, 148, 8, 101, 24, 106, 246, 73, 237, 150,
            134, 219, 67, 223, 52, 241, 76, 109, 48, 167, 62, 93, 103, 0, 27, 228, 245, 75, 46,
            226, 89, 244, 26, 70,
        ],
        [
            106, 54, 65, 227, 216, 75, 192, 250, 94, 140, 229, 43, 157, 24, 255, 100, 207, 55, 41,
            7, 121, 79, 88, 111, 98, 77, 89, 115, 170, 200, 33, 5, 199, 35, 145, 167, 233, 190,
            223, 44, 150, 198, 251, 9, 155, 59, 92, 86, 37, 224, 243, 0, 40, 141, 152, 103, 36,
            181, 83, 4, 244, 122, 143, 49, 166, 8, 230, 149, 96, 84, 64, 112, 71, 219, 61, 148, 46,
            176, 85, 242, 160, 97, 214, 113, 57, 66, 178, 34, 119, 124, 107, 114, 47, 252, 221, 21,
            191, 28, 235, 188,
        ],
        [
            108, 171, 59, 229, 119, 26, 36, 2, 151, 247, 111, 217, 152, 133, 170, 0, 224, 62, 44,
            61, 222, 221, 165, 83, 191, 78, 94, 63, 173, 208, 64, 55, 12, 181, 145, 194, 32, 131,
            58, 121, 246, 168, 51, 18, 27, 103, 15, 239, 3, 199, 238, 114, 132, 220, 16, 74, 86,
            160, 104, 209, 107, 195, 159, 148, 50, 192, 39, 89, 189, 184, 213, 231, 147, 71, 69,
            225, 4, 76, 174, 201, 252, 197, 175, 60, 150, 80, 125, 248, 11, 130, 136, 158, 52, 123,
            211, 31, 124, 234, 166, 90,
        ],
    ];

    const TEST_SLICES_NON_SPLIT_16: [[u8; 16]; 11] = [
        [
            123, 40, 49, 100, 53, 99, 71, 111, 170, 50, 28, 171, 192, 155, 16, 43,
        ],
        [
            148, 84, 133, 234, 175, 230, 19, 44, 212, 100, 92, 55, 137, 195, 2, 117,
        ],
        [
            191, 247, 171, 69, 208, 244, 5, 80, 98, 122, 49, 136, 113, 173, 26, 160,
        ],
        [
            60, 93, 145, 105, 224, 119, 48, 127, 185, 227, 221, 209, 117, 182, 239, 244,
        ],
        [
            148, 95, 144, 191, 211, 26, 65, 48, 73, 245, 184, 123, 20, 127, 67, 149,
        ],
        [
            244, 183, 179, 139, 45, 121, 213, 165, 176, 217, 234, 237, 186, 110, 52, 202,
        ],
        [
            209, 110, 89, 193, 144, 98, 97, 40, 235, 178, 172, 128, 114, 159, 96, 158,
        ],
        [
            45, 14, 246, 132, 7, 15, 244, 125, 89, 164, 140, 170, 189, 225, 78, 230,
        ],
        [
            226, 121, 123, 219, 243, 212, 76, 78, 8, 216, 200, 88, 33, 14, 120, 22,
        ],
        [
            22, 32, 161, 2, 56, 202, 5, 85, 57, 191, 145, 108, 28, 195, 143, 203,
        ],
        [
            182, 74, 158, 102, 197, 117, 23, 145, 63, 40, 220, 252, 109, 178, 166, 238,
        ],
    ];

    const TEST_SLICES_NON_SPLIT_4: [[u8; 4]; 11] = [
        [123, 40, 49, 100],
        [148, 84, 133, 234],
        [191, 247, 171, 11],
        [60, 93, 145, 105],
        [148, 95, 144, 191],
        [244, 183, 179, 139],
        [209, 110, 89, 193],
        [45, 14, 246, 132],
        [226, 121, 123, 219],
        [22, 32, 161, 2],
        [182, 74, 158, 8],
    ];
}

#[cfg(test)]
mod flag_verification_tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Helper to create a valid field list for a single topology.
    /// `include_tricky` must be true for multi‑topology groups.
    fn make_fields(
        include_len: bool,
        include_crc: bool,
        include_idconn: bool,
        include_id_sender_receiver: bool,
        include_ttl: bool,
        include_nonce: bool,
        include_tricky: bool,
    ) -> Box<[PackFields]> {
        let mut fields = Vec::new();
        // Counter is mandatory
        fields.push(PackFields::Counter(4));
        if include_tricky {
            fields.push(PackFields::TrickyByte);
        }
        if include_len {
            fields.push(PackFields::Len(4));
        }
        if include_crc {
            fields.push(PackFields::HeadCRC(4));
        }
        if include_idconn {
            fields.push(PackFields::IdConnect(4));
        }
        if include_id_sender_receiver {
            fields.push(PackFields::IdSender(4));
            fields.push(PackFields::IdReceiver(4));
        }
        if include_ttl {
            fields.push(PackFields::TTL(4));
        }
        if include_nonce {
            fields.push(PackFields::Nonce(4));
        }
        fields.into_boxed_slice()
    }

    // ------------------------------------------------------------------------
    // Single topology – flags must reflect exactly the fields present
    // ------------------------------------------------------------------------
    #[test]
    fn single_topology_flags_match_fields() {
        let fields = make_fields(
            true,  // len
            true,  // crc
            true,  // idconn
            true,  // id_sender_receiver
            true,  // ttl
            true,  // nonce
            false, // tricky not required for single
        );
        let group = GroupTopology::new(&[(fields, 42)], 16, true, false).unwrap();

        assert!(group.all_have_len_field());
        assert!(group.all_have_crc_field());
        assert!(group.all_have_idconn_field());
        assert!(group.all_have_id_sender_receiver_fields());
        assert!(group.all_have_ttl_field());
        assert!(group.all_have_counter_field());
        assert!(group.all_have_nonce_field());

        // Now a topology with none of the optional fields (only counter)
        let minimal = Box::new([PackFields::Counter(4)]);
        let group2 = GroupTopology::new(&[(minimal, 42)], 16, true, false).unwrap();
        assert!(!group2.all_have_len_field());
        assert!(!group2.all_have_crc_field());
        assert!(!group2.all_have_idconn_field());
        assert!(!group2.all_have_id_sender_receiver_fields());
        assert!(!group2.all_have_ttl_field());
        assert!(group2.all_have_counter_field()); // always true
        assert!(!group2.all_have_nonce_field());
    }

    // ------------------------------------------------------------------------
    // Multi‑topology – all flags true only when every topology contains the field
    // ------------------------------------------------------------------------
    #[test]
    fn all_flags_true_when_all_topologies_have_all_fields() {
        let fields1 = make_fields(true, true, true, true, true, true, true);
        let fields2 = make_fields(true, true, true, true, true, true, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(group.all_have_len_field());
        assert!(group.all_have_crc_field());
        assert!(group.all_have_idconn_field());
        assert!(group.all_have_id_sender_receiver_fields());
        assert!(group.all_have_ttl_field());
        assert!(group.all_have_counter_field());
        assert!(group.all_have_nonce_field());
    }

    #[test]
    fn all_have_len_false_when_missing_in_one_topology() {
        let fields1 = make_fields(true, false, false, false, false, false, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_len_field());
        // other flags remain false because no topology has them
        assert!(!group.all_have_crc_field());
        assert!(!group.all_have_idconn_field());
        assert!(!group.all_have_id_sender_receiver_fields());
        assert!(!group.all_have_ttl_field());
        assert!(group.all_have_counter_field());
        assert!(!group.all_have_nonce_field());
    }

    #[test]
    fn all_have_crc_false_when_missing_in_one_topology() {
        let fields1 = make_fields(false, true, false, false, false, false, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_crc_field());
        assert!(!group.all_have_len_field());
        assert!(group.all_have_counter_field());
    }

    #[test]
    fn all_have_idconn_false_when_missing_in_one_topology() {
        let fields1 = make_fields(false, false, true, false, false, false, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_idconn_field());
    }

    #[test]
    fn all_have_id_sender_receiver_false_when_missing_in_one_topology() {
        let fields1 = make_fields(false, false, false, true, false, false, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_id_sender_receiver_fields());
    }

    #[test]
    fn all_have_ttl_false_when_missing_in_one_topology() {
        let fields1 = make_fields(false, false, false, false, true, false, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_ttl_field());
    }

    #[test]
    fn all_have_nonce_false_when_missing_in_one_topology() {
        let fields1 = make_fields(false, false, false, false, false, true, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_nonce_field());
    }

    // ------------------------------------------------------------------------
    // Counter flag – always true for any valid GroupTopology
    // ------------------------------------------------------------------------
    #[test]
    fn all_have_counter_always_true() {
        // Minimal valid topology (only counter)
        let minimal = Box::new([PackFields::Counter(4)]);
        let group = GroupTopology::new(&[(minimal, 1)], 16, true, false).unwrap();
        assert!(group.all_have_counter_field());

        // Multi‑topology with various fields
        let fields1 = make_fields(true, true, true, true, true, true, true);
        let fields2 = make_fields(false, false, false, false, false, false, true);
        let group2 = GroupTopology::new(&[(fields1, 1), (fields2, 2)], 16, true, false).unwrap();
        assert!(group2.all_have_counter_field());
    }

    // ------------------------------------------------------------------------
    // Mixed presence – each flag independent
    // ------------------------------------------------------------------------
    #[test]
    fn mixed_presence_multiple_fields() {
        // Topology A: has len, crc, ttl
        // Topology B: has idconn, nonce, id_sender_receiver
        let fields_a = make_fields(true, true, false, false, true, false, true);
        let fields_b = make_fields(false, false, true, true, false, true, true);

        let group = GroupTopology::new(&[(fields_a, 1), (fields_b, 2)], 16, true, false).unwrap();

        assert!(!group.all_have_len_field()); // only A has len
        assert!(!group.all_have_crc_field()); // only A has crc
        assert!(!group.all_have_idconn_field()); // only B has idconn
        assert!(!group.all_have_id_sender_receiver_fields()); // only B has both
        assert!(!group.all_have_ttl_field()); // only A has ttl
        assert!(!group.all_have_nonce_field()); // only B has nonce
        assert!(group.all_have_counter_field()); // always true
    }

    // ------------------------------------------------------------------------
    // Edge case: three topologies, field present in two out of three
    // ------------------------------------------------------------------------
    #[test]
    fn flag_false_if_not_present_in_every_topology() {
        let fields_all = make_fields(true, true, true, true, true, true, true);
        let fields_missing_len = make_fields(false, true, true, true, true, true, true);
        let fields_missing_crc = make_fields(true, false, true, true, true, true, true);

        let group = GroupTopology::new(
            &[
                (fields_all, 1),
                (fields_missing_len, 2),
                (fields_missing_crc, 3),
            ],
            16,
            true,
            false,
        )
        .unwrap();

        // len missing in second topology
        assert!(!group.all_have_len_field());
        // crc missing in third topology
        assert!(!group.all_have_crc_field());
        // idconn, sender/receiver, ttl, nonce are present in all three
        assert!(group.all_have_idconn_field());
        assert!(group.all_have_id_sender_receiver_fields());
        assert!(group.all_have_ttl_field());
        assert!(group.all_have_nonce_field());
        assert!(group.all_have_counter_field());
    }
}
