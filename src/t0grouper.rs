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
// specific imports for clarity and to avoid namespace pollution
use crate::t0pology::{PackFields as PF, PackTopology};

use crate::w1types::PackTypeGroup;
use crate::{EXPCP, checked_cast};

const PRIMES: &[u16] = &[
    1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 256,
];

#[derive(Debug, PartialEq, Clone)]
///a group of distinct PackTopologies that are united solely by the identical position of
/// the trick byte and the length of all Pack Fields. contains a set of PackTopologies,
/// where each PackTopology either has fields whose lengths match the lengths of all
/// corresponding fields in all other groups, or has none of them,
pub struct GroupTopology {
    pub(crate) topologs: Box<[Option<(PackTopology, PackTypeGroup)>]>,
    pub(crate) fback_max_min_len: usize,
    pub(crate) fback_min_min_len: usize,
    pub(crate) data_max_min_len: usize,
    pub(crate) data_min_min_len: usize,
    pub(crate) all_have_len: Option<(bool, usize)>,
    //
    //The "trash_content_slices" field does not have a hard size limit,
    //so a simplified presence marker is used for it in the group,
    pub(crate) any_have_thash: bool, //
    pub(crate) all_have_crc: Option<(bool, usize)>,
    pub(crate) all_have_idconn: Option<(bool, usize)>,
    pub(crate) all_have_id_rec_send: Option<(bool, usize)>,
    pub(crate) all_have_ttl: Option<(bool, usize)>,
    pub(crate) all_have_ctr: Option<(bool, usize)>,
    pub(crate) all_have_nonce: Option<(bool, usize)>,
    pub(crate) pos_tbyte: Option<usize>,
    pub(crate) how_elems_in_me: usize,
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
    /// * `input_topoler` - slice of tuples containing field definitions and PackTypeGrou(With type of fiels for pack) and u8 keys
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
        input_topoler: &[(Box<[PF]>, PackTypeGroup, u8)],
        tag_len: usize,
        data_save: bool,
        tcp_mode: bool,
    ) -> Result<Self, String> {
        // reject empty input to avoid undefined behavior with min/max calculations
        if input_topoler.is_empty() {
            return Err(
                "input_topoler cannot be empty: at least one topology required".to_string(),
            );
        }
        let mut all_have_len = true;
        let mut all_have_crc = true;
        let mut all_have_idconn = true;
        let mut all_have_id_rec_send = true;
        let mut all_have_ttl = true;
        let mut all_have_ctr = true;
        let mut all_have_nonce = true;
        //
        let mut any_have_thash = false;
        let mut fback_max_min_len = 0;
        let mut fback_min_min_len = usize::MAX;

        let mut data_max_min_len = 0;
        let mut data_min_min_len = usize::MAX;

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

        for (fields, my_type, key) in input_topoler.iter() {
            let idx = checked_cast!(*key => usize, err "Key out of range for usize")?
                .checked_rem(topologs.len())
                .ok_or("Modulo operation failed: divisor is zero")?;
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
                *temp = Some((
                    PackTopology::new(tag_len, fields, data_save, tcp_mode)?,
                    *my_type,
                ));
                EXPCP!(
                    &temp.as_ref(),
                    "this is an impossible state since the assignment of this element was on the \
                     line above"
                )
            };
            let topology = &topology.0;

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
                                        same position relative to the beginning of the packet"
                                .to_string());
                        }
                    } else {
                        pos_tbyte = Some(tb_pos);
                    }
                }
            } else if input_topoler.len() > 1 {
                return Err(
                    "all packet topology variants must have tricky_byte when grouping multiple \
                     topologies"
                        .to_string(),
                );
            }

            // validate field length uniformity across all topologies
            // counter: mandatory field, must have consistent length
            {
                any_have_thash |= topology.trash_content_slice().is_some();

                if let Some((_, _, len)) = topology.counter_slice() {
                    if let Some(expected) = counter_len {
                        if len != expected {
                            return Err(
                                "counter field length mismatch across topologies".to_string()
                            );
                        }
                    } else {
                        counter_len = Some(len);
                    }
                }

                // len: if present in any topology, must have consistent length everywhere
                if let Some((_, _, len)) = topology.len_slice() {
                    if let Some(expected) = len_field_len {
                        if len != expected {
                            return Err("len field length mismatch across topologies".to_string());
                        }
                    } else {
                        len_field_len = Some(len);
                    }
                }

                // head_crc: if present, must have consistent length
                if let Some((_, _, len)) = topology.head_crc_slice() {
                    if let Some(expected) = crc_len {
                        if len != expected {
                            return Err(
                                "head_crc field length mismatch across topologies".to_string()
                            );
                        }
                    } else {
                        crc_len = Some(len);
                    }
                }

                // nonce: if present, must have consistent length
                if let Some((_, _, len)) = topology.nonce_slice() {
                    if let Some(expected) = nonce_len {
                        if len != expected {
                            return Err("nonce field length mismatch across topologies".to_string());
                        }
                    } else {
                        nonce_len = Some(len);
                    }
                }

                // ttl: if present, must have consistent length
                if let Some((_, _, len)) = topology.ttl_slice() {
                    if let Some(expected) = ttl_len {
                        if len != expected {
                            return Err("ttl field length mismatch across topologies".to_string());
                        }
                    } else {
                        ttl_len = Some(len);
                    }
                }

                // idconn: if present, must have consistent length
                if let Some((_, _, len)) = topology.idconn_slice() {
                    if let Some(expected) = idconn_len {
                        if len != expected {
                            return Err(
                                "idconn field length mismatch across topologies".to_string()
                            );
                        }
                    } else {
                        idconn_len = Some(len);
                    }
                }

                // id_sender: if present, must have consistent length
                if let Some((_, _, len)) = topology.id_of_sender_slice() {
                    if let Some(expected) = id_sender_len {
                        if len != expected {
                            return Err(
                                "id_sender field length mismatch across topologies".to_string()
                            );
                        }
                    } else {
                        id_sender_len = Some(len);
                    }
                }

                // id_receiver: if present, must have consistent length AND match sender length
                if let Some((_, _, len)) = topology.id_of_receiver_slice() {
                    if let Some(expected) = id_receiver_len {
                        if len != expected {
                            return Err(
                                "id_receiver field length mismatch across topologies".to_string()
                            );
                        }
                    } else {
                        id_receiver_len = Some(len);
                    }
                    // cross-check: sender and receiver must have equal length within each topology
                    if let Some(sender_len) = id_sender_len
                        && len != sender_len
                    {
                        return Err(
                            "id_receiver and id_sender must have equal length within each topology"
                                .to_string(),
                        );
                    }
                }
                // reciprocal check in case sender was processed after receiver
                if let Some((_, _, len)) = topology.id_of_sender_slice()
                    && let Some(receiver_len) = id_receiver_len
                    && len != receiver_len
                {
                    return Err(
                        "id_sender and id_receiver must have equal length within each topology"
                            .to_string(),
                    );
                }
            }
            // update min/max minimal packet lengths
            let t_l = topology.overhead_len();

            match my_type {
                PackTypeGroup::Any => {
                    data_max_min_len = data_max_min_len.max(t_l);
                    data_min_min_len = data_min_min_len.min(t_l);
                    fback_max_min_len = fback_max_min_len.max(t_l);
                    fback_min_min_len = fback_min_min_len.min(t_l);
                },
                PackTypeGroup::Data => {
                    data_max_min_len = data_max_min_len.max(t_l);
                    data_min_min_len = data_min_min_len.min(t_l);
                },
                PackTypeGroup::Fback => {
                    fback_max_min_len = fback_max_min_len.max(t_l);
                    fback_min_min_len = fback_min_min_len.min(t_l);
                },
            }

            //end for
        }

        // sanity check: min_min_len should have been updated (empty input already rejected)
        if data_min_min_len == usize::MAX {
            return Err("internal error: data_min_min_len not properly initialized".to_string());
        }
        // additional sanity: min should not exceed max
        if data_min_min_len > data_max_min_len {
            return Err(
                "internal error: data_min_min_len > data_max_min_len indicates logic bug"
                    .to_string(),
            );
        }

        // sanity check: min_min_len should have been updated (empty input already rejected)
        if fback_min_min_len == usize::MAX {
            return Err("internal error: fback_min_min_len not properly initialized".to_string());
        }
        // additional sanity: min should not exceed max
        if fback_min_min_len > fback_max_min_len {
            return Err(
                "internal error: fback_min_min_len > fback_max_min_len indicates logic bug"
                    .to_string(),
            );
        }

        let all_have_len: Option<(bool, usize)> = len_field_len.map(|len| (all_have_len, len));
        let all_have_crc: Option<(bool, usize)> = crc_len.map(|len| (all_have_crc, len));
        let all_have_idconn: Option<(bool, usize)> = idconn_len.map(|len| (all_have_idconn, len));
        let all_have_ttl: Option<(bool, usize)> = ttl_len.map(|len| (all_have_ttl, len));
        let all_have_ctr: Option<(bool, usize)> = counter_len.map(|len| (all_have_ctr, len));
        let all_have_nonce: Option<(bool, usize)> = nonce_len.map(|len| (all_have_nonce, len));

        let all_have_id_rec_send: Option<(bool, usize)> = match (id_sender_len, id_receiver_len) {
            // 1. If both fields are present, verify their lengths match
            (Some(s_len), Some(r_len)) => {
                if s_len != r_len {
                    return Err(
                        "The id_sender_len and id_receiver_len fields must have the same length"
                            .to_string(),
                    );
                }
                // If lengths are equal, store the data identically to others
                Some((all_have_id_rec_send, s_len))
            },
            // 2. If only one field is present (symmetry is broken)
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "Both sender and receiver fields must be either simultaneously present or absent".to_string(),
                );
            },
            // 3. If both fields are missing (None, None), the result is None
            (None, None) => None,
        };

        Ok(Self {
            topologs,
            data_max_min_len,
            data_min_min_len,
            fback_max_min_len,
            fback_min_min_len,
            all_have_len,
            any_have_thash,
            all_have_crc,
            all_have_idconn,
            all_have_id_rec_send,
            all_have_ttl,
            all_have_ctr,
            all_have_nonce,
            pos_tbyte,
            how_elems_in_me: input_topoler.len(),
        })
    }
    ///Get the PackTopology diagram by its ID (byte)
    /// Retrieves a reference to a `PackTopology` based on a raw byte index and checks for type compatibility.
    ///
    /// This method maps a given `trikly_byte` to a valid cyclic index within the `topologs` collection.
    /// It then verifies if the requested `type_conformity` matches the actual type of the stored packet.
    ///
    /// # Parameters
    ///
    /// * `trikly_byte` - A raw `u8` value used to calculate the cyclic index within the topologies collection.
    /// * `type_conformity` - The expected packet type group filter (`Data`, `Fback`, or `Any`).
    ///
    /// # Returns
    ///
    /// * `Some(&PackTopology)` - If a topology exists at the calculated index and its type is compatible with `type_conformity`.
    /// * `None` - If no topology is present at the index, or if there is a type mismatch.
    ///
    /// # Panics
    ///
    /// This method will panic under the following conditions:
    /// * If the `u8` to `usize` conversion of `trikly_byte` fails.
    /// * If the internal `topologs` collection is empty (causing a modulo by zero error).
    /// * If the calculated index is out of bounds (which represents an impossible internal state).
    pub fn get_from_u8(
        &self,
        trikly_byte: u8,
        type_conformity: PackTypeGroup,
    ) -> Option<&PackTopology> {
        let idx = checked_cast!(trikly_byte => usize, expect "u8 to usize conversion failed")
            .checked_rem(self.topologs.len())
            .expect("Modulo by zero: topologs is empty");
        if let Some((topol, my_type)) = self
            .topologs
            .get(idx)
            .expect("impossible state since here the index is taken in the length model")
            .as_ref()
        {
            match (type_conformity, my_type) {
                (PackTypeGroup::Data, PackTypeGroup::Data) => Some(topol),
                (PackTypeGroup::Fback, PackTypeGroup::Fback) => Some(topol),
                (PackTypeGroup::Any, _) => Some(topol),
                (_, PackTypeGroup::Any) => Some(topol),
                _ => None,
            }
        } else {
            None
        }
    }

    /// finds the smallest prime table size (from a predefined list) that can accommodate
    /// all given `u8` values without collisions, using a simple modulo hash function.
    ///
    /// the function takes a slice of `(Box<[Pack Fields]>, u8)` pairs, extracts the `u8`
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
    ///   of `Pack Fields` (ignored by the algorithm), the second component is a `u8` key
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
    pub(crate) fn find_minimal_table_size(
        input_topoler: &[(Box<[PF]>, PackTypeGroup, u8)],
    ) -> Result<usize, String> {
        let target_len = input_topoler.len();
        let max_u8 = checked_cast!(u8::MAX => usize,err "u8::MAX to usize conversion failed")?;
        if target_len > max_u8 {
            return Err("input length exceeds maximum supported prime (255)".to_string());
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
            for (_, _, val) in input_topoler {
                let numerator =
                    checked_cast!(*val => usize, err "Value conversion to usize failed")?;
                let denominator =
                    checked_cast!(size => usize, err "Size conversion to usize failed")?;

                let h = numerator
                    .checked_rem(denominator)
                    .ok_or("Modulo operation failed: denominator is zero")?;
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
        Err("no collision‑free prime size found (all have conflicts)".to_string())
    }
}

impl GroupTopology {
    /// returns the maximum minimal packet length among all grouped topologies(PackTypeGroup::Fback).
    ///
    /// this value represents the largest `total_minimal_len` across all individual
    /// `PackTopology` instances in the group. it can be used to pre-allocate buffers
    /// that are guaranteed to fit any packet from any topology in the group.

    pub fn fback_max_minimal_len(&self) -> usize {
        self.fback_max_min_len
    }

    /// returns the minimum minimal packet length among all grouped topologies(PackTypeGroup::Fback).
    ///
    /// this value represents the smallest `total_minimal_len` across all individual
    /// `PackTopology` instances in the group. it can be used for optimistic buffer
    /// sizing or to detect unusually small packets that may belong to a subset of
    /// topologies.

    pub fn fback_min_minimal_len(&self) -> usize {
        self.fback_min_min_len
    }

    /// returns the maximum minimal packet length among all grouped topologies(PackTypeGroup::Data).
    ///
    /// this value represents the largest `total_minimal_len` across all individual
    /// `PackTopology` instances in the group. it can be used to pre-allocate buffers
    /// that are guaranteed to fit any packet from any topology in the group.

    pub fn data_max_minimal_len(&self) -> usize {
        self.data_max_min_len
    }

    /// returns the minimum minimal packet length among all grouped topologies(PackTypeGroup::Data).
    ///
    /// this value represents the smallest `total_minimal_len` across all individual
    /// `PackTopology` instances in the group. it can be used for optimistic buffer
    /// sizing or to detect unusually small packets that may belong to a subset of
    /// topologies.

    pub fn data_min_minimal_len(&self) -> usize {
        self.data_min_min_len
    }

    /// returns `true` if every topology in the group contains a `Len` field.
    ///
    /// the `Len` field is required for tcp-like (stream-oriented) protocols to delimit
    /// packet boundaries. if this method returns `true`, the group can safely assume
    /// that all packets have an explicit length header.
    ///
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_len_field(&self) -> Option<(bool, usize)> {
        self.all_have_len
    }

    /// returns `true` if every topology in the group contains a `HeadCRC` field.
    ///
    /// the `HeadCRC` field protects header integrity in unreliable transport channels
    /// (e.g., udp-like). if this method returns `true`, all packets in the group can
    /// be validated for header corruption before decryption.
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_crc_field(&self) -> Option<(bool, usize)> {
        self.all_have_crc
    }

    /// returns `true` if every topology in the group contains an `IdConnect` field.
    ///
    /// the `IdConnect` field associates packets with a specific connection or session.
    /// if this method returns `true`, all packets in the group support connection-level
    /// multiplexing or session tracking.
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_idconn_field(&self) -> Option<(bool, usize)> {
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
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_id_sender_receiver_fields(&self) -> Option<(bool, usize)> {
        self.all_have_id_rec_send
    }

    /// returns `true` if every topology in the group contains a `TTL` field.
    ///
    /// the `TTL` (time-to-live) field limits packet lifetime in multi-hop networks to
    /// prevent infinite loops. if this method returns `true`, all packets in the group
    /// support hop-count expiration semantics.
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_ttl_field(&self) -> Option<(bool, usize)> {
        self.all_have_ttl
    }

    /// returns `true` if every topology in the group contains a `Counter` field.
    ///
    /// the `Counter` field is **mandatory** for all topologies and holds a unique,
    /// incrementing packet sequence number (1–8 bytes). this method will always return
    /// `true` for any successfully constructed `GroupTopology`, but is provided for
    /// api symmetry and future extensibility.
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_counter_field(&self) -> Option<(bool, usize)> {
        self.all_have_ctr
    }

    /// returns `true` if every topology in the group contains a `Nonce` field.
    ///
    /// the `Nonce` field provides a unique cryptographic nonce for authenticated
    /// encryption (e.g., aes-gcm, chacha20-poly1305). if this method returns `true`,
    /// all packets in the group support per-packet nonce-based encryption.
    ///### Update! It now returns Option<(bool, usize)>
    ///where bool is “every topology in the group contains a (field name)”
    ///and usize is the length of the field in bytes. Read the description of the new() function
    pub fn all_have_nonce_field(&self) -> Option<(bool, usize)> {
        self.all_have_nonce
    }
    ///get the position of the trick byte
    pub fn tricky_position(&self) -> Option<usize> {
        self.pos_tbyte
    }

    ///get the number of different topologies contained in the structure
    pub fn how_elems_in_me(&self) -> usize {
        self.how_elems_in_me
    }

    ///get the position of the trick byte
    /// The "trash_content_slices" field has no strict size limits,
    /// so a simplified marker of presence in the group is used.
    /// Therefore, if this field exists somewhere in the group,
    /// the method will return true; if it does not exist anywhere, the function will return false.
    pub fn any_have_trash_field(&self) -> bool {
        self.any_have_thash
    }

    /// for tesl only
    #[cfg(test)]
    pub fn topol_set(&mut self, topologs: Box<[Option<(PackTopology, PackTypeGroup)>]>) {
        self.topologs = topologs;
    }
}
