use crate::t0pology::PackTopology;
use crate::wt1types::*;
use crate::{t0pology, wutils};

pub fn get_tricky_byte(pack: &mut [u8], topology: &PackTopology) -> Result<u8, WTypeErr> {
    if let Some(star) = topology.tricky_byte() {
        if pack.len() <= star {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        return Ok(pack[star]);
    }

    Err(WTypeErr::CompileFieldsErr(
        "tricky_byte not in PackTopology",
    ))
}

pub fn set_tricky_byte(
    pack: &mut [u8],
    topology: &PackTopology,
    tricky_byte: u8,
) -> Result<(), WTypeErr> {
    if let Some(star) = topology.tricky_byte() {
        if pack.len() <= star {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        pack[star] = tricky_byte;
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr(
        "tricky_byte not in PackTopology",
    ))
}

/// computes and validates the header crc checksum using a user-provided crc function
/// takes mutable packet data, packet topology, and a crc function: (&[u8], &mut [u8]) ->
/// Result<(), &'static str> the header is defined as bytes from start of packet to
/// encrypt_start_pos (before encrypted data) returns Ok(true) if checksum matches,
/// Ok(false) if mismatch, Err if configuration or validation fails if head_crc_slice is
/// not defined in topology, returns error ensures crc field length does not exceed
/// MAXIMAL_CRC_LEN (32 bytes), otherwise returns error before computing crc, the crc
/// field in the header is zeroed to prevent self-inclusion in calculation
/// uses a temporary buffer (twice MAXIMAL_CRC_LEN) to store:
/// - current crc value (from packet) in first half
/// - recalculated crc value in second half
///
/// compares both to determine integrity
/// warning: calling this function twice on corrupted data may yield false positive on
/// second call because the first call may overwrite the crc field with correct value —
/// always validate result on first invocation intended for use in unreliable channels
/// where header integrity must be verified independently of payload
/// ---------------------------------------------------------------------------------
/// #addition, to the previous fart, a new behavior has been added to set_get_head_crc,
/// #repeated generation of crc only if create_new_crc_summ == true,
/// #if create_new_crc_summ == false, the crc value does not change and
/// #repeated checking with incorrect chc will give Ok(false).
/// #this change was accepted during the discussion about dangerous behavior
pub fn set_get_head_crc<F>(
    create_new_crc_summ: bool,
    pack: &mut [u8],
    topology: &PackTopology,
    mut crcfn: F,
) -> Result<bool, WTypeErr>
where
    F: FnMut(&[u8], &mut [u8]) -> Result<(), &'static str>,
{
    if let Some((start, end, len)) = topology.head_crc_slice() {
        if len > t0pology::MAXIMAL_CRC_LEN {
            return Err(WTypeErr::LenSizeErr("len >  t2page::MAXIMAL_CRC_LEN"));
        }

        if pack.len() <= end {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        let head: &mut [u8] = &mut pack[..topology.encrypt_start_pos()];

        let mut temp_old = [0_u8; t0pology::MAXIMAL_CRC_LEN];
        let mut temp_new = [0_u8; t0pology::MAXIMAL_CRC_LEN];

        {
            let head_sl: &mut [u8] = &mut head[start..end];
            temp_old[..len].copy_from_slice(head_sl); //temp = crc head
            head_sl.fill(0); // crc in head = 0
        }

        crcfn(head, &mut temp_new[..len]).map_err(WTypeErr::PackageDamaged)?; //

        head[start..end].copy_from_slice(if create_new_crc_summ {
            &temp_new[..len] //crc
        } else {
            &temp_old[..len] //crc
        });
        return Ok(temp_new[..len] == temp_old[..len]);
    }

    Err(WTypeErr::CompileFieldsErr(
        "head_crc_slice not in PackTopology",
    ))
}

/// set_ttl updates the time-to-live (ttl) value in the packet header based on topology
/// takes mutable packet data, packet topology, a signed delta (ttl_i_edit), max allowed
/// ttl, and is_start_ttl flag<br> returns Ok(()) on success, Err(&'static str) on
/// failure<br> if ttl field is not present in topology, returns error<br>
/// if is_start_ttl is true, initializes ttl to ttl_i_edit (treated as absolute starting
/// value, must be positive)<br> otherwise, increments existing ttl value by ttl_i_edit
/// (can be negative to decrease)<br> reads current ttl from packet using bytes_to_u64; if
/// parsing fails, returns error<br> result is computed via safe add_u64_i64 to prevent
/// overflow/underflow<br> validates that resulting ttl is less than ttl_max and fits
/// within the field's byte length (1–8 bytes)<br> if ttl exceeds capacity of its slice
/// (based on len), returns error to avoid truncation<br> writes updated value back into
/// packet using u64_to_1_8bytes<br> used in multi-hop networks to limit packet lifetime;
/// often paired with crc checks for integrity<br><br> Result<u64, WTypeErr> , Ok(u64)
/// return value ttl after subtracting ttl_i_edit
pub fn set_ttl(
    pack: &mut [u8],
    topology: &PackTopology,
    ttl_i_edit: i64,
    ttl_max: u64,
    is_start_ttl: bool,
) -> Result<u64, WTypeErr> {
    if let Some((start, end, len)) = topology.ttl_slice() {
        if pack.len() <= end {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }

        let temp = wutils::add_u64_i64(
            if is_start_ttl {
                if ttl_i_edit < 0 {
                    return Err(WTypeErr::WorkTimeErr(
                        "is_start_ttl is true, but ttl_i_edit is a negative number, which is an \
                         error, since the initial TTL must be positive.",
                    ));
                }
                0
            } else {
                let ttl_before =
                    wutils::bytes_to_u64(&pack[start..end]).map_err(WTypeErr::WorkTimeErr)?;
                if ttl_before > ttl_max {
                    return Err(WTypeErr::PackageDamaged("ttl_max <=ttl_before "));
                }
                ttl_before
            },
            ttl_i_edit,
            true,
        )
        .map_err(WTypeErr::PackageDamaged)?;
        if ttl_max <= temp {
            return Err(WTypeErr::PackageDamaged("ttl_max <=ttl "));
        }
        if temp > wutils::len_byte_maximal_capacity_check(len).0 {
            return Err(WTypeErr::PackageDamaged(
                "ttl_is TTL is more than capable of accommodating the TTL_SLICE field",
            ));
        }
        wutils::u64_to_1_8bytes(temp, &mut pack[start..end]).map_err(WTypeErr::WorkTimeErr)?;

        return Ok(temp);
    }
    Err(WTypeErr::CompileFieldsErr(" set_ttl not in  PackTopology"))
}

///
/// get_ttl reads the current ttl value from the packet header
/// returns Ok(u64) if ttl field exists and is valid, Err otherwise
/// reads from the slice defined in topology; parsing uses bytes_to_u64
/// should be called on unmodified packet data before any ttl updates for accurate
/// inspection both functions require ttl_slice to be properly defined in PackTopology
/// during construction
pub fn get_ttl(pack: &[u8], topology: &PackTopology) -> Result<u64, WTypeErr> {
    if let Some((start, end, _)) = topology.ttl_slice() {
        if pack.len() <= end {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        return wutils::bytes_to_u64(&pack[start..end]).map_err(WTypeErr::WorkTimeErr);
    }
    Err(WTypeErr::CompileFieldsErr(" set_ttl not in  PackTopology"))
}

/// set_len sets the packet length field in the header based on the actual size of the
/// packet takes mutable packet data, packet topology, and mtu (maximum transmission unit)
/// of the channel returns Ok(()) if successful, Err(&'static str) if validation or
/// encoding fails requires len_slice to be defined in topology; otherwise returns error
/// checks that packet length does not exceed mtu to prevent fragmentation or transmission
/// issues ensures the length value fits within the allocated field (1–8 bytes); if too
/// large, returns error encodes the length using u64_to_1_8bytes to match the field’s
/// byte size and writes it into place used in stream-based protocols (e.g., TCP-like)
/// where length is needed for framing and parsing
pub fn set_len(pack: &mut [u8], topology: &PackTopology, mtu: usize) -> Result<(), WTypeErr> {
    let sls = topology
        .len_slice()
        .ok_or(WTypeErr::CompileFieldsErr(" topology.len_slice() is none"))?;

    if pack.len() <= sls.1 {
        return Err(WTypeErr::LenSizeErr("pack len non correct"));
    }

    let plen = pack.len();

    if plen > mtu {
        return Err(WTypeErr::LenSizeErr("pack len non correct"));
    }

    if plen > wutils::len_byte_maximal_capacity_check(sls.2).0 as usize {
        return Err(WTypeErr::LenSizeErr(
            "pack.len()> len_byte_maximal_capacity_cheak(len)",
        ));
    }

    wutils::u64_to_1_8bytes(pack.len() as u64, &mut pack[sls.0..sls.1])
        .map_err(WTypeErr::WorkTimeErr)?;

    Ok(())
}

/// get_len reads the declared packet length from the header
/// takes immutable packet data and topology, returns Result<usize, &'static str>
/// extracts the length value from the slice defined by len_slice in topology
/// decodes bytes via bytes_to_u64 and converts to usize; returns error on parsing failure
/// useful for determining packet boundaries during parsing or validation
/// both functions assume the length field is unencrypted and located in the packet header
pub fn get_len(pack: &[u8], topology: &PackTopology) -> Result<usize, WTypeErr> {
    let sls = topology
        .len_slice()
        .ok_or(WTypeErr::CompileFieldsErr(" topology.len_slice() is none"))?;
    if pack.len() <= sls.1 {
        return Err(WTypeErr::LenSizeErr("pack len non correct"));
    }
    Ok(wutils::bytes_to_u64(&pack[sls.0..sls.1]).map_err(WTypeErr::WorkTimeErr)? as usize)
}

/// set_id_conn sets the connection identifier and sender role bit in the packet header
/// takes mutable packet data, topology, a 64-bit connection id, and a role indicating
/// sender role role = true means the packet is sent by the session initiator (client)
/// role = false means the packet is sent by the responder (non-initiator)
/// the id_conn value is shifted left by 1 bit, and role is stored in the least
/// significant bit ensures id_conn fits within the available bits: field size (1–8 bytes)
/// minus 1 bit for send_flag returns error if id_conn exceeds capacity or idconn_slice is
/// not defined in topology uses u64_to_1_8bytes to encode the value into the correct
/// number of bytes allows routing and session tracking in bidirectional communication
/// over stateless channels
pub fn set_id_conn(
    pack: &mut [u8],
    topology: &PackTopology,
    id_conn: u64,
    role: MyRole,
) -> Result<(), WTypeErr> {
    if let Some(x) = topology.idconn_slice() {
        if pack.len() <= x.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        if id_conn > wutils::len_byte_maximal_capacity_check(x.2).0 >> 1 {
            return Err(WTypeErr::PackageDamaged(
                "id_conn > wutils::len_byte_maximal_capacity_cheak(x.2).0 >>1",
            ));
        }
        wutils::u64_to_1_8bytes(
            (id_conn << 1) | role.sate_to_bit() as u64,
            &mut pack[x.0..x.1],
        )
        .map_err(WTypeErr::WorkTimeErr)?;
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr("topology.idconn_slice is None"))
}

/// get_id_conn extracts the connection id and sender role from the packet header
/// returns Ok((u64, MyRole)) where the first value is the connection id (shifted right by
/// 1) and the second is the role: true if the sender is the initiator, false otherwise
/// reads bytes from idconn_slice, converts to u64, then strips off the saved role (least
/// significant bit) returns an error if idconn_slice is not present in the topology or
/// parsing fails used to determine the session the packet belongs to and its sender role
/// both functions assume that the idconn field is unencrypted and is in the packet header
pub fn get_id_conn(pack: &[u8], topology: &PackTopology) -> Result<(u64, MyRole), WTypeErr> {
    if let Some(x) = topology.idconn_slice() {
        if pack.len() <= x.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        let reta = wutils::bytes_to_u64(&pack[x.0..x.1]).map_err(WTypeErr::WorkTimeErr)?;
        return Ok((reta >> 1, MyRole::bit_to_state((reta & 1) as u8)));
    }
    Err(WTypeErr::CompileFieldsErr("topology.idconn_slice is None"))
}

/// set_id_sender_and_recv sets both sender and receiver identifiers in the packet header
/// takes mutable packet data, topology, sender id (u64), and receiver id (u64)
/// both id_of_sender_slice and id_of_recver_slice must exist in topology; otherwise
/// returns error retrieves the maximum value that can be stored in the field based on its
/// byte length (1–8 bytes) checks that both ids are within this limit; if either exceeds
/// it, returns an error encodes both ids using u64_to_1_8bytes and writes them into their
/// respective slices used in mesh or multi-hop networks where routing depends on explicit
/// sender/receiver addressing
pub fn set_id_sender_and_recv(
    pack: &mut [u8],
    topology: &PackTopology,
    id_sender: u64,
    id_recv: u64,
) -> Result<(), WTypeErr> {
    if let (Some(x_s), Some(x_r)) = (
        topology.id_of_sender_slice(),
        topology.id_of_receiver_slice(),
    ) {
        let maxim = wutils::len_byte_maximal_capacity_check(x_s.2).0;
        if pack.len() <= x_s.1 || pack.len() <= x_r.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        if maxim < id_recv || maxim < id_sender {
            return Err(WTypeErr::PackageDamaged(
                "maxim < id_recv OR maxim < id_sender",
            ));
        }

        wutils::u64_to_1_8bytes(id_recv, &mut pack[x_r.0..x_r.1]).map_err(WTypeErr::WorkTimeErr)?;
        wutils::u64_to_1_8bytes(id_sender, &mut pack[x_s.0..x_s.1])
            .map_err(WTypeErr::WorkTimeErr)?;
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr(
        "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None",
    ))
}

/// get_id_sender_and_recv reads sender and receiver identifiers from the packet header
/// returns Ok((u64, u64)) with (sender_id, receiver_id) if both fields are present
/// returns error if either slice is missing in topology or decoding fails
/// parses values using bytes_to_u64 from the defined slices in the header
/// allows endpoints to identify source and destination without external context
/// both functions require that sender and receiver fields are present and of equal
/// length, as per protocol rules
pub fn get_id_sender_and_recv(
    pack: &[u8],
    topology: &PackTopology,
) -> Result<(u64, u64), WTypeErr> {
    if let (Some(x_s), Some(x_r)) = (
        topology.id_of_sender_slice(),
        topology.id_of_receiver_slice(),
    ) {
        if pack.len() <= x_s.1 || pack.len() <= x_r.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        return Ok((
            wutils::bytes_to_u64(&pack[x_s.0..x_s.1]).map_err(WTypeErr::WorkTimeErr)?,
            wutils::bytes_to_u64(&pack[x_r.0..x_r.1]).map_err(WTypeErr::WorkTimeErr)?,
        ));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None",
    ))
}

/// set_counter writes the packet counter value into the header with a control bit
/// takes mutable packet data, topology, a 64-bit counter (countr), and a
/// last_bit_in_countr flag of type WPackageType the counter field must exist in topology;
/// otherwise returns error computes maximum value that fits in the allocated field (1–8
/// bytes), then shifts right by 1 to reserve one bit combines the counter (masked to fit)
/// with the flag bit, shifted into the LSB, forming the final value checks that packet
/// length covers the counter slice; if not, returns length error encodes the result using
/// u64_to_1_8bytes and writes it into the packet returns Ok((encoded_counter, max_cap))
/// on success, where max_cap is the max counter range per field size used to embed
/// sequence number and packet type (e.g., data/control) in a compact format
pub fn set_counter(
    pack: &mut [u8],
    topology: &PackTopology,
    countr: u64,
    my_type: PackType,
) -> Result<(u64, u64), WTypeErr> {
    if let Some(x) = topology.counter_slice() {
        if pack.len() <= x.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        let max_cap = wutils::len_byte_maximal_capacity_check(x.2).0 >> 1;

        let pack_ctr = ((max_cap & countr) << 1) | my_type.sate_to_bit() as u64;

        wutils::u64_to_1_8bytes(pack_ctr, &mut pack[x.0..x.1]).map_err(WTypeErr::WorkTimeErr)?;

        return Ok((pack_ctr, max_cap));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.counter_slice() is none",
    ))
}

/// set_counter writes the packet counter value into the header with a control bit
/// takes mutable packet data, topology, a 64-bit counter (countr), and a
/// last_bit_in_countr flag of type WPackageType the counter field must exist in topology;
/// otherwise returns error computes maximum value that fits in the allocated field (1–8
/// bytes), then shifts right by 1 to reserve one bit combines the counter (masked to fit)
/// with the flag bit, shifted into the LSB, forming the final value checks that packet
/// length covers the counter slice; if not, returns length error encodes the result using
/// u64_to_1_8bytes and writes it into the packet returns Ok((encoded_counter, max_cap))
/// on success, where max_cap is the max counter range per field size used to embed
/// sequence number and packet type (e.g., data/control) in a compact format
///
/// get_counter reconstructs the full 64-bit counter from packet and context
/// takes immutable packet data, topology, and two context counters (countr1 and countr2)
/// returns Ok((reconstructed_counter, WPackageType)) or error if counter field is missing
/// or packet is truncated reads raw counter bytes and extracts:
/// - the data counter (bits 1–63, right-shifted and masked)
/// - the flag bit (LSB) indicating packet type (via WPackageType)
/// selects base counter: countr1 if flag bit is 1, countr2 if 0 — used for packet stream
/// differentiation reconstructs full counter by combining high bits from base counter
/// with low bits from packet if reconstructed counter is less than base, assumes
/// wraparound and adds (max_cap + 1) to handle overflow enables reliable counter recovery
/// in lossy or out-of-order networks, supporting anti-replay and ordering critical for
/// protocols using sliding windows or requiring full sequence tracking across restarts
pub fn get_counter(
    pack: &[u8],
    topology: &PackTopology,
    countr1_fback: u64,
    countr2_data: u64,
) -> Result<(u64, PackType), WTypeErr> {
    if let Some(x) = topology.counter_slice() {
        if pack.len() <= x.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct"));
        }
        let ctr_in_pack = wutils::bytes_to_u64(&pack[x.0..x.1]).map_err(WTypeErr::WorkTimeErr)?;
        let (max_cap, _) = wutils::len_byte_maximal_capacity_check(x.2);
        let max_cap = max_cap >> 1;
        let pack_ctr = (ctr_in_pack >> 1) & max_cap;
        let my_type = PackType::bit_to_state((ctr_in_pack & 1) as u8);

        let countr = if my_type.is_fback() {
            countr1_fback
        } else {
            countr2_data
        };

        //When working with the algorithm,
        //keep in mind that the counter in the packet has a smaller field than the real counter,
        //so if the packet numbers differ significantly,
        //so that the difference in values is greater than the maximum capacity,
        //the real counter will be determined incorrectly,
        //the incorrect counter will give an incorrect initial state for the cipher,
        //resulting in the packet being identified as a damaged packet, thanks to the tag field.

        //                     older bytes       ctr_ pack
        let real_countr = (countr & (!max_cap)) | pack_ctr;
        return Ok((
            if real_countr < countr {
                real_countr
                    .checked_add(
                        max_cap
                            .checked_add(1)
                            .ok_or(WTypeErr::WorkTimeErr("overflow max_cap+1"))?,
                    )
                    .ok_or(WTypeErr::WorkTimeErr("overflow real_countr+OLDER BIT"))?
            } else {
                real_countr
            },
            my_type,
        ));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.counter_slice() is none",
    ))
}

/// set_user_field generates and fills the user-defined field (aka "trash field") in the
/// packet header takes mutable packet data, topology, a counter value, full packet
/// length, and a user-provided generator function the generator function: fn(&mut [u8],
/// u64, usize, usize) -> Result<(), &'static str> is called with:<br>
/// 1 a byte slice of the field that needs to be filled with user information,<br>
/// 2 the packet counter,<br>
/// 3 the total packet length>,<br>
/// 4 the user field number,<br>
/// since there may be several user fields, for custom data generation only executes if
/// trash_content_slice is defined in topology; otherwise returns error validates that
/// packet length covers the entire field range; returns error if out of bounds
/// writes generated data directly into the specified slice in the packet
/// returns Ok(()) on success, or error if field is missing or generator fails
/// this field is unencrypted and intended to obscure packet structure from DPI and
/// traffic analysis systems by varying content at fixed positions, it helps prevent
/// protocol fingerprinting and blocking no getter function is provided to avoid
/// accidental exposure of sensitive or generated data purely for obfuscation — commonly
/// used in censorship-resistant or mimicry protocols
pub fn set_user_field<F>(
    pack: &mut [u8],
    topology: &PackTopology,
    counter: u64,
    full_len: usize,
    mut field_gen: F,
) -> Result<(), WTypeErr>
where
    F: FnMut(&mut [u8], u64, usize, usize) -> Result<(), &'static str>,
{
    if let Some(vecta_trash) = topology.trash_content_slice() {
        for (i, (start, end, _)) in vecta_trash.iter().enumerate() {
            if pack.len() <= *end {
                return Err(WTypeErr::LenSizeErr("pack len non correct"));
            }

            field_gen(&mut pack[*start..*end], counter, full_len, i)
                .map_err(WTypeErr::PackageDamaged)?; //
        }
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr("user_field not in PackTopology"))
}

/// crypt performs encryption or decryption of the packet payload and computes
/// authentication tag takes mutable packet data, packet topology, encryption mode
/// (enc/dec), optional counter, and nonce generator returns Ok(()) on success, or error
/// if validation or crypto operation fails ensures packet length meets minimal required
/// size (header + tag) before processing
///
/// during encryption:
/// - requires either a counter, a nonce, or both; if neither present, returns error
/// - if nonce is used, calls nonce_gener to fill the nonce field in the header with
///   random data
/// - counter must be provided if counter_slice exists; otherwise returns error
/// - zeroizes TTL and HeadCRC fields before crypto operation, as they may change in
///   transit and invalidate the tag
/// - preserves original values in temporary buffers to restore them after encryption
///
/// supports two crypto interface modes via TypeGetMode for maximum library compatibility:
///
/// TypeGetMode::Type1SplitMutSlices:
/// - passes data as three mutable slices:
/// 1. [u8] – unencrypted header (read-only)
/// 2. &mut [u8] – payload to encrypt/decrypt
/// 3. &mut [u8] – output location for authentication tag
/// - also passes counter (u64) and optional nonce slice
/// - suitable for libraries expecting separated data segments
///
/// TypeGetMode::Type2FullArrAndIndexes:
/// - passes full mutable packet and indices:
/// 1. &mut [u8] – entire packet buffer
/// 2. usize – start index of encrypted payload
/// 3. usize – start index of tag field
/// 4. u64 – packet counter (or 0 if not used)
/// 5. Option<(usize, usize)> – start/end of nonce within header, if present
/// - allows in-place processing with offset-based access
/// - useful for libraries requiring full packet context or custom memory layout
///
/// after crypto operation, restores original TTL and HeadCRC values to maintain packet
/// semantics designed for use with AEAD ciphers (e.g., ChaCha20-Poly1305, AES-GCM) where
/// tag covers both header and payload enables censorship-resistant protocols by allowing
/// flexible, pluggable crypto backends
pub fn crypt<Tenc, Tnoncer>(
    pack: &mut [u8],
    topology: &PackTopology,
    enc_mode: Cryptlag,
    enc_struct: &Tenc,
    countr: Option<u64>,
    nonce_gener: Option<&mut Tnoncer>,
) -> Result<(), WTypeErr>
where
    Tenc: EncWis,
    Tnoncer: Noncer,
{
    let p_len = pack.len();

    if p_len < topology.total_minimal_len() {
        return Err(WTypeErr::LenSizeErr(
            "pack.len()< topology.total_minimal_len()",
        ));
    }

    let is_encrypt = match enc_mode {
        Cryptlag::Encrypt => true,
        Cryptlag::Decrypt => false,
    };

    if is_encrypt {
        if_encrypt(topology, pack, nonce_gener, countr)?;
    }

    //since TTL and HEADCRC can be changed during packet transmission, these two fields are
    // filled with zeros because the whole packet falls into tag, and head data too, while
    // TTL and HEADCRC do not affect data integrity and can be changed.
    let mut ttl_vec_temp_mem = [0_u8; t0pology::MAXIMAL_TTL_LEN];
    let mut crc_vec_temp_mem = [0_u8; t0pology::MAXIMAL_CRC_LEN];
    if let Some((s, e, len)) = topology.ttl_slice() {
        ttl_vec_temp_mem[..len].copy_from_slice(&pack[s..e]);
        pack[s..e].fill(0);
    }

    if let Some((s, e, len)) = topology.head_crc_slice() {
        crc_vec_temp_mem[..len].copy_from_slice(&pack[s..e]);
        pack[s..e].fill(0);
    }

    crypt_procress(is_encrypt, topology, p_len, enc_struct, pack, countr)?;

    if let Some((s, e, len)) = topology.ttl_slice() {
        pack[s..e].copy_from_slice(&ttl_vec_temp_mem[..len]);
    }

    if let Some((s, e, len)) = topology.head_crc_slice() {
        pack[s..e].copy_from_slice(&crc_vec_temp_mem[..len]);
    }

    Ok(())
}

fn crypt_procress<Tenc: EncWis>(
    is_encrypt: bool,
    topology: &PackTopology,
    p_len: usize,
    enc_struct: &Tenc,
    pack: &mut [u8],
    countr: Option<u64>,
) -> Result<(), WTypeErr> {
    let enc_start = topology.encrypt_start_pos();
    let enc_end = p_len - topology.tag_len();
    //Previously, a check was performed to ensure that p_len < topology.total_minimal_len(),
    //which means that the packet length is large enough so that the operation of splitting
    // into slays does not cause panic.
    let (free_data, mac_only) = pack.split_at_mut(enc_end);
    let (head, to_enc_only) = free_data.split_at_mut(enc_start);

    let nonce = topology.nonce_slice().map(|x| &head[x.0..x.1]);

    if is_encrypt {
        enc_struct
            .encrypt(head, to_enc_only, mac_only, countr.unwrap_or(0), nonce)
            .map_err(WTypeErr::WorkTimeErr)?;
    } else if enc_struct
        .decrypt(head, to_enc_only, mac_only, countr.unwrap_or(0), nonce)
        .map_err(WTypeErr::WorkTimeErr)?
        .is_damaged()
    {
        return Err(WTypeErr::PackageDamaged(
            "error return during decryption associated with packet corruption",
        ));
    }
    Ok(())
}

///---Nonce gen     or/and counter set---<br>
///nonce + counter:valid<br>
///counter only :valid<br>
///nonce only:valid<br>
///not counter and nonce :invalid<br>
fn if_encrypt<Tnoncer: Noncer>(
    topology: &PackTopology,
    pack: &mut [u8],
    nonce_gener: Option<&mut Tnoncer>,
    countr: Option<u64>,
) -> Result<(), WTypeErr> {
    let (n, c) = (
        if let Some(x) = topology.nonce_slice() {
            nonce_gener
                .ok_or(WTypeErr::CompileFieldsErr("nonce_gener required"))?
                .set_nonce(&mut pack[x.0..x.1])
                .map_err(WTypeErr::WorkTimeErr)?;
            1
        } else {
            0
        },
        if topology.counter_slice().is_some() {
            if countr.is_none() {
                return Err(WTypeErr::CompileFieldsErr("counter_field required"));
            }
            1
        } else {
            0
        },
    );
    if 0 == n + c {
        return Err(WTypeErr::CompileFieldsErr(
            "Incorrect combination, the packet must have either a counter field, a nonce field, \
             or a nonce field + a counter field. This topology has neither a counter field nor a \
             nonce field.",
        ));
    }
    Ok(())
}

//##=============================================================TESTS====================================TESTS===================////=============
//##=============================================================TESTS====================================TESTS====================////=============

#[cfg(test)]
mod tests {
    use super::*;
    use crate::t1dumps_struct::*;

    #[test]
    fn test_tricky_byte() {
        let fields = vec![
            t0pology::PackFields::UserField(33),
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::TrickyByte,
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::HeadCRC(8),
        ];

        let result = PackTopology::new(59, &fields, true, false).unwrap();

        let mut tets1 = vec![0; 100];

        assert_eq!(set_tricky_byte(&mut tets1[..], &result, 7), Ok(()));

        assert_eq!(
            set_tricky_byte(&mut tets1[..100 - 60], &result, 7),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(get_tricky_byte(&mut tets1[..], &result), Ok(7));

        assert_eq!(
            get_tricky_byte(&mut tets1[..100 - 60], &result),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        for i in 0..15 {
            set_tricky_byte(&mut tets1[..], &result, i).expect("");

            assert_eq!(get_tricky_byte(&mut tets1[..], &result), Ok(i));
        }

        let fields = vec![
            t0pology::PackFields::UserField(33),
            t0pology::PackFields::Counter(7),
            //t0pology::PackFields::TrickyByte,
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::HeadCRC(8),
        ];

        let result = PackTopology::new(59, &fields, true, false).unwrap();

        assert_eq!(
            get_tricky_byte(&mut tets1[..100 - 60], &result),
            Err(WTypeErr::CompileFieldsErr(
                "tricky_byte not in PackTopology"
            ))
        );

        assert_eq!(
            set_tricky_byte(&mut tets1[..100 - 60], &result, 7),
            Err(WTypeErr::CompileFieldsErr(
                "tricky_byte not in PackTopology"
            ))
        );
    }

    #[test]
    fn test_gen_head_crc() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::UserField(3333),
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::HeadCRC(8),
        ];

        let result = PackTopology::new(59, &fields, true, false).unwrap();

        let fields2 = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::UserField(3333),
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
        ];

        let result_non_crc = PackTopology::new(59, &fields2, true, false).unwrap();

        let mut bb = vec![0_u8; 3500];

        for x in bb.iter_mut().enumerate() {
            *x.1 = x.0.wrapping_mul(1) as u8;
        }
        set_get_head_crc(true, &mut bb, &result, dummy_crc_gen).unwrap();

        if let Some((start, end, _)) = result.head_crc_slice() {
            println!("{:?}", &bb[start..end]);
            assert_eq!(&bb[start..end], [45, 22, 151, 232, 151, 44, 216, 206]);
        } else {
            panic!(
                "result.head_crc_slice() is er {:?}",
                result.head_crc_slice()
            );
        }
        assert!(set_get_head_crc(true, bb.as_mut_slice(), &result, dummy_crc_gen).unwrap());

        {
            let mut eer_result = result.clone();
            eer_result.__warning_test_only_force_edit_crc(Some((
                0,
                t0pology::MAXIMAL_CRC_LEN + 1,
                t0pology::MAXIMAL_CRC_LEN + 1,
            )));
            assert_eq!(
                set_get_head_crc(true, bb.as_mut_slice(), &eer_result, dummy_crc_gen),
                Err(WTypeErr::LenSizeErr("len >  t2page::MAXIMAL_CRC_LEN"))
            ); //err
        }

        for i in 0..result.encrypt_start_pos() {
            let mut bbt = bb.clone();
            bbt[i] = !bbt[i];

            assert!(
                !set_get_head_crc(true, bbt.as_mut_slice(), &result, dummy_crc_gen).unwrap(),
                "i:  {}",
                i
            );
            //print!("{} ",i);
        }

        let mut bb = vec![0_u8; 3500];

        for x in bb.iter_mut().enumerate() {
            *x.1 = x.0.wrapping_mul(1) as u8;
        }
        {
            assert_eq!(
                set_get_head_crc(false, &mut bb, &result, dummy_crc_gen),
                Ok(false)
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result, dummy_crc_gen),
                Ok(false)
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result, dummy_crc_gen),
                Ok(false)
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result, dummy_crc_gen),
                Ok(false)
            );
        }

        for x in bb.iter_mut().enumerate() {
            assert!(*x.1 == x.0.wrapping_mul(1) as u8);
        }

        {
            assert_eq!(
                set_get_head_crc(true, &mut bb, &result, dummy_crc_gen),
                Ok(false)
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result, dummy_crc_gen),
                Ok(true)
            );

            bb[result.head_crc_slice().unwrap().0..result.head_crc_slice().unwrap().1].fill(1);

            assert_eq!(
                set_get_head_crc(true, &mut bb, &result, dummy_crc_gen),
                Ok(false)
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result, dummy_crc_gen),
                Ok(true)
            );

            assert_eq!(
                set_get_head_crc(
                    false,
                    &mut bb[..result.head_crc_slice().unwrap().1],
                    &result,
                    dummy_crc_gen
                ),
                Err(WTypeErr::LenSizeErr("pack len non correct"))
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result_non_crc, dummy_crc_gen),
                Err(WTypeErr::CompileFieldsErr(
                    "head_crc_slice not in PackTopology"
                ))
            );
        }
    }

    #[test]
    fn test_ttl() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let result = PackTopology::new(5, &fields, true, false).unwrap();

        let fields2 = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
        ];

        let result_no_ttl = PackTopology::new(5, &fields2, true, false).unwrap();

        let mut bb = vec![0_u8; result.total_minimal_len()];

        for x in bb.iter_mut().enumerate() {
            *x.1 = x.0 as u8;
        }

        //println!("{:?}",&bb[result.head_crc_slice().unwrap().0..result.head_crc_slice().
        // unwrap().1]);
        assert_eq!(set_ttl(&mut bb, &result, 435, 1000, true), Ok(435));

        assert!(set_ttl(&mut bb, &result, 6546, 1000, false).is_err());

        assert_eq!(get_ttl(&bb, &result), Ok(435));

        assert_eq!(set_ttl(&mut bb, &result, 435, 1000, false), Ok(435 * 2));

        assert_eq!(get_ttl(&bb, &result).unwrap(), 435 * 2);

        assert_eq!(
            set_ttl(&mut bb, &result, -300, 1000, false),
            Ok((435 * 2) - 300)
        );

        assert_eq!(get_ttl(&bb, &result).unwrap(), (435 * 2) - 300);

        assert_eq!(set_ttl(&mut bb, &result, -900, 1000, false), Ok(0));

        assert_eq!(set_ttl(&mut bb, &result, 9, 1000, true), Ok(9));

        assert_eq!(get_ttl(&bb, &result), Ok(9));

        assert_eq!(
            set_ttl(&mut bb, &result, 1000, 9, false),
            Err(WTypeErr::PackageDamaged("ttl_max <=ttl "))
        );
        assert_eq!(
            set_ttl(&mut bb, &result_no_ttl, 1000, 90000, false),
            Err(WTypeErr::CompileFieldsErr(" set_ttl not in  PackTopology"))
        );
        assert_eq!(
            set_ttl(
                &mut bb[..result.ttl_slice().unwrap().1],
                &result,
                1000,
                90000,
                false
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            get_ttl(&bb[..result.ttl_slice().unwrap().1], &result),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
        assert_eq!(
            get_ttl(&bb, &result_no_ttl),
            Err(WTypeErr::CompileFieldsErr(" set_ttl not in  PackTopology"))
        );

        assert_eq!(
            set_ttl(&mut bb, &result, -435, 1000, true),
            Err(WTypeErr::WorkTimeErr(
                "is_start_ttl is true, but ttl_i_edit is a negative number, which is an error, \
                 since the initial TTL must be positive."
            ))
        );

        assert_eq!(set_ttl(&mut bb, &result, 999, 1000, true), Ok(999));
        assert_eq!(
            set_ttl(&mut bb, &result, -500, 800, false),
            Err(WTypeErr::PackageDamaged("ttl_max <=ttl_before "))
        );
    }

    #[test]
    fn test_crypt() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::UserField(1),
            t0pology::PackFields::Counter(1),
            t0pology::PackFields::IdConnect(2),
            t0pology::PackFields::HeadCRC(2),
            t0pology::PackFields::Nonce(6),
            t0pology::PackFields::TTL(2),
            t0pology::PackFields::Len(3),
        ];

        let result = PackTopology::new(16, &fields, true, true).unwrap();
        let mut bb = vec![0_u8; result.total_minimal_len() + 11];

        for x in bb.iter_mut().enumerate() {
            *x.1 = x.0.wrapping_add(1) as u8;
        }

        assert!(set_ttl(&mut bb, &result, 100, 200, true).is_ok());

        assert_eq!(set_len(&mut bb, &result, 100), Ok(()));

        let mut noncex = DumpNonser::new(&[0]).unwrap();

        let ctr_n = Some(1000);

        let cs = DumpEnc::new(&[1, 2, 3, 4, 5, 6]).unwrap();

        let validation = bb[result.encrypt_start_pos()..bb.len() - result.tag_len()].to_vec();
        assert_eq!(
            crypt(
                &mut bb,
                &result,
                Cryptlag::Encrypt,
                &cs,
                ctr_n,
                Some(&mut noncex)
            ),
            Ok(())
        ); //enc
        assert_ne!(
            bb[result.encrypt_start_pos()..bb.len() - result.tag_len()],
            validation
        );
        //println!("\ndd :{:?}",bb);

        let mut bbb = bb.clone();

        let mut bbb1 = bb.clone();

        let mut bbb2 = bb.clone();
        assert_eq!(
            crypt(
                &mut bbb,
                &result,
                Cryptlag::Decrypt,
                &cs,
                ctr_n,
                Some(&mut noncex)
            ),
            Ok(())
        ); //decr

        let _ = set_ttl(&mut bbb1, &result, 21, 200, true).unwrap();
        assert_eq!(
            crypt(
                &mut bbb1,
                &result,
                Cryptlag::Decrypt,
                &cs,
                ctr_n,
                Some(&mut noncex)
            ),
            Ok(())
        ); //decr

        set_get_head_crc(true, &mut bbb2, &result, dummy_crc_gen).unwrap();
        assert_eq!(
            crypt(
                &mut bbb2,
                &result,
                Cryptlag::Decrypt,
                &cs,
                ctr_n,
                Some(&mut noncex)
            ),
            Ok(())
        ); //decr

        assert_eq!(
            bbb[result.encrypt_start_pos()..bb.len() - result.tag_len()],
            validation
        );

        //println!("\ndd :{:?}",bbb);
        //return;
        print!("test_crypt ");
        for i in 0..bb.len() {
            let mut bbb = bb.clone();

            bbb[i] = !bbb[i];
            print!("{} ", i);

            if let Some(x) = result.head_crc_slice()
                && i >= x.0
                && i < x.1
            {
                assert_eq!(
                    crypt(
                        &mut bbb,
                        &result,
                        Cryptlag::Decrypt,
                        &cs,
                        ctr_n,
                        Some(&mut noncex)
                    ),
                    Ok(())
                );
                continue;
            }
            if let Some(x) = result.ttl_slice()
                && i >= x.0
                && i < x.1
            {
                assert_eq!(
                    crypt(
                        &mut bbb,
                        &result,
                        Cryptlag::Decrypt,
                        &cs,
                        ctr_n,
                        Some(&mut noncex)
                    ),
                    Ok(())
                );
                continue;
            }
            assert_eq!(
                crypt(
                    &mut bbb,
                    &result,
                    Cryptlag::Decrypt,
                    &cs,
                    ctr_n,
                    Some(&mut noncex)
                ),
                Err(WTypeErr::PackageDamaged(
                    "error return during decryption associated with packet corruption"
                ))
            );
        }
    }

    #[test]
    fn test_len() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
        ];

        let result = PackTopology::new(5, &fields, true, true).unwrap();

        let fields2 = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
        ];

        let result_non_len = PackTopology::new(5, &fields2, true, false).unwrap();

        let mut bb = vec![0_u8; result.total_minimal_len() + 132];

        assert!(set_len(&mut bb, &result, 435,).is_ok());

        assert!(set_len(&mut bb, &result, 15).is_err());

        let fields2 = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
        ];

        let result1 = PackTopology::new(5, &fields2, true, false).unwrap();

        assert!(get_len(&bb, &result1).is_err());

        assert_eq!(get_len(&bb, &result), Ok(bb.len()));

        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(1),
        ];

        let result = PackTopology::new(5, &fields, true, true).unwrap();

        let mut bb = vec![0_u8; result.total_minimal_len() + 242];

        assert_eq!(
            set_len(&mut bb, &result, 435,),
            Err(WTypeErr::LenSizeErr(
                "pack.len()> len_byte_maximal_capacity_cheak(len)"
            ))
        );

        assert_eq!(
            set_len(&mut bb[..result.len_slice().unwrap().1], &result, 435,),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
        assert_eq!(
            set_len(&mut bb, &result_non_len, 435,),
            Err(WTypeErr::CompileFieldsErr(" topology.len_slice() is none"))
        );

        assert_eq!(
            get_len(&bb[..result.len_slice().unwrap().1], &result),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
        assert_eq!(
            get_len(&bb, &result_non_len),
            Err(WTypeErr::CompileFieldsErr(" topology.len_slice() is none"))
        );
    }

    #[test]
    fn test_trash() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::UserField(334),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
        ];

        let result = PackTopology::new(5, &fields, true, true).unwrap();

        let fields1 = vec![
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
        ];

        let fieldsus = vec![
            t0pology::PackFields::UserField(4),
            t0pology::PackFields::UserField(3),
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::UserField(11),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::UserField(6),
            t0pology::PackFields::Len(4),
            t0pology::PackFields::UserField(4),
            t0pology::PackFields::UserField(5),
        ];
        let result_usr_test = PackTopology::new(5, &fieldsus, true, true).unwrap();

        let result1 = PackTopology::new(5, &fields1, true, true).unwrap();

        let mut bb1 = vec![0_u8; result.total_minimal_len() + 1];
        let mut bb2 = vec![0_u8; result.total_minimal_len() + 1];
        let mut bb3 = vec![0_u8; result.total_minimal_len() + 1];
        let mut bb4 = vec![0_u8; result.total_minimal_len() + 1];

        let mut bb4_usr_test = vec![0_u8; result_usr_test.total_minimal_len() + 1];

        let mut tb1 = vec![0_u8; 334];
        let mut tb2 = vec![0_u8; 334];
        let mut tb3 = vec![0_u8; 334];
        let mut tb4 = vec![0_u8; 334];

        dummy_usf(&mut tb1, 312, 38865, 0).unwrap();
        dummy_usf(&mut tb2, 675, 7564, 0).unwrap();
        dummy_usf(&mut tb3, 987, 765, 0).unwrap();
        dummy_usf(&mut tb4, 12213, 987, 0).unwrap();

        set_user_field(&mut bb4_usr_test, &result_usr_test, 20, 111, dummy_usf).unwrap();

        assert_eq!(
            bb4_usr_test,
            [
                20, 111, 0, 20, 20, 111, 1, 0, 0, 0, 0, 0, 0, 0, 20, 111, 2, 20, 111, 2, 20, 111,
                2, 20, 111, 0, 0, 0, 0, 20, 111, 3, 20, 111, 3, 0, 0, 0, 0, 20, 111, 4, 20, 20,
                111, 5, 20, 111, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        assert_ne!(tb1, tb2);
        assert_ne!(tb2, tb3);
        assert_ne!(tb4, tb1);
        assert_ne!(tb1, tb3);
        assert_ne!(tb2, tb4);

        set_user_field(&mut bb1, &result, 312, 38865, dummy_usf).unwrap();
        set_user_field(&mut bb2, &result, 675, 7564, dummy_usf).unwrap();
        set_user_field(&mut bb3, &result, 987, 765, dummy_usf).unwrap();
        set_user_field(&mut bb4, &result, 12213, 987, dummy_usf).unwrap();

        assert_eq!(
            set_user_field(&mut bb3, &result1, 987, 765, dummy_usf),
            Err(WTypeErr::CompileFieldsErr("user_field not in PackTopology"))
        );
        assert_eq!(
            set_user_field(
                &mut bb4[..result.trash_content_slice().unwrap()[0].1],
                &result,
                12213,
                987,
                dummy_usf
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            tb1[..],
            bb1[result.trash_content_slice().unwrap()[0].0
                ..result.trash_content_slice().unwrap()[0].1]
        );
        assert_eq!(
            tb2[..],
            bb2[result.trash_content_slice().unwrap()[0].0
                ..result.trash_content_slice().unwrap()[0].1]
        );
        assert_eq!(
            tb3[..],
            bb3[result.trash_content_slice().unwrap()[0].0
                ..result.trash_content_slice().unwrap()[0].1]
        );
        assert_eq!(
            tb4[..],
            bb4[result.trash_content_slice().unwrap()[0].0
                ..result.trash_content_slice().unwrap()[0].1]
        );
    }

    #[test]
    fn test_ctr() {
        let fields = vec![
            t0pology::PackFields::TTL(2),
            t0pology::PackFields::Counter(1),
        ];

        let result = PackTopology::new(16, &fields, true, false).unwrap();

        let mut bb = vec![0_u8; result.total_minimal_len() + 11];

        for x in bb.iter_mut().enumerate() {
            *x.1 = 0xFF;
        }

        for tt in [true, false] {
            for i in (31231..31231 + 300).step_by(17) {
                let (i1, i2) = (i, i * 12349);
                for y in 0..120 {
                    let ccc = if tt { i1 } else { i2 };

                    assert!(
                        set_counter(&mut bb, &result, ccc, PackType::bit_to_state(tt as u8))
                            .is_ok()
                    );
                    assert!(get_counter(&bb, &result, i1, i2).is_ok());

                    assert_eq!(
                        get_counter(&bb, &result, i1, i2).unwrap(),
                        (if tt { i1 } else { i2 }, PackType::bit_to_state(tt as u8)),
                        "from get_counter {:?}  real {:?}  i:{i}  tt:{tt}  y:{y}",
                        get_counter(&bb, &result, i1 - y, i2 - y).unwrap(),
                        (if tt { i1 } else { i2 }, tt)
                    );
                }
            }
        }

        assert_eq!(
            set_counter(
                &mut bb[..result.counter_slice().unwrap().1],
                &result,
                21,
                PackType::FBack
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
        assert_eq!(
            get_counter(&bb[..result.counter_slice().unwrap().1], &result, 21, 1),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
    }

    #[test]
    fn test_id_conn() {
        let fields1 = vec![
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
            t0pology::PackFields::Counter(2),
            t0pology::PackFields::IdConnect(7),
        ];
        let fields2 = vec![
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
            t0pology::PackFields::Counter(4),
        ];

        let result1 = PackTopology::new(5, &fields1, true, false).unwrap();
        let result2 = PackTopology::new(5, &fields2, true, false).unwrap();

        let mut bb = vec![32_u8; result1.total_minimal_len() + 132];

        assert!(set_id_conn(&mut bb, &result1, 213214, MyRole::Initiator).is_ok());

        assert!(set_id_conn(&mut bb, &result2, 213214, MyRole::Initiator).is_err());

        assert!(set_id_conn(&mut bb, &result1, 213214, MyRole::Initiator).is_ok());

        assert!(set_id_conn(&mut bb, &result1, (!0_u64) >> 8, MyRole::Initiator).is_err());

        assert!(set_id_conn(&mut bb, &result1, 100000, MyRole::Initiator).is_ok());

        assert!(get_id_conn(&bb, &result2).is_err());

        assert!(get_id_conn(&bb, &result1).is_ok());

        assert_eq!(
            get_id_conn(&bb, &result1).unwrap(),
            (100000, MyRole::Initiator)
        );

        assert!(set_id_conn(&mut bb, &result1, 13321, MyRole::Passive).is_ok());
        assert_eq!(
            get_id_conn(&bb, &result1).unwrap(),
            (13321, MyRole::Passive)
        );

        assert_eq!(
            get_id_conn(&bb, &result2),
            Err(WTypeErr::CompileFieldsErr("topology.idconn_slice is None"))
        );
        assert_eq!(
            get_id_conn(&bb[0..result1.idconn_slice().unwrap().1], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            set_id_conn(&mut bb, &result1, 2312123213213221221, MyRole::Initiator),
            Err(WTypeErr::PackageDamaged(
                "id_conn > wutils::len_byte_maximal_capacity_cheak(x.2).0 >>1"
            ))
        );
        assert_eq!(
            set_id_conn(
                &mut bb[0..result1.idconn_slice().unwrap().1],
                &result1,
                2,
                MyRole::Initiator
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
        assert_eq!(
            set_id_conn(&mut bb, &result2, 213214, MyRole::Initiator),
            Err(WTypeErr::CompileFieldsErr("topology.idconn_slice is None"))
        );
    }

    #[test]
    fn test_err_id_sender_recv() {
        let fields1 = vec![
            t0pology::PackFields::Counter(2),
            t0pology::PackFields::IdSender(4),
            t0pology::PackFields::IdReceiver(4),
        ];
        let fields2 = vec![
            t0pology::PackFields::Counter(2),
            t0pology::PackFields::IdReceiver(4),
            t0pology::PackFields::IdSender(4),
        ];

        let result1 = PackTopology::new(5, &fields1, true, false).unwrap();
        let result2 = PackTopology::new(5, &fields2, true, false).unwrap();

        let mut bb = vec![0; 100];

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_receiver_slice().unwrap().1], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_sender_slice().unwrap().1], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_receiver_slice().unwrap().1], &result2),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_sender_slice().unwrap().1], &result2),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_receiver_slice().unwrap().1],
                &result1,
                0,
                0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_sender_slice().unwrap().1],
                &result1,
                0,
                0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_receiver_slice().unwrap().1],
                &result2,
                0,
                0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_sender_slice().unwrap().1],
                &result2,
                0,
                0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
    }

    #[test]
    fn test_id_sender_recv() {
        let fields1 = vec![
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
            t0pology::PackFields::Counter(2),
            t0pology::PackFields::IdSender(4),
            t0pology::PackFields::IdReceiver(4),
        ];
        let fields2 = vec![
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
            t0pology::PackFields::Counter(4),
        ];

        let result1 = PackTopology::new(5, &fields1, true, false).unwrap();
        let result2 = PackTopology::new(5, &fields2, true, false).unwrap();

        let mut bb = vec![32_u8; result1.total_minimal_len() + 132];
        assert!(set_id_sender_and_recv(&mut bb, &result1, 213214, 213214).is_ok());
        assert!(set_id_sender_and_recv(&mut bb, &result2, 213214, 213214).is_err());
        assert!(
            set_id_sender_and_recv(&mut bb, &result1, !(312312_u64) << 16, !(111233_u64) << 8)
                .is_err()
        );
        assert!(set_id_sender_and_recv(&mut bb, &result1, 987654, 1234567).is_ok());
        assert!(get_id_sender_and_recv(&bb, &result1).is_ok());
        assert_eq!(
            get_id_sender_and_recv(&bb, &result1).unwrap(),
            (987654, 1234567)
        );

        assert_eq!(
            get_id_sender_and_recv(&bb, &result2),
            Err(WTypeErr::CompileFieldsErr(
                "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None"
            ))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..5], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
        assert_eq!(
            set_id_sender_and_recv(&mut bb, &result2, 987, 123),
            Err(WTypeErr::CompileFieldsErr(
                "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None"
            ))
        );
        assert_eq!(
            set_id_sender_and_recv(&mut bb[..5], &result1, 7, 1),
            Err(WTypeErr::LenSizeErr("pack len non correct"))
        );
    }

    #[test]
    fn full_module_test() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::IdSender(7),
            t0pology::PackFields::IdReceiver(7),
            t0pology::PackFields::Len(1),
            t0pology::PackFields::Counter(4),
            t0pology::PackFields::TTL(2),
            t0pology::PackFields::IdConnect(4),
            t0pology::PackFields::HeadCRC(t0pology::MAXIMAL_CRC_LEN),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::Nonce(16),
        ];

        let id_s = 0x2299FFAABBCC10;
        let id_r = 0x11223344556677;
        let id_c = 423423;
        let id_c_b = false;
        let ctr_m = 0x1122334455;
        let len = 234;
        let ttl = 432;

        let topology = PackTopology::new(50, &fields, true, false).unwrap();

        let mut pak = vec![0_u8; topology.total_minimal_len() + 100];
        let pack = &mut pak[..];
        //id R  S
        assert!(set_id_sender_and_recv(pack, &topology, 0x22, 0x1122334455667788).is_err());
        assert!(set_id_sender_and_recv(pack, &topology, 0x2299FFAABBCC1088, 0x11).is_err());
        assert!(
            set_id_sender_and_recv(pack, &topology, 0x2299FFAABBCC1088, 0x1122334455667788)
                .is_err()
        );
        assert!(set_id_sender_and_recv(pack, &topology, id_s, id_r).is_ok());

        assert!(get_id_sender_and_recv(pack, &topology).is_ok());

        assert_eq!(
            get_id_sender_and_recv(pack, &topology).unwrap(),
            (id_s, id_r)
        );
        //LEN
        assert!(set_len(pack, &topology, 0x10).is_err());
        {
            let mut pack = [0_u8; 256];
            assert!(set_len(&mut pack, &topology, 0x1000).is_err());
        }
        assert!(set_len(pack, &topology, 0x1000).is_ok());

        assert_eq!(get_len(pack, &topology).unwrap(), pack.len());

        //COUNTER
        assert!(set_counter(pack, &topology, ctr_m, PackType::FBack).is_ok());
        assert_eq!(
            set_get_head_crc(true, pack, &topology, dummy_crc_gen),
            Ok(false)
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 17, ctr_m - 30),
            Ok((ctr_m, PackType::FBack))
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 100, ctr_m - 31,),
            Ok((ctr_m, PackType::FBack))
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 123, ctr_m - 23,),
            Ok((ctr_m, PackType::FBack))
        );

        //TTL
        assert!(set_ttl(pack, &topology, 70000, 100000, true).is_err());

        assert!(set_ttl(pack, &topology, ttl, 1000, true).is_ok());
        assert_eq!(get_ttl(pack, &topology).unwrap(), ttl as u64);

        //IDC
        assert!(set_id_conn(pack, &topology, (!0_u32) as u64, MyRole::Initiator).is_err());
        assert!(set_id_conn(pack, &topology, id_c, MyRole::bit_to_state(id_c_b as u8)).is_ok());
        assert_eq!(
            get_id_conn(pack, &topology).unwrap(),
            (id_c, MyRole::bit_to_state(id_c_b as u8))
        );

        //us reash
        assert!(set_user_field(pack, &topology, ctr_m, len, dummy_usf).is_ok());

        /*
        IN FUTURE

        assert_eq!(
            set_head_byte(
                &mut pack,
                &topology,
                WPascageMode::FastEPVQeuqe,
                WKeyMode::Defauld,
                WPackageType::Data
            )
            .is_ok(),
            true
        )
        ;*/
        let cs = DumpEnc::new(&[1, 2, 3, 4, 45]).unwrap();
        if 1 == 1 {
            let mut ttt = vec![0; pack.len()];
            pack.clone_into(&mut ttt);

            let llen = pack.len();

            pack[topology.content_start_pos()..llen - topology.tag_len()].fill(0x71);
            let mut noncex = DumpNonser::new(&[0]).unwrap();

            let none_nonse: Option<&mut DumpNonser> = None;
            assert_ne!(
                crypt(
                    &mut ttt[..],
                    &topology,
                    Cryptlag::Encrypt,
                    &cs,
                    None,
                    none_nonse
                ),
                Ok(())
            );
            assert_ne!(
                crypt(
                    &mut ttt[..],
                    &topology,
                    Cryptlag::Encrypt,
                    &cs,
                    None,
                    Some(&mut noncex)
                ),
                Ok(())
            );
            let none_nonse: Option<&mut DumpNonser> = None;
            assert_ne!(
                crypt(
                    &mut ttt[..],
                    &topology,
                    Cryptlag::Encrypt,
                    &cs,
                    Some(ctr_m),
                    none_nonse
                ),
                Ok(())
            );
            println!("before H {:?}", &pack[..topology.encrypt_start_pos()]);
            println!();
            println!("before D {:?}", &pack[topology.encrypt_start_pos()..]);
            println!();
            println!();

            assert_eq!(
                crypt(
                    pack,
                    &topology,
                    Cryptlag::Encrypt,
                    &cs,
                    Some(ctr_m),
                    Some(&mut noncex)
                ),
                Ok(())
            );
            println!("after H {:?}", &pack[..topology.encrypt_start_pos()]);
            println!();
            println!("after D {:?}", &pack[topology.encrypt_start_pos()..]);
            println!();
            println!();
        }
        let tttttlls = topology.ttl_slice().unwrap_or((9999999999, 9999999999, 0));
        let crsrsr = topology
            .head_crc_slice()
            .unwrap_or((9999999999, 9999999999, 0));
        let mut noncex = DumpNonser::new(&[0]).unwrap();
        for x in 0..topology.encrypt_start_pos() {
            let mut t = vec![0; pack.len()];
            for x in t.iter_mut().zip(pack.iter()) {
                *x.0 = *x.1;
            }
            t[x] = !t[x];

            if (x >= tttttlls.0 && x < tttttlls.1) || (x >= crsrsr.0 && x < crsrsr.1) {
                assert_eq!(
                    crypt(
                        &mut t,
                        &topology,
                        Cryptlag::Decrypt,
                        &cs,
                        Some(ctr_m),
                        Some(&mut noncex)
                    ),
                    Ok(()),
                    "pos: {}",
                    x
                );
            } else {
                assert_ne!(
                    crypt(
                        &mut t,
                        &topology,
                        Cryptlag::Decrypt,
                        &cs,
                        Some(ctr_m),
                        Some(&mut noncex)
                    ),
                    Ok(()),
                    "pos: {}",
                    x
                );
            }
        }

        //let ctr_m = 0x1122334415;

        for x in topology.encrypt_start_pos()..pack.len() {
            let mut t = vec![0; pack.len()];
            for x in t.iter_mut().zip(pack.iter()) {
                *x.0 = *x.1;
            }
            t[x] = !t[x];
            assert_ne!(
                crypt(
                    &mut t,
                    &topology,
                    Cryptlag::Decrypt,
                    &cs,
                    Some(ctr_m),
                    Some(&mut noncex)
                ),
                Ok(())
            );
        }

        //CRC
        assert!(!set_get_head_crc(true, pack, &topology, dummy_crc_gen).unwrap());
        assert!(set_get_head_crc(true, pack, &topology, dummy_crc_gen).unwrap());

        let mut last_after_head = vec![0; topology.encrypt_start_pos()];

        pack[0..topology.encrypt_start_pos()].clone_into(&mut last_after_head);

        for x in 0..topology.encrypt_start_pos() {
            let mut t = vec![0; pack.len()];
            for x in t.iter_mut().zip(pack.iter()) {
                *x.0 = *x.1;
            }
            t[x] = !t[x];
            assert!(!set_get_head_crc(true, &mut t[..], &topology, dummy_crc_gen).unwrap());
        }

        for x in topology.encrypt_start_pos()..pack.len() {
            let mut t = vec![0; pack.len()];
            for x in t.iter_mut().zip(pack.iter()) {
                *x.0 = *x.1;
            }
            t[x] = !t[x];
            assert!(set_get_head_crc(true, &mut t[..], &topology, dummy_crc_gen).unwrap());
        }

        for (i, (&x, &y)) in last_after_head
            .iter()
            .zip(pack[..topology.encrypt_start_pos()].iter())
            .enumerate()
        {
            assert_eq!(x, y, "pos:{i}")
        }

        //testt
        assert_eq!(
            crypt(
                pack,
                &topology,
                Cryptlag::Decrypt,
                &cs,
                Some(ctr_m),
                Some(&mut noncex)
            ),
            Ok(())
        );

        println!("Dfter H {:?}", &pack[..topology.encrypt_start_pos()]);
        println!();
        println!("Dfter D {:?}", &pack[topology.encrypt_start_pos()..]);
        println!();
        println!();

        assert_eq!(
            pack[topology.content_start_pos()..pack.len() - topology.tag_len()],
            vec![0x71; pack.len() - (topology.content_start_pos() + topology.tag_len())]
        );
        /*
        IN FUTUTE


        assert_eq!(
            get_head_byte(&pack, &topology),
            Ok((
                WPascageMode::FastEPVQeuqe,
                WKeyMode::Defauld,
                WPackageType::Data
            ))
        );
        */
        assert_eq!(
            get_id_conn(pack, &topology).unwrap(),
            (id_c, MyRole::bit_to_state(id_c_b as u8))
        );

        assert_eq!(
            set_get_head_crc(true, pack, &topology, dummy_crc_gen),
            Ok(true)
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 10, ctr_m - 11),
            Ok((ctr_m, PackType::FBack))
        );
        assert_eq!(get_ttl(pack, &topology).unwrap(), ttl as u64);
        assert_eq!(
            get_id_sender_and_recv(pack, &topology).unwrap(),
            (id_s, id_r)
        );
        assert_eq!(get_len(pack, &topology).unwrap(), pack.len());
    }

    //============================================================================================================helper functions for testing====================
    //============================================================================================================helper functions for testing====================
    //============================================================================================================helper functions for testing====================
    //============================================================================================================helper functions for testing====================

    fn dummy_usf(
        field: &mut [u8],
        counter: u64,
        full_len: usize,
        i: usize,
    ) -> Result<(), &'static str> {
        let teto = [counter as u8, full_len as u8, i as u8];
        for (x, t) in field.iter_mut().zip(teto.iter().cycle()) {
            *x = *t;
        }
        Ok(())
    }

    fn dummy_crc_gen(inp: &[u8], crc: &mut [u8]) -> Result<(), &'static str> {
        DumpCfcser::new(&[0]).unwrap().gen_crc(inp, crc)?;

        Ok(())
    }
}
