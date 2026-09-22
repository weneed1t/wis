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

use crate::t0pology::PackTopology;
use crate::w1types::*;
use crate::{checked_cast, t0pology, w1utils};

/// Copies the provided payload data into the designated payload section of a pre-allocated packet buffer.
///
/// # Arguments
/// * `pack` - The mutable byte slice of the entire network packet, including headers and tags.
/// * `payload` - The raw data slice to be written into the packet.
/// * `topology` - The structural map of the packet used to locate boundaries.
///
/// # Errors
/// Returns an error if:
/// * The packet size is too small to fit the security tag.
/// * The calculated payload boundaries are invalid or out of bounds.
/// * The size of the provided `payload` does not exactly match the available space in the packet.
pub fn set_payload(
    pack: &mut [u8],
    payload: &[u8],
    topology: &PackTopology,
) -> Result<(), WTypeErr> {
    let end_pos = pack
        .len()
        .checked_sub(topology.tag_len())
        .ok_or_else(|| WTypeErr::LenSizeErr("pack len is less than tag_len".to_string()))?;

    let start_pos = topology.encrypt_start_pos();
    if start_pos > end_pos {
        return Err(WTypeErr::LenSizeErr(
            "encrypt_start_pos exceeds end_pos".to_string(),
        ));
    }

    let in_me = pack.get_mut(start_pos..end_pos).ok_or_else(|| {
        WTypeErr::LenSizeErr("Calculated payload range is out of pack bounds".to_string())
    })?;

    if in_me.len() != payload.len() {
        return Err(WTypeErr::CompileFieldsErr(format!(
            "Payload length mismatch: expected {}, got {}",
            in_me.len(),
            payload.len()
        )));
    }

    in_me.copy_from_slice(payload);
    Ok(())
}

/// Extracts the payload data from a packet buffer and appends it to a reusable vector.
///
/// # Arguments
/// * `pack` - The immutable byte slice of the network packet to read from.
/// * `pre_created_vec` - A mutable vector where the extracted payload will be stored.
///                       Its previous contents are cleared before copying.
/// * `topology` - The structural map of the packet used to locate boundaries.
///
/// # Errors
/// Returns an error if:
/// * The packet size is too small to fit the security tag.
/// * The calculated payload boundaries are invalid or out of bounds.
pub fn get_payload(
    pack: &[u8],
    pre_created_vec: &mut Vec<u8>,
    topology: &PackTopology,
) -> Result<(), WTypeErr> {
    pre_created_vec.clear();

    let end_pos = pack
        .len()
        .checked_sub(topology.tag_len())
        .ok_or_else(|| WTypeErr::LenSizeErr("pack len is less than tag_len".to_string()))?;

    let start_pos = topology.encrypt_start_pos();
    if start_pos > end_pos {
        return Err(WTypeErr::LenSizeErr(
            "encrypt_start_pos exceeds end_pos".to_string(),
        ));
    }

    let in_me = pack.get(start_pos..end_pos).ok_or_else(|| {
        WTypeErr::LenSizeErr("Calculated payload range is out of pack bounds".to_string())
    })?;

    pre_created_vec.reserve(in_me.len());
    pre_created_vec.extend_from_slice(in_me);

    Ok(())
}

///get tricky byte
pub fn get_tricky_byte(pack: &[u8], topology: &PackTopology) -> Result<u8, WTypeErr> {
    if let Some(star) = topology.tricky_byte() {
        Ok(*pack.get(star).ok_or(WTypeErr::LenSizeErr(
            "tricky_byte pack len so small".to_string(),
        ))?)
    } else {
        Err(WTypeErr::CompileFieldsErr(
            "tricky_byte not in PackTopology".to_string(),
        ))
    }
}

///set tricky byte
pub fn set_tricky_byte(
    pack: &mut [u8],
    topology: &PackTopology,
    tricky_byte: u8,
) -> Result<(), WTypeErr> {
    if let Some(star) = topology.tricky_byte() {
        let temp = pack
            .get_mut(star)
            .ok_or(WTypeErr::LenSizeErr("pack len non correct".to_string()))?;
        *temp = tricky_byte;
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr(
        "tricky_byte not in PackTopology".to_string(),
    ))
}

/// computes and validates the header crc checksum using a user-provided crc function
/// takes mutable packet data, packet topology, and a crc function: (&[u8], &mut [u8]) ->
/// Result<(), String> the header is defined as bytes from start of packet to
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
    F: FnMut(&[u8], &mut [u8]) -> Result<(), String>,
{
    if let Some((start, end, len)) = topology.head_crc_slice() {
        if len > t0pology::MAXIMAL_CRC_LEN {
            return Err(WTypeErr::LenSizeErr(
                "len >  t2page::MAXIMAL_CRC_LEN".to_string(),
            ));
        }

        let encrypt_start_pos = topology.encrypt_start_pos();
        if pack.len() <= encrypt_start_pos || pack.len() <= end {
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }

        let head_end = encrypt_start_pos;
        let head = pack
            .get_mut(..head_end)
            .ok_or(WTypeErr::LenSizeErr("pack len non correct".to_string()))?;

        let mut temp_old = [0_u8; t0pology::MAXIMAL_CRC_LEN];
        let mut temp_new = [0_u8; t0pology::MAXIMAL_CRC_LEN];

        {
            let head_sl = head
                .get_mut(start..end)
                .ok_or(WTypeErr::LenSizeErr("invalid crc slice range".to_string()))?;
            let temp_old_slice = temp_old
                .get_mut(..len)
                .ok_or(WTypeErr::LenSizeErr("temp_old slice error".to_string()))?;
            temp_old_slice.copy_from_slice(head_sl);
            head_sl.fill(0);
        }

        let temp_new_slice = temp_new
            .get_mut(..len)
            .ok_or(WTypeErr::LenSizeErr("temp_new slice error".to_string()))?;
        //
        crcfn(head, temp_new_slice).map_err(WTypeErr::PackageDamaged)?;
        //
        let target_slice = head
            .get_mut(start..end)
            .ok_or(WTypeErr::LenSizeErr("invalid crc slice range".to_string()))?;
        let source_slice = if create_new_crc_summ {
            temp_new
                .get(..len)
                .ok_or(WTypeErr::LenSizeErr("temp_new get error".to_string()))?
        } else {
            temp_old
                .get(..len)
                .ok_or(WTypeErr::LenSizeErr("temp_old get error".to_string()))?
        };

        target_slice.copy_from_slice(source_slice);

        let new_slice = temp_new
            .get(..len)
            .ok_or(WTypeErr::LenSizeErr("temp_new compare error".to_string()))?;
        let old_slice = temp_old
            .get(..len)
            .ok_or(WTypeErr::LenSizeErr("temp_old compare error".to_string()))?;

        return Ok(new_slice == old_slice);
    }

    Err(WTypeErr::CompileFieldsErr(
        "head_crc_slice not in PackTopology".to_string(),
    ))
}

fn ttl_corr(ttl: &Ttl, ttl_t: &mut u64) -> Result<(), WTypeErr> {
    if *ttl_t > ttl.max() {
        if ttl.forced_pruning() {
            *ttl_t = ttl.max();
        } else {
            return Err(WTypeErr::PackageDamaged(
                "TTL in pack largest of ttl.max()".to_string(),
            ));
        }
    }
    if *ttl_t == 0 {
        return Err(WTypeErr::PackageDamaged("TTL pack is 0".to_string()));
    }

    Ok(())
}

/// Updates the TTL field in the packet header using the provided Ttl policy.
///
/// # Parameters
/// - `pack`        : mutable packet bytes.
/// - `topology`    : defines the TTL slice (start, end, length).
/// - `ttl`         : configuration (max, edit, start, forced_pruning).
/// - `is_start_ttl`: if true, initialises to `ttl.start()`; otherwise reads current,
/// applies `ttl_corr`, adds `ttl.edit()`, normalises again.
///
/// # Returns
/// `Ok(final_ttl)` or `Err(WTypeErr)`.
///
/// # Steps
/// 1. Locate TTL slice; validate packet length.
/// 2. Compute `temp`:
///    - if `is_start_ttl` → `ttl.start()`
///    - else → read u64 → `ttl_corr()` → saturating add `ttl.edit()`
/// 3. Apply `ttl_corr()` to `temp` (enforces ≤ max, non‑zero, pruning).
/// 4. Verify `temp` fits in the field’s byte capacity (1–8 bytes).
/// 5. Write back and return `temp`.
///
/// # Errors
/// - `LenSizeErr`       : invalid slice or packet too short.
/// - `WorkTimeErr`      : `edit` exceeds `max`, or capacity overflow.
/// - `PackageDamaged`   : zero TTL, exceeds max without pruning, or arithmetic overflow.
/// - `CompileFieldsErr` : TTL slice not defined in topology.
///
/// # Remarks
/// - Centralises TTL parameters into a single struct for cleaner interface.
/// - `ttl_corr()` ensures invariants (non‑zero, ≤ max) at every stage.
pub fn set_ttl(
    pack: &mut [u8],
    topology: &PackTopology,
    ttl: &Ttl,
    is_start_ttl: bool,
) -> Result<u64, WTypeErr> {
    if let Some((start, end, len)) = topology.ttl_slice() {
        let ttl_slice = pack
            .get_mut(start..end)
            .ok_or(WTypeErr::LenSizeErr("invalid ttl slice range".to_string()))?;

        let mut temp = if is_start_ttl {
            ttl.start()
        } else {
            let mut ttl_raw = w1utils::bytes_to_u64(ttl_slice).map_err(WTypeErr::WorkTimeErr)?;

            ttl_corr(ttl, &mut ttl_raw)?;

            w1utils::add_u64_i64(ttl_raw, ttl.edit(), true).map_err(WTypeErr::PackageDamaged)?
        };

        ttl_corr(ttl, &mut temp)?;

        if temp > w1utils::len_byte_maximal_capacity_check(len).0 {
            return Err(WTypeErr::PackageDamaged(
                "ttl_is TTL is more than capable of accommodating the TTL_SLICE field".to_string(),
            ));
        }

        w1utils::u64_to_1_8bytes(temp, ttl_slice).map_err(WTypeErr::WorkTimeErr)?;

        return Ok(temp);
    }
    Err(WTypeErr::CompileFieldsErr(
        " set_ttl not in  PackTopology".to_string(),
    ))
}

///
/// get_ttl reads the current ttl value from the packet header
/// returns Ok(u64) if ttl field exists and is valid, Err otherwise
/// reads from the slice defined in topology; parsing uses bytes_to_u64
/// should be called on unmodified packet data before any ttl updates for accurate
/// inspection both functions require ttl_slice to be properly defined in PackTopology
/// during construction
pub fn get_ttl(pack: &[u8], topology: &PackTopology, ttl: &Ttl) -> Result<u64, WTypeErr> {
    if let Some((start, end, _)) = topology.ttl_slice() {
        if pack.len() <= end {
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }
        let ttl_slice = pack
            .get(start..end)
            .ok_or(WTypeErr::LenSizeErr("invalid ttl slice range".to_string()))?;

        let mut ttl_u64 = w1utils::bytes_to_u64(ttl_slice).map_err(WTypeErr::WorkTimeErr)?;

        ttl_corr(ttl, &mut ttl_u64)?;

        return Ok(ttl_u64);
    }
    Err(WTypeErr::CompileFieldsErr(
        " set_ttl not in  PackTopology".to_string(),
    ))
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
pub fn set_len(pack: &mut [u8], topology: &PackTopology, mtu: &usize) -> Result<(), WTypeErr> {
    let sls = topology.len_slice().ok_or(WTypeErr::CompileFieldsErr(
        " topology.len_slice() is none".to_string(),
    ))?;

    if pack.len() <= sls.1 {
        return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
    }

    let plen = pack.len();

    if plen > *mtu {
        return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
    }

    if plen
        > checked_cast!(w1utils::len_byte_maximal_capacity_check(sls.2).0 => usize, err WTypeErr::CompileFieldsErr("len of len slice into to 64 is overflow".to_string() ))?
    {
        return Err(WTypeErr::LenSizeErr(
            "pack.len()> len_byte_maximal_capacity_cheak(len)".to_string(),
        ));
    }

    let len_slice = pack
        .get_mut(sls.0..sls.1)
        .ok_or(WTypeErr::LenSizeErr("invalid len slice range".to_string()))?;
    w1utils::u64_to_1_8bytes(
        checked_cast!(plen => u64, err WTypeErr::WorkTimeErr("plen to u64 conversion failed".to_string() ))?,
        len_slice,
    )
    .map_err(WTypeErr::WorkTimeErr)?;

    Ok(())
}
/// get_len reads the declared packet length from the header
/// takes immutable packet data and topology, returns Result<usize, String>
/// extracts the length value from the slice defined by len_slice in topology
/// decodes bytes via bytes_to_u64 and converts to usize; returns error on parsing failure
/// useful for determining packet boundaries during parsing or validation
/// both functions assume the length field is unencrypted and located in the packet header
pub fn get_len(pack: &[u8], topology: &PackTopology) -> Result<usize, WTypeErr> {
    let sls = topology.len_slice().ok_or(WTypeErr::CompileFieldsErr(
        " topology.len_slice() is none".to_string(),
    ))?;
    if pack.len() <= sls.1 {
        return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
    }
    let len_slice = pack
        .get(sls.0..sls.1)
        .ok_or(WTypeErr::LenSizeErr("invalid len slice range".to_string()))?;
    Ok(
        checked_cast!(w1utils::bytes_to_u64(len_slice).map_err(WTypeErr::WorkTimeErr)? => usize, err WTypeErr::WorkTimeErr("u64 to usize conversion failed".to_string() ))?,
    )
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
    id_conn: &u64,
    role: &MyRole,
) -> Result<(), WTypeErr> {
    if let Some(x) = topology.idconn_slice() {
        if pack.len() <= x.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }
        if *id_conn > w1utils::len_byte_maximal_capacity_check(x.2).0 >> 1 {
            return Err(WTypeErr::PackageDamaged(
                "id_conn > wutils::len_byte_maximal_capacity_cheak(x.2).0 >>1".to_string(),
            ));
        }
        let id_slice = pack.get_mut(x.0..x.1).ok_or(WTypeErr::LenSizeErr(
            "invalid id_conn slice range".to_string(),
        ))?;
        let combined = (id_conn << 1)
            | checked_cast!(role.sate_to_bit() => u64, err WTypeErr::WorkTimeErr("role.sate_to_bit conversion to u64 failed".to_string() ))?;
        w1utils::u64_to_1_8bytes(combined, id_slice).map_err(WTypeErr::WorkTimeErr)?;
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr(
        "topology.idconn_slice is None".to_string(),
    ))
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
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }
        let id_slice = pack.get(x.0..x.1).ok_or(WTypeErr::LenSizeErr(
            "invalid id_conn slice range".to_string(),
        ))?;
        let reta = w1utils::bytes_to_u64(id_slice).map_err(WTypeErr::WorkTimeErr)?;
        return Ok((
            reta >> 1,
            MyRole::bit_to_state(
                checked_cast!(reta & 1 => u8, expect "bit to u8 conversion failed"),
            ),
        ));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.idconn_slice is None".to_string(),
    ))
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
    id_sender: &u64,
    id_recv: &u64,
) -> Result<(), WTypeErr> {
    if let (Some(x_s), Some(x_r)) = (
        topology.id_of_sender_slice(),
        topology.id_of_receiver_slice(),
    ) {
        let maximal = w1utils::len_byte_maximal_capacity_check(x_s.2).0;
        if pack.len() <= x_s.1 || pack.len() <= x_r.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }
        if maximal < *id_recv || maximal < *id_sender {
            return Err(WTypeErr::PackageDamaged(
                "maxim < id_recv OR maxim < id_sender".to_string(),
            ));
        }
        if *id_recv == *id_sender {
            return Err(WTypeErr::WorkTimeErr(
                "err id_recv ==  id_sender".to_string(),
            ));
        }

        let recv_slice = pack.get_mut(x_r.0..x_r.1).ok_or(WTypeErr::LenSizeErr(
            "invalid receiver id slice range".to_string(),
        ))?;
        w1utils::u64_to_1_8bytes(*id_recv, recv_slice).map_err(WTypeErr::WorkTimeErr)?;

        let sender_slice = pack.get_mut(x_s.0..x_s.1).ok_or(WTypeErr::LenSizeErr(
            "invalid sender id slice range".to_string(),
        ))?;
        w1utils::u64_to_1_8bytes(*id_sender, sender_slice).map_err(WTypeErr::WorkTimeErr)?;

        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr(
        "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None".to_string(),
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
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }

        let sender_slice = pack.get(x_s.0..x_s.1).ok_or(WTypeErr::LenSizeErr(
            "invalid sender id slice range".to_string(),
        ))?;
        let receiver_slice = pack.get(x_r.0..x_r.1).ok_or(WTypeErr::LenSizeErr(
            "invalid receiver id slice range".to_string(),
        ))?;

        return Ok((
            w1utils::bytes_to_u64(sender_slice).map_err(WTypeErr::WorkTimeErr)?,
            w1utils::bytes_to_u64(receiver_slice).map_err(WTypeErr::WorkTimeErr)?,
        ));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None".to_string(),
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
    countr: &u64,
    my_type: PackType,
) -> Result<(u64, u64), WTypeErr> {
    if let Some(x) = topology.counter_slice() {
        if pack.len() <= x.1 {
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }
        let max_cap = w1utils::len_byte_maximal_capacity_check(x.2).0 >> 1;

        let pack_ctr = checked_cast!((max_cap & countr) << 1 => u64, err WTypeErr::WorkTimeErr("pack_ctr conversion failed".to_string() ))?
            | checked_cast!(my_type.sate_to_bit() => u64, err WTypeErr::WorkTimeErr("my_type conversion failed".to_string() ))?;

        let counter_slice = pack.get_mut(x.0..x.1).ok_or(WTypeErr::LenSizeErr(
            "invalid counter slice range".to_string(),
        ))?;
        w1utils::u64_to_1_8bytes(pack_ctr, counter_slice).map_err(WTypeErr::WorkTimeErr)?;

        return Ok((pack_ctr, max_cap));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.counter_slice() is none".to_string(),
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
            return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
        }

        let counter_slice = pack.get(x.0..x.1).ok_or(WTypeErr::LenSizeErr(
            "invalid counter slice range".to_string(),
        ))?;
        let ctr_in_pack = w1utils::bytes_to_u64(counter_slice).map_err(WTypeErr::WorkTimeErr)?;

        let (max_cap, _) = w1utils::len_byte_maximal_capacity_check(x.2);
        let max_cap = max_cap >> 1;
        let pack_ctr = (ctr_in_pack >> 1) & max_cap;
        let my_type = PackType::bit_to_state(
            checked_cast!(ctr_in_pack & 1 => u8, expect "bit to u8 conversion failed"),
        );

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
                            .ok_or(WTypeErr::WorkTimeErr("overflow max_cap+1".to_string()))?,
                    )
                    .ok_or(WTypeErr::WorkTimeErr(
                        "overflow real_countr+OLDER BIT".to_string(),
                    ))?
            } else {
                real_countr
            },
            my_type,
        ));
    }
    Err(WTypeErr::CompileFieldsErr(
        "topology.counter_slice() is none".to_string(),
    ))
}

/// set_user_field generates and fills the user-defined field (aka "trash field") in the
/// packet header takes mutable packet data, topology, a counter value, full packet
/// length, and a user-provided generator function the generator function: fn(&mut [u8],
/// u64, usize, usize) -> Result<(), String> is called with:<br>
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
    counter: &u64,
    full_len: &usize,
    mut field_gen: F,
) -> Result<(), WTypeErr>
where
    F: FnMut(&mut [u8], &u64, &usize, &usize, &PackTopology) -> Result<(), String>,
{
    if let Some(vecta_trash) = topology.trash_content_slice() {
        for (i, (start, end, _)) in vecta_trash.iter().enumerate() {
            if pack.len() <= *end {
                return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
            }

            let field_slice = pack.get_mut(*start..*end).ok_or(WTypeErr::LenSizeErr(
                "invalid user field slice range".to_string(),
            ))?;
            field_gen(field_slice, counter, full_len, &i, topology)
                .map_err(WTypeErr::PackageDamaged)?;
        }
        return Ok(());
    }

    Err(WTypeErr::CompileFieldsErr(
        "user_field not in PackTopology".to_string(),
    ))
}

///set_headbyte is needed to set the value of topology.head_byte_pos() equal to head_byte
pub fn set_headbyte(
    pack: &mut [u8],
    topology: &PackTopology,
    head_byte: HeadByteStruct,
) -> Result<(), WTypeErr> {
    if pack.len() <= topology.head_byte_pos() {
        return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
    }

    let head_byte_in_slice = pack
        .get_mut(topology.head_byte_pos())
        .ok_or(WTypeErr::LenSizeErr(
            "invalid headbyte slice range".to_string(),
        ))?;

    *head_byte_in_slice = head_byte.to_byte();

    Ok(())
}

///set_headbyte is needed to get the value from topology.head_byte_pos() and return the HeadByteStruct
pub fn get_headbyte(pack: &mut [u8], topology: &PackTopology) -> Result<HeadByteStruct, WTypeErr> {
    if pack.len() <= topology.head_byte_pos() {
        return Err(WTypeErr::LenSizeErr("pack len non correct".to_string()));
    }

    let head_byte_in_slice = pack
        .get(topology.head_byte_pos())
        .ok_or(WTypeErr::LenSizeErr(
            "invalid headbyte slice range".to_string(),
        ))?;

    Ok(HeadByteStruct::from_byte(*head_byte_in_slice))
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
pub fn crypt<Tencrer, Tnoncer>(
    pack: &mut [u8],
    topology: &PackTopology,
    enc_mode: Cryptlag,
    enc_struct: &mut Tencrer,
    countr: Option<&u64>,
    nonce_gener: Option<&mut Tnoncer>,
) -> Result<(), WTypeErr>
where
    Tencrer: EncWis,
    Tnoncer: Noncer,
{
    let p_len = pack.len();

    if p_len < topology.overhead_len() {
        return Err(WTypeErr::LenSizeErr(
            "pack.len()< topology.total_minimal_len()".to_string(),
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
        let ttl_slice = pack
            .get(s..e)
            .ok_or(WTypeErr::LenSizeErr("invalid ttl slice range".to_string()))?;
        let temp_ttl_slice = ttl_vec_temp_mem
            .get_mut(..len)
            .ok_or(WTypeErr::LenSizeErr("temp ttl slice error".to_string()))?;
        temp_ttl_slice.copy_from_slice(ttl_slice);

        let ttl_mut_slice = pack
            .get_mut(s..e)
            .ok_or(WTypeErr::LenSizeErr("invalid ttl slice range".to_string()))?;
        ttl_mut_slice.fill(0);
    }

    if let Some((s, e, len)) = topology.head_crc_slice() {
        let crc_slice = pack
            .get(s..e)
            .ok_or(WTypeErr::LenSizeErr("invalid crc slice range".to_string()))?;
        let temp_crc_slice = crc_vec_temp_mem
            .get_mut(..len)
            .ok_or(WTypeErr::LenSizeErr("temp crc slice error".to_string()))?;
        temp_crc_slice.copy_from_slice(crc_slice);

        let crc_mut_slice = pack
            .get_mut(s..e)
            .ok_or(WTypeErr::LenSizeErr("invalid crc slice range".to_string()))?;
        crc_mut_slice.fill(0);
    }

    crypt_procress(is_encrypt, topology, p_len, enc_struct, pack, countr)?;

    if let Some((s, e, len)) = topology.ttl_slice() {
        let ttl_mut_slice = pack
            .get_mut(s..e)
            .ok_or(WTypeErr::LenSizeErr("invalid ttl slice range".to_string()))?;
        let temp_ttl_slice = ttl_vec_temp_mem
            .get(..len)
            .ok_or(WTypeErr::LenSizeErr("temp ttl slice error".to_string()))?;
        ttl_mut_slice.copy_from_slice(temp_ttl_slice);
    }

    if let Some((s, e, len)) = topology.head_crc_slice() {
        let crc_mut_slice = pack
            .get_mut(s..e)
            .ok_or(WTypeErr::LenSizeErr("invalid crc slice range".to_string()))?;
        let temp_crc_slice = crc_vec_temp_mem
            .get(..len)
            .ok_or(WTypeErr::LenSizeErr("temp crc slice error".to_string()))?;
        crc_mut_slice.copy_from_slice(temp_crc_slice);
    }

    Ok(())
}

fn crypt_procress<Tencrer: EncWis>(
    is_encrypt: bool,
    topology: &PackTopology,
    p_len: usize,
    enc_struct: &Tencrer,
    pack: &mut [u8],
    countr: Option<&u64>,
) -> Result<(), WTypeErr> {
    let enc_start = topology.encrypt_start_pos();
    let enc_end = p_len
        .checked_sub(topology.tag_len())
        .ok_or(WTypeErr::WorkTimeErr(
            "p_len - topology.tag_len() = overflow".to_string(),
        ))?;

    // Previously, a check was performed to ensure that p_len < topology.total_minimal_len(),
    // which means that the packet length is large enough so that the operation of splitting
    // into slays does not cause panic.
    let (free_data, mac_only) = pack
        .split_at_mut_checked(enc_end)
        .ok_or(WTypeErr::WorkTimeErr(
            "enc_end is bigest that pack.len()".to_string(),
        ))?;
    let (head, to_enc_only) =
        free_data
            .split_at_mut_checked(enc_start)
            .ok_or(WTypeErr::WorkTimeErr(
                "enc_start bigest that free_data".to_string(),
            ))?;

    let nonce = if let Some(x) = topology.nonce_slice() {
        Some(head.get(x.0..x.1).ok_or(WTypeErr::LenSizeErr(
            "invalid nonce slice range".to_string(),
        ))?)
    } else {
        None
    };

    let counter_val = countr.unwrap_or(&0); //<-

    if is_encrypt {
        enc_struct
            .encrypt(head, to_enc_only, mac_only, counter_val, nonce)
            .map_err(WTypeErr::WorkTimeErr)?;
    } else if enc_struct
        .decrypt(head, to_enc_only, mac_only, counter_val, nonce)
        .map_err(WTypeErr::WorkTimeErr)?
        .is_damaged()
    {
        return Err(WTypeErr::PackageDamaged(
            "error return during decryption associated with packet corruption".to_string(),
        ));
    }
    Ok(())
}

/// Validates and prepares encryption data: generates a Nonce and/or verifies the counter.
/// Valid combinations:
/// - Nonce + Counter: valid
/// - Counter only: valid
/// - Nonce only: valid
/// - Neither: invalid
fn if_encrypt<Tnoncer: Noncer>(
    topology: &PackTopology,
    pack: &mut [u8],
    nonce_gener: Option<&mut Tnoncer>,
    countr: Option<&u64>,
) -> Result<(), WTypeErr> {
    let nonce_range = topology.nonce_slice();
    let counter_range = topology.counter_slice();

    // 1. Early exit: Check if topology is valid for encryption
    if nonce_range.is_none() && counter_range.is_none() {
        return Err(WTypeErr::CompileFieldsErr(
            "Invalid combination: topology must contain either a counter field, a nonce field, or \
             both. This topology has neither."
                .to_string(),
        ));
    }

    // 2. Handle Nonce generation if required by topology
    if let Some((start, end, _)) = nonce_range {
        let nonce_slice = pack.get_mut(start..end).ok_or(WTypeErr::LenSizeErr(
            "invalid nonce slice range".to_string(),
        ))?;

        nonce_gener
            .ok_or(WTypeErr::CompileFieldsErr(
                "nonce_gener required".to_string(),
            ))?
            .set_nonce(nonce_slice)
            .map_err(WTypeErr::WorkTimeErr)?;
    }

    // 3. Ensure counter value is provided if topology expects a counter
    if counter_range.is_some() && countr.is_none() {
        return Err(WTypeErr::CompileFieldsErr(
            "counter_field required".to_string(),
        ));
    }

    Ok(())
}

///(array(head fields len + headbyte len + payload len+ tag len),(payload start pos, payload endpos) )
pub fn pre_alloc(
    topology: &PackTopology,
    mtu: usize,
    payloadlen: usize,
    fill: u8,
) -> Result<(Box<[u8]>, (usize, usize)), WTypeErr> {
    let len_pack = topology
        .overhead_len()
        .checked_add(payloadlen)
        .ok_or(WTypeErr::LenSizeErr(
            "overflow payloadlen + minimal_len()".to_string(),
        ))?;

    let remaining = len_pack
        .checked_sub(topology.tag_len())
        .ok_or(WTypeErr::WorkTimeErr(
            "subtraction underflow: len_pack < topology.tag_len()".to_string(),
        ))?;
    Ok((
        vec![
            fill;
            if len_pack > mtu {
                return Err(WTypeErr::LenSizeErr("len_pack > mtu".to_string()));
            } else {
                len_pack
            }
        ]
        .into_boxed_slice(),
        (topology.content_start_pos(), remaining),
    ))
}

#[cfg(test)]
mod tests_prealocc {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::t0pology::PackFields;
    #[test]
    fn test_prealoc() {
        let mkd = [13, 7, 6, 8];
        let fields = vec![
            //t2page::PackFields::HeadByte,
            PackFields::UserField(mkd[0]),
            PackFields::Counter(mkd[1]),
            PackFields::IdConnect(mkd[2]),
            PackFields::HeadCRC(mkd[3]),
        ];

        let result = PackTopology::new(19, &fields, true, false).unwrap();

        //let mut temp = pre_alloc(&result, 1000, 500).unwrap();
        let total: usize = mkd.iter().sum();

        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 50, 0),
            Err(WTypeErr::LenSizeErr("len_pack > mtu".to_string()))
        );
        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 49, 0),
            Ok((
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
                .into_boxed_slice(),
                (35usize, 84usize)
            ))
        );

        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 49, 99),
            Ok((
                vec![
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99
                ]
                .into_boxed_slice(),
                (35usize, 84usize)
            ))
        );

        assert_eq!(
            pre_alloc(&result, !0_usize, (!0_usize) - 1, 0),
            Err(WTypeErr::LenSizeErr(
                "overflow payloadlen + minimal_len()".to_string()
            ))
        );

        let mut t = pre_alloc(&result, 100000, 43, 0).unwrap();
        t.0[t.1.0..t.1.1].fill(1);
        let count = t.0.iter().filter(|&&element| element == 1).count();
        let count0 = t.0.iter().take_while(|&&x| x == 0).count();

        assert_eq!(count, 43);
        assert_eq!(count0, result.total_head_slice().2 + 1);

        println!("{:?}   /n{} /n {}", t.0, count, count0);
    }
}

//##=============================================================TESTS====================================TESTS===================////=============
//##=============================================================TESTS====================================TESTS====================////=============

#[cfg(test)]
mod tests {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::t1dumb_srct::*;

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

        let mut tets1 = [0; 100];

        assert_eq!(set_tricky_byte(&mut tets1[..], &result, 7), Ok(()));

        assert_eq!(
            set_tricky_byte(&mut tets1[..100 - 60], &result, 7),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(get_tricky_byte(&tets1[..], &result), Ok(7));

        assert_eq!(
            get_tricky_byte(&tets1[..100 - 60], &result),
            Err(WTypeErr::LenSizeErr(
                "tricky_byte pack len so small".to_string()
            ))
        );

        for i in 0..15 {
            set_tricky_byte(&mut tets1[..], &result, i).unwrap();

            assert_eq!(get_tricky_byte(&tets1[..], &result), Ok(i));
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
            get_tricky_byte(&tets1[..100 - 60], &result),
            Err(WTypeErr::CompileFieldsErr(
                "tricky_byte not in PackTopology".to_string()
            ))
        );

        assert_eq!(
            set_tricky_byte(&mut tets1[..100 - 60], &result, 7),
            Err(WTypeErr::CompileFieldsErr(
                "tricky_byte not in PackTopology".to_string()
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
            assert_eq!(&bb[start..end], [251, 101, 178, 118, 224, 42, 80, 167]);
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
                Err(WTypeErr::LenSizeErr(
                    "len >  t2page::MAXIMAL_CRC_LEN".to_string()
                ))
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
                Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
            );

            assert_eq!(
                set_get_head_crc(
                    false,
                    &mut bb[..result.encrypt_start_pos()],
                    &result,
                    dummy_crc_gen
                ),
                Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
            );

            assert_eq!(
                set_get_head_crc(false, &mut bb, &result_non_crc, dummy_crc_gen),
                Err(WTypeErr::CompileFieldsErr(
                    "head_crc_slice not in PackTopology".to_string()
                ))
            );
        }
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
        let mut bb = vec![0_u8; result.overhead_len() + 11];

        for x in bb.iter_mut().enumerate() {
            *x.1 = x.0.wrapping_add(1) as u8;
        }

        let ttl1 = Ttl::new(200, 100, 100, false).unwrap();

        assert!(set_ttl(&mut bb, &result, &ttl1, true).is_ok());

        assert_eq!(set_len(&mut bb, &result, &100), Ok(()));

        let mut noncex = DumpNonser::new(&[0]).unwrap();

        let ctr_n = Some(&1000);

        let mut cs = DumpEnc::new(&[1, 2, 3, 4, 5, 6]).unwrap();

        let validation = bb[result.encrypt_start_pos()..bb.len() - result.tag_len()].to_vec();
        assert_eq!(
            crypt(
                &mut bb,
                &result,
                Cryptlag::Encrypt,
                &mut cs,
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
                &mut cs,
                ctr_n,
                Some(&mut noncex)
            ),
            Ok(())
        ); //decr
        let ttl1 = Ttl::new(200, 21, 21, false).unwrap();
        let _ = set_ttl(&mut bbb1, &result, &ttl1, true).unwrap();
        assert_eq!(
            crypt(
                &mut bbb1,
                &result,
                Cryptlag::Decrypt,
                &mut cs,
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
                &mut cs,
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
                        &mut cs,
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
                        &mut cs,
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
                    &mut cs,
                    ctr_n,
                    Some(&mut noncex)
                ),
                Err(WTypeErr::PackageDamaged(
                    "error return during decryption associated with packet corruption".to_string()
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

        let mut bb = vec![0_u8; result.overhead_len() + 132];

        assert!(set_len(&mut bb, &result, &435,).is_ok());

        assert!(set_len(&mut bb, &result, &15).is_err());

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

        let mut bb = vec![0_u8; result.overhead_len() + 242];

        assert_eq!(
            set_len(&mut bb, &result, &435,),
            Err(WTypeErr::LenSizeErr(
                "pack.len()> len_byte_maximal_capacity_cheak(len)".to_string()
            ))
        );

        assert_eq!(
            set_len(&mut bb[..result.len_slice().unwrap().1], &result, &435,),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );
        assert_eq!(
            set_len(&mut bb, &result_non_len, &435,),
            Err(WTypeErr::CompileFieldsErr(
                " topology.len_slice() is none".to_string()
            ))
        );

        assert_eq!(
            get_len(&bb[..result.len_slice().unwrap().1], &result),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );
        assert_eq!(
            get_len(&bb, &result_non_len),
            Err(WTypeErr::CompileFieldsErr(
                " topology.len_slice() is none".to_string()
            ))
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

        let mut bb1 = vec![0_u8; result.overhead_len() + 1];
        let mut bb2 = vec![0_u8; result.overhead_len() + 1];
        let mut bb3 = vec![0_u8; result.overhead_len() + 1];
        let mut bb4 = vec![0_u8; result.overhead_len() + 1];

        let mut bb4_usr_test = vec![0_u8; result_usr_test.overhead_len() + 1];

        let mut tb1 = vec![0_u8; 334];
        let mut tb2 = vec![0_u8; 334];
        let mut tb3 = vec![0_u8; 334];
        let mut tb4 = vec![0_u8; 334];

        dummy_usf(&mut tb1, &312, &38865, &0, &result1).unwrap();
        dummy_usf(&mut tb2, &675, &7564, &0, &result1).unwrap();
        dummy_usf(&mut tb3, &987, &765, &0, &result1).unwrap();
        dummy_usf(&mut tb4, &12213, &987, &0, &result1).unwrap();

        set_user_field(&mut bb4_usr_test, &result_usr_test, &20, &111, dummy_usf).unwrap();

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

        set_user_field(&mut bb1, &result, &312, &38865, dummy_usf).unwrap();
        set_user_field(&mut bb2, &result, &675, &7564, dummy_usf).unwrap();
        set_user_field(&mut bb3, &result, &987, &765, dummy_usf).unwrap();
        set_user_field(&mut bb4, &result, &12213, &987, dummy_usf).unwrap();

        assert_eq!(
            set_user_field(&mut bb3, &result1, &987, &765, dummy_usf),
            Err(WTypeErr::CompileFieldsErr(
                "user_field not in PackTopology".to_string()
            ))
        );
        assert_eq!(
            set_user_field(
                &mut bb4[..result.trash_content_slice().unwrap()[0].1],
                &result,
                &12213,
                &987,
                dummy_usf
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
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

        let mut bb = vec![0_u8; result.overhead_len() + 11];

        for x in bb.iter_mut().enumerate() {
            *x.1 = 0xFF;
        }

        for tt in [true, false] {
            for i in (31231..31231 + 300).step_by(17) {
                let (i1, i2) = (i, i * 12349);
                for y in 0..120 {
                    let ccc = if tt { i1 } else { i2 };

                    assert!(
                        set_counter(&mut bb, &result, &ccc, PackType::bit_to_state(tt as u8))
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
                &21,
                PackType::Fback
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );
        assert_eq!(
            get_counter(&bb[..result.counter_slice().unwrap().1], &result, 21, 1),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
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

        let mut bb = vec![32_u8; result1.overhead_len() + 132];

        assert!(set_id_conn(&mut bb, &result1, &213214, &MyRole::Initiator).is_ok());

        assert!(set_id_conn(&mut bb, &result2, &213214, &MyRole::Initiator).is_err());

        assert!(set_id_conn(&mut bb, &result1, &213214, &MyRole::Initiator).is_ok());

        assert!(set_id_conn(&mut bb, &result1, &((!0_u64) >> 8), &MyRole::Initiator).is_err());

        assert!(set_id_conn(&mut bb, &result1, &100000, &MyRole::Initiator).is_ok());

        assert!(get_id_conn(&bb, &result2).is_err());

        assert!(get_id_conn(&bb, &result1).is_ok());

        assert_eq!(
            get_id_conn(&bb, &result1).unwrap(),
            (100000, MyRole::Initiator)
        );

        assert!(set_id_conn(&mut bb, &result1, &13321, &MyRole::Passive).is_ok());
        assert_eq!(
            get_id_conn(&bb, &result1).unwrap(),
            (13321, MyRole::Passive)
        );

        assert_eq!(
            get_id_conn(&bb, &result2),
            Err(WTypeErr::CompileFieldsErr(
                "topology.idconn_slice is None".to_string()
            ))
        );
        assert_eq!(
            get_id_conn(&bb[0..result1.idconn_slice().unwrap().1], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            set_id_conn(&mut bb, &result1, &2312123213213221221, &MyRole::Initiator),
            Err(WTypeErr::PackageDamaged(
                "id_conn > wutils::len_byte_maximal_capacity_cheak(x.2).0 >>1".to_string()
            ))
        );
        assert_eq!(
            set_id_conn(
                &mut bb[0..result1.idconn_slice().unwrap().1],
                &result1,
                &2,
                &MyRole::Initiator
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );
        assert_eq!(
            set_id_conn(&mut bb, &result2, &213214, &MyRole::Initiator),
            Err(WTypeErr::CompileFieldsErr(
                "topology.idconn_slice is None".to_string()
            ))
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

        let mut bb = [0; 100];

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_receiver_slice().unwrap().1], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_sender_slice().unwrap().1], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_receiver_slice().unwrap().1], &result2),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..result1.id_of_sender_slice().unwrap().1], &result2),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_receiver_slice().unwrap().1],
                &result1,
                &0,
                &0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_sender_slice().unwrap().1],
                &result1,
                &0,
                &0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_receiver_slice().unwrap().1],
                &result2,
                &0,
                &0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );

        assert_eq!(
            set_id_sender_and_recv(
                &mut bb[..result1.id_of_sender_slice().unwrap().1],
                &result2,
                &0,
                &0
            ),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
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

        let mut bb = vec![32_u8; result1.overhead_len() + 132];

        assert_eq!(
            set_id_sender_and_recv(&mut bb, &result1, &213214, &213214),
            Err(WTypeErr::WorkTimeErr(
                "err id_recv ==  id_sender".to_string()
            ))
        );

        assert!(set_id_sender_and_recv(&mut bb, &result2, &213214, &1114).is_err());
        assert!(
            set_id_sender_and_recv(
                &mut bb,
                &result1,
                &(!(312312_u64) << 16),
                &(!(111233_u64) << 8)
            )
            .is_err()
        );
        assert!(set_id_sender_and_recv(&mut bb, &result1, &987654, &1234567).is_ok());

        assert!(get_id_sender_and_recv(&bb, &result1).is_ok());
        assert_eq!(
            get_id_sender_and_recv(&bb, &result1).unwrap(),
            (987654, 1234567)
        );

        assert_eq!(
            get_id_sender_and_recv(&bb, &result2),
            Err(WTypeErr::CompileFieldsErr(
                "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None"
                    .to_string()
            ))
        );

        assert_eq!(
            get_id_sender_and_recv(&bb[..5], &result1),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );
        assert_eq!(
            set_id_sender_and_recv(&mut bb, &result2, &987, &123),
            Err(WTypeErr::CompileFieldsErr(
                "topology.id_of_sender_slice() or topology.id_of_receiver_slice() is None"
                    .to_string()
            ))
        );
        assert_eq!(
            set_id_sender_and_recv(&mut bb[..5], &result1, &7, &1),
            Err(WTypeErr::LenSizeErr("pack len non correct".to_string()))
        );
    }

    #[test]
    fn test_head_byte() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            //t2page::PackFields::IdReceiver(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::Len(4),
        ];

        let result = PackTopology::new(5, &fields, true, true).unwrap();

        let hb = HeadByteStruct::from_byte(0b1010_1010);

        let mut bb = vec![0_u8; result.overhead_len() + 132];

        assert!(set_headbyte(&mut bb[0..result.head_byte_pos() + 1], &result, hb).is_ok());

        assert!(set_headbyte(&mut bb, &result, hb).is_ok());

        assert_eq!(
            set_headbyte(&mut bb[0..result.head_byte_pos()], &result, hb)
                .err()
                .unwrap(),
            WTypeErr::LenSizeErr("pack len non correct".to_string())
        );

        assert_eq!(
            get_headbyte(&mut bb[0..result.head_byte_pos()], &result)
                .err()
                .unwrap(),
            WTypeErr::LenSizeErr("pack len non correct".to_string())
        );

        assert_eq!(
            get_headbyte(&mut bb[0..result.head_byte_pos() + 1], &result),
            Ok(HeadByteStruct::from_byte(hb.to_byte()))
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
        let ctr_m = &0x1122334455;
        let len = 234;

        let topology = PackTopology::new(50, &fields, true, false).unwrap();

        let mut pak = vec![0_u8; topology.overhead_len() + 100];
        let pack = &mut pak[..];
        //id R  S
        assert!(set_id_sender_and_recv(pack, &topology, &0x22, &0x1122334455667788).is_err());
        assert!(set_id_sender_and_recv(pack, &topology, &0x2299FFAABBCC1088, &0x11).is_err());
        assert!(
            set_id_sender_and_recv(pack, &topology, &0x2299FFAABBCC1088, &0x1122334455667788)
                .is_err()
        );
        assert!(set_id_sender_and_recv(pack, &topology, &id_s, &id_r).is_ok());

        assert!(get_id_sender_and_recv(pack, &topology).is_ok());

        assert_eq!(
            get_id_sender_and_recv(pack, &topology).unwrap(),
            (id_s, id_r)
        );
        //LEN
        assert!(set_len(pack, &topology, &0x10).is_err());
        {
            let mut pack = [0_u8; 256];
            assert!(set_len(&mut pack, &topology, &0x1000).is_err());
        }
        assert!(set_len(pack, &topology, &0x1000).is_ok());

        assert_eq!(get_len(pack, &topology).unwrap(), pack.len());

        //COUNTER
        assert!(set_counter(pack, &topology, ctr_m, PackType::Fback).is_ok());
        assert_eq!(
            set_get_head_crc(true, pack, &topology, dummy_crc_gen),
            Ok(false)
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 17, ctr_m - 30),
            Ok((*ctr_m, PackType::Fback))
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 100, ctr_m - 31,),
            Ok((*ctr_m, PackType::Fback))
        );
        assert_eq!(
            get_counter(pack, &topology, ctr_m - 123, ctr_m - 23,),
            Ok((*ctr_m, PackType::Fback))
        );

        //head byte

        let hb = HeadByteStruct::from_byte(0b1010_1010);

        assert!(set_headbyte(pack, &topology, hb).is_ok());

        //TTL
        let ttl1 = Ttl::new(170_000, 100_000, 100_000, false).unwrap();

        assert!(set_ttl(pack, &topology, &ttl1, true).is_err());

        let ttl1 = Ttl::new(30_000, 20_000, 19_000, false).unwrap();

        assert!(set_ttl(pack, &topology, &ttl1, true).is_ok());

        assert_eq!(get_ttl(pack, &topology, &ttl1).unwrap(), 19_000);

        //IDC
        assert!(set_id_conn(pack, &topology, &((!0_u32) as u64), &MyRole::Initiator).is_err());
        assert!(set_id_conn(pack, &topology, &id_c, &MyRole::bit_to_state(id_c_b as u8)).is_ok());
        assert_eq!(
            get_id_conn(pack, &topology).unwrap(),
            (id_c, MyRole::bit_to_state(id_c_b as u8))
        );

        //us reash
        assert!(set_user_field(pack, &topology, ctr_m, &len, dummy_usf).is_ok());

        let mut cs = DumpEnc::new(&[1, 2, 3, 4, 45]).unwrap();
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
                    &mut cs,
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
                    &mut cs,
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
                    &mut cs,
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
                    &mut cs,
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
                        &mut cs,
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
                        &mut cs,
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

        for iter in topology.encrypt_start_pos()..pack.len() {
            let mut t = vec![0; pack.len()];
            for x in t.iter_mut().zip(pack.iter()) {
                *x.0 = *x.1;
            }
            t[iter] = !t[iter];
            assert_ne!(
                crypt(
                    &mut t,
                    &topology,
                    Cryptlag::Decrypt,
                    &mut cs,
                    Some(ctr_m),
                    Some(&mut noncex)
                ),
                Ok(()),
                "uter: {}",
                iter
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
                &mut cs,
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
            Ok((*ctr_m, PackType::Fback))
        );

        for _ in 0..10 {
            assert_eq!(get_ttl(pack, &topology, &ttl1).unwrap(), 19_000);
        }

        assert_eq!(
            get_id_sender_and_recv(pack, &topology).unwrap(),
            (id_s, id_r)
        );
        assert_eq!(get_len(pack, &topology).unwrap(), pack.len());

        //head byte
        assert_eq!(
            get_headbyte(pack, &topology),
            Ok(HeadByteStruct::from_byte(hb.to_byte()))
        );
    }

    //============================================================================================================helper functions for testing====================
    //============================================================================================================helper functions for testing====================
    //============================================================================================================helper functions for testing====================
    //============================================================================================================helper functions for testing====================

    fn dummy_usf(
        field: &mut [u8],
        counter: &u64,
        full_len: &usize,
        i: &usize,
        _topoligy: &PackTopology,
    ) -> Result<(), String> {
        let teto = [*counter as u8, *full_len as u8, *i as u8];
        for (x, t) in field.iter_mut().zip(teto.iter().cycle()) {
            *x = *t;
        }
        Ok(())
    }

    fn dummy_crc_gen(inp: &[u8], crc: &mut [u8]) -> Result<(), String> {
        DumpCrcser::new(&[0]).unwrap().gen_crc(inp, crc)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_ttl {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::integer_division)]
    use super::*;
    use crate::t0pology::PackFields;
    use crate::t0pology::PackTopology;
    use crate::w1types::WTypeErr;
    use crate::w1utils;

    // Helper: create a topology with a TTL slice of given length (1..8)
    fn make_topology(ttl_len: usize) -> PackTopology {
        let mut fields = vec![
            PackFields::Counter(7),
            PackFields::IdConnect(6),
            PackFields::UserField(10),
            PackFields::HeadCRC(4),
        ];
        if ttl_len > 0 {
            fields.push(PackFields::TTL(ttl_len));
        }
        PackTopology::new(5, &fields, true, false).unwrap()
    }

    // Helper: create a packet of exact length for the topology
    fn make_packet(topology: &PackTopology) -> Vec<u8> {
        vec![0u8; topology.overhead_len()]
    }

    // Helper: write a u64 value into the TTL slice of a packet
    fn write_ttl(pack: &mut [u8], topology: &PackTopology, value: u64) {
        let (start, end, _) = topology.ttl_slice().unwrap();
        let slice = &mut pack[start..end];
        w1utils::u64_to_1_8bytes(value, slice).unwrap();
    }

    // Helper: read a u64 value from the TTL slice
    fn read_ttl(pack: &[u8], topology: &PackTopology) -> u64 {
        let (start, end, _) = topology.ttl_slice().unwrap();
        let slice = &pack[start..end];
        w1utils::bytes_to_u64(slice).unwrap()
    }

    // ===== TESTS FOR ttl_corr =====
    #[test]
    fn ttl_corr_errors_and_corrections_p() {
        struct Case {
            max: u64,
            input: u64,
            pruning: bool,
            expected: Result<u64, WTypeErr>,
        }

        let cases = vec![
            Case {
                max: 10,
                input: 15,
                pruning: false,
                expected: Err(WTypeErr::PackageDamaged(
                    "TTL in pack largest of ttl.max()".to_string(),
                )),
            },
            Case {
                max: 10,
                input: 15,
                pruning: true,
                expected: Ok(10),
            },
            Case {
                max: 10,
                input: 0,
                pruning: false,
                expected: Err(WTypeErr::PackageDamaged("TTL pack is 0".to_string())),
            },
            Case {
                max: 10,
                input: 0,
                pruning: true,
                expected: Err(WTypeErr::PackageDamaged("TTL pack is 0".to_string())),
            },
            Case {
                max: 10,
                input: 5,
                pruning: false,
                expected: Ok(5),
            },
            Case {
                max: 10,
                input: 5,
                pruning: true,
                expected: Ok(5),
            },
            Case {
                max: 10,
                input: 10,
                pruning: false,
                expected: Ok(10),
            },
            Case {
                max: 10,
                input: 10,
                pruning: true,
                expected: Ok(10),
            },
            // : max = 1
            Case {
                max: 2,
                input: 2,
                pruning: false,
                expected: Ok(2),
            },
            Case {
                max: 2,
                input: 0,
                pruning: false,
                expected: Err(WTypeErr::PackageDamaged("TTL pack is 0".to_string())),
            },
            Case {
                max: 2,
                input: 3,
                pruning: false,
                expected: Err(WTypeErr::PackageDamaged(
                    "TTL in pack largest of ttl.max()".to_string(),
                )),
            },
            Case {
                max: 2,
                input: 3,
                pruning: true,
                expected: Ok(2),
            },
        ];

        for case in cases {
            let ttl = Ttl::new(case.max, 1, 1, case.pruning).unwrap();
            let mut val = case.input;
            let res = ttl_corr(&ttl, &mut val);
            match case.expected {
                Ok(expected_val) => {
                    assert!(res.is_ok(), "Expected Ok, got {:?}", res);
                    assert_eq!(val, expected_val, "Value mismatch");
                },
                Err(expected_err) => {
                    assert_eq!(res, Err(expected_err), "Error mismatch");
                },
            }
        }

        for max in [2, 5, 100, 255, 1000, u64::MAX] {
            let ttl = Ttl::new(max, 1, 1, false).unwrap();
            let mut values = vec![1];
            if max > 1 {
                values.push(max / 2);
                values.push(max - 1);
                values.push(max);
            }
            // Для маленьких max добавляем все значения
            if max <= 10 {
                values = (1..=max).collect();
            }
            for val in values {
                let mut v = val;
                assert!(ttl_corr(&ttl, &mut v).is_ok());
                assert_eq!(v, val);
            }
        }
    }

    // ===== TESTS FOR set_ttl =====
    #[test]
    fn set_ttl_errors_p() {
        // Topology without TTL -> CompileFieldsErr
        let topo_no_ttl = make_topology(0);
        let mut pack = make_packet(&topo_no_ttl);
        let ttl = Ttl::new(100, 10, 10, false).unwrap();
        let res = set_ttl(&mut pack, &topo_no_ttl, &ttl, false);
        assert!(
            matches!(res, Err(WTypeErr::CompileFieldsErr(_))),
            "{:?}",
            res
        );

        // Packet too short -> LenSizeErr
        let topo = make_topology(4);
        let mut short_pack = vec![0; 5]; // shorter than end index
        let ttl = Ttl::new(100, 10, 10, false).unwrap();
        let res = set_ttl(&mut short_pack, &topo, &ttl, false);
        assert!(matches!(res, Err(WTypeErr::LenSizeErr(_))), "{:?}", res);

        // edit > max -> WorkTimeErr
        let ttl = Ttl::new(100, 101, 10, false).unwrap();
        let mut pack = make_packet(&topo);
        let res = set_ttl(&mut pack, &topo, &ttl, false);
        assert!(matches!(res, Err(WTypeErr::PackageDamaged(_))), "{:?}", res);

        // max > i64::MAX -> conversion error
        let ttl = Ttl::new(u64::MAX, 10, 10, false).unwrap();
        let res = set_ttl(&mut pack, &topo, &ttl, false);
        assert!(matches!(res, Err(WTypeErr::PackageDamaged(_))), "{:?}", res);
    }

    #[test]
    fn set_ttl_start_mode() {
        for cap_cap in [1, 2, 3, 4, 5, 6, 7] {
            let topo = make_topology(cap_cap);
            let mut pack = make_packet(&topo);

            // Valid start values
            let starts = [1, 2, 3, 4, 5, 6, 7];
            for indd in starts {
                let start = 1 << ((indd - 1) * 8);

                let ttl = Ttl::new(start + 1, 1, start, false).unwrap();
                let res = set_ttl(&mut pack, &topo, &ttl, true);

                if indd > cap_cap {
                    assert_eq!(
                        res,
                        Err(WTypeErr::PackageDamaged(
                            "ttl_is TTL is more than capable of accommodating the TTL_SLICE field"
                                .to_string()
                        )),
                        "iter {:?} cap_cap {:?}",
                        indd,
                        cap_cap
                    );
                } else {
                    assert_eq!(res, Ok(start), "iter {:?} cap_cap {:?}", indd, cap_cap);
                    assert_eq!(read_ttl(&pack, &topo), start);
                }

                // Verify written value
            }
        }

        // Start with pruning: start > max? Not allowed by constructor, but we test max == start? Constructor rejects max <= start.
        // So no test.

        // Start with forced_pruning true: if start > max? Can't happen.
    }

    #[test]
    fn set_ttl_read_mode_without_error() {
        let topo = make_topology(4);
        let mut pack = make_packet(&topo);

        // Test positive edits (increase)
        let cases = vec![
            (10, 5, false, 5, 15),    // initial 5, edit +10 -> 15
            (10, 5, true, 5, 10),     // initial 5, edit +10, max=10 -> pruned to 10
            (100, 50, false, 40, 90), // initial 40, edit +50 -> 90
            (100, 50, true, 60, 100), // initial 60, edit +50, max=100 -> 100
        ];
        for (max, edit, pruning, initial, expected) in cases {
            let ttl = Ttl::new(max, edit, 1, pruning).unwrap();
            write_ttl(&mut pack, &topo, initial);
            let res = set_ttl(&mut pack, &topo, &ttl, false);
            if !pruning && expected < max {
                assert_eq!(read_ttl(&pack, &topo), expected);
                assert_eq!(res, Ok(expected));
            } else {
                assert_eq!(res, Ok(max));
                assert_eq!(read_ttl(&pack, &topo), max);
            }
        }

        // Test negative edits (decrease)
        let cases = vec![
            (100, -10, false, 50, 40),
            (100, -10, true, 50, 40),
            (100, -50, false, 30, 0), // would become 0 -> ttl_corr error
            (100, -50, true, 30, 0),  // same error
        ];
        for (max, edit, pruning, initial, expected) in cases {
            let ttl = Ttl::new(max, edit, 1, pruning).unwrap();
            write_ttl(&mut pack, &topo, initial);
            let res = set_ttl(&mut pack, &topo, &ttl, false);
            if expected == 0 {
                assert!(matches!(res, Err(WTypeErr::PackageDamaged(_))));
            } else {
                assert_eq!(res, Ok(expected));
                assert_eq!(read_ttl(&pack, &topo), expected);
            }
        }

        // Test overflow (add_u64_i64 saturates) – but add_u64_i64 with true returns Result, can fail? Let's see.
        // We'll test values that cause overflow beyond u64::MAX.
        let ttl = Ttl::new(u64::MAX, 1, 1, false).unwrap();
        write_ttl(&mut pack, &topo, u64::MAX);
        let res = set_ttl(&mut pack, &topo, &ttl, false);
        // add_u64_i64 will return Err on overflow (since true means saturating? Actually the function may return Err on overflow).
        // We need to know exact behavior. In code, map_err converts to PackageDamaged.
        // So we expect PackageDamaged.
        assert!(matches!(res, Err(WTypeErr::PackageDamaged(_))));
    }

    #[test]
    fn set_ttl_capacity_errors() {
        // TTL field length 1 byte can hold up to 255
        let topo = make_topology(1);
        let mut pack = make_packet(&topo);
        let ttl = Ttl::new(300, 10, 10, false).unwrap();
        let res = set_ttl(&mut pack, &topo, &ttl, true);
        assert_eq!(res, Ok(10), "{:?}", res);
        // But if we set max=200, start=10, it should work
        let ttl2 = Ttl::new(200, 10, 10, false).unwrap();
        let res2 = set_ttl(&mut pack, &topo, &ttl2, true);
        assert_eq!(res2, Ok(10));
        // Now write a value that fits
        write_ttl(&mut pack, &topo, 100);
        let ttl3 = Ttl::new(200, 10, 1, false).unwrap();
        let res3 = set_ttl(&mut pack, &topo, &ttl3, false);
        assert_eq!(res3, Ok(110)); // 100+10=110 < 200 and <255
        // Try to exceed 255
        let ttl4 = Ttl::new(300, 200, 1, false).unwrap();
        let res4 = set_ttl(&mut pack, &topo, &ttl4, true);
        assert_eq!(res4, Ok(1), "{:?}", res4); // 200 > 255 capacity
    }

    // ===== TESTS FOR get_ttl =====
    #[test]
    fn get_ttl_errors_p() {
        let topo_no_ttl = make_topology(0);
        let pack = make_packet(&topo_no_ttl);
        let ttl = Ttl::new(100, 10, 10, false).unwrap();
        let res = get_ttl(&pack, &topo_no_ttl, &ttl);
        assert!(matches!(res, Err(WTypeErr::CompileFieldsErr(_))));

        let topo = make_topology(4);
        let short_pack = vec![0; 5];
        let res = get_ttl(&short_pack, &topo, &ttl);
        assert!(matches!(res, Err(WTypeErr::LenSizeErr(_))));

        // Invalid TTL value in packet (e.g., 0)
        let mut pack = make_packet(&topo);
        write_ttl(&mut pack, &topo, 0);
        let res = get_ttl(&pack, &topo, &ttl);
        assert!(matches!(res, Err(WTypeErr::PackageDamaged(_))));

        // Value > max without pruning
        let ttl_no_prune = Ttl::new(50, 10, 10, false).unwrap();
        write_ttl(&mut pack, &topo, 60);
        let res = get_ttl(&pack, &topo, &ttl_no_prune);
        assert!(matches!(res, Err(WTypeErr::PackageDamaged(_))));

        // Value > max with pruning -> pruned
        let ttl_prune = Ttl::new(50, 10, 10, true).unwrap();
        write_ttl(&mut pack, &topo, 60);
        let res = get_ttl(&pack, &topo, &ttl_prune);
        assert_eq!(res, Ok(50));
        // But note: get_ttl does not modify the packet, so reading again would still be 60 if we read raw, but get_ttl returns corrected value.
        // We can check that it returns 50.
    }

    #[test]
    fn get_ttl_valid_p() {
        let topo = make_topology(4);
        let mut pack = make_packet(&topo);
        let ttl = Ttl::new(100, 10, 10, false).unwrap();
        // Write various valid values
        for val in [1, 50, 99, 100] {
            write_ttl(&mut pack, &topo, val);
            let res = get_ttl(&pack, &topo, &ttl);
            assert_eq!(res, Ok(val));
        }
    }

    // ===== INTEGRATION TESTS: set + get =====
    #[test]
    fn set_and_get_consistency_p() {
        let topo = make_topology(4);
        let mut pack = make_packet(&topo);

        // Use different TTL configurations and verify get after set
        let configs = vec![
            (100, 10, 20, false),
            (100, -5, 20, false),
            (50, 5, 10, true),
            (50, -5, 10, true),
            (u64::MAX - 10, 10, 1, false),
            (u64::MAX, -10, 1, false),
        ];
        for (max, edit, start, pruning) in configs {
            let ttl = Ttl::new(max, edit, start, pruning).unwrap();
            // First, set with is_start_ttl=true
            let res_set = set_ttl(&mut pack, &topo, &ttl, true);
            if let Ok(val) = res_set {
                let res_get = get_ttl(&pack, &topo, &ttl);
                assert_eq!(res_get, Ok(val));
                // Now modify by reading mode
                let res_set2 = set_ttl(&mut pack, &topo, &ttl, false);
                if let Ok(val2) = res_set2 {
                    let res_get2 = get_ttl(&pack, &topo, &ttl);
                    assert_eq!(res_get2, Ok(val2));
                } else {
                    // If set fails, get should also fail on the same packet? Not necessarily.
                    // We'll just check that the packet is not changed on error.
                }
            }
        }
    }

    #[test]
    fn set_ttl_on_different_field_lengths_p() {
        for len in 1..=7 {
            let topo = make_topology(len);
            let mut pack = make_packet(&topo);
            let max_cap = w1utils::len_byte_maximal_capacity_check(len).0;
            // Test values that fit exactly
            let ttl = Ttl::new(max_cap, 1, 1, false).unwrap();
            let res = set_ttl(&mut pack, &topo, &ttl, true);
            assert_eq!(res, Ok(1));
            // Try to exceed capacity
            let ttl_big = Ttl::new(max_cap + 2, 1, max_cap + 1, false).unwrap();
            let res2 = set_ttl(&mut pack, &topo, &ttl_big, true);
            assert!(
                matches!(res2, Err(WTypeErr::PackageDamaged(_))),
                "{:?}",
                res2
            );

            set_ttl(&mut pack, &topo, &ttl, true).unwrap();
            let ttl_big = Ttl::new(max_cap + 2, max_cap as i64, 1, false).unwrap();
            let res2 = set_ttl(&mut pack, &topo, &ttl_big, false);
            assert!(
                matches!(res2, Err(WTypeErr::PackageDamaged(_))),
                "{:?} {}",
                res2,
                len
            );
        }
    }

    // Edge case: edit = i64::MIN
    #[test]
    fn set_ttl_negative_edit_min_p() {
        let topo = make_topology(8);
        let mut pack = make_packet(&topo);
        let ttl = Ttl::new(u64::MAX, i64::MIN, 1, false).unwrap();
        // Start mode: edit not used
        let res = set_ttl(&mut pack, &topo, &ttl, true);
        assert_eq!(res, Ok(1));
        // Read mode: subtract large number, should underflow -> error
        write_ttl(&mut pack, &topo, 100);
        let res2 = set_ttl(&mut pack, &topo, &ttl, false);
        // add_u64_i64 with negative i64::MIN will underflow (since 100 + (-9223372036854775808) < 0)
        assert!(matches!(res2, Err(WTypeErr::PackageDamaged(_))));
    }

    // Edge: forced_pruning=true and value > max in read mode
    #[test]
    fn set_ttl_pruning_on_read_p() {
        let topo = make_topology(4);
        let mut pack = make_packet(&topo);
        let ttl = Ttl::new(50, 10, 1, true).unwrap();
        write_ttl(&mut pack, &topo, 60); // already above max
        // read mode: ttl_corr will prune to 50, then add 10 -> 60, then ttl_corr again prunes to 50
        let res = set_ttl(&mut pack, &topo, &ttl, false);
        assert_eq!(res, Ok(50));
        assert_eq!(read_ttl(&pack, &topo), 50);
    }
}

#[cfg(test)]
mod tests_get_set_data_copy {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::t0pology::{self, PackTopology};
    use crate::w1types::WTypeErr;

    /// Returns a set of valid `PackTopology` instances covering different
    /// `encrypt_start_pos` and `tag_len` combinations.
    fn topologies() -> Vec<PackTopology> {
        let mut v = Vec::new();

        // 1. Full topology with encryption tag (Nonce, TTL, Len).
        let fields1 = vec![
            t0pology::PackFields::UserField(8),
            t0pology::PackFields::Counter(4),
            t0pology::PackFields::HeadCRC(2),
            t0pology::PackFields::Nonce(4),
            t0pology::PackFields::TTL(2),
            t0pology::PackFields::Len(2),
        ];
        v.push(PackTopology::new(64, &fields1, true, true).unwrap());

        // 2. Topology without encryption tag.
        let fields2 = vec![
            t0pology::PackFields::UserField(16),
            t0pology::PackFields::Counter(8),
            t0pology::PackFields::HeadCRC(4),
        ];
        v.push(PackTopology::new(64, &fields2, true, false).unwrap());

        // 3. Another full topology with different field sizes.
        let fields3 = vec![
            t0pology::PackFields::UserField(1),
            t0pology::PackFields::Counter(1),
            t0pology::PackFields::IdConnect(2),
            t0pology::PackFields::HeadCRC(2),
            t0pology::PackFields::Nonce(6),
            t0pology::PackFields::TTL(2),
            t0pology::PackFields::Len(3),
        ];
        v.push(PackTopology::new(16, &fields3, true, false).unwrap());

        // 4. Topology with `encrypt_start_pos == 0` (only encrypted fields).
        let fields4 = vec![
            t0pology::PackFields::Nonce(4),
            t0pology::PackFields::TTL(2),
            t0pology::PackFields::Len(2),
            t0pology::PackFields::Counter(1),
        ];
        v.push(PackTopology::new(64, &fields4, true, false).unwrap());

        v
    }

    #[test]
    fn test_set_payload_and_get_payload() {
        for topology in topologies() {
            let start = topology.encrypt_start_pos();
            let tag_len = topology.tag_len();

            // ---------- Success cases with various payload lengths ----------
            for payload_len in 0..=64 {
                let pack_len = start + payload_len + tag_len;
                let pack = vec![0xAA_u8; pack_len];
                let payload: Vec<u8> = (0..payload_len)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                    .collect();

                // set_payload success
                let mut pack_copy = pack.clone();
                assert_eq!(
                    set_payload(&mut pack_copy, &payload, &topology),
                    Ok(()),
                    "set_payload failed for start={}, tag_len={}, payload_len={}",
                    start,
                    tag_len,
                    payload_len
                );
                // Verify payload area
                assert_eq!(
                    &pack_copy[start..start + payload_len],
                    &payload[..],
                    "payload mismatch after set_payload"
                );
                // Verify bytes outside payload area are untouched
                for i in 0..start {
                    assert_eq!(
                        pack_copy[i], 0xAA,
                        "byte before payload changed at index {} (start={}, tag_len={}, payload_len={})",
                        i, start, tag_len, payload_len
                    );
                }
                for i in start + payload_len..pack_len {
                    assert_eq!(
                        pack_copy[i], 0xAA,
                        "byte after payload changed at index {} (start={}, tag_len={}, payload_len={})",
                        i, start, tag_len, payload_len
                    );
                }

                // get_payload success
                let mut out_vec = vec![0xBB; 7];
                assert_eq!(
                    get_payload(&pack_copy, &mut out_vec, &topology),
                    Ok(()),
                    "get_payload failed for start={}, tag_len={}, payload_len={}",
                    start,
                    tag_len,
                    payload_len
                );
                assert_eq!(
                    out_vec, payload,
                    "get_payload returned wrong data for start={}, tag_len={}, payload_len={}",
                    start, tag_len, payload_len
                );

                // get_payload from original pack (filled with 0xAA)
                let mut out_vec2 = vec![0xCC; 3];
                assert_eq!(get_payload(&pack, &mut out_vec2, &topology), Ok(()));
                assert_eq!(out_vec2, vec![0xAA; payload_len]);
            }

            // ---------- set_payload payload length mismatch ----------
            for pack_len in (start + tag_len)..=(start + tag_len + 20) {
                let expected_payload_len = pack_len - start - tag_len;
                let pack = vec![0xAA_u8; pack_len];
                // Try different payload lengths that don't match
                for delta in [-3i32, -1, 1, 3, 10].iter() {
                    let payload_len = (expected_payload_len as i32 + delta).max(0) as usize;
                    if payload_len == expected_payload_len {
                        continue;
                    }
                    let payload = vec![0x55; payload_len];
                    let mut pack_copy = pack.clone();
                    let err = set_payload(&mut pack_copy, &payload, &topology).unwrap_err();
                    let expected_msg = format!(
                        "Payload length mismatch: expected {}, got {}",
                        expected_payload_len, payload_len
                    );
                    assert_eq!(
                        err,
                        WTypeErr::CompileFieldsErr(expected_msg),
                        "wrong error for pack_len={}, expected_payload_len={}, payload_len={}",
                        pack_len,
                        expected_payload_len,
                        payload_len
                    );
                    // Ensure pack was not modified
                    assert_eq!(
                        pack_copy, pack,
                        "set_payload modified pack on length mismatch"
                    );
                }
            }

            // ---------- pack too small for tag ----------
            if tag_len > 0 {
                for pack_len in 0..tag_len {
                    let pack = vec![0xAA_u8; pack_len];
                    let payload = vec![0x55; 0];
                    let mut pack_copy = pack.clone();
                    let err = set_payload(&mut pack_copy, &payload, &topology).unwrap_err();
                    assert_eq!(
                        err,
                        WTypeErr::LenSizeErr("pack len is less than tag_len".to_string()),
                        "wrong error for pack_len < tag_len"
                    );
                    assert_eq!(pack_copy, pack);

                    let mut out_vec = vec![0xBB; 5];
                    let err = get_payload(&pack, &mut out_vec, &topology).unwrap_err();
                    assert_eq!(
                        err,
                        WTypeErr::LenSizeErr("pack len is less than tag_len".to_string()),
                        "wrong get_payload error for pack_len < tag_len"
                    );
                    assert!(out_vec.is_empty(), "get_payload should clear vec on error");
                }
            }

            // ---------- start > end (pack too small for encrypt_start_pos) ----------
            if start > 0 {
                let min_len = tag_len;
                let max_len = tag_len + start - 1;
                for pack_len in min_len..=max_len {
                    let pack = vec![0xAA_u8; pack_len];
                    let payload = vec![0x55; 0];
                    let mut pack_copy = pack.clone();
                    let err = set_payload(&mut pack_copy, &payload, &topology).unwrap_err();
                    assert_eq!(
                        err,
                        WTypeErr::LenSizeErr("encrypt_start_pos exceeds end_pos".to_string()),
                        "wrong error for start > end"
                    );
                    assert_eq!(pack_copy, pack);

                    let mut out_vec = vec![0xBB; 5];
                    let err = get_payload(&pack, &mut out_vec, &topology).unwrap_err();
                    assert_eq!(
                        err,
                        WTypeErr::LenSizeErr("encrypt_start_pos exceeds end_pos".to_string()),
                        "wrong get_payload error for start > end"
                    );
                    assert!(out_vec.is_empty(), "get_payload should clear vec on error");
                }
            }
        }
    }

    //
    //
    //
    #[test]
    fn test_set_get_payload_boundary_and_oversized_inputs() {
        // We explicitly assert "no panic" for pathological inputs.  If any of the
        // calls below panics, `catch_unwind` will return `Err` and the outer
        // `assert!` will report a single, clear failure instead of an obscure
        // backtrace.  `AssertUnwindSafe` is required because `topologies()` uses
        // interior mutability of the `PackTopology` builder only at construction
        // time; once built, the value is only read.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for topology in topologies() {
                let start = topology.encrypt_start_pos();
                let tag_len = topology.tag_len();
                let min_pack_len = start + tag_len;

                // -----------------------------------------------------------------
                // 1. Minimum valid pack: exactly `start + tag_len`, empty payload.
                // -----------------------------------------------------------------
                {
                    let mut pack = vec![0xAA_u8; min_pack_len];
                    let empty: Vec<u8> = Vec::new();

                    assert_eq!(
                        set_payload(&mut pack, &empty, &topology),
                        Ok(()),
                        "minimum pack (len={}) must accept an empty payload \
                     (start={}, tag_len={})",
                        min_pack_len,
                        start,
                        tag_len
                    );

                    // Round-trip with a pre-filled destination vector that must be
                    // cleared by `get_payload`.
                    let mut out = vec![0xDE, 0xAD, 0xBE, 0xEF];
                    assert_eq!(get_payload(&pack, &mut out, &topology), Ok(()));
                    assert!(
                        out.is_empty(),
                        "empty payload expected after get_payload on minimum pack"
                    );
                }

                // -----------------------------------------------------------------
                // 2. Minimum invalid pack: one byte less than `start + tag_len`.
                //    Must fail with the correct error variant and must not touch
                //    the buffer.
                // -----------------------------------------------------------------
                if min_pack_len > 0 {
                    let bad_len = min_pack_len - 1;
                    let mut pack = vec![0xAA_u8; bad_len];
                    let empty: Vec<u8> = Vec::new();

                    // Two mutually exclusive error paths depending on which
                    // boundary is hit first inside the implementation.
                    let expected = if bad_len < tag_len {
                        WTypeErr::LenSizeErr("pack len is less than tag_len".to_string())
                    } else {
                        WTypeErr::LenSizeErr("encrypt_start_pos exceeds end_pos".to_string())
                    };

                    let err = set_payload(&mut pack, &empty, &topology).unwrap_err();
                    assert_eq!(
                        err, expected,
                        "one-byte-short pack must fail with the correct variant \
                     (start={}, tag_len={}, pack_len={})",
                        start, tag_len, bad_len
                    );
                    // Buffer must be untouched.
                    assert!(
                        pack.iter().all(|&b| b == 0xAA),
                        "set_payload must not modify a pack that fails validation"
                    );

                    let mut out = vec![0x11, 0x22, 0x33, 0x44];
                    let err = get_payload(&pack, &mut out, &topology).unwrap_err();
                    assert_eq!(err, expected);
                    assert!(
                        out.is_empty(),
                        "get_payload must clear the destination vector on error"
                    );
                }

                // -----------------------------------------------------------------
                // 3. Large pack with matching large payload (1 MiB).
                // -----------------------------------------------------------------
                {
                    const BIG: usize = 1 << 20; // 1 MiB
                    let pack_len = start + BIG + tag_len;
                    let mut pack = vec![0u8; pack_len];
                    let payload: Vec<u8> = (0..BIG).map(|i| (i as u8) ^ 0x5A).collect();

                    assert_eq!(
                        set_payload(&mut pack, &payload, &topology),
                        Ok(()),
                        "1 MiB pack (len={}) must accept a 1 MiB payload",
                        pack_len
                    );

                    // Verify payload content and untouched boundaries.
                    assert_eq!(&pack[start..start + BIG], &payload[..]);
                    assert!(
                        pack[..start].iter().all(|&b| b == 0),
                        "prefix bytes must be untouched"
                    );
                    assert!(
                        pack[start + BIG..].iter().all(|&b| b == 0),
                        "trailing bytes (tag area) must be untouched"
                    );

                    let mut out = Vec::new();
                    assert_eq!(get_payload(&pack, &mut out, &topology), Ok(()));
                    assert_eq!(out.len(), BIG);
                    assert_eq!(out, payload, "1 MiB round-trip must be byte-exact");
                }

                // -----------------------------------------------------------------
                // 4. Oversized payload against a small pack.
                //    The implementation must reject it and must not write anything.
                // -----------------------------------------------------------------
                {
                    let small_pack_len = min_pack_len + 4; // room for exactly 4 payload bytes
                    let mut pack = vec![0xAA_u8; small_pack_len];
                    let oversized = vec![0x55_u8; 10_000];

                    let expected_msg = format!(
                        "Payload length mismatch: expected {}, got {}",
                        4,
                        oversized.len()
                    );
                    let err = set_payload(&mut pack, &oversized, &topology).unwrap_err();
                    assert_eq!(
                        err,
                        WTypeErr::CompileFieldsErr(expected_msg),
                        "oversized payload must be rejected with a clear message"
                    );
                    // No byte must have been written.
                    assert!(
                        pack.iter().all(|&b| b == 0xAA),
                        "set_payload must not write anything on length mismatch"
                    );
                }

                // -----------------------------------------------------------------
                // 5. Payload length off by one in both directions.
                // -----------------------------------------------------------------
                {
                    const MID: usize = 32;
                    let pack_len = start + MID + tag_len;
                    let mut pack = vec![0xAA_u8; pack_len];

                    for &delta in &[-1i32, 1] {
                        let plen = (MID as i32 + delta) as usize;
                        let payload = vec![0x77u8; plen];
                        let expected_msg =
                            format!("Payload length mismatch: expected {}, got {}", MID, plen);
                        let err = set_payload(&mut pack, &payload, &topology).unwrap_err();
                        assert_eq!(
                            err,
                            WTypeErr::CompileFieldsErr(expected_msg),
                            "off-by-{} payload must be rejected",
                            delta
                        );
                        // Buffer unchanged after rejection.
                        assert!(
                            pack.iter().all(|&b| b == 0xAA),
                            "off-by-{} must not modify the pack",
                            delta
                        );
                    }
                }

                // -----------------------------------------------------------------
                // 6. Very long pack with payload of exactly the same very long
                //    length (4 MiB).  Stresses size arithmetic without overflow.
                // -----------------------------------------------------------------
                {
                    const HUGE: usize = 4 * 1024 * 1024; // 4 MiB
                    let pack_len = start + HUGE + tag_len;
                    let mut pack = vec![0u8; pack_len];
                    let payload = vec![0xABu8; HUGE];

                    assert_eq!(
                        set_payload(&mut pack, &payload, &topology),
                        Ok(()),
                        "4 MiB payload must be accepted without overflow"
                    );

                    let mut out = Vec::new();
                    assert_eq!(get_payload(&pack, &mut out, &topology), Ok(()));
                    assert_eq!(out.len(), HUGE);
                    assert!(
                        out.iter().all(|&b| b == 0xAB),
                        "4 MiB round-trip must be byte-exact"
                    );
                }

                // -----------------------------------------------------------------
                // 7. Zero-length payload round-trip on every topology.
                // -----------------------------------------------------------------
                {
                    let pack_len = start + tag_len;
                    let mut pack = vec![0x00u8; pack_len];
                    let payload: Vec<u8> = Vec::new();

                    assert_eq!(set_payload(&mut pack, &payload, &topology), Ok(()));

                    let mut out = vec![0xFF; 16];
                    assert_eq!(get_payload(&pack, &mut out, &topology), Ok(()));
                    assert!(
                        out.is_empty(),
                        "zero-length payload must yield an empty vector"
                    );
                }
            }
        }));

        assert!(
            outcome.is_ok(),
            "set_payload/get_payload panicked on boundary or oversized input"
        );
    }
}
