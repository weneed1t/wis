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

/// Mutable view of the payload region of a packet.
///
/// The payload spans `content_start_pos()..len() - tag_len()`.
///
/// # Errors
/// * `LenSizeErr` if `pack.len() < topology.tag_len()`.
/// * `LenSizeErr` if `content_start_pos() > end_pos` (pack too short).
/// * `LenSizeErr` if the computed range is out of bounds.
pub fn payload_sls_mut<'a>(
    pack: &'a mut [u8],
    topology: &PackTopology,
) -> Result<&'a mut [u8], WTypeErr> {
    let end_pos = pack
        .len()
        .checked_sub(topology.tag_len())
        .ok_or_else(|| WTypeErr::LenSizeErr("pack len is less than tag_len".to_string()))?;

    let start_pos = topology.content_start_pos();
    if start_pos > end_pos {
        return Err(WTypeErr::LenSizeErr(
            "encrypt_start_pos exceeds end_pos".to_string(),
        ));
    }

    let in_me = pack.get_mut(start_pos..end_pos).ok_or_else(|| {
        WTypeErr::LenSizeErr("Calculated payload range is out of pack bounds".to_string())
    })?;

    Ok(in_me)
}
/// Immutable view of the payload region of a packet.
///
/// The payload spans `content_start_pos()..len() - tag_len()`.
///
/// # Errors
/// * `LenSizeErr` if `pack.len() < topology.tag_len()`.
/// * `LenSizeErr` if `content_start_pos() > end_pos` (pack too short).
/// * `LenSizeErr` if the computed range is out of bounds.s
pub fn payload_sls<'a>(pack: &'a [u8], topology: &PackTopology) -> Result<&'a [u8], WTypeErr> {
    let end_pos = pack
        .len()
        .checked_sub(topology.tag_len())
        .ok_or_else(|| WTypeErr::LenSizeErr("pack len is less than tag_len".to_string()))?;

    let start_pos = topology.content_start_pos();
    if start_pos > end_pos {
        return Err(WTypeErr::LenSizeErr(
            "encrypt_start_pos exceeds end_pos".to_string(),
        ));
    }

    let in_me = pack.get(start_pos..end_pos).ok_or_else(|| {
        WTypeErr::LenSizeErr("Calculated payload range is out of pack bounds".to_string())
    })?;

    Ok(in_me)
}

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
    let in_me = payload_sls_mut(pack, topology)?;

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
/// Its previous contents are cleared before copying.
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

    let in_me = payload_sls(pack, topology)?;

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

pub(crate) fn ttl_corr(ttl: &Ttl, ttl_t: &mut u64) -> Result<(), WTypeErr> {
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
pub fn crypt<Tencrer, Tnoncer, Tend>(
    pack: &mut [u8],
    topology: &PackTopology,
    enc_mode: Cryptlag,
    enc_struct: &mut Tencrer,
    countr: Option<&u64>,
    nonce_gener: Option<&mut Tnoncer>,
) -> Result<(), WTypeErr>
where
    Tencrer: EncWis<Tend>,
    Tnoncer: Noncer,
    Tend: EndCryptStuctor,
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

fn crypt_procress<Tencrer: EncWis<Tend>, Tend: EndCryptStuctor>(
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
