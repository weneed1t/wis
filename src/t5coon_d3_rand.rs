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

use crate::t4param::WsConnectParam;

use crate::w1utils::{check_probability, fuck_coeff_of_rand_pack_trim};

/// Determines the final payload length and the 'fake' flag.
pub fn get_pack_len_and_is_fake(
    cp: &WsConnectParam,
    force_no_edit_pack_type: Option<bool>,
    can_trim: bool,
    payload_len: &usize,
    overhead_len: &usize,
    rand_for_fake: Option<u32>,
    rand_for_range: Option<usize>,
) -> Result<(usize, bool), String> {
    // Quick exit: random effects are disabled — nothing to change.
    if !cp.need_init_random() {
        return Ok((*payload_len, false));
    }

    let free_len_zone = cp
        .mtu()
        .checked_sub(*overhead_len)
        .ok_or("mtu - overhead_len unreal state")?;

    let was_set_fake = decide_fake_status(cp, force_no_edit_pack_type, rand_for_fake)?;
    let final_len = adjust_payload_len(payload_len, &free_len_zone, can_trim, cp, rand_for_range)?;

    Ok((final_len, was_set_fake))
}

/// Determines whether a packet should be marked as "fake."
///
/// * `Some(true)`  — forces the packet to be "not fake"
/// * `Some(false)` — forces the packet to be "fake"
/// * `None`        — probabilistic, based on `cp.percent_fake_any_packets()`
pub(crate) fn decide_fake_status(
    cp: &WsConnectParam,
    force_no_edit_pack_type: Option<bool>,
    rand_for_fake: Option<u32>,
) -> Result<bool, String> {
    match force_no_edit_pack_type {
        Some(true) => return Ok(false),
        Some(false) => return Ok(true),
        None => {},
    }

    // Probabilistic branch.
    let Some(coeff) = cp.percent_fake_any_packets() else {
        return Ok(false);
    };
    let rand_n = rand_for_fake
        .ok_or("rand_for_fake must be Some when percent_fake_any_packets() is Some")?;
    Ok(check_probability(coeff, rand_n))
}

/// Randomly shortens or lengthens the payload within an allowed range.
/// If `cp.length_trimming_range()` is `None`, the length remains unchanged.
pub(crate) fn adjust_payload_len(
    payload_len: &usize,
    free_len_zone: &usize,
    can_trim: bool,
    cp: &WsConnectParam,
    rand_for_range: Option<usize>,
) -> Result<usize, String> {
    let Some(rangee) = cp.length_trimming_range() else {
        return Ok(*payload_len);
    };
    let rand_n =
        rand_for_range.ok_or("rand_for_range must be Some when length_trimming_range() is Some")?;
    fuck_coeff_of_rand_pack_trim(free_len_zone, payload_len, &rand_n, &rangee, can_trim)
}
