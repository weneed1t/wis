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
/*
/// Determines the final payload length and whether the packet was marked as fake.
///
/// The function may randomly adjust the packet length within a configured range
/// and optionally change the packet type to `Fake` with a given probability.
///
/// # Arguments
/// * `force_no_edit_pack_type` – if `true`, prevents the type from being changed to `Fake`.
/// * `pack_type` – current packet type (Data, Fback, or Fake).
/// * `payload_len` – current payload length.
/// * `overhead_len` – length of protocol overhead.
///
/// # Returns
/// * `Ok((new_length, was_fake))` – the adjusted length and a boolean indicating
///   whether the type was actually changed to `Fake`.
/// * `Err` – if the free space cannot be computed or the random generator is missing.
/// The final pack is constructed from overhead_len + get_pack_len_and_is_fake(...)
/// The function returns the length of the PAYLOAD ONLY!
/// force_no_edit_pack_type: None -> pack_type is random
/// force_no_edit_pack_type: true -> force set pack_type is non edit
/// force_no_edit_pack_type: false -> force set pack_type is fake
///
///
pub fn get_pack_len_and_is_fake(
    cp: &WsConnectParam,
    force_no_edit_pack_type: Option<bool>,
    can_trim: bool,
    payload_len: &usize,
    overhead_len: &usize,
    rand_for_fake: Option<u32>,
    rand_for_range: Option<usize>,
) -> Result<(usize, bool), String> {
    let random_need = cp.need_init_random();
    let mtu = cp.mtu();

    let mut ret_len = *payload_len;

    // Maximum payload size allowed by the link MTU minus overhead.
    let free_len_zone = mtu
        .checked_sub(*overhead_len)
        .ok_or("mtu - overhead_len unreal state")?;
    //
    // for test
    #[cfg(test)]
    let mut alg_param = (
        ret_len,       //ret len after edit // 0
        mtu,           //mut // 1
        free_len_zone, // free zone 2
        None,          //pack type after edit 3
        can_trim,      // pack edit before edit 4
        None,          // rand u32  5
        None,          // need trim 6
        None,          //rand_n usize // 7
        random_need,   // random_need 8,
        cp.length_trimming_range(),
    );

    // Random adjustments are only applied if enabled globally.
    let was_set_fake = if random_need {
        let ranger = cp.length_trimming_range();
        let coef_fake = cp.percent_fake_any_packets();
        /*
                    let rnd = self.random_gener.as_mut().ok_or(
                        "impossible state random_gener is none,it must be defined get_pack_len_and_is_fake",
                    )?;
        */

        // Possibly convert the packet to Fake based on probability.
        let was_set_fake_local = match force_no_edit_pack_type {
            Some(true) => false,
            Some(false) => true,
            None => {
                if let Some(coeff) = coef_fake {
                    let rand_n = rand_for_fake.ok_or(
                            "impossible state rand_for_fake is none,it must be defined get_pack_len_and_is_fake",
                        )?;

                    #[cfg(test)]
                    {
                        alg_param.5 = Some(rand_n);
                        alg_param.3 = Some(can_trim);
                    }
                    check_probability(coeff, rand_n)
                } else {
                    false
                }
            },
        };

        // Randomly trim or extend the payload length within the allowed range.
        if let Some(rangee) = ranger {
            let rand_n = rand_for_range.ok_or(
                            "impossible state rrand_for_range is none,it must be defined get_pack_len_and_is_fake",
                        )?;

            #[cfg(test)]
            {
                alg_param.6 = Some(can_trim);
                alg_param.7 = Some(rand_n);
            }

            ret_len = fuck_coeff_of_rand_pack_trim(
                &free_len_zone,
                payload_len,
                &rand_n,
                &rangee,
                can_trim,
            )?;
        }
        was_set_fake_local
    } else {
        false
    };

    #[cfg(test)]
    test_get_pack_len_and_is_fake(
        (ret_len, was_set_fake),
        (
            force_no_edit_pack_type,
            can_trim,
            *payload_len,
            *overhead_len,
        ),
        alg_param,
    );

    Ok((ret_len, was_set_fake))
}

#[cfg(test)]
fn test_get_pack_len_and_is_fake(
    return_param: (usize, bool),
    input_param: (Option<bool>, bool, usize, usize),
    hiddy_param: (
        usize,         // 0: ret_len after edit
        usize,         // 1: mtu
        usize,         // 2: free_len_zone
        Option<bool>,  // 3: pack_type after edit (if coef_fake condition met)
        bool,          // 4: pack_type before edit
        Option<u32>,   // 5: rand_u32 (if coef_fake condition met)
        Option<bool>,  // 6: need_trimm (if ranger present)
        Option<usize>, // 7: rand_n usize (if ranger present)
        bool,          // 8: random_need
        Option<usize>, //  length_trimming_range
    ),
) {
    #![allow(clippy::unwrap_used)]

    let (ret_len, was_set_fake) = return_param;
    let (force_no_edit, pack_type_in, payload_len, overhead_len) = input_param;
    let (
        ret_len_after_edit,
        mtu,
        free_len_zone,
        pack_type_after_edit_opt,
        pack_type_before_edit,
        rand_u32_opt,
        need_trimm_opt,
        rand_n_opt,
        random_need,
        length_trimming_range,
    ) = hiddy_param;

    if let Some(x) = force_no_edit {
        assert_ne!(x, !was_set_fake);
    }

    assert_eq!(mtu.checked_sub(overhead_len).unwrap(), free_len_zone);

    // Check that the stored ret_len matches the returned length.
    assert_eq!(ret_len_after_edit, ret_len);

    // Verify that the 'before edit' pack type is as passed.
    assert_eq!(pack_type_before_edit, pack_type_in);

    // If random adjustments are disabled, nothing should change.
    if !random_need {
        assert_eq!(ret_len, payload_len);
        assert!(!was_set_fake);
        assert_eq!(pack_type_after_edit_opt.clone(), None);
        assert_eq!(rand_u32_opt, None);
        assert_eq!(need_trimm_opt, None);
        assert_eq!(rand_n_opt, None);
        return;
    }

    // --- Random adjustments are enabled ---

    // Check fake conversion path.
    // coef_fake and force_no_edit are known only at runtime, but we can check invariants:
    // If pack_type_after_edit_opt is Some, it means the condition (coef_fake && !force_no_edit) was true.
    // If it is None, the condition was false.
    let p_temt = pack_type_after_edit_opt;
    if let Some(_pack_type_after) = p_temt {
        // Then rand_u32 must have been generated.
        assert!(rand_u32_opt.is_some());
        // If was_set_fake is true, the type must have been changed to Fake.
    } else {
        // Condition not met -> no fake probability evaluation.
        assert_eq!(rand_u32_opt, None);
        // was_set_fake must be false because fake cannot be set.
        assert!(!was_set_fake);
        // pack_type_after remains the original (but we don't store it).
    }

    // Check length trimming path.
    if let (Some(need_trimm), Some(rand_n)) = (need_trimm_opt, rand_n_opt) {
        // ranger was present.
        // Recompute expected length using the same logic as in fuck_coeff_of_rand_pack_trim.
        let expected_len = fuck_coeff_of_rand_pack_trim(
            &free_len_zone,
            &payload_len,
            &rand_n,
            &length_trimming_range.unwrap(), // rangee must be the same, but we don't have it directly.,
            need_trimm,
        )
        .unwrap();

        assert_eq!(expected_len, ret_len);

        // However, we don't have the actual rangee value in hiddy_param.
        // We can retrieve it from the connection params, but that would break isolation.
        // Instead, we can trust that the function's logic is correct and just check that ret_len is within bounds.
        assert!(ret_len >= 1 && ret_len <= free_len_zone);
        // Also check that ret_len matches the value stored in alg_param.0 (already checked).
        // We can also verify that if need_trimm == true (no_trim == false), then ret_len may be less than payload_len,
        // but not strictly enforceable because random_offset can increase it.
    } else {
        // ranger not present -> no length adjustment.
        assert_eq!(need_trimm_opt, None);
        assert_eq!(rand_n_opt, None);
        assert_eq!(ret_len, payload_len);
    }

    // Additional invariants:
    // If was_set_fake is true, the final pack_type (input_param.1 after mutation) must be Fake,
    // but we don't have that value. However, we can deduce: if was_set_fake true, then pack_type_after_edit_opt must be Some(Fake).

    // Ensure that if random_need is false, the options are all None (already covered above).
}


*/

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
