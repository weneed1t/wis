#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::as_conversions)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::integer_division)]
//#![allow(clippy::expect_used)]
#![allow(clippy::unreachable)]
#![allow(clippy::todo)]
#![allow(clippy::float_cmp)]
#![forbid(unsafe_code)]

use crate::t5coon_d3_rand::*;
use crate::tests::t5connector_test::fast_wconn_maker;
use crate::w1utils::check_probability;
use crate::w1utils::fuck_coeff_of_rand_pack_trim;
mod tests {
    use super::*;

    #[test]
    fn decide_fake_forced_true_returns_false() {
        // force_no_edit_pack_type = Some(true)  → no fake

        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        temp.need_use_random.percent_fake_any_packets = Some((0.9f64 * u32::MAX as f64) as u32);

        let cp = temp;
        assert!(!decide_fake_status(&cp, Some(true), Some(0)).unwrap());
    }

    #[test]
    fn decide_fake_forced_false_returns_true() {
        // force_no_edit_pack_type = Some(false) → fake

        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        temp.need_use_random.percent_fake_any_packets = Some((0.0f64 * u32::MAX as f64) as u32);

        let cp = temp;

        assert!(decide_fake_status(&cp, Some(false), Some(0)).unwrap());
    }

    #[test]
    fn decide_fake_no_probability_returns_false() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        temp.need_use_random.percent_fake_any_packets = None;

        let cp = temp;

        assert!(!decide_fake_status(&cp, None, Some(123)).unwrap());
    }

    #[test]
    fn decide_fake_missing_rand_is_error() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        temp.need_use_random.percent_fake_any_packets = Some((0.5f64 * u32::MAX as f64) as u32);

        let cp = temp;
        assert!(decide_fake_status(&cp, None, None).is_err());
    }

    #[test]
    fn decide_fake_uses_probability1() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        // 50% fake → coeff ≈ u32::MAX / 2
        temp.need_use_random.percent_fake_any_packets = Some((0.5f64 * u32::MAX as f64) as u32);

        let cp = temp;

        let coeff = cp.percent_fake_any_packets().unwrap();

        // `decide_fake_status` must not reinterpret `rand`:
        // when `force=None` and `coeff=Some(...)`, it must delegate `check_probability` as is.
        for rand in [0u32, 1, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
            let expected = check_probability(coeff, rand);
            let actual = decide_fake_status(&cp, None, Some(rand)).unwrap();
            assert_eq!(
                actual, expected,
                "decide_fake_status diverged from check_probability at rand={rand}, coeff={coeff}"
            );
        }

        // Note: At a 50% threshold, the extreme values ​​of `rand` should yield
        // different results — otherwise, the coefficient is effectively "not working."
        let low = decide_fake_status(&cp, None, Some(0)).unwrap();
        let high = decide_fake_status(&cp, None, Some(u32::MAX)).unwrap();
        assert_ne!(
            low, high,
            "50% threshold should distinguish rand=0 from rand=u32::MAX"
        );
    }

    #[test]
    fn adjust_len_no_range_returns_same() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        temp.need_use_random.length_trimming_range = None;

        let cp = temp;
        let len = 100;
        let free_len_zone = 1000;

        assert_eq!(
            adjust_payload_len(&len, &free_len_zone, false, &cp, None).unwrap(),
            len
        );
    }

    #[test]
    fn adjust_len_missing_rand_is_error() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        // A valid value (1 <= x <= mtu), so that the "range is Some" branch is reachable.
        temp.need_use_random.length_trimming_range = Some(1);

        let cp = temp;
        let len = 100;
        let free_len_zone = 1000;

        assert!(adjust_payload_len(&len, &free_len_zone, false, &cp, None).is_err());
    }

    #[test]
    fn adjust_len_applies_range() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        temp.need_use_random.length_trimming_range = Some(1);

        let cp = temp;
        let len = 100;
        let free_len_zone = 1000;
        let can_trim = false;
        let rand_n = 7;

        let rangee = cp.length_trimming_range().unwrap();
        let expected =
            fuck_coeff_of_rand_pack_trim(&free_len_zone, &len, &rand_n, &rangee, can_trim).unwrap();

        assert_eq!(
            adjust_payload_len(&len, &free_len_zone, can_trim, &cp, Some(rand_n)).unwrap(),
            expected
        );
    }

    #[test]
    fn get_pack_len_no_random_returns_input_unchanged() {
        let mut temp = fast_wconn_maker().connect_param().as_ref().clone();

        // Disable all random options so that need_init_random() returns false.
        temp.need_use_random.percent_fake_any_packets = None;
        temp.need_use_random.length_trimming_range = None;

        let cp = temp;

        // Explicitly verify the test's premise: if fast_wconn_maker()
        // enables some additional random option by default, this assert
        // will indicate that it needs to be disabled right here.
        assert!(!cp.need_init_random());

        assert_eq!(
            get_pack_len_and_is_fake(&cp, None, false, &77, &13, None, None).unwrap(),
            (77, false)
        );
    }
}
