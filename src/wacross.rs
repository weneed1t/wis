//#![deny(clippy::indexing_slicing)]
//#![deny(clippy::unwrap_used)]
//#![deny(clippy::as_conversions)]
//#![deny(clippy::arithmetic_side_effects)]
//#![deny(clippy::integer_division)]
//#![deny(clippy::expect_used)]
//#![deny(clippy::unreachable)]
//#![deny(clippy::todo)]
//#![deny(clippy::float_cmp)]
//#![forbid(unsafe_code)]

///exept
#[macro_export]
macro_rules! EXPCP {
    ($expr:expr, $msg:expr) => {
        $expr.expect($msg)
    };
}

/// SAFE INTEGER CONVERSION MACRO
///
/// This macro safely converts between integer types using TryFrom,
/// preventing silent truncation or data loss.
///
/// STRATEGIES:
/// 1. Result: Returns Result<T, String> for use with the '?' operator.
/// 2. Panic: Uses 'unwrap' or 'expect' for cases where failure is a bug.
/// 3. Custom Error: Allows attaching a specific message to the error.
///
/// ARGUMENTS:
/// - $x: The value to convert (e.g., ///key, u8::MAX).
/// - $t: The target type (e.g., usize, i64).
///
/// USAGE EXAMPLES:
///
/// // A. Handle errors with '?'
/// let idx = checked_cast!(key => usize)?;
/// let idx = checked_cast!(key => usize, err "Key out of range")?;
///
/// // B. Panic on failure
/// let val = checked_cast!(some_u64 => usize, unwrap);
/// let val = checked_cast!(some_u64 => usize, expect "Should fit");
///
/// // C. In closures or logic blocks
/// let is_valid = |p: u16| checked_cast!(p => usize, unwrap) < limit;
///
/// SAFETY:
/// Uses TryFrom trait. Prefer the Result variant (?) for recoverable errors.
/// Use expect/unwrap only when conversion is guaranteed by logic.
#[macro_export]
macro_rules! checked_cast {
    // No extra actions - returns Result with default error message
    ($x:expr => $t:ty) => {
        $crate::checked_cast!($x => $t, return_result)
    };

    // Panic with custom message (for unrecoverable errors)
    ($x:expr => $t:ty, expect $msg:expr) => {{
        //use std::convert::TryInto;
        <$t>::try_from($x).expect($msg)
    }};

    // Simple panic with default message (for quick prototyping)
    ($x:expr => $t:ty, unwrap) => {{
        use std::convert::TryInto;
        <$t>::try_from($x).unwrap()
    }};

    // Returns Result with custom error (for use with ? operator)
    ($x:expr => $t:ty, err $err:expr) => {{
        //use std::convert::TryInto;
        <$t>::try_from($x).map_err(|_| $err)
    }};

    // Returns Result with detailed default error message
    ($x:expr => $t:ty, return_result) => {{
        use std::convert::TryInto;
        <$t>::try_from($x).map_err(|_| concat!(
            "conversion failed: cannot cast `",
            stringify!($x),
            "` to `",
            stringify!($t),
            "`"
        ))
    }};
}
#[macro_export]
///math_safe calls expect on overflow in the release build and in test scenarios
macro_rules! math_safe {
    ($a:expr, $b:expr, add) => {
        $a.checked_add($b).expect("overflow")
    };
    ($a:expr, $b:expr, sub) => {
        $a.checked_sub($b).expect("underflow")
    };
    ($a:expr, $b:expr, mul) => {
        $a.checked_mul($b).expect("overflow")
    }; //    ($a:expr, $b:expr, ss) => {
       //        $a.checked_sub($b).expect("underflow")
       //    };
}
#[macro_export]
/// wrapp math
macro_rules! math_wrapp {
    ($a:expr, $b:expr, add) => {
        $a.wrapping_add($b)
    };
    ($a:expr, $b:expr, sub) => {
        $a.wrapping_sub($b)
    };
    ($a:expr, $b:expr, mul) => {
        $a.wrapping_mul($b)
    }; //    ($a:expr, $b:expr, ss) => {
       //        $a.checked_sub($b).expect("underflow")
       //    };
}

//
//
#[cfg(test)]
mod test_wk {
    #[test]
    #[should_panic(expected = "overflow")]
    fn test_add_overflow() {
        let _ = math_safe!(0xFF_FF_FF_FF_u32, 10_u32, add);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_mul_overflow() {
        let _ = math_safe!(0xFF_FF_FF_FF_u32, 10_u32, mul);
    }

    #[test]
    #[should_panic(expected = "underflow")] // например
    fn test_sub_underflow() {
        let _ = math_safe!(0_u32, 1_u32, sub);
    }

    #[test]
    fn test_add_() {
        let r = math_safe!(0xFF_FF_FF_F0_u32, 10_u32, add);
        assert_eq!(r, 0xFF_FF_FF_FA_u32)
    }

    #[test]
    fn test_mul_() {
        let r = math_safe!(0xFF_FF_FF_u32, 0x10_u32, mul);
        assert_eq!(r, 0xF_FF_FF_F0u32)
    }

    #[test]
    fn test_sub_() {
        let r = math_safe!(3_u32, 1_u32, sub);
        assert_eq!(r, 2)
    }

    #[test]
    fn test_math_wrapp_operations() {
        let a = 5u32;
        let b = 3u32;

        // Сложение
        assert_eq!(math_wrapp!(a, b, add), 8);
        // Вычитание
        assert_eq!(math_wrapp!(a, b, sub), 2);
        // Умножение
        assert_eq!(math_wrapp!(a, b, mul), 15);
    }
}
