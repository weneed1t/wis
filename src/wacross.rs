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

///wrapping_add
#[macro_export]
macro_rules! addw {
    ($a:expr, $b:expr) => {
        $a.wrapping_add($b)
    };
}
///wrapping_sub
#[macro_export]
macro_rules! subw {
    ($a:expr, $b:expr) => {
        $a.wrapping_sub($b)
    };
}
///wrapping_mul
#[macro_export]
macro_rules! mulw {
    ($a:expr, $b:expr) => {
        $a.wrapping_mul($b)
    };
}

//==================================================================

///checked_sub
#[macro_export]
macro_rules! subex {
    ($lhs:expr, $rhs:expr, $msg:expr) => {
        $lhs.checked_sub($rhs).EXPCP!($msg)
    };
}
///checked_mul
#[macro_export]
macro_rules! mulex {
    ($lhs:expr, $rhs:expr, $msg:expr) => {
        $lhs.checked_mul($rhs).EXPCP!($msg)
    };
}
///checked_add
#[macro_export]
macro_rules! addex {
    ($lhs:expr, $rhs:expr, $msg:expr) => {
        $lhs.checked_add($rhs).EXPCP!($msg)
    };
}
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
/// 1. Result: Returns Result<T, &'static str> for use with the '?' operator.
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
