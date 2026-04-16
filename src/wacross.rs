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
