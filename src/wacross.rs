#[macro_export]
macro_rules! addw {
    ($a:expr, $b:expr) => {
        $a.wrapping_add($b)
    };
}

#[macro_export]
macro_rules! subw {
    ($a:expr, $b:expr) => {
        $a.wrapping_sub($b)
    };
}

#[macro_export]
macro_rules! mulw {
    ($a:expr, $b:expr) => {
        $a.wrapping_mul($b)
    };
}

//==================================================================
#[macro_export]
macro_rules! subex {
    ($lhs:expr, $rhs:expr, $msg:expr) => {
        $lhs.checked_sub($rhs).EXPCP!($msg)
    };
}

#[macro_export]
macro_rules! mulex {
    ($lhs:expr, $rhs:expr, $msg:expr) => {
        $lhs.checked_mul($rhs).EXPCP!($msg)
    };
}

#[macro_export]
macro_rules! addex {
    ($lhs:expr, $rhs:expr, $msg:expr) => {
        $lhs.checked_add($rhs).EXPCP!($msg)
    };
}

#[macro_export]
macro_rules! EXPCP {
    ($expr:expr, $msg:expr) => {
        $expr.expect($msg)
    };
}
