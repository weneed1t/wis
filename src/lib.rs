//pub mod t10_api;
#![forbid(unsafe_code)]
//#![deny(clippy::all)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod t0pology;
pub mod t1dumps_struct;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
//pub mod __t2proc_fields;
pub mod wacross;

mod t1queue_tcpudp;
pub mod t3poc_files;
pub mod t4algo_param;
pub mod t5_2_connect_data;
pub mod t5_connect_data;
pub mod w1utils;
pub mod wt1types; //utils //topology

pub mod t0_grouper;
pub mod t0_parsel;

#[cfg(feature = "wisdel")]
pub mod wisdel;

pub use crate::t1queue_tcpudp::recv_queue::{
    WSRecvQueueCtrs, WSTcpLike as TcpPackageSplitter, WSUdpLike,
    WSWaitQueue as UnconfirmedQueuePackets,
};

pub mod private_core {
    pub use crate::{t0pology as PackageFields, t1fields as PacketsProcessingFields};
}
/*
delete this in prod dapgp

rustup component add clippy
cargo clippy --fix
cargo fix --allow-dirty
cargo clippy --fix --allow-dirty --broken-code

git add . &&
git commit -S -m "dev" &&
git push origin main

cargo fix --allow-dirty
cargo clippy --fix --all --allow-dirty
git rm -r --cached t.txt


cargo +nightly fmt
rustup toolchain install nightly
rustup run nightly cargo fmt


cargo clippy --fix  --allow-dirty &&
cargo fix --allow-dirty &&
cargo clippy --fix --allow-dirty --broken-code &&
cargo clippy --fix --all --allow-dirty &&
rustup run nightly cargo fmt &&
cargo fmt


if a have crush
rustup component add rust-analyzer
*/
