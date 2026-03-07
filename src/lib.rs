//pub mod t10_api;
pub mod t0pology;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
pub mod t2proc_fields;

pub mod t3poc_files;
pub mod t4algo_param;
pub mod t5_connect_data;
pub mod wt1_types;
pub mod wutils; //utils //topology

mod t1queue_tcpudp;
pub mod zw;
pub use crate::t1queue_tcpudp::recv_queue::{
    WSQueueErr as ErrType, WSRecvQueueCtrs, WSTcpLike as TcpPackageSplitter, WSUdpLike,
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

*/
