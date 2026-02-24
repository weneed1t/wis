//pub mod t10_api;
pub mod t0pology;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
pub mod t2proc_fields;

pub mod t3poc_files;
pub mod t4_connect_data;
pub mod t4algo_param;
pub mod wt1_types;
pub mod wutils; //utils //topology

mod t1queue_tcpudp;
pub use crate::t1queue_tcpudp::recv_queue::{
    WSQueueErr as ErrType, WSRecvQueueCtrs, WSTcpLike as TcpPackageSplitter, WSUdpLike,
    WSWaitQueue as UnconfirmedQueuePackets,
};

pub mod private_core {
    pub use crate::t0pology as PackageFields;
    pub use crate::t1fields as PacketsProcessingFields;
}
/*
delete this in prod da


git add . &&
git commit -S -m "dev" &&
git push origin main


*/
