pub mod t10_api;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
pub mod t1pology;
pub mod t2fields_gen;
pub mod t2router;
pub mod t3conn;
pub mod wutils; //utils //topology

mod t1queue_tcpudp;
pub use crate::t1queue_tcpudp::recv_queue::{
    WSQueueErr as ErrType, WSTcpLike as TcpPackageSplitter, WaitQueue as UnconfirmedQueuePackets,
};

pub mod private_core {
    pub use crate::t1fields as PacketsProcessingFields;
    pub use crate::t1pology as PackageFields;
}
