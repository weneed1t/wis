//pub mod t10_api;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
pub mod t1pology;

pub mod t10algo_param;

//pub mod t2fields_gen;
//pub mod t2router;
//pub mod t3conn;
pub mod t3poc_files;
pub mod wutils; //utils //topology

mod t1queue_tcpudp;
pub use crate::t1queue_tcpudp::recv_queue::{
    WSQueueErr as ErrType, WSRecvQueueCtrs, WSTcpLike as TcpPackageSplitter, WSUdpLike,
    WSWaitQueue as UnconfirmedQueuePackets,
};

pub mod private_core {
    pub use crate::t1fields as PacketsProcessingFields;
    pub use crate::t1pology as PackageFields;
}
/* delete this in prod
git add . &&
git commit -m "DEATH TRUNK" &&
git push origin
*/
