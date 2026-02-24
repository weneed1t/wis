use crate::t1queue_tcpudp::recv_queue;
use crate::t3poc_files::WSFileSplitter;
use crate::wt1_types;
pub struct Ids {
    pub id_sender: u64,
    pub id_receiver: u64,
}

pub struct Identified {
    my_metall_id: u64,
    my_s_r_id: Option<Ids>,
    id_conn: Option<u64>,
}

pub struct WsConnectData<Tudp, Twait, Tencrypt: wt1_types::EncWis> {
    file_proc: WSFileSplitter,
    udp_queue: recv_queue::WSUdpLike<Tudp>,
    wait_queue: recv_queue::WSWaitQueue<Twait, f32>,
    fback_queue: recv_queue::WSRecvQueueCtrs,
    ctr_data: u64,
    ctr_fback: u64,
    network_stability: f32,
    network_latency: f32,
    enrypt: Tencrypt,
}
