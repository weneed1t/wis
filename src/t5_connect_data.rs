use crate::t0pology::PackTopology;
use crate::t1queue_tcpudp::recv_queue::{
    WSQueueErr, WSQueueState, WSRecvQueueCtrs, WSUdpLike, WSWaitQueue,
};
use crate::t3poc_files::WSFileSplitter;
use crate::t4algo_param::WsConnectParam;
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

pub struct WsConnection<Tudp: Clone, Twait: Clone, Tencrypt: wt1_types::EncWis> {
    file_proc: WSFileSplitter,
    udp_queue: WSUdpLike<Tudp>,
    wait_queue: WSWaitQueue<Twait, f32>,
    fback_queue: WSRecvQueueCtrs,
    ctr_data: u64,
    ctr_fback: u64,
    network_stability: f32,
    network_latency: f32,
    enrypt: Tencrypt,
    connect_param: WsConnectParam,
    enrypaaa: bool,
    is_active: bool,
}

impl<Tudp: Clone, Twait: Clone, Tencrypt: wt1_types::EncWis> WsConnection<Tudp, Twait, Tencrypt> {
    pub fn new(
        connect_param: WsConnectParam,
        enrypt: Tencrypt,
        enrypaaa: bool,
    ) -> Result<Self, WSQueueErr> {
        Ok(Self {
            file_proc: WSFileSplitter::new(connect_param.max_len_file())
                .map_err(WSQueueErr::Critical)?,
            udp_queue: WSUdpLike::new(connect_param.maximum_length_udp_queue_packages())?,
            wait_queue: WSWaitQueue::new(
                connect_param.maximum_length_queue_unconfirmed_packages(),
            )?,
            fback_queue: WSRecvQueueCtrs::new(
                connect_param
                    .pack_topology()
                    .counter_slice()
                    .ok_or(WSQueueErr::Critical(""))?
                    .2,
                connect_param.maximum_length_fback_queue_packages(),
                connect_param.mtu(),
            )
            .unwrap(),
            ctr_data: 0,
            ctr_fback: 1,
            network_stability: 0.0,
            network_latency: 0.0,
            enrypt,
            connect_param,
            enrypaaa,
            is_active: true,
        })
    }
}
