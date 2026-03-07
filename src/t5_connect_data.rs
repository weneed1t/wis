use crate::t1queue_tcpudp::recv_queue::{WSQueueErr, WSRecvQueueCtrs, WSUdpLike, WSWaitQueue};
use crate::t3poc_files::WSFileSplitter;
use crate::t4algo_param::WsConnectParam;
use crate::wt1_types;
use crate::wt1_types::{Cfcser, MyRole, Noncer};
pub struct Ids {
    pub id_sender: u64,
    pub id_receiver: u64,
}

pub struct Identified {
    my_metall_id: u64,
    my_s_r_id: Option<Ids>,
    id_conn: Option<u64>,
}

pub struct WsConnection<
    TCfcser: Cfcser,
    Tnoncer: Noncer,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: wt1_types::EncWis,
> {
    file_proc: WSFileSplitter,
    udp_queue: WSUdpLike<Tudp>,
    wait_queue: WSWaitQueue<Twait, f32>,
    fback_queue: WSRecvQueueCtrs,
    ctr_data: u64,
    ctr_fback: u64,
    network_stability: f64,
    network_latency: f64,
    enrypt: Tencrypt,
    connect_param: WsConnectParam,
    enrypaaa: bool,
    is_active: bool,
    nonce_gener: Option<Tnoncer>,
    cfc_gener: Option<TCfcser>,
    measurement_window_latency: f64,
    my_role: MyRole,
    my_identified: Identified,
}

impl<TCfcser: Cfcser, Tnoncer: Noncer, Tudp: Clone, Twait: Clone, Tencrypt: wt1_types::EncWis>
    WsConnection<TCfcser, Tnoncer, Tudp, Twait, Tencrypt>
{
    pub fn new(
        connect_param: &WsConnectParam,
        default_enc_key: &[u8],
        my_role: MyRole,
        my_identified: Identified,
        nonce_seed: Option<&[u8]>,
        cfc_seed: Option<&[u8]>,
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
            enrypt: Tencrypt::new(default_enc_key).map_err(WSQueueErr::Critical)?,
            connect_param: connect_param.clone(),
            enrypaaa: true,
            is_active: true,
            nonce_gener: if connect_param.pack_topology().nonce_slice().is_some() {
                Some(
                    Tnoncer::new(nonce_seed.ok_or(WSQueueErr::Critical(
                        "nonce_seed is none but \
                         connect_param.pack_topology().nonce_slice().is_some() == true",
                    ))?)
                    .map_err(WSQueueErr::Critical)?,
                )
            } else {
                None
            },
            cfc_gener: if connect_param.pack_topology().head_crc_slice().is_some() {
                Some(
                    TCfcser::new(cfc_seed.ok_or(WSQueueErr::Critical(
                        "cfc_seed is none but \
                         connect_param.pack_topology().head_crc_slice().is_some() == true",
                    ))?)
                    .map_err(WSQueueErr::Critical)?,
                )
            } else {
                None
            },
            my_identified,
            my_role,
            measurement_window_latency: connect_param.start_ms_latency(),
        })
    }

    pub fn paste_file() {}

    pub fn send_pack() {}
    pub fn recv_pack() {}

    pub fn send_fake_pack() {}
}
