use crate::t1queue_tcpudp::recv_queue::{WSRecvQueueCtrs, WSUdpLike, WSWaitQueue};
use crate::t3poc_files::WSFileSplitter;
use crate::t4algo_param::WsConnectParam;
use crate::wt1_types::{
    EncWis, MyRole, /* , Cfcser, WTypeErr */
    Noncer, PackErr, Randomer, Thrasher, WSQueueErr,
};
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
    //TCfcser: Cfcser,
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
> {
    file_proc: WSFileSplitter,
    udp_queue: WSUdpLike<Tudp>,
    wait_queue: WSWaitQueue<Twait, f64>,
    fback_queue: WSRecvQueueCtrs,
    ctr_data: u64,
    ctr_fback: u64,
    network_stability: f64,
    network_latency: f64,
    encrypt: Tencrypt,
    connect_param: WsConnectParam,
    enrypaaa: bool,
    is_active: bool,
    nonce_gener: Option<Tnoncer>,
    //cfc_gener: Option<TCfcser>,
    user_field_gener: Option<TThrasher>,
    random_gener: Option<TRandomer>,
    measurement_window_latency: f64,
    my_role: MyRole,
    intermediate_questionable_packages_queue: Option<Box<[u8]>>,
    identified: Identified,
}

impl<
    /* TCfcser: Cfcser, */
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
> WsConnection</* TCfcser, */ Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer>
{
    pub fn new(
        connect_param: &WsConnectParam,
        default_enc_key: &[u8],
        my_role: MyRole,
        nonce_seed: Option<&[u8]>,
        random_seed: Option<&[u8]>,
        user_field_seed: Option<&[u8]>,
        identified: Identified, //cfc_seed: Option<&[u8]>,
    ) -> Result<Self, WSQueueErr> {
        if connect_param.pack_topology().idconn_slice().is_some() && identified.id_conn.is_none() {
            return Err(WSQueueErr::Critical(
                "connect_param.pack_topology().idconn_slice().is_some() == true but \
                 identified.id_conn.is_none() == false, you need to set a value for \
                 identified.id_conn",
            ));
        }

        if connect_param.pack_topology().id_of_sender_slice().is_some()
            && identified.my_s_r_id.is_none()
        {
            return Err(WSQueueErr::Critical(
                "connect_param.pack_topology().id_of_sender_slice().is_some() == true but \
                 identified.my_s_r_id.is_none() == false, you need to set a value for \
                 identified.my_s_r_id",
            ));
        }

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
                    .ok_or(WSQueueErr::Critical(
                        ".pack_topology().counter_slice() is empty, but the algorithm requires \
                         the explicit presence of a counter!!!",
                    ))?
                    .2,
                connect_param.maximum_length_fback_queue_packages(),
                connect_param.mtu(),
            )
            .map_err(WSQueueErr::Critical)?,
            ctr_data: 0,
            ctr_fback: 1,
            network_stability: 0.0,
            network_latency: 0.0,
            encrypt: Tencrypt::new(default_enc_key).map_err(WSQueueErr::Critical)?,
            connect_param: connect_param.clone(),
            enrypaaa: true,
            is_active: true,
            intermediate_questionable_packages_queue: None,

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
            }, /*
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
               */
            user_field_gener: if connect_param
                .pack_topology()
                .trash_content_slice()
                .is_some()
            {
                Some(
                    TThrasher::new(user_field_seed.ok_or(WSQueueErr::Critical(
                        "user_field_seed is none but \
                         connect_param.pack_topology().trash_content_slice().is_some() == true, \
                         `trash_content_slice() is user_field` ",
                    ))?)
                    .map_err(WSQueueErr::Critical)?,
                )
            } else {
                None
            },
            random_gener: if connect_param.need_init_random() {
                Some(
                    TRandomer::new(random_seed.ok_or(WSQueueErr::Critical(
                        "random_seed is none but connect_param.need_init_random() == true",
                    ))?)
                    .map_err(WSQueueErr::Critical)?,
                )
            } else {
                None
            },
            my_role,
            measurement_window_latency: connect_param.start_ms_latency(),
            identified,
        })
    }

    fn add_two(&self, num: &mut u64) -> Result<(), PackErr> {
        *num = num.checked_add(2).ok_or(PackErr::UndefinedErr(
            "The capacity limit of the main counter u64 has been reached, so it is no longer \
             possible to send new messages over this connection. The connection must be closed!",
        ))?;
        Ok(())
    }

    pub fn paste_file() {}

    pub fn send_pack() {}
    pub fn recv_pack() {}

    pub fn send_fake_pack() {}
}

// getters for wsconnection - separate impl for clarity
impl<
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
> WsConnection<Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer>
{
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn my_role(&self) -> MyRole {
        self.my_role.clone()
    }

    pub fn network_latency(&self) -> f64 {
        self.network_latency
    }

    pub fn network_stability(&self) -> f64 {
        self.network_stability
    }

    pub fn ctr_data(&self) -> u64 {
        self.ctr_data
    }

    pub fn ctr_fback(&self) -> u64 {
        self.ctr_fback
    }

    pub fn connect_param(&self) -> &WsConnectParam {
        &self.connect_param
    }

    pub fn identified(&self) -> &Identified {
        &self.identified
    }

    pub fn measurement_window_latency(&self) -> &f64 {
        &self.measurement_window_latency
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn create_test() {}
}
