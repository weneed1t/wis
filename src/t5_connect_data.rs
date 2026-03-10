use crate::t1queue_tcpudp::recv_queue::{WSRecvQueueCtrs, WSUdpLike, WSWaitQueue};
use crate::t3poc_files::WSFileSplitter;
use crate::t4algo_param::WsConnectParam;
use crate::wt1_types::{
    Cfcser, EncWis, MyRole, /* , Cfcser, WTypeErr */
    Noncer, PackErr, Randomer, Thrasher, WSQueueErr,
};
#[derive(Clone)]
pub struct Ids {
    pub id_sender: u64,
    pub id_receiver: u64,
}

#[derive(Clone)]
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
    TCfcser: Cfcser,
> {
    file_proc: WSFileSplitter,           //-
    udp_queue: WSUdpLike<Tudp>,          //-
    wait_queue: WSWaitQueue<Twait, f64>, //-
    fback_queue: WSRecvQueueCtrs,        //-
    ctr_data: u64,
    ctr_fback: u64,
    network_stability: f64,
    network_latency: f64,
    encrypt: Tencrypt,
    connect_param: WsConnectParam,
    enrypaaa: bool,
    is_active: bool,
    nonce_gener: Option<Tnoncer>, //+

    user_field_gener: Option<TThrasher>, //+
    random_gener: Option<TRandomer>,     //+
    crc_gener: Option<TCfcser>,
    measurement_window_latency: f64,
    my_role: MyRole,
    intermediate_questionable_packages_queue: Option<Box<[u8]>>,
    identified: Identified, //+
}

impl<
    /* TCfcser: Cfcser, */
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
    TCfcser: Cfcser,
> WsConnection</* TCfcser, */ Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer, TCfcser>
{
    pub fn new(
        connect_param: &WsConnectParam,
        default_enc_key: &[u8],
        my_role: MyRole,
        nonce_seed: Option<&[u8]>,
        random_seed: Option<&[u8]>,
        user_field_seed: Option<&[u8]>,
        crc_seed: Option<&[u8]>,
        identified: &Identified, //crc_seed: Option<&[u8]>,
    ) -> Result<Self, WSQueueErr> {
        if connect_param.pack_topology().idconn_slice().is_some() && identified.id_conn.is_none() {
            return Err(WSQueueErr::Critical(
                "connect_param.pack_topology().idconn_slice().is_some() == true but \
                 identified.id_conn.is_none() == false, you need to set a value for \
                 identified.id_conn",
            ));
        }

        if let Some(xids) = &identified.my_s_r_id
            && xids.id_receiver == xids.id_sender
        {
            return Err(WSQueueErr::Critical(
                "identified.id_receiver == identified.id_sender The sender and recipient IDs must \
                 be different!",
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
            crc_gener: if connect_param.pack_topology().head_crc_slice().is_some() {
                Some(
                    TCfcser::new(crc_seed.ok_or(WSQueueErr::Critical(
                        "crc_seed is none but \
                         connect_param.pack_topology().head_crc_slice().is_some() == true",
                    ))?)
                    .map_err(WSQueueErr::Critical)?,
                )
            } else {
                None
            },
            ctr_data: 0,
            ctr_fback: 1,
            network_stability: 0.0,
            network_latency: 0.0,
            encrypt: Tencrypt::new(default_enc_key).map_err(WSQueueErr::Critical)?,
            connect_param: connect_param.clone(),
            enrypaaa: true,
            is_active: true,
            intermediate_questionable_packages_queue: connect_param
                .intermediate_questionable_packages_queue()
                .map(|vec_q| vec![0; vec_q].into_boxed_slice()),

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
            identified: identified.clone(),
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
    TCfcser: Cfcser,
> WsConnection<Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer, TCfcser>
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
mod test_new {
    use super::*;
    use crate::wt1_types::*;
    use crate::{t0pology, t4algo_param};

    #[test]
    fn idconn_slice() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[6, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "connect_param.pack_topology().idconn_slice().is_some() == true but \
                 identified.id_conn.is_none() == false, you need to set a value for \
                 identified.id_conn"
            )
        );
    }

    #[test]
    fn idconn_slice_inv() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: Some(999),
            },
        );

        assert_eq!(te1.is_ok(), true);
    }

    #[test]
    fn id_of_sender_slice() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "connect_param.pack_topology().id_of_sender_slice().is_some() == true but \
                 identified.my_s_r_id.is_none() == false, you need to set a value for \
                 identified.my_s_r_id"
            )
        );
    }

    #[test]
    fn id_of_sender_slice_inv1() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3333,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "identified.id_receiver == identified.id_sender The sender and recipient IDs must \
                 be different!"
            )
        );
    }

    #[test]
    fn id_of_sender_slice_inv2() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[6, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.is_ok(), true);
    }

    #[test]
    fn nonce_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
            t0pology::PackFields::Nonce(10),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "nonce_seed is none but connect_param.pack_topology().nonce_slice().is_some() == \
                 true"
            )
        );
    }

    #[test]
    fn nonce_gener_inv() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
            t0pology::PackFields::Nonce(10),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[1, 1, 1, 1]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.is_ok(), true);

        assert_eq!(te1.unwrap().nonce_gener.unwrap().v, vec![1, 1, 1, 1])
    }

    #[test]
    fn user_field_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            Some(&[3, 3, 3, 3]),
            None,
            None,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "user_field_seed is none but \
                 connect_param.pack_topology().trash_content_slice().is_some() == true, \
                 `trash_content_slice() is user_field` "
            )
        );
    }

    #[test]
    fn user_field_gener_inv() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po).build().unwrap();

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[1, 1, 1, 1]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.is_ok(), true);

        assert_eq!(te1.unwrap().user_field_gener.unwrap().v, vec![4, 4, 4, 4])
    }

    #[test]
    fn random_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po)
            .percent_fake_data_packets(Some(0.3))
            .percent_fake_fback_packets(Some(0.3))
            .percent_len_random_coefficient(Some(0.3))
            .build()
            .unwrap();

        assert_eq!(result.need_init_random(), true);

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            None,
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "random_seed is none but connect_param.need_init_random() == true"
            )
        );
    }

    #[test]
    fn random_gener_inv1() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po)
            .percent_fake_data_packets(Some(0.3))
            //.percent_fake_fback_packets(Some(0.3))
            //.percent_len_random_coefficient(Some(0.3))
            .build()
            .unwrap();

        assert_eq!(result.need_init_random(), true);

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.unwrap().random_gener.unwrap().v, vec![3, 3, 3, 3]);
    }

    #[test]
    fn random_gener_inv2() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert_eq!(result.need_init_random(), false);

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.unwrap().random_gener.is_none(), true);
    }

    #[test]
    fn cfc_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert_eq!(result.need_init_random(), false);

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            None,
            Some(&[4, 4, 4, 4]),
            None,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WSQueueErr::Critical(
                "crc_seed is none but connect_param.pack_topology().head_crc_slice().is_some() == \
                 true"
            )
        );
    }

    #[test]
    fn cfc_gener_inv1() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert_eq!(result.need_init_random(), false);

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            None,
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.unwrap().crc_gener.unwrap().v, vec![5, 5, 5, 5]);
    }

    #[test]
    fn cfc_gener_inv2() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert_eq!(result.need_init_random(), false);

        let te1: Result<
            WsConnection<DumpNonser, DumpThrasher, u32, u32, DumpEnc, DumpRandomer, DumpCfcser>,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            None,
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.unwrap().random_gener.is_none(), true);
    }
}
