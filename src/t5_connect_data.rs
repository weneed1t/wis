use crate::t1queue_tcpudp::recv_queue::{WSRecvQueueCtrs, WSUdpLike, WSWaitQueue};
use crate::t3poc_files::WSFileSplitter;
use crate::t4algo_param::WsConnectParam;
use crate::w1utils::SafeBuffer;
use crate::wt1types::{
    Crcser, EncWis, HandMaker, Identified, MyRole, Noncer, Randomer, Thrasher, WSQueueErr,
};

const FBACK_START_CTR: u64 = 1;
const DATA_START_CTR: u64 = 0;

/// see method new
pub struct WsConnection<
    //TCfcser: Cfcser,
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
    TCfcser: Crcser,
    Hmaker: HandMaker,
> {
    file_splitter: WSFileSplitter,       //-
    udp_queue: WSUdpLike<Tudp>,          //-
    wait_queue: WSWaitQueue<Twait, f64>, //-
    fback_queue: WSRecvQueueCtrs<f64>,   //-
    my_ctr_data: u64,
    my_ctr_fback: u64,
    frend_ctr_data: u64,
    frend_ctr_fback: u64,
    network_stability: f64,
    network_latency: f64,
    encrypt: Tencrypt,
    connect_param: WsConnectParam,
    enrypaaa: Hmaker,
    handshake_is_end: bool,
    nonce_gener: Option<Tnoncer>, //+

    user_field_gener: Option<TThrasher>, //+
    random_gener: Option<TRandomer>,     //+
    crc_gener: Option<TCfcser>,
    measurement_window_latency: f64,
    my_role: MyRole,
    intermediate_questionable_packages_queue: Option<Box<[u8]>>,
    identified: Identified, //+
    non_alloc_buf: Option<SafeBuffer>,
    was_killed: bool,
}

impl<
    /* TCfcser: Cfcser, */
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
    TCfcser: Crcser,
    Hmaker: HandMaker,
>
    WsConnection<
        /* TCfcser, */ Tnoncer,
        TThrasher,
        Tudp,
        Twait,
        Tencrypt,
        TRandomer,
        TCfcser,
        Hmaker,
    >
{
    ///Create a new connection. `default_enc_key` is the key that will be used at the
    /// start of the connection before the private key is initialized.
    ///`my_role` refers to the role of the user who initiated the connection or the user
    /// who accepted the connection. `handmaker/nonce/crc/random seed` are the initial
    /// values for the corresponding classes (`random` is used to generate a random
    /// packet length if this option is enabled). The `identified` field is not
    /// strictly necessary and should not (at least not yet—perhaps this will change?)
    /// be used to influence packet identification
    ///when a packet arrives at the input; however, when a packet is generated within
    /// this class (structure), the values from `identified` are automatically
    /// included in the packet if the corresponding fields are specified.
    ///`use_non_alloc_buf` is also a deprecated setting
    ///(again, this code is still under development, and I can't say for sure whether
    /// this will change in the future) use_non_alloc_buf is needed so that when
    /// generating a packet, a new array isn't allocated in memory, but instead uses
    /// an already allocated temp array; if use_non_alloc_buf is true, then a temp
    /// array of length MTU is created (so don't set MTU to a very large value)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connect_param: &WsConnectParam,
        default_enc_key: &[u8],
        my_role: MyRole,
        nonce_seed: Option<&[u8]>,
        random_seed: Option<&[u8]>,
        user_field_seed: Option<&[u8]>,
        crc_seed: Option<&[u8]>,
        handmaker_seed: &[u8],
        identified: &Identified,
        use_non_alloc_buf: bool,
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
            file_splitter: WSFileSplitter::new(connect_param.max_len_file())
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
            my_ctr_data: DATA_START_CTR,
            my_ctr_fback: FBACK_START_CTR, //
            frend_ctr_data: DATA_START_CTR,
            frend_ctr_fback: FBACK_START_CTR, //
            network_stability: 0.0,
            network_latency: 0.0,
            encrypt: Tencrypt::new(default_enc_key).map_err(WSQueueErr::Critical)?,
            connect_param: connect_param.clone(),
            enrypaaa: Hmaker::new(my_role.clone(), handmaker_seed).map_err(WSQueueErr::Critical)?, /* in progress */
            handshake_is_end: false,
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
            non_alloc_buf: if use_non_alloc_buf {
                Some(SafeBuffer::new(connect_param.mtu()))
            } else {
                None
            },
            was_killed: false,
        })
    }

    fn add_two(&self, num: &mut u64) -> Result<(), &'static str> {
        *num = num.checked_add(2).ok_or(
            "The capacity limit of the main counter u64 has been reached, so it is no longer \
             possible to send new messages over this connection. The connection must be closed!",
        )?;
        Ok(())
    }
}

// getters for wsconnection - separate impl for clarity
impl<
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
    TCfcser: Crcser,
    Hmaker: HandMaker,
> WsConnection<Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer, TCfcser, Hmaker>
{
    ///Check whether the connection is active or has received a close signal;
    ///  if it is not active, no more data will be transmitted over this connection.
    pub fn handshake_is_end(&self) -> bool {
        self.handshake_is_end
    }
    ///the person who initiated the connection or the person who responded to the
    /// connection
    pub fn my_role(&self) -> MyRole {
        self.my_role.clone()
    }
    ///get the corresponding value
    pub fn network_latency(&self) -> f64 {
        self.network_latency
    }
    ///get the corresponding value

    pub fn network_stability(&self) -> f64 {
        self.network_stability
    }
    ///get the corresponding value

    pub fn my_ctr_data(&self) -> u64 {
        self.my_ctr_data
    }
    ///get the corresponding value

    pub fn my_ctr_fback(&self) -> u64 {
        self.my_ctr_fback
    }
    ///get the corresponding value

    pub fn frend_ctr_data(&self) -> u64 {
        self.frend_ctr_data
    }
    ///get the corresponding value

    pub fn frend_ctr_fback(&self) -> u64 {
        self.frend_ctr_fback
    }
    ///get the corresponding value

    pub fn connect_param(&self) -> &WsConnectParam {
        &self.connect_param
    }
    ///get the corresponding value

    pub fn identified(&self) -> &Identified {
        &self.identified
    }
    ///get the corresponding value

    pub fn measurement_window_latency(&self) -> &f64 {
        &self.measurement_window_latency
    }
}

#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test_new {

    use super::*;
    use crate::t1dumps_struct::*;
    use crate::wt1types::Ids;
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();
        //Hmaker: HandMaker,

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[6, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: WsConnection<
            DumpNonser,
            DumpThrasher,
            u32,
            u32,
            DumpEnc,
            DumpRandomer,
            DumpCrcser,
            DumpHandMaker,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: Some((999, MyRole::Initiator)),
            },
            false,
        )
        .unwrap();

        let mut a0 = 1;
        let mut a10000 = 100000;
        let mut aerr = (!0u64) ^ 0b1;

        assert_eq!(te1.add_two(&mut a0), Ok(()));
        assert_eq!(te1.add_two(&mut a10000), Ok(()));
        assert_eq!(
            te1.add_two(&mut aerr),
            Err(
                "The capacity limit of the main counter u64 has been reached, so it is no longer \
                 possible to send new messages over this connection. The connection must be \
                 closed!"
            )
        );

        assert_eq!(a0, 3);
        assert_eq!(a10000, 100002)
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3333,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[6, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
        );

        assert!(te1.is_ok());
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[1, 1, 1, 1]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            true,
        );

        assert!(te1.is_ok());
        let ty2 = &te1.unwrap();
        assert_eq!(ty2.non_alloc_buf.as_ref().unwrap().capacity(), result.mtu());

        assert!(!ty2.was_killed);

        assert_eq!(ty2.nonce_gener.as_ref().unwrap().v, vec![1, 1, 1, 1])
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            Some(&[3, 3, 3, 3]),
            None,
            None,
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[1, 1, 1, 1]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
        );

        assert!(te1.is_ok());
        let ty2 = &te1.unwrap();
        assert_eq!(ty2.non_alloc_buf.as_ref(), None);

        assert!(!ty2.was_killed);

        assert_eq!(ty2.user_field_gener.as_ref().unwrap().v, vec![4, 4, 4, 4]);
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

        let result = t4algo_param::base_builder_pub(&po)
            .percent_fake_data_packets(Some(0.3))
            .percent_fake_fback_packets(Some(0.3))
            .percent_len_random_coefficient(Some(0.3))
            .build()
            .unwrap();

        assert!(result.need_init_random());

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            None,
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po)
            .percent_fake_data_packets(Some(0.3))
            //.percent_fake_fback_packets(Some(0.3))
            //.percent_len_random_coefficient(Some(0.3))
            .build()
            .unwrap();

        assert!(result.need_init_random());

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            Some(&[3, 3, 3, 3]),
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
        );

        assert!(te1.unwrap().random_gener.is_none());
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

        let result = t4algo_param::base_builder_pub(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            None,
            Some(&[4, 4, 4, 4]),
            None,
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            Some(&[2, 2, 2, 2]),
            None,
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
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

        let result = t4algo_param::base_builder_pub(&po)
            .percent_fake_data_packets(None)
            .percent_fake_fback_packets(None)
            .percent_len_random_coefficient(None)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let te1: Result<
            WsConnection<
                DumpNonser,
                DumpThrasher,
                u32,
                u32,
                DumpEnc,
                DumpRandomer,
                DumpCrcser,
                DumpHandMaker,
            >,
            WSQueueErr,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            None,
            Some(&[4, 4, 4, 4]),
            Some(&[5, 5, 5, 5]),
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
            false,
        );

        assert!(te1.unwrap().random_gener.is_none());
    }

    #[test]
    fn add_to() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(1),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

        let result = t4algo_param::base_builder_pub(&po).build().unwrap();

        let te1: WsConnection<
            DumpNonser,
            DumpThrasher,
            u32,
            u32,
            DumpEnc,
            DumpRandomer,
            DumpCrcser,
            DumpHandMaker,
        > = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            None,
            None,
            None,
            None,
            &[1, 2, 3, 4, 5, 6, 7],
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
            false,
        )
        .unwrap();

        let mut h = 1;
        assert!(te1.add_two(&mut h).is_ok());
        assert_eq!(h, 3);
        assert!(te1.add_two(&mut h).is_ok());
        assert_eq!(h, 5);

        h = u64::MAX - 1;

        assert_eq!(
            te1.add_two(&mut h),
            Err(
                "The capacity limit of the main counter u64 has been reached, so it is no longer \
                 possible to send new messages over this connection. The connection must be \
                 closed!"
            )
        );
    }
}
