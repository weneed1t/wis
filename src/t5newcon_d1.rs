// /*
use crate::t1queues::{WSFbackQueue, WSUdpLike, WSWaitQueue};
use crate::t3files_m::WSFileSplitter;
use crate::t4param::WsConnectParam;
use crate::t5pack_flds::MutCockSuck;
use crate::w1types::{
    Crcser, EncWis, HandMaker, Identified, MyRole, Noncer, PackScheme, Randomer, Rcc, Thrasher,
    TrickyBMaker, WisErr,
};

use std::cell::RefCell;
use std::rc::Rc;

const FBACK_START_CTR: u64 = 1;
const DATA_START_CTR: u64 = 0;

#[derive(Debug, Clone, PartialEq)]
struct Countrs {
    pub my_data: u64,
    pub my_fback: u64,
    pub frend_data: u64,
    pub frend_fback: u64,
}
#[derive(Debug, PartialEq, Clone)]
struct NeedyParam {
    idconn_slice_any: bool,
    id_of_sender_slice_any: bool,
    counter_slice_any: usize,
    head_crc_slice_any: bool,
    nonce_slice_any: bool,
    any_trash_content_slice: bool,
    need_tricky: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Seeds {
    pub nonce: Option<Box<[u8]>>,
    pub random: Option<Box<[u8]>>,
    pub user_field: Option<Box<[u8]>>,
    pub crc: Option<Box<[u8]>>,
    pub handmaker: Box<[u8]>,
    pub tricky: Option<Box<[u8]>>,
}

fn get_needy_pack_param(connect_param: &PackScheme) -> Result<NeedyParam, String> {
    Ok(match *connect_param {
        PackScheme::OnePack(ref x) => NeedyParam {
            idconn_slice_any: x.idconn_slice().is_some(),
            id_of_sender_slice_any: x.id_of_sender_slice().is_some(),
            counter_slice_any: x
                .counter_slice()
                .ok_or("impossible state, the counter must always be is some()")?
                .2,
            head_crc_slice_any: x.head_crc_slice().is_some(),
            nonce_slice_any: x.nonce_slice().is_some(),
            any_trash_content_slice: x.trash_content_slice().is_some(),
            need_tricky: x.tricky_byte().is_some(),
        },
        PackScheme::GroupPack(ref x) => NeedyParam {
            idconn_slice_any: x.all_have_idconn_field().is_some(),
            id_of_sender_slice_any: x.all_have_id_sender_receiver_fields().is_some(),
            counter_slice_any: x
                .all_have_counter_field()
                .ok_or("impossible state, the counter must always be is some()")?
                .1,
            head_crc_slice_any: x.all_have_crc_field().is_some(),
            nonce_slice_any: x.all_have_nonce_field().is_some(),
            any_trash_content_slice: x.any_have_trash_field(),
            need_tricky: true, //If there is a group, then tricky is definitely needed in it.
        },
    })
}

/// see method new
#[derive(Clone, Debug)]
pub struct WsConnection<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tenc: EncWis,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
> {
    connect_param: Rcc<WsConnectParam>,
    tricky_byter: Option<Ttricker>,
    file_splitter: WSFileSplitter,  //-
    udp_queue: WSUdpLike<Rc<[u8]>>, //-
    prealoc_buf_udp_queue: Vec<(u64, Rc<[u8]>)>,
    ///(u64, P, T)
    wait_queue: WSWaitQueue<(usize, Rc<[u8]>), f32>,
    ///`Option<usize>` is a pointer indicating where in the vector to take the data from.
    prealoc_buf_wait_queue: (Option<usize>, Vec<(u64, f32, (usize, Rc<[u8]>))>), //prealoc_buff
    fback_queue: WSFbackQueue<f32>,
    intermediate_questionable_packages_queue: Option<Box<[u8]>>,
    ///`Option<usize>` is a pointer of ending data non_alloc_buf.
    non_alloc_buf: (Option<usize>, Box<[u8]>),
    ctrs: Countrs,
    network_unstability: f32,
    network_latency: f32,
    handshake_is_end: bool,
    measurement_window_latency: f32,
    my_role: MyRole,
    identified: Identified,
    was_killed: bool,
    fuck_mut_struct: RefCell<MutCockSuck<Tnoncer, Tcrcser, Tthrasher, FuserLogicBuf>>,
    encrypt: RefCell<Tenc>,
    random_gener: Option<Trander>, //+
    enrypaaa: Thmaker,
}

impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tenc: EncWis,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
>
    WsConnection<
        Tnoncer,       // 1
        Tthrasher,     // 2.
        Tenc,          // 3
        Trander,       // 4
        Tcrcser,       // 5
        Thmaker,       // 6
        Ttricker,      // 7.
        FuserLogicBuf, // 8.
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connect_param: &WsConnectParam,
        default_enc_key: &[u8],
        my_role: MyRole,
        seeds: &Seeds,
        identified: &Identified,
    ) -> Result<Self, WisErr<String, String>> {
        let pack_sheme = get_needy_pack_param(connect_param.sheme()).map_err(WisErr::Critical)?;

        if pack_sheme.idconn_slice_any == identified.id_conn.is_none() {
            return Err(WisErr::Critical(
                "connect_param.pack_topology().idconn_slice().is_some() == identified.id_conn.is_none()\
                 you need to set a value".to_string(),
            ));
        }

        if let Some(xids) = &identified.my_s_r_id
            && xids.id_receiver == xids.id_sender
        {
            return Err(WisErr::Critical(
                "identified.id_receiver == identified.id_sender The sender and recipient IDs must \
                 be different!"
                    .to_string(),
            ));
        }

        if pack_sheme.id_of_sender_slice_any == identified.my_s_r_id.is_none() {
            return Err(WisErr::Critical(
                "connect_param.pack_topology().id_of_sender_slice().is_some()\
                != identified.my_s_r_id.is_some() you need to set a value for \
                 identified.my_s_r_id"
                    .to_string(),
            ));
        }

        let nonce_gener = if pack_sheme.nonce_slice_any {
            Some(
                Tnoncer::new(
                    seeds.nonce.as_deref().ok_or(WisErr::Critical(
                        "nonce_seed is none but \
                         connect_param.pack_topology().nonce_slice().is_some() == true"
                            .to_string(),
                    ))?,
                )
                .map_err(WisErr::Critical)?,
            )
        } else {
            None
        };

        let user_field_gener = if pack_sheme.any_trash_content_slice {
            Some(
                Tthrasher::new(
                    seeds.user_field.as_deref().ok_or(WisErr::Critical(
                        "user_field_seed is none but \
                         connect_param.pack_topology().trash_content_slice().is_some() == true, \
                         `trash_content_slice() is user_field` "
                            .to_string(),
                    ))?,
                )
                .map_err(WisErr::Critical)?,
            )
        } else {
            None
        };

        let random_gener = if connect_param.need_init_random() {
            Some(
                Trander::new(seeds.random.as_deref().ok_or(WisErr::Critical(
                    "random_seed is none but connect_param.need_init_random() == true".to_string(),
                ))?)
                .map_err(WisErr::Critical)?,
            )
        } else {
            None
        };

        let crc_gener = if pack_sheme.head_crc_slice_any {
            Some(
                Tcrcser::new(
                    seeds.crc.as_deref().ok_or(WisErr::Critical(
                        "crc_seed is none but \
                         connect_param.pack_topology().head_crc_slice().is_some() == true"
                            .to_string(),
                    ))?,
                )
                .map_err(WisErr::Critical)?,
            )
        } else {
            None
        };
        //
        let ctrs = Countrs {
            my_data: DATA_START_CTR,
            my_fback: FBACK_START_CTR,
            frend_data: DATA_START_CTR,
            frend_fback: FBACK_START_CTR,
        };

        let tricky_byter = if pack_sheme.need_tricky {
            Some(
                TrickyBMaker::new(
                    seeds.tricky.as_deref().ok_or(WisErr::Critical(
                        "tricky_seed is none but \
                    connect_param contains the packet schema that requires tricky_byte"
                            .to_string(),
                    ))?,
                    connect_param.sheme().clone(),
                )
                .map_err(WisErr::Critical)?,
            )
        } else {
            None
        };

        let fuck_mut_struct = MutCockSuck {
            nonce_gener,
            user_field_gener,
            user_buf: None,
            crc_gener,
        };

        let fback_queue = WSFbackQueue::new(
            pack_sheme.counter_slice_any,
            connect_param.maximum_length_fback_queue_packages(),
            connect_param.mtu(),
        )
        .map_err(WisErr::Critical)?;

        let file_splitter =
            WSFileSplitter::new(connect_param.max_len_file()).map_err(WisErr::Critical)?;

        let intermediate_questionable_packages_queue = connect_param
            .intermediate_questionable_packages_queue()
            .map(|vec_q| vec![0; vec_q].into_boxed_slice());
        Ok(Self {
            tricky_byter,

            file_splitter,
            udp_queue: WSUdpLike::new(connect_param.maximum_length_udp_queue_packages())?,
            prealoc_buf_udp_queue: vec![],
            wait_queue: WSWaitQueue::new(
                connect_param.maximum_length_queue_unconfirmed_packages(),
            )?,

            prealoc_buf_wait_queue: (None, vec![]),
            fback_queue,
            ctrs,
            network_unstability: 0.0,
            network_latency: 0.0,
            encrypt: RefCell::new(Tenc::new(default_enc_key).map_err(WisErr::Critical)?),
            connect_param: Rcc::new(connect_param.clone()),
            enrypaaa: Thmaker::new(my_role.clone(), &seeds.handmaker).map_err(WisErr::Critical)?, /* in progress */
            handshake_is_end: false,
            intermediate_questionable_packages_queue,
            random_gener,
            my_role,
            measurement_window_latency: connect_param.start_ms_latency(),
            identified: identified.clone(),
            non_alloc_buf: (None, vec![0; connect_param.mtu()].into_boxed_slice()),
            was_killed: false,
            fuck_mut_struct: RefCell::new(fuck_mut_struct),
        })
    }
}
///add 2 to the number
pub fn add_two(num: &mut u64) -> Result<(), String> {
    *num = num.checked_add(2).ok_or(
        "The capacity limit of the main counter u64 has been reached, so it is no longer \
             possible to send new messages over this connection. The connection must be closed!",
    )?;
    Ok(())
}

// getters for wsconnection - separate impl for clarity
impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tenc: EncWis,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
>
    WsConnection<
        Tnoncer,       // 1
        Tthrasher,     // 2.
        Tenc,          // 3
        Trander,       // 4
        Tcrcser,       // 5
        Thmaker,       // 6
        Ttricker,      // 7.
        FuserLogicBuf, // 8.
    >
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
    pub fn network_latency(&self) -> f32 {
        self.network_latency
    }
    ///get the corresponding value

    pub fn network_unstability(&self) -> f32 {
        self.network_unstability
    }
    ///get the corresponding value

    pub fn my_ctr_data(&self) -> u64 {
        self.ctrs.my_data
    }
    ///get the corresponding value

    pub fn my_ctr_fback(&self) -> u64 {
        self.ctrs.my_fback
    }
    ///get the corresponding value

    pub fn frend_ctr_data(&self) -> u64 {
        self.ctrs.frend_data
    }
    ///get the corresponding value

    pub fn frend_ctr_fback(&self) -> u64 {
        self.ctrs.frend_fback
    }

    ///get the corresponding value
    pub fn connect_param(&self) -> Rcc<WsConnectParam> {
        self.connect_param.clone()
    }
    ///get the corresponding value

    pub fn identified(&self) -> &Identified {
        &self.identified
    }
    ///get the corresponding value

    pub fn measurement_window_latency(&self) -> f32 {
        self.measurement_window_latency
    }
}

#[cfg(test)]
type Dumdwcn = WsConnection<
    DumpNonser,
    DumpThrasher<String>, // Передали <u32> внутрь структуры заглушки
    DumpEnc,
    DumpRandomer,
    DumpCrcser,
    DumpHandMaker,
    DumpTricker<String>, // Заменили трейт TrickyBMaker на конкретный тип-заглушку
    String,
>;

#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test_new {

    use super::*;

    use crate::w1types::{Ids, Ttl};
    use crate::{t0pology, t4param};
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };
        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "connect_param.pack_topology().idconn_slice().is_some() == identified.id_conn.is_none()\
                 you need to set a value".to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .mtu(9876)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Dumdwcn = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: Some((999, MyRole::Initiator)),
            },
        )
        .unwrap();

        let mut a0 = 1;
        let mut a10000 = 100000;
        let mut aerr = (!0u64) ^ 0b1;

        assert_eq!(te1.connect_param().mtu(), 9876);

        assert_eq!(te1.non_alloc_buf.1.len(), te1.connect_param().mtu());
        assert_eq!(te1.non_alloc_buf.0, None);

        assert_eq!(add_two(&mut a0), Ok(()));
        assert_eq!(add_two(&mut a10000), Ok(()));
        assert_eq!(
            add_two(&mut aerr),
            Err(
                "The capacity limit of the main counter u64 has been reached, so it is no longer \
                 possible to send new messages over this connection. The connection must be \
                 closed!"
                    .to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "connect_param.pack_topology().id_of_sender_slice().is_some()!= identified.my_s_r_id.is_some() you need to set a value for identified.my_s_r_id".to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
            WisErr::Critical(
                "identified.id_receiver == identified.id_sender The sender and recipient IDs must \
                 be different!"
                    .to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();
        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };
        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: None, //Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
            WisErr::Critical(
                "nonce_seed is none but connect_param.pack_topology().nonce_slice().is_some() == \
                 true"
                    .to_string()
            )
        );
    }

    #[test]
    fn nonce_gener_inv() {
        let fields = vec![
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
            t0pology::PackFields::Nonce(10),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.is_ok());
        let ty2 = &te1.unwrap();

        assert!(!ty2.was_killed);

        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .nonce_gener
                .as_ref()
                .unwrap()
                .v,
            vec![2, 2, 2, 2]
        );
        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .user_field_gener
                .as_ref()
                .unwrap()
                .v,
            vec![5, 5, 5, 5u8]
        );
        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .crc_gener
                .as_ref()
                .unwrap()
                .v,
            vec![6, 4, 4, 4]
        )
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: None, // Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
            WisErr::Critical(
                "user_field_seed is none but \
                 connect_param.pack_topology().trash_content_slice().is_some() == true, \
                 `trash_content_slice() is user_field` "
                    .to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.is_ok());
        let ty2 = &te1.unwrap();

        assert!(!ty2.was_killed);

        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .user_field_gener
                .as_ref()
                .unwrap()
                .v,
            vec![5, 5, 5, 5]
        );
        assert_eq!(ty2.enrypaaa._private_seed, [9, 9, 9, 9u8].into());
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(Some(0.3))
            .length_trimming_range(Some(11))
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, // Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
            WisErr::Critical(
                "random_seed is none but connect_param.need_init_random() == true".to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(Some(0.3))
            //.percent_fake_fback_packets(Some(0.3))
            //.percent_len_random_coefficient(Some(0.3))
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, //Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, // Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: None, //Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
            WisErr::Critical(
                "crc_seed is none but connect_param.pack_topology().head_crc_slice().is_some() == \
                 true"
                    .to_string()
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, // Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([5, 5, 5, 5])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
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
            te1.unwrap()
                .fuck_mut_struct
                .try_borrow()
                .unwrap()
                .crc_gener
                .clone()
                .unwrap()
                .v,
            vec![5, 5, 5, 5]
        );
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
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: None,  // Some(Box::new([2, 2, 2, 2])),
            random: None, //Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.unwrap().random_gener.is_none());
    }

    #[test]
    fn add_to() {
        let mut h = 1;
        assert!(add_two(&mut h).is_ok());
        assert_eq!(h, 3);
        assert!(add_two(&mut h).is_ok());
        assert_eq!(h, 5);

        h = u64::MAX - 1;

        assert_eq!(
            add_two(&mut h),
            Err(
                "The capacity limit of the main counter u64 has been reached, so it is no longer \
                 possible to send new messages over this connection. The connection must be \
                 closed!"
                    .to_string()
            )
        );
    }
}

#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::float_cmp)]
#[cfg(test)]
mod test_api {

    use super::*;
    use crate::w1types::Ttl;
    use crate::{t0pology, t4param};

    #[test]
    fn api_tets() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let mut te1: Dumdwcn = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: Some((999, MyRole::Initiator)),
            },
        )
        .unwrap();

        assert_eq!(DATA_START_CTR, te1.frend_ctr_data());
        assert_eq!(DATA_START_CTR, te1.my_ctr_data());
        assert_eq!(FBACK_START_CTR, te1.frend_ctr_fback());
        assert_eq!(FBACK_START_CTR, te1.my_ctr_fback());

        te1.ctrs.frend_data = 1000;
        te1.ctrs.my_data = 1111;
        te1.ctrs.frend_fback = 2222;
        te1.ctrs.my_fback = 3333;

        assert_eq!(1000, te1.frend_ctr_data());
        assert_eq!(1111, te1.my_ctr_data());
        assert_eq!(2222, te1.frend_ctr_fback());
        assert_eq!(3333, te1.my_ctr_fback());

        //===========
        assert_eq!(MyRole::Initiator, te1.my_role());

        te1.my_role = MyRole::Passive;

        assert_eq!(MyRole::Passive, te1.my_role());

        assert_eq!(te1.handshake_is_end(), te1.handshake_is_end);

        assert!(!te1.handshake_is_end());

        te1.handshake_is_end = true;

        assert!(te1.handshake_is_end());
        //===========
        assert_eq!(te1.network_latency, te1.network_latency());
        assert_eq!(te1.network_latency, 0.0);
        te1.network_latency = 1234567.1;
        assert_eq!(1234567.1, te1.network_latency());

        //===========

        assert_eq!(te1.network_unstability, te1.network_unstability());
        assert_eq!(te1.network_unstability, 0.0);
        te1.network_unstability = 98765.0;
        assert_eq!(98765.0, te1.network_unstability());

        //===========

        assert_eq!(
            te1.measurement_window_latency,
            te1.measurement_window_latency()
        );
        te1.measurement_window_latency = 11198765.0;
        assert_eq!(11198765.0, te1.measurement_window_latency());

        //===========

        assert_eq!(te1.identified().clone(), te1.identified.clone());
        te1.identified.my_metall_id = 999_111_222;

        assert_eq!(te1.identified().clone().my_metall_id, 999_111_222);

        //===========
        let x1 = te1.connect_param().clone();
        let x2 = te1.connect_param.clone();
        assert_eq!(x1, x2);

        let mut tx = 0;
        add_two(&mut tx).unwrap();

        assert_eq!(tx, 2);
        add_two(&mut tx).unwrap();

        assert_eq!(tx, 4);
        add_two(&mut tx).unwrap();

        assert_eq!(tx, 6);
    }
}

#[cfg(test)]
mod tests_get_needy_pack_param {
    #![allow(clippy::unwrap_used)]
    use super::*; // Imports the items from the outer module (PackScheme, get_needy_pack_param, etc.)
    use crate::{
        t0grouper::GroupTopology, t0pology::PackFields, t0pology::PackTopology,
        w1types::PackTypeGroup,
    };

    // Helper to create a PackTopology with default parameters.
    // - tag_len = 16 (arbitrary, but valid)
    // - data_save = true (so HeadCRC is not required)
    // - tcp_mode = false (so Len is not required)
    fn make_topology(fields: &[PackFields]) -> PackTopology {
        PackTopology::new(16, fields, true, false).unwrap()
    }

    // Expected NeedyParam for a single PackTopology.
    fn expected_from_topo(topo: &PackTopology) -> NeedyParam {
        NeedyParam {
            idconn_slice_any: topo.idconn_slice().is_some(),
            id_of_sender_slice_any: topo.id_of_sender_slice().is_some(),
            counter_slice_any: topo.counter_slice().unwrap().2, // safe: always Some
            head_crc_slice_any: topo.head_crc_slice().is_some(),
            nonce_slice_any: topo.nonce_slice().is_some(),
            any_trash_content_slice: topo.trash_content_slice().is_some(),
            need_tricky: false,
        }
    }

    // Expected NeedyParam for a GroupTopology.
    // Note: for GroupPack, the “any” flags are true if the field exists in *any* topology.
    fn expected_from_group(group: &GroupTopology) -> NeedyParam {
        NeedyParam {
            idconn_slice_any: group.all_have_idconn_field().is_some(),
            id_of_sender_slice_any: group.all_have_id_sender_receiver_fields().is_some(),
            counter_slice_any: group.all_have_counter_field().unwrap().1, // safe: always Some
            head_crc_slice_any: group.all_have_crc_field().is_some(),
            nonce_slice_any: group.all_have_nonce_field().is_some(),
            any_trash_content_slice: group.any_have_trash_field(),
            need_tricky: group.how_elems_in_me() > 1,
        }
    }

    // Compare results from OnePack and GroupPack for the same single topology.
    #[test]
    fn single_topology_consistency() {
        // Define a variety of field combinations (Counter is always present).
        let field_sets = vec![
            vec![PackFields::Counter(1)],
            vec![PackFields::Counter(1), PackFields::IdConnect(1)],
            vec![
                PackFields::Counter(1),
                PackFields::IdSender(1),
                PackFields::IdReceiver(1),
            ],
            vec![PackFields::Counter(1), PackFields::HeadCRC(1)],
            vec![PackFields::Counter(1), PackFields::Nonce(1)],
            vec![PackFields::Counter(1), PackFields::UserField(1)],
            vec![
                PackFields::Counter(1),
                PackFields::IdConnect(1),
                PackFields::HeadCRC(1),
                PackFields::Nonce(1),
                PackFields::UserField(1),
                PackFields::IdSender(1),
                PackFields::IdReceiver(1),
            ],
            // Additional combination: id_sender/receiver without idconn, etc.
            vec![
                PackFields::Counter(1),
                PackFields::IdSender(1),
                PackFields::IdReceiver(1),
                PackFields::HeadCRC(1),
            ],
            vec![
                PackFields::Counter(1),
                PackFields::IdConnect(1),
                PackFields::Nonce(1),
                PackFields::UserField(1),
            ],
        ];

        for fields in field_sets {
            let topo = make_topology(&fields);

            // Test OnePack
            let scheme_one = PackScheme::OnePack(topo.clone());
            let result_one = get_needy_pack_param(&scheme_one).unwrap();
            let expected_one = expected_from_topo(&topo);
            assert_eq!(result_one, expected_one);

            // Build a GroupTopology containing exactly this topology (key = 0)
            let group_input = vec![(fields.clone().into_boxed_slice(), PackTypeGroup::Any, 0)];
            let topo = GroupTopology::new(&group_input, 16, true, false).unwrap();

            // Test GroupPack
            let scheme_group = PackScheme::GroupPack(topo.clone());
            let mut result_group = get_needy_pack_param(&scheme_group).unwrap();
            let mut expected_group = expected_from_group(&topo);

            assert_ne!(result_group, expected_group);

            assert!(result_group.need_tricky);
            assert!(!expected_group.need_tricky);

            result_group.need_tricky = false;
            expected_group.need_tricky = false;

            assert_eq!(result_group, expected_group);
            // Both schemes must produce identical results for a single topology.
            assert_eq!(result_one, result_group);
        }
    }

    // Test GroupPack with multiple topologies where fields differ.
    #[test]
    fn group_multiple_topologies() {
        // Case 1: two topologies with disjoint fields.
        let fields1 = vec![
            PackFields::Counter(1),
            PackFields::TrickyByte,
            PackFields::IdConnect(1),
        ];
        let fields2 = vec![
            PackFields::IdConnect(1),
            PackFields::TrickyByte,
            PackFields::Counter(1),
        ];
        let group_input = vec![
            (fields1.into_boxed_slice(), PackTypeGroup::Any, 0),
            (fields2.into_boxed_slice(), PackTypeGroup::Any, 1),
        ];
        let topo = GroupTopology::new(&group_input, 16, true, false).unwrap();
        let result = get_needy_pack_param(&PackScheme::GroupPack(topo.clone())).unwrap();
        let expected = expected_from_group(&topo);
        assert_eq!(result, expected);
        // idconn exists in at least one, nonce exists in at least one,
        // but id_of_sender and head_crc and trash are absent from all.
        assert!(result.idconn_slice_any);
        assert!(!result.id_of_sender_slice_any);
        assert!(!result.nonce_slice_any);
        assert!(!result.head_crc_slice_any);
        assert!(!result.any_trash_content_slice);

        // Case 2: one topology has trash, another does not.
        let fields3 = vec![
            PackFields::Counter(1),
            PackFields::TrickyByte,
            PackFields::UserField(1),
        ];
        let fields4 = vec![PackFields::Counter(1), PackFields::TrickyByte];
        let group_input2 = vec![
            (fields3.into_boxed_slice(), PackTypeGroup::Any, 0),
            (fields4.into_boxed_slice(), PackTypeGroup::Any, 1),
        ];
        let topo = GroupTopology::new(&group_input2, 16, true, false).unwrap();
        let result2 = get_needy_pack_param(&PackScheme::GroupPack(topo.clone())).unwrap();
        let expected2 = expected_from_group(&topo);
        assert_eq!(result2, expected2);
        assert!(result2.any_trash_content_slice);
    }

    // Verify that counter length is correctly extracted for both schemes.
    #[test]
    fn counter_length_extraction() {
        let len = 4;
        let fields = vec![PackFields::Counter(len)];
        let topo = make_topology(&fields);

        // OnePack
        let result_one = get_needy_pack_param(&PackScheme::OnePack(topo.clone())).unwrap();
        assert_eq!(result_one.counter_slice_any, len);

        // GroupPack (single topology)
        let group_input = vec![(fields.clone().into_boxed_slice(), PackTypeGroup::Any, 0)];
        let topo = GroupTopology::new(&group_input, 16, true, false).unwrap();
        let result_group = get_needy_pack_param(&PackScheme::GroupPack(topo.clone())).unwrap();
        assert_eq!(result_group.counter_slice_any, len);
    }
}

#[cfg(test)]
use crate::t1dumb_srct::*;
#[cfg(test)]
use crate::{t0pology, t4param};
#[cfg(test)]
///for test only
///
#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::float_cmp)]
pub fn fast_wconn_maker() -> Dumdwcn {
    use crate::w1types::Ttl;

    let fields = vec![
        //t2page::PackFields::HeadByte,
        t0pology::PackFields::Counter(7),
        t0pology::PackFields::IdConnect(6),
        t0pology::PackFields::UserField(10),
        t0pology::PackFields::HeadCRC(4),
        t0pology::PackFields::TTL(4),
    ];

    let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

    let ttl = Ttl::new(100, -1, 20, false).unwrap();

    let result = t4param::base_builder_pub(po)
        .ttl_max_start_cost(ttl)
        .build()
        .unwrap();

    let seeds = Seeds {
        nonce: Some(Box::new([2, 2, 2, 2])),
        random: Some(Box::new([3, 3, 3, 3])),
        user_field: Some(Box::new([5, 5, 5, 5u8])),
        crc: Some(Box::new([6, 4, 4, 4])),
        handmaker: Box::new([9, 9, 9, 9u8]),
        tricky: Some(Box::new([7, 7, 7, 7u8])),
    };

    let ret = WsConnection::new(
        &result,
        &[1, 1, 1, 1],
        MyRole::Initiator,
        &seeds,
        &Identified {
            my_metall_id: 999,
            my_s_r_id: None,
            id_conn: Some((999, MyRole::Initiator)),
        },
    )
    .unwrap();
    ret.clone()
}
// */
