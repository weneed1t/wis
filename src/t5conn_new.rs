use crate::t1queues::{WSFbackQueue, WSUdpLike, WSWaitQueue};
use crate::t3files_m::WSFileSplitter;
use crate::t4param::WsConnectParam;
use crate::t5pack_flds::MutCockSuck;
use crate::w1types::{
    Crcser, EncWis, EndCryptStuctor, HandMaker, Identified, MyRole, Noncer, PackScheme, Randomer,
    Rcc, Thrasher, TrickyBMaker, WisErr,
};
use std::marker::PhantomData;

//#[cfg(test)]
use std::cell::RefCell;
use std::rc::Rc;

///no cm
pub const FBACK_START_CTR: u64 = 1;
///no cm
pub const DATA_START_CTR: u64 = 0;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Countrs {
    pub my_data: u64,
    pub my_fback: u64,
    pub frend_data: u64,
    pub frend_fback: u64,
}
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct NeedyParam {
    pub(crate) idconn_slice_any: bool,
    pub(crate) id_of_sender_slice_any: bool,
    pub(crate) counter_slice_any: usize,
    pub(crate) head_crc_slice_any: bool,
    pub(crate) nonce_slice_any: bool,
    pub(crate) any_trash_content_slice: bool,
    pub(crate) need_tricky: bool,
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

pub(crate) fn get_needy_pack_param(connect_param: &PackScheme) -> Result<NeedyParam, String> {
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
    Tenc: EncWis<EndCpt>,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker<EndCpt>,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
    EndCpt: EndCryptStuctor + Clone,
> {
    pub(crate) connect_param: Rcc<WsConnectParam>,
    pub(crate) tricky_byter: Option<Ttricker>,
    pub(crate) file_splitter: WSFileSplitter,  //-
    pub(crate) udp_queue: WSUdpLike<Rc<[u8]>>, //-
    pub(crate) prealoc_buf_udp_queue: Vec<(u64, Rc<[u8]>)>,
    ///(u64, P, T)
    pub(crate) wait_queue: WSWaitQueue<(usize, Rc<[u8]>), f32>,
    ///`Option<usize>` is a pointer indicating where in the vector to take the data from.
    pub(crate) prealoc_buf_wait_queue: (Option<usize>, Vec<(u64, f32, (usize, Rc<[u8]>))>), //prealoc_buff
    pub(crate) fback_queue: WSFbackQueue<f32>,
    pub(crate) intermediate_questionable_packages_queue: Option<Box<[u8]>>,

    pub(crate) non_alloc_buf: Box<[u8]>,
    pub(crate) ctrs: Countrs,
    pub(crate) network_unstability: f32,
    pub(crate) network_latency: f32,
    pub(crate) handshake_is_end: bool,
    pub(crate) measurement_window_latency: f32,
    pub(crate) my_role: MyRole,
    pub(crate) identified: Identified,
    pub(crate) was_killed: bool,
    pub(crate) fuck_mut_struct:
        RefCell<MutCockSuck<Tnoncer, Tcrcser, Tthrasher, FuserLogicBuf, EndCpt>>,
    pub(crate) encrypt: RefCell<Tenc>,
    pub(crate) random_gener: Option<Trander>, //+
    pub(crate) enrypaaa: Thmaker,
    pub(crate) _end_cpt: PhantomData<EndCpt>,
}

impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tenc: EncWis<EndCpt>,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker<EndCpt>,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
    EndCpt: EndCryptStuctor + Clone,
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
        EndCpt,
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
            end_key: None,
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
            encrypt: RefCell::new(Tenc::new(default_enc_key, None).map_err(WisErr::Critical)?),
            connect_param: Rcc::new(connect_param.clone()),
            enrypaaa: Thmaker::new(my_role, &seeds.handmaker).map_err(WisErr::Critical)?, /* in progress */
            handshake_is_end: false,
            intermediate_questionable_packages_queue,
            random_gener,
            my_role,
            measurement_window_latency: connect_param.start_ms_latency(),
            identified: *identified,
            non_alloc_buf: vec![0; connect_param.mtu()].into_boxed_slice(),
            was_killed: false,
            fuck_mut_struct: RefCell::new(fuck_mut_struct),
            _end_cpt: PhantomData,
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
    Tenc: EncWis<EndCpt>,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker<EndCpt>,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
    EndCpt: EndCryptStuctor + Clone,
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
        EndCpt,
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
        self.my_role
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
