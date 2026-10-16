use crate::t1queues::{WSFbackQueue, WSUdpLike, WSWaitQueue};
use crate::t3files_m::WSFileSplitter;
use crate::t4param::WsConnectParam;
use crate::t5pack_flds::MutCockSuck;
use crate::w1types::{
    Crcser, EncWis, EndCryptStuctor, HandMaker, Identified, MyRole, Noncer, PackScheme, Randomer,
    Rcc, Thrasher, TrickyBMaker, WisErr,
};
use std::marker::PhantomData;

use crate::t0pology::PackTopology;
use crate::t5coon_d3_rand::get_pack_len_and_is_fake;
use crate::t5pack_flds::init_all_pack_to_send;
//#[cfg(test)]
use crate::w1types::{
    HeadByteStruct, PackAddedStatus, PackType, PackTypeGroup, Ttl, WSQueueState, WTypeErr,
};
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
    Tenc: EncWis,
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
    pub(crate) fuck_mut_struct: RefCell<MutCockSuck<Tnoncer, Tcrcser, Tthrasher, FuserLogicBuf>>,
    pub(crate) encrypt: RefCell<Tenc>,
    pub(crate) random_gener: Option<Trander>, //+
    pub(crate) enrypaaa: Thmaker,
    pub(crate) _end_cpt: PhantomData<EndCpt>,
}

impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tenc: EncWis,
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
    Tenc: EncWis,
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

#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
struct DebugPackSnapshot {
    pack: Vec<u8>,
    topology: PackTopology,
    head_byte: HeadByteStruct,
    ctr: u64,
    pack_type: PackType,
    all_id: Identified,
    tricky_byte: Option<u8>,
    ttl: Option<(Ttl, bool)>,
    mtu: usize,
    sp: SendPlan,
}

#[cfg(debug_assertions)]
thread_local! {
    ///DEBUG_PACK_HISTORY
    pub static DEBUG_PACK_HISTORY: RefCell<Option<DebugPackSnapshot>> = const { RefCell::new(None) };
}

#[allow(clippy::too_many_arguments)]

///only test!
fn init_all_pack_to_send_wrapper<
    Tenc: EncWis,
    Tnoncer: Noncer,
    Tcrc: Crcser,
    Trshr: Thrasher<FuserLogicBuf>,
    FuserLogicBuf,
>(
    pack: &mut [u8],
    topology: &PackTopology,
    head_byte: HeadByteStruct,
    ctr: &u64,
    pack_type: PackType,
    all_id: &Identified,
    tricky_byte: Option<u8>,
    ttl: Option<(Ttl, bool)>,
    mtu: &usize,
    encrypt: &mut Tenc,
    fuck_mut: &mut MutCockSuck<Tnoncer, Tcrc, Trshr, FuserLogicBuf>,
    sp: &SendPlan,
) -> Result<(), WTypeErr> {
    // This block will execute ONLY in a debug build (cargo run / cargo test)
    if cfg!(debug_assertions) {
        #[cfg(debug_assertions)]
        DEBUG_PACK_HISTORY.with(|history| {
            let snapshot = DebugPackSnapshot {
                pack: pack.to_vec(), // Копируем срез байт в вектор
                topology: topology.clone(),
                head_byte,
                ctr: *ctr,
                pack_type,
                all_id: *all_id,
                tricky_byte,
                ttl,
                mtu: *mtu,
                sp: *sp,
            };
            *history.borrow_mut() = Some(snapshot);
        });
    }

    // Call the original heavy logic (works in both debug and release)
    init_all_pack_to_send(
        pack,
        topology,
        head_byte,
        ctr,
        pack_type,
        all_id,
        tricky_byte,
        ttl,
        mtu,
        encrypt,
        fuck_mut,
    )
}

#[derive(Debug, PartialEq, Clone, Copy)]
struct SendPlan {
    mtu: usize,
    ttl: Option<(Ttl, bool)>,
    id: Identified,
    tb: Option<u8>,
    ptype: PackTypeGroup,
    can_trim: bool,
    what_should_send: WhatSend,
    pack_ctr: u64,
    payload_len_final: usize,
    owerhead: usize,
    is_fake: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WhatSend {
    Fback,
    Data,
    DataResending,
}

impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tencrer: EncWis,
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
        Tencrer,       // 3
        Trander,       // 4
        Tcrcser,       // 5
        Thmaker,       // 6
        Ttricker,      // 7.
        FuserLogicBuf, // 8.
        EndCpt,
    >
{
    pub fn send_data<F>(
        &mut self,
        _force_no_edit_pack_type: Option<bool>,
        _paste_api: F,
        _curent_time: f32,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&mut [u8]) -> Result<(), String>,
    {
        Ok(())
    }

    pub fn send_fback<F>(
        &mut self,
        _force_no_edit_pack_type: Option<bool>,
        _paste_api: F,
        _curent_time: f32,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&mut [u8]) -> Result<(), String>,
    {
        Ok(())
    }

    pub fn send_resending<F>(
        &mut self,
        _force_no_edit_pack_type: Option<bool>,
        _paste_api: F,
        _curent_time: f32,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&mut [u8]) -> Result<(), String>,
    {
        Ok(())
    }
    ///Create a new file to send; if a file already exists or the transfer is incomplete,
    /// an error will occur
    pub fn paste_file(&mut self, file: Rcc<Box<[u8]>>) -> Result<(), WTypeErr> {
        if self.was_killed {
            return Err(WTypeErr::WorkTimeErr("connect_is kill".to_string()));
        }
        if self.handshake_is_end {
            return Err(WTypeErr::WorkTimeErr(
                "connection during the key installation process".to_string(),
            ));
        }
        self.file_splitter
            .write_new_rc_file(file)
            .map_err(WTypeErr::WorkTimeErr)
    }

    ///get_pack to send<br>
    ///send_api<br>
    ///---&\[u8\] -> this is the data packet to be sent<br>
    /// bool -> is fake or real
    ///--- Result<f32> -> this is the time the packet was sent<br>
    /// force_no_edit_pack_type: None -> pack_type is random
    /// force_no_edit_pack_type: true -> force set pack_type is non edit
    /// force_no_edit_pack_type: false -> force set pack_type is fake
    fn send_any_pack<F>(
        &mut self,
        what_should_send: WhatSend,
        force_no_edit_pack_type: Option<bool>,
        real_payload_len: usize,
        pack_ctr: u64,
        paste_api: F,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&mut [u8]) -> Result<(), String>,
    {
        let cp = self.connect_param();

        //get common fields
        //send plan
        let mut sp = SendPlan {
            mtu: cp.mtu(),
            // ttl start -> true
            ttl: cp.ttl_max_start_cost().map(|x| (x, true)),
            id: *self.identified(),
            tb: self.get_tb(),
            ptype: match &what_should_send {
                WhatSend::Fback => PackTypeGroup::Fback,
                _ => PackTypeGroup::Data,
            },
            can_trim: match &what_should_send {
                WhatSend::Data => true,
                _ => false,
            },
            what_should_send,
            pack_ctr,
            payload_len_final: usize::MAX,
            owerhead: usize::MAX,
            is_fake: false,
        };

        let topol = cp.sheme().get_topol(sp.tb.unwrap_or(0), sp.ptype);

        debug_assert_eq!(topol.is_none(), cp.sheme().is_one());
        //debug_assert_eq!(self.non_alloc_buf.0, Some(0));

        let topol = topol
            .ok_or(WTypeErr::WorkTimeErr(
                "The value generated by `tricky_byter.get_tricky_byte` does not match any packet in the packet scheme.".to_string()))?;
        sp.owerhead = topol.overhead_len();

        let (r_u32, r_usize) = if let Some(rnd) = self.random_gener.as_mut() {
            (Some(rnd.gen_rand_u32()), Some(rnd.gen_rand_usize()))
        } else {
            (None, None)
        };

        (sp.payload_len_final, sp.is_fake) = get_pack_len_and_is_fake(
            &cp,
            force_no_edit_pack_type,
            sp.can_trim,
            &real_payload_len,
            &sp.owerhead,
            r_u32,
            r_usize,
        )
        .map_err(WTypeErr::WorkTimeErr)?;

        debug_assert_ne!(sp.payload_len_final, usize::MAX);
        debug_assert_ne!(sp.owerhead, usize::MAX);

        self.paste_and_send(&sp, topol, paste_api)?;

        Ok(())
    }

    fn paste_and_send<F>(
        &mut self,
        sp: &SendPlan,
        tp: &PackTopology,
        _paste_api: F,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&mut [u8]) -> Result<(), String>,
    {
        //
        let all_pack_len =
            sp.payload_len_final
                .checked_add(sp.owerhead)
                .ok_or(WTypeErr::LenSizeErr(format!(
                    "payload_len_final + ovh owerwlow {} {} ",
                    sp.payload_len_final, sp.owerhead
                )))?;

        let mut_enc = self.encrypt.get_mut();

        let mut_fms = self.fuck_mut_struct.get_mut();

        let mut hb = HeadByteStruct::new();

        hb.set_need_trim_is_pad(false); // no realice

        hb.set_need_trim_is_pad(sp.is_fake);
        hb.set_is_kill(self.was_killed);

        let buffer_operating_range =
            self.non_alloc_buf
                .get_mut(..all_pack_len)
                .ok_or(WTypeErr::LenSizeErr(format!(
                    "self.non_alloc_buf.1[..0] all_pack_len err, {} mtu {}",
                    all_pack_len, sp.mtu
                )))?;

        init_all_pack_to_send_wrapper(
            buffer_operating_range,
            tp,
            hb,
            &sp.pack_ctr,
            PackType::Fback,
            &sp.id,
            sp.tb,
            sp.ttl,
            &sp.mtu,
            mut_enc,
            mut_fms,
            sp,
        )?;

        //         debug_assert_eq!(self.non_alloc_buf.0, Some(all_pack_len));

        Ok(())
    }

    fn get_tb(&mut self) -> Option<u8> {
        if let Some(x) = &self.tricky_byter {
            let m_ub = self.fuck_mut_struct.get_mut().user_buf.as_mut();

            Some(x.get_tricky_byte(PackType::Fback, &self.ctrs.my_fback, m_ub))
        } else {
            debug_assert!(self.tricky_byter.is_none());

            None
        }
    }

    ///adds a packet to both the fback and udp queues simultaneously
    pub(crate) fn get_queque_process(
        &mut self,
        ctr: u64,
        ctr_p: f32,
        data_pack: Rc<[u8]>,
    ) -> Result<PackAddedStatus, WisErr<String, String>> {
        if self.fback_queue.free_space() > 0 {
            if WSQueueState::ElemIdIsBig != self.udp_queue.insert(ctr, &data_pack) {
                self.fback_queue.push(ctr, ctr_p).map_err(|err_msg| {
                    let detailed_msg = format!("Critiacl fback_queue err: {}", err_msg);
                    WisErr::Critical(detailed_msg)
                })?;

                return Ok(PackAddedStatus::WasAdded);
            }
            return Ok(PackAddedStatus::UdpQueueCtrIsBig);
        }
        Ok(PackAddedStatus::FbackQueueIsfull)
    }
}
