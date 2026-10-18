use crate::t4param::WsConnectParam;
use crate::t5conn_new::*;
use crate::t5pack_flds::MutCockSuck;
use crate::w1types::{
    Crcser, EncWis, EndCryptStuctor, HandMaker, Identified, Noncer, Randomer, Rcc, Thrasher,
    TrickyBMaker, WisErr,
};

use crate::t0pology::PackTopology;
use crate::t5coon_d3_rand::get_pack_len_and_is_fake;
use crate::t5pack_flds::init_all_pack_to_send;
//#[cfg(test)]
use crate::w1types::{
    HeadByteStruct, PackAddedStatus, PackType, PackTypeGroup, Ttl, WSQueueState, WTypeErr,
};
use std::cell::RefCell;
use std::rc::Rc;

#[macro_export]
macro_rules! impl_ws_connection {
    ( $( $item:item )* ) => {
        impl<
            Tnoncer: Noncer,
            Tthrasher: Thrasher<FuserLogicBuf>,
            Tencrer: EncWis<EndCpt>,
            Trander: Randomer,
            Tcrcser: Crcser,
            Thmaker: HandMaker<EndCpt>,
            Ttricker: TrickyBMaker<FuserLogicBuf>,
            FuserLogicBuf: Clone,
            EndCpt: EndCryptStuctor + Clone,
        >
            WsConnection<
                Tnoncer, Tthrasher, Tencrer, Trander, Tcrcser,
                Thmaker, Ttricker, FuserLogicBuf, EndCpt,
            >
        {
            $( $item )*
        }
    };
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
    Tenc: EncWis<EndCpt>,
    Tnoncer: Noncer,
    Tcrc: Crcser,
    Trshr: Thrasher<FuserLogicBuf>,
    FuserLogicBuf,
    EndCpt: EndCryptStuctor + Clone,
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
    fuck_mut: &mut MutCockSuck<Tnoncer, Tcrc, Trshr, FuserLogicBuf, EndCpt>,
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

impl_ws_connection! {
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
}

///general logic
impl_ws_connection! {

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
        let mut sp = self.get_send_plan(&cp, pack_ctr, what_should_send);

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


}

//micro tools!
impl_ws_connection! {
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

    ///Create a new file to send; if a file already exists or the transfer is incomplete,
    /// an error will occur
    pub fn paste_file(&mut self, file: Rcc<Box<[u8]>>) -> Result<(), WTypeErr> {
        if self.was_killed {
            return Err(WTypeErr::WorkTimeErr("connect_is kill".to_string()));
        }
        if !self.handshake_is_end {
            return Err(WTypeErr::WorkTimeErr(
                "connection during the key installation process".to_string(),
            ));
        }
        self.file_splitter
            .write_new_rc_file(file)
            .map_err(WTypeErr::WorkTimeErr)
    }

    ///Check if a file can be inserted
    pub fn check_paste_file(&self) -> bool {
        if self.was_killed {
            return false;
        }
        if !self.handshake_is_end {
            return false;
        }
        !self.file_splitter.i_have_some_send()
    }

    fn get_send_plan(
        &mut self,
        cp: &Rcc<WsConnectParam>,
        pack_ctr: u64,
        what_should_send: WhatSend,
    ) -> SendPlan {
        SendPlan {
            mtu: cp.mtu(),
            // ttl start -> true
            ttl: cp.ttl_max_start_cost().map(|x| (x, true)),
            id: *self.identified(),
            tb: self.get_tb(),
            ptype: match &what_should_send {
                WhatSend::Fback => PackTypeGroup::Fback,
                _ => PackTypeGroup::Data,
            },
            can_trim: matches!(&what_should_send, WhatSend::Data),
            what_should_send,
            pack_ctr,
            payload_len_final: usize::MAX,
            owerhead: usize::MAX,
            is_fake: false,
        }
    }

}
