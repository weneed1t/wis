// /*
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::integer_division)]
//#![deny(clippy::expect_used)]
#![deny(clippy::unreachable)]
#![deny(clippy::todo)]
#![deny(clippy::float_cmp)]
#![forbid(unsafe_code)]
include!("t5newcon_d1.rs");

use crate::t0pology::PackTopology;
use crate::t1fields::payload_sls_mut;
use crate::t5pack_flds::init_all_pack_to_send;
//#[cfg(test)]
use crate::w1types::{
    HeadByteStruct, PackAddedStatus, PackType, PackTypeGroup, Ttl, WSQueueState, WTypeErr,
};
use crate::w1utils::{check_probability, fuck_coeff_of_rand_pack_trim, pad_maker};

#[derive(Debug, PartialEq, Eq, Clone)]
enum WhatSend {
    Fback(usize),
    Data(usize),
    DataResending(usize),
}

impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tencrer: EncWis,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
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
    >
{
    ///Create a new file to send; if a file already exists or the transfer is incomplete,
    /// an error will occur
    pub fn paste_file(&mut self, file: Rcc<Box<[u8]>>) -> Result<(), WTypeErr> {
        self.file_splitter
            .write_new_rc_file(file)
            .map_err(WTypeErr::WorkTimeErr)
    }

    ///get_pack to send<br>
    ///send_api<br>
    ///---&\[u8\] -> this is the data packet to be sent<br>
    /// bool -> is fake or real
    ///--- Result<f32> -> this is the time the packet was sent<br>
    pub fn send_pack<F>(
        &mut self,
        _send_api: F,
        _current_time: f32,
        _force_no_edit_pack_type: bool,
        force_fback_send: bool,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&[u8], PackType, bool) -> Result<f32, String>,
    {
        //get wait queque

        // let wq = self.wait_queue.get_elements_to(current_time);

        //getfback_pack
        if self.connect_param.instant_feedback_on_packet_loss() || force_fback_send {

            //   let a = self.get_pack_len_and_is_fake(force_no_edit_pack_type, pack_type, payload_len, overhead_len)
        }
        //turn fake pack
        // if  self.connect_param().percent_fake_data_packets().is_some() || self.connect_param().percent_len_random_coefficient {
        //     //
        //     let randomer = self
        //         .random_gener
        //       .as_mut()
        //          .ok_or(WTypeErr::WorkTimeErr("UNDEAL"))?;
        //     let randomer.gen_rand_u32();
        //
        //          //потом сделаю
        //    }
        //queue unconfirmed packages is full
        if self.wait_queue.capacity() <= self.wait_queue.elems_in_me() {
            return Err(WTypeErr::WorkTimeErr("wait_queue is full".to_string()));
        }
        //file splitter is empty
        if !self.file_splitter.i_have_some_recv() {
            return Err(WTypeErr::WorkTimeErr("file_splitter is empty".to_string()));
        }

        Ok(())
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
        _send_api: F,
        _current_time: f32,
        what_should_send: WhatSend,
        force_no_edit_pack_type: Option<bool>,
    ) -> Result<(), WTypeErr>
    where
        F: FnMut(&[u8], PackType, bool) -> Result<f32, String>,
    {
        self.non_alloc_buf.0 = Some(0);

        let cp = self.connect_param();

        //get common fields
        let mtu = cp.mtu();
        let ttl_s = cp.ttl_max_start_cost();
        let id_s = self.identified().clone();
        let tbyte = self.get_tb();

        // start -> true
        let ttl_for_init = ttl_s.as_ref().map(|x| (x, true));

        let (group_pack_type, can_trim, real_payload_len) = match &what_should_send {
            WhatSend::Data(len) => (PackTypeGroup::Data, true, *len),
            WhatSend::DataResending(len) => (PackTypeGroup::Data, false, *len),
            WhatSend::Fback(len) => (PackTypeGroup::Fback, false, *len),
        };
        //==
        // 1. can_trim can be true ONLY if the group is Data.
        debug_assert!(
            !can_trim || group_pack_type == PackTypeGroup::Data,
            "can_trim is true, but group is not Data"
        );

        // 2. If the group is Fback, can_trim MUST be false.
        if group_pack_type == PackTypeGroup::Fback {
            debug_assert!(!can_trim, "Fback packet cannot be trimmed");
        }
        //==

        let topol = cp.sheme().get_topol(tbyte.unwrap_or(0), group_pack_type);

        debug_assert!(topol.is_none() && cp.sheme().is_one());
        debug_assert_eq!(self.non_alloc_buf.0, Some(0));

        let topol = topol
            .ok_or(WTypeErr::WorkTimeErr(
                "The value generated by `tricky_byter.get_tricky_byte` does not match any packet in the packet scheme.".to_string()))?;
        let ovh = topol.overhead_len();

        let (payload_len_final, is_fake) = self
            .get_pack_len_and_is_fake(
                &cp,
                force_no_edit_pack_type,
                can_trim,
                &real_payload_len,
                &ovh,
            )
            .map_err(WTypeErr::WorkTimeErr)?;

        debug_assert!(payload_len_final >= self.non_alloc_buf.1.len());

        let antoher = (ttl_for_init, &id_s, tbyte, topol);

        self.paste_and_send(
            is_fake,
            &mtu,
            &ovh,
            &payload_len_final,
            what_should_send,
            antoher,
        )?;

        Ok(())
    }

    fn paste_and_send(
        &mut self,
        is_fake: bool,
        mtu: &usize,
        ovh: &usize,
        payload_len_final: &usize,
        what_should_send: WhatSend,
        antoher: (Option<(&Ttl, bool)>, &Identified, Option<u8>, &PackTopology),
    ) -> Result<(), WTypeErr> {
        //
        let all_pack_len = payload_len_final
            .checked_add(*ovh)
            .ok_or(WTypeErr::LenSizeErr(format!(
                "payload_len_final + ovh owerwlow {} {} ",
                payload_len_final, *ovh
            )))?;

        self.non_alloc_buf.0 = Some(all_pack_len);

        let buffer_operating_range =
            self.non_alloc_buf
                .1
                .get_mut(..all_pack_len)
                .ok_or(WTypeErr::LenSizeErr(format!(
                    "self.non_alloc_buf.1[..0] all_pack_len err, {} mtu {}",
                    all_pack_len, *mtu
                )))?;
        //
        let was_padding = if !is_fake {
            let sls_payload = payload_sls_mut(buffer_operating_range, antoher.3)?;

            

            match &what_should_send {
                WhatSend::Data(_len) => false, //was paddind
                WhatSend::DataResending(len) => {
                    let index = self.prealoc_buf_wait_queue.0.ok_or_else(|| {
                        WTypeErr::CompileFieldsErr(
        "This is an impossible condition, because whenever this branch is called,
         the caller must verify that the prealoc_buf_wait_queue option has a value.".to_string()
    )
                    })?;

                    let resend = self
                        .prealoc_buf_wait_queue
                        .1
                        .get(index)
                        .ok_or(WTypeErr::CompileFieldsErr("An invalid condition:
                         in `Option prealoc_buf_wait_queue`,
                          the value is greater than the length of the `prealoc_buf_wait_queue` vector.".to_string()))?;
                    let resend = &resend.2;
                    debug_assert!(resend.len() <= *payload_len_final);
                    debug_assert_eq!(resend.len(), *len);

                    if *payload_len_final > *len {
                        if !pad_maker(sls_payload, *len) {
                            panic!(
                                "an impossible state, since pad_maker must always return true if *payload_len_final > *len"
                            );
                        }
                        true //was paddind
                    } else {
                        false //was paddind
                    }
                },

                WhatSend::Fback(_) => {
                    debug_assert!(
                        self.fback_queue.payload_len_in_bytes() <= *payload_len_final,
                        ".payload_len_in_bytes() {}   payload_len_final {}",
                        self.fback_queue.payload_len_in_bytes(),
                        *payload_len_final
                    );

                    //The value `false` is used here because `ctrs_pack`
                    // is a specific sequence of bytes that contains information about the end of the payload.
                    self.fback_queue
                        .copy_ctrs_pack_to_slice(sls_payload, false)
                        .map_err(|x| {
                            WTypeErr::WorkTimeErr(format!(
                                "ERR fback_queue
                    .copy_ctrs_pack_to_slice err: {:?}",
                                x
                            ))
                        })?;
                    false //was paddind
                },
            }
        } else {
            false
        };

        let mut_enc = self.encrypt.get_mut();

        let mut_fms = self.fuck_mut_struct.get_mut();

        let mut hb = HeadByteStruct::new();

        hb.set_need_trim_is_pad(was_padding);
        hb.set_need_trim_is_pad(is_fake);
        hb.set_is_kill(self.was_killed);

        init_all_pack_to_send(
            buffer_operating_range,
            antoher.3,
            hb,
            &self.ctrs.my_fback,
            PackType::Fback,
            antoher.1,
            antoher.2,
            antoher.0,
            mtu,
            mut_enc,
            mut_fms,
        )?;

        debug_assert_eq!(self.non_alloc_buf.0, Some(all_pack_len));

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

    /// Determines the final payload length and whether the packet was marked as fake.
    ///
    /// The function may randomly adjust the packet length within a configured range
    /// and optionally change the packet type to `Fake` with a given probability.
    ///
    /// # Arguments
    /// * `force_no_edit_pack_type` – if `true`, prevents the type from being changed to `Fake`.
    /// * `pack_type` – current packet type (Data, Fback, or Fake).
    /// * `payload_len` – current payload length.
    /// * `overhead_len` – length of protocol overhead.
    ///
    /// # Returns
    /// * `Ok((new_length, was_fake))` – the adjusted length and a boolean indicating
    ///   whether the type was actually changed to `Fake`.
    /// * `Err` – if the free space cannot be computed or the random generator is missing.
    /// The final pack is constructed from overhead_len + get_pack_len_and_is_fake(...)
    /// The function returns the length of the PAYLOAD ONLY!
    /// force_no_edit_pack_type: None -> pack_type is random
    /// force_no_edit_pack_type: true -> force set pack_type is non edit
    /// force_no_edit_pack_type: false -> force set pack_type is fake
    fn get_pack_len_and_is_fake(
        &mut self,
        cp: &WsConnectParam,
        force_no_edit_pack_type: Option<bool>,
        can_trim: bool,
        payload_len: &usize,
        overhead_len: &usize,
    ) -> Result<(usize, bool), String> {
        let random_need = cp.need_init_random();
        let mtu = cp.mtu();

        let mut ret_len = *payload_len;

        // Maximum payload size allowed by the link MTU minus overhead.
        let free_len_zone = mtu
            .checked_sub(*overhead_len)
            .ok_or("mtu - overhead_len unreal state")?;
        //
        // for test
        #[cfg(test)]
        let mut alg_param = (
            ret_len,       //ret len after edit // 0
            mtu,           //mut // 1
            free_len_zone, // free zone 2
            None,          //pack type after edit 3
            can_trim,      // pack edit before edit 4
            None,          // rand u32  5
            None,          // need trim 6
            None,          //rand_n usize // 7
            random_need,   // random_need 8
        );

        // Random adjustments are only applied if enabled globally.
        let was_set_fake = if random_need {
            let ranger = cp.length_trimming_range();
            let coef_fake = cp.percent_fake_any_packets();

            let rnd = self.random_gener.as_mut().ok_or(
                "impossible state random_gener is none,it must be defined get_pack_len_and_is_fake",
            )?;

            // Possibly convert the packet to Fake based on probability.
            let was_set_fake_local = match force_no_edit_pack_type {
                Some(true) => false,
                Some(false) => true,
                None => {
                    if let Some(coeff) = coef_fake {
                        let rand_n = rnd.gen_rand_u32();

                        #[cfg(test)]
                        {
                            alg_param.5 = Some(rand_n);
                            alg_param.3 = Some(can_trim);
                        }
                        check_probability(coeff, rand_n)
                    } else {
                        false
                    }
                },
            };

            // Randomly trim or extend the payload length within the allowed range.
            if let Some(rangee) = ranger {
                let rand_n = rnd.gen_rand_usize();

                #[cfg(test)]
                {
                    alg_param.6 = Some(can_trim);
                    alg_param.7 = Some(rand_n);
                }

                ret_len = fuck_coeff_of_rand_pack_trim(
                    &free_len_zone,
                    payload_len,
                    &rand_n,
                    &rangee,
                    can_trim,
                )?;
            }
            was_set_fake_local
        } else {
            false
        };

        #[cfg(test)]
        self.test_get_pack_len_and_is_fake(
            (ret_len, was_set_fake),
            (
                force_no_edit_pack_type,
                can_trim,
                *payload_len,
                *overhead_len,
            ),
            alg_param,
        );

        Ok((ret_len, was_set_fake))
    }

    ///adds a packet to both the fback and udp queues simultaneously
    fn get_queque_process(
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
///
///
///
/// -===================================TESTS ====================================TEST ============================
///
///
#[cfg(test)]
#[allow(clippy::unwrap_used)]
impl<
    Tnoncer: Noncer,
    Tthrasher: Thrasher<FuserLogicBuf>,
    Tencrer: EncWis,
    Trander: Randomer,
    Tcrcser: Crcser,
    Thmaker: HandMaker,
    Ttricker: TrickyBMaker<FuserLogicBuf>,
    FuserLogicBuf: Clone,
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
    >
{
    #[cfg(test)]
    ///get_udp f
    pub fn test_get_fback(&mut self) -> &mut WSFbackQueue<f32> {
        &mut self.fback_queue
    }
    #[cfg(test)]
    ///get_udp
    pub fn test_get_udp(&mut self) -> &mut WSUdpLike<Rc<[u8]>> {
        &mut self.udp_queue
    }
    #[cfg(test)]
    ///swap_udp fb
    pub fn test_swap_fback(&mut self, fb: WSFbackQueue<f32>) {
        self.fback_queue = fb;
    }
    #[cfg(test)]
    ///swap_udp q
    pub fn test_swap_udp(&mut self, udp: WSUdpLike<Rc<[u8]>>) {
        self.udp_queue = udp;
    }

    fn test_get_pack_len_and_is_fake(
        &self,
        return_param: (usize, bool),
        input_param: (Option<bool>, bool, usize, usize),
        hiddy_param: (
            usize,         // 0: ret_len after edit
            usize,         // 1: mtu
            usize,         // 2: free_len_zone
            Option<bool>,  // 3: pack_type after edit (if coef_fake condition met)
            bool,          // 4: pack_type before edit
            Option<u32>,   // 5: rand_u32 (if coef_fake condition met)
            Option<bool>,  // 6: need_trimm (if ranger present)
            Option<usize>, // 7: rand_n usize (if ranger present)
            bool,          // 8: random_need
        ),
    ) {
        let (ret_len, was_set_fake) = return_param;
        let (force_no_edit, pack_type_in, payload_len, overhead_len) = input_param;
        let (
            ret_len_after_edit,
            mtu,
            free_len_zone,
            pack_type_after_edit_opt,
            pack_type_before_edit,
            rand_u32_opt,
            need_trimm_opt,
            rand_n_opt,
            random_need,
        ) = hiddy_param;

        if let Some(x) = force_no_edit {
            assert_ne!(x, !was_set_fake);
        }
        assert_eq!(mtu.checked_sub(overhead_len).unwrap(), free_len_zone);

        // Check that the stored ret_len matches the returned length.
        assert_eq!(ret_len_after_edit, ret_len);

        // Verify that the 'before edit' pack type is as passed.
        assert_eq!(pack_type_before_edit, pack_type_in);

        // If random adjustments are disabled, nothing should change.
        if !random_need {
            assert_eq!(ret_len, payload_len);
            assert!(!was_set_fake);
            assert_eq!(pack_type_after_edit_opt.clone(), None);
            assert_eq!(rand_u32_opt, None);
            assert_eq!(need_trimm_opt, None);
            assert_eq!(rand_n_opt, None);
            return;
        }

        // --- Random adjustments are enabled ---

        // Check fake conversion path.
        // coef_fake and force_no_edit are known only at runtime, but we can check invariants:
        // If pack_type_after_edit_opt is Some, it means the condition (coef_fake && !force_no_edit) was true.
        // If it is None, the condition was false.
        let p_temt = pack_type_after_edit_opt;
        if let Some(_pack_type_after) = p_temt {
            // Then rand_u32 must have been generated.
            assert!(rand_u32_opt.is_some());
            // If was_set_fake is true, the type must have been changed to Fake.
        } else {
            // Condition not met -> no fake probability evaluation.
            assert_eq!(rand_u32_opt, None);
            // was_set_fake must be false because fake cannot be set.
            assert!(!was_set_fake);
            // pack_type_after remains the original (but we don't store it).
        }

        // Check length trimming path.
        if let (Some(need_trimm), Some(rand_n)) = (need_trimm_opt, rand_n_opt) {
            // ranger was present.
            // Recompute expected length using the same logic as in fuck_coeff_of_rand_pack_trim.
            let expected_len = fuck_coeff_of_rand_pack_trim(
                &free_len_zone,
                &payload_len,
                &rand_n,
                &self.connect_param().length_trimming_range().unwrap(), // rangee must be the same, but we don't have it directly.
                need_trimm,
            )
            .unwrap();

            assert_eq!(expected_len, ret_len);

            // However, we don't have the actual rangee value in hiddy_param.
            // We can retrieve it from the connection params, but that would break isolation.
            // Instead, we can trust that the function's logic is correct and just check that ret_len is within bounds.
            assert!(ret_len >= 1 && ret_len <= free_len_zone);
            // Also check that ret_len matches the value stored in alg_param.0 (already checked).
            // We can also verify that if need_trimm == true (no_trim == false), then ret_len may be less than payload_len,
            // but not strictly enforceable because random_offset can increase it.
        } else {
            // ranger not present -> no length adjustment.
            assert_eq!(need_trimm_opt, None);
            assert_eq!(rand_n_opt, None);
            assert_eq!(ret_len, payload_len);
        }

        // Additional invariants:
        // If was_set_fake is true, the final pack_type (input_param.1 after mutation) must be Fake,
        // but we don't have that value. However, we can deduce: if was_set_fake true, then pack_type_after_edit_opt must be Some(Fake).

        // Ensure that if random_need is false, the options are all None (already covered above).
    }
}

#[cfg(test)]
mod test_get_queque_process {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    //#![deny(clippy::expect_used)]
    #![allow(clippy::unreachable)]
    #![allow(clippy::todo)]
    #![allow(clippy::float_cmp)]
    use super::*;
    use std::rc::Rc;

    #[test]
    fn test_get_queque_process() {
        let mut tw = fast_wconn_maker();

        let mut vv: Vec<(usize, f32, Rc<[u8]>)> = Vec::with_capacity(90);

        for x in 0..vv.capacity() {
            vv.push((x, x as f32 * 1.234, Rc::from(vec![1; 10])));
        }
        for len_f in [7, 17, 30] {
            for len_u in [7, 17, 30] {
                let fb = WSFbackQueue::<f32>::new(3, len_f, 1000).unwrap();
                let ud = WSUdpLike::new(len_u).unwrap();

                tw.test_swap_udp(ud);
                tw.test_swap_fback(fb);

                for (i, d) in vv.iter().enumerate() {
                    let mut need_clean = true;

                    let test = tw.get_queque_process(d.0 as u64, d.1, d.2.clone()).unwrap();

                    // println!("{:?}, i {}  lf {}   lu {}", test.clone(), i, len_f, len_u);
                    let min = std::cmp::min(len_f, len_u);
                    if test == PackAddedStatus::WasAdded {
                        need_clean = false;

                        //println!("{}", i % (min + 1));
                        assert_ne!(i % (min + 1), min)
                    } else {
                        assert_ne!(i % std::cmp::min(len_f, len_u), min);
                        assert_eq!(i % (min + 1), min);
                        // println!(" =========== qq {}", min);
                        if len_f <= len_u {
                            assert_eq!(test, PackAddedStatus::FbackQueueIsfull);
                        } else if len_f > len_u {
                            assert_eq!(test, PackAddedStatus::UdpQueueCtrIsBig);
                        } else {
                            panic!("inreal test state!");
                        }
                    }

                    if need_clean {
                        {
                            let ffb = tw.test_get_fback();
                            let _ = ffb.get_ctrs_as_byte_pack_vec();
                        }

                        let uud = tw.test_get_udp();

                        let _ = uud.insert(d.0 as u64, &d.2.clone());
                        let _ = uud.get_queue(None);
                        let _ = uud.insert(d.0 as u64, &d.2.clone()); //double add double dell
                        let _ = uud.get_queue(None); // double dell
                    }
                    // println!("{:?}", test);
                }
            }
        }
    }

    #[test]
    fn test_one_shuf() {
        let mut x1 = vec![];
        for i in 0..10000 {
            x1.push(i);
        }
        let x = x1.clone();

        for m in [3isize, 10, 14, 20].iter() {
            let mut etalon = x.clone();

            let mut ct = 0;
            shuffle_with_limited_displacement(&mut etalon, *m as usize);

            for yy in etalon.iter().zip(x.iter()) {
                let mut r = *yy.0 - *yy.1;

                if r < 0 {
                    r *= -1;
                }

                assert!(r <= *m, "{m}");

                ct += (*yy.0 == *yy.1) as i32;
            }
            assert!(0.38 > (ct as f32 / x.len() as f32)); //first m = 3, 1/3 =0.33333, 0.38 > 0.33 +-0.05
            println!("{}", ct as f32 / x.len() as f32);
        }
    }

    fn shuffle_with_limited_displacement<T>(vec: &mut [T], mm: usize) {
        let n = vec.len();
        if n == 0 || mm == 0 {
            return;
        }

        let block_size = mm + 1;
        let mut seed = 123456789u64; //seed

        let mut start = 0;
        while start < n {
            let end = (start + block_size).min(n);
            let _len = end - start;

            // Перемешивание блока [start, end) алгоритмом Фишера-Йетса
            for i in (start..end).rev() {
                // Генерация псевдослучайного числа в диапазоне [start, i]
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (seed >> 16) as usize % (i - start + 1);
                let j = start + offset;
                vec.swap(i, j);
            }

            start = end;
        }
    }
}
