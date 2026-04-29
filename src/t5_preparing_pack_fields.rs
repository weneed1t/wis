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
use crate::checked_cast;
use crate::t0pology::*;
use crate::t1fields::{
    crypt, get_id_conn, get_id_sender_and_recv, get_len, get_tricky_byte, get_ttl, set_counter,
    set_get_head_crc, set_id_conn, set_id_sender_and_recv, set_len, set_tricky_byte, set_ttl,
    set_user_field,
};
use crate::wt1types::{
    Crcser, Cryptlag, EncWis, Identified, Ids, Noncer, PackType, Thrasher, Ttl, WTypeErr,
};

///check crc + get idc/ids/idr + get len + get TrickyByte
pub fn get_all_pub_info_of_package<'a, Tcrc>(
    metal_id: u64,
    pack: &'a mut [u8],
    topology: &PackTopology,
    check_head_crc_if_pack_not_from_tls_like_queue: Option<&mut Tcrc>,
    ttl: Option<(&Ttl, bool)>,
) -> Result<(Identified, usize, Option<u64>, Option<u8>, &'a mut [u8]), WTypeErr>
where
    Tcrc: Crcser,
{
    // HEAR CRC
    //

    if let Some(chrss) = check_head_crc_if_pack_not_from_tls_like_queue {
        let lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), &'static str> {
            chrss.gen_crc(da1ta, out)?;

            Ok(())
        };

        if !set_get_head_crc(false, pack, topology, lbo)? {
            return Err(WTypeErr::PackageDamaged("head crc is incorrect"));
        }
    }

    // LEN
    //
    let len_of_pack = if topology.len_slice().is_some() {
        get_len(pack, topology)?
    } else {
        pack.len()
    };

    //IDS
    //
    let mut ids_mys = Identified {
        my_metall_id: metal_id,
        my_s_r_id: None,
        id_conn: None,
    };

    if topology.id_of_sender_slice().is_some() {
        let (send, recv) = get_id_sender_and_recv(pack, topology)?;
        ids_mys.my_s_r_id = Some(Ids {
            id_sender: send,
            id_receiver: recv,
        })
    }
    //ID CON
    //
    if topology.idconn_slice().is_some() {
        let (id_conn, role) = get_id_conn(pack, topology)?;
        ids_mys.id_conn = Some((id_conn, role));
    }

    Ok((
        ids_mys,
        len_of_pack,
        if topology.ttl_slice().is_some() {
            //TTL
            //if ttl == some / else = err
            if let Some(ttl_main) = ttl {
                //ttl_main.1 = true get and edit ttl / ttl_main.1 = false only get ttl
                if ttl_main.1 {
                    Some(set_ttl(
                        pack,
                        topology,
                        &ttl_main.0.ttl_edit,
                        &ttl_main.0.ttl_max,
                        false, // ttl is no start
                        ttl_main.0.forced_pruning,
                    )?)
                } else {
                    Some(get_ttl(pack, topology, &ttl_main.0.ttl_max)?)
                }
            } else {
                return Err(WTypeErr::CompileFieldsErr(
                    "topology.ttl_slice().is_some() but ttl.is_none()",
                ));
            }
        } else {
            None
        },
        if topology.tricky_byte().is_some() {
            //TrickyByte
            Some(get_tricky_byte(pack, topology)?)
        } else {
            None
        },
        pack.get_mut(..len_of_pack).ok_or(WTypeErr::PackageDamaged(
            "impossible state since here len_of_pack should indicate the length of the packet and \
             should be checked before being used",
        ))?,
    ))
}

///general
#[allow(clippy::too_many_arguments)]
pub fn init_all_pack_to_send<Tenc: EncWis, Tnoncer: Noncer, Tcrc: Crcser, Trshr: Thrasher>(
    pack: &mut [u8],
    topology: &PackTopology,
    ctr: &u64,
    pack_type: &PackType,
    all_id: &Identified,
    tricky_byte: Option<u8>,
    ttl: Option<(&Ttl, bool)>,
    nonce_gener: Option<&mut Tnoncer>,
    crc: Option<&mut Tcrc>,
    trash_gener: Option<&mut Trshr>,
    enc_struct: &mut Tenc,
    mtu: &usize,
) -> Result<(), WTypeErr> {
    //
    //idi:
    {
        if topology.idconn_slice().is_some() {
            let (id_conn, role) = all_id
                .id_conn
                .as_ref()
                .ok_or(WTypeErr::CompileFieldsErr("Identified::id connect is none"))?;

            set_id_conn(pack, topology, id_conn, role)?;
        }

        if topology.id_of_sender_slice().is_some() {
            let id_s_r = all_id
                .my_s_r_id
                .as_ref()
                .ok_or(WTypeErr::CompileFieldsErr("Identified::Ids is none"))?;
            set_id_sender_and_recv(pack, topology, &id_s_r.id_sender, &id_s_r.id_receiver)?;
        }
    }
    // len set
    if topology.len_slice().is_some() {
        set_len(pack, topology, mtu)?;
    }

    // counter set
    if topology.counter_slice().is_some() {
        set_counter(pack, topology, ctr, pack_type)?;
    }

    //ttl
    //if ttl == some / else = err\
    if topology.ttl_slice().is_some() {
        let ttl_main = ttl.ok_or(WTypeErr::CompileFieldsErr(
            "topology.ttl_slice().is_some() but ttl.is_none()",
        ))?;
        let temptl = ttl_main.0.ttl_start;
        let ttl_i64 = checked_cast!( temptl=> i64, err WTypeErr::WorkTimeErr("ttl start(u64) to ttl edit(i64) convert error"))?;

        set_ttl(
            pack,
            topology,
            &ttl_i64,
            &ttl_main.0.ttl_max,
            true, //is ttl start
            ttl_main.0.forced_pruning,
        )?;
    }
    // user fields
    if topology.trash_content_slice().is_some() {
        let trasher = trash_gener.ok_or(WTypeErr::CompileFieldsErr(
            "trash_gener is none but topology.trash_content_slice().is_some()",
        ))?;

        let lbo = |fieldt_to_fill: &mut [u8],
                   ctr_pack: &u64,
                   len_of_pack: &usize,
                   ctr_field_in_pack: &usize,
                   topolog_y: &PackTopology|
         -> Result<(), &'static str> {
            trasher.set_user_field(
                fieldt_to_fill,
                ctr_pack,
                len_of_pack,
                ctr_field_in_pack,
                topolog_y,
            )
        };

        set_user_field(pack, topology, ctr, &pack.len(), lbo)?;
    }

    //set_tricky_byte
    if topology.tricky_byte().is_some() {
        set_tricky_byte(
            pack,
            topology,
            tricky_byte.ok_or(WTypeErr::CompileFieldsErr(
                "topology.tricky_byte().is_some() but tricky_byte is none",
            ))?,
        )?
    }

    //crypt
    crypt(
        pack,
        topology,
        Cryptlag::Encrypt,
        enc_struct,
        Some(ctr),
        nonce_gener,
    )?;

    if topology.head_crc_slice().is_some() {
        let crcer = crc.ok_or(WTypeErr::CompileFieldsErr(
            "topology.head_crc_slice().is_some()  but crc is none",
        ))?;

        let lbo = |head: &[u8], crc_slice: &mut [u8]| -> Result<(), &'static str> {
            crcer.gen_crc(head, crc_slice)
        };

        set_get_head_crc(true, pack, topology, lbo)?;
    }

    Ok(())
}

#[cfg(test)]
mod test_get_all_pub_info_of_package {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    use super::*;
    use crate::t1dumps_struct::{DumpCrcser, DumpEnc, DumpNonser, DumpThrasher};
    use crate::t1fields::{set_id_conn, set_id_sender_and_recv, set_len, set_tricky_byte, set_ttl};
    use crate::wt1types::MyRole;
    #[test]
    #[allow(clippy::len_zero)]
    fn t1_get_pack_pube() {
        let fields = vec![PackFields::Counter(8)];

        let mut ctr_glob = 0;
        for a_len in [vec![PackFields::Len(4)], vec![]] {
            for a_sr in [
                vec![PackFields::IdSender(6), PackFields::IdReceiver(6)],
                vec![],
            ] {
                for (a_crc, head_damage) in [
                    (vec![PackFields::HeadCRC(4)], false),
                    (vec![PackFields::HeadCRC(4)], true), // brear bytes in head
                    (vec![], false),
                ] {
                    for a_tb in [vec![PackFields::TrickyByte], vec![]] {
                        for a_ttl in [vec![PackFields::TTL(3)], vec![]] {
                            for a_idc in [vec![PackFields::IdConnect(7)], vec![]] {
                                for ttl_bool_edit in [true, false] {
                                    ctr_glob += 1;

                                    //
                                    let fields: Vec<PackFields> = fields
                                        .clone()
                                        .into_iter()
                                        .chain(a_crc.clone())
                                        .chain(a_tb.clone())
                                        .chain(a_ttl.clone())
                                        .chain(a_len.clone())
                                        .chain(a_sr.clone())
                                        .chain(a_idc.clone())
                                        .collect();

                                    let ttl_struct = Ttl {
                                        ttl_max: 200,
                                        ttl_edit: -73,
                                        ttl_start: 100,
                                        forced_pruning: false,
                                    };

                                    let mut pack = vec![0x11; 100];

                                    let topology =
                                        PackTopology::new(5, &fields, true, false).unwrap();

                                    //
                                    //
                                    if a_len.len() > 0 {
                                        set_len(&mut pack[..90], &topology, &1000).unwrap();
                                    }
                                    if a_sr.len() > 0 {
                                        set_id_sender_and_recv(
                                            &mut pack, &topology, &7890, &123456,
                                        )
                                        .unwrap();
                                    }
                                    if a_ttl.len() > 0 {
                                        set_ttl(
                                            &mut pack,
                                            &topology,
                                            &(ttl_struct.ttl_start as i64),
                                            &ttl_struct.ttl_max,
                                            true,
                                            false,
                                        )
                                        .unwrap();
                                    }
                                    if a_idc.len() > 0 {
                                        set_id_conn(&mut pack, &topology, &3213, &MyRole::Passive)
                                            .unwrap();
                                    }
                                    if a_tb.len() > 0 {
                                        set_tricky_byte(&mut pack, &topology, 123).unwrap();
                                    }

                                    if a_crc.len() > 0 {
                                        //GENERATE CRC
                                        //
                                        let mut chrss = DumpCrcser::new(&[0]).unwrap();

                                        let lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), &'static str> {
                                          chrss.gen_crc(da1ta, out)?;

                                         // println!("CRC ME COCEKD: {:?},   all data{:?}",out,Vec::from( &da1ta[..topology.encrypt_start_pos()]));
                                         Ok(())};

                                        set_get_head_crc(true, &mut pack, &topology, lbo).unwrap();
                                    } //geneg crc
                                    //

                                    if head_damage {
                                        //damage random head byte
                                        pack[topology.encrypt_start_pos() / 2] ^= 0xFF; // !pa_2[5] ;
                                    }
                                    //

                                    let mut not_use_in_check = Vec::from(&pack[..]);

                                    let omygood = &get_all_pub_info_of_package(
                                        1337,
                                        &mut not_use_in_check[..],
                                        &topology,
                                        Some(&mut DumpCrcser::new(&[0]).unwrap()),
                                        Some((&ttl_struct, ttl_bool_edit)),
                                    );

                                    if head_damage {
                                        println!("CTR ME: {}", ctr_glob);
                                        assert_eq!(
                                            omygood.as_ref().unwrap_err(),
                                            &WTypeErr::PackageDamaged("head crc is incorrect")
                                        );
                                        continue;
                                    }

                                    if a_crc.len() == 0 {
                                        let t = omygood.as_ref().unwrap_err();
                                        assert_eq!(
                                            *t,
                                            WTypeErr::CompileFieldsErr(
                                                "head_crc_slice not in PackTopology"
                                            )
                                        );
                                    } else {
                                        let get_ids_len_triclyb = omygood.as_ref().unwrap();

                                        if a_len.len() > 0 {
                                            assert_eq!(get_ids_len_triclyb.1, 90);
                                        } else {
                                            assert_eq!(get_ids_len_triclyb.1, 100);
                                        }

                                        if a_sr.len() > 0 {
                                            let ids =
                                                get_ids_len_triclyb.0.my_s_r_id.as_ref().unwrap();
                                            let rr = ids.id_receiver;
                                            let ss = ids.id_sender;

                                            assert_eq!(rr, 123456);
                                            assert_eq!(ss, 7890);
                                        } else {
                                            assert!(get_ids_len_triclyb.0.my_s_r_id.is_none());
                                        }
                                        //
                                        //
                                        if a_idc.len() > 0 {
                                            assert_eq!(
                                                get_id_conn(&pack, &topology).unwrap(),
                                                *get_ids_len_triclyb.0.id_conn.as_ref().unwrap()
                                            );
                                        } else {
                                            assert!(get_id_conn(&pack, &topology).is_err());
                                            assert!(
                                                get_ids_len_triclyb.0.id_conn.as_ref().is_none()
                                            );
                                        }
                                        //
                                        //

                                        if a_ttl.len() > 0 {
                                            let ttl_after_get = if ttl_bool_edit {
                                                ttl_struct.ttl_start
                                            } else {
                                                ((ttl_struct.ttl_max as i64) + ttl_struct.ttl_edit)
                                                    as u64
                                            };

                                            assert_eq!(
                                                get_ttl(
                                                    get_ids_len_triclyb.4,
                                                    &topology,
                                                    &ttl_after_get
                                                )
                                                .unwrap(),
                                                *get_ids_len_triclyb.2.as_ref().unwrap()
                                            );
                                        } else {
                                            assert!(
                                                get_ttl(&pack, &topology, &ttl_struct.ttl_max)
                                                    .is_err()
                                            );
                                            assert!(get_ids_len_triclyb.2.as_ref().is_none());
                                        }
                                        //
                                        //

                                        if a_tb.len() > 0 {
                                            assert_eq!(
                                                get_tricky_byte(&pack, &topology).unwrap(),
                                                *get_ids_len_triclyb.3.as_ref().unwrap()
                                            );
                                            assert_eq!(
                                                get_tricky_byte(&pack, &topology).unwrap(),
                                                123
                                            );
                                        } else {
                                            assert!(get_tricky_byte(&pack, &topology).is_err());
                                            assert!(get_ids_len_triclyb.3.as_ref().is_none());
                                        }

                                        // println!("{:?}", omygood);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[allow(clippy::len_zero)]
    fn t1_set_pack_pube() {
        let mut ctr_glob = 0;
        let mut ctr_of_err = 0;

        let (
            pack_ctr_options,
            len_options,
            id_connect_options,
            user_fields_options,
            nonce_options,
            sr_options,
            crc_options,
            tricky_byte_options,
            ttl_options,
        ) = get_options1();

        let mut crcer = DumpCrcser::new(&[0]).unwrap();
        let mut encer = DumpEnc::new(&[0]).unwrap();
        let mut user_fieldser = DumpThrasher::new(&[0]).unwrap();

        let mut rolle = true;

        for pack_ctr in pack_ctr_options.iter() {
            for (user_fields, user_flag) in user_fields_options.iter() {
                for (a_nonce, nonce_flag) in nonce_options.iter() {
                    for a_len in len_options.iter() {
                        for (a_sr, sr_flag) in sr_options.iter() {
                            for (a_crc, crc_flag) in crc_options.iter() {
                                for (a_tb, tb_flag) in tricky_byte_options.iter() {
                                    for (a_ttl, ttl_flag) in ttl_options.iter() {
                                        for (a_idc, idc_flag) in id_connect_options.iter() {
                                            let mut nanoser = DumpNonser::new(&[0]).unwrap();
                                            let mut nanoser_test = DumpNonser::new(&[0]).unwrap();
                                            let all_flags_true = *user_flag
                                                && *nonce_flag
                                                && *sr_flag
                                                && *crc_flag
                                                && *tb_flag
                                                && *ttl_flag
                                                && *idc_flag;

                                            ctr_glob += 1;

                                            let fields: Vec<PackFields> = {
                                                vec![]
                                                    .clone()
                                                    .into_iter()
                                                    .chain((*a_crc).clone())
                                                    .chain((*a_tb).clone())
                                                    .chain((*a_ttl).clone())
                                                    .chain((*a_len).clone())
                                                    .chain((*a_sr).clone())
                                                    .chain((*a_idc).clone())
                                                    .chain((*pack_ctr).clone())
                                                    .chain((*user_fields).clone())
                                                    .chain((*a_nonce).clone())
                                                    .collect()
                                            };

                                            let ttl_struct = Ttl {
                                                ttl_max: 200,
                                                ttl_edit: -73,
                                                ttl_start: 100,
                                                forced_pruning: false,
                                            };

                                            let ctr_in_pack = ctr_glob; //randomize

                                            let mut pack = vec![0x11; 500];
                                            let mut pack_for_check = pack.clone();

                                            let topology =
                                                PackTopology::new(5, &fields, true, false).unwrap();

                                            let resultat = init_all_pack_to_send(
                                                &mut pack[..],
                                                &topology,
                                                &ctr_in_pack,
                                                &PackType::Data,
                                                &ids_get(
                                                    *idc_flag,
                                                    *sr_flag,
                                                    if rolle {
                                                        rolle = !rolle;
                                                        MyRole::Initiator
                                                    } else {
                                                        rolle = !rolle;
                                                        MyRole::Passive
                                                    },
                                                ),
                                                if *tb_flag { Some(123) } else { None },
                                                if *ttl_flag {
                                                    Some((&ttl_struct, false))
                                                } else {
                                                    None
                                                },
                                                if *nonce_flag {
                                                    Some(&mut nanoser)
                                                } else {
                                                    None
                                                },
                                                if *crc_flag { Some(&mut crcer) } else { None },
                                                if *user_flag {
                                                    Some(&mut user_fieldser)
                                                } else {
                                                    None
                                                },
                                                &mut encer,
                                                &1000,
                                            );
                                            let pack = pack;

                                            if let Some(err_res) = resultat.err() {
                                                if all_flags_true {
                                                    println!(
                                                        "glob:{} err:{}   {:?} {:?}",
                                                        ctr_glob, ctr_of_err, err_res, fields
                                                    );
                                                    assert!(
                                                        false == true,
                                                        "The error should only occur when \
                                                         all_flags_true == false, if the error \
                                                         occurs when all_flags_true == true, the \
                                                         code does not work correctly!"
                                                    );
                                                } else {
                                                    continue;
                                                }
                                                ctr_of_err += 1;

                                                assert!(!all_flags_true);
                                            }

                                            //
                                            //CHECK!!!!
                                            //

                                            {
                                                //ttl
                                                if a_ttl.len() > 0 {
                                                    set_ttl(
                                                        &mut pack_for_check,
                                                        &topology,
                                                        &(ttl_struct.ttl_start as i64),
                                                        &ttl_struct.ttl_max,
                                                        true,
                                                        ttl_struct.forced_pruning,
                                                    )
                                                    .unwrap();

                                                    let (s, n, _) = topology.ttl_slice().unwrap();
                                                    assert!(pack[s..n].eq(&pack_for_check[s..n]));
                                                }

                                                //len
                                                if a_len.len() > 0 {
                                                    set_len(&mut pack_for_check, &topology, &1000)
                                                        .unwrap();

                                                    let (s, n, _) = topology.len_slice().unwrap();
                                                    assert!(pack[s..n].eq(&pack_for_check[s..n]));
                                                }

                                                //nonce
                                                if a_nonce.len() > 0 {
                                                    let (s, n, _) = topology.nonce_slice().unwrap();

                                                    nanoser_test
                                                        .set_nonce(&mut pack_for_check[s..n])
                                                        .unwrap();

                                                    assert!(
                                                        pack[s..n].eq(&pack_for_check[s..n]),
                                                        "noncetes ! = pack[s..n]  \n{:?} \n{:?}",
                                                        Vec::from(&pack[s..n]),
                                                        &pack_for_check[s..n],
                                                    );
                                                }

                                                // sed recv
                                                if a_sr.len() > 0 {
                                                    set_id_sender_and_recv(
                                                        &mut pack_for_check,
                                                        &topology,
                                                        &1111111,
                                                        &2222222,
                                                    )
                                                    .unwrap();

                                                    let (s, n, _) =
                                                        topology.id_of_sender_slice().unwrap();
                                                    assert!(pack[s..n].eq(&pack_for_check[s..n]));

                                                    let (s, n, _) =
                                                        topology.id_of_receiver_slice().unwrap();
                                                    assert!(pack[s..n].eq(&pack_for_check[s..n]));
                                                }

                                                // sed idc
                                                if a_idc.len() > 0 {
                                                    set_id_conn(
                                                        &mut pack_for_check,
                                                        &topology,
                                                        &33333,
                                                        &if !rolle {
                                                            MyRole::Initiator
                                                        } else {
                                                            MyRole::Passive
                                                        },
                                                    )
                                                    .unwrap();

                                                    let (s, n, _) =
                                                        topology.idconn_slice().unwrap();
                                                    assert!(pack[s..n].eq(&pack_for_check[s..n]));
                                                }

                                                // sed ctr
                                                {
                                                    set_counter(
                                                        &mut pack_for_check,
                                                        &topology,
                                                        &ctr_in_pack,
                                                        &PackType::Data,
                                                    )
                                                    .unwrap();

                                                    let (s, n, _) =
                                                        topology.counter_slice().unwrap();
                                                    assert!(
                                                        pack[s..n].eq(&pack_for_check[s..n]),
                                                        "noncetes ! = pack[s..n]  \n{:?} \n{:?}",
                                                        Vec::from(&pack[s..n]),
                                                        &pack_for_check[s..n],
                                                    );
                                                }

                                                // sed tricky_byte
                                                if a_tb.len() > 0 {
                                                    set_tricky_byte(
                                                        &mut pack_for_check,
                                                        &topology,
                                                        123,
                                                    )
                                                    .unwrap();

                                                    let s = topology.tricky_byte().unwrap();
                                                    assert!(pack[s] == pack_for_check[s]);
                                                }

                                                if user_fields.len() > 0 {
                                                    let lbo =|
                                                    _user_field: &mut [u8],
        _counter_pack: &u64,
        _len_pack: &usize,
        _counter_of_field: &usize,
        _topoligy: &PackTopology,| -> Result<(), &'static str> {user_fieldser.set_user_field(_user_field, _counter_pack, _len_pack, _counter_of_field, _topoligy)};

                                                    set_user_field(
                                                        &mut pack_for_check,
                                                        &topology,
                                                        &ctr_in_pack,
                                                        &pack.len(),
                                                        lbo,
                                                    )
                                                    .unwrap();

                                                    for &(s, n, _) in topology
                                                        .trash_content_slice()
                                                        .unwrap()
                                                        .iter()
                                                    {
                                                        assert!(
                                                            pack[s..n].eq(&pack_for_check[s..n]),
                                                            "noncetes ! = pack[s..n]  \n{:?} \
                                                             \n{:?}",
                                                            Vec::from(&pack[s..n]),
                                                            &pack_for_check[s..n],
                                                        );
                                                    }
                                                }

                                                //crc

                                                //  /*

                                                if a_crc.len() > 0 {
                                                    let lbo =
                                                    |head: &[u8], crc_slice: &mut [u8]| -> Result<(), &'static str> {crcer.gen_crc(head, crc_slice)};

                                                    set_get_head_crc(
                                                        true,
                                                        &mut pack_for_check,
                                                        &topology,
                                                        lbo,
                                                    )
                                                    .unwrap();

                                                    let (s, n, _) =
                                                        topology.head_crc_slice().unwrap();
                                                    assert!(pack[s..n].eq(&pack_for_check[s..n]));
                                                } // */
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[allow(clippy::len_zero)]
    fn pack_pube_bnc() {
        if true == true {
            return; // =========== NO BENCH IN TEST
        }

        fn ids_get_s(id_coon: bool, id_sr: bool, p: MyRole) -> Identified {
            Identified {
                my_metall_id: 45654654,
                my_s_r_id: if id_sr {
                    Some(Ids {
                        id_sender: 111,
                        id_receiver: 222,
                    })
                } else {
                    None
                },
                id_conn: if id_coon { Some((99, p)) } else { None },
            }
        }
        let mut crcer = DumpCrcser::new(&[0]).unwrap();
        let mut encer = DumpEnc::new(&[0]).unwrap();
        let mut user_fieldser = DumpThrasher::new(&[0]).unwrap();

        let mut nanoser = DumpNonser::new(&[0]).unwrap();

        let ttl_struct = Ttl {
            ttl_max: 200,
            ttl_edit: -73,
            ttl_start: 100,
            forced_pruning: false,
        };

        let fields = vec![
            //PackFields::Len(2),
            //PackFields::UserField(1),
            PackFields::Counter(4),
            //PackFields::IdSender(1),
            //PackFields::IdReceiver(1),
            //PackFields::UserField(1),
            //PackFields::HeadCRC(2),
            //PackFields::TrickyByte,
            //PackFields::UserField(1),
            //PackFields::Nonce(1),
            //PackFields::TTL(1),
            //PackFields::UserField(1),
            //PackFields::IdConnect(1),
        ];

        let topology = PackTopology::new(10, &fields, true, false).unwrap();

        let one_gb = 1 << 30;
        let pack_len = 26;
        for all_it in 0..one_gb / pack_len {
            let mut pack = vec![0x11; pack_len];

            init_all_pack_to_send(
                &mut pack[..],
                &topology,
                &(all_it as u64),
                &PackType::Data,
                &ids_get_s(true, true, MyRole::Initiator),
                Some(123),
                Some((&ttl_struct, false)),
                Some(&mut nanoser),
                Some(&mut crcer),
                Some(&mut user_fieldser),
                &mut encer,
                &50000,
            )
            .unwrap();
        }
    }

    /// Returns a tuple of nine option arrays for packet field combinations:
    /// 0: pack_ctr_options - [Vec<PackFields>; 2] (Counter(8), Counter(1))
    /// 1: len_options - [Vec<PackFields>; 2] (Len(4), empty)
    /// 2: id_connect_options - [Vec<PackFields>; 2] (IdConnect(7), empty)
    /// 3: user_fields_options - [(Vec<PackFields>, bool); 6] (UserField variants with
    /// false/true) 4: nonce_options - [(Vec<PackFields>, bool); 4] (Nonce(20) and
    /// empty, each with false/true) 5: sr_options - [(Vec<PackFields>, bool); 4]
    /// (IdSender+IdReceiver and empty, each with false/true) 6: crc_options -
    /// [(Vec<PackFields>, bool); 4] (HeadCRC(4) and empty, each with false/true)
    /// 7: tricky_byte_options - [(Vec<PackFields>, bool); 4] (TrickyByte and empty, each
    /// with false/true) 8: ttl_options - [(Vec<PackFields>, bool); 4] (TTL(3) and
    /// empty, each with false/true)
    fn get_options1() -> (
        [Vec<PackFields>; 2],         // pack_ctr_options
        [Vec<PackFields>; 2],         // len_options
        [(Vec<PackFields>, bool); 3], // id_connect_options
        [(Vec<PackFields>, bool); 5], // user_fields_options
        [(Vec<PackFields>, bool); 3], // nonce_options
        [(Vec<PackFields>, bool); 3], // sr_options
        [(Vec<PackFields>, bool); 3], // crc_options
        [(Vec<PackFields>, bool); 3], // tricky_byte_options
        [(Vec<PackFields>, bool); 3], // ttl_options
    ) {
        (
            // pack_ctr_options
            [vec![PackFields::Counter(8)], vec![PackFields::Counter(1)]],
            // len_options
            [vec![PackFields::Len(4)], vec![]],
            // id_connect_options
            [
                (vec![PackFields::IdConnect(7)], true),
                (vec![PackFields::IdConnect(7)], false),
                (vec![], false),
            ],
            // user_fields_options
            [
                (vec![PackFields::UserField(1)], false),
                (vec![PackFields::UserField(1)], true),
                (
                    vec![
                        PackFields::UserField(14),
                        PackFields::UserField(6),
                        PackFields::UserField(65),
                    ],
                    false,
                ),
                (
                    vec![
                        PackFields::UserField(14),
                        PackFields::UserField(6),
                        PackFields::UserField(65),
                    ],
                    true,
                ),
                (vec![], false),
            ],
            // nonce_options
            [
                (vec![PackFields::Nonce(20)], false),
                (vec![PackFields::Nonce(20)], true),
                (vec![], false),
            ],
            // sr_options
            [
                (
                    vec![PackFields::IdSender(6), PackFields::IdReceiver(6)],
                    false,
                ),
                (
                    vec![PackFields::IdSender(6), PackFields::IdReceiver(6)],
                    true,
                ),
                (vec![], false),
            ],
            // crc_options
            [
                (vec![PackFields::HeadCRC(4)], false),
                (vec![PackFields::HeadCRC(4)], true),
                (vec![], false),
            ],
            // tricky_byte_options
            [
                (vec![PackFields::TrickyByte], false),
                (vec![PackFields::TrickyByte], true),
                (vec![], false),
            ],
            // ttl_options
            [
                (vec![PackFields::TTL(3)], false),
                (vec![PackFields::TTL(3)], true),
                (vec![], false),
            ],
        )
    }

    /// all, m+ sr, m+coon , only metall
    fn ids_get(id_coon: bool, id_sr: bool, p: MyRole) -> Identified {
        Identified {
            my_metall_id: 45654654,
            my_s_r_id: if id_sr {
                Some(Ids {
                    id_sender: 1111111,
                    id_receiver: 2222222,
                })
            } else {
                None
            },
            id_conn: if id_coon { Some((33333, p)) } else { None },
        }
    }
}
