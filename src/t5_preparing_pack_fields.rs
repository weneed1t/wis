#![deny(clippy::as_conversions)]
use crate::checked_cast;
use crate::t0pology::*;
use crate::t1fields::{
    get_id_conn, get_id_sender_and_recv, get_len, get_tricky_byte, get_ttl, set_counter,
    set_get_head_crc, set_id_conn, set_id_sender_and_recv, set_len, set_ttl, set_user_field,
};
use crate::wt1types::{Crcser, EncWis, Identified, Ids, Noncer, PackType, Thrasher, Ttl, WTypeErr};

const FBACK_START_CTR: u64 = 1;
const DATA_START_CTR: u64 = 0;

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

pub fn init_all_pack_to_send<Tenc: EncWis, Tnoncer: Noncer, Tcrc: Crcser, Trshr: Thrasher>(
    pack: &mut [u8],
    topology: &PackTopology,
    ctr: &u64,
    pack_type: &PackType,
    all_id: &Identified,
    _tricky_byte: Option<u8>,
    ttl: Option<(&Ttl, bool)>,
    _nonce_gener: Option<&mut Tnoncer>,
    _crc: Option<&mut Tcrc>,
    trash_gener: Option<&mut Trshr>,
    _enc_struct: &Tenc,
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
            );

            Ok(())
        };

        set_user_field(pack, topology, *ctr, pack.len(), lbo)?;
    }

    Ok(())
}

#[cfg(test)]
mod test_get_all_pub_info_of_package {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]

    use super::*;
    use crate::t1dumps_struct::DumpCrcser;
    use crate::t1fields::{set_id_conn, set_id_sender_and_recv, set_len, set_tricky_byte, set_ttl};
    use crate::wt1types::MyRole;
    #[test]
    #[allow(clippy::len_zero)]
    fn t1_get_set_pack_pube() {
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
}
