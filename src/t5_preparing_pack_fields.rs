use std::usize;

use crate::t0pology::*;
use crate::t1fields::{
    get_id_conn, get_id_sender_and_recv, get_len, get_tricky_byte, get_ttl, set_counter,
    set_get_head_crc, set_id_conn, set_id_sender_and_recv, set_len, set_ttl,
};
use crate::wt1types::{Cfcser, MyRole, PackType, WTypeErr};

#[derive(Clone, Debug)]
///all id
pub struct Identified {
    ///The identifier of a specific device—it doesn't really matter what this value is,
    ///  since it's just for the user's convenience and isn't passed on when the device is
    /// transferred;  it could be a TCP port number or a physical address.
    pub my_metall_id: u64,
    /// reed Ids doc
    pub my_s_r_id: Option<Ids>,
    ///identifier  connection role + value id
    pub id_conn: Option<(u64, MyRole)>,
}

const FBACK_START_CTR: u64 = 1;
const DATA_START_CTR: u64 = 0;
#[derive(Clone, Debug)]
///id sender and recv
pub struct Ids {
    ///
    pub id_sender: u64,
    ///
    pub id_receiver: u64,
}
/// ttl max, ttl start, ttl edit
#[derive(Clone, Debug)]
pub struct TTL {
    ttl_max: u64,
    ttl_edit: i64,
    ttl_start: bool,
    forced_pruning: bool,
}

///check crc + get idc/ids/idr + get len + get TrickyByte
pub fn get_all_pub_info_of_package<'a, Tcrc>(
    metal_id: u64,
    pack: &'a mut [u8],
    topology: &PackTopology,
    check_head_crc_if_pack_not_from_tls_like_queue: Option<&mut Tcrc>,
    ttl: Option<(&TTL, bool)>,
) -> Result<(Identified, usize, Option<u64>, Option<u8>, &'a mut [u8]), WTypeErr>
where
    Tcrc: Cfcser,
{
    // HEAR CRC
    //

    if let Some(chrss) = check_head_crc_if_pack_not_from_tls_like_queue {
        let lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), &'static str> {
            chrss.gen_crc(da1ta, out)?;
            Ok(())
        };

        set_get_head_crc(false, pack, topology, lbo)?;
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
                        ttl_main.0.ttl_start,
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
        pack.get_mut(..len_of_pack).expect(
            "impossible state since here len_of_pack should indicate the length of the packet and \
             should be checked before being used",
        ),
    ))
}

pub fn init_all_pack_to_send(
    pack: &mut [u8],
    topology: &PackTopology,
    ctr: &u64,
    my_type: &PackType,
    all_id: &Identified,
    _crc: Option<bool>,
    _nonce: Option<bool>,
    _tricky_byte: Option<u8>,
    ttl: Option<(&TTL, bool)>,
    _crypter: bool,
    mtu: &usize,
) -> Result<(), WTypeErr> {
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
        set_counter(pack, topology, ctr, my_type)?;
    }
    //ttl
    //if ttl == some / else = err
    if let Some(ttl_main) = ttl {
        set_ttl(
            pack,
            topology,
            &ttl_main.0.ttl_edit,
            &ttl_main.0.ttl_max,
            ttl_main.0.ttl_start,
            ttl_main.0.forced_pruning,
        )?;
    } else {
        return Err(WTypeErr::CompileFieldsErr(
            "topology.ttl_slice().is_some() but ttl.is_none()",
        ));
    }

    Ok(())
}
/*
#[cfg(test)]
mod test_get_all_pub_info_of_package {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::t1dumps_struct::DumpCfcser;
    use crate::t1fields::{set_id_conn, set_id_sender_and_recv, set_len, set_tricky_byte, set_ttl};
    #[test]
    #[allow(clippy::len_zero)]
    fn t1() {
        let fields = vec![PackFields::Counter(3)];

        for a_len in [vec![PackFields::Len(4)], vec![]] {
            for a_sr in [
                vec![PackFields::IdSender(6), PackFields::IdReceiver(6)],
                vec![],
            ] {
                for a_crc in [vec![PackFields::HeadCRC(4)], vec![]] {
                    for a_tb in [vec![PackFields::TrickyByte], vec![]] {
                        for a_ttl in [vec![PackFields::TTL(3)], vec![]] {
                            for a_idc in [vec![PackFields::IdConnect(7)], vec![]] {
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

                                //println!("{:?}", fields);

                                let mut pack = vec![0; 100];

                                let topology = PackTopology::new(5, &fields, true, false).unwrap();
                                //
                                //
                                //
                                //
                                //
                                if a_len.len() > 0 {
                                    set_len(&mut pack[..90], &topology, &1000).unwrap();
                                }
                                if a_sr.len() > 0 {
                                    set_id_sender_and_recv(&mut pack, &topology, &7890, &123456)
                                        .unwrap();
                                }
                                if a_ttl.len() > 0 {
                                    set_ttl(&mut pack, &topology, 100, 200, true).unwrap();
                                }
                                if a_idc.len() > 0 {
                                    set_id_conn(&mut pack, &topology, &3213, &MyRole::Passive)
                                        .unwrap();
                                }
                                if a_tb.len() > 0 {
                                    set_tricky_byte(&mut pack, &topology, 123).unwrap();
                                }
                                //
                                //
                                //
                                //
                                //
                                let mut pa_2 = pack.clone();
                                let omygood = &get_all_pub_info_of_package(
                                    1337,
                                    &mut pa_2[..],
                                    &topology,
                                    Some(&mut DumpCfcser::new(&[0]).unwrap()),
                                );

                                if a_crc.len() == 0 {
                                    let t = omygood.as_ref().unwrap_err();
                                    assert_eq!(
                                        *t,
                                        WTypeErr::CompileFieldsErr(
                                            "head_crc_slice not in PackTopology"
                                        )
                                    );
                                } else {
                                    let orew = omygood.as_ref().unwrap();

                                    if a_len.len() > 0 {
                                        assert_eq!(orew.1, 90);
                                    } else {
                                        assert_eq!(orew.1, 100);
                                    }

                                    if a_sr.len() > 0 {
                                        let ids = orew.0.my_s_r_id.as_ref().unwrap();
                                        let rr = ids.id_receiver;
                                        let ss = ids.id_sender;

                                        assert_eq!(rr, 123456);
                                        assert_eq!(ss, 7890);
                                    } else {
                                        assert!(orew.0.my_s_r_id.is_none());
                                    }
                                    //
                                    //
                                    if a_idc.len() > 0 {
                                        assert_eq!(
                                            get_id_conn(&pack, &topology).unwrap(),
                                            *orew.0.id_conn.as_ref().unwrap()
                                        );
                                    } else {
                                        assert!(get_id_conn(&pack, &topology).is_err());
                                        assert!(orew.0.id_conn.as_ref().is_none());
                                    }
                                    //
                                    //

                                    if a_ttl.len() > 0 {
                                        assert_eq!(
                                            get_ttl(&pack, &topology).unwrap(),
                                            *orew.2.as_ref().unwrap()
                                        );

                                        assert_eq!(get_ttl(&pack, &topology).unwrap(), 100);
                                    } else {
                                        assert!(get_ttl(&pack, &topology).is_err());
                                        assert!(orew.2.as_ref().is_none());
                                    }
                                    //
                                    //

                                    if a_tb.len() > 0 {
                                        assert_eq!(
                                            get_tricky_byte(&pack, &topology).unwrap(),
                                            *orew.3.as_ref().unwrap()
                                        );
                                        assert_eq!(get_tricky_byte(&pack, &topology).unwrap(), 123);
                                    } else {
                                        assert!(get_tricky_byte(&pack, &topology).is_err());
                                        assert!(orew.3.as_ref().is_none());
                                    }

                                    println!("{:?}", omygood);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
*/
