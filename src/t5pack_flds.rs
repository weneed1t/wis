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

use crate::t0pology::*;
use crate::t1fields::*;
use crate::w1types::{
    Crcser, Cryptlag, EncWis, EndCryptStuctor, HeadByteStruct, Identified, Ids, Noncer, PackType,
    Thrasher, Ttl, WTypeErr,
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
        let lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), String> {
            chrss.gen_crc(da1ta, out)?;

            Ok(())
        };

        if !set_get_head_crc(false, pack, topology, lbo)? {
            return Err(WTypeErr::PackageDamaged(
                "head crc is incorrect".to_string(),
            ));
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
    //
    //TTL
    let my_ttl = if topology.ttl_slice().is_some() {
        //if ttl == some / else = err
        if let Some(ttl_main) = ttl {
            //ttl_main.1 = true get and edit ttl / ttl_main.1 = false only get ttl
            if ttl_main.1 {
                Some(set_ttl(
                    pack, topology, ttl_main.0, false, // ttl is no start
                )?)
            } else {
                Some(get_ttl(pack, topology, ttl_main.0)?)
            }
        } else {
            return Err(WTypeErr::CompileFieldsErr(
                "topology.ttl_slice().is_some() but ttl.is_none()".to_string(),
            ));
        }
    } else {
        None
    };

    let my_tricky = if topology.tricky_byte().is_some() {
        //TrickyByte
        Some(get_tricky_byte(pack, topology)?)
    } else {
        None
    };

    Ok((
        ids_mys,
        len_of_pack,
        my_ttl,
        my_tricky,
        pack.get_mut(..len_of_pack).ok_or(WTypeErr::PackageDamaged(
            "impossible state since here len_of_pack should indicate the length of the packet and \
             should be checked before being used"
                .to_string(),
        ))?,
    ))
}

///Writing code in rust is something only fags and niggers like. ;)
///Because of the mut limit,
///  it's impossible to write code properly.
///  If you want, go ahead and submit a commit to fix it
///  I don't give a shit, I'm killing people.
#[derive(Debug, Clone)]
pub struct MutCockSuck<
    Tnoncer: Noncer,
    Tcrc: Crcser,
    Trshr: Thrasher<FuserLogicBuf>,
    FuserLogicBuf,
    Endcpt: EndCryptStuctor,
> {
    ///nonce_gener
    pub nonce_gener: Option<Tnoncer>,
    ///user_field_gener
    pub user_field_gener: Option<Trshr>,
    ///crc_gener
    pub crc_gener: Option<Tcrc>,
    /// user_buf
    pub user_buf: Option<FuserLogicBuf>,
    pub end_key: Option<Endcpt>,
}

///general
#[allow(clippy::too_many_arguments)]
pub fn init_all_pack_to_send<
    Tenc: EncWis<Endcpt>,
    Tnoncer: Noncer,
    Tcrc: Crcser,
    Trshr: Thrasher<FuserLogicBuf>,
    FuserLogicBuf,
    Endcpt: EndCryptStuctor + Clone,
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
    fuck_mut: &mut MutCockSuck<Tnoncer, Tcrc, Trshr, FuserLogicBuf, Endcpt>,
) -> Result<(), WTypeErr>
where
{
    set_headbyte(pack, topology, head_byte)?;

    //
    //idi:
    {
        if topology.idconn_slice().is_some() {
            let (id_conn, role) = all_id.id_conn.as_ref().ok_or(WTypeErr::CompileFieldsErr(
                "Identified::id connect is none".to_string(),
            ))?;

            set_id_conn(pack, topology, id_conn, role)?;
        }

        if topology.id_of_sender_slice().is_some() {
            let id_s_r = all_id.my_s_r_id.as_ref().ok_or(WTypeErr::CompileFieldsErr(
                "Identified::Ids is none".to_string(),
            ))?;
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
            "topology.ttl_slice().is_some() but ttl.is_none()".to_string(),
        ))?;

        set_ttl(
            pack,
            topology,
            &ttl_main.0,
            true, //is ttl start
        )?;
    }

    // user fields
    if topology.trash_content_slice().is_some() {
        let trasher = fuck_mut
            .user_field_gener
            .as_mut()
            .ok_or(WTypeErr::CompileFieldsErr(
                "trash_gener is none but topology.trash_content_slice().is_some()".to_string(),
            ))?;

        // Ensure the original buffer is mutable so we can perform zero-cost reborrows sequentially
        let user_logic_buffer = &mut fuck_mut.user_buf;
        // Mark the closure as mutable (FnMut) since it mutates its captured environment on each call
        let mut lbo = |fieldt_to_fill: &mut [u8],
                       ctr_pack: &u64,
                       len_of_pack: &usize,
                       ctr_field_in_pack: &usize,
                       topolog_y: &PackTopology|
         -> Result<(), String> {
            trasher.set_user_field(
                fieldt_to_fill,
                ctr_pack,
                len_of_pack,
                ctr_field_in_pack,
                topolog_y,
                // Reborrow the mutable reference for the inner function call
                user_logic_buffer.as_mut(),
            )
        };

        // Pass the closure as a mutable reference if required by the FnMut trait bound
        set_user_field(pack, topology, ctr, &pack.len(), &mut lbo)?;
    }

    //set_tricky_byte
    if topology.tricky_byte().is_some() {
        set_tricky_byte(
            pack,
            topology,
            tricky_byte.ok_or(WTypeErr::CompileFieldsErr(
                "topology.tricky_byte().is_some() but tricky_byte is none".to_string(),
            ))?, // Reborrow the original buffer here, as it was never consumed or moved by the previous block
        )?
    }

    //crypt
    crypt(
        pack,
        topology,
        Cryptlag::Encrypt,
        encrypt,
        Some(ctr),
        fuck_mut.nonce_gener.as_mut(),
    )?;

    if topology.head_crc_slice().is_some() {
        let crcer = fuck_mut
            .crc_gener
            .as_mut()
            .ok_or(WTypeErr::CompileFieldsErr(
                "topology.head_crc_slice().is_some()  but crc is none".to_string(),
            ))?;

        let lbo = |head: &[u8], crc_slice: &mut [u8]| -> Result<(), String> {
            crcer.gen_crc(head, crc_slice)
        };

        set_get_head_crc(true, pack, topology, lbo)?;
    }

    Ok(())
}
