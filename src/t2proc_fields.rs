use core::task;
use std::f32::consts::E;
use std::thread::panicking;

use crate::t1pology::PackTopology;

use crate::t4_connect_data;

use crate::t1fields;

/*

    IdOfSender(usize),
    IdReceiver(usize),
    Len(usize),
    Counter(usize),
    UserField(usize),
    HeadCRC(usize),
    TTL(usize),
    Nonce(usize),
    IdConnect(usize),

*/

pub enum WsOk {
    IsMyPackage,
    IsNotMyPackage,
}

pub enum WsErr {
    IncorrectPackLen,
    IncorrectCrcSum,
    DecryptErr,
    AnyErr(&'static str),
}

pub trait WsConnectStorager<Tudp, Twait, Tencrypt: t1fields::EncWis> {
    fn checking_if_is_my_pack(
        fn_if_is_my_pack: fn(
            &mut t4_connect_data::WsConnectData<Tudp, Twait, Tencrypt>,
            u64,
            usize,
        ) -> Result<(), WsErr>,
    ) -> Result<(), WsErr>;
}

pub struct Ids {
    pub id_sender: u64,
    pub id_receiver: u64,
}
pub struct IdConn {
    pub id_conn: u64,
    pub pack_from_why: bool,
}

///The UserField and Nonce fields are deliberately omitted here so as not to tempt users to enter sensitive data in these fields,
///  since Nonce is an entropy field that is only needed for encryption.
///The UserField field can only contain gibberish and 0% useful information.
pub struct WsPubFields {
    pub my_len: Option<usize>,
    pub my_rs_id: Option<Ids>,
    pub my_idconn: Option<IdConn>,
    pub my_ttl: Option<u64>,
    pub my_ctr: u64,
    pub is_fback: bool,
}

pub fn get_public_fields<
    Tudp,
    Twait,
    Tencrypt: t1fields::EncWis,
    T: WsConnectStorager<Tudp, Twait, Tencrypt>,
>(
    metal_id: u64,
    storager: &mut T,
    topology: &PackTopology,
    pack: &mut [u8],
    crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    allowed_trash_at_end_package: bool,
) -> Result<WsOk, t1fields::WTypeErr> {
    if pack.len() < topology.total_minimal_len() {
        return Err(t1fields::WTypeErr::LenSizeErr(
            "pack.len() < topology.total_minimal_len()",
        ));
    }

    if topology.head_crc_slice().is_some() {
        if !t1fields::set_get_head_crc(
            false,
            pack,
            topology,
            crcfn.expect("topology: &PackTopology has a field but crcfn == None"),
        )? {
            return Err(t1fields::WTypeErr::PackageDamaged(
                "crc summ does not match",
            ));
        };
    }

    let pack = if topology.len_slice().is_some() {
        let size_pack = t1fields::get_len(pack, topology)?;

        if (!allowed_trash_at_end_package) && (size_pack != pack.len()) {
            return Err(t1fields::WTypeErr::LenSizeErr("allowed_trash_at_end_package is set to false, but the value in the length field does not match the true length pack: &mut [u8]"));
        }
        if size_pack > pack.len() {
            return Err(t1fields::WTypeErr::LenSizeErr("value in the length field is GREATER than the actual length of the pack: &mut [u8], packet is corrupted"));
        }

        &mut pack[..size_pack] //new truncated packet
    } else {
        pack
    };

    let (sender, receiver) = t1fields::get_id_sender_and_recv(pack, topology)?;
    let (id_conn, id_conn_from_why) = t1fields::get_id_conn(pack, topology)?;

    //EEEDET
    Ok(WsOk::IsMyPackage)
}

//trait  {

//}
