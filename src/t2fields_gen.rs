use crate::t1fields;
use crate::t1pology;
use std::collections::HashMap;
pub struct PackGener {}

impl PackGener {
    pub fn recv<Cry: t1fields::EncWis>(
        im_initiator: bool,
        metal_interface_id: u64,
        mtu: usize,
        pack: &mut [u8],
        topology: &t1pology::PackTopology,
        head_crc: &Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
        cryptor: &Cry,
        nonce_gener: &Option<fn(&mut [u8]) -> Result<(), &'static str>>,
        //field_gen: &Option<fn(&mut [u8], u64, usize) -> Result<(), &'static str>>,
    ) -> Result<bool, t1fields::WTypeErr> {
        if topology.head_crc_slice().is_some() {
            let crc_fn = head_crc.as_ref().expect(
            "The topology definitely has a head_crc field, but in head_crc: &Option<fn> == None");

            if !t1fields::set_get_head_crc(false, pack, topology, *crc_fn)? {
                return Err(t1fields::WTypeErr::PackageDamaged(
                    "head damaget, head_crc non valid",
                ));
            }
        }

        let pack_slise = if topology.len_slice().is_some() {
            let le = t1fields::get_len(pack, topology)?;
            if le > mtu {
                return Err(t1fields::WTypeErr::LenSizeErr(
                    "len in paclage len slise > mtu",
                ));
            }
            &mut pack[..le]
        } else {
            pack
        };

        Ok(true)
    }
}
