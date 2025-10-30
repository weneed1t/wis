use crate::t1fields;
use crate::t1pology;
use std::collections::HashMap;
pub struct PackGener {}

impl PackGener {
    pub fn recv(
        pack: &mut [u8],
        topology: &t1pology::PackTopology,
        head_crc: &Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
        nonce_gener: &Option<fn(&mut [u8]) -> Result<(), &'static str>>,
        field_gen: &Option<fn(&mut [u8], u64, usize) -> Result<(), &'static str>>,
    ) -> Result<bool, &'static str> {
        if topology.head_crc_slice().is_some() {
            let crc_fn = head_crc.as_ref().expect(
            "The topology definitely has a head_crc field, but in head_crc: &Option<fn> == None",
        );

            // t1fields::set_get_head_crc(false, pack, topology, *crc_fn)?;
        }

        Ok(true)
    }
}
