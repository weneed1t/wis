/*use crate::t1pology::PackTopology;
use crate::t1queue_tcpudp::recv_queue::{WSTcpLike, WSUdpLike};

enum Wtype {
    WTCP(WSTcpLike),
    WUDP(WSUdpLike<Box<[u8]>>),
}

pub struct WQueue {
    pack_topology: PackTopology,
    my_type_like: Wtype,
    mtu: usize,
    counter_of_last_stream_paskage: usize,
    crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
}

impl WQueue {
    pub fn new_as_tcp(
        pack_topology: PackTopology,
        mtu: usize,
        crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    ) -> Result<Self, &'static str> {
        Ok(Self::universal_construct(
            Wtype::WTCP(WSTcpLike::new(mtu, pack_topology, crcfn)?),
            mtu,
            pack_topology,
            crcfn,
        ))
    }

    pub fn new_as_udp(
        pack_topology: PackTopology,
        mtu: usize,
        sizecap: usize,
        crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    ) -> Result<Self, &'static str> {
        Ok(Self::universal_construct(
            Wtype::WUDP(WSUdpLike::new(sizecap)?),
            mtu,
            pack_topology,
            crcfn,
        ))
    }

    fn universal_construct(
        my_type_like: Wtype,
        mtu: usize,
        pack_topology: PackTopology,
        crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    ) -> Self {
        Self {
            pack_topology,
            my_type_like,
            mtu,
            counter_of_last_stream_paskage: 0,
            crcfn,
        }
    }

    fn pack_info_get(&self) {}

    pub fn as_udp(
        &mut self,
        pack: &Box<[u8]>,
        metal_in_and_sender_id: Option<(u64, u64)>,
    ) -> Result<Self, &'static str> {
        match &mut self.my_type_like {
            Wtype::WUDP(x) => {
                // x.insert(pack);
            }
            _ => {
                return Err("my type is not udp like");
            }
        }
        Err("")
    }
    pub fn as_tcp(
        &mut self,
        pack: &Box<[u8]>,
        metal_in_and_sender_id: Option<(u64, u64)>,
    ) -> Result<Self, &'static str> {
        match &mut self.my_type_like {
            Wtype::WTCP(x) => {
                x.buf_in(pack)?;
            }
            _ => {
                return Err("my type is not tcp like");
            }
        }

        Err("")
    }
}

*/
