use crate::t1fields;
use crate::t1pology::PackTopology;

pub struct WStcplike {
    elems_in_buf: usize,
    u_buf: Box<[u8]>,
    pack_topology: PackTopology,
    mtu: usize,
    crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
}

impl WStcplike {
    pub fn new(
        mtu: usize,
        pack_topology: PackTopology,
        crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    ) -> Result<Self, &'static str> {
        if pack_topology.len_slice().is_none() {
            return Err("pack_topology.len_slice() is none");
        }

        Ok(Self {
            elems_in_buf: 0,
            u_buf: vec![0; mtu].into_boxed_slice(),
            pack_topology,
            mtu,
            crcfn,
        })
    }

    pub fn buf_in(&mut self, data: &[u8]) -> Result<Box<[Box<[u8]>]>, &'static str> {
        let _ = self
            .pack_topology
            .len_slice()
            .ok_or("pack_topology.len_slice() is none");

        if self.u_buf.len() < self.mtu {
            return Err("u_buf.len() wanna be >= of mtu");
        }

        let min_len = self.pack_topology.total_minimal_len();
        let mut ret_paks: Vec<Box<[u8]>> = Vec::with_capacity(20);
        let mut pos_in_data = 0;
        //println!("\n__len pf p {}\n", data.len());

        while pos_in_data < data.len() {
            // check. choosing the shorter length.
            // since there are two stores, 1 is the amount of free space in the buffer,
            // 2 is the number of elements that need to be processed in data[].
            // a lower value is selected and as many elements are copied from data to the buffer.
            // elems_in_buf means how many elements are in
            // the buffer and u_buf.len()-elems_in_buf means how much free space is in the buffer.
            // data.len()-pos_in_data means how many elements are left in the data.
            //pos_in_data and elems_in_buf are offsets for u_buf and data[], respectively.
            let copy_elems_to_buf = {
                let buf_void = self
                    .u_buf
                    .len()
                    .checked_sub(self.elems_in_buf)
                    .ok_or("err in u_buf.len() sub elems_in_buf <0")?;

                let data_elems = data
                    .len()
                    .checked_sub(pos_in_data)
                    .ok_or("err data.len() sub pos_in_data >0")?;

                if buf_void < data_elems {
                    buf_void
                } else {
                    data_elems
                }
            };
            //if the elements in data[] have run out, then exit the loop
            if copy_elems_to_buf == 0 {
                break;
            }
            //copying copy_elems_to_buf from data to a buffer using offsets
            self.u_buf[self.elems_in_buf..self.elems_in_buf + copy_elems_to_buf]
                .copy_from_slice(&data[pos_in_data..pos_in_data + copy_elems_to_buf]);

            //Updating offsets to copy_elems_to_buf value
            self.elems_in_buf = self
                .elems_in_buf
                .checked_add(copy_elems_to_buf)
                .ok_or("err elems_in_buf add= copy_elems_to_buf")?;
            pos_in_data = pos_in_data
                .checked_add(copy_elems_to_buf)
                .ok_or("err in pos_in_data + opy_elems_to_buf")?;

            let mut ptr_to_start = 0;
            let mut old_ret_pos: usize = 0;
            while ptr_to_start < self.elems_in_buf {
                let elem_in_buf_quque = self
                    .elems_in_buf
                    .checked_sub(ptr_to_start)
                    .ok_or("err elems_in_buf sub ptr_to_start")?;

                //if the length of the data in the buffer is greater than the minimum packet size,
                // it means that you can read the packet length fields to find out its end.
                if elem_in_buf_quque >= min_len {
                    //if the package has a crc signature of the head data,
                    // then it must be checked. if the data is intact, add it to ret_paks
                    if self.pack_topology.head_crc_slice().is_some() {
                        if !t1fields::set_get_head_crc(
                            false,
                            &mut self.u_buf[ptr_to_start..],
                            &self.pack_topology,
                            self.crcfn.ok_or("crcfn is none")?,
                        )? {
                            return Err("package is damaged");
                        }
                    }

                    //getting the length of the packet from the length field in the packet.
                    let len_of_curent_pack =
                        t1fields::get_len(&self.u_buf[ptr_to_start..], &self.pack_topology)?;
                    //if the length value in the length field is greater than MTU,
                    // then the packet is corrupted, an error is caused.
                    if len_of_curent_pack > self.mtu {
                        return Err("len_of_curent_pack > mtu");
                    }
                    //if the value of the length field is correct,
                    //but in the raw data buffer it is less than the length from the length field,
                    //then the packet has not arrived in its entirety,
                    //and you need to wait until the packet arrives in its entirety.
                    if elem_in_buf_quque >= len_of_curent_pack {
                        //current package is a full in buf
                        ptr_to_start += len_of_curent_pack;
                    } else {
                        break;
                    }
                    ret_paks.push(
                        self.u_buf[old_ret_pos..ptr_to_start]
                            .to_vec()
                            .into_boxed_slice(),
                    );
                    old_ret_pos = ptr_to_start;
                } else {
                    break;
                };
            }
            //shifting elements that have already been processed and added to ret_paks
            self.u_buf[0..self.elems_in_buf].rotate_left(ptr_to_start);
            //position changes so that the beginning is there, and the last raw element
            self.elems_in_buf = self
                .elems_in_buf
                .checked_sub(ptr_to_start)
                .ok_or("err elems_in_buf sub= ptr_to_start")?;
        }

        Ok(ret_paks.into_boxed_slice())
        //Err("")
    }
}
#[cfg_attr(test, derive(Debug))]
pub enum WSQueueState {
    ElemIdIsBig,
    ElemIdIsSmall,
    ElemIsAlreadyIn,
    SuccessfulInsertion,
}

impl PartialEq for WSQueueState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (WSQueueState::ElemIdIsBig, WSQueueState::ElemIdIsBig) => true,
            (WSQueueState::ElemIdIsSmall, WSQueueState::ElemIdIsSmall) => true,
            (WSQueueState::ElemIsAlreadyIn, WSQueueState::ElemIsAlreadyIn) => true,
            (WSQueueState::SuccessfulInsertion, WSQueueState::SuccessfulInsertion) => true,
            _ => false,
        }
    }
}

pub struct WSUdplike<T> {
    in_queue: usize,
    k_mod: usize,
    last_give_num: usize,
    data: Box<[Option<(usize, T)>]>,
    was_get_queue: bool,
}

impl<T: Clone> WSUdplike<T> {
    pub fn new(sizecap: usize) -> Result<Self, &'static str> {
        if sizecap == 0 {
            return Err("sizecap must be greater than zero");
        }
        Ok(Self {
            in_queue: 0,
            k_mod: 0,
            last_give_num: 0,
            data: vec![None; sizecap].into_boxed_slice(),
            was_get_queue: false,
        })
    }

    pub fn insert(&mut self, item: (usize, T)) -> WSQueueState {
        if item.0 < self.last_give_num {
            return WSQueueState::ElemIdIsSmall;
        }

        let pos = (item.0 - self.last_give_num) - self.was_get_queue as usize;

        if pos >= self.data.len() {
            return WSQueueState::ElemIdIsBig;
        }

        let elem_url = &mut self.data[(pos + self.k_mod) % self.data.len()];

        if elem_url.is_some() {
            return WSQueueState::ElemIsAlreadyIn;
        }

        *elem_url = Some(item);

        self.in_queue += 1;

        WSQueueState::SuccessfulInsertion
    }

    fn k_add(&mut self, addin: usize) {
        self.k_mod = (self.k_mod + addin) % self.data.len();
    }

    fn edit_my_state(&mut self, size_of_ret: usize, last_item_num: usize) {
        let le = self.data.len();
        for x in self.k_mod..size_of_ret + self.k_mod {
            self.data[x % le] = None;
        }

        self.in_queue = match self.in_queue.checked_sub(size_of_ret) {
            Some(new_in) => new_in,
            None => {
                panic!(
                    r#"fatal error in pub fn get_queue().
                       function pub fn get_queue wants to
                       return more elements than it has,
                       can't be handled via Result<>, Sorry~~"#
                );
            }
        };

        self.k_add(size_of_ret);

        self.last_give_num = last_item_num;
    }

    pub fn get_queue(&mut self) -> Box<[(usize, T)]> {
        let copied_slice: Box<[(usize, T)]> = self
            .data
            .iter()
            .cycle()
            .skip(self.k_mod)
            .take(self.data.len())
            .take_while(|opt| opt.is_some())
            .map(|opt| opt.as_ref().unwrap().clone())
            .collect::<Vec<_>>()
            .into_boxed_slice();

        self.edit_my_state(
            copied_slice.len(),
            match copied_slice.last() {
                Some(x) => x.0,

                _ => {
                    return vec![].into_boxed_slice();
                }
            },
        );

        self.was_get_queue = true;

        copied_slice
    }

    pub fn how_items_in_queue(&self) -> usize {
        self.in_queue
    }
    pub fn last_num_get(&self) -> usize {
        self.last_give_num
    }
}

#[cfg(test)]
mod tests_wtcp {

    use super::*;
    use crate::t1fields;
    use crate::t1pology::{PackTopology, PakFields};

    fn datas() -> (Vec<Vec<u8>>, Vec<u8>, Vec<usize>, Box<[u8]>, PackTopology) {
        let packet_specs = (0..100_000u64)
            .map(|x| {
                let b = 11 + ((x.wrapping_mul(347)) % 30);
                (b as u8, b as usize)
            })
            .collect::<Vec<_>>();

        let mut packets: Vec<Vec<u8>> = packet_specs
            .iter()
            .map(|&(value, len)| vec![value; len])
            .collect();

        let fields = vec![
            PakFields::Len(1),
            PakFields::IdOfSender(1),
            PakFields::IdReceiver(1),
            PakFields::Counter(1),
            PakFields::HeadCRC(3),
        ];

        let pack_topology = PackTopology::new(2, &fields, true, true).unwrap();

        let mut pkks: Vec<u8> = Vec::new();
        for mut packet in packets.iter_mut() {
            t1fields::set_get_head_crc(true, &mut packet, &pack_topology, dummy_crc_gen).unwrap();
            pkks.append(&mut packet.clone());
        }

        let buf = vec![0u8; 41].into_boxed_slice();

        let data_slises = (0..200)
            .map(|x| (x * 347 * 499 * 809) % 500 as usize)
            .collect::<Vec<usize>>();

        //let mut data_slises = data_slises.iter().cycle();

        (packets, pkks, data_slises, buf, pack_topology)
    }

    #[test]
    fn test_bufpack() {
        let datas_x = datas();

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();

        let mut w_tcp = WStcplike::new(41, datas_x.4, Some(dummy_crc_gen)).unwrap();
        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;
            let ret = w_tcp.buf_in(&data.into_boxed_slice()).unwrap();

            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                // println!("{:?}", i);
            }
        }
    }
    #[test]
    fn test_bufpack_err_len_mtu() {
        let datas_x = datas();

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();

        let mut w_tcp = WStcplike::new(39, datas_x.4, Some(dummy_crc_gen)).unwrap();

        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;

            let ret = w_tcp.buf_in(&data.into_boxed_slice());
            if ret.is_err() {
                assert_eq!(ret, Err("len_of_curent_pack > mtu"));
                return;
            }
            let ret = ret.unwrap();
            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                // println!("{:?}", i);
            }
        }
        assert!(
            false,
            "there should have been a buffer size error, but it didn't happen!"
        );
    }

    #[test]
    fn test_bufpack_package_damage() {
        let datas_x = datas();

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();
        let mut w_tcp = WStcplike::new(39, datas_x.4, Some(dummy_crc_gen)).unwrap();
        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let mut data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;

            if data.len() > 1 && index > 200 {
                data[0] = !data[0];
            }

            let ret = w_tcp.buf_in(&data.into_boxed_slice());
            if ret.is_err() {
                assert_eq!(ret, Err("package is damaged"));
                return;
            }
            let ret = ret.unwrap();
            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                //println!("{:?}", i);
            }
        }
        assert!(
            false,
            "there should have been a buffer size error, but it didn't happen!"
        );
    }

    fn dummy_crc_gen(inp: &[u8], crc: &mut [u8]) -> Result<(), &'static str> {
        if crc.len() == 0 {
            return Err("CRC  crc.len() == 0");
        }
        crc.fill(77);
        for (i, &byte) in inp.iter().enumerate() {
            for (ii, byteii) in crc.iter_mut().enumerate() {
                *byteii = byteii.wrapping_add(byte.wrapping_mul((i + 1) as u8));
                *byteii = byteii.rotate_left(ii as u32 & 0x111);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests_wudp {

    use super::*;

    #[test]
    fn test_work_subsequence() {
        let mut xx: WSUdplike<u32> = WSUdplike::new(50).unwrap();

        let mut xxx = 0_usize;
        for _ in 0..30_usize {
            for az in 0..50usize {
                let _ = xx.insert((xxx + (az + 17) % 50, 0));

                if az % 5 == 0 {
                    if xx.insert((xxx + (az + 17) % 50, 0)) != WSQueueState::ElemIsAlreadyIn {
                        assert!(false, "xx.insert != WSQueueState::ElemIsAlreadyIn")
                    }
                }

                if az % 11 == 0 && az > 60 {
                    if WSQueueState::ElemIsAlreadyIn != xx.insert((xxx + (az + 17) % 10, 0)) {
                        assert!(false, "xx.insert != WSQueueState::ElemIsAlreadyIn")
                    }
                }
            }
            xxx += 50;

            let tempo = xx.get_queue().to_vec();

            //println!("{:?}",tempo.iter().map(|x|{x.0}).collect::<Vec<usize>>());
            let mut t = tempo.first().unwrap().0;
            //println!("tempo.len() = {:?}", tempo.len());
            for l in tempo.iter().skip(1) {
                assert!(l.0 > t, "> l.0 = {} is not greater than t = {}", l.0, t);
                assert!(l.0 - 1 == t, "==tempo[{}].0 is not greater than {}", l.0, t);
                t = l.0;
                //println!("l.0 = {}", l.0);
            }
        }
    }

    #[test]
    fn test_segment() {
        let mut xx: WSUdplike<u32> = WSUdplike::new(50).unwrap();

        for x in 1..1000_usize {
            let _ = xx.insert((x - 1, 0));

            if x > 1 && x % 13 == 0 {
                let bw = xx.how_items_in_queue();

                let geu = xx.get_queue();
                assert_eq!(geu.len(), 13);
                assert_eq!(geu.len(), bw);
                //println!("geulen:{}",geu.len());
            }
        }
    }

    #[test]
    fn test_kmod() {
        let mut xx: WSUdplike<u32> = WSUdplike::new(123).unwrap();

        xx.k_mod = 100;

        xx.k_add(70);
        assert_eq!(xx.k_mod, (100 + 70) % 123);

        xx.k_add(1000);
        assert_eq!(xx.k_mod, (100 + 70 + 1000) % 123);

        xx.k_add(3);
        assert_eq!(xx.k_mod, (100 + 70 + 1000 + 3) % 123);
    }

    #[test]
    fn test_hands() {
        let mut xx: WSUdplike<f32> = WSUdplike::new(8).unwrap();

        assert_eq!(xx.insert((4, 0.0)), WSQueueState::SuccessfulInsertion); //1
        assert_eq!(xx.insert((0, 0.0)), WSQueueState::SuccessfulInsertion); //2
        assert_eq!(xx.insert((2, 0.0)), WSQueueState::SuccessfulInsertion); //3
        assert_eq!(xx.insert((3, 0.0)), WSQueueState::SuccessfulInsertion); //4
        assert_eq!(xx.insert((5, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((6, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((7, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.insert((8, 0.0)), WSQueueState::ElemIdIsBig); //8
        assert_eq!(xx.insert((3, 0.0)), WSQueueState::ElemIsAlreadyIn); //9
        assert_eq!(xx.insert((1, 0.0)), WSQueueState::SuccessfulInsertion); //10

        assert_eq!(xx.in_queue, 8);

        assert_eq!(
            xx.get_queue(),
            (vec![
                (0, 0.0),
                (1, 0.0),
                (2, 0.0),
                (3, 0.0),
                (4, 0.0),
                (5, 0.0),
                (6, 0.0),
                (7, 0.0)
            ])
            .into_boxed_slice()
        );

        assert_eq!(xx.insert((9, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((11, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((12, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

        assert_eq!(xx.insert((10, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((13, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

        assert_eq!(xx.insert((8, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(
            xx.get_queue(),
            (vec![
                (8, 0.0),
                (9, 0.0),
                (10, 0.0),
                (11, 0.0),
                (12, 0.0),
                (13, 0.0)
            ])
            .into_boxed_slice()
        );

        assert_eq!(xx.insert((22, 0.0)), WSQueueState::ElemIdIsBig);
        assert_eq!(xx.insert((21, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((2, 0.0)), WSQueueState::ElemIdIsSmall);
        assert_eq!(xx.insert((14, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.get_queue(), (vec![(14, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((15, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((16, 0.0)), WSQueueState::SuccessfulInsertion);

        assert_eq!(xx.insert((17, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((18, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((19, 0.0)), WSQueueState::SuccessfulInsertion);
        assert_eq!(xx.insert((20, 0.0)), WSQueueState::SuccessfulInsertion);

        assert_eq!(
            xx.get_queue(),
            (vec![
                (15, 0.0),
                (16, 0.0),
                (17, 0.0),
                (18, 0.0),
                (19, 0.0),
                (20, 0.0),
                (21, 0.0)
            ])
            .into_boxed_slice()
        );

        let mut xx: WSUdplike<f32> = WSUdplike::new(7).unwrap();

        assert_eq!(xx.insert((0, 0.0)), WSQueueState::SuccessfulInsertion); //1
        assert_eq!(xx.insert((1, 0.0)), WSQueueState::SuccessfulInsertion); //2
        assert_eq!(xx.insert((2, 0.0)), WSQueueState::SuccessfulInsertion); //3
        assert_eq!(xx.insert((3, 0.0)), WSQueueState::SuccessfulInsertion); //4
        assert_eq!(xx.insert((4, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((5, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((6, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.in_queue, 7);
        assert_eq!(
            xx.get_queue(),
            (vec![
                (0, 0.0),
                (1, 0.0),
                (2, 0.0),
                (3, 0.0),
                (4, 0.0),
                (5, 0.0),
                (6, 0.0)
            ])
            .into_boxed_slice()
        );

        let mut xx: WSUdplike<f32> = WSUdplike::new(7).unwrap();

        assert_eq!(xx.insert((0, 0.0)), WSQueueState::SuccessfulInsertion); //1
        assert_eq!(xx.in_queue, 1);
        assert_eq!(xx.get_queue(), (vec![(0, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((1, 0.0)), WSQueueState::SuccessfulInsertion); //2
        assert_eq!(xx.in_queue, 1);
        assert_eq!(
            xx.get_queue(),
            (vec![(1, 0.0)]).into_boxed_slice(),
            "{:?}",
            xx.data
        );

        assert_eq!(xx.insert((2, 0.0)), WSQueueState::SuccessfulInsertion); //3

        assert_eq!(xx.in_queue, 1);
        assert_eq!(xx.get_queue(), (vec![(2, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((3, 0.0)), WSQueueState::SuccessfulInsertion); //4
        assert_eq!(xx.in_queue, 1);
        assert_eq!(xx.get_queue(), (vec![(3, 0.0)]).into_boxed_slice());

        assert_eq!(xx.insert((4, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((5, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((6, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.insert((7, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((8, 0.0)), WSQueueState::SuccessfulInsertion); //6
        assert_eq!(xx.insert((9, 0.0)), WSQueueState::SuccessfulInsertion); //7
        assert_eq!(xx.insert((10, 0.0)), WSQueueState::SuccessfulInsertion); //5
        assert_eq!(xx.insert((11, 0.0)), WSQueueState::ElemIdIsBig); //6
        assert_eq!(xx.in_queue, 7);
        assert_eq!(
            xx.get_queue(),
            (vec![
                (4, 0.0),
                (5, 0.0),
                (6, 0.0),
                (7, 0.0),
                (8, 0.0),
                (9, 0.0),
                (10, 0.0)
            ])
            .into_boxed_slice()
        );
    }

    use std::time;

    #[test]
    fn ets() {
        let std_start = time::Instant::now();

        let mut kd: WSUdplike<u32> = WSUdplike::new(100).unwrap();

        for x in 0..100_000_000 {
            kd.insert((x, 1));

            if x % 90 == 0 {
                let _ = kd.get_queue();
            }
        }

        println!("{:}", std_start.elapsed().as_secs_f32());
        assert!(false)
    }
}
