use crate::{t2fields, t2pology};

pub fn buf_make(
    elems_in_buf: &mut usize,
    u_buf: &mut Box<[u8]>,
    pack_topology: &t2pology::PackTopology,
    data: Box<[u8]>,
    mtu: usize,
    crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
) -> Result<Box<[Box<[u8]>]>, &'static str> {
    let _ = pack_topology
        .len_slice()
        .ok_or("pack_topology.len_slice() is none");

    if u_buf.len() < mtu {
        return Err("u_buf.len() wanna be >= of mtu");
    }

    let min_len = pack_topology.total_minimal_len();
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
            let buf_void = u_buf
                .len()
                .checked_sub(*elems_in_buf)
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
        u_buf[*elems_in_buf..*elems_in_buf + copy_elems_to_buf]
            .copy_from_slice(&data[pos_in_data..pos_in_data + copy_elems_to_buf]);

        //Updating offsets to copy_elems_to_buf value
        *elems_in_buf = elems_in_buf
            .checked_add(copy_elems_to_buf)
            .ok_or("err elems_in_buf add= copy_elems_to_buf")?;
        pos_in_data = pos_in_data
            .checked_add(copy_elems_to_buf)
            .ok_or("err in pos_in_data + opy_elems_to_buf")?;

        let mut ptr_to_start = 0;
        let mut old_ret_pos: usize = 0;
        while ptr_to_start < *elems_in_buf {
            let elem_in_buf_quque = elems_in_buf
                .checked_sub(ptr_to_start)
                .ok_or("err elems_in_buf sub ptr_to_start")?;

            //if the length of the data in the buffer is greater than the minimum packet size,
            // it means that you can read the packet length fields to find out its end.
            if elem_in_buf_quque >= min_len {
                //if the package has a crc signature of the head data,
                // then it must be checked. if the data is intact, add it to ret_paks
                if pack_topology.head_crc_slice().is_some() {
                    if !t2fields::set_get_head_crc(
                        false,
                        &mut u_buf[ptr_to_start..],
                        pack_topology,
                        crcfn.ok_or("crcfn is none")?,
                    )? {
                        return Err("package is damaged");
                    }
                }

                //getting the length of the packet from the length field in the packet.
                let len_of_curent_pack = t2fields::get_len(&u_buf[ptr_to_start..], pack_topology)?;
                //if the length value in the length field is greater than MTU,
                // then the packet is corrupted, an error is caused.
                if len_of_curent_pack > mtu {
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
                ret_paks.push(u_buf[old_ret_pos..ptr_to_start].to_vec().into_boxed_slice());
                old_ret_pos = ptr_to_start;
            } else {
                break;
            };
        }
        //shifting elements that have already been processed and added to ret_paks
        u_buf[0..*elems_in_buf].rotate_left(ptr_to_start);
        //position changes so that the beginning is there, and the last raw element
        *elems_in_buf = elems_in_buf
            .checked_sub(ptr_to_start)
            .ok_or("err elems_in_buf sub= ptr_to_start")?;
    }

    Ok(ret_paks.into_boxed_slice())
    //Err("")
}

#[cfg(test)]
mod tests {

    use super::*;

    fn datas() -> (
        Vec<Vec<u8>>,
        Vec<u8>,
        Vec<usize>,
        Box<[u8]>,
        t2pology::PackTopology,
    ) {
        let packet_specs = (0..100_000_00u64)
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
            t2pology::PakFields::Len(1),
            t2pology::PakFields::IdOfSender(1),
            t2pology::PakFields::IdReceiver(1),
            t2pology::PakFields::Counter(1),
            t2pology::PakFields::HeadCRC(3),
        ];

        let pack_topology = t2pology::PackTopology::new(2, &fields, true, true).unwrap();

        let mut pkks: Vec<u8> = Vec::new();
        for mut packet in packets.iter_mut() {
            t2fields::set_get_head_crc(true, &mut packet, &pack_topology, dummy_crc_gen).unwrap();
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
        let mut datas_x = datas();

        let mut lensis = 0;
        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();
        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;

            let ret = buf_make(
                &mut lensis,
                &mut datas_x.3,
                &datas_x.4,
                data.into_boxed_slice(),
                41,
                Some(dummy_crc_gen),
            )
            .unwrap();

            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                // println!("{:?}", i);
            }
        }
    }
    #[test]
    fn test_bufpack_err_len_mtu() {
        let mut datas_x = datas();

        let mut lensis = 0;
        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();
        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;

            let ret = buf_make(
                &mut lensis,
                &mut datas_x.3,
                &datas_x.4,
                data.into_boxed_slice(),
                39,
                Some(dummy_crc_gen),
            );
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
        let mut datas_x = datas();

        let mut lensis = 0;
        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();
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

            let ret = buf_make(
                &mut lensis,
                &mut datas_x.3,
                &datas_x.4,
                data.into_boxed_slice(),
                39,
                Some(dummy_crc_gen),
            );
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
