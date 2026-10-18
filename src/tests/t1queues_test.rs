mod test_wait {

    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use crate::t1queues::*;

    #[test]
    fn test_one() {
        let mut prevec = vec![];
        for pre_vec in [true, false, true, false, true, false] {
            assert!(WSWaitQueue::<bool, u32>::new(0).is_err());

            let mut waa = WSWaitQueue::<bool, u32>::new(10).unwrap();

            let max_x = 10;
            let addrt = 10;
            assert_eq!(waa.elems_in_me(), 0);
            assert_eq!(waa.max_elem_id_and_p(), None);
            assert_eq!(waa.min_elem_id_and_p(), None);

            for x in addrt..max_x + addrt {
                let res = waa.push(x * 2, x as u32, true);
                assert_eq!(res, Ok(()));

                assert_eq!(waa.max_elem_id_and_p(), Some((x * 2, x as u32)));
                assert_eq!(waa.min_elem_id_and_p(), Some((addrt * 2, addrt as u32)));
                assert_eq!(waa.elems_in_me(), (1 + x - addrt) as usize);
            }

            for x in waa.data_map.iter() {
                println!(" id: {} cb:{:?} cl {:?}", x.0, x.1.cb, x.1.cl);
            }

            let temp = waa.get_elements_to(
                waa.max_elem_id_and_p().unwrap().1,
                if pre_vec { Some(&mut prevec) } else { None },
            );

            let final_vec = if pre_vec {
                assert!(temp.is_none());
                prevec.clone()
            } else {
                temp.unwrap()
            };

            assert_eq!(
                final_vec
                    .iter()
                    .map(|x| (x.0 / 2) - addrt)
                    .collect::<Vec<u64>>(),
                (0..max_x).collect::<Vec<u64>>()
            );
        }
    }

    #[test]
    fn test_main() {
        {
            let mut prevec = vec![];

            for pre_vec in [true, false, true, false, true, false] {
                let mut waa = WSWaitQueue::<bool, u32>::new(10).unwrap();

                let max_x = 10;
                //let addrt = 10;
                assert_eq!(waa.elems_in_me(), 0);
                assert_eq!(waa.capacity(), 10);
                assert!(waa.is_empty());
                assert_eq!(waa.max_elem_id_and_p(), None);
                assert_eq!(waa.min_elem_id_and_p(), None);

                for x in 0..max_x {
                    let res = waa.push(x, x as u32, true);
                    assert_eq!(res, Ok(()));

                    assert_eq!(waa.max_elem_id_and_p(), Some((x, x as u32)));
                    assert_eq!(waa.min_elem_id_and_p(), Some((0, 0)));
                    assert_eq!(waa.elems_in_me(), (1 + x) as usize);
                }
                //====================================
                let temp = waa.get_elements_to(
                    waa.max_elem_id_and_p().unwrap().1,
                    if pre_vec { Some(&mut prevec) } else { None },
                );

                let final_vec = if pre_vec {
                    assert!(temp.is_none());
                    prevec.clone()
                } else {
                    temp.unwrap()
                };

                assert_eq!(
                    final_vec.iter().map(|x| x.0).collect::<Vec<u64>>(),
                    (0..max_x).collect::<Vec<u64>>()
                );

                //double read===========================

                {
                    let mut waa = waa.clone();

                    let bl = final_vec.last().unwrap().0 + 1000;

                    let bs = final_vec.first().unwrap().0;

                    for retme in bs..bl {
                        waa.remove(retme);
                    }

                    let temp = waa
                        .get_elements_to(999999999, if pre_vec { Some(&mut prevec) } else { None });

                    assert!(temp.is_none());
                    //println!("{}", waa.elems_in_me);
                    if pre_vec {
                        assert_eq!(prevec.len(), 0, "id need pre {}", pre_vec);
                    }
                }
                waa.remove(4).unwrap();
                //====================================
                let temp = waa.get_elements_to(
                    waa.max_elem_id_and_p().unwrap().1,
                    if pre_vec { Some(&mut prevec) } else { None },
                );

                let final_vec = if pre_vec {
                    assert!(temp.is_none());
                    prevec.clone()
                } else {
                    temp.unwrap()
                };

                assert_eq!(
                    final_vec.iter().map(|x| x.0).collect::<Vec<u64>>(),
                    vec![0, 1, 2, 3, 5, 6, 7, 8, 9]
                );

                waa.remove(5).unwrap();
                waa.remove(7).unwrap();
                waa.remove(1).unwrap();

                //====================================
                let temp = waa.get_elements_to(
                    waa.max_elem_id_and_p().unwrap().1,
                    if pre_vec { Some(&mut prevec) } else { None },
                );
                let final_vec = if pre_vec {
                    assert!(temp.is_none());
                    prevec.clone()
                } else {
                    temp.unwrap()
                };

                assert_eq!(
                    final_vec.iter().map(|x| x.0).collect::<Vec<u64>>(),
                    vec![0, 2, 3, 6, 8, 9]
                );
                //====================================
                assert_eq!(waa.max_elem_id_and_p(), Some((9, 9)));
                assert_eq!(waa.min_elem_id_and_p(), Some((0, 0)));

                waa.remove(9).unwrap();

                assert_eq!(waa.max_elem_id_and_p(), Some((8, 8)));

                waa.remove(8).unwrap();

                assert_eq!(waa.max_elem_id_and_p(), Some((6, 6)));
                assert_eq!(waa.min_elem_id_and_p(), Some((0, 0)));

                waa.remove(0).unwrap();

                assert_eq!(waa.min_elem_id_and_p(), Some((2, 2)));

                waa.push(10, 10, true).unwrap();
                waa.push(20, 1000, true).unwrap();

                assert!(waa.push(30, 999, true).is_ok());
                assert!(waa.push(30, 1000, true).is_err()); // id 30 == 30 

                assert!(waa.push(30, 1000000, true).is_err());
                assert!(waa.push(31, 1001, true).is_ok());

                waa.remove(2).unwrap();
                waa.remove(20).unwrap();
                waa.remove(6).unwrap();
                waa.remove(10).unwrap();

                assert!(waa.push(50, 0, true).is_ok());
                assert!(waa.push(51, 43, true).is_ok());
                assert!(waa.push(52, 6, true).is_ok());
                //====================================

                let temp = waa.get_elements_to(
                    waa.max_elem_id_and_p().unwrap().1,
                    if pre_vec { Some(&mut prevec) } else { None },
                );
                let final_vec = if pre_vec {
                    assert!(temp.is_none());
                    prevec.clone()
                } else {
                    temp.unwrap()
                };

                assert_eq!(
                    final_vec.iter().map(|x| x.0).collect::<Vec<u64>>(),
                    vec![3, 30, 31, 50, 51, 52]
                );
                //====================================
                let temp = waa.get_elements_to(
                    waa.max_elem_id_and_p().unwrap().1,
                    if pre_vec { Some(&mut prevec) } else { None },
                );
                let final_vec = if pre_vec {
                    assert!(temp.is_none());
                    prevec.clone()
                } else {
                    temp.unwrap()
                };
                assert_eq!(
                    final_vec.iter().map(|x| x.1).collect::<Vec<u32>>(),
                    vec![3, 1000, 1001, 1001, 1001, 1001]
                );

                waa.remove(31).unwrap();
                waa.remove(30).unwrap();
                waa.remove(50).unwrap();
                waa.remove(51).unwrap();
                waa.remove(52).unwrap();

                /*
                println!("==============");
                for x in waa.data_map.iter() {
                    println!(
                        " id: {} cb:{:?} cl {:?} p{:?}",
                        x.0,
                        x.1.cb,
                        x.1.cl,
                        x.1.p_order.clone()
                    );
                }*/
                assert_eq!(waa.max_elem_id_and_p(), Some((3, 3)));
                assert_eq!(waa.min_elem_id_and_p(), Some((3, 3)));
                assert_eq!(waa.elems_in_me(), 1);
                waa.remove(3).unwrap();

                assert_eq!(waa.max_elem_id_and_p(), None);
                assert_eq!(waa.min_elem_id_and_p(), None);
                assert_eq!(waa.elems_in_me(), 0);
                assert!(waa.is_empty());
            }
        }
    }
}

mod tests_wtcp {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

    use crate::t0grouper::GroupTopology;
    use crate::t0pology::{PackFields, PackTopology};
    use crate::t1dumb_srct::*;
    use crate::t1fields;
    use crate::t1queues::*;
    use crate::w1types::{Crcser, PackScheme, PackTypeGroup as PTG, WisErr};
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
            PackFields::Len(1),
            PackFields::IdSender(1),
            PackFields::IdReceiver(1),
            PackFields::Counter(1),
            PackFields::HeadCRC(3),
        ];

        let pack_topology = PackTopology::new(2, &fields, true, true).unwrap();

        let mut pkks: Vec<u8> = Vec::new();
        let mut d_crc = DumpCrcser::new(&[0]).unwrap();

        let mut lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), String> {
            d_crc.gen_crc(da1ta, out)?;
            Ok(())
        };

        for packet in packets.iter_mut() {
            t1fields::set_get_head_crc(true, packet, &pack_topology, &mut lbo).unwrap();
            pkks.append(&mut packet.clone());
        }

        let buf = vec![0u8; 41].into_boxed_slice();

        let data_slises = (0..200)
            .map(|x| (x * 347 * 499 * 809) % 500_usize)
            .collect::<Vec<usize>>();

        //let mut data_slises = data_slises.iter().cycle();

        (packets, pkks, data_slises, buf, pack_topology)
    }

    fn datas_multi() -> (Vec<Vec<u8>>, Vec<u8>, Vec<usize>, GroupTopology, Vec<u8>) {
        let packets_specs_lens = (0..100_000u64)
            .map(|x| {
                let b = 40 + ((x.wrapping_mul(347)) % 20);
                (b as u8 ^ (0x12), b as usize)
            })
            .collect::<Vec<_>>();

        let mut packets_pride: Vec<Vec<u8>> = packets_specs_lens
            .iter()
            .map(|&(value, len)| vec![value; len])
            .collect();

        let mut vec_of_tryli_bytes_num: Vec<u8> = vec![];
        let mut num_iter_trikly = 100;
        let mut ffilders = vec![];
        for x1 in [PackFields::HeadCRC(3), PackFields::UserField(2)].iter() {
            for x2 in [PackFields::UserField(7), PackFields::UserField(3)].iter() {
                for x3 in [PackFields::TTL(3), PackFields::UserField(1)].iter() {
                    for x4 in [PackFields::UserField(3), PackFields::UserField(4)].iter() {
                        for x5 in [PackFields::IdConnect(2), PackFields::UserField(1)].iter() {
                            let mut temp = vec![PackFields::UserField(2), PackFields::TrickyByte];

                            temp.push(x1.clone());
                            temp.push(x2.clone());
                            temp.push(x3.clone());
                            temp.push(x4.clone());
                            temp.push(PackFields::Len(7));
                            temp.push(x5.clone());
                            temp.push(PackFields::Counter(4));

                            //let test = PackTopology::new(3, &temp, true, true).unwrap();
                            //temp.push(PackFields::UserField(40 - test.total_minimal_len()));
                            if 0 == num_iter_trikly % 2 {
                                ffilders.push((
                                    temp.into_boxed_slice(),
                                    PTG::Data,
                                    num_iter_trikly,
                                ));
                            } else {
                                ffilders.push((
                                    temp.into_boxed_slice(),
                                    PTG::Fback,
                                    num_iter_trikly,
                                ));
                            }

                            vec_of_tryli_bytes_num.push(num_iter_trikly);
                            num_iter_trikly += 1;
                        }
                    }
                }
            }
        }

        let pack_topology_group = GroupTopology::new(&ffilders[..], 3, true, true).unwrap();

        let mut pkks: Vec<u8> = Vec::new();
        let mut d_crc = DumpCrcser::new(&[0]).unwrap();

        let mut lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), String> {
            d_crc.gen_crc(da1ta, out)?;
            Ok(())
        };

        for (ii, packet) in packets_pride.iter_mut().enumerate() {
            let tbute = vec_of_tryli_bytes_num[(ii + 13) % vec_of_tryli_bytes_num.len()];

            let my_top = pack_topology_group.get_from_u8(tbute, PTG::Any).unwrap();

            let paaake = &mut packet[..];

            t1fields::set_tricky_byte(paaake, my_top, tbute).unwrap();
            t1fields::set_len(paaake, my_top, &1000).unwrap();
            if my_top.head_crc_slice().is_some() {
                t1fields::set_get_head_crc(true, paaake, my_top, &mut lbo).unwrap();
            }

            pkks.append(&mut paaake.to_vec().clone());
            //println!("l {}   {:?}", ii, paaake.len());
        }

        let data_slises = (0..9999)
            .map(|x| {
                ((x as u64 * 347 * 499 * 809).wrapping_add((x as u64 * 21337).rotate_left(17))
                    % 500) as usize
            })
            .collect::<Vec<usize>>();

        //let mut data_slises = data_slises.iter().cycle();

        (
            packets_pride,
            pkks,
            data_slises,
            pack_topology_group,
            vec_of_tryli_bytes_num,
        )
    }
    #[test]
    fn test_bufpack() {
        let datas_x = datas();

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();

        let mut w_tcp: WSTcpLike<DumpCrcser> =
            WSTcpLike::new(41, PackScheme::OnePack(datas_x.4), Some(&[0])).unwrap();

        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;
            let ret = w_tcp
                .split_byte_stream_into_packages(&data.into_boxed_slice())
                .unwrap();

            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                println!("{:?}", i);
            }
        }
    }
    #[test]
    fn test_bufpack_err_len_mtu() {
        let datas_x = datas();

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();

        let mut w_tcp: WSTcpLike<DumpCrcser> =
            WSTcpLike::new(39, PackScheme::OnePack(datas_x.4), Some(&[0])).unwrap();

        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;

            let ret = w_tcp.split_byte_stream_into_packages(&data.into_boxed_slice());
            if ret.is_err() {
                assert_eq!(
                    ret,
                    Err(WisErr::Critical("len_of_curent_pack > mtu".to_string()))
                );
                return;
            }
            let ret = ret.unwrap();
            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                //println!("{:?}", i);
            }
        }
        assert_eq!(
            false, false,
            "there should have been a buffer size error, but it didn't happen!"
        );
    }

    #[test]
    fn test_bufpack_package_damage() {
        let datas_x = datas();

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();
        let mut w_tcp: WSTcpLike<DumpCrcser> =
            WSTcpLike::new(39, PackScheme::OnePack(datas_x.4), Some(&[0])).unwrap();
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

            let ret = w_tcp.split_byte_stream_into_packages(&data.into_boxed_slice());
            if ret.is_err() {
                assert_eq!(ret, Err(WisErr::Critical("package is damaged".to_string())));
                return;
            }
            let ret = ret.unwrap();
            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                //println!("{:?}", i);
            }
        }
        assert_eq!(
            false, false,
            "there should have been a buffer size error, but it didn't happen!"
        );
    }

    #[test]
    fn test_bufpack_grooup() {
        let mut datas_x = datas_multi();

        for vi in datas_x.0.iter_mut() {
            let tpos = datas_x.3.tricky_position().unwrap();

            let te1 = datas_x.3.get_from_u8(vi[tpos], PTG::Any).unwrap();

            assert_eq!(vi.len(), t1fields::get_len(&vi[..], te1).unwrap());

            let mut d_crc = DumpCrcser::new(&[0]).unwrap();

            let mut lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), String> {
                d_crc.gen_crc(da1ta, out)?;
                Ok(())
            };

            if te1.head_crc_slice().is_some() {
                assert!(t1fields::set_get_head_crc(false, &mut vi[..], te1, &mut lbo).unwrap());
            }
            /*
            println!(
                " tb:{}  Pack:  {:?}",
                vi[datas_x.3.tricky_position().unwrap()],
                vi
            );
            */
        }

        //println!("==============================");

        let mut index = 0;

        let mut arepackets = datas_x.0.iter();
        let mut data_slises = datas_x.2.iter().cycle();

        let mut w_tcp: WSTcpLike<DumpCrcser> =
            WSTcpLike::new(311, PackScheme::GroupPack(datas_x.3), Some(&[0])).unwrap();

        while index < datas_x.1.len() {
            let s = data_slises.next().unwrap();
            let data = if s + index < datas_x.1.len() {
                datas_x.1[index..index + *s].to_vec()
            } else {
                datas_x.1[index..].to_vec()
            };
            index += *s;
            let ret = w_tcp
                .split_byte_stream_into_packages(&data.into_boxed_slice())
                .unwrap();

            for i in ret.iter() {
                assert_eq!(i.to_vec(), *arepackets.next().unwrap());
                //println!("{:?}", &i[..20]);
            }
        }
    }
}

mod tests_wudp {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use crate::t1queues::*;
    use crate::w1types::WSQueueState;

    #[test]
    fn test_segment() {
        let mut vv = vec![];
        let mut xx: WSUdpLike<u32> = WSUdpLike::new(50).unwrap();
        let emeee = 0;
        for x in 1..1000 {
            let is_prea = x % 2 == 0;

            let _ = xx.insert(x - 1, &emeee);

            if x > 1 && x % 13 == 0 {
                let bw = xx.how_items_in_me();

                let geu = xx.get_queue(if is_prea { Some(&mut vv) } else { None });

                let geu = if is_prea {
                    vv.clone()
                } else {
                    geu.unwrap().clone()
                };

                assert_eq!(geu.len(), 13);
                assert_eq!(geu.len(), bw);
                //println!("geulen:{}",geu.len());
            }
        }
    }

    #[test]
    fn test_kmod() {
        let mut xx: WSUdpLike<u32> = WSUdpLike::new(123).unwrap();

        xx.k_mod = 100;

        xx.k_add(70);
        assert_eq!(xx.k_mod, (100 + 70) % 123);

        xx.k_add(1000);
        assert_eq!(xx.k_mod, (100 + 70 + 1000) % 123);

        xx.k_add(3);
        assert_eq!(xx.k_mod, (100 + 70 + 1000 + 3) % 123);
    }

    fn test_api<T: Clone>(
        uddp: &mut WSUdpLike<T>,
        is_pre: bool,
        pre_ve: &mut Vec<(u64, T)>,
    ) -> Vec<(u64, T)> {
        let geu = uddp.get_queue(if is_pre {
            Some(pre_ve)
        } else {
            pre_ve.clear();
            None
        });

        if is_pre {
            assert!(geu.is_none())
        }

        if let Some(x) = geu {
            x.clone()
        } else {
            pre_ve.clone()
        }
    }

    #[test]
    fn test_hands() {
        let mut vv = vec![];

        for is_pre in [false, true, false, true, true, true, false, false, false].iter() {
            let mut xx: WSUdpLike<f32> = WSUdpLike::new(8).unwrap();
            assert!(xx.capacity() == 8);
            let eleme = 0.0;
            {
                {
                    assert_eq!(xx.last_ctr_get(), None);
                    assert_eq!(xx.how_items_in_me(), 0);
                    assert_eq!(xx.free_space(), xx.capacity());
                    assert!(xx.is_empty());
                    assert_eq!(xx.get_largest_ctr(), None);
                    //
                    assert_eq!(xx.insert(4, &eleme), WSQueueState::SuccessfulInsertion); //1
                    assert!(xx.gap_in_queue());
                    assert_eq!(xx.insert(0, &eleme), WSQueueState::SuccessfulInsertion); //2
                    //
                    assert_eq!(xx.last_ctr_get(), None);
                    assert_eq!(xx.how_items_in_me(), 2);
                    assert_eq!(xx.free_space(), xx.capacity() - 2);
                    assert!(!xx.is_empty());
                    assert_eq!(xx.get_largest_ctr(), Some(4));
                    //
                    assert_eq!(xx.insert(2, &eleme), WSQueueState::SuccessfulInsertion); //3
                    assert!(xx.gap_in_queue());
                    assert_eq!(xx.insert(3, &eleme), WSQueueState::SuccessfulInsertion); //4
                    assert_eq!(xx.insert(5, &eleme), WSQueueState::SuccessfulInsertion); //5
                    //
                    assert_eq!(xx.last_ctr_get(), None);
                    assert_eq!(xx.how_items_in_me(), 5);
                    assert!(!xx.is_empty());
                    assert_eq!(xx.get_largest_ctr(), Some(5));
                    //
                }
                assert_eq!(xx.insert(6, &eleme), WSQueueState::SuccessfulInsertion); //6
                assert_eq!(xx.insert(7, &eleme), WSQueueState::SuccessfulInsertion); //7
                assert_eq!(xx.insert(8, &eleme), WSQueueState::ElemIdIsBig); //8
                assert_eq!(xx.insert(3, &eleme), WSQueueState::ElemIsAlreadyIn); //9
                assert_eq!(xx.insert(1, &eleme), WSQueueState::SuccessfulInsertion); //10
                assert!(!xx.gap_in_queue());
                assert_eq!(xx.in_queue, 8);
                assert_eq!(xx.free_space(), xx.capacity() - 8);
                //
                assert_eq!(xx.last_ctr_get(), None);
                assert_eq!(xx.how_items_in_me(), 8);
                assert_eq!(xx.get_largest_ctr(), Some(7));
            }
            assert_eq!(
                test_api(&mut xx, *is_pre, &mut vv),
                vec![
                    (0, 0.0),
                    (1, 0.0),
                    (2, 0.0),
                    (3, 0.0),
                    (4, 0.0),
                    (5, 0.0),
                    (6, 0.0),
                    (7, 0.0)
                ]
            );
            {
                assert!(!xx.gap_in_queue());
                assert_eq!(xx.insert(9, &eleme), WSQueueState::SuccessfulInsertion);

                assert_eq!(xx.insert(11, &eleme), WSQueueState::SuccessfulInsertion);

                assert_eq!(xx.insert(12, &eleme), WSQueueState::SuccessfulInsertion);
                assert!(xx.gap_in_queue());
                assert_eq!(test_api(&mut xx, *is_pre, &mut vv), vec![]);
                //
                assert_eq!(xx.last_ctr_get(), Some(7));
                assert_eq!(xx.how_items_in_me(), 3);
                assert_eq!(xx.get_largest_ctr(), Some(12));
                //
                assert_eq!(xx.insert(10, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(13, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(test_api(&mut xx, *is_pre, &mut vv), vec![]);
                assert!(xx.gap_in_queue());
                //
                assert_eq!(xx.last_ctr_get(), Some(7));
                assert_eq!(xx.how_items_in_me(), 5);
                assert_eq!(xx.get_largest_ctr(), Some(13));
                //
                assert_eq!(xx.insert(8, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(
                    test_api(&mut xx, *is_pre, &mut vv),
                    vec![
                        (8, 0.0),
                        (9, 0.0),
                        (10, 0.0),
                        (11, 0.0),
                        (12, 0.0),
                        (13, 0.0)
                    ]
                );
            }
            {
                assert_eq!(xx.insert(12, &eleme), WSQueueState::ElemIdIsSmall);
                assert_eq!(xx.insert(13, &eleme), WSQueueState::ElemIdIsSmall);

                assert_eq!(xx.insert(22, &eleme), WSQueueState::ElemIdIsBig);
                assert_eq!(xx.insert(21, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(2, &eleme), WSQueueState::ElemIdIsSmall);

                //
                assert_eq!(xx.last_ctr_get(), Some(13));
                assert_eq!(xx.how_items_in_me(), 1);
                assert_eq!(xx.free_space(), xx.capacity() - 1);
                assert_eq!(xx.get_largest_ctr(), Some(21));
                //
                assert_eq!(xx.insert(14, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(test_api(&mut xx, *is_pre, &mut vv), vec![(14, 0.0)]);

                assert_eq!(xx.insert(15, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(16, &eleme), WSQueueState::SuccessfulInsertion);

                assert_eq!(xx.insert(17, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(18, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(19, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(20, &eleme), WSQueueState::SuccessfulInsertion);
            }
            assert_eq!(
                test_api(&mut xx, *is_pre, &mut vv),
                vec![
                    (15, 0.0),
                    (16, 0.0),
                    (17, 0.0),
                    (18, 0.0),
                    (19, 0.0),
                    (20, 0.0),
                    (21, 0.0)
                ]
            );

            let mut xx: WSUdpLike<f32> = WSUdpLike::new(7).unwrap();
            assert!(!xx.gap_in_queue());
            assert_eq!(xx.insert(0, &eleme), WSQueueState::SuccessfulInsertion); //1
            assert!(!xx.gap_in_queue());
            assert_eq!(xx.insert(1, &eleme), WSQueueState::SuccessfulInsertion); //2
            assert_eq!(xx.insert(2, &eleme), WSQueueState::SuccessfulInsertion); //3
            assert_eq!(xx.insert(3, &eleme), WSQueueState::SuccessfulInsertion); //4
            assert!(!xx.gap_in_queue());
            assert_eq!(xx.insert(4, &eleme), WSQueueState::SuccessfulInsertion); //5
            assert_eq!(xx.insert(5, &eleme), WSQueueState::SuccessfulInsertion); //6
            assert_eq!(xx.insert(6, &eleme), WSQueueState::SuccessfulInsertion); //7
            assert_eq!(xx.in_queue, 7);
            assert_eq!(
                test_api(&mut xx, *is_pre, &mut vv),
                (vec![
                    (0, 0.0),
                    (1, 0.0),
                    (2, 0.0),
                    (3, 0.0),
                    (4, 0.0),
                    (5, 0.0),
                    (6, 0.0)
                ])
            );

            let mut xx: WSUdpLike<f32> = WSUdpLike::new(7).unwrap();

            assert_eq!(xx.insert(0, &eleme), WSQueueState::SuccessfulInsertion); //1
            assert_eq!(xx.in_queue, 1);
            assert_eq!(test_api(&mut xx, *is_pre, &mut vv), (vec![(0, 0.0)]));

            assert_eq!(xx.insert(1, &eleme), WSQueueState::SuccessfulInsertion); //2
            assert_eq!(xx.in_queue, 1);
            assert_eq!(
                test_api(&mut xx, *is_pre, &mut vv),
                (vec![(1, 0.0)]),
                "{:?}",
                xx.data
            );

            assert_eq!(xx.insert(2, &eleme), WSQueueState::SuccessfulInsertion); //3

            assert_eq!(xx.in_queue, 1);
            assert_eq!(test_api(&mut xx, *is_pre, &mut vv), (vec![(2, 0.0)]));

            assert_eq!(xx.insert(3, &eleme), WSQueueState::SuccessfulInsertion); //4
            assert_eq!(xx.in_queue, 1);
            assert_eq!(test_api(&mut xx, *is_pre, &mut vv), (vec![(3, 0.0)]));

            assert_eq!(xx.insert(4, &eleme), WSQueueState::SuccessfulInsertion); //5
            assert_eq!(xx.insert(5, &eleme), WSQueueState::SuccessfulInsertion); //6
            assert_eq!(xx.insert(6, &eleme), WSQueueState::SuccessfulInsertion); //7
            assert_eq!(xx.insert(7, &eleme), WSQueueState::SuccessfulInsertion); //5
            assert_eq!(xx.insert(8, &eleme), WSQueueState::SuccessfulInsertion); //6
            assert_eq!(xx.insert(9, &eleme), WSQueueState::SuccessfulInsertion); //7
            assert_eq!(xx.insert(10, &eleme), WSQueueState::SuccessfulInsertion); //5
            assert_eq!(xx.insert(11, &eleme), WSQueueState::ElemIdIsBig); //6
            assert_eq!(xx.in_queue, 7);
            assert_eq!(
                test_api(&mut xx, *is_pre, &mut vv),
                (vec![
                    (4, 0.0),
                    (5, 0.0),
                    (6, 0.0),
                    (7, 0.0),
                    (8, 0.0),
                    (9, 0.0),
                    (10, 0.0)
                ])
            );
        }
    }

    #[test]
    fn test_gap() {
        let mut vv = vec![];
        for is_pre in [false, true, false, true, true, true, false, false, false].iter() {
            let mut xx: WSUdpLike<f32> = WSUdpLike::new(20).unwrap();
            assert!(xx.capacity() == 20);
            let eleme = 0.0;
            {
                assert!(!xx.gap_in_queue());
                xx.insert(0, &eleme);
                assert!(!xx.gap_in_queue());
                xx.insert(1, &eleme);
                xx.insert(1, &eleme);
                xx.insert(3, &eleme);
                assert!(xx.gap_in_queue());
                xx.insert(4, &eleme);
                xx.insert(5, &eleme);
                assert!(xx.gap_in_queue());
                xx.insert(2, &eleme);
                assert!(!xx.gap_in_queue());
                xx.insert(7, &eleme);
                assert!(xx.gap_in_queue());
                xx.insert(6, &eleme);
                assert!(!xx.gap_in_queue());
                test_api(&mut xx, *is_pre, &mut vv);
                assert!(!xx.gap_in_queue());
                //
                xx.insert(9, &eleme);
                assert!(xx.gap_in_queue());
                xx.insert(8, &eleme);
                assert!(!xx.gap_in_queue());
                test_api(&mut xx, *is_pre, &mut vv);
                xx.insert(11, &eleme);
                xx.insert(12, &eleme);
                xx.insert(13, &eleme);
                assert!(xx.gap_in_queue());

                xx.insert(10, &eleme);
                assert!(!xx.gap_in_queue());
                //
                xx.insert(15, &eleme);
                xx.insert(16, &eleme);
                xx.insert(17, &eleme);
                assert!(xx.gap_in_queue());
                test_api(&mut xx, *is_pre, &mut vv);
                assert!(xx.gap_in_queue());
                xx.insert(14, &eleme);
                assert!(!xx.gap_in_queue());
            }
        }
    }
}

mod test_recv_queue_ctrs {
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::float_cmp)]
    use ::std::collections::HashMap;

    use crate::t0pology::{PackFields, PackTopology};
    use crate::t1queues::U64_LEN_IN_BYTES;
    use crate::t1queues::{WSFbackQueue, WSWaitQueue};
    #[test]
    fn test_base() {
        let fields = vec![PackFields::Counter(2)];

        let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

        for x in 1..20 {
            let x = x * 26;

            assert_eq!(
                WSFbackQueue::<f64>::max_len_from_mtu(pack_topology.counter_slice().unwrap().2, x)
                    .unwrap(),
                (x - (U64_LEN_IN_BYTES + WSFbackQueue::<f64>::P_SIZE))
                    / pack_topology.counter_slice().unwrap().2
            );
        }

        assert_eq!(
            WSFbackQueue::<f64>::max_len_from_mtu(pack_topology.counter_slice().unwrap().2, 9),
            Err(
                "mtu < (pack_topology.total_minimal_len() + U64_LEN_IN_BYTES + P_len_as_bytes )"
                    .to_string()
            )
        );

        assert!(
            WSFbackQueue::<f64>::new(pack_topology.counter_slice().unwrap().2, 39, 100).is_ok()
        );
    }
    #[test]
    fn test_wait() {
        println!("test_wait");

        {
            let fields = vec![PackFields::Counter(1)];

            let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

            let mut zero_test =
                WSFbackQueue::<f32>::new(pack_topology.counter_slice().unwrap().2, 500, 1000)
                    .unwrap();

            let (ret_ve, opt_p) = zero_test.get_ctrs_as_byte_pack_vec(1999999.0).unwrap();

            assert_eq!(ret_ve.len(), 0, "assert №1");
            assert_eq!(opt_p, None, "assert №2");
            let mut t_t = vec![0; 100];

            for fff_ttt in [true, false] {
                let (ret, opt_p) = zero_test
                    .copy_ctrs_pack_to_slice(9999.0, &mut t_t, fff_ttt)
                    .unwrap();

                assert_eq!(opt_p, None, "assert №3");
                assert_eq!(ret, 0, "assert №4");
            }
        }

        let mut vee_pre = vec![];
        for pre_aloo in [true, false, true, false, false, false, true, true, true].iter() {
            if !*pre_aloo {
                vee_pre.clear();
            }
            let ctr_len = 1; //dnt touch
            let fields = vec![PackFields::Counter(ctr_len)];

            let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

            let mut test_me =
                WSFbackQueue::new(pack_topology.counter_slice().unwrap().2, 500, 1000).unwrap();

            assert!(test_me.capacity() == 500);

            for fall_maker in 500..512 {
                let test_me_fall = WSFbackQueue::<f32>::new(1, 500, fall_maker);

                assert!(test_me_fall.is_err(), "{:?}", test_me_fall.ok().unwrap());
            }

            let test_me_fall1 = WSFbackQueue::<f32>::new(0, 500, 1000);

            let test_me_fall2 = WSFbackQueue::<f32>::new(9, 500, 1000);

            let test_me_fall3 = WSFbackQueue::<f32>::new(1, 500, 507);

            let test_me_ok = WSFbackQueue::<f32>::new(1, 500, 512);

            assert_eq!(
                test_me_fall1.err().unwrap(),
                "pack_topology.counter_slice() == 0 or len_ctr_field > 8",
                "assert №5"
            );
            assert_eq!(
                test_me_fall2.err().unwrap(),
                "pack_topology.counter_slice() == 0 or len_ctr_field > 8",
                "assert №6"
            );
            assert_eq!(
                test_me_fall3.err().unwrap(),
                "The byte representation of the maximum length must be less than or equal to mtu.",
                "assert №6"
            );

            assert!(test_me_ok.is_ok(), "{:?}", test_me_ok.err().unwrap());

            let mut ws_wa: WSWaitQueue<String, f64> = WSWaitQueue::new(500).unwrap();
            assert_eq!(ws_wa.capacity(), 500, "assert №8");
            for iterata_ma in [
                10_000_000,
                10_000,
                10,
                100_000_000,
                500,
                123456789,
                0,
                12,
                0x1F_FF_FF_FF_FF_FF_FE_11,
                87667,
            ] {
                let mut hm: HashMap<u64, u64> = HashMap::new();

                println!("| {:>20} |===================================", iterata_ma);
                for x in (iterata_ma..iterata_ma + 256).enumerate() {
                    hm.insert(x.1, x.1);
                    test_me.push(x.1, 0.2 * x.1 as f64).unwrap();
                    assert_eq!(test_me.free_space(), 500 - 1 - x.0, "assert №9");
                    assert_eq!(
                        test_me.get_min_max_and_max_p(),
                        (iterata_ma, x.1, Some(0.2 * x.1 as f64)),
                        "assert №10"
                    );
                    assert_eq!(test_me.elems_in_me(), x.0 + 1, "assert №11");

                    let last_p = x.1 as f64 * 1.2;
                    ws_wa.push(x.1, last_p, "data".to_string()).unwrap();
                }
                assert_eq!(hm.len(), 256, "assert №12");

                let test_me_old = test_me.clone();

                assert_eq!(test_me.elems_in_me(), 256, "assert №13");

                let p_in_test_me = test_me.get_min_max_and_max_p().2.unwrap();
                assert!(!test_me.is_empty(), "assert № 01 17");

                let my_cur_p = test_me.get_min_max_and_max_p().2.unwrap();
                {
                    let test_is = test_me.clone();
                    let eps = my_cur_p.abs() * 0.01; // 1 %
                    let is_ok1 = test_is.clone().get_ctrs_as_byte_pack_vec(my_cur_p);
                    let is_ok2 = test_is.clone().get_ctrs_as_byte_pack_vec(my_cur_p - eps);
                    let is_err = test_is.clone().get_ctrs_as_byte_pack_vec(my_cur_p + eps);

                    assert!(is_ok1.is_ok(), "assert № 02 17");
                    assert!(is_ok2.is_err(), "assert № 03 17");
                    assert!(is_err.is_ok(), "assert № 04 17");
                }

                let (ret_ve, opt_p) = test_me
                    .get_ctrs_as_byte_pack_vec((0xFF_FF_FF_FF_FF_FF_FE_11u64 + 1) as f64)
                    .unwrap();
                assert_eq!(
                    opt_p,
                    Some((0xFF_FF_FF_FF_FF_FF_FE_11u64 + 1) as f64 - p_in_test_me),
                    "assert №14"
                );

                assert_eq!(test_me.elems_in_me(), 0, "assert № 05 17");
                assert!(test_me.is_empty(), "assert № 06 17");
                assert_eq!(test_me.get_min_max_and_max_p(), (0, 0, None), "assert №15");

                assert_eq!(
                    test_me_old.payload_len_in_bytes(),
                    8 + U64_LEN_IN_BYTES + test_me_old.elems_in_me(), //f64 as bytes is 8 bytes
                    "assert №16"
                );
                assert_eq!(ws_wa.elems_in_me(), 256, "assert №17");

                let re_recv = WSFbackQueue::delete_ctrs_in_byte_pack_from_ws_wait_queue(
                    &ret_ve, ctr_len, &mut ws_wa,
                )
                .unwrap();

                assert_eq!(
                    re_recv,
                    (
                        256,
                        Some(iterata_ma as f64 * 1.2),
                        Some((iterata_ma + 255) as f64 * 1.2),
                        (0xFF_FF_FF_FF_FF_FF_FE_11u64 + 1) as f64 - p_in_test_me
                    ),
                    "assert №18"
                );

                assert_eq!(ws_wa.elems_in_me(), 0, "assert №19");

                let (my_p, remap_ve) = WSFbackQueue::<f64>::split_byte_ctrs_pack_to_slice(
                    &ret_ve[..],
                    pack_topology.counter_slice().unwrap().2,
                    if *pre_aloo { Some(&mut vee_pre) } else { None },
                )
                .unwrap();

                assert_eq!(
                    my_p,
                    (0xFF_FF_FF_FF_FF_FF_FE_11u64 + 1) as f64 - p_in_test_me,
                    "assert №20"
                );
                if *pre_aloo {
                    assert!(remap_ve.is_none())
                }

                let remap_ve = if let Some(xxx) = remap_ve {
                    xxx.clone()
                } else {
                    vee_pre.clone()
                };

                for x in (iterata_ma..iterata_ma + 256).enumerate() {
                    hm.remove(&remap_ve[x.0]);
                }
                assert_eq!(hm.len(), 0, "assert №21")
            }
        }
    }

    #[test]
    fn test_wait_blurred_boundaries() {
        let mut vee_pre = vec![];

        for pre_aloo in [true, false, true, false, false, false, true, true, true].iter() {
            if !*pre_aloo {
                vee_pre.clear();
            }
            let ctr_len = 2; //dnt touch

            let mut ws_wa: WSWaitQueue<String, f64> = WSWaitQueue::new(500).unwrap();

            let mut test_me = WSFbackQueue::new(ctr_len, 500, 1100).unwrap();

            for iterata_ma in [10_000_000, 10_000, 10, 100_000_000, 500, 123456789] {
                println!("| {:>10} |===================================", iterata_ma);
                for x in [
                    56, 29, 45, 6, 100, 100, 100, 100, 100, 23, 4, 5, 1, 2, 6, 54, 95, 45, 12, 39,
                    91, 42, 36, 4, 1, 56, 1, 1, 100, 1, 100, 5, 4, 16u64, 0,
                ]
                .iter()
                .enumerate()
                {
                    let x = iterata_ma + x.1;
                    test_me.push(x, 0.32132).unwrap();
                    let _ = ws_wa.push(x, x as f64 * 1.2, "333".to_string());
                }

                assert_eq!(ws_wa.elems_in_me(), 19);
                let mut tc2 = test_me.clone();

                let mut temp_vec_sl = vec![42u8/*42 is trash */; 200];
                let mut temp_vec_sl_c = vec![42u8/*42 is trash */; 200];

                assert!(!tc2.is_empty());

                let mut tc3 = tc2.clone();

                let mut tc4 = tc2.clone();

                let p_len_before_get = tc3.payload_len_in_bytes();

                let my_cur_p = tc2.get_min_max_and_max_p().2.unwrap();

                {
                    let test_is = tc2.clone();
                    let is_ok1 = test_is.clone().get_ctrs_as_byte_pack_vec(my_cur_p);

                    let is_ok2 = test_is.clone().get_ctrs_as_byte_pack_vec(my_cur_p - 0.001);

                    let is_err = test_is.clone().get_ctrs_as_byte_pack_vec(my_cur_p + 0.001);

                    assert!(is_ok1.is_ok());
                    assert!(is_ok2.is_err());
                    assert!(is_err.is_ok());
                }

                let (size_payload, opt_p) = tc2
                    .copy_ctrs_pack_to_slice(my_cur_p, &mut temp_vec_sl, true)
                    .unwrap();

                assert_eq!(opt_p, Some(0.0));

                let mut temp_vec_sl_c_sp = vec![42u8/*42 is trash */; size_payload];
                tc4.copy_ctrs_pack_to_slice(my_cur_p, &mut temp_vec_sl_c_sp, true)
                    .unwrap();

                assert_eq!(p_len_before_get, size_payload);

                tc3.copy_ctrs_pack_to_slice(my_cur_p, &mut temp_vec_sl_c, false)
                    .unwrap();

                assert!(tc2.is_empty());
                //clear reaad
                {
                    let temp1 = WSFbackQueue::<f64>::split_byte_ctrs_pack_to_slice(
                        &[0, 0, 0],
                        ctr_len,
                        if *pre_aloo { Some(&mut vee_pre) } else { None },
                    );

                    assert_eq!(
                        temp1.err().unwrap(),
                        "The packet length is less than the reference counter length(-U64_LEN_IN_BYTES), which is an invalid packet."
                    );
                    if *pre_aloo {
                        assert!(vee_pre.is_empty());
                    }
                }

                assert_eq!(temp_vec_sl[..size_payload], temp_vec_sl_c[..size_payload]);

                assert_eq!(
                    temp_vec_sl_c[size_payload..],
                    vec![42; temp_vec_sl_c.len() - size_payload]
                );
                assert_eq!(
                    temp_vec_sl[size_payload..],
                    vec![0; temp_vec_sl.len() - size_payload]
                );
                let my_cur_p = test_me.get_min_max_and_max_p().2.unwrap();

                let (vec_sl, opt_p) = test_me.get_ctrs_as_byte_pack_vec(my_cur_p).unwrap();

                assert_eq!(opt_p, Some(0.0));

                let h1 = WSFbackQueue::<f64>::split_byte_ctrs_pack_to_slice(
                    &temp_vec_sl,
                    ctr_len,
                    if *pre_aloo { Some(&mut vee_pre) } else { None },
                )
                .unwrap();

                let vee_pre_clone = vee_pre.clone();

                let h2 = WSFbackQueue::<f64>::split_byte_ctrs_pack_to_slice(
                    &vec_sl,
                    ctr_len,
                    if *pre_aloo { Some(&mut vee_pre) } else { None },
                )
                .unwrap();

                WSFbackQueue::delete_ctrs_in_byte_pack_from_ws_wait_queue(
                    &temp_vec_sl,
                    ctr_len,
                    &mut ws_wa,
                )
                .unwrap();

                assert_eq!(ws_wa.elems_in_me(), 0);
                assert_eq!(h1, h2);
                assert_eq!(vee_pre_clone, vee_pre);
            }

            test_me.push(10, 0.11).unwrap(); //1
            test_me.push(1022, 0.12).unwrap(); //2
            test_me.push(1022, 0.13).unwrap(); //3
            test_me.push(10322, 0.14).unwrap(); //4
            let my_cur_p = test_me.get_min_max_and_max_p().2.unwrap();
            assert_eq!(my_cur_p, 0.14);
            test_me.push(10322, 0.15).unwrap(); //5
            test_me.push(10322, 0.16).unwrap(); //6
            let my_cur_p = test_me.get_min_max_and_max_p().2.unwrap();
            assert_eq!(my_cur_p, 0.14);
            test_me.push(1430, 0.17).unwrap(); //7
            test_me.push(18876, 0.18).unwrap(); //8 
            test_me.push(652, 0.9).unwrap(); //9
            test_me.push(11, 1.1).unwrap(); //10
            let my_cur_p = test_me.get_min_max_and_max_p().2.unwrap();
            assert_eq!(my_cur_p, 1.1);
            let (vet, opt_p) = test_me.get_ctrs_as_byte_pack_vec(20.0).unwrap();

            assert_eq!(opt_p, Some(20.0 - 1.1));
            assert_eq!(22 + 8, vet.len());

            let (my_p, temp1) = WSFbackQueue::<f64>::split_byte_ctrs_pack_to_slice(
                &vet,
                ctr_len,
                if *pre_aloo { Some(&mut vee_pre) } else { None },
            )
            .unwrap();

            assert_eq!(my_p, 20.0 - 1.1);

            let temp1 = if let Some(xxx) = temp1 {
                xxx.clone()
            } else {
                vee_pre.clone()
            };

            assert_eq!(temp1, vec![11, 1022, 10322, 1430, 18876, 652, 10]);
            let (my_p, temp1) = WSFbackQueue::<f64>::split_byte_ctrs_pack_to_slice(
                &vet[..vet.len() - 3],
                ctr_len,
                if *pre_aloo { Some(&mut vee_pre) } else { None },
            )
            .unwrap();

            assert_eq!(my_p, 20.0 - 1.1);
            let temp1 = if let Some(xxx) = temp1 {
                xxx.clone()
            } else {
                vee_pre.clone()
            };

            assert_eq!(temp1, vec![11, 1022, 10322, 1430, 18876] /* -2 ctr */);
        }
    }

    #[test]
    fn test_extend_err() {
        let ctr_len = 2; //dnt touch
        let fields = vec![PackFields::Counter(ctr_len)];

        let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

        let mut test_me =
            WSFbackQueue::new(pack_topology.counter_slice().unwrap().2, 500, 1100).unwrap();

        for x in 0..501 {
            assert_eq!(
                test_me.push(x, 0.23),
                if x < 500 {
                    assert_eq!(499 - x as usize, test_me.free_space());
                    Ok(())
                } else {
                    Err("the queue is full".to_string())
                }
            );
        }

        let mut test_me1 =
            WSFbackQueue::new(pack_topology.counter_slice().unwrap().2, 500, 1100).unwrap();

        test_me1.push(1 << ((8 * 2) + 1), 0.2121).unwrap();
        assert_eq!(
            test_me1.push(1, 0.32321),
            Err(
                "The difference between the maximum and minimum counters is greater than the \
                     counter_slice field can hold."
                    .to_string()
            )
        );

        let mut test_me1 =
            WSFbackQueue::new(pack_topology.counter_slice().unwrap().2, 500, 1100).unwrap();

        test_me1.push(1, 0.12).unwrap();
        assert_eq!(
            test_me1.push(1 << ((8 * 2) + 1), 0.3),
            Err(
                "The difference between the maximum and minimum counters is greater than the \
                     counter_slice field can hold."
                    .to_string()
            )
        );
    }
}

mod test_collab {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]

    //use crate::t0pology::PackFields;
    use crate::t0pology::*;
    use crate::t1queues::{WSFbackQueue, WSUdpLike, WSWaitQueue};
    use crate::w1types::WSQueueState;
    #[test]
    fn test_full_colab_test() {
        fn randr(mut inn: u64) -> u64 {
            for x in 17..47 {
                inn = inn.wrapping_add(inn.rotate_left(7));
                inn = inn.wrapping_mul(x);
                inn ^= inn
                    .wrapping_add(inn.rotate_left((x * 7) as u32 & 0b111_111))
                    .rotate_left(32);
            }
            inn
        }

        fn coof(cof: f32, rrr: u64) -> bool {
            let smalll = rrr.wrapping_add(rrr >> 32) as u32;

            (!0_u32) as f32 * cof > smalll as f32
        }

        fn shuffle<T>(array: &mut [T], s: u64) {
            let len = array.len();

            for i in (1..len).rev() {
                let j = (randr(i as u64 + s) % (i as u64 + 1)) as usize;
                array.swap(i, j);
            }
        }

        let fields = vec![PackFields::Counter(3)];

        let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

        let mut ctrs_que =
            WSFbackQueue::<f32>::new(pack_topology.counter_slice().unwrap().2, 130, 1000).unwrap();
        let mut wait_que: WSWaitQueue<String, f32> = WSWaitQueue::new(1000).unwrap();
        let mut udp_que: WSUdpLike<String> = WSUdpLike::new(1000).unwrap();
        assert!(ctrs_que.capacity() == 130);
        let mut net_steak = Vec::new();
        let mut net_steak_recv: Vec<Vec<u8>> = Vec::new();
        let mut un_blear_ctr = 0;

        let mut pack_to_inp = 0;

        let net_stable = 0.49990;

        let max_ctrs = 20_000;

        for time_soon in 0..3_0000000 {
            if un_blear_ctr >= max_ctrs - 1 {
                break;
            }

            if time_soon % 500 == 0 {
                println!(
                    "| stack:{:<5} | queue continuity:{:<5} | unconfirmed:{:<5} | not sent \
                         confirmation:{:<5} |",
                    udp_que.how_items_in_me(),
                    un_blear_ctr,
                    wait_que.elems_in_me(),
                    ctrs_que.elems_in_me()
                );
            }

            //send generrr
            if coof(0.7, randr(time_soon)) {
                {
                    //resending packets
                    let get_non_proff_ctr = wait_que.get_elements_to(time_soon as f32 * 1.1, None);

                    let get_non_proff_ctr = if let Some(x) = get_non_proff_ctr {
                        x
                    } else {
                        assert_eq!(wait_que.elems_in_me(), 0);
                        vec![]
                    };

                    for non_prosf in get_non_proff_ctr {
                        net_steak.push(non_prosf.0);
                        wait_que.remove(non_prosf.0).unwrap();
                        wait_que
                            .push(
                                non_prosf.0,
                                (time_soon as f32 * 1.1) + 20.0,
                                "str".to_string(),
                            )
                            .unwrap();
                    }
                    if pack_to_inp < max_ctrs {
                        //last k
                        net_steak.push(pack_to_inp);
                        if wait_que
                            .push(
                                pack_to_inp,
                                (time_soon as f32 * 1.1) + 20.0,
                                "str".to_string(),
                            )
                            .is_ok()
                        {
                            pack_to_inp += 1;
                        }
                    }
                }

                for xxx in net_steak_recv.iter() {
                    WSFbackQueue::delete_ctrs_in_byte_pack_from_ws_wait_queue(
                        &xxx[..],
                        pack_topology.counter_slice().unwrap().2,
                        &mut wait_que,
                    )
                    .unwrap();
                }
                net_steak_recv = Vec::new();
            }

            //seng//net unstable
            if net_steak.len() > 10 + randr(time_soon.rotate_left(6)) as usize % 10 {
                shuffle(&mut net_steak[..], time_soon.rotate_left(5));

                let mut mc_t = Vec::new();

                for x in net_steak.iter() {
                    //30% is loss 20% is dublicate
                    if coof(net_stable, randr(time_soon.rotate_left(6))) {
                        mc_t.push(*x);
                        if coof(1.0 - net_stable, randr(time_soon.rotate_left(7))) {
                            mc_t.push(*x);
                        }
                    }
                }
                net_steak = mc_t;
            } else {
                continue;
            }

            //recv
            for x in net_steak.iter() {
                let inert_in_rcv = !matches!(
                    udp_que.insert(*x, &"str".to_string()),
                    WSQueueState::ElemIdIsBig
                );
                if inert_in_rcv {
                    ctrs_que.push(*x, 0.2).unwrap();
                }
                //udp wue cheak
                for pack in udp_que.get_queue(None).unwrap_or(vec![]) {
                    if pack.0 > 0 {
                        if un_blear_ctr + 1 == pack.0 {
                            un_blear_ctr += 1;
                        } else {
                            panic!("ERR IN QUEQUE UDP!!!")
                        }
                    }
                }

                if ctrs_que.elems_in_me() > 6 + randr(time_soon.rotate_left(8)) as usize % 10 {
                    let mut ret = vec![0; ctrs_que.payload_len_in_bytes()];

                    let my_cur_p = ctrs_que.get_min_max_and_max_p().2.unwrap();

                    ctrs_que
                        .copy_ctrs_pack_to_slice(my_cur_p, &mut ret, false)
                        .unwrap();
                    net_steak_recv.push(ret);
                }
            }

            let mut t2 = Vec::new();

            for x2 in net_steak_recv.iter() {
                if coof(net_stable, randr(time_soon)) {
                    t2.push(x2.clone());
                }
            }
            net_steak_recv = t2.clone();

            //clear
            net_steak = Vec::new();
        }

        println!("{:?}", wait_que.get_elements_to(999999999999999999.0, None));
    }
}
