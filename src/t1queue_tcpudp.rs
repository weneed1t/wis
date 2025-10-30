// I HATE FUCKING RUST!

pub mod recv_queue {
    use crate::t1fields;
    use crate::t1pology::PackTopology;
    use std::{
        collections::HashMap,
        hash::{BuildHasher, Hasher},
    };

    #[cfg_attr(test, derive(Debug))]
    pub enum WSQueueErr {
        NonCritical(&'static str),
        Critical(&'static str),
    }

    impl WSQueueErr {
        pub fn is_critical(&self) -> bool {
            match self {
                WSQueueErr::Critical(_) => true,
                WSQueueErr::NonCritical(_) => false,
            }
        }

        pub fn is_non_critical(&self) -> bool {
            match self {
                WSQueueErr::Critical(_) => false,
                WSQueueErr::NonCritical(_) => true,
            }
        }
    }

    impl PartialEq for WSQueueErr {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (WSQueueErr::NonCritical(x), WSQueueErr::NonCritical(y)) => {
                    if x == y {
                        true
                    } else {
                        false
                    }
                }
                (WSQueueErr::Critical(x), WSQueueErr::Critical(y)) => {
                    if x == y {
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }
    }
    pub struct WSTcpLike {
        elems_in_buf: usize,
        u_buf: Box<[u8]>,
        pack_topology: PackTopology,
        mtu: usize,
        crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    }
    ///TCP queue, already directly related to conversion into packets from a TCP data stream,
    ///  since such data exchange protocols do not divide data into packets at the user level
    ///  and provide abstraction only as a data stream.
    ///  When sending packets 1 (100 bytes long) 2 (150 bytes long) 3 (50 bytes long)
    ///  , the recipient will receive a continuous stream of 300 bytes.
    ///  To split it into packets, the WSTcpLike class is used.
    ///  A stream of 300 bytes is passed to it,
    ///  and the output is the packets that were sent: 1 (100 bytes long) 2 (150 bytes long) 3 (50 bytes long).

    ///Note that WSTcpLike is resistant to packets being split during transmission,
    /// for example, a stream of three concatenated packets 1 (100 bytes long) 2 (150 bytes long) 3 (50 bytes long),
    /// will be partially accepted as a stream of 290 bytes,
    ///  which will be transferred to  buf_in(), and the remaining 10 bytes,
    ///  then WSTcpLike will return two separate packets 1 (100 bytes long) 2(150 bytes long),
    ///  after which it will wait to receive the remaining part of packet number 3 (10 bytes),
    ///  and then return packet number 3 (50 bytes long).
    impl WSTcpLike {
        pub fn new(
            mtu: usize,
            pack_topology: PackTopology,
            crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
        ) -> Result<Self, WSQueueErr> {
            if pack_topology.len_slice().is_none() {
                return Err(WSQueueErr::Critical("pack_topology.len_slice() is none"));
            }

            Ok(Self {
                elems_in_buf: 0,
                u_buf: vec![0; mtu].into_boxed_slice(),
                pack_topology,
                mtu,
                crcfn,
            })
        }

        pub fn buf_in(&mut self, data: &[u8]) -> Result<Box<[Box<[u8]>]>, WSQueueErr> {
            let _ = self
                .pack_topology
                .len_slice()
                .ok_or(WSQueueErr::Critical("pack_topology.len_slice() is none"))?;

            let min_len = self.pack_topology.total_minimal_len();
            let mut ret_paks: Vec<Box<[u8]>> = Vec::with_capacity(10);
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
                    let buf_void = self.u_buf.len().checked_sub(self.elems_in_buf).ok_or(
                        WSQueueErr::Critical("err in u_buf.len() checked_sub elems_in_buf <0"),
                    )?;

                    let data_elems =
                        data.len()
                            .checked_sub(pos_in_data)
                            .ok_or(WSQueueErr::Critical(
                                "err data.len() checked_sub pos_in_data >0",
                            ))?;

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
                self.elems_in_buf = self.elems_in_buf.checked_add(copy_elems_to_buf).ok_or(
                    WSQueueErr::Critical("err elems_in_buf add= copy_elems_to_buf"),
                )?;
                pos_in_data =
                    pos_in_data
                        .checked_add(copy_elems_to_buf)
                        .ok_or(WSQueueErr::Critical(
                            "err in pos_in_data + opy_elems_to_buf",
                        ))?;

                let mut ptr_to_start = 0;
                let mut old_ret_pos: usize = 0;
                while ptr_to_start < self.elems_in_buf {
                    let elem_in_buf_quque = self
                        .elems_in_buf
                        .checked_sub(ptr_to_start)
                        .ok_or(WSQueueErr::Critical("err elems_in_buf sub ptr_to_start"))?;

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
                                self.crcfn.ok_or(WSQueueErr::Critical("crcfn is none"))?,
                            )
                            .map_err(|err| WSQueueErr::Critical(err.err_to_str()))?
                            {
                                return Err(WSQueueErr::Critical("package is damaged"));
                            }
                        }

                        //getting the length of the packet from the length field in the packet.
                        let len_of_curent_pack =
                            t1fields::get_len(&self.u_buf[ptr_to_start..], &self.pack_topology)
                                .map_err(|err| WSQueueErr::Critical(err.err_to_str()))?;
                        //if the length value in the length field is greater than MTU,
                        // then the packet is corrupted, an error is caused.
                        if len_of_curent_pack > self.mtu {
                            return Err(WSQueueErr::Critical("len_of_curent_pack > mtu"));
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
                    .ok_or(WSQueueErr::Critical("err elems_in_buf sub= ptr_to_start"))?;
            }

            Ok(ret_paks.into_boxed_slice())
        }
    }
    ///The UDP packet queue accepts packets in random order,
    ///sorts them with O(1) sorting, and returns a continuous sequence of packets.
    ///For example, if the initial queue counter is 0,
    ///the queue accepted packets 7, 2, 1, 5, 3, 6.
    ///The queue will return a vector of elements 1,2,3.
    //Since there is no packet number 4 in the queue,
    ///the queue has a continuity gap and will wait for packet number 4.
    ///Upon receiving packet number 4, the queue will be able to return a vector of packets 4,5,6,7.
    pub struct WSUdpLike<T> {
        in_queue: usize,
        k_mod: usize,
        last_give_num: usize,
        data: Box<[Option<(usize, T)>]>,
        was_get_queue: bool,
    }

    impl<T: Clone> WSUdpLike<T> {
        pub fn new(sizecap: usize) -> Result<Self, WSQueueErr> {
            if sizecap == 0 {
                return Err(WSQueueErr::Critical("sizecap must be greater than zero"));
            }
            Ok(Self {
                in_queue: 0,
                k_mod: 0,
                last_give_num: 0,
                data: vec![None; sizecap].into_boxed_slice(),
                was_get_queue: false,
            })
        }
        /// insert(&mut self, item: (usize, T))
        ///The element is usize, must always be increasing except when there are gaps
        ///  in the sequence, and must be unique. T is its data.
        pub fn insert(&mut self, item: (usize, T)) -> Result<(), WSQueueErr> {
            if item.0 < self.last_give_num {
                return Err(WSQueueErr::NonCritical("Elem Id Is Small"));
            }

            let pos = (item.0 - self.last_give_num) - self.was_get_queue as usize;

            if pos >= self.data.len() {
                return Err(WSQueueErr::NonCritical("Elem Id Is Big"));
            }

            let elem_url = &mut self.data[(pos + self.k_mod) % self.data.len()];

            if elem_url.is_some() {
                return Err(WSQueueErr::NonCritical("Elem Is Already In"));
            }

            *elem_url = Some(item);

            self.in_queue += 1;

            Ok(())
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

    #[derive(Default)]
    struct IdentityHasher {
        hash: u64,
    }
    //This hash table does not require a reliable hash function, as each packet has its own ID.
    impl Hasher for IdentityHasher {
        fn finish(&self) -> u64 {
            self.hash
        }

        fn write(&mut self, bytes: &[u8]) {
            self.hash = u64::from_ne_bytes(bytes.try_into().unwrap());
        }

        fn write_u64(&mut self, i: u64) {
            self.hash = i;
        }
    }
    #[derive(Default)]
    struct IdentityBuildHasher;

    impl BuildHasher for IdentityBuildHasher {
        type Hasher = IdentityHasher;

        fn build_hasher(&self) -> Self::Hasher {
            IdentityHasher::default()
        }
    }
    struct ElemMy<T, P> {
        cl: Option<u64>,
        cb: Option<u64>,
        data: T,
        p_order: P,
    }
    ///Queue of packets, access to get, remove, and push takes O(1),
    ///uses a hash table internally, the table was chosen because
    ///a binary tree showed extremely slow read and write operations in performance tests.
    pub struct WaitQueue<T, P> {
        data_map: HashMap<u64, ElemMy<T, P>, IdentityBuildHasher>,
        max_capacity_elems: usize,
        of_min_p: Option<(u64, P)>,
        of_max_p: Option<(u64, P)>,
        //last_elem_id: Option<u64>,
        //max_elem_p: Option<P>,
    }

    impl<T: Clone, P: PartialEq + PartialOrd + Clone> WaitQueue<T, P> {
        pub fn new(max_elems: usize) -> Result<Self, WSQueueErr> {
            if max_elems == 0 {
                return Err(WSQueueErr::Critical("max_elems is 0"));
            }

            Ok(WaitQueue {
                //data_map: HashMap::with_capacity_and_hasher(max_elems, IdentityBuildHasher),
                data_map: HashMap::with_hasher(IdentityBuildHasher),
                max_capacity_elems: max_elems,
                of_max_p: None,
                of_min_p: None,
                //last_elem_id: None,
                //max_elem_p: None,
            })
        }
        /// Inserting an element, id is the unique id of the element in the hash table,
        /// p_order is a check object, usually f32/f64 or u32/64.
        /// If p_order is greater than all p_orders currently in the table,
        /// the insertion occurs in O(1); if p_order is smaller,
        /// forse_to_max_p if  == true, then if the value of p_order is less than max_elem_id_and_p,
        /// the element will be added, but its p_order will be equal to max_elem_id_and_p;
        ///  if forse_to_max_p if  == false, then if the value of p_order for the element is
        ///  less than max_elem_id_and_p, an error will be triggered.
        pub fn push(
            &mut self,
            id: u64,
            p_order: P,
            forse_to_max_p: bool,
            elem: T,
        ) -> Result<(), &'static str> {
            if self.data_map.len() >= self.max_capacity_elems {
                return Err("queue is overflowing");
            }
            let mut p_order = p_order;
            if let Some(mp) = &mut self.of_max_p {
                if forse_to_max_p {
                    p_order = mp.1.clone();
                }
                if mp.1 > p_order {
                    return Err("self.max_elem_p < p_order");
                }
            }

            match self.data_map.entry(id) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err("this id elem is already in");
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ElemMy {
                        cl: None,
                        cb: self.of_max_p.as_ref().map(|x| x.0),
                        data: elem,
                        p_order: p_order.clone(),
                    });
                }
            };

            if let Some(lei) = self.of_max_p.as_ref().map(|x| x.0) {
                let  last_elem = self.data_map.get_mut(&lei).expect("a critical condition that shouldn't exist, an element is missing, but it's impossible");
                last_elem.cl = Some(id);
            }
            self.of_max_p = Some((id, p_order.clone()));
            //if self.of_max_p.is_none() {
            //    if self.data_map.len() == 0 {
            //        panic!("Critically incorrect algorithm behavior! There are elements in data_map, but the value of id_of_max_p is undefined!");
            //    }
            //    self.of_max_p = Some((id, p_order.clone()));
            //}
            if self.of_min_p.is_none() {
                if self.data_map.len() == 0 {
                    panic!("Critically incorrect algorithm behavior! There are elements in data_map, but the value of id_of_min_p is undefined!");
                }
                self.of_min_p = Some((id, p_order.clone()));
            }

            Ok(())
        }
        ///Deleting an element.
        ///Each element has a pointer in the form of an id
        ///cl -> means the next element
        ///cb -> means the previous element
        pub fn remove(&mut self, id: u64) -> Option<(T, P)> {
            //take an element by its id value and delete it from the table
            let removed_elem = self.data_map.remove(&id);

            let removed_elem = if removed_elem.is_none() {
                return None;
            } else {
                removed_elem.unwrap()
            };
            // example:
            // | id:10 ,cb:None,cl:2 |---> | id:2 ,cb:10,cl:7 |---> | id:7 ,cb:2,cl:15 |---> | id:15 ,cb:7,cl:None |--->

            //  delete id:2 elem:
            // | id:10 ,cb:None,cl:2 |---> |________None______|---> | id:7 ,cb:2,cl:15 |---> | id:15 ,cb:7,cl:None |--->

            //swap:
            //Exchange ID pointers in the table:
            //When deleting element number 2, obtain the cl of element cb, then 2cl and 2cb, then exchange the pointers.
            //For element number 2cl, change the cb field to the value 2cb; for element number 2cb, change the cl field value to the value 2cl.
            // 10cl = 2cl
            // 7cb = 2cb
            // | id:10 ,cb:None,cl:7 |---> | id:7 ,cb:10,cl:15 |---> | id:15 ,cb:7,cl:None |--->

            if let Some(x_cb) = removed_elem.cb {
                let cb_elem = self.data_map.get_mut(&x_cb)
                .expect("critical condition, the .cb counter points to an element that is not in the table");
                cb_elem.cl = removed_elem.cl
            }

            if let Some(x_cl) = removed_elem.cl {
                let cl_elem = self.data_map.get_mut(&x_cl)
                .expect("critical condition, the .cl counter points to an element that is not in the table");
                cl_elem.cb = removed_elem.cb
            }

            //If the deleted element was the element with the largest P,
            //then the global pointer to the largest element is updated to the one that was before the deleted element.
            if let Some(last_elem_id) = self.of_max_p.as_ref() {
                if last_elem_id.0 == id {
                    if let Some(cb_id) = removed_elem.cb.as_ref() {
                        self.of_max_p =
                            Some((*cb_id, self.data_map.get(&cb_id).expect("Critical error: incorrect logic, link to previous element exists, but it is missing from the table.").p_order.clone()));
                    } else {
                        self.of_max_p = None;
                    }
                }
            } else {
                panic!("Critically incorrect algorithm behavior! There are elements in data_map, but the value of id_of_max_p is undefined!");
            }
            //If the deleted element was the element with the smallest P,
            //then the global pointer to the smallest element is updated to the one that was next after the deleted element.
            if let Some(first_elem_id) = self.of_min_p.as_ref() {
                if first_elem_id.0 == id {
                    if let Some(cl_id) = removed_elem.cl.as_ref() {
                        self.of_min_p =
                            Some((*cl_id, self.data_map.get(&cl_id).expect("Critical error: incorrect logic, link does not exist, but it is missing from the table.").p_order.clone()));
                    } else {
                        self.of_min_p = None;
                    }
                }
            } else {
                panic!("Critically incorrect algorithm behavior! There are elements in data_map, but the value of id_of_max_p is undefined!");
            }

            Some((removed_elem.data, removed_elem.p_order.clone()))
        }
        //returns all elements whose p_order value is less than or equal to p_order_limit as a list Vec<(u64, P, T)>,
        // where u64 is its id, P is its p_order, and T is the data itself
        pub fn get_elements_to(&mut self, p_order_limit: P) -> Vec<(u64, P, T)> {
            if self.data_map.len() == 0 {
                return Vec::new();
            }

            let first = if let Some(ret) = self.of_min_p.as_ref() {
                ret.0
            } else {
                panic!("Critically incorrect algorithm behavior! There are elements in data_map, but the value of id_of_min_p is undefined!");
            };
            //self.data_map.len() / 3 is the optimal value,
            //as it is assumed that the queue will wait for packets, and the packets can be in three places:
            //1 place is in the network awaiting receipt
            //2 packets are received by the recipient and await transmission
            //3 the recipient sends confirmation packets to the network
            //Therefore, in the vast majority of cases, the queue of unconfirmed packets will not exceed 1/3 of the total number of packets.
            let mut reta_vec = Vec::with_capacity(self.data_map.len() / 3);

            let mut temp_id = first;

            for x in 0..self.data_map.len() {
                let temp = self
                    .data_map
                    .get(&temp_id)
                    .expect("critical condition, there is a gap in the queue ");
                if p_order_limit >= temp.p_order {
                    reta_vec.push((temp_id, temp.p_order.clone(), temp.data.clone()));
                }
                //The last element in the sequence does not have a reference to the next element,
                //so if x + 1 == self.data_map.len(),
                //then this element is the last one and there is no need to take cl from it, since it is None.
                if x + 1 == self.data_map.len() {
                    break;
                }
                temp_id = temp
                    .cl
                    .expect("critical condition, there is a gap in the queue ");
            }

            reta_vec
        }

        pub fn len(&self) -> usize {
            self.data_map.len()
        }

        pub fn max_elem_id_and_p(&self) -> Option<(u64, P)> {
            self.of_max_p.as_ref().map(|x| (x.0, x.1.clone()))
        }

        pub fn min_elem_id_and_p(&self) -> Option<(u64, P)> {
            self.of_min_p.as_ref().map(|x| (x.0, x.1.clone()))
        }
    }
    #[cfg(test)]
    mod test_wait {
        use super::*;

        #[test]
        fn test_one() {
            assert_eq!(WaitQueue::<bool, u32>::new(0).is_err(), true);

            let mut waa = WaitQueue::<bool, u32>::new(10).unwrap();

            let max_x = 10;
            let addrt = 10;
            assert_eq!(waa.len(), 0);
            assert_eq!(waa.max_elem_id_and_p(), None);
            assert_eq!(waa.min_elem_id_and_p(), None);

            for x in addrt..max_x + addrt {
                let res = waa.push(x * 2, x as u32, false, true);
                assert_eq!(res, Ok(()));

                assert_eq!(waa.max_elem_id_and_p(), Some((x * 2, x as u32)));
                assert_eq!(waa.min_elem_id_and_p(), Some((addrt * 2, addrt as u32)));
                assert_eq!(waa.len(), (1 + x - addrt) as usize);
                //println!("{}", x)
            }

            for x in waa.data_map.iter() {
                println!(" id: {} cb:{:?} cl {:?}", x.0, x.1.cb, x.1.cl);
            }

            assert_eq!(
                waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                    .iter()
                    .map(|x| (x.0.clone() / 2) - addrt)
                    .collect::<Vec<u64>>(),
                (0..max_x).collect::<Vec<u64>>()
            );
        }

        #[test]
        fn test_main() {
            {
                let mut waa = WaitQueue::<bool, u32>::new(10).unwrap();

                let max_x = 10;
                //let addrt = 10;
                assert_eq!(waa.len(), 0);
                assert_eq!(waa.max_elem_id_and_p(), None);
                assert_eq!(waa.min_elem_id_and_p(), None);

                for x in 0..max_x {
                    let res = waa.push(x, x as u32, false, true);
                    assert_eq!(res, Ok(()));

                    assert_eq!(waa.max_elem_id_and_p(), Some((x, x as u32)));
                    assert_eq!(waa.min_elem_id_and_p(), Some((0, 0)));
                    assert_eq!(waa.len(), (1 + x) as usize);
                }
                /*
                                for x in waa.data_map.iter() {
                                    println!(
                                        " id: {} cb:{:?} cl {:?} p{:?}",
                                        x.0,
                                        x.1.cb,
                                        x.1.cl,
                                        x.1.p_order.clone()
                                    );
                                }
                */
                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| (x.0.clone()))
                        .collect::<Vec<u64>>(),
                    (0..max_x).collect::<Vec<u64>>()
                );

                waa.remove(4).unwrap();

                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| (x.0.clone()))
                        .collect::<Vec<u64>>(),
                    vec![0, 1, 2, 3, 5, 6, 7, 8, 9]
                );

                waa.remove(5).unwrap();
                waa.remove(7).unwrap();
                waa.remove(1).unwrap();
                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| (x.0.clone()))
                        .collect::<Vec<u64>>(),
                    vec![0, 2, 3, 6, 8, 9]
                );

                assert_eq!(waa.max_elem_id_and_p(), Some((9, 9)));
                assert_eq!(waa.min_elem_id_and_p(), Some((0, 0)));

                waa.remove(9).unwrap();

                assert_eq!(waa.max_elem_id_and_p(), Some((8, 8)));

                waa.remove(8).unwrap();

                assert_eq!(waa.max_elem_id_and_p(), Some((6, 6)));
                assert_eq!(waa.min_elem_id_and_p(), Some((0, 0)));

                waa.remove(0).unwrap();

                assert_eq!(waa.min_elem_id_and_p(), Some((2, 2)));

                waa.push(10, 10, false, true).unwrap();
                waa.push(20, 1000, false, true).unwrap();

                assert_eq!(waa.push(30, 999, false, true).is_err(), true);
                assert_eq!(waa.push(30, 1000, false, true).is_ok(), true); //is ok !!!!! order <= p

                assert_eq!(waa.push(30, 1000000, false, true).is_err(), true);
                assert_eq!(waa.push(31, 1001, false, true).is_ok(), true); //is ok !!!!! order <= p\

                waa.remove(2).unwrap();
                waa.remove(20).unwrap();
                waa.remove(6).unwrap();
                waa.remove(10).unwrap();

                assert_eq!(waa.push(50, 0, true, true).is_ok(), true);
                assert_eq!(waa.push(51, 43, true, true).is_ok(), true);
                assert_eq!(waa.push(52, 6, true, true).is_ok(), true);
                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| (x.0.clone()))
                        .collect::<Vec<u64>>(),
                    vec![3, 30, 31, 50, 51, 52]
                );

                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| (x.1.clone()))
                        .collect::<Vec<u32>>(),
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
                assert_eq!(waa.len(), 1);
                waa.remove(3).unwrap();

                assert_eq!(waa.max_elem_id_and_p(), None);
                assert_eq!(waa.min_elem_id_and_p(), None);
                assert_eq!(waa.len(), 0);
            }
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
                t1fields::set_get_head_crc(true, &mut packet, &pack_topology, dummy_crc_gen)
                    .unwrap();
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

            let mut w_tcp = WSTcpLike::new(41, datas_x.4, Some(dummy_crc_gen)).unwrap();
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

            let mut w_tcp = WSTcpLike::new(39, datas_x.4, Some(dummy_crc_gen)).unwrap();

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
                    assert_eq!(ret, Err(WSQueueErr::Critical("len_of_curent_pack > mtu")));
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
            let mut w_tcp = WSTcpLike::new(39, datas_x.4, Some(dummy_crc_gen)).unwrap();
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
                    assert_eq!(ret, Err(WSQueueErr::Critical("package is damaged")));
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
            let mut xx: WSUdpLike<u32> = WSUdpLike::new(50).unwrap();

            let mut xxx = 0_usize;
            for _ in 0..30_usize {
                for az in 0..50usize {
                    let _ = xx.insert((xxx + (az + 17) % 50, 0));

                    if az % 5 == 0 {
                        if let Err(x) = xx.insert((xxx + (az + 17) % 50, 0)) {
                            if x.is_critical() {
                                assert!(false, "{:?}", x)
                            }
                        }
                    }

                    if az % 11 == 0 && az > 60 {
                        if let Err(x) = xx.insert((xxx + (az + 17) % 10, 0)) {
                            if x.is_critical() {
                                assert!(false, "{:?}", x)
                            }
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
            let mut xx: WSUdpLike<u32> = WSUdpLike::new(50).unwrap();

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
            let mut xx: WSUdpLike<u32> = WSUdpLike::new(123).unwrap();

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
            let mut xx: WSUdpLike<f32> = WSUdpLike::new(8).unwrap();

            assert_eq!(xx.insert((4, 0.0)), Ok(())); //1
            assert_eq!(xx.insert((0, 0.0)), Ok(())); //2
            assert_eq!(xx.insert((2, 0.0)), Ok(())); //3
            assert_eq!(xx.insert((3, 0.0)), Ok(())); //4
            assert_eq!(xx.insert((5, 0.0)), Ok(())); //5
            assert_eq!(xx.insert((6, 0.0)), Ok(())); //6
            assert_eq!(xx.insert((7, 0.0)), Ok(())); //7
            assert_eq!(
                xx.insert((8, 0.0)),
                Err(WSQueueErr::NonCritical("Elem Id Is Big"))
            ); //8
            assert_eq!(
                xx.insert((3, 0.0)),
                Err(WSQueueErr::NonCritical("Elem Is Already In"))
            ); //9
            assert_eq!(xx.insert((1, 0.0)), Ok(())); //10

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

            assert_eq!(xx.insert((9, 0.0)), Ok(()));
            assert_eq!(xx.insert((11, 0.0)), Ok(()));
            assert_eq!(xx.insert((12, 0.0)), Ok(()));
            assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

            assert_eq!(xx.insert((10, 0.0)), Ok(()));
            assert_eq!(xx.insert((13, 0.0)), Ok(()));
            assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

            assert_eq!(xx.insert((8, 0.0)), Ok(()));
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

            assert_eq!(
                xx.insert((22, 0.0)),
                Err(WSQueueErr::NonCritical("Elem Id Is Big"))
            );
            assert_eq!(xx.insert((21, 0.0)), Ok(()));
            assert_eq!(
                xx.insert((2, 0.0)),
                Err(WSQueueErr::NonCritical("Elem Id Is Small"))
            );
            assert_eq!(xx.insert((14, 0.0)), Ok(()));
            assert_eq!(xx.get_queue(), (vec![(14, 0.0)]).into_boxed_slice());

            assert_eq!(xx.insert((15, 0.0)), Ok(()));
            assert_eq!(xx.insert((16, 0.0)), Ok(()));

            assert_eq!(xx.insert((17, 0.0)), Ok(()));
            assert_eq!(xx.insert((18, 0.0)), Ok(()));
            assert_eq!(xx.insert((19, 0.0)), Ok(()));
            assert_eq!(xx.insert((20, 0.0)), Ok(()));

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

            let mut xx: WSUdpLike<f32> = WSUdpLike::new(7).unwrap();

            assert_eq!(xx.insert((0, 0.0)), Ok(())); //1
            assert_eq!(xx.insert((1, 0.0)), Ok(())); //2
            assert_eq!(xx.insert((2, 0.0)), Ok(())); //3
            assert_eq!(xx.insert((3, 0.0)), Ok(())); //4
            assert_eq!(xx.insert((4, 0.0)), Ok(())); //5
            assert_eq!(xx.insert((5, 0.0)), Ok(())); //6
            assert_eq!(xx.insert((6, 0.0)), Ok(())); //7
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

            let mut xx: WSUdpLike<f32> = WSUdpLike::new(7).unwrap();

            assert_eq!(xx.insert((0, 0.0)), Ok(())); //1
            assert_eq!(xx.in_queue, 1);
            assert_eq!(xx.get_queue(), (vec![(0, 0.0)]).into_boxed_slice());

            assert_eq!(xx.insert((1, 0.0)), Ok(())); //2
            assert_eq!(xx.in_queue, 1);
            assert_eq!(
                xx.get_queue(),
                (vec![(1, 0.0)]).into_boxed_slice(),
                "{:?}",
                xx.data
            );

            assert_eq!(xx.insert((2, 0.0)), Ok(())); //3

            assert_eq!(xx.in_queue, 1);
            assert_eq!(xx.get_queue(), (vec![(2, 0.0)]).into_boxed_slice());

            assert_eq!(xx.insert((3, 0.0)), Ok(())); //4
            assert_eq!(xx.in_queue, 1);
            assert_eq!(xx.get_queue(), (vec![(3, 0.0)]).into_boxed_slice());

            assert_eq!(xx.insert((4, 0.0)), Ok(())); //5
            assert_eq!(xx.insert((5, 0.0)), Ok(())); //6
            assert_eq!(xx.insert((6, 0.0)), Ok(())); //7
            assert_eq!(xx.insert((7, 0.0)), Ok(())); //5
            assert_eq!(xx.insert((8, 0.0)), Ok(())); //6
            assert_eq!(xx.insert((9, 0.0)), Ok(())); //7
            assert_eq!(xx.insert((10, 0.0)), Ok(())); //5
            assert_eq!(
                xx.insert((11, 0.0)),
                Err(WSQueueErr::NonCritical("Elem Id Is Big"))
            ); //6
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
        /*
        use std::time;

        #[test]
        fn ets() {
            let std_start = time::Instant::now();

            let mut kd: WSUdpLike<u32> = WSUdpLike::new(100).unwrap();

            for x in 0..23_000_000 {
                kd.insert((x, 1));

                if x % 90 == 0 {
                    let _ = kd.get_queue();
                }
            }

            println!("{:}", std_start.elapsed().as_secs_f32());
            //assert!(false)
        }*/
    }
}
