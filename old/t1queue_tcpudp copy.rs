// I HATE FUCKING RUST!

const U64_LEN_IN_BYTES: usize = 8;

pub mod recv_queue {
    use crate::t1pology::PackTopology;
    use crate::wutils;
    use crate::{t1fields, t1queue_tcpudp::U64_LEN_IN_BYTES};

    use std::fmt::Debug;
    use std::usize;
    use std::{
        collections::HashMap,
        hash::{BuildHasher, Hasher},
        u64,
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
    #[derive(Clone)]
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
    ///  which will be transferred to  split_byte_stream_into_packages(), and the remaining 10 bytes,
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

        pub fn split_byte_stream_into_packages(
            &mut self,
            data: &[u8],
        ) -> Result<Box<[Box<[u8]>]>, WSQueueErr> {
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
                        let mut boxed_slice =
                            vec![0u8; ptr_to_start - old_ret_pos].into_boxed_slice();
                        boxed_slice.copy_from_slice(&self.u_buf[old_ret_pos..ptr_to_start]);
                        ret_paks.push(boxed_slice);

                        old_ret_pos = ptr_to_start;
                    } else {
                        break;
                    };
                }
                //shifting elements that have already been processed and added to ret_paks
                if self.elems_in_buf > self.u_buf.len() {
                    panic!("is critical logic error: self.elems_in_buf >self.u_buf.len()")
                }

                if ptr_to_start > 0 && self.elems_in_buf > ptr_to_start {
                    self.u_buf.copy_within(ptr_to_start..self.elems_in_buf, 0);
                }

                //position changes so that the beginning is there, and the last raw element
                self.elems_in_buf = self
                    .elems_in_buf
                    .checked_sub(ptr_to_start)
                    .ok_or(WSQueueErr::Critical("err elems_in_buf sub= ptr_to_start"))?;
            }

            Ok(ret_paks.into_boxed_slice())
        }
    }

    #[derive(Debug)]
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

    ///The UDP packet queue accepts packets in random order,
    ///sorts them with O(1) sorting, and returns a continuous sequence of packets.
    ///For example, if the initial queue counter is 0,
    ///the queue accepted packets 7, 2, 1, 5, 3, 6.
    ///The queue will return a vector of elements 1,2,3.
    //Since there is no packet number 4 in the queue,
    ///the queue has a continuity gap and will wait for packet number 4.
    ///Upon receiving packet number 4, the queue will be able to return a vector of packets 4,5,6,7.
    #[derive(Clone)]
    pub struct WSUdpLike<T> {
        in_queue: usize,
        k_mod: usize,
        last_give_num: Option<u64>,
        data: Box<[Option<(u64, T)>]>,
    }

    impl<T: Clone> WSUdpLike<T> {
        pub fn new(sizecap: usize) -> Result<Self, WSQueueErr> {
            if sizecap == 0 {
                return Err(WSQueueErr::Critical("sizecap must be greater than zero"));
            }
            Ok(Self {
                in_queue: 0,
                k_mod: 0,
                last_give_num: None,
                data: vec![None; sizecap].into_boxed_slice(),
            })
        }
        /// insert(&mut self,item_ctr: u64, item: T)
        ///The element is u64, must always be increasing except when there are gaps
        ///  in the sequence, and must be unique. T is its data.
        pub fn insert(&mut self, item_ctr: u64, item: &T) -> WSQueueState {
            if item_ctr == u64::MAX {
                panic!("item_ctr == u64::MAX ")
            }

            let minimal_ctr = match self.last_give_num {
                Some(x) => x + 1,
                None => 0,
            };

            let pos = match item_ctr.checked_sub(minimal_ctr) {
                Some(diff) => diff as usize,
                None => return WSQueueState::ElemIdIsSmall,
            };

            if pos >= self.data.len() {
                return WSQueueState::ElemIdIsBig;
            }

            let elem_url = &mut self.data[(pos + self.k_mod) % self.data.len()];

            if elem_url.is_some() {
                return WSQueueState::ElemIsAlreadyIn;
            }

            *elem_url = Some((item_ctr, item.clone()));

            self.in_queue += 1;

            WSQueueState::SuccessfulInsertion
        }

        fn k_add(&mut self, addin: usize) {
            self.k_mod = (self.k_mod + addin) % self.data.len();
        }

        fn edit_my_state(&mut self, size_of_ret: usize, last_item_num: u64) {
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

            self.last_give_num = Some(last_item_num);
        }

        pub fn get_queue(&mut self) -> Box<[(u64, T)]> {
            let copied_slice: Box<[(u64, T)]> = self
                .data
                .iter()
                .cycle()
                .skip(self.k_mod)
                .take(self.data.len())
                .take_while(|opt| opt.is_some())
                .map(|opt| opt.as_ref().unwrap().clone())
                .collect::<Box<[_]>>();

            self.edit_my_state(
                copied_slice.len(),
                match copied_slice.last() {
                    Some(x) => x.0,

                    _ => {
                        return vec![].into_boxed_slice();
                    }
                },
            );

            copied_slice
        }

        pub fn how_items_in_queue(&self) -> usize {
            self.in_queue
        }
        pub fn last_num_get(&self) -> Option<u64> {
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
    #[derive(Default, Clone)]
    struct IdentityBuildHasher;

    impl BuildHasher for IdentityBuildHasher {
        type Hasher = IdentityHasher;

        fn build_hasher(&self) -> Self::Hasher {
            IdentityHasher::default()
        }
    }
    #[derive(Clone)]
    struct ElemMy<T, P> {
        cl: Option<u64>,
        cb: Option<u64>,
        data: T,
        p_order: P,
    }
    ///Queue of packets, access to get, remove, and push takes O(1),
    ///uses a hash table internally, the table was chosen because
    ///a binary tree showed extremely slow read and write operations in performance tests.
    #[derive(Clone)]
    pub struct WSWaitQueue<T, P> {
        data_map: HashMap<u64, ElemMy<T, P>, IdentityBuildHasher>,
        max_capacity_elems: usize,
        of_min_p: Option<(u64, P)>,
        of_max_p: Option<(u64, P)>,
        //last_elem_id: Option<u64>,
        //max_elem_p: Option<P>,
    }

    impl<T: Clone, P: PartialEq + PartialOrd + Clone> WSWaitQueue<T, P> {
        pub fn new(max_elems: usize) -> Result<Self, WSQueueErr> {
            if max_elems == 0 {
                return Err(WSQueueErr::Critical("max_elems is 0"));
            }

            Ok(WSWaitQueue {
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
                return Err("queue is full");
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
    #[derive(Clone)]
    pub struct WSRecvQueueCtrs {
        data: Box<[u64]>,
        ptr: usize,
        ctr_slice_len: usize,
        max: u64,
        min: u64,
    }

    impl WSRecvQueueCtrs {
        pub fn max_len_from_mtu(
            len_ctr_slise: usize,
            payload_mtu: usize,
        ) -> Result<usize, &'static str> {
            if len_ctr_slise == 0 {
                return Err("pack_topology
                .counter_slice() == 0");
            }
            let ctrs = payload_mtu
                .checked_sub(U64_LEN_IN_BYTES)
                .ok_or("mtu < (pack_topology.total_minimal_len() + U64_LEN_IN_BYTES )")?
                / len_ctr_slise;

            if ctrs == 0 {
                return Err("The MTU is too small to accommodate even one counter.");
            }

            return Ok(ctrs);
        }

        pub fn new(
            len_ctr_slise: usize,
            max_len: usize,
            payload_mtu: usize,
        ) -> Result<Self, &'static str> {
            if max_len > Self::max_len_from_mtu(len_ctr_slise, payload_mtu)? {
                return Err("The byte representation of the maximum length must be less than or equal to mtu.");
            }

            Ok(Self {
                data: vec![0; max_len].into_boxed_slice(),
                ptr: 0,
                ctr_slice_len: len_ctr_slise,
                max: 0,
                min: 0,
                //mtu,
            })
        }

        pub fn push(&mut self, ctr_elem: u64) -> Result<usize, &'static str> {
            if self.ptr >= self.data.len() {
                return Err("the queue is full");
            }
            self.max = if self.max > ctr_elem && 0 < self.ptr {
                self.max
            } else {
                ctr_elem
            };

            self.min = if self.min < ctr_elem && 0 < self.ptr {
                self.min
            } else {
                ctr_elem
            };

            if self.max.checked_sub(self.min).expect(
                "wtf broo. what the fuck is the minimum number MORE than the maximum fucking?",
            ) > wutils::len_byte_maximal_capacyty_cheak(self.ctr_slice_len).0
            {
                return Err("The difference between the maximum and minimum counters is greater than the counter_slice field can hold.");
            }

            self.data[self.ptr] = ctr_elem;
            self.ptr = self.ptr.checked_add(1).expect("counter overflow");

            Ok(self
                .data
                .len()
                .checked_sub(self.ptr)
                .expect("obvious algorithm error The pointer counter is always no longer than the length of the Box."))
        }

        pub fn payload_len_in_bytes(&self) -> usize {
            //U64_LEN_IN_BYTES + (self.ptr * self.ctr_slice_len)
            self.ptr
                .checked_mul(self.ctr_slice_len)
                .expect("self.payload_len()* self.ctr_slice_len overflow")
                .checked_add(U64_LEN_IN_BYTES)
                .expect("(self.payload_len()* self.ctr_slice_len) + U64_LEN_IN_BYTES overflow")
        }

        pub fn len(&self) -> usize {
            self.ptr
        }

        pub fn get_ctrs_as_vec(&mut self) -> Vec<u8> {
            let mut ret_vec = vec![0; self.payload_len_in_bytes()];

            self.get_ctrs_in_slice(&mut ret_vec)
                .expect("algorithm error; if the code has been tested, there should be no errors ");
            ret_vec
        }

        pub fn get_ctrs_in_slice(
            &mut self,
            pack_payload_slice: &mut [u8],
        ) -> Result<(), &'static str> {
            if self.payload_len_in_bytes() != pack_payload_slice.len() {
                return Err("self.payload_len() != pack_payload_slice.len()");
            }
            wutils::u64_to_1_8bytes(self.min, &mut pack_payload_slice[..U64_LEN_IN_BYTES])?;
            for sls in pack_payload_slice[U64_LEN_IN_BYTES..]
                .chunks_exact_mut(self.ctr_slice_len)
                .zip(self.data.iter())
            {
                wutils::u64_to_1_8bytes((*sls.1).checked_sub(self.min).expect("algorithm error, the minimum value must be less than any value in the array"), sls.0).unwrap();
            }

            self.ptr = 0;
            self.max = 0;
            self.min = 0;

            Ok(())
        }

        pub fn len_check<'a>(
            payload: &'a [u8],
            len_ctr_slise: usize,
        ) -> Result<(u64, usize, std::slice::ChunksExact<'a, u8>), &'static str> {
            let ret_len_ctrs = payload.len().checked_sub(U64_LEN_IN_BYTES)
            .ok_or("The packet length is less than the reference counter length, which is an invalid packet.")?;

            if 0 == len_ctr_slise {
                panic!("0 == len_ctr_slise")
            }

            if 0 != ret_len_ctrs % len_ctr_slise {
                return Err("The packet length is incorrect because the packet length (the length of the reference counter) is not a multiple of the counter field length in the packet topology.");
            }

            Ok((
                wutils::bytes_to_u64(&payload[..U64_LEN_IN_BYTES])?,
                ret_len_ctrs / len_ctr_slise,
                payload[U64_LEN_IN_BYTES..].chunks_exact(len_ctr_slise),
            ))
        }

        pub fn split_byte_ctrs_pack_to_vec(
            pack: &[u8],
            pack_topology: &PackTopology,
        ) -> Result<Vec<u64>, &'static str> {
            let len_ctr_slise = pack_topology
                .counter_slice()
                .ok_or("error in pack_topology no field for counter")?
                .2;

            let pre_pross = Self::len_check(pack, len_ctr_slise)?;

            let mut ret = vec![0; pre_pross.1];

            for (ctr_chank, ret_el) in pre_pross.2.zip(ret.iter_mut()) {
                *ret_el = pre_pross
                    .0
                    .checked_add(wutils::bytes_to_u64(ctr_chank)?)
                    .ok_or("The reference counter + one of the delta counters caused overflow operations; most likely, the packet has an error.")?;
            }

            Ok(ret)
        }

        pub fn delete_ctrs_in_byte_pack_from_ws_wait_queue<T, P>(
            pack: &[u8],
            len_ctr_slise: usize,
            wait_queue: &mut WSWaitQueue<T, P>,
        ) -> Result<usize, &'static str>
        where
            T: Clone + Debug,
            P: PartialEq + PartialOrd + Clone + Debug,
        {
            let pre_pross = Self::len_check(pack, len_ctr_slise)?;
            let mut how_was_deleted = 0;
            for ctr_chank in pre_pross.2 {
                let ret_el = pre_pross
                    .0
                    .checked_add(wutils::bytes_to_u64(ctr_chank)?)
                    .ok_or("The reference counter + one of the delta counters caused overflow operations; most likely, the packet has an error.")?;

                how_was_deleted += wait_queue.remove(ret_el).is_some() as usize & 1;
            }

            Ok(how_was_deleted)
        }

        pub fn get_min_max(&self) -> (u64, u64) {
            (self.min, self.max)
        }
    }
}
