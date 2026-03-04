// I HATE FUCKING RUST!

const U64_LEN_IN_BYTES: usize = 8;

pub mod recv_queue {
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::hash::{BuildHasher, Hasher};

    use crate::t0pology::PackTopology;
    use crate::t1queue_tcpudp::U64_LEN_IN_BYTES;
    use crate::{t1fields, wutils};

    #[cfg_attr(test, derive(Debug))]
    pub enum WSQueueErr {
        NonCritical(&'static str),
        Critical(&'static str),
    }

    impl WSQueueErr {
        pub fn is_critical(&self) -> bool {
            match self {
                Self::Critical(_) => true,
                Self::NonCritical(_) => false,
            }
        }

        pub fn is_non_critical(&self) -> bool {
            match self {
                Self::Critical(_) => false,
                Self::NonCritical(_) => true,
            }
        }
    }

    impl PartialEq for WSQueueErr {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::NonCritical(x), Self::NonCritical(y)) => x == y,
                (Self::Critical(x), Self::Critical(y)) => x == y,
                _ => false,
            }
        }
    }
    #[derive(Clone)]
    pub struct WSTcpLike<'a> {
        elems_in_buf: usize,
        u_buf: Box<[u8]>,
        pack_topology: &'a PackTopology,
        mtu: usize,
        crcfn: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    }
    ///TCP queue, already directly related to conversion into packets from a TCP data
    /// stream,  since such data exchange protocols do not divide data into packets at
    /// the user level  and provide abstraction only as a data stream.
    ///  When sending packets 1 (100 bytes long) 2 (150 bytes long) 3 (50 bytes long)
    ///  , the recipient will receive a continuous stream of 300 bytes.
    ///  To split it into packets, the WSTcpLike class is used.
    ///  A stream of 300 bytes is passed to it,
    ///  and the output is the packets that were sent: 1 (100 bytes long) 2 (150 bytes
    /// long) 3 (50 bytes long).
    ///
    ///Note that WSTcpLike is resistant to packets being split during transmission,
    /// for example, a stream of three concatenated packets 1 (100 bytes long) 2 (150
    /// bytes long) 3 (50 bytes long), will be partially accepted as a stream of 290
    /// bytes,  which will be transferred to  split_byte_stream_into_packages(), and
    /// the remaining 10 bytes,  then WSTcpLike will return two separate packets 1
    /// (100 bytes long) 2(150 bytes long),  after which it will wait to receive the
    /// remaining part of packet number 3 (10 bytes),  and then return packet number 3
    /// (50 bytes long).
    impl<'a> WSTcpLike<'a> {
        pub fn new(
            mtu: usize,
            pack_topology: &'a PackTopology,
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

            while pos_in_data < data.len() {
                // check. choosing the shorter length.
                // since there are two stores, 1 is the amount of free space in the buffer,
                // 2 is the number of elements that need to be processed in data[].
                // a lower value is selected and as many elements are copied from data to the
                // buffer. elems_in_buf means how many elements are in
                // the buffer and u_buf.len()-elems_in_buf means how much free space is in the
                // buffer. data.len()-pos_in_data means how many elements are left
                // in the data. pos_in_data and elems_in_buf are offsets for u_buf
                // and data[], respectively.
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
                self.u_buf[self.elems_in_buf
                    ..self
                        .elems_in_buf
                        .checked_add(copy_elems_to_buf)
                        .expect("err in elems_in_buf + copy_elems_to_buf")]
                    .copy_from_slice(
                        &data[pos_in_data
                            ..pos_in_data
                                .checked_add(copy_elems_to_buf)
                                .expect("err in pos_in_data + copy_elems_to_buf")],
                    );

                //Updating offsets to copy_elems_to_buf value
                self.elems_in_buf = self.elems_in_buf.checked_add(copy_elems_to_buf).ok_or(
                    WSQueueErr::Critical("err elems_in_buf add= copy_elems_to_buf"),
                )?;
                pos_in_data =
                    pos_in_data
                        .checked_add(copy_elems_to_buf)
                        .ok_or(WSQueueErr::Critical(
                            "err in pos_in_data + copy_elems_to_buf",
                        ))?;

                let mut ptr_to_start: usize = 0;
                let mut old_ret_pos: usize = 0;
                while ptr_to_start < self.elems_in_buf {
                    let elem_in_buf_quque = self
                        .elems_in_buf
                        .checked_sub(ptr_to_start)
                        .ok_or(WSQueueErr::Critical("err elems_in_buf sub ptr_to_start"))?;

                    //if the length of the data in the buffer is greater than the minimum packet
                    // size, it means that you can read the packet length fields
                    // to find out its end.
                    if elem_in_buf_quque >= min_len {
                        //if the package has a crc signature of the head data,
                        // then it must be checked. if the data is intact, add it to ret_paks
                        if self.pack_topology.head_crc_slice().is_some()
                            && !t1fields::set_get_head_crc(
                                false,
                                &mut self.u_buf[ptr_to_start..],
                                self.pack_topology,
                                self.crcfn.ok_or(WSQueueErr::Critical("crcfn is none"))?,
                            )
                            .map_err(|err| WSQueueErr::Critical(err.err_to_str()))?
                        {
                            return Err(WSQueueErr::Critical("package is damaged"));
                        }

                        //getting the length of the packet from the length field in the packet.
                        let len_of_curent_pack =
                            t1fields::get_len(&self.u_buf[ptr_to_start..], self.pack_topology)
                                .map_err(|err| WSQueueErr::Critical(err.err_to_str()))?;
                        //if the length value in the length field is greater than MTU,
                        // then the packet is corrupted, an error is caused.
                        if len_of_curent_pack > self.mtu {
                            return Err(WSQueueErr::Critical("len_of_curent_pack > mtu"));
                        }
                        //if the value of the length field is correct,
                        //but in the raw data buffer it is less than the length from the length
                        // field, then the packet has not arrived in its
                        // entirety, and you need to wait until the packet
                        // arrives in its entirety.
                        if elem_in_buf_quque >= len_of_curent_pack {
                            //current package is a full in buf
                            ptr_to_start = ptr_to_start
                                .checked_add(len_of_curent_pack)
                                .expect("err ptr_to_start + len_of_curent_pack");
                        } else {
                            break;
                        }
                        let mut boxed_slice = vec![
                            0u8;
                            ptr_to_start
                                .checked_sub(old_ret_pos)
                                .expect("err ptr_to_start - old_ret_pos")
                        ]
                        .into_boxed_slice();
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
            matches!(
                (self, other),
                (Self::ElemIdIsBig, Self::ElemIdIsBig)
                    | (Self::ElemIdIsSmall, Self::ElemIdIsSmall)
                    | (Self::ElemIsAlreadyIn, Self::ElemIsAlreadyIn)
                    | (Self::SuccessfulInsertion, Self::SuccessfulInsertion)
            )
        }
    }

    ///The UDP packet queue accepts packets in random order,
    ///sorts them with O(1) sorting, and returns a continuous sequence of packets.
    ///For example, if the initial queue counter is 0,
    ///the queue accepted packets 7, 2, 1, 5, 3, 6.
    ///The queue will return a vector of elements 1,2,3.
    //Since there is no packet number 4 in the queue,
    ///the queue has a continuity gap and will wait for packet number 4.
    ///Upon receiving packet number 4, the queue will be able to return a vector of
    /// packets 4,5,6,7.
    #[derive(Clone)]
    pub struct WSUdpLike<T> {
        in_queue: usize,
        k_mod: usize,
        last_give_ctr: Option<u64>,
        largest_ctr: Option<u64>,
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
                largest_ctr: None,
                last_give_ctr: None,
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

            let minimal_ctr = match self.last_give_ctr {
                Some(x) => x.checked_add(1).expect("err x +1"),
                None => 0,
            };

            let pos = match item_ctr.checked_sub(minimal_ctr) {
                Some(diff) => diff as usize,
                None => return WSQueueState::ElemIdIsSmall,
            };

            if pos >= self.data.len() {
                return WSQueueState::ElemIdIsBig;
            }

            let elem_url = &mut self.data
                [(pos.checked_add(self.k_mod).expect("err pos + self.k_mod")) % self.data.len()];

            if elem_url.is_some() {
                return WSQueueState::ElemIsAlreadyIn;
            }

            if let Some(ref mut lar) = self.largest_ctr {
                if item_ctr > *lar {
                    *lar = item_ctr;
                }
            } else {
                self.largest_ctr = Some(item_ctr);
            }

            *elem_url = Some((item_ctr, item.clone()));

            self.in_queue = self.in_queue.checked_add(1).expect("err self.in_queue + 1");

            WSQueueState::SuccessfulInsertion
        }

        fn k_add(&mut self, addin: usize) {
            self.k_mod = (self
                .k_mod
                .checked_add(addin)
                .expect("err addin + self.k_mod"))
                % self.data.len();
        }

        fn edit_my_state(&mut self, size_of_ret: usize, last_item_ctr: u64) {
            let le = self.data.len();
            for x in self.k_mod
                ..size_of_ret
                    .checked_add(self.k_mod)
                    .expect("err self.k_mod + size_of_ret")
            {
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
                },
            };

            self.k_add(size_of_ret);

            self.last_give_ctr = Some(last_item_ctr);
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
                    },
                },
            );

            copied_slice
        }

        pub fn how_items_in_queue(&self) -> usize {
            self.in_queue
        }
        pub fn last_ctr_get(&self) -> Option<u64> {
            self.last_give_ctr
        }

        pub fn get_largest_ctr(&self) -> Option<u64> {
            self.largest_ctr
        }

        pub fn gap_in_queue(&self) -> bool {
            if self.in_queue > u64::MAX as usize {
                panic!(
                    "self.in_queue > u64::MAX as usize  There is a slight discrepancy between the \
                     capacity of usize and u64. Your device is not suitable for this code :("
                );
            }

            let lgctr = self.last_give_ctr.unwrap_or(0);

            if 0 == self.in_queue {
                return false;
            }

            if let Some(lctr) = self.largest_ctr {
                let ad = self.last_give_ctr.is_some() as u64 & 1;

                //println!(
                //    "last {} large {} sub {}  inq {}  gap {}",
                //    lctr,
                //    lgctr,
                //    (lctr - lgctr),
                //    self.in_queue,
                //    ex
                //);
                ((self.in_queue as u64)
                    .checked_add(ad)
                    .expect("err ad + self.in_queue"))
                    < (lctr.checked_sub(lgctr).expect("err (lctr - lgctr)"))
                        .checked_add(1)
                        .expect("(lctr - lgctr) + 1")
            } else {
                false
            }
        }
    }

    #[derive(Default)]
    struct IdentityHasher {
        hash: u64,
    }
    //This hash table does not require a reliable hash function, as each packet has its own
    // ID.
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
    ///a binary tree showed extremely slow read and write operations in performance
    /// tests.
    #[derive(Clone)]
    pub struct WSWaitQueue<T, P> {
        data_map: HashMap<u64, ElemMy<T, P>, IdentityBuildHasher>,
        max_capacity_elems: usize,
        elems_in_me: usize,
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

            Ok(Self {
                //data_map: HashMap::with_capacity_and_hasher(max_elems, IdentityBuildHasher),
                data_map: HashMap::with_hasher(IdentityBuildHasher),
                max_capacity_elems: max_elems,
                elems_in_me: 0,
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
        /// force_to_max_p if  == true, then if the value of p_order is less than
        /// max_elem_id_and_p, the element will be added, but its p_order will be
        /// equal to max_elem_id_and_p;  if force_to_max_p if  == false, then if
        /// the value of p_order for the element is  less than max_elem_id_and_p,
        /// an error will be triggered.
        pub fn push(
            &mut self,
            id: u64,
            p_order: P,
            force_to_max_p: bool,
            elem: T,
        ) -> Result<(), &'static str> {
            if self.elems_in_me >= self.max_capacity_elems {
                return Err("queue is full");
            }
            let mut p_order = p_order;
            if let Some(mp) = &mut self.of_max_p {
                if force_to_max_p {
                    p_order = mp.1.clone();
                }
                if mp.1 > p_order {
                    return Err("self.max_elem_p < p_order");
                }
            }

            match self.data_map.entry(id) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err("this id elem is already in");
                },
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ElemMy {
                        cl: None,
                        cb: self.of_max_p.as_ref().map(|x| x.0),
                        data: elem,
                        p_order: p_order.clone(),
                    });
                    self.elems_in_me = self
                        .elems_in_me
                        .checked_add(1)
                        .expect("err 1+ self.elems_in_me");
                },
            };

            if let Some(lei) = self.of_max_p.as_ref().map(|x| x.0) {
                let last_elem = self.data_map.get_mut(&lei).expect(
                    "a critical condition that shouldn't exist, an element is missing, but it's \
                     impossible",
                );
                last_elem.cl = Some(id);
            }
            self.of_max_p = Some((id, p_order.clone()));

            if self.of_min_p.is_none() {
                if self.elems_in_me == 0 {
                    panic!(
                        "Critically incorrect algorithm behavior! There are elements in data_map, \
                         but the value of id_of_min_p is undefined!"
                    );
                }
                self.of_min_p = Some((id, p_order.clone()));
            }

            Ok(())
        }

        ///take an element by its id value and delete it from the table
        fn get_removed_elem(&mut self, id: u64) -> Option<ElemMy<T, P>> {
            let removed_elem = self.data_map.remove(&id);

            if removed_elem.is_none() {
                None
            } else {
                self.elems_in_me = self
                    .elems_in_me
                    .checked_sub(1)
                    .expect("impossible situation");
                removed_elem
            }
        }

        ///Deleting an element.
        ///Each element has a pointer in the form of an id
        ///cl -> means the next element
        ///cb -> means the previous element
        pub fn remove(&mut self, id: u64) -> Option<(T, P)> {
            //take an element by its id value and delete it from the table
            let removed_elem = self.get_removed_elem(id)?;

            // example:
            // | id:10 ,cb:None,cl:2 |---> | id:2 ,cb:10,cl:7 |---> | id:7 ,cb:2,cl:15 |---> | id:15 ,cb:7,cl:None |--->

            //  delete id:2 elem:
            // | id:10 ,cb:None,cl:2 |---> |________None______|---> | id:7 ,cb:2,cl:15 |---> | id:15 ,cb:7,cl:None |--->

            //swap:
            //Exchange ID pointers in the table:
            //When deleting element number 2, obtain the cl of element cb, then 2cl and 2cb, then
            // exchange the pointers. For element number 2cl, change the cb field to the
            // value 2cb; for element number 2cb, change the cl field value to the value 2cl.
            // 10cl = 2cl
            // 7cb = 2cb
            // | id:10 ,cb:None,cl:7 |---> | id:7 ,cb:10,cl:15 |---> | id:15 ,cb:7,cl:None |--->

            if let Some(x_cb) = removed_elem.cb {
                let cb_elem = self.data_map.get_mut(&x_cb).expect(
                    "critical condition, the .cb counter points to an element that is not in the \
                     table",
                );
                cb_elem.cl = removed_elem.cl
            }

            if let Some(x_cl) = removed_elem.cl {
                let cl_elem = self.data_map.get_mut(&x_cl).expect(
                    "critical condition, the .cl counter points to an element that is not in the \
                     table",
                );
                cl_elem.cb = removed_elem.cb
            }

            //If the deleted element was the element with the largest P,
            //then the global pointer to the largest element is updated to the one that was before
            // the deleted element.
            if let Some(last_elem_id) = self.of_max_p.as_ref() {
                if last_elem_id.0 == id {
                    if let Some(cb_id) = removed_elem.cb.as_ref() {
                        self.of_max_p = Some((
                            *cb_id,
                            self.data_map
                                .get(cb_id)
                                .expect(
                                    "Critical error: incorrect logic, link to previous element \
                                     exists, but it is missing from the table.",
                                )
                                .p_order
                                .clone(),
                        ));
                    } else {
                        self.of_max_p = None;
                    }
                }
            } else {
                panic!(
                    "Critically incorrect algorithm behavior! There are elements in data_map, but \
                     the value of id_of_max_p is undefined!"
                );
            }
            //If the deleted element was the element with the smallest P,
            //then the global pointer to the smallest element is updated to the one that was next
            // after the deleted element.
            if let Some(first_elem_id) = self.of_min_p.as_ref() {
                if first_elem_id.0 == id {
                    if let Some(cl_id) = removed_elem.cl.as_ref() {
                        self.of_min_p = Some((
                            *cl_id,
                            self.data_map
                                .get(cl_id)
                                .expect(
                                    "Critical error: incorrect logic, link does not exist, but it \
                                     is missing from the table.",
                                )
                                .p_order
                                .clone(),
                        ));
                    } else {
                        self.of_min_p = None;
                    }
                }
            } else {
                panic!(
                    "Critically incorrect algorithm behavior! There are elements in data_map, but \
                     the value of id_of_max_p is undefined!"
                );
            }

            Some((removed_elem.data, removed_elem.p_order.clone()))
        }
        //returns all elements whose p_order value is less than or equal to p_order_limit as a
        // list Vec<(u64, P, T)>, where u64 is its id, P is its p_order, and T is the data
        // itself
        pub fn get_elements_to(&mut self, p_order_limit: P) -> Vec<(u64, P, T)> {
            if self.elems_in_me == 0 {
                return Vec::new();
            }

            let first = if let Some(ret) = self.of_min_p.as_ref() {
                ret.0
            } else {
                panic!(
                    "Critically incorrect algorithm behavior! There are elements in data_map, but \
                     the value of id_of_min_p is undefined!"
                );
            };
            //self.elems_in_me / 3 is the optimal value,
            //as it is assumed that the queue will wait for packets, and the packets can be in
            // three places: 1 place is in the network awaiting receipt
            //2 packets are received by the recipient and await transmission
            //3 the recipient sends confirmation packets to the network
            //Therefore, in the vast majority of cases, the queue of unconfirmed packets will not
            // exceed 1/3 of the total number of packets.
            let mut reta_vec = Vec::with_capacity(self.elems_in_me / 3);

            let mut temp_id = first;

            for x in 0..self.elems_in_me {
                let temp = self
                    .data_map
                    .get(&temp_id)
                    .expect("critical condition, there is a gap in the queue ");
                if p_order_limit >= temp.p_order {
                    reta_vec.push((temp_id, temp.p_order.clone(), temp.data.clone()));
                }
                //The last element in the sequence does not have a reference to the next element,
                //so if x + 1 ==self.elems_in_me,
                //then this element is the last one and there is no need to take cl from it, since
                // it is None.
                if x.checked_add(1).expect("err x + 1") == self.elems_in_me {
                    break;
                }
                temp_id = temp
                    .cl
                    .expect("critical condition, there is a gap in the queue ");
            }

            reta_vec
        }

        pub fn len(&self) -> usize {
            self.elems_in_me
        }

        pub fn max_elem_id_and_p(&self) -> Option<(u64, P)> {
            self.of_max_p.as_ref().map(|x| (x.0, x.1.clone()))
        }

        pub fn min_elem_id_and_p(&self) -> Option<(u64, P)> {
            self.of_min_p.as_ref().map(|x| (x.0, x.1.clone()))
        }
    }

    ///WSRecvQueueCtrs structure for creating and receiving accepted counters from the
    /// protocol packet field
    #[derive(Clone)]
    pub struct WSRecvQueueCtrs {
        data: Box<[u64]>,
        ptr: usize,
        ctr_slice_len: usize,
        max: u64,
        min: u64,
        ptr_of_min: usize,
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

            Ok(ctrs)
        }
        ///payload_mtu indicates the maximum payload length in your network in bytes
        ///len_ctr_slise is a variable that takes the length of the counter field in
        /// bytes. max_len is the maximum number of counters in pieces that can be
        /// in the WSRecvQueueCtrs structure.
        ///
        ///
        ///  UPDATE !! blurred_boundaries always equals TRUE !!!
        ///
        ///
        ///  blurred_boundaries: Since WSRecvQueueCtrs was designed as a structure that
        ///  forms packet delivery confirmation packets, analogous to ACK packets in TCP,
        ///  such packets are usually much shorter than packets with useful data.
        ///  To make it more difficult to identify an ACK packet,
        ///  you can use blurred_boundaries == true,
        ///
        ///
        ///  What does blurred_boundaries == true affect? See pub fn
        /// copy_ctrs_pack_to_slice.
        pub fn new(
            len_ctr_slise: usize,
            max_len: usize,
            payload_mtu: usize,
        ) -> Result<Self, &'static str> {
            if max_len > Self::max_len_from_mtu(len_ctr_slise, payload_mtu)? {
                return Err(
                    "The byte representation of the maximum length must be less than or equal to \
                     mtu.",
                );
            }

            Ok(Self {
                data: vec![0; max_len].into_boxed_slice(),
                ptr: 0,
                ctr_slice_len: len_ctr_slise,
                max: 0,
                min: 0,
                ptr_of_min: 0,
            })
        }

        ///push also checks that abs_diff (the largest counter in the queue,
        ///  the smallest counter in the queue) was not greater than what can fit into
        /// 2^(8*len_ctr_slice)
        ///
        /// Please note that push does NOT implement SET() and uniqueness checks in order
        /// to save space,  which means that some counters in the queue may be
        /// duplicated.
        pub fn push(&mut self, ctr_elem: u64) -> Result<(), &'static str> {
            if self.ptr >= self.data.len() {
                return Err("the queue is full");
            }
            //Removing duplicates of maximum and minimum counters is necessary
            // for the correct operation of end boundary determination when
            // setting end_is_max_ctr (fuzzy slice boundaries,
            //see the description of the new() function for details).
            if self.ptr > 0 && (self.max == ctr_elem || self.min == ctr_elem) {
                return Ok(());
            }

            self.max = if self.max > ctr_elem && 0 < self.ptr {
                self.max
            } else {
                ctr_elem
            };

            self.min = if self.min < ctr_elem && 0 < self.ptr {
                self.min
            } else {
                self.ptr_of_min = self.ptr;
                ctr_elem
            };

            if self.max.checked_sub(self.min).expect(
                "wtf broo. what the fuck is the minimum number MORE than the maximum fucking?",
            ) > wutils::len_byte_maximal_capacity_check(self.ctr_slice_len).0
            {
                return Err(
                    "The difference between the maximum and minimum counters is greater than the \
                     counter_slice field can hold.",
                );
            }

            self.data[self.ptr] = ctr_elem;
            self.ptr = self.ptr.checked_add(1).expect("counter overflow");

            Ok(())
        }
        ///calculates how many more times counters can be push()
        pub fn free_space(&self) -> usize {
            self.data.len().checked_sub(self.ptr).expect(
                "obvious algorithm error The pointer counter is always no longer than the length \
                 of the Box.",
            )
        }

        ///returns the length of the entire queue in bytes
        ///queue structure
        //// |--------------------|-----|-----|-----|----|-----|
        ///  |8 bytes u64 main ctr|ctr_1|ctr_2|ctr_3|....|ctr_N|
        //// |--------------------|-----|-----|-----|----|-----|
        ///
        /// ctr len = len_ctr_slise
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
        ///get_ctrs_as_byte_pack_vec is a wrapper for  copy_ctrs_pack_to_slice
        pub fn get_ctrs_as_byte_pack_vec(&mut self) -> Vec<u8> {
            let mut ret_vec = vec![0; self.payload_len_in_bytes()];

            self.copy_ctrs_pack_to_slice(&mut ret_vec)
                .expect("algorithm error; if the code has been tested, there should be no errors ");
            ret_vec
        }
        /// get the full set of reverse counters, but copy them to a byte array to avoid
        /// additional memory allocation To find out what the length of
        /// pack_payload_slice should be, call self.payload_len_in_bytes().
        /// get_ctrs_as_byte_pack_vec and copy_ctrs_pack_to_slice return all contents of
        /// the queue, and the WSRecvQueueCtrs structure is completely cleared of
        /// internal objects.
        ///
        ///  UPDATE !! blurred_boundaries always equals TRUE !!!
        ///
        /// if blurred_boundaries == true
        ///then pack_payload_slice: &mut [u8] can be GREATER THAN OR EQUAL TO
        /// self.payload_len_in_bytes() usize,
        ///
        ///queue structure
        //// |--------------------|-----|-----|-----|----|-----|
        ///  |8 bytes u64 main ctr|ctr_1|ctr_2|ctr_3|....|ctr_N|
        //// |--------------------|-----|-----|-----|----|-----|
        ///
        /// ctr len = len_ctr_slise
        ///The counter under the number ctr_N, i.e. the last counter, is always equal to
        /// 0.
        pub fn copy_ctrs_pack_to_slice(
            &mut self,
            pack_payload_slice: &mut [u8],
        ) -> Result<(), &'static str> {
            if pack_payload_slice.len() < self.payload_len_in_bytes() {
                return Err("self.payload_len() > pack_payload_slice.len()");
            }

            if 0 == self.ptr {
                pack_payload_slice.fill(0);
                return Ok(());
            }
            /*
            because if you subtract the minimum value from
            the minimum value, you get 0, since there is only
            one maximum and minimum value in self.data,
            so the position of the minimum element (0)
            swaps zero to the end of the array.
            */
            let temp_swap = self.data[self.ptr_of_min];
            self.data[self.ptr_of_min] = self.data[self
                .ptr
                .checked_sub(1)
                .expect("impossible state overflow when subtracting ")];
            self.data[self.ptr.checked_sub(1).expect("err self.ptr - 1")] = temp_swap;

            //copying the reference counter to the swing slice
            wutils::u64_to_1_8bytes(self.min, &mut pack_payload_slice[..U64_LEN_IN_BYTES])?;

            for sls in pack_payload_slice[U64_LEN_IN_BYTES..]
                .chunks_exact_mut(self.ctr_slice_len)
                .zip(self.data[..self.ptr].iter())
            {
                wutils::u64_to_1_8bytes(
                    (*sls.1).checked_sub(self.min).expect(
                        "algorithm error, the minimum value must be less than any value in the \
                         array",
                    ),
                    sls.0,
                )
                .unwrap();
            }
            //cleansing of the internal state
            self.ptr = 0;
            self.max = 0;
            self.min = 0;

            Ok(())
        }

        fn len_check<'a>(
            payload: &'a [u8],
            len_ctr_slise: usize,
        ) -> Result<(u64, usize, std::slice::ChunksExact<'a, u8>), &'static str> {
            let ret_len_ctrs = payload.len().checked_sub(U64_LEN_IN_BYTES).ok_or(
                "The packet length is less than the reference counter length, which is an invalid \
                 packet.",
            )?;

            if 0 == len_ctr_slise {
                panic!("0 == len_ctr_slise")
            }

            // UPDATE !! blurred_boundaries always equals TRUE !!!
            //if 0 != ret_len_ctrs % len_ctr_slise {
            //    return Err("The packet length is incorrect because the packet length (the length
            // of the reference counter) is not a multiple of the counter field length in the packet
            // topology.");
            //}

            Ok((
                wutils::bytes_to_u64(&payload[..U64_LEN_IN_BYTES])?,
                ret_len_ctrs / len_ctr_slise,
                payload[U64_LEN_IN_BYTES..].chunks_exact(len_ctr_slise),
            ))
        }
        ///receives a slice as input, i.e.
        ///  the output from the copy_ctrs_pack_to_slice or get_ctrs_as_byte_pack_vec
        /// method,  and then returns an array of u64 values that are counters.
        pub fn split_byte_ctrs_pack_to_vec(
            pack: &[u8],
            len_ctr_slise: usize,
        ) -> Result<Vec<u64>, &'static str> {
            let pre_pross = Self::len_check(pack, len_ctr_slise)?;

            let mut ret = Vec::with_capacity(pre_pross.1);

            for ctr_chank in pre_pross.2 {
                let r_ctr = pre_pross
                    .0
                    .checked_add(wutils::bytes_to_u64(ctr_chank)?)
                    .ok_or(
                        "The reference counter + one of the delta counters caused overflow \
                         operations; most likely, the packet has an error.",
                    )?;

                ret.push(r_ctr);
                if r_ctr == pre_pross.0 {
                    //if this is the final element, then the payload is complete
                    return Ok(ret);
                }
            }

            Ok(ret)
        }
        ///receives a slice as input, i.e.
        ///  the output from the copy_ctrs_pack_to_slice or get_ctrs_as_byte_pack_vec
        /// method,
        ///
        /// Since WSRecvQueueCtrs is intended to be used with WSWaitQueue to avoid
        /// unnecessary allocation,  it receives a mutable wait_queue: &mut
        /// WSWaitQueue<T, P>,  and removes from it all counters that are encoded
        /// in pack: &[u8],
        ///
        /// --
        ///
        ///  returns (
        ///
        /// usize value that indicates how many counters were removed from WSWaitQueue,
        ///
        ///  Option<maximum P of the removed element from &mut WSWaitQueue<T, P>>,
        ///
        ///  Option<minimum P of the removed element from &mut WSWaitQueue<T, P>>
        ///
        /// )
        pub fn delete_ctrs_in_byte_pack_from_ws_wait_queue<T, P>(
            pack: &[u8],
            len_ctr_slise: usize,
            wait_queue: &mut WSWaitQueue<T, P>,
        ) -> Result<(usize, Option<P>, Option<P>), &'static str>
        where
            T: Clone + Debug,
            P: PartialEq + PartialOrd + Clone + Debug,
        {
            let pre_pross = Self::len_check(pack, len_ctr_slise)?;
            let mut how_was_deleted: usize = 0;
            let mut min_del = None;
            let mut max_del = None;
            for ctr_chank in pre_pross.2 {
                let ret_el = pre_pross
                    .0
                    .checked_add(wutils::bytes_to_u64(ctr_chank)?)
                    .ok_or(
                        "The reference counter + one of the delta counters caused overflow \
                         operations; most likely, the packet has an error.",
                    )?;

                if let Some(ref del_elem) = wait_queue.remove(ret_el) {
                    if let Some(min_xax) = &mut min_del {
                        if *min_xax > del_elem.1 {
                            *min_xax = del_elem.1.clone();
                        }
                    } else {
                        min_del = Some(del_elem.1.clone())
                    }

                    if let Some(max_xax) = &mut max_del {
                        if del_elem.1 > *max_xax {
                            *max_xax = del_elem.1.clone();
                        }
                    } else {
                        max_del = Some(del_elem.1.clone())
                    }

                    how_was_deleted = how_was_deleted
                        .checked_add(1)
                        .expect("err 1 + how_was_deleted");
                }

                if pre_pross.0 == ret_el {
                    //if this is the final element, then the payload is complete
                    return Ok((how_was_deleted, min_del, max_del));
                }
            }

            Ok((how_was_deleted, min_del, max_del))
        }
        //get the maximum and minimum counters currently in the queue
        pub fn get_min_max(&self) -> (u64, u64) {
            (self.min, self.max)
        }
    }

    #[cfg(test)]
    mod test_wait {
        use super::*;

        #[test]
        fn test_one() {
            assert_eq!(WSWaitQueue::<bool, u32>::new(0).is_err(), true);

            let mut waa = WSWaitQueue::<bool, u32>::new(10).unwrap();

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
                let mut waa = WSWaitQueue::<bool, u32>::new(10).unwrap();

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
                        .map(|x| x.0.clone())
                        .collect::<Vec<u64>>(),
                    (0..max_x).collect::<Vec<u64>>()
                );

                waa.remove(4).unwrap();

                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| x.0.clone())
                        .collect::<Vec<u64>>(),
                    vec![0, 1, 2, 3, 5, 6, 7, 8, 9]
                );

                waa.remove(5).unwrap();
                waa.remove(7).unwrap();
                waa.remove(1).unwrap();
                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| x.0.clone())
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
                        .map(|x| x.0.clone())
                        .collect::<Vec<u64>>(),
                    vec![3, 30, 31, 50, 51, 52]
                );

                assert_eq!(
                    waa.get_elements_to(waa.max_elem_id_and_p().unwrap().1)
                        .iter()
                        .map(|x| x.1.clone())
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
        use crate::t0pology::{PackTopology, PakFields};
        use crate::t1fields;

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

            let mut w_tcp = WSTcpLike::new(41, &datas_x.4, Some(dummy_crc_gen)).unwrap();
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

            let mut w_tcp = WSTcpLike::new(39, &datas_x.4, Some(dummy_crc_gen)).unwrap();

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
            let mut w_tcp = WSTcpLike::new(39, &datas_x.4, Some(dummy_crc_gen)).unwrap();
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
        fn test_segment() {
            let mut xx: WSUdpLike<u32> = WSUdpLike::new(50).unwrap();
            let emeee = 0;
            for x in 1..1000 {
                let _ = xx.insert(x - 1, &emeee);

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
            let eleme = 0.0;
            {
                assert_eq!(xx.insert(4, &eleme), WSQueueState::SuccessfulInsertion); //1
                assert_eq!(xx.gap_in_queue(), true);
                assert_eq!(xx.insert(0, &eleme), WSQueueState::SuccessfulInsertion); //2
                assert_eq!(xx.insert(2, &eleme), WSQueueState::SuccessfulInsertion); //3
                assert_eq!(xx.gap_in_queue(), true);
                assert_eq!(xx.insert(3, &eleme), WSQueueState::SuccessfulInsertion); //4
                assert_eq!(xx.insert(5, &eleme), WSQueueState::SuccessfulInsertion); //5
                assert_eq!(xx.insert(6, &eleme), WSQueueState::SuccessfulInsertion); //6
                assert_eq!(xx.insert(7, &eleme), WSQueueState::SuccessfulInsertion); //7
                assert_eq!(xx.insert(8, &eleme), WSQueueState::ElemIdIsBig); //8
                assert_eq!(xx.insert(3, &eleme), WSQueueState::ElemIsAlreadyIn); //9
                assert_eq!(xx.insert(1, &eleme), WSQueueState::SuccessfulInsertion); //10
                assert_eq!(xx.gap_in_queue(), false);
                assert_eq!(xx.in_queue, 8);
            }
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
            {
                assert_eq!(xx.gap_in_queue(), false);
                assert_eq!(xx.insert(9, &eleme), WSQueueState::SuccessfulInsertion);

                assert_eq!(xx.insert(11, &eleme), WSQueueState::SuccessfulInsertion);

                assert_eq!(xx.insert(12, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.gap_in_queue(), true);
                assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());

                assert_eq!(xx.insert(10, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(13, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.get_queue(), (vec![]).into_boxed_slice());
                assert_eq!(xx.gap_in_queue(), true);

                assert_eq!(xx.insert(8, &eleme), WSQueueState::SuccessfulInsertion);
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
            }
            {
                assert_eq!(xx.insert(12, &eleme), WSQueueState::ElemIdIsSmall);
                assert_eq!(xx.insert(13, &eleme), WSQueueState::ElemIdIsSmall);

                assert_eq!(xx.insert(22, &eleme), WSQueueState::ElemIdIsBig);
                assert_eq!(xx.insert(21, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(2, &eleme), WSQueueState::ElemIdIsSmall);
                assert_eq!(xx.insert(14, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.get_queue(), (vec![(14, 0.0)]).into_boxed_slice());

                assert_eq!(xx.insert(15, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(16, &eleme), WSQueueState::SuccessfulInsertion);

                assert_eq!(xx.insert(17, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(18, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(19, &eleme), WSQueueState::SuccessfulInsertion);
                assert_eq!(xx.insert(20, &eleme), WSQueueState::SuccessfulInsertion);
            }
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
            assert_eq!(xx.gap_in_queue(), false);
            assert_eq!(xx.insert(0, &eleme), WSQueueState::SuccessfulInsertion); //1
            assert_eq!(xx.gap_in_queue(), false);
            assert_eq!(xx.insert(1, &eleme), WSQueueState::SuccessfulInsertion); //2
            assert_eq!(xx.insert(2, &eleme), WSQueueState::SuccessfulInsertion); //3
            assert_eq!(xx.insert(3, &eleme), WSQueueState::SuccessfulInsertion); //4
            assert_eq!(xx.gap_in_queue(), false);
            assert_eq!(xx.insert(4, &eleme), WSQueueState::SuccessfulInsertion); //5
            assert_eq!(xx.insert(5, &eleme), WSQueueState::SuccessfulInsertion); //6
            assert_eq!(xx.insert(6, &eleme), WSQueueState::SuccessfulInsertion); //7
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

            assert_eq!(xx.insert(0, &eleme), WSQueueState::SuccessfulInsertion); //1
            assert_eq!(xx.in_queue, 1);
            assert_eq!(xx.get_queue(), (vec![(0, 0.0)]).into_boxed_slice());

            assert_eq!(xx.insert(1, &eleme), WSQueueState::SuccessfulInsertion); //2
            assert_eq!(xx.in_queue, 1);
            assert_eq!(
                xx.get_queue(),
                (vec![(1, 0.0)]).into_boxed_slice(),
                "{:?}",
                xx.data
            );

            assert_eq!(xx.insert(2, &eleme), WSQueueState::SuccessfulInsertion); //3

            assert_eq!(xx.in_queue, 1);
            assert_eq!(xx.get_queue(), (vec![(2, 0.0)]).into_boxed_slice());

            assert_eq!(xx.insert(3, &eleme), WSQueueState::SuccessfulInsertion); //4
            assert_eq!(xx.in_queue, 1);
            assert_eq!(xx.get_queue(), (vec![(3, 0.0)]).into_boxed_slice());

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

        #[test]
        fn test_gap() {
            let mut xx: WSUdpLike<f32> = WSUdpLike::new(20).unwrap();
            let eleme = 0.0;
            {
                assert_eq!(xx.gap_in_queue(), false);
                xx.insert(0, &eleme);
                assert_eq!(xx.gap_in_queue(), false);
                xx.insert(1, &eleme);
                xx.insert(1, &eleme);
                xx.insert(3, &eleme);
                assert_eq!(xx.gap_in_queue(), true);
                xx.insert(4, &eleme);
                xx.insert(5, &eleme);
                assert_eq!(xx.gap_in_queue(), true);
                xx.insert(2, &eleme);
                assert_eq!(xx.gap_in_queue(), false);
                xx.insert(7, &eleme);
                assert_eq!(xx.gap_in_queue(), true);
                xx.insert(6, &eleme);
                assert_eq!(xx.gap_in_queue(), false);
                xx.get_queue();
                assert_eq!(xx.gap_in_queue(), false);
                //
                xx.insert(9, &eleme);
                assert_eq!(xx.gap_in_queue(), true);
                xx.insert(8, &eleme);
                assert_eq!(xx.gap_in_queue(), false);
                xx.get_queue();
                xx.insert(11, &eleme);
                xx.insert(12, &eleme);
                xx.insert(13, &eleme);
                assert_eq!(xx.gap_in_queue(), true);

                xx.insert(10, &eleme);
                assert_eq!(xx.gap_in_queue(), false);
                //
                xx.insert(15, &eleme);
                xx.insert(16, &eleme);
                xx.insert(17, &eleme);
                assert_eq!(xx.gap_in_queue(), true);
                xx.get_queue();
                assert_eq!(xx.gap_in_queue(), true);
                xx.insert(14, &eleme);
                assert_eq!(xx.gap_in_queue(), false);
            }
        }
    }

    #[cfg(test)]
    mod test_recv_queue_ctrs {

        use ::std::collections::HashMap;

        use crate::t0pology::{PackTopology, PakFields};
        use crate::t1queue_tcpudp::U64_LEN_IN_BYTES;
        use crate::t1queue_tcpudp::recv_queue::{WSRecvQueueCtrs, WSWaitQueue};
        #[test]
        fn test_base() {
            let fields = vec![PakFields::Counter(2)];

            let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

            for x in 1..20 {
                let x = x * 26;

                assert_eq!(
                    WSRecvQueueCtrs::max_len_from_mtu(pack_topology.counter_slice().unwrap().2, x)
                        .unwrap(),
                    (x - U64_LEN_IN_BYTES) / pack_topology.counter_slice().unwrap().2
                );
            }

            assert_eq!(
                WSRecvQueueCtrs::max_len_from_mtu(pack_topology.counter_slice().unwrap().2, 9),
                Err("The MTU is too small to accommodate even one counter.")
            );

            assert_eq!(
                WSRecvQueueCtrs::new(pack_topology.counter_slice().unwrap().2, 39, 100).is_ok(),
                true
            );
        }

        #[test]
        fn test_wait() {
            println!("test_wait");
            let ctr_len = 1; //dnt touch
            let fields = vec![PakFields::Counter(ctr_len)];

            let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

            let mut test_me =
                WSRecvQueueCtrs::new(pack_topology.counter_slice().unwrap().2, 500, 1000).unwrap();
            let mut ws_wa: WSWaitQueue<String, f32> = WSWaitQueue::new(500).unwrap();

            for iterata_ma in [
                10_000_000,
                10_000,
                10,
                100_000_000,
                500,
                123456789,
                0,
                12,
                0xFF_FF_FF_FF_FF_FF_FE_11,
                87667,
            ] {
                let mut hm: HashMap<u64, u64> = HashMap::new();

                println!("| {:>20} |===================================", iterata_ma);
                for x in (iterata_ma..iterata_ma + 256).enumerate() {
                    hm.insert(x.1, x.1);
                    test_me.push(x.1).unwrap();
                    assert_eq!(test_me.free_space(), 500 - 1 - x.0);
                    assert_eq!(test_me.get_min_max(), (iterata_ma, x.1));
                    assert_eq!(test_me.len(), x.0 + 1);
                    ws_wa
                        .push(x.1, x.1 as f32 * 1.2, false, "data".to_string())
                        .unwrap();
                }
                assert_eq!(hm.len(), 256);

                assert_eq!(
                    test_me.push(iterata_ma + 256),
                    Err(
                        "The difference between the maximum and minimum counters is greater than \
                         the counter_slice field can hold."
                    )
                );

                let test_me_old = test_me.clone();

                assert_eq!(test_me.len(), 256);

                let ret_ve = test_me.get_ctrs_as_byte_pack_vec();

                //println!("{:?}", ret_ve);

                assert_eq!(test_me.len(), 0);
                assert_eq!(test_me.get_min_max(), (0, 0));

                assert_eq!(
                    test_me_old.payload_len_in_bytes(),
                    U64_LEN_IN_BYTES + test_me_old.len() * 1
                );
                assert_eq!(ws_wa.len(), 256);

                let re_recv = WSRecvQueueCtrs::delete_ctrs_in_byte_pack_from_ws_wait_queue(
                    &ret_ve, ctr_len, &mut ws_wa,
                )
                .unwrap();
                //println!("{:?}", re_recv);

                assert_eq!(
                    re_recv,
                    (
                        256,
                        Some(iterata_ma as f32 * 1.2),
                        Some((iterata_ma + 255) as f32 * 1.2)
                    )
                );
                //assert_eq!(re_recv, 0);

                assert_eq!(ws_wa.len(), 0);

                let remap_ve = WSRecvQueueCtrs::split_byte_ctrs_pack_to_vec(
                    &ret_ve[..],
                    pack_topology.counter_slice().unwrap().2,
                )
                .unwrap();

                for x in (iterata_ma..iterata_ma + 256).enumerate() {
                    hm.remove(&remap_ve[x.0]);
                }
                assert_eq!(hm.len(), 0)
                // println!("{:?}", ret_ve);

                // println!(
                //    "{:?}",
                //    WSRecvQueueCtrs::split_byte_ctrs_pack_to_vec(&ret_ve[..],
                // &pack_topology).unwrap()
                //);
            }
        }

        #[test]
        fn test_wait_blurred_boundaries() {
            let ctr_len = 2; //dnt touch

            let mut ws_wa: WSWaitQueue<String, f32> = WSWaitQueue::new(500).unwrap();

            let mut test_me = WSRecvQueueCtrs::new(ctr_len, 500, 1100).unwrap();

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
                    test_me.push(x).unwrap();
                    let _ = ws_wa.push(x, x as f32 * 1.2, true, "333".to_string());
                }

                assert_eq!(ws_wa.len(), 19);
                let mut tc2 = test_me.clone();

                let mut temp_vec_sl = vec![42u8/*42 is trash */; 200];

                tc2.copy_ctrs_pack_to_slice(&mut temp_vec_sl).unwrap();
                let vec_sl = test_me.get_ctrs_as_byte_pack_vec();

                let h1 =
                    WSRecvQueueCtrs::split_byte_ctrs_pack_to_vec(&temp_vec_sl, ctr_len).unwrap();

                let h2 = WSRecvQueueCtrs::split_byte_ctrs_pack_to_vec(&vec_sl, ctr_len).unwrap();

                WSRecvQueueCtrs::delete_ctrs_in_byte_pack_from_ws_wait_queue(
                    &temp_vec_sl,
                    ctr_len,
                    &mut ws_wa,
                )
                .unwrap();
                assert_eq!(ws_wa.len(), 0);
                assert_eq!(h1, h2)
            }

            test_me.push(10).unwrap(); //1
            test_me.push(1022).unwrap(); //2
            test_me.push(1022).unwrap(); //3
            test_me.push(10322).unwrap(); //4
            test_me.push(10322).unwrap(); //5
            test_me.push(10322).unwrap(); //6
            test_me.push(1430).unwrap(); //7
            test_me.push(18876).unwrap(); //8
            test_me.push(652).unwrap(); //9
            test_me.push(11).unwrap(); //10

            let vet = test_me.get_ctrs_as_byte_pack_vec();

            assert_eq!(22, vet.len());

            assert_eq!(
                WSRecvQueueCtrs::split_byte_ctrs_pack_to_vec(&vet, ctr_len).unwrap(),
                [11, 1022, 10322, 1430, 18876, 652, 10]
            );

            assert_eq!(
                WSRecvQueueCtrs::split_byte_ctrs_pack_to_vec(&vet[..vet.len() - 3], ctr_len)
                    .unwrap(),
                [11, 1022, 10322, 1430, 18876] /* -2 ctr */
            );
        }

        #[test]
        fn test_extend_err() {
            let ctr_len = 2; //dnt touch
            let fields = vec![PakFields::Counter(ctr_len)];

            let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

            let mut test_me =
                WSRecvQueueCtrs::new(pack_topology.counter_slice().unwrap().2, 500, 1100).unwrap();

            for x in 0..501 {
                assert_eq!(
                    test_me.push(x),
                    if x < 500 {
                        assert_eq!(499 - x as usize, test_me.free_space());
                        Ok(())
                    } else {
                        Err("the queue is full")
                    }
                );
            }

            let mut test_me1 =
                WSRecvQueueCtrs::new(pack_topology.counter_slice().unwrap().2, 500, 1100).unwrap();

            test_me1.push(1 << (8 * 2) + 1).unwrap();
            assert_eq!(
                test_me1.push(1),
                Err(
                    "The difference between the maximum and minimum counters is greater than the \
                     counter_slice field can hold."
                )
            );

            let mut test_me1 =
                WSRecvQueueCtrs::new(pack_topology.counter_slice().unwrap().2, 500, 1100).unwrap();

            test_me1.push(1).unwrap();
            assert_eq!(
                test_me1.push(1 << (8 * 2) + 1),
                Err(
                    "The difference between the maximum and minimum counters is greater than the \
                     counter_slice field can hold."
                )
            );
        }
    }

    #[cfg(test)]
    use crate::t0pology::PakFields;

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

            (!(0 as u32)) as f32 * cof > smalll as f32
        }

        fn shuffle<T>(array: &mut [T], s: u64) {
            let len = array.len();

            for i in (1..len).rev() {
                let j = (randr(i as u64 + s) % (i as u64 + 1)) as usize;
                array.swap(i, j);
            }
        }

        let fields = vec![PakFields::Counter(3)];

        let pack_topology = PackTopology::new(10, &fields, true, false).unwrap();

        let mut ctrs_que =
            WSRecvQueueCtrs::new(pack_topology.counter_slice().unwrap().2, 130, 1000).unwrap();
        let mut wait_que: WSWaitQueue<String, f32> = WSWaitQueue::new(1000).unwrap();
        let mut udp_que: WSUdpLike<String> = WSUdpLike::new(1000).unwrap();

        let mut net_steak = Vec::new();
        let mut net_steak_recv: Vec<Vec<u8>> = Vec::new();
        let mut un_blear_ctr = 0;

        let mut pack_to_inp = 0;

        let net_stable = 0.49990;

        let max_ctrs = 2_000_0;

        for time_soon in 0..3_0000000 {
            if un_blear_ctr >= max_ctrs - 1 {
                break;
            }

            if time_soon % 500 == 0 {
                println!(
                    "| stack:{:<5} | queue continuity:{:<5} | unconfirmed:{:<5} | not sent \
                     confirmation:{:<5} |",
                    udp_que.how_items_in_queue(),
                    un_blear_ctr,
                    wait_que.len(),
                    ctrs_que.len()
                );
            }

            //send generrr
            if coof(0.7, randr(time_soon)) {
                {
                    //resending packets
                    let get_non_proff_ctr = wait_que.get_elements_to(time_soon as f32 * 1.1);

                    for non_prosf in get_non_proff_ctr {
                        net_steak.push(non_prosf.0);
                        wait_que.remove(non_prosf.0).unwrap();
                        wait_que
                            .push(
                                non_prosf.0,
                                (time_soon as f32 * 1.1) + 20.0,
                                false,
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
                                false,
                                "str".to_string(),
                            )
                            .is_ok()
                        {
                            pack_to_inp += 1;
                        }
                    }
                }

                for xxx in net_steak_recv.iter() {
                    WSRecvQueueCtrs::delete_ctrs_in_byte_pack_from_ws_wait_queue(
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
                let inert_in_rcv = match udp_que.insert(*x, &"str".to_string()) {
                    WSQueueState::ElemIdIsBig => false,
                    _ => true,
                };
                if inert_in_rcv {
                    ctrs_que.push(*x).unwrap();
                }
                //udp wue cheak
                for pack in udp_que.get_queue() {
                    if pack.0 > 0 {
                        if un_blear_ctr + 1 == pack.0 {
                            un_blear_ctr += 1;
                        } else {
                            panic!("ERR IN QUEQUE UDP!!!")
                        }
                    }
                }

                if ctrs_que.len() > 6 + randr(time_soon.rotate_left(8)) as usize % 10 {
                    let mut ret = vec![0; ctrs_que.payload_len_in_bytes()];
                    ctrs_que.copy_ctrs_pack_to_slice(&mut ret).unwrap();
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

        println!("{:?}", wait_que.get_elements_to(999999999999999.0));
    }
}
