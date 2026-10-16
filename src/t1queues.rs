// I HATE FUCKING RUST!
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::integer_division)]
//#![deny(clippy::expect_used)]
#![deny(clippy::unreachable)]
#![deny(clippy::todo)]
#![deny(clippy::float_cmp)]
#![forbid(unsafe_code)]
pub const U64_LEN_IN_BYTES: usize = 8;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::{BuildHasher, Hasher};

use crate::t0pology::PackTopology;

use crate::w1types::{Crcser, PackScheme, PackTypeGroup as PTG, WSQueueState, WisErr};
use crate::{EXPCP, checked_cast, t1fields, w1utils};

#[derive(Clone, Debug)]
///See the description of the `new` method
pub struct WSTcpLike<Tcrcser: Crcser> {
    elems_in_buf: usize,
    u_buf: RefCell<Box<[u8]>>,
    sheme_topology: RefCell<PackScheme>,
    mtu: usize,
    crc_gener: RefCell<Option<Tcrcser>>,
}

impl<Tcrcser: Crcser> WSTcpLike<Tcrcser> {
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
    pub fn new(
        mtu: usize,
        sheme_topology: PackScheme,
        crc_seed: Option<&[u8]>,
    ) -> Result<Self, WisErr<String, String>> {
        //if pack_topology.len_slice().is_none() {
        //    return Err(WSQueueErr::Critical("pack_topology.len_slice() is none"));
        //}

        Ok(Self {
            elems_in_buf: 0,
            u_buf: RefCell::new(vec![0; mtu].into_boxed_slice()),
            sheme_topology: RefCell::new(sheme_topology),
            mtu,
            crc_gener: RefCell::new(if let Some(seeeed) = crc_seed {
                Some(Tcrcser::new(seeeed).map_err(WisErr::Critical)?)
            } else {
                None
            }),
        })
    }
    ///receives a continuous stream of data,
    /// such as that carried by the TCP protocol, and divides the received continuous
    /// sequence into individual packets
    pub fn split_byte_stream_into_packages(
        &mut self,
        data: &[u8],
    ) -> Result<Box<[Box<[u8]>]>, WisErr<String, String>> {
        //let min_len1 = self.pack_topology.total_minimal_len();
        let mut ret_paks: Vec<Box<[u8]>> = Vec::with_capacity(10);
        let mut pos_in_data = 0;

        while pos_in_data < data.len() {
            let copy_elems_to_buf = self.check_choosing_shorter_length(data, &pos_in_data)?;
            //if the elements in data[] have run out, then exit the loop
            if copy_elems_to_buf == 0 {
                break;
            }
            self.updating_and_copying(data, &mut pos_in_data, &copy_elems_to_buf)?;

            let mut ptr_to_start: usize = 0;
            let mut old_ret_pos: usize = 0;
            while ptr_to_start < self.elems_in_buf {
                let elem_in_buf_quque =
                    self.elems_in_buf
                        .checked_sub(ptr_to_start)
                        .ok_or(WisErr::Critical(
                            "err elems_in_buf sub ptr_to_start".to_string(),
                        ))?;

                //if the length of the data in the buffer is greater than the minimum packet
                // size, it means that you can read the packet length fields
                // to find out its end.

                //if let Some(go_topol_read) = self.read_or_not(&elem_in_buf_quque)? {
                //if the package has a crc signature of the head data,
                // then it must be checked. if the data is intact, add it to ret_paks

                if !self.read_or_not(
                    &elem_in_buf_quque,
                    &mut ptr_to_start,
                    |fina_top, pt_to_s| {
                        self.read_fields(
                            fina_top,
                            pt_to_s,
                            &elem_in_buf_quque,
                            &mut old_ret_pos,
                            &mut ret_paks,
                        )
                    },
                )? {
                    break;
                }
            }
            self.ender(&ptr_to_start)?;
        }

        Ok(ret_paks.into_boxed_slice())
    }

    fn read_or_not<F>(
        &self,
        elem_in_buf_quque: &usize,
        ptr_to_start: &mut usize,
        mut fuck_rust_rules: F,
    ) -> Result<bool, WisErr<String, String>>
    where
        F: FnMut(&PackTopology, &mut usize) -> Result<bool, WisErr<String, String>>,
    {
        let sheme_lock = self
            .sheme_topology
            .try_borrow()
            .map_err(|e| WisErr::Critical(format!("The slot is already booked: {}", e)))?;
        let final_topol = match *sheme_lock {
            PackScheme::GroupPack(ref x_group) => {
                // check if the group uses a specific byte as a topology selector
                if let Some(tricky_pos) = x_group.tricky_position() {
                    if tricky_pos >= *elem_in_buf_quque {
                        None
                    } else {
                        // if a selector position is defined, ensure we have enough data to read
                        // it

                        if let Some(tp_num) = self
                            .u_buf
                            .try_borrow()
                            .map_err(|e| {
                                WisErr::Critical(format!("u_buf Buffer is already borrowed: {}", e))
                            })?
                            .get(
                                tricky_pos
                                    .checked_add(*ptr_to_start)
                                    .ok_or(WisErr::Critical(
                                        "ptr_to_start+tricky_pos overwlow".to_string(),
                                    ))?,
                            )
                        {
                            // retrieve the specific topology from the group using the index
                            // from the buffer

                            Some(
                                x_group
                                    .get_from_u8(*tp_num, PTG::Any)
                                    .ok_or(WisErr::Critical(
                                        "
                                error: there is no topology with this index
                                in the topology group. most likely, the bytes of this packet are \
                                     corrupted. critical error."
                                            .to_string(),
                                    ))?,
                            )
                        } else {
                            // not enough data in buffer to determine the topology yet
                            None
                        }
                    }
                } else {
                    // if tricky_position is none, the group contains only one universal
                    // topology we use index 0 as the default entry
                    // point for this single-topology case
                    x_group.get_from_u8(0, PTG::Any)
                }
            },

            PackScheme::OnePack(ref x) => Some(x),
        };

        // final validation: check if we have found a topology and if the buffer
        // has reached its required minimal length for a full read
        if let Some(x_final) = final_topol {
            if *elem_in_buf_quque >= x_final.overhead_len() {
                fuck_rust_rules(x_final, ptr_to_start)
                //Ok(Some(x_final))
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// check. choosing the shorter length.
    /// since there are two stores, 1 is the amount of free space in the buffer,
    /// 2 is the number of elements that need to be processed in data[].
    /// a lower value is selected and as many elements are copied from data to the
    /// buffer. elems_in_buf means how many elements are in
    /// the buffer and u_buf.len()-elems_in_buf means how much free space is in the
    /// buffer. data.len()-pos_in_data means how many elements are left
    /// in the data. pos_in_data and elems_in_buf are offsets for u_buf
    /// and data[], respectively.
    fn check_choosing_shorter_length(
        &self,
        data: &[u8],
        pos_in_data: &usize,
    ) -> Result<usize, WisErr<String, String>> {
        let buf_void = self
            .u_buf
            .try_borrow()
            .map_err(|e| WisErr::Critical(format!("Buffer borrow error: {}", e)))?
            .len()
            .checked_sub(self.elems_in_buf)
            .ok_or(WisErr::Critical(
                "err in u_buf.len() checked_sub elems_in_buf <0".to_string(),
            ))?;

        let data_elems = data
            .len()
            .checked_sub(*pos_in_data)
            .ok_or(WisErr::Critical(
                "err data.len() checked_sub pos_in_data >0".to_string(),
            ))?;

        Ok(if buf_void < data_elems {
            buf_void
        } else {
            data_elems
        })
    }

    ///if the package has a crc signature of the head data,
    /// then it must be checked. if the data is intact, add it to ret_paks
    fn read_fields(
        &self,
        pack_topology: &PackTopology,
        ptr_to_start: &mut usize,
        elem_in_buf_quque: &usize,
        old_ret_pos: &mut usize,
        ret_paks: &mut Vec<Box<[u8]>>,
    ) -> Result<bool, WisErr<String, String>> {
        if pack_topology.head_crc_slice().is_some() {
            let mut lbo = |da1ta: &[u8], out: &mut [u8]| -> Result<(), String> {
                let mut borrow = self.crc_gener.try_borrow_mut().map_err(|e| e.to_string())?;
                let cfc = borrow.as_mut().ok_or("crc_gener is None")?;
                cfc.gen_crc(da1ta, out)?;
                Ok(())
            };

            let crc_result = {
                // 1. We take a mutable reference and immediately convert its error to a WisErr using map_err and the ? operator
                let mut buf_mut = self.u_buf.try_borrow_mut().map_err(|e| {
                    WisErr::Critical(format!("buf_mut Buffer is already borrowed: {}", e))
                })?;

                // 2. Now `buf_mut` is of type `RefMut`, and you can call `get_mut()` on it
                let buf_slice = buf_mut.get_mut(*ptr_to_start..).ok_or(WisErr::Critical(
                    "invalid buffer range for crc check".to_string(),
                ))?;

                t1fields::set_get_head_crc(false, buf_slice, pack_topology, &mut lbo)
            }
            .map_err(|err| WisErr::Critical(err.err_to_str()))?;

            if !crc_result {
                return Err(WisErr::Critical("package is damaged".to_string()));
            }
        }

        let len_of_curent_pack = {
            let buf_ref = self.u_buf.try_borrow().map_err(|e| {
                WisErr::Critical(format!("buf_ref Buffer is already borrowed: {}", e))
            })?;

            let buf_for_len = buf_ref.get(*ptr_to_start..).ok_or(WisErr::Critical(
                "invalid buffer range for length read".to_string(),
            ))?;

            t1fields::get_len(buf_for_len, pack_topology)
        }
        .map_err(|err| WisErr::Critical(err.err_to_str()))?;

        if len_of_curent_pack > self.mtu {
            return Err(WisErr::Critical("len_of_curent_pack > mtu".to_string()));
        }

        if *elem_in_buf_quque >= len_of_curent_pack {
            *ptr_to_start = EXPCP!(
                ptr_to_start.checked_add(len_of_curent_pack),
                "err ptr_to_start + len_of_curent_pack"
            );
        } else {
            return Ok(false);
        }

        let copy_len = EXPCP!(
            ptr_to_start.checked_sub(*old_ret_pos),
            "err ptr_to_start - old_ret_pos"
        );

        let mut boxed_slice = vec![0u8; copy_len].into_boxed_slice();

        {
            let buf_ref = self.u_buf.try_borrow().map_err(|e| {
                WisErr::Critical(format!("buf_ref Buffer is already borrowed: {}", e))
            })?;

            let src_slice = buf_ref
                .get(*old_ret_pos..*ptr_to_start)
                .ok_or(WisErr::Critical(
                    "invalid buffer range for copy".to_string(),
                ))?;

            boxed_slice.copy_from_slice(src_slice);
        }

        ret_paks.push(boxed_slice);
        *old_ret_pos = *ptr_to_start;

        Ok(true)
    }

    fn updating_and_copying(
        &mut self,
        data: &[u8],
        pos_in_data: &mut usize,
        copy_elems_to_buf: &usize,
    ) -> Result<(), WisErr<String, String>> {
        let end_buf = self
            .elems_in_buf
            .checked_add(*copy_elems_to_buf)
            .ok_or(WisErr::Critical(
                "err in elems_in_buf + copy_elems_to_buf".to_string(),
            ))?;

        let end_data = pos_in_data
            .checked_add(*copy_elems_to_buf)
            .ok_or(WisErr::Critical(
                "err in pos_in_data + copy_elems_to_buf".to_string(),
            ))?;

        {
            let mut buf_guard = self.u_buf.try_borrow_mut().map_err(|e| {
                WisErr::Critical(format!("buf_guard Buffer is already borrowed: {}", e))
            })?;

            let dest_slice =
                buf_guard
                    .get_mut(self.elems_in_buf..end_buf)
                    .ok_or(WisErr::Critical(
                        "invalid destination buffer range".to_string(),
                    ))?;

            let src_slice = data
                .get(*pos_in_data..end_data)
                .ok_or(WisErr::Critical("invalid source data range".to_string()))?;

            dest_slice.copy_from_slice(src_slice);
        }

        self.elems_in_buf = end_buf;
        *pos_in_data = end_data;

        Ok(())
    }
    fn ender(&mut self, ptr_to_start: &usize) -> Result<(), WisErr<String, String>> {
        //shifting elements that have already been processed and added to ret_paks
        if self.elems_in_buf
            > self
                .u_buf
                .try_borrow()
                .map_err(|e| {
                    WisErr::Critical(format!("elems_in_buf Buffer is already borrowed: {}", e))
                })?
                .len()
        {
            panic!("is critical logic error: self.elems_in_buf > self.u_buf.len()")
        }

        if *ptr_to_start > 0 && self.elems_in_buf > *ptr_to_start {
            // get_mut() возвращает &mut Box<[u8]> напрямую, без Result!
            self.u_buf
                .get_mut()
                .copy_within(*ptr_to_start..self.elems_in_buf, 0);
        }

        //position changes so that the beginning is there, and the last raw element
        self.elems_in_buf =
            self.elems_in_buf
                .checked_sub(*ptr_to_start)
                .ok_or(WisErr::Critical(
                    "err elems_in_buf sub= ptr_to_start".to_string(),
                ))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
///See the description of the `new` method
pub struct WSUdpLike<T> {
    in_queue: usize,
    k_mod: usize,
    last_give_ctr: Option<u64>,
    largest_ctr: Option<u64>,
    data: Box<[Option<(u64, T)>]>,
}

impl<T: Clone> WSUdpLike<T> {
    #[cfg(test)]
    ///for test only
    pub fn for_test_in_queue(&self) -> usize {
        self.in_queue
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_k_mod(&self) -> usize {
        self.k_mod
    }
    #[cfg(test)]
    ///for test only
    pub fn for_test_data(&self) -> Box<[Option<(u64, T)>]> {
        self.data.clone()
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_k_mod_set(&mut self, mood: usize) {
        self.k_mod = mood
    }
}

impl<T: Clone> WSUdpLike<T> {
    ///The UDP packet queue accepts packets in random order,
    ///sorts them with O(1) sorting, and returns a continuous sequence of packets.
    ///For example, if the initial queue counter is 0,
    ///the queue accepted packets 7, 2, 1, 5, 3, 6.
    ///The queue will return a vector of elements 1,2,3.
    //Since there is no packet number 4 in the queue,
    ///the queue has a continuity gap and will wait for packet number 4.
    ///Upon receiving packet number 4, the queue will be able to return a vector of
    /// packets 4,5,6,7.
    pub fn new(sizecap: usize) -> Result<Self, WisErr<String, String>> {
        if sizecap == 0 {
            return Err(WisErr::Critical(
                "sizecap must be greater than zero".to_string(),
            ));
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
            panic!("item_ctr == u64 MAX ")
        }

        let minimal_ctr = match self.last_give_ctr {
            Some(x) => x.checked_add(1).expect("err x +1"),
            None => 0,
        };

        let pos = match item_ctr.checked_sub(minimal_ctr) {
            Some(diff) => {
                checked_cast!(diff => usize, expect "diff conversion to usize failed")
            },
            None => return WSQueueState::ElemIdIsSmall,
        };

        if pos >= self.data.len() {
            return WSQueueState::ElemIdIsBig;
        }

        let idx = (pos.checked_add(self.k_mod).expect("err pos + self.k_mod"))
            .checked_rem(self.data.len())
            .expect("modulo by zero: data.len() is 0");

        let elem_url = self.data.get_mut(idx).expect("invalid data index");

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
    ///k_mod + addin
    pub fn k_add(&mut self, addin: usize) {
        let sum = EXPCP!(self.k_mod.checked_add(addin), "err addin + self.k_mod");
        self.k_mod = sum
            .checked_rem(self.data.len())
            .expect("modulo by zero (data.len() == 0)");
    }

    fn edit_my_state(&mut self, size_of_ret: usize, last_item_ctr: u64) {
        let le = self.data.len();
        let end = EXPCP!(
            size_of_ret.checked_add(self.k_mod),
            "err self.k_mod + size_of_ret"
        );

        for x in self.k_mod..end {
            let idx = x
                .checked_rem(le)
                .expect("division by zero in modulo operation");
            if let Some(slot) = self.data.get_mut(idx) {
                *slot = None;
            }
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

    fn fill_queue_vec(&mut self, vec: &mut Vec<(u64, T)>) {
        vec.clear(); //Be sure to clean before use!
        vec.extend(
            self.data
                .iter()
                .cycle()
                .skip(self.k_mod)
                .take(self.data.len())
                .take_while(|opt| opt.is_some())
                .map(|opt| EXPCP!(opt.as_ref(), "unreal state").clone()),
        );

        self.edit_my_state(
            vec.len(),
            match vec.last() {
                Some(x) => x.0,

                _ => {
                    vec.clear();
                    return;
                },
            },
        );
    }
    ///Retrieve all possible queues from the packets
    ///The packets are sorted in ascending order, without skipping counters,without,duplication
    /// To avoid creating allocations, you can use pre_created_vec.
    ///If pre_created_vec is some, it is filled with values ​​and the function returns None.
    ///If pre_created_vec is none, a new vector is created into which the values ​​are placed,
    ///and the function returns Some.
    ///If there are no ready packets in the queue, the queue will always return None.
    pub fn get_queue(
        &mut self,
        pre_created_vec: Option<&mut Vec<(u64, T)>>,
    ) -> Option<Vec<(u64, T)>> {
        match pre_created_vec {
            Some(vec) => {
                self.fill_queue_vec(vec);
                None
            },
            None => {
                let mut vec = Vec::new();
                self.fill_queue_vec(&mut vec);
                if vec.is_empty() { None } else { Some(vec) }
            },
        }
    }

    ///How many elements are there in the queue?
    pub fn how_items_in_me(&self) -> usize {
        self.in_queue
    }

    ///How many free_spacse are there in the queue?
    pub fn free_space(&self) -> usize {
        EXPCP!(
            self.data.len().checked_sub(self.in_queue),
            "self.data.len() - self.in_queue underflow"
        )
    }
    ///len
    pub fn capacity(&self) -> usize {
        self.data.len()
    }
    ///is_empty
    pub fn is_empty(&self) -> bool {
        self.in_queue == 0
    }

    #[cfg(test)]
    ///only needed in a test scenario
    pub fn test_get_state(&self) -> Box<[Option<(u64, T)>]> {
        self.data.clone()
    }

    ///last_ctr_ge returns the last counter that WAS set in get_queue
    pub fn last_ctr_get(&self) -> Option<u64> {
        self.last_give_ctr
    }
    ///get_largest_ctr returns the largest counter currently in the queue
    pub fn get_largest_ctr(&self) -> Option<u64> {
        self.largest_ctr
    }
    ///gap_in_queue returns true if there is a gap in the queue,<br>
    /// for example, if the queue contains packets:<br>
    /// 11, 12, 13, and 15.<br>
    /// If packet number 14 is missing, then there is a gap.<br>
    /// if there are no packets in the queue, false is returned
    pub fn gap_in_queue(&self) -> bool {
        if self.in_queue
            > checked_cast!(u64::MAX => usize, expect "u64::MAX to usize conversion failed")
        {
            panic!(
                "self.in_queue > u64 MAX as usize  There is a slight discrepancy between the \
                     capacity of usize and u64. Your device is not suitable for this code :("
            );
        }

        let lgctr = self.last_give_ctr.unwrap_or(0);

        if 0 == self.in_queue {
            return false;
        }

        if let Some(lctr) = self.largest_ctr {
            let ad = if self.last_give_ctr.is_some() { 1 } else { 0 };

            (EXPCP!(
                checked_cast!(self.in_queue => u64, expect "in_queue conversion to u64 failed")
                    .checked_add(ad),
                "err ad + self.in_queue"
            )) < EXPCP!(
                (EXPCP!(lctr.checked_sub(lgctr), "err (lctr - lgctr)")).checked_add(1),
                "(lctr - lgctr) + 1"
            )
        } else {
            false
        }
    }
}

#[derive(Default)]
pub struct IdentityHasher {
    hash: u64,
}
//This hash table does not require a reliable hash function, as each packet has its own
// ID.
impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        self.hash = u64::from_ne_bytes(EXPCP!(bytes.try_into(), "unreal state"));
    }

    fn write_u64(&mut self, i: u64) {
        self.hash = i;
    }
}
#[derive(Default, Clone)]

///mis cm
pub struct IdentityBuildHasher;

impl BuildHasher for IdentityBuildHasher {
    type Hasher = IdentityHasher;

    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher::default()
    }
}
#[derive(Clone, Debug)]
///no cm
pub struct ElemMy<T, P> {
    cl: Option<u64>,
    cb: Option<u64>,
    data: T,
    p_order: P,
}
///See the description of the `new` method
#[derive(Clone, Debug)]
pub struct WSWaitQueue<T, P> {
    data_map: HashMap<u64, ElemMy<T, P>, IdentityBuildHasher>,
    max_capacity_elems: usize,
    elems_in_me: usize,
    of_min_p: Option<(u64, P)>,
    of_max_p: Option<(u64, P)>,
}

impl<T: Clone, P: PartialEq + PartialOrd + Clone> WSWaitQueue<T, P> {
    ///Queue of packets, access to get, remove, and push takes O(1),
    ///uses a hash table internally, the table was chosen because
    ///a binary tree showed extremely slow read and write operations in performance
    /// tests.
    pub fn new(max_elems: usize) -> Result<Self, WisErr<String, String>> {
        if max_elems == 0 {
            return Err(WisErr::Critical("max_elems is 0".to_string()));
        }

        Ok(Self {
            //data_map: HashMap::with_capacity_and_hasher(max_elems, IdentityBuildHasher),
            data_map: HashMap::with_hasher(IdentityBuildHasher {}),
            max_capacity_elems: max_elems,
            elems_in_me: 0,
            of_max_p: None,
            of_min_p: None,
        })
    }
    /// Inserts an element into the queue. The `id` must be a unique identifier within the hash table.
    /// The `p_order` acts as a priority/ordering object (typically `f32`/`f64` or `u32`/`u64`).
    ///
    /// # Behavior
    /// * If the provided `p_order` is greater than or equal to the current maximum priority (`of_max_p`),
    ///   the insertion occurs in O(1) time complexity.
    /// * If the provided `p_order` is smaller than the current maximum priority, it is automatically
    ///   clamped (promoted) to equal the current maximum priority value to maintain queue consistency.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The queue has reached its maximum capacity (`max_capacity_elems`).
    /// * The element with the given `id` already exists in the table.
    pub fn push(&mut self, id: u64, p_order: P, elem: T) -> Result<(), String> {
        if self.elems_in_me >= self.max_capacity_elems {
            return Err("queue is full".to_string());
        }
        let mut p_order = p_order;
        if let Some(mp) = &mut self.of_max_p
            && mp.1 > p_order
        {
            p_order = mp.1.clone();
        }

        match self.data_map.entry(id) {
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err("this id elem is already in".to_string());
            },
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(ElemMy {
                    cl: None,
                    cb: self.of_max_p.as_ref().map(|x| x.0),
                    data: elem,
                    p_order: p_order.clone(),
                });
                self.elems_in_me =
                    EXPCP!(self.elems_in_me.checked_add(1), "err 1+ self.elems_in_me");
            },
        };

        if let Some(lei) = self.of_max_p.as_ref().map(|x| x.0) {
            let last_elem = EXPCP!(
                self.data_map.get_mut(&lei),
                "a critical condition that shouldn't exist, an element is missing, but it's \
                     impossible"
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
            self.elems_in_me = EXPCP!(self.elems_in_me.checked_sub(1), "impossible situation");
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
            let cb_elem = EXPCP!(
                self.data_map.get_mut(&x_cb),
                "critical condition, the .cb counter points to an element that is not in the \
                     table"
            );
            cb_elem.cl = removed_elem.cl
        }

        if let Some(x_cl) = removed_elem.cl {
            let cl_elem = EXPCP!(
                self.data_map.get_mut(&x_cl),
                "critical condition, the .cl counter points to an element that is not in the \
                     table"
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
                        EXPCP!(
                            self.data_map.get(cb_id),
                            "Critical error: incorrect logic, link to previous element \
                                 exists, but it is missing from the table."
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
                        EXPCP!(
                            self.data_map.get(cl_id),
                            "Critical error: incorrect logic, link does not exist, but it is \
                                 missing from the table."
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
    ///returns all elements whose p_order value is less than or equal to
    ///p_order_limit as a list Vec<(u64, P, T)>, where u64 is its id, P is
    ///its p_order, and T is the data itself
    ///Note: To speed up the operation, the pre_created_vec option was added.
    ///If pre_created_vec == Some, the write will be made to this variable,
    ///and the function will return None.
    ///If you pass None to pre_created_vec, the write will be made to a new variable,
    ///which will be returned.
    ///If there are no elements in the queue that are less than the specified value,
    ///the function will return None, and if pre_created_vec == Some, it will perform a
    /// .clear() operation on the value inside.
    pub fn get_elements_to(
        &mut self,
        p_order_limit: P,
        mut pre_created_vec: Option<&mut Vec<(u64, P, T)>>,
    ) -> Option<Vec<(u64, P, T)>> {
        if let Some(x) = pre_created_vec.as_deref_mut() {
            x.clear(); //Be sure to clean before use!
        }

        if self.elems_in_me == 0 {
            return None;
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
        let mut local_backup_vec = None;

        let reta_vec = if let Some(pre_vec) = pre_created_vec {
            pre_vec
        } else {
            local_backup_vec = Some(Vec::with_capacity(
                self.elems_in_me
                    .checked_div(3)
                    .expect("division by zero or overflow"),
            ));
            local_backup_vec
                .as_mut()
                .expect("unreal state, there should be Some here if the code is at this point")
        };

        let mut temp_id = first;

        for x in 0..self.elems_in_me {
            let temp = EXPCP!(
                self.data_map.get(&temp_id),
                "critical condition, there is a gap in the queue "
            );
            if p_order_limit >= temp.p_order {
                reta_vec.push((temp_id, temp.p_order.clone(), temp.data.clone()));
            }
            //The last element in the sequence does not have a reference to the next element,
            //so if x + 1 ==self.elems_in_me,
            //then this element is the last one and there is no need to take cl from it, since
            // it is None.
            if EXPCP!(x.checked_add(1), "err x + 1") == self.elems_in_me {
                break;
            }
            temp_id = EXPCP!(temp.cl, "critical condition, there is a gap in the queue ");
        }
        local_backup_vec
    }
    ///How many meters are in the queue?
    pub fn elems_in_me(&self) -> usize {
        self.elems_in_me
    }
    /// if len == 0 -> true
    pub fn is_empty(&self) -> bool {
        self.elems_in_me == 0
    }

    /// get max capacity of elems
    pub fn capacity(&self) -> usize {
        self.max_capacity_elems
    }

    ///Get the maximum ID and P (the element itself) in the queue
    pub fn max_elem_id_and_p(&self) -> Option<(u64, P)> {
        self.of_max_p.as_ref().map(|x| (x.0, x.1.clone()))
    }
    ///Get the minimum ID and P (the element itself) in the queue
    pub fn min_elem_id_and_p(&self) -> Option<(u64, P)> {
        self.of_min_p.as_ref().map(|x| (x.0, x.1.clone()))
    }
}

//##############################################################################################################################
//----------------------------------------TRATE TO INTERPT TYPE 'P' IN WSFbackQueue AS BYTE MESSAGE!----------------------------
pub trait NumericBytes: Sized {
    // Returns the exact size of the type in bytes
    fn bytes_len(&self) -> usize;

    // Writes Big Endian bytes directly into a pre-allocated buffer without allocations
    fn write_be_bytes(&self, buffer: &mut [u8]) -> Result<usize, &'static str>;

    // Safely restores the value from a dynamic byte slice
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

macro_rules! impl_numeric_bytes {
    ($($t:ty),*) => {
        $(
            impl NumericBytes for $t {
                #[inline(always)]
                fn bytes_len(&self) -> usize {
                    std::mem::size_of::<Self>()
                }

                #[inline(always)]
                fn write_be_bytes(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
                    let size = std::mem::size_of::<Self>();
                    if buffer.len() < size {
                        return Err("Buffer is too small");
                    }
                    // Safe buffer copy without unsafe or memory allocations
                    buffer.get_mut(..size).ok_or(" buffer.get_mut(..size) out of range")?.copy_from_slice(&self.to_be_bytes());
                    Ok(size)
                }

                #[inline(always)]
                fn from_bytes(bytes: &[u8]) -> Option<Self> {
                    let array: [u8; std::mem::size_of::<$t>()] = bytes.try_into().ok()?;
                    Some(Self::from_be_bytes(array))
                }
            }
        )*
    };
}

// Generate code for all your target types
impl_numeric_bytes!(u64, i64, f64, f32, u32, i32, i16, u16, u8, i8);

// Clean separate implementation for bool
impl NumericBytes for bool {
    #[inline(always)]
    fn bytes_len(&self) -> usize {
        1
    }

    #[inline(always)]
    fn write_be_bytes(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if buffer.is_empty() {
            return Err("Buffer is too small");
        }
        {
            #![allow(clippy::as_conversions)]
            debug_assert!(*self as usize <= u8::MAX as usize);

            (*buffer
                .first_mut()
                .ok_or(" buffer.first_mut() out of range")?) = *self as u8;
        }
        Ok(1)
    }

    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [0] => Some(false),
            [1] => Some(true),
            _ => None,
        }
    }
}

//##############################################################################################################################
//
//
///WSFbackQueue structure for creating and receiving accepted counters from the
/// protocol packet field
#[derive(Clone, Debug)]
pub struct WSFbackQueue<P> {
    ctr_slice_len: usize,

    data: Box<[u64]>,
    ptr: usize,
    max: u64,
    min: u64,
    ptr_of_min: usize,
    max_p_in_queue: Option<P>,
}

impl<P: PartialEq + PartialOrd + Clone + Default + Debug + NumericBytes> WSFbackQueue<P> {
    ///size in bytes of type P
    pub const P_SIZE: usize = std::mem::size_of::<P>();
    ///Find out how many counters can fit within the specified payload_mtu size (the
    /// payload_mtu specifies the size in bytes,  and counters can occupy
    /// several bytes, ranging from 1 to 8)
    pub fn max_len_from_mtu(len_ctr_field: usize, payload_mtu: usize) -> Result<usize, String> {
        if len_ctr_field == 0 || len_ctr_field > 8 {
            return Err("pack_topology.counter_slice() == 0 or len_ctr_field > 8".to_string());
        }

        let ctrs = payload_mtu
            .checked_sub(Self::P_SIZE)
            .ok_or("mtu < P_len_as_bytes")?
            .checked_sub(U64_LEN_IN_BYTES)
            .ok_or(
                "mtu < (pack_topology.total_minimal_len() + U64_LEN_IN_BYTES + P_len_as_bytes )"
                    .to_string(),
            )?
            .checked_div(len_ctr_field)
            .ok_or("division by zero or overflow")?;

        if ctrs == 0 {
            return Err("The MTU is too small to accommodate even one counter.".to_string());
        }

        Ok(ctrs)
    }
    ///payload_mtu indicates the maximum payload length in your network in bytes
    ///len_ctr_field is a variable that takes the length of the counter field in
    /// bytes. max_len is the maximum number of counters in pieces that can be
    /// in the WSFbackQueue structure.
    ///
    ///
    ///  UPDATE !! blurred_boundaries always equals TRUE !!!
    ///
    ///
    ///  blurred_boundaries: Since WSFbackQueue was designed as a structure that
    ///  forms packet delivery confirmation packets, analogous to ACK packets in TCP,
    ///  such packets are usually much shorter than packets with useful data.
    ///  To make it more difficult to identify an ACK packet,
    ///  you can use blurred_boundaries == true,
    ///
    ///
    ///  What does blurred_boundaries == true affect? See pub fn
    /// copy_ctrs_pack_to_slice.
    pub fn new(len_ctr_field: usize, max_len: usize, payload_mtu: usize) -> Result<Self, String> {
        if max_len > Self::max_len_from_mtu(len_ctr_field, payload_mtu)? {
            return Err(
                "The byte representation of the maximum length must be less than or equal to \
                     mtu."
                    .to_string(),
            );
        }

        Ok(Self {
            ctr_slice_len: len_ctr_field,

            data: vec![0; max_len].into_boxed_slice(),
            ptr: 0,
            max: 0,
            min: 0,
            ptr_of_min: 0,
            max_p_in_queue: None,
        })
    }

    ///push also checks that abs_diff (the largest counter in the queue,
    ///  the smallest counter in the queue) was not greater than what can fit into
    /// 2^(8*len_ctr_slice)
    ///
    /// Please note that push does NOT implement SET() and uniqueness checks in order
    /// to save space,  which means that some counters in the queue may be
    /// duplicated.
    ///
    /// max_p_in_queue is the time (most likely a double) when the packet was received;
    ///  since the packet is stored for a certain amount of time before being sent,
    ///  the send time must be calculated at the end. RecvQueueCtrs is the time when
    /// the Ctr was received,  RecvQueueCtrs stores only one <P> that belongs
    /// to the packet with the largest ctr_elem;  if ctr_elem turns out to be
    /// larger than the current one,  then when writing, the old value of <P>
    /// will be replaced with the <P> belonging to the new ctr_elem
    pub fn push(&mut self, ctr_elem: u64, max_p_in_queue: P) -> Result<(), String> {
        if self.ptr >= self.data.len() {
            return Err("the queue is full".to_string());
        }
        //It is very important, because for the correct separation of important data
        // from the tail in copy_ctrs_pack_to_slice,
        //it is necessary that the maximum (or minimum, I have not yet decided) is only one in this structure
        if self.ptr > 0 && (self.max == ctr_elem || self.min == ctr_elem) {
            return Ok(());
        }

        self.max = if self.max > ctr_elem && 0 < self.ptr {
            self.max
        } else {
            self.max_p_in_queue = Some(max_p_in_queue);
            ctr_elem
        };

        self.min = if self.min < ctr_elem && 0 < self.ptr {
            self.min
        } else {
            self.ptr_of_min = self.ptr;
            ctr_elem
        };

        let diff = self.max.checked_sub(self.min).ok_or(
            "wtf broo. what the fuck is the minimum number MORE than the maximum fucking?",
        )?;

        if diff > w1utils::len_byte_maximal_capacity_check(self.ctr_slice_len).0 {
            return Err(
                "The difference between the maximum and minimum counters is greater than the \
                     counter_slice field can hold."
                    .to_string(),
            );
        }

        let slot = self
            .data
            .get_mut(self.ptr)
            .ok_or("queue index out of bounds")?;
        *slot = ctr_elem;

        self.ptr = self.ptr.checked_add(1).ok_or("counter overflow")?;

        Ok(())
    }
    ///calculates how many more times counters can be push()
    pub fn free_space(&self) -> usize {
        EXPCP!(
            self.data.len().checked_sub(self.ptr),
            "obvious algorithm error The pointer counter is always no longer than the length \
                 of the Box."
        )
    }

    ///returns the length of the entire queue in bytes
    ///queue structure
    /// |-------------|--------------------|-----|-----|-----|----|-----|
    /// |p of max u64 |8 bytes u64 main ctr|ctr_1|ctr_2|ctr_3|....|ctr_N|
    /// |-------------|--------------------|-----|-----|-----|----|-----|
    ///
    /// ctr len = len_ctr_field
    pub fn payload_len_in_bytes(&self) -> usize {
        //P as bytes+ U64_LEN_IN_BYTES + (self.ptr * self.ctr_slice_len)
        EXPCP!(
            Self::P_SIZE.checked_add(EXPCP!(
                EXPCP!(
                    self.ptr.checked_mul(self.ctr_slice_len),
                    "self.payload_len()* self.ctr_slice_len overflow"
                )
                .checked_add(U64_LEN_IN_BYTES),
                "(self.payload_len()* self.ctr_slice_len) + U64_LEN_IN_BYTES overflow"
            )),
            "(self.payload_len()* self.ctr_slice_len) + U64_LEN_IN_BYTES + P as bytes -> overflow"
        )
    }
    ///How many meters are in the queue?
    pub fn elems_in_me(&self) -> usize {
        self.ptr
    }

    ///capacity
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    ///if len == 0  -> true
    pub fn is_empty(&self) -> bool {
        self.ptr == 0
    }

    #[cfg(test)]
    ///only needed in a test scenario

    pub fn test_get_state(&self) -> Box<[u64]> {
        self.data.clone()
    }

    ///get_ctrs_as_byte_pack_vec is a wrapper for  copy_ctrs_pack_to_slice
    /// Option<P> in the return value from the function is the P of the largest counter by u64 value
    /// If the structure contains no counters, it will return an array of zero length! Ok([], None)
    pub fn get_ctrs_as_byte_pack_vec(&mut self) -> (Box<[u8]>, Option<P>) {
        if 0 == self.ptr {
            return (vec![].into_boxed_slice(), None);
        }

        let mut ret_vec = vec![0; self.payload_len_in_bytes()].into_boxed_slice();

        let err = self.copy_ctrs_pack_to_slice(&mut ret_vec, false);

        let ret = EXPCP!(
            err,
            &format!(
                "algorithm error; if the code has been tested, there should be no errors ret_vec len {} state(no data) {:#?}",
                ret_vec.len(),
                {
                    // in debug
                    let mut x = self.clone();
                    x.data = Vec::new().into_boxed_slice();
                    x
                }
            )
        );

        debug_assert!(self.ptr == 0);
        debug_assert!(self.min == 0);
        debug_assert!(self.max == 0);
        debug_assert!(self.max_p_in_queue.is_none());

        (ret_vec, ret.1)
    }
    /// get the full set of reverse counters, but copy them to a byte array to avoid
    /// additional memory allocation To find out what the length of
    /// pack_payload_slice should be, call self.payload_len_in_bytes().
    /// get_ctrs_as_byte_pack_vec and copy_ctrs_pack_to_slice return all contents of
    /// the queue, and the WSFbackQueue structure is completely cleared of
    /// internal objects.
    ///
    ///  UPDATE !! blurred_boundaries always equals TRUE !!!
    ///
    /// If the structure contains no counters, it will return an usize of zero length! Ok(0, None)
    ///
    /// if blurred_boundaries == true
    ///then pack_payload_slice: &mut [u8] can be GREATER THAN OR EQUAL TO
    /// self.payload_len_in_bytes() usize,
    ///
    ///queue structure
    /// |-------------|--------------------|-----|-----|-----|----|-----|
    /// |p of max u64 |8 bytes u64 main ctr|ctr_1|ctr_2|ctr_3|....|ctr_N|
    /// |-------------|--------------------|-----|-----|-----|----|-----|
    ///
    /// ctr len = len_ctr_field
    ///The counter under the number ctr_N, i.e. the last counter, is always equal to
    /// 0.
    /// Option<P> in the return value from the function is the P of the largest counter by u64 value
    /// P in return is a time mark or largest ctr u64
    pub fn copy_ctrs_pack_to_slice(
        &mut self,
        pack_payload_slice: &mut [u8],
        fill_tail_zeros: bool,
    ) -> Result<(usize, Option<P>), String> {
        let payload_len_in_bytes = self.payload_len_in_bytes();

        let p_my = if let Some(x) = self.max_p_in_queue.as_ref() {
            debug_assert!(
                self.ptr != 0,
                "an impossible state, since if there are no objects in the queue (ptr == 0, then no objects were added, which means p should be None)"
            );
            x.clone()
        } else {
            debug_assert!(
                self.ptr == 0,
                "an impossible state, since if there are objects in the queue, (ptr !=0 then objects were not added, which means p must be Some)"
            );
            P::default()
        };

        {
            //add P as bytes
            let main_p_slice = pack_payload_slice
                .get_mut(..Self::P_SIZE)
                .ok_or("invalid main p size counter slice")?;

            debug_assert_eq!(main_p_slice.len(), Self::P_SIZE);

            p_my.write_be_bytes(main_p_slice)
                .expect("Buffer size is always sufficient for safe primitive types");
        }

        {
            //add u64 as bytes
            let main_ctr_slice = pack_payload_slice
                .get_mut(
                    Self::P_SIZE
                        ..U64_LEN_IN_BYTES
                            .checked_add(Self::P_SIZE)
                            .ok_or("invalid main counter slice in P as bytes + u64 as bytes")?,
                )
                .ok_or("invalid main counter slice")?;
            w1utils::u64_to_1_8bytes(self.min, main_ctr_slice)?;
        }

        if 0 == self.ptr {
            if fill_tail_zeros {
                pack_payload_slice.fill(0);
            }
            return Ok((0, None));
        }

        let pack_payload_real = {
            let temp = pack_payload_slice
                .split_at_mut_checked(payload_len_in_bytes)
                .ok_or("self.payload_len() > pack_payload_slice.len()")?;
            if fill_tail_zeros {
                temp.1.fill(0); // temp.1 is tail
            }
            temp.0 //place for payload
        };

        let last_idx = self
            .ptr
            .checked_sub(1)
            .ok_or("impossible state overflow when subtracting")?;

        // Read values first using safe indexing to avoid overlapping mutable borrows
        let min_val = *self.data.get(self.ptr_of_min).ok_or("invalid min index")?;
        let last_val = *self.data.get(last_idx).ok_or("invalid last index")?;

        // Write back using separate mutable borrows to satisfy borrow checker
        if self.ptr_of_min != last_idx {
            *self
                .data
                .get_mut(self.ptr_of_min)
                .ok_or("invalid min index")? = last_val;
            *self.data.get_mut(last_idx).ok_or("invalid last index")? = min_val;
        }

        let payload_rest = pack_payload_real
            .get_mut(
                U64_LEN_IN_BYTES.checked_add(Self::P_SIZE).ok_or(
                    "invalid main counter slice in P as bytes + u64 as bytes in payload_rest",
                )?..,
            )
            .ok_or("invalid payload rest slice")?;

        // Use iterator with take() instead of slicing [..] to avoid direct indexing
        for (sls, ctr_val) in payload_rest
            .chunks_exact_mut(self.ctr_slice_len)
            .zip(self.data.iter().take(self.ptr))
        {
            let diff = (*ctr_val).checked_sub(self.min).ok_or(
                "algorithm error, the minimum value must be less than any value in the array",
            )?;
            w1utils::u64_to_1_8bytes(diff, sls).map_err(|_| "unreal state")?;
        }

        self.ptr = 0;
        self.max = 0;
        self.min = 0;
        /*
        Here, the Some(Some(...).expect()) construct is chosen to check at the compilation stage that the values ​​correspond to the program logic.*/
        Ok((
            payload_len_in_bytes,
            Some(self.max_p_in_queue.take().expect(
                "impossible state! The value can be none only if the queue is empty, \
         but if the queue is empty, then return should be at the beginning of the function.",
            )),
        ))
    }

    fn len_check<'a>(
        payload: &'a [u8],
        len_ctr_field: usize,
    ) -> Result<(P, u64, usize, std::slice::ChunksExact<'a, u8>), String> {
        let ret_len_ctrs = payload
            .len()
            .checked_sub(U64_LEN_IN_BYTES)
            .ok_or(
                "The packet length is less than the reference counter length(-U64_LEN_IN_BYTES), which is an invalid \
                 packet.",
            )?
            .checked_sub(Self::P_SIZE)
            .ok_or(
                "The packet length is less than the reference counter length(-(U64_LEN_IN_BYTES + Self::P_SIZE)), which is an invalid \
                 packet.",
            )?;

        if 0 == len_ctr_field {
            return Err("its unreal state 0 == len_ctr_field".to_string());
        }

        let my_p = P::from_bytes(
            payload
                .get(..Self::P_SIZE)
                .ok_or("invalid p counter slice")?,
        )
        .expect("P::from_bytes2 impossible state");

        let main_ctr_slice = payload
            .get(
                Self::P_SIZE
                    ..Self::P_SIZE
                        .checked_add(U64_LEN_IN_BYTES)
                        .ok_or("invalid P_SIZE +U64_LEN_IN_BYTES")?,
            )
            .ok_or("invalid main counter slice")?;

        let payload_rest = payload
            .get(
                Self::P_SIZE
                    .checked_add(U64_LEN_IN_BYTES)
                    .ok_or("invalid P_SIZE +U64_LEN_IN_BYTES in payload_rest")?..,
            )
            .ok_or("invalid ctrs rest slice")?;

        Ok((
            my_p,
            w1utils::bytes_to_u64(main_ctr_slice)?,
            ret_len_ctrs
                .checked_div(len_ctr_field)
                .expect("division by zero or overflow"),
            payload_rest.chunks_exact(len_ctr_field),
        ))
    }
    ///receives a slice as input, i.e.
    ///  the output from the copy_ctrs_pack_to_slice or get_ctrs_as_byte_pack_vec
    /// method,  and then returns an array of u64 values that are counters.
    ///Note: To speed up the operation, the pre_created_vec option was added.
    ///If pre_created_vec == Some, the write will be made to this variable,
    ///and the function will return None.
    ///If you pass None to pre_created_vec, the write will be made to a new variable,
    ///which will be returned.
    ///If there are no elements in the queue that are less than the specified value,
    ///the function will return None, and if pre_created_vec == Some, it will perform a
    /// .clear() operation on the value inside.
    /// P in return is a time mark or largest ctr u64
    pub fn split_byte_ctrs_pack_to_slice(
        payload_bytes: &[u8],
        len_ctr_field: usize,
        mut pre_created_vec: Option<&mut Vec<u64>>,
    ) -> Result<(P, Option<Vec<u64>>), String> {
        if let Some(x) = pre_created_vec.as_deref_mut() {
            x.clear(); //Be sure to clean before use!
        }

        let pre_pross = Self::len_check(payload_bytes, len_ctr_field)?;

        let mut local_vec = None;

        let ret = if let Some(xs) = pre_created_vec {
            debug_assert!(xs.is_empty());
            xs
        } else {
            local_vec = Some(Vec::with_capacity(pre_pross.2));
            local_vec.as_mut(). ok_or("this is an unrealistic state, since the vector is defined above in the adjacent line")?
        };

        for ctr_chank in pre_pross.3 {
            let r_ctr = pre_pross
                .1
                .checked_add(w1utils::bytes_to_u64(ctr_chank)?)
                .ok_or(
                    "The reference counter + one of the delta counters caused overflow \
                         operations; most likely, the packet has an error.",
                )?;

            ret.push(r_ctr);
            if r_ctr == pre_pross.1 {
                //if this is the final element, then the payload is complete
                break;
                //return Ok(ret.into_boxed_slice());
            }
        }

        debug_assert_eq!(
            (payload_bytes
                .len()
                .checked_sub(Self::P_SIZE)
                .expect("in test")
                .checked_sub(U64_LEN_IN_BYTES)
                .expect("in test")
                < len_ctr_field),
            ret.is_empty()
        );

        if ret.is_empty() {
            Ok((P::default(), None))
        } else {
            Ok((pre_pross.0, local_vec))
        }
    }
    ///receives a slice as input, i.e.
    ///  the output from the copy_ctrs_pack_to_slice or get_ctrs_as_byte_pack_vec
    /// method,
    ///
    /// Since WSFbackQueue is intended to be used with WSWaitQueue to avoid
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
    ///  P is the timestamp of the largest counter in payload_ctrs
    ///
    /// )
    pub fn delete_ctrs_in_byte_pack_from_ws_wait_queue<T>(
        payload_ctrs: &[u8],
        len_ctr_field: usize,
        wait_queue: &mut WSWaitQueue<T, P>,
    ) -> Result<(usize, Option<P>, Option<P>, P), String>
    where
        T: Clone + Debug,
        P: PartialEq + PartialOrd + Clone + Debug,
    {
        let pre_pross = Self::len_check(payload_ctrs, len_ctr_field)?;
        let mut how_was_deleted: usize = 0;
        let mut min_del = None;
        let mut max_del = None;
        for ctr_chank in pre_pross.3 {
            let ret_el = pre_pross
                .1
                .checked_add(w1utils::bytes_to_u64(ctr_chank)?)
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

                how_was_deleted = EXPCP!(how_was_deleted.checked_add(1), "err 1 + how_was_deleted");
            }

            if pre_pross.1 == ret_el {
                //if this is the final element, then the payload is complete
                return Ok((how_was_deleted, min_del, max_del, pre_pross.0));
            }
        }

        Ok((how_was_deleted, min_del, max_del, pre_pross.0))
    }
    ///get the maximum and minimum counters currently in the queue
    pub fn get_min_max_and_max_p(&self) -> (u64, u64, Option<P>) {
        (self.min, self.max, self.max_p_in_queue.clone())
    }
}

impl<T, P> WSWaitQueue<T, P> {
    #[cfg(test)]
    ///for test only
    pub fn for_test_data_map(&self) -> &HashMap<u64, ElemMy<T, P>, IdentityBuildHasher> {
        &self.data_map
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_max_capacity_elems(&self) -> usize {
        self.max_capacity_elems
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_elems_in_me(&self) -> usize {
        self.elems_in_me
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_of_min_p(&self) -> Option<&(u64, P)> {
        self.of_min_p.as_ref()
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_of_max_p(&self) -> Option<&(u64, P)> {
        self.of_max_p.as_ref()
    }
}
impl<T, P> ElemMy<T, P> {
    #[cfg(test)]
    ///for test only
    pub fn for_test_cl(&self) -> Option<u64> {
        self.cl
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_cb(&self) -> Option<u64> {
        self.cb
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_data(&self) -> &T {
        &self.data
    }

    #[cfg(test)]
    ///for test only
    pub fn for_test_p_order(&self) -> &P {
        &self.p_order
    }
}
