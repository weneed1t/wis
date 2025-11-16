use crate::wutils;

const FILE_HEAD_LEN: usize = 9;

use std::{cmp::min, rc::Rc};

struct DataDrain {
    ptr_in_head: usize,
    ptr_in_body: usize,
    len_of_head: usize,
    head: [u8; FILE_HEAD_LEN],
}

pub struct WSFileSplitter {
    max_len_of_file: Option<usize>,
    send_file: Option<(DataDrain, Rc<Vec<u8>>)>,
    recv_data: Option<(DataDrain, Option<Box<[u8]>>)>,
}

impl WSFileSplitter {
    pub fn new(max_len_of_file: Option<usize>) -> Result<Self, &'static str> {
        if let Some(x) = max_len_of_file {
            if x == 0 {
                return Err("max_len_of_recv must be greater than zero");
            }
        }

        Ok(Self {
            max_len_of_file: max_len_of_file,
            send_file: None,
            recv_data: None,
        })
    }

    pub fn write_new_rc_file(&mut self, rc_file: Rc<Vec<u8>>) -> Result<(), &'static str> {
        if self.send_file.is_some() {
            return Err("WSFileSplitter already has an unprocessed file ");
        }
        if let Some(x) = self.max_len_of_file {
            if rc_file.len() > x {
                return Err("rc_file length greater than max_len_of_recv");
            }
        }
        if rc_file.len() == 0 {
            return Err("rc_file must be greater than zero");
        }

        let cap_head_of_rc = wutils::len_byte_maximal_capacyty_cheak(rc_file.len());

        if cap_head_of_rc.1 < u8::MAX as usize {
            panic!("panic because the values from cap_head_of_rc.1 must be in a range smaller than u8::MAX");
        }
        if cap_head_of_rc.1 + 1 > FILE_HEAD_LEN {
            panic!("Panic because the file header (u64 as bytes len + 1 byte length) is larger than FILE_HEAD_LEN");
        }

        let mut new_file = DataDrain {
            ptr_in_head: 0,
            ptr_in_body: 0,
            len_of_head: 1 + cap_head_of_rc.1,
            head: [0; FILE_HEAD_LEN],
        };

        new_file.head[0] = cap_head_of_rc.1 as u8;
        wutils::u64_to_1_8bytes(
            rc_file.len() as u64,
            &mut new_file.head[1..1 + cap_head_of_rc.1],
        )?;

        self.send_file = Some((new_file, rc_file));
        Ok(())
    }

    pub fn file_to_slices(&mut self, slice: &mut [u8]) -> usize {
        if let Some(rfile) = &mut self.send_file {
            let ptr_slice =/*copy head*/ if rfile.0.ptr_in_head < rfile.0.len_of_head {
                let min_len = min(slice.len(), rfile.0.len_of_head - rfile.0.ptr_in_head);

                rfile.0.head[rfile.0.ptr_in_head..rfile.0.ptr_in_head + min_len]
                    .copy_from_slice(&mut slice[..min_len]);
                rfile.0.ptr_in_head += min_len;
                min_len
            } else {
                0
            };
            //body
            if rfile.0.ptr_in_body < rfile.1.len() {
                let min_len = min(slice.len(), rfile.1.len() - rfile.0.ptr_in_body);

                rfile.0.head[rfile.0.ptr_in_head..rfile.0.ptr_in_head + min_len]
                    .copy_from_slice(&mut slice[..min_len]);
                rfile.0.ptr_in_head += min_len;
                min_len
            } else {
                0
            };
        }

        0
    }
    pub fn slices_to_file(&mut self, slice: &[u8]) -> usize {
        0
    }

    pub fn len_of_recv_file() {}
    pub fn len_of_rc_file() {}

    pub fn remaining_len_of_rc_file() -> usize {
        0
    }
    pub fn remaining_len_of_recv_file() -> usize {
        0
    }
}
