use crate::wutils;

const FILE_HEAD_LEN: usize = 9;

use core::panic;
use std::{cmp::min, rc::Rc};

#[derive(Debug, PartialEq, Clone)]
struct DataDrain {
    ptr_in_head: usize,
    ptr_in_body: usize,
    len_of_head: usize,
    head: [u8; FILE_HEAD_LEN],
}

#[derive(Debug, PartialEq, Clone)]
pub struct WSFileSplitter {
    max_len_of_file: Option<usize>,
    send_file: Option<(DataDrain, Rc<Vec<u8>>)>,
    recv_data: Option<(DataDrain, Option<Vec<u8>>)>,
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

        let cap_head_of_rc = wutils::len_u64_as_bytes(rc_file.len() as u64);

        if cap_head_of_rc > u8::MAX as usize {
            panic!("panic because the values from cap_head_of_rc.1 must be in a range smaller than u8::MAX");
        }
        if cap_head_of_rc + 1 > FILE_HEAD_LEN {
            panic!("Panic because the file header (u64 as bytes len + 1 byte length) is larger than FILE_HEAD_LEN");
        }

        let mut new_file = DataDrain {
            ptr_in_head: 0,
            ptr_in_body: 0,
            len_of_head: 1 + cap_head_of_rc,
            head: [0; FILE_HEAD_LEN],
        };

        new_file.head[0] = cap_head_of_rc as u8;
        wutils::u64_to_1_8bytes(
            rc_file.len() as u64,
            &mut new_file.head[1..1 + cap_head_of_rc],
        )?;

        self.send_file = Some((new_file, rc_file));
        Ok(())
    }

    pub fn file_to_slices(&mut self, slice: &mut [u8]) -> usize {
        let mut how_much_left = 0;

        if let Some(rfile) = &mut self.send_file {
            let slice =/*copy head*/ if rfile.0.ptr_in_head < rfile.0.len_of_head {
                let min_len = min(slice.len(), rfile.0.len_of_head - rfile.0.ptr_in_head);

                slice[..min_len].copy_from_slice(&rfile.0.head[rfile.0.ptr_in_head..rfile.0.ptr_in_head + min_len] );
                rfile.0.ptr_in_head += min_len;
                &mut slice[min_len..]
            } else {
                slice
            };
            //body
            if rfile.0.ptr_in_body < rfile.1.len() {
                let min_len = min(slice.len(), rfile.1.len() - rfile.0.ptr_in_body);

                slice[..min_len]
                    .copy_from_slice(&rfile.1[rfile.0.ptr_in_body..rfile.0.ptr_in_body + min_len]);
                rfile.0.ptr_in_body += min_len;
            }

            how_much_left = rfile.0.len_of_head.checked_sub(rfile.0.ptr_in_head).expect("panic an impossible state The pointer len_of_head must always be less than or equal to ptr_in_head.").checked_add( rfile.1.len().checked_sub(rfile.0.ptr_in_body).expect("panic an impossible state The pointer rfile.1.len() must always be less than or equal to rfile.0.ptr_in_body.")).expect("usize type is overflow");
        }

        if 0 == how_much_left {
            self.send_file = None
        }

        how_much_left
    }

    fn start_proc_file<'a>(&mut self, slice: &'a [u8]) -> Option<&'a [u8]> {
        let slice = if self.recv_data.is_none() {
            if let Some(index) = slice.iter().position(|&x| x > 0) {
                &slice[index..]
            } else {
                return None;
            }
        } else {
            &slice
        };

        if 0 == slice.len() {
            return None;
        }

        if self.recv_data.is_none() {
            self.recv_data = Some((
                DataDrain {
                    len_of_head: slice[0] as usize,
                    ptr_in_body: 0,
                    ptr_in_head: 1, //len_of_head is first byte
                    head: [0; FILE_HEAD_LEN],
                },
                None,
            ));
        }
        Some(slice)
    }

    pub fn slices_to_file(&mut self, slice: &[u8]) -> usize {
        let slice = if let Some(slic) = self.start_proc_file(slice) {
            slic
        } else {
            return 0;
        };

        if if let Some(recv_me) = &mut self.recv_data {
            // (1 byte of len) + (1-8bytes of u64)

            let (slice, head_is_full) = if recv_me.0.len_of_head + 1 > recv_me.0.ptr_in_head {
                let min_len = min(
                    slice.len(),
                    recv_me.0.len_of_head + 1 - recv_me.0.ptr_in_head,
                );
                let shif = FILE_HEAD_LEN - recv_me.0.len_of_head;
                recv_me.0.head
                    [shif + recv_me.0.ptr_in_head..shif + recv_me.0.ptr_in_head + min_len]
                    .copy_from_slice(&slice[..min_len]);

                recv_me.0.ptr_in_body += min_len;
                (
                    &slice[min_len..],                                   //new slice
                    (recv_me.0.len_of_head + 1 > recv_me.0.ptr_in_head), //bool
                )
            } else {
                (slice, true)
            };

            if recv_me.1.is_none() && head_is_full {
                recv_me.1 = Some(vec![0; wutils::bytes_to_u64(&recv_me.0.head[1..])
                        .expect("impossible state Slice lengths and boundaries are static, verified at compile time, and do not change dynamically.") as usize]);
                false
            } else {
                if let Some(file_recv) = &mut recv_me.1 {
                    let min_len = min(slice.len(), file_recv.len() - recv_me.0.ptr_in_body);

                    file_recv[recv_me.0.ptr_in_body..recv_me.0.ptr_in_body + min_len]
                        .copy_from_slice(&slice[..min_len]);

                    recv_me.0.ptr_in_body += min_len;

                    recv_me.0.ptr_in_body >= file_recv.len() //bool
                } else {
                    panic!("impossible state, Some is created above");
                }
            }
        } else {
            panic!("impossible state, Some is created above");
        } {
            println!("{:?}", self.recv_data.clone().unwrap().1.unwrap());
            self.recv_data = None
        }

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

#[cfg(test)]
mod tests_wudp {

    use super::*;
    #[test]
    fn test_simple_create() {
        let tw_s_z = WSFileSplitter::new(Some(0));
        let _tw_s = WSFileSplitter::new(Some(100)).unwrap();

        assert_eq!(tw_s_z, Err("max_len_of_recv must be greater than zero"));

        let _tw_n = WSFileSplitter::new(None).unwrap();
    }
    #[test]
    fn test_file_splitt() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        let rc: Rc<Vec<u8>> = Rc::new((0..50).map(|x| x).collect());
        let rc_err: Rc<Vec<u8>> = Rc::new((0..51).map(|x| x).collect());
        assert_eq!(
            tw_s.write_new_rc_file(rc_err),
            Err("rc_file length greater than max_len_of_recv")
        );

        assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

        println!("{:?}", tw_s.clone().send_file.unwrap().0);

        assert_eq!(
            tw_s.write_new_rc_file(rc),
            Err("WSFileSplitter already has an unprocessed file ")
        );

        let mut reta1 = vec![0; 20];
        let mut reta2 = vec![0; 0];
        let mut reta3 = vec![0; 7];
        let mut reta4 = vec![0; 11];
        let mut reta5 = vec![0; 19];

        assert_eq!(tw_s.file_to_slices(&mut reta1), 50 + 1 + 1 - 20);
        assert_eq!(
            tw_s.clone().send_file.unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 18,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(tw_s.file_to_slices(&mut reta2), 50 + 1 + 1 - 20 - 0);
        assert_eq!(
            tw_s.clone().send_file.unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 18,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(tw_s.file_to_slices(&mut reta3), 50 + 1 + 1 - 20 - 0 - 7);
        assert_eq!(
            tw_s.clone().send_file.unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 25,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(
            tw_s.file_to_slices(&mut reta4),
            50 + 1 + 1 - 20 - 0 - 7 - 11
        );
        assert_eq!(
            tw_s.clone().send_file.unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 36,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(tw_s.file_to_slices(&mut reta5), 0);
        assert_eq!(tw_s.clone().send_file.is_none(), true);

        println!("{:?}", reta1);
        //println!("{:?}", reta2);is zero size
        println!("{:?}", reta3);

        println!("{:?}", reta4);
        println!("{:?}", reta5);

        assert_eq!(
            reta1,
            [1, 50, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        );
        assert_eq!(reta2, []);
        assert_eq!(reta3, [18, 19, 20, 21, 22, 23, 24]);
        assert_eq!(reta4, [25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35]);
        assert_eq!(
            reta5,
            [36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_spkit_to_file() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        let rc: Rc<Vec<u8>> = Rc::new((0..50).map(|x| x).collect());

        assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

        let mut reta1 = vec![0; 55];
        //let mut reta5 = vec![0; 19];

        tw_s.file_to_slices(&mut reta1);

        tw_s.slices_to_file(&reta1);
    }
}
