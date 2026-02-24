use crate::wutils;

const FILE_HEAD_LEN: usize = 9;

use std::{cmp::min, rc::Rc};

#[derive(Debug, PartialEq, Clone)]
struct DataDrain {
    ptr_in_head: usize,
    ptr_in_body: usize,
    len_of_head: usize,
    head: [u8; FILE_HEAD_LEN],
}

///The WSFileSplitter structure is needed to split the data stream into separate user-defined
///  files of arbitrary length and to create files from user data
///  for transmission over a TCP-like data stream.
///  In protocols where there is no data splitting and data is not marked.
///  The maximum file size is (2^64) - 9 bytes.
#[derive(Debug, PartialEq, Clone)]
pub struct WSFileSplitter {
    max_len_of_file: Option<usize>,
    send_file: Option<(DataDrain, Rc<Vec<u8>>)>,
    recv_data: Option<(DataDrain, Option<Vec<u8>>)>,
}

impl WSFileSplitter {
    ///max_len_of_file is a variable that limits the maximum size of incoming and outgoing files.
    ///  This is necessary to prevent systems with
    ///  limited resources from allocating memory for very large files.
    ///  If the limitation is not needed, leave the value as None.
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
    /// Write a new file get a file, Rc<Vec<u8>> Rc is used to minimize the overhead of
    ///  copying data to a new vector. Only one file can be in the WSFileSplitter structure
    ///  at a time. To find out if a file is in the structure, call remaining_len_of_rc_file(&self).
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
        if rc_file.len() > u64::MAX as usize {
            panic!(
                "rc_file.len() > u64::MAX as usize  There is a slight discrepancy between the capacity of usize and u64. Your device is not suitable for this code :("
            );
        }
        //Calculates how many bytes the file size will fit into
        let cap_head_of_rc = wutils::len_u64_as_bytes(rc_file.len() as u64);

        if cap_head_of_rc > u8::MAX as usize {
            panic!(
                "panic because the values from cap_head_of_rc.1 must be in a range smaller than u8::MAX"
            );
        }

        if cap_head_of_rc + 1 > FILE_HEAD_LEN {
            panic!(
                "Panic because the file header (u64 as bytes len + 1 byte length) is larger than FILE_HEAD_LEN"
            );
        }

        let mut new_file = DataDrain {
            ptr_in_head: 0,
            ptr_in_body: 0,
            len_of_head: 1 + cap_head_of_rc,
            head: [0; FILE_HEAD_LEN],
        };
        //The structure of the slice contained in WSFileSplitter is as follows:
        // |-----------------------|---------------------------------------|------------------|
        // | 1 byte length counter |length of user data (from 1 to 8 bytes)|bytes of user data|
        // |-----------------------|---------------------------------------|------------------|
        new_file.head[0] = cap_head_of_rc as u8;
        wutils::u64_to_1_8bytes(
            rc_file.len() as u64,
            &mut new_file.head[1..1 + cap_head_of_rc],
        )?;

        self.send_file = Some((new_file, rc_file));
        Ok(())
    }

    ///file_to_slices accepts multiple slices of varying lengths and copies file data into them.
    ///  IMPORTANT: file_to_slices DOES NOT MARK THE SEQUENCE OF SLICES IN ANY WAY!
    ///  THE ORDER IN WHICH THE SLICES WERE TRANSFERRED
    ///  IS THE ORDER IN WHICH THEY MUST BE RECEIVED IN slices_to_file!.
    ///
    ///Note that slices can be of any length.
    ///  If a slice is shorter than the file or the remaining part of the file,
    ///  the remaining end of the slice will be filled with zeros.
    ///  To calculate the slice length more optimally,
    ///  you can find out the size of the remaining bytes by calling remaining_len_of_rc_file($self).
    ///
    ///  If the file bytes in the structure have ended, and remaining_len_of_rc_file($self) == None,
    ///  then the structure can accept the next file in write_new_rc_file().
    /// This function returns -> Option<usize> because it involves remaining_len_of_rc_file($self)
    /// internally, so if file_to_slices() == None, it means the file is finished.
    pub fn file_to_slices(&mut self, slice: &mut [u8]) -> Option<usize> {
        let mut how_much_left = 0;
        //if the file exists
        if let Some(rfile) = &mut self.send_file {
            //slice with truncated header bytes

            let slice_after_head =/*copy head*/ if rfile.0.ptr_in_head < rfile.0.len_of_head/*if not all of the head is copied*/ {
                //checking which is smaller, the slice length or the remaining bytes in the header
                let min_len = min(slice.len(), rfile.0.len_of_head - rfile.0.ptr_in_head);
                //copying bytes from the header to the slice
                slice[..min_len].copy_from_slice(&rfile.0.head[rfile.0.ptr_in_head..rfile.0.ptr_in_head + min_len] );
                //adding the number of bytes copied from the header to the copied bytes pointer
                rfile.0.ptr_in_head += min_len;
                //return the slice with the already filled part truncated to slice_after_head
                &mut slice[min_len..]
            } else {
                //if the head has already been copied, return the untouched slice to slice_after_head
                slice
            };
            //body
            if rfile.0.ptr_in_body < rfile.1.len() {
                //checking which is smaller, the slice length or the remaining bytes in the body
                let min_len = min(slice_after_head.len(), rfile.1.len() - rfile.0.ptr_in_body);
                //If there are any untouched bytes left at the end of the slice,
                // they must be filled with zeros to clear them of user garbage.
                if min_len < slice_after_head.len() {
                    slice_after_head[min_len..].fill(0);
                }
                //copying bytes from the body to the slice
                slice_after_head[..min_len]
                    .copy_from_slice(&rfile.1[rfile.0.ptr_in_body..rfile.0.ptr_in_body + min_len]);
                rfile.0.ptr_in_body += min_len;
            }
            //rfile.0.len_of_head - rfile.0.ptr_in_head + (file.1.len() -rfile.0.ptr_in_body )
            how_much_left = self.remaining_len_of_send_file().expect("impossible state, if &mut self.send_file == Some() then self.remaining_len_of_rc_file() must also return Some(usize)");
        } else {
            //If the file does not exist,
            // fill the entire slice with zeros so that there
            // is no garbage in it that could have been left by the user.
            slice.fill(0)
        }
        //if there are no more bytes left in the file, then the file will be deleted from the structure
        if 0 == how_much_left {
            self.send_file = None;
            return None;
        }

        Some(how_much_left)
    }

    fn start_proc_file<'a>(&mut self, slice: &'a [u8]) -> Result<Option<&'a [u8]>, &'static str> {
        /*It's difficult to explain, but I'll try.
        This method is mainly needed when a new file is created,
        since it is assumed that files are transferred in a stream,
        in some external packets, so it is assumed that there
        may be some space between files in the stream
        (necessarily filled with noise), for example,
        a TCP stream. |head file1|file1 body |0,0,0,0,0,0,0, |head file2|file2 body |.
        If recv_data:Option is not currently open in the structure,
        this method skips all zeros until it finds a non-zero byte,
        then checks that the first non-zero byte is in the range 1-8,
        sets the header size in recv_data: Option HEAD,
        1 byte of header length + (1-8 bytes of file body length).
        and returns a slice with the truncated initial part
        that it has already copied so as not to truncate it in the future.*/
        //
        //

        let slice = if self.recv_data.is_none() {
            //if it is a new file, we look for the first non-zero byte; if the file is open, we return the slice unchanged
            if let Some(index) = slice.iter().position(|&x| x > 0) {
                if slice[index] > 8 {
                    return Err(
                        "error, the first non-zero byte of the file is greater than 8, the length of u64 must be greater than 0 and less than 9 bytes  ",
                    );
                }
                //trimming the slice so that it starts with useful data (head)
                &slice[index..]
            } else {
                return Ok(None);
            }
        } else {
            &slice
        };
        //just in case
        if 0 == slice.len() {
            return Ok(None);
        }
        //
        if self.recv_data.is_none() {
            self.recv_data = Some((
                DataDrain {
                    len_of_head: slice[0] as usize, //use first byte
                    ptr_in_body: 0,
                    ptr_in_head: 1, //len_of_head is first byte
                    head: [0; FILE_HEAD_LEN],
                },
                None,
            ));
            //If the slice length is 1 and this is the beginning of the file,
            // then 1 byte was used as the first byte in the header.
            if 1 == slice.len() {
                Ok(None)
            } else {
                Ok(Some(&slice[1..])) //index 0 is a len of head slice[1..len_of_head+1] is a u64
            }
        } else {
            Ok(Some(slice)) //index 0 is a len of head slice[1..len_of_head+1] is a u64
        }
    }

    ///
    pub fn slices_to_file(&mut self, slice: &[u8]) -> Result<(usize, Vec<Vec<u8>>), &'static str> {
        let mut slice = slice;
        let mut old_slice_len = slice.len();

        let mut reta = vec![];
        loop {
            slice = if let Some(slic) = self.start_proc_file(slice)? {
                slic
            } else {
                return Ok((0, reta));
            };
            // IF(if the file is full and completely filled) IF(is there a head )
            if if let Some(recv_me) = &mut self.recv_data {
                // (1 byte of len) + (1-8bytes of u64)
                //head treatment
                let head_is_non_full = if recv_me.0.len_of_head + 1 > recv_me.0.ptr_in_head {
                    //find the minimum that is shorter than the length
                    //of the slice or the length of the unfilled space in the head
                    let min_len = min(
                        slice.len(),
                        recv_me.0.len_of_head + 1 - recv_me.0.ptr_in_head,
                    );
                    //copy a safe number of bytes to a file in the structure
                    recv_me.0.head[recv_me.0.ptr_in_head..recv_me.0.ptr_in_head + min_len]
                        .copy_from_slice(&slice[..min_len]);
                    //move the pointer to the number of bytes copied
                    recv_me.0.ptr_in_head += min_len;
                    //slice trimming
                    slice = &slice[min_len..]; //new slice
                    //
                    recv_me.0.len_of_head + 1 > recv_me.0.ptr_in_head //bool
                } else {
                    false
                };
                if head_is_non_full {
                    return Ok((0, reta));
                }
                //if there is no body (payload)
                if recv_me.1.is_none() {
                    //calculation of payload length
                    let len_vec =
                        wutils::bytes_to_u64(&recv_me.0.head[1..1 + recv_me.0.len_of_head]).expect("impossible state Slice lengths and boundaries are static, verified at compile time, and do not change dynamically.");

                    if len_vec > usize::MAX as u64 {
                        panic!(
                            "len_vec > usize::MAX as u64  There is a slight discrepancy between the capacity of usize and u64. Your device is not suitable for this code :("
                        );
                    }

                    if 0 == len_vec {
                        return Err(
                            "An error occurred, the file size == 0 which is impossible, it's likely the file has been corrupted",
                        );
                    }
                    if let Some(m_len) = self.max_len_of_file {
                        if len_vec as usize > m_len {
                            return Err(
                                "The size of the received file exceeds the maximum max_len_of_file.",
                            );
                        }
                    }

                    recv_me.1 = Some(vec![0; len_vec as usize]);
                }
                //if the load vector has already been allocated
                if let Some(file_recv) = &mut recv_me.1 {
                    //find the minimum that is shorter than the length
                    //of the slice or the length of the unfilled space in the body
                    let min_len = min(slice.len(), file_recv.len() - recv_me.0.ptr_in_body);
                    //copy a safe number of bytes to a file in the structure
                    file_recv[recv_me.0.ptr_in_body..recv_me.0.ptr_in_body + min_len]
                        .copy_from_slice(&slice[..min_len]);
                    //move the pointer to the number of bytes copied
                    recv_me.0.ptr_in_body += min_len;
                    //slice trimming
                    slice = &slice[min_len..]; //new slice
                    //
                    if recv_me.0.ptr_in_body > file_recv.len() {
                        panic!(
                            "impossible condition, according to the logic of the program, the pointer should not be longer than the length of the massva file"
                        );
                    }
                    //if the file is full and completely filled
                    recv_me.0.ptr_in_body == file_recv.len() //bool
                } else {
                    panic!("impossible state, Some is created above");
                }
            } else {
                panic!("impossible state, Some is created above");
            } {
                //if the file is full and completely filled

                //The file's payload is added to the array that needs to be returned.
                reta.push(
                    std::mem::replace(&mut self.recv_data, None)
                        .expect("Panicking is an impossible state because this code is executed only when self.recv_data is Some.")
                    .1
                    .expect("Panic is an impossible state because this code only executes when self.recv_data is Some() and it has Some() vector and it's only called when the file is completely received, at this point the file should be longer than 0")

                );

                self.recv_data = None
            }

            if 0 == slice.len() {
                break;
            }
            //Since a loop is used here, according to the standard,
            //it is necessary to verify that
            //the loop will not repeat indefinitely and will exit the loop 100% of the time.
            if old_slice_len == slice.len() {
                panic!(
                    "Error in algorithm development: in each iteration of the loop, the value of slice.len() should decrease!"
                );
            }
            old_slice_len = slice.len()
        }
        Ok((0, reta))
    }

    ///Returns the full length of the received file,
    /// returns ONLY the length of the payload
    /// if the file header is not fully transmitted, returns None
    pub fn len_of_recv_file(&self) -> Option<usize> {
        if let Some(ref hea) = self.recv_data {
            if let Some(ref dataa) = hea.1 {
                Some(dataa.len())
            } else {
                None
            }
        } else {
            None
        }
    }
    //full len of sending file
    pub fn len_of_send_file(&self) -> Option<usize> {
        if let Some(ref rfile) = self.send_file {
            Some(rfile.1.len())
        } else {
            None
        }
    }
    ///returns True if there is a started file in the structure
    pub fn i_have_some_recv(&self) -> bool {
        self.recv_data.is_some()
    }
    ///Returns the remaining length of the file send by the structure.
    ///
    ///the remaining length in bytes will be returned.
    pub fn remaining_len_of_send_file(&self) -> Option<usize> {
        if let Some(ref rfile) = self.send_file {
            Some( rfile.0.len_of_head.checked_sub(rfile.0.ptr_in_head).
            expect("panic an impossible state The pointer len_of_head must always be less than or equal to ptr_in_head.").
            checked_add( rfile.1.len().
            checked_sub(rfile.0.ptr_in_body).
            expect("panic an impossible state The pointer rfile.1.len() must always be less than or equal to rfile.0.ptr_in_body.")).
            expect("usize type is overflow"))
        } else {
            None
        }
    }
    ///Returns the remaining length of the file received by the structure.
    ///
    ///Note: if the file header was not transferred completely and
    /// the length field is incomplete, the method will return None;
    /// if the header was transferred completely,
    /// then the remaining length will be returned.
    pub fn remaining_len_of_recv_file(&self) -> Option<usize> {
        if let Some(ref hea) = self.recv_data {
            if let Some(ref dataa) = hea.1 {
                Some(dataa.len().checked_sub(hea.0.ptr_in_body).expect(
                    "impossible condition, hea.0.ptr_in_bod must always be less than dataa.len()",
                ))
            } else {
                None
            }
        } else {
            None
        }
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
    fn test_simple_err() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        assert_eq!(
            tw_s.slices_to_file(&vec![9, 1, 1, 1, 1,]),
            Err(
                "error, the first non-zero byte of the file is greater than 8, the length of u64 must be greater than 0 and less than 9 bytes  "
            )
        );

        assert_eq!(
            tw_s.slices_to_file(&vec![1, 0, 1, 1, 1, 1, 1]),
            Err(
                "An error occurred, the file size == 0 which is impossible, it's likely the file has been corrupted"
            )
        );
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

        //println!("{:?}", tw_s.clone().send_file.unwrap().0);

        assert_eq!(
            tw_s.write_new_rc_file(rc),
            Err("WSFileSplitter already has an unprocessed file ")
        );

        let mut reta1 = vec![1; 20];
        let mut reta2 = vec![1; 0];
        let mut reta3 = vec![1; 7];
        let mut reta4 = vec![1; 11];
        let mut reta5 = vec![1; 19];

        assert_eq!(tw_s.file_to_slices(&mut reta1).unwrap(), 50 + 1 + 1 - 20);
        assert_eq!(
            tw_s.clone().send_file.unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 18,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(
            tw_s.file_to_slices(&mut reta2).unwrap(),
            50 + 1 + 1 - 20 - 0
        );
        assert_eq!(
            tw_s.clone().send_file.unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 18,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(
            tw_s.file_to_slices(&mut reta3).unwrap(),
            50 + 1 + 1 - 20 - 0 - 7
        );
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
            tw_s.file_to_slices(&mut reta4).unwrap(),
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

        assert_eq!(tw_s.file_to_slices(&mut reta5), None);
        assert_eq!(tw_s.clone().send_file.is_none(), true);

        // println!("{:?}", reta1);
        //println!("{:?}", reta2);is zero size
        //println!("{:?}", reta3);

        //println!("{:?}", reta4);
        //println!("{:?}", reta5);

        assert_eq!(
            reta1,
            [
                1, 50, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
            ]
        );
        assert_eq!(reta2, []);
        assert_eq!(reta3, [18, 19, 20, 21, 22, 23, 24]);
        assert_eq!(reta4, [25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35]);
        assert_eq!(
            reta5,
            [
                36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_spkit_to_file() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        let rc: Rc<Vec<u8>> = Rc::new((0..50).map(|x| x).collect());

        let rc2: Rc<Vec<u8>> = Rc::new((0..20).map(|x| 20 - x).collect());

        assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

        let mut reta1 = vec![0; 95];
        //let mut reta5 = vec![0; 19];

        tw_s.file_to_slices(&mut reta1[10..]);

        assert_eq!(tw_s.write_new_rc_file(rc2.clone()), Ok(()));

        tw_s.file_to_slices(&mut reta1[71..]);

        tw_s.slices_to_file(&reta1).unwrap();
    }

    #[test]
    fn test_spkit_to_file_flow() {
        let mut tw_s = WSFileSplitter::new(Some(9500)).unwrap();

        let mut vecca: Vec<u8> = Vec::new();

        let fs_vec = [
            40, 10, 15, 7, 1, 12, 1148, 3876, 5, 4, 43, 99, 29, 134, 17, 14, 95, 1523, 50, 9, 5, 6,
            8214, 65, 3217, 45, 43, 99, 299, 134, 117, 90, 5, 72, 4, 6, 3865, 1, 626, 3, 1, 78, 54,
            6, 94, 2, 1, 564, 7, 60, 1, 3, 1, 29, 6, 729, 4, 23,
        ];

        for file_size_in_iter in fs_vec {
            let rc: Rc<Vec<u8>> = Rc::new((0..file_size_in_iter).map(|x| x as u8).collect());

            assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

            let mut over_len = 0;
            let mut max_me = 0;
            for chunk_size in [
                4, 6, 7, 5, 6, 0, 3, 1, 45, 90, 5, 72, 4, 6, 35, 0, 62, 3, 1, 78, 5, 6, 94, 2, 1,
                64, 7, 60, 1, 3, 1, 2, 6, 79, 4, 23,
            ]
            .iter()
            .cycle()
            {
                //if *infl == 1 {
                //    print!("INFIL: {}", infl)
                //}

                let trash_noise = *chunk_size as u8;
                let mut nw = vec![ /*trash bytes*/ trash_noise ; *chunk_size];

                assert_eq!(
                    tw_s.file_to_slices(&mut nw),
                    tw_s.remaining_len_of_send_file()
                );

                //  println!("          real {} | {:?}", nw.len(), nw);

                //if over_len > 200 {
                // nw[0] = 0;
                // }

                vecca.extend_from_slice(&nw);

                let get_me = tw_s.slices_to_file(&nw).unwrap().1;

                over_len += *chunk_size;
                // println!("          real {} | {:?}  |  {:?}", nw.len(), nw, get_me);
                // println!("          real {} | {:?}  |  {:?}", nw.len(), nw, get_me);
                //checking that remaining_len_of_recv_file() returns the correct number of bytes remaining in the file
                //it does not take into account the length of the head
                max_me = if max_me < tw_s.remaining_len_of_recv_file().unwrap_or(0) {
                    assert_eq!(
                        tw_s.remaining_len_of_recv_file().unwrap_or(0) + chunk_size,
                        file_size_in_iter as usize
                            + wutils::len_u64_as_bytes(file_size_in_iter)
                            + 1
                    );

                    tw_s.remaining_len_of_recv_file().unwrap_or(0)
                } else {
                    max_me
                };
                // println!(
                //     "rema leng {}   over{}   mm {} chs {}",
                //     tw_s.remaining_len_of_recv_file().unwrap_or(0),
                //     over_len,
                //     max_me,
                //      chunk_size
                //  );

                for _xxx in get_me.clone() {
                    //println!("{}", _xxx.len());
                    max_me = 0;
                }
                for ggg in get_me {
                    // println!("----------{}| {:?} ", ggg.len(), ggg);

                    let lelel = ggg.len();

                    let xo: Vec<u8> = (0..lelel).map(|x| x as u8).collect();

                    let me_co = ggg
                        .clone()
                        .iter()
                        .zip(xo.iter())
                        .map(|x| x.0.abs_diff(*(x.1)))
                        .collect::<Vec<u8>>();

                    assert_eq!(
                        ggg,
                        xo,
                        "\n_-_-_-_meco{:?} ||||| {:?}",
                        me_co,
                        me_co.iter().position(|&x| x > 0)
                    );
                }
                if over_len >= file_size_in_iter as usize + 10 {
                    break;
                }
                //over_len += *chunk_size;
            }
        }

        assert_eq!(tw_s.slices_to_file(&vecca).unwrap().1.len(), fs_vec.len());
    }
}
