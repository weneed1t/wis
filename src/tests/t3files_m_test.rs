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
use crate::t3files_m::*;
use crate::w1types::Rcc;
use crate::w1utils;

#[cfg(test)]
mod tests_file {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]

    use super::*;
    #[test]
    fn test_simple_create() {
        let tw_s_z = WSFileSplitter::new(Some(0));
        let _tw_s = WSFileSplitter::new(Some(100)).unwrap();

        assert_eq!(
            tw_s_z,
            Err("max_len_of_recv must be greater than zero".to_string())
        );

        let _tw_n = WSFileSplitter::new(None).unwrap();
    }

    #[test]
    fn test_simple_err() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        assert_eq!(
            tw_s.slices_to_files(&[9, 1, 1, 1, 1]),
            Err(
                "error, the first non-zero byte of the file is greater than 8, the length of u64 \
                 must be greater than 0 and less than 9 bytes  "
                    .to_string()
            )
        );

        assert_eq!(
            tw_s.slices_to_files(&[1, 0, 1, 1, 1, 1, 1]),
            Err(
                "An error occurred, the file size == 0 which is impossible, it's likely the file \
                 has been corrupted"
                    .to_string()
            )
        );
    }
    #[test]
    fn test_file_splitt() {
        let mut etw_s = WSFileSplitter::new(Some(50)).unwrap();
        let rc_err = Rcc::new((0..51).collect());
        assert_eq!(
            etw_s.write_new_rc_file(rc_err),
            Err("rc_file length greater than max_len_of_recv".to_string())
        );

        let lens_file = [
            0, 10, 20, 999, 17_000, 3, 7, 8, 7_584, 20_000, 500, 100, 1500usize,
        ];
        let mut was_zero = false;
        let mut ctr_check = 0;
        let mut ctr_check_reming = 0;

        let mut all_vecs_slices = vec![];
        let mut all_vecs_slices_sourse_files = vec![];

        for curent_file_len in lens_file {
            let mut tw_s = WSFileSplitter::new(Some(*lens_file.iter().max().unwrap())).unwrap();

            let rc = Rcc::new((0..curent_file_len).map(|x| x as u8).collect::<Box<[u8]>>());
            all_vecs_slices_sourse_files.push(rc.clone());

            if curent_file_len == 0 {
                assert_eq!(
                    tw_s.write_new_rc_file(rc.clone()),
                    Err("rc_file must be greater than zero".to_string())
                );
                was_zero = true;
                continue;
            } else {
                assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));
            }

            assert_eq!(
                tw_s.write_new_rc_file(rc),
                Err("WSFileSplitter already has an unprocessed file ".to_string())
            );

            let mut temp_remianing = None;

            let mut ctr_of_get_len_sls_len = 0;
            for (break_me, sls_len) in [
                1, 2, 0, 33, 543, 3, 4, 88, 32, 9, 65, 999, 21, 3, 4, 9, 2, 7, 4, 1, 5, 1000, 1500,
            ]
            .iter()
            .cycle()
            .enumerate()
            {
                assert!(
                    break_me < 200,
                    "If this error appears, it means that `cycle()` is running indefinitely."
                );
                let mut tempo_ve = vec![(sls_len ^ 0xae) as u8; *sls_len];

                if !tw_s.i_have_some_send() {
                    assert_eq!(tw_s.len_of_send_file(), None);
                    assert_eq!(tw_s.remaining_len_of_send_file(), None);

                    break;
                }

                let is_remaing = Some(
                    1 + w1utils::len_u64_as_bytes(curent_file_len as u64)
                        + (curent_file_len - ctr_of_get_len_sls_len),
                );

                if temp_remianing.is_some() {
                    assert_eq!(is_remaing, temp_remianing);
                    ctr_check_reming += 1;
                }

                assert_eq!(tw_s.len_of_send_file(), Some(curent_file_len));
                assert_eq!(tw_s.remaining_len_of_send_file(), is_remaing);

                ctr_check += 1;

                temp_remianing = tw_s.file_to_slices(&mut tempo_ve);

                all_vecs_slices.append(&mut tempo_ve);

                /*
                                assert_eq!(
                    tw_s.clone().send_file.unwrap().0,
                    DataDrain {
                        ptr_in_head: 2,
                        ptr_in_body: 18,
                        len_of_head: 2,
                        head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
                    }
                );
                    */

                ctr_of_get_len_sls_len += sls_len;
            }
        }

        let mut tw_eend = WSFileSplitter::new(Some(*lens_file.iter().max().unwrap())).unwrap();

        let tets_lens_of_nums_files = tw_eend.slices_to_files(&all_vecs_slices);

        if tets_lens_of_nums_files.is_err() {
            assert_eq!(
                tets_lens_of_nums_files,
                Err(
                    "This line appears only if `tets_lens_of_nums_files.is_err()` 
            == TRUE, to indicate a specific issue there. DO NOT EDIT THIS LINE—IT IS A \
                     PLACEHOLDER!!"
                        .to_string()
                )
            );
        }

        let tets_lens_of_nums_files = tets_lens_of_nums_files.unwrap();

        //The first element is a file with a length of 0; this file is not added to the loop, so
        // the first element is skipped here!
        assert_eq!(tets_lens_of_nums_files.len(), lens_file.len() - 1);
        //
        //
        assert_eq!(
            lens_file.len(),
            all_vecs_slices_sourse_files.len(),
            "This line only checks the status of the test; if an error appears here, it means the \
             test has failed—this line is testing the test itself!"
        );
        for x in tets_lens_of_nums_files
            .iter()
            .zip(all_vecs_slices_sourse_files[1..].iter())
        {
            assert_eq!(x.0[..], x.1[..]);
        }

        assert!(was_zero);
        //
        assert!(ctr_check > 200);
        assert!(ctr_check_reming > 200); //I'm too lazy to calculate exactly what this number should be, 
        //but it should indicate that the `if`
        //condition branch has been executed enough times (assuming the dimensions of the
        // array remain unchanged in the two `for` loops).
    }

    #[test]
    fn test_file_splitt_old() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        let rc = Rcc::new((0..50).collect::<Box<[u8]>>());
        let rc_err = Rcc::new((0..51).collect());
        assert_eq!(
            tw_s.write_new_rc_file(rc_err),
            Err("rc_file length greater than max_len_of_recv".to_string())
        );

        assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

        assert_eq!(
            tw_s.write_new_rc_file(rc),
            Err("WSFileSplitter already has an unprocessed file ".to_string())
        );

        let mut reta1 = vec![1; 20];
        let mut reta2 = vec![1; 0];
        let mut reta3 = vec![1; 7];
        let mut reta4 = vec![1; 11];
        let mut reta5 = vec![1; 19];

        assert_eq!(tw_s.file_to_slices(&mut reta1).unwrap(), 50 + 1 + 1 - 20);
        assert_eq!(
            tw_s.clone().for_test_send_file().unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 18,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(tw_s.file_to_slices(&mut reta2).unwrap(), (50 + 1 + 1 - 20));
        assert_eq!(
            tw_s.clone().for_test_send_file().unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 18,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(
            tw_s.file_to_slices(&mut reta3).unwrap(),
            (50 + 1 + 1 - 20) - 7
        );
        assert_eq!(
            tw_s.clone().for_test_send_file().unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 25,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(
            tw_s.file_to_slices(&mut reta4).unwrap(),
            (50 + 1 + 1 - 20) - 7 - 11
        );
        assert_eq!(
            tw_s.clone().for_test_send_file().unwrap().0,
            DataDrain {
                ptr_in_head: 2,
                ptr_in_body: 36,
                len_of_head: 2,
                head: [1, 50, 0, 0, 0, 0, 0, 0, 0]
            }
        );

        assert_eq!(tw_s.file_to_slices(&mut reta5), None);
        assert!(tw_s.clone().for_test_send_file().is_none());

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
        println!("hfhfhf {:?}", tw_s.len_of_send_file());
    }

    #[test]
    fn test_spkit_to_file() {
        let mut tw_s = WSFileSplitter::new(Some(50)).unwrap();

        let rc = Rcc::new((0..50).collect::<Box<[u8]>>());

        let rc2 = Rcc::new((0..20).map(|x| 20 - x).collect::<Box<[u8]>>());

        assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

        let mut reta1 = vec![0; 95];
        //let mut reta5 = vec![0; 19];

        tw_s.file_to_slices(&mut reta1[10..]);

        assert_eq!(tw_s.write_new_rc_file(rc2.clone()), Ok(()));

        tw_s.file_to_slices(&mut reta1[71..]);

        tw_s.slices_to_files(&reta1).unwrap();
    }

    #[test]
    fn test_spkit_to_file_flow() {
        let mut tw_s = WSFileSplitter::new(Some(19500)).unwrap();

        let mut vecca: Vec<u8> = Vec::new();

        let fs_vec = [
            40, 10, 15, 7, 1, 12, 1148, 3876, 5, 4, 43, 99, 29, 134, 14447, 14, 95, 1523, 5043, 9,
            5, 6, 8214, 65, 3217, 45, 43, 99, 299, 134, 117, 90, 5765, 72, 4, 6, 3865, 1, 626, 3,
            1, 78, 54, 6, 94, 2, 1, 564, 7, 60, 1, 3, 1333, 29, 6, 729, 4, 23,
        ];

        let mut ctr_temp_len_have = 0;

        for file_size_in_iter in fs_vec {
            let rc = Rcc::new(
                (0..file_size_in_iter)
                    .map(|x| x as u8)
                    .collect::<Box<[u8]>>(),
            );

            assert_eq!(tw_s.write_new_rc_file(rc.clone()), Ok(()));

            let mut over_len = 0;
            let mut max_me = 0;
            for chunk_size in [
                4, 6, 7, 5, 6, 0, 3, 1, 45, 90, 5, 72, 4, 6, 35, 0, 62, 3, 1, 78, 5, 6, 94, 2, 1,
                64, 7, 60, 1, 3, 1000, 2, 6, 79, 4, 23,
            ]
            .iter()
            .cycle()
            {
                let trash_noise = *chunk_size as u8;
                let mut nw = vec![ /*trash bytes*/ trash_noise ; *chunk_size];

                assert_eq!(
                    tw_s.file_to_slices(&mut nw),
                    tw_s.remaining_len_of_send_file()
                );

                if let Some(xxx) = tw_s.len_of_recv_file() {
                    // println!("{:?} {:?} ", xxx, *chunk_size);
                    assert_eq!(xxx, file_size_in_iter as usize);

                    assert!(tw_s.i_have_some_recv());

                    ctr_temp_len_have += 1;
                } else {
                    assert!(!tw_s.i_have_some_recv());
                }

                vecca.extend_from_slice(&nw);

                let get_me = tw_s.slices_to_files(&nw).unwrap();

                over_len += *chunk_size;
                // println!("          real {} | {:?}  |  {:?}", nw.len(), nw, get_me);
                // println!("          real {} | {:?}  |  {:?}", nw.len(), nw, get_me);
                //checking that remaining_len_of_recv_file() returns the correct number of bytes
                // remaining in the file it does not take into account the length of
                // the head
                max_me = if max_me < tw_s.remaining_len_of_recv_file().unwrap_or(0) {
                    assert_eq!(
                        tw_s.remaining_len_of_recv_file().unwrap_or(0) + chunk_size,
                        file_size_in_iter as usize
                            + w1utils::len_u64_as_bytes(file_size_in_iter)
                            + 1
                    );

                    tw_s.remaining_len_of_recv_file().unwrap_or(0)
                } else {
                    max_me
                };

                for _xxx in get_me.clone() {
                    max_me = 0;
                }
                for ggg in get_me {
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
                        xo.into_boxed_slice(),
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

        assert!(ctr_temp_len_have > 0, "len_of_recv_file() always none!");

        assert_eq!(tw_s.slices_to_files(&vecca).unwrap().len(), fs_vec.len());
    }
}
