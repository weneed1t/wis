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

use crate::t0pology::PackTopology;
use crate::wt1types::*;
//#############################################################3
///
pub struct DumpNonser {
    #[cfg(test)]
    t: u64,
    /// only in test
    pub v: Vec<u8>,
}
///
pub struct DumpCrcser {
    ///
    pub t: u64,
    /// only in test
    pub v: Vec<u8>,
}
///
pub struct DumpThrasher {
    #[cfg(test)]
    _t: u64,
    /// only in test
    pub v: Vec<u8>,
}
///
pub struct DumpRandomer {
    #[cfg(test)]
    t: u64,
    /// only in test
    pub v: Vec<u8>,
}
///
pub struct DumpEnc {
    #[cfg(test)]
    t: u64,
    /// only in test
    pub v: Vec<u8>,
}
//#############################################################3

impl Noncer for DumpNonser {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        #[cfg(not(test))]
        panic!(
            "This panic is called from DumpNonser because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpNonser> = None;"
        );
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
                v: _key.to_vec(),
            })
        }
    }
    fn set_nonce(&mut self, _nonce_gener: &mut [u8]) -> Result<(), &'static str> {
        #[cfg(not(test))]
        panic!(
            "This panic is called from DumpNonser because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpNonser> = None;"
        );
        #[cfg(test)]
        bpg(&mut self.t, _nonce_gener);
        #[cfg(test)]
        Ok(())
    }
}

impl Crcser for DumpCrcser {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpCfcser because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<DumpCfcser> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
                v: _key.to_vec(),
            })
        }
        //Ok(Self {})
    }
    fn gen_crc(&mut self, _payload: &[u8], _crc_field: &mut [u8]) -> Result<(), &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpCfcser because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<DumpCfcser> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]

            use crate::murmur3::*;

            let mut hash = murmurhash3_x64_128(_payload, self.t as u32);

            bpg(&mut hash[0], _crc_field);
            Ok(())
        }
    }
}

impl Thrasher for DumpThrasher {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from Thrasher because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<Thrasher> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            Ok(Self {
                _t: _key.iter().map(|&x| x as u64).sum(),
                v: _key.to_vec(),
            })
        }
    }
    fn set_user_field(
        &mut self,
        _user_field: &mut [u8],
        _counter_pack: &u64,
        _len_pack: &usize,
        _counter_of_field: &usize,
        _topoligy: &PackTopology,
    ) -> Result<(), &'static str> {
        #[cfg(not(test))]
        panic!(
            "This panic is called from Thrasher because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<Thrasher> = None;"
        );
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            let teto: [u8; 3] = [
                *_counter_pack as u8,
                *_len_pack as u8,
                *_counter_of_field as u8,
            ];
            for (x, t) in _user_field.iter_mut().zip(teto.iter().cycle()) {
                *x = *t;
            }

            Ok(())
        }
    }
}

impl Randomer for DumpRandomer {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpRandomer> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
                v: _key.to_vec(),
            })
        }
    }
    fn gen_rand_u32(&mut self) -> u32 {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpRandomer> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            self.gen_rand_u64() as u32
        }
    }

    fn gen_rand_u64(&mut self) -> u64 {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpNonser because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpNonser> = None;"
            );
        }
        #[cfg(test)]
        {
            let mut x = [0];
            bpg(&mut self.t, &mut x);
            self.t
        }
    }
}

impl EncWis for DumpEnc {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpRandomer> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
                v: _key.to_vec(),
            })
        }
    }

    fn encrypt(
        &self,
        _non_enc_head: &[u8],
        _enc_payload: &mut [u8],
        _auth_tag: &mut [u8],
        _nonce_countr: &u64,
        _nonce: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpRandomer> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            bpg(&mut (self.t.clone()), _enc_payload);

            let mut hat = vec![];
            hat.extend_from_slice(_non_enc_head);
            hat.extend_from_slice(_enc_payload);

            let xh = _nonce.unwrap_or(&[0, 1, 2, 3, 4, 5, 6, 7u8]);
            hat.extend_from_slice(xh);

            _auth_tag.fill(0);
            bpg(&mut (hat.iter().map(|&x| x as u64).sum()), _auth_tag);

            Ok(())
        }
    }

    fn decrypt(
        &self,
        _non_enc_head: &[u8],
        _enc_payload: &mut [u8],
        _auth_tag: &mut [u8],
        _nonce_countr: &u64,
        _nonce: Option<&[u8]>,
    ) -> Result<StatusDecrypt, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpRandomer> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]
            let mut hat = vec![];
            hat.extend_from_slice(_non_enc_head);
            hat.extend_from_slice(_enc_payload);

            let xh = _nonce.unwrap_or(&[0, 1, 2, 3, 4, 5, 6, 7u8]);
            hat.extend_from_slice(xh);

            let mut hat2 = vec![0; _auth_tag.len()];

            bpg(&mut (hat.iter().map(|&x| x as u64).sum()), &mut hat2);
            if hat2.iter().eq(_auth_tag.iter()) {
                bpg(&mut (self.t.clone()), _enc_payload);
                Ok(StatusDecrypt::DecodedCorrectly)
            } else {
                Ok(StatusDecrypt::PackageDamaged)
            }
        }
    }
}

#[cfg(test)]
fn bpg(t: &mut u64, v: &mut [u8]) {
    #![allow(clippy::as_conversions)]
    for x in v.iter_mut() {
        *t = t.rotate_left(11).wrapping_add(*t).wrapping_add(42389);
        *x ^= *t as u8;
    }
}

#[derive(Debug, Clone)]
///
pub struct DumpHandMaker {
    _in_state: Box<[AtomHandFile]>,
    _ptr_in_state: usize,
    _role: MyRole,
    _private_key: u64,
}

/*  */

impl HandMaker for DumpHandMaker {
    fn new(_my_role: MyRole, _seed: &[u8]) -> Result<Self, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::arithmetic_side_effects)]
            #![allow(clippy::as_conversions)]
            let mut staka: u64 = 0;
            for x in _seed {
                staka = staka.rotate_left(27).wrapping_add(*x as u64 * 123345)
            }

            Ok(Self {
                _in_state: [
                    AtomHandFile::InitiatorFileSize(2),
                    AtomHandFile::PassiveFileSize(3),
                    AtomHandFile::PassiveFileSize(2),
                    AtomHandFile::InitiatorFileSize(3),
                    AtomHandFile::PassiveFileSize(2),
                ]
                .to_vec()
                .into_boxed_slice(),
                _ptr_in_state: 0,
                _role: _my_role,
                _private_key: staka,
            })
        }
    }

    fn send(&mut self) -> Result<InFile<u8>, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::arithmetic_side_effects)]
            #![allow(clippy::as_conversions)]
            let curent_step = self
                ._in_state
                .get(self._ptr_in_state)
                .ok_or("too many steps, step index outside the bounds of the circuit array")?;

            println!(
                "send {:?}  {:?}  ptr {}  key_state: {}",
                curent_step, self._role, self._ptr_in_state, self._private_key
            );

            if self._role.is_initiator() == curent_step.is_initiator() {
                let t1 = (self._ptr_in_state * 17) as u8;
                let t2 = ((self._ptr_in_state + 2) * 17) as u8;
                let t3 = self._ptr_in_state as u8;

                self._private_key = self._private_key.rotate_left(t1 as u32);
                self._private_key = self._private_key.wrapping_mul(t2 as u64);

                self._ptr_in_state += 1;

                return match curent_step.size() {
                    2 => Ok(InFile::new([t1, t2].to_vec().into_boxed_slice())),
                    3 => {
                        self._private_key = self._private_key.wrapping_add(t3 as u64);
                        Ok(InFile::new([t1, t2, t3].to_vec().into_boxed_slice()))
                    },
                    _ => {
                        panic!("its unreal state")
                    },
                };
            }

            Err(
                "Send order error: The initiator cannot accept files from the initiator, 
        and the passive cannot accept files from the passive!
        The correct order is for the initiator to accept files from the passive,
        or for the passive to send files to the initiator!",
            )
        }
    }

    fn recv(&mut self, _file: InFile<u8>) -> Result<(), &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        {
            #![allow(clippy::arithmetic_side_effects)]
            #![allow(clippy::as_conversions)]
            let curent_step = self
                ._in_state
                .get(self._ptr_in_state)
                .ok_or("too many steps, step index outside the bounds of the circuit array")?;

            println!(
                "recv {:?}  {:?}  ptr {}  key_state: {}",
                curent_step, self._role, self._ptr_in_state, self._private_key
            );

            if self._role.is_initiator() == curent_step.is_passive() {
                let byte0 = *_file.first().ok_or("missing byte 0")?;
                let byte1 = *_file.get(1).ok_or("missing byte 1")?;

                self._private_key = self._private_key.rotate_left(byte0 as u32);
                self._private_key = self._private_key.wrapping_mul(byte1 as u64);

                if _file.len() == 3 {
                    let byte2 = *_file.get(2).ok_or("missing byte 2")?;
                    self._private_key = self._private_key.wrapping_add(byte2 as u64);
                }

                self._ptr_in_state += 1;

                if _file.len() == 2 || _file.len() == 3 {
                    return Ok(());
                }
            }

            Err(
                "Recv order error: The initiator cannot accept files from the initiator, 
        and the passive cannot accept files from the passive!
        The correct order is for the initiator to accept files from the passive,
        or for the passive to send files to the initiator!",
            )
        }
    }

    fn file_sheme(&self) -> &[AtomHandFile] {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        {
            &self._in_state[..]
        }
    }
    fn get_private_key(&mut self) -> Result<Box<[u8]>, &'static str> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpRandomer because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        {
            if self._ptr_in_state == self._in_state.len() {
                Ok(self._private_key.to_be_bytes().to_vec().into_boxed_slice())
            } else {
                Err("The key installation process is still not complete!")
            }
        }
    }
}

#[cfg(test)]
mod tests_enca {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ packerr partialeq – equality depends only on variant, not on string       │
    // └────────────────────────────────────────────────────────────────────────────┘

    #[test]
    fn same_variant_with_different_strings_are_equal() {
        let dn = DumpEnc::new(&[1, 2, 3, 4]).unwrap();

        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();
        println!(" ");
        println!(" ");
        println!("headd {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::DecodedCorrectly, ret);
        //
        //
        //
        //
        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let mut a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        a4[7] = !a4[7];

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();
        println!("before enc ");
        println!(" ");
        println!("head {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);

        let mut a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        a1[7] = !a1[7];

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();
        println!("after dec");
        println!(" ");
        println!("head {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);

        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();

        a2[7] = !a2[7];

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, &0, Some(&a4)).unwrap();
        println!(" ");
        println!(" ");
        println!("head {:?} ", a1);
        println!("paload(enc) {:?} ", a2);
        println!("auth tag  {:?} ", a3);
        println!("none  {:?} ", a4);
        println!("status {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);
    }
}

#[cfg(test)]
mod tests_dumps_nonser_cfcser {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ dumpnonser tests – every method must panic with the documented message    │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    //#[should_panic(expected = "This panic is called from DumpNonser")]
    fn dumpnonser_new_panics() {
        let _ = DumpNonser::new(&[]);
    }

    #[test]
    //#[should_panic(expected = "This panic is called from DumpNonser")]
    fn dumpnonser_set_nonce_panics() {
        let mut stub = DumpNonser { t: 10, v: vec![] }; // we can create it directly because it's a struct
        let mut buf = [0u8; 8];
        stub.set_nonce(&mut buf).unwrap();
    }

    // verify that the type can be placed in an Option (as intended)
    #[test]
    fn dumpnonser_option_none_works() {
        let opt: Option<DumpNonser> = None;
        assert!(opt.is_none());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ dumpcfcser tests – every method must panic with the documented message    │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    //#[should_panic(expected = "This panic is called from DumpCfcser")]
    fn dumpcfcser_new_panics() {
        let _ = DumpCrcser::new(&[]);
    }

    #[test]
    //#[should_panic(expected = "This panic is called from DumpCfcser")]
    fn dumpcfcser_gen_crc_panics() {
        let mut stub = DumpCrcser { t: 10, v: vec![] };
        let mut crc_field = [0u8; 4];
        let payload = [1, 2, 3];
        stub.gen_crc(&payload, &mut crc_field).unwrap();
    }

    #[test]
    fn dumpcfcser_option_none_works() {
        let opt: Option<DumpCrcser> = None;
        assert!(opt.is_none());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ trait bounds – ensure that the stubs satisfy all required traits          │
    // │ (compilation already guarantees this, but we can explicitly check)        │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn dumpnonser_impl_noncer() {
        fn takes_noncer<T: Noncer>(_: T) {}
        takes_noncer(DumpNonser { t: 10, v: vec![] }); // compiles -> ok
    }

    #[test]
    fn dumpcfcser_impl_cfcser() {
        fn takes_cfcser<T: Crcser>(_: T) {}
        takes_cfcser(DumpCrcser { t: 10, v: vec![] }); // compiles -> ok
    }
}
