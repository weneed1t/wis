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
use crate::w1types::*;
use std::cell::RefCell;
//#############################################################3
#[derive(Debug, Clone, PartialEq)]
///Don't even look at these fields and methods, they are only needed for tests, you can have any of them
pub struct DumpNonser {
    #[cfg(test)]
    ///for test
    pub t: u64,
    /// only in test
    pub v: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq)]
///Don't even look at these fields and methods, they are only needed for tests, you can have any of them
pub struct DumpTricker<FuserLogicBuf: Clone> {
    user_logic_buffer_clone: RefCell<Option<FuserLogicBuf>>, // Обернули в Option, так как буфер может быть None
    ctr_test: RefCell<u64>,
    pack_type_test: RefCell<PackType>,
    what_i_set: RefCell<u8>,
}
///Don't even look at these fields and methods, they are only needed for tests, you can have any of them
#[derive(Debug, Clone, PartialEq)]
pub struct DumpCrcser {
    ///
    pub t: u64,
    /// only in test
    pub v: Vec<u8>,
    //
}
///Don't even look at these fields and methods, they are only needed for tests, you can have any of them
#[derive(Debug, Clone, PartialEq)]
pub struct DumpThrasher<FuserLogicBuf> {
    #[cfg(test)]
    _t: u64,
    /// only in test
    pub v: Vec<u8>,
    user_logic_buffer_clone: RefCell<FuserLogicBuf>,
    counter_pack: RefCell<u64>,
}
///Don't even look at these fields and methods, they are only needed for tests, you can have any of them
#[derive(Debug, Clone, PartialEq)]
pub struct DumpRandomer {
    #[cfg(test)]
    t: u64,
    /// only in test
    pub v: Vec<u8>,
}
///Don't even look at these fields and methods, they are only needed for tests, you can have any of them
#[derive(Debug, Clone, PartialEq)]
pub struct DumpEnc {
    #[cfg(test)]
    t: u64,
    /// only in test
    pub v: Vec<u8>,
}
//#############################################################3

impl Noncer for DumpNonser {
    fn new(_key: &[u8]) -> Result<Self, String> {
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
    fn set_nonce(&mut self, _nonce_gener: &mut [u8]) -> Result<(), String> {
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

impl<FuserLogicBuf: Default + Clone> TrickyBMaker<FuserLogicBuf> for DumpTricker<FuserLogicBuf> {
    fn new(_key: &[u8], _pack_sheme: PackScheme) -> Result<Self, String> {
        #[cfg(not(test))]
        panic!(
            "This panic is called from  TrickyBMaker<FuserLogicBuf>  because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option< TrickyBMaker<FuserLogicBuf> > = None;"
        );
        #[cfg(test)]
        {
            #![allow(clippy::as_conversions)]

            Ok(Self {
                ctr_test: RefCell::new(0),
                // Исправлено: добавлена закрывающая скобка для RefCell::new
                user_logic_buffer_clone: RefCell::new(Some(FuserLogicBuf::default())),
                pack_type_test: RefCell::new(PackType::Data),
                what_i_set: RefCell::new(0),
            })
        }
    }
    fn get_tricky_byte(
        &self,
        _pack_type: PackType,
        _ctr: &u64,
        _user_logic_buffer: Option<&mut FuserLogicBuf>,
    ) -> u8 {
        #[cfg(not(test))]
        panic!(
            "This panic is called from  TrickyBMaker<FuserLogicBuf>  because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option< TrickyBMaker<FuserLogicBuf> > = None;"
        );
        #[cfg(test)]
        {
            *self
                .ctr_test
                .try_borrow_mut()
                .expect("unreal state in test code self.ctr_test") = *_ctr;

            //*self.user_logic_buffer_clone.try_borrow_mut() = _user_logic_buffer.clone();
            *self
                .user_logic_buffer_clone
                .try_borrow_mut()
                .expect("unreal state in test code self.user_logic_buffer_clone") =
                _user_logic_buffer.map(|b| b.clone());

            *self
                .pack_type_test
                .try_borrow_mut()
                .expect("unreal state in test code self.pack_type_test") = _pack_type;
        }

        #[cfg(test)]
        *self
            .what_i_set
            .try_borrow()
            .expect("unreal state in test code  *self.what_i_set.")
    }
}
#[cfg(test)]
impl<FuserLogicBuf: Default + Clone> DumpTricker<FuserLogicBuf> {
    /// for test only
    pub fn get_state(&self) -> (PackType, u64, FuserLogicBuf) {
        #[cfg(not(test))]
        panic!(
            "This panic is called from  TrickyBMaker<FuserLogicBuf>  because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option< TrickyBMaker<FuserLogicBuf> > = None;"
        );
        #[cfg(test)]
        (
            *self
                .pack_type_test
                .try_borrow()
                .expect("unreal state in test code  self.pack_type_test"),
            *self
                .ctr_test
                .try_borrow()
                .expect("unreal state in test code  .ctr_test"),
            self.user_logic_buffer_clone
                .try_borrow()
                .expect("unreal state in test code  .ser_logic_buffer_clone")
                .clone()
                .unwrap_or_default(),
        )
    }
    #[cfg(test)]
    /// for test only
    pub fn set_byte(&self, _b: u8) {
        #[cfg(not(test))]
        panic!(
            "This panic is called from  TrickyBMaker<FuserLogicBuf>  because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option< TrickyBMaker<FuserLogicBuf> > = None;"
        );
        #[cfg(test)]
        {
            *self
                .what_i_set
                .try_borrow_mut()
                .expect("unreal state in test code self.what_i_set") = _b;
        }
    }
}

impl Crcser for DumpCrcser {
    fn new(_key: &[u8]) -> Result<Self, String> {
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
    fn gen_crc(&mut self, _payload: &[u8], _crc_field: &mut [u8]) -> Result<(), String> {
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

impl<FuserLogicBuf: Clone + Default> Thrasher<FuserLogicBuf> for DumpThrasher<FuserLogicBuf> {
    fn new(_key: &[u8]) -> Result<Self, String> {
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
                user_logic_buffer_clone: RefCell::new(FuserLogicBuf::default()),
                counter_pack: RefCell::new(0),
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
        _user_logic_buffer: Option<&mut FuserLogicBuf>,
    ) -> Result<(), String> {
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

            *self
                .counter_pack
                .try_borrow_mut()
                .expect("unreal state in test code self.counter_pack") = *_counter_pack;
            if let Some(x) = _user_logic_buffer {
                *self
                    .user_logic_buffer_clone
                    .try_borrow_mut()
                    .expect("unreal state in test code user_logic_buffer_clone") = x.clone();
            }
            Ok(())
        }
    }
}

impl<FuserLogicBuf: Default + Clone> DumpThrasher<FuserLogicBuf> {
    #[cfg(test)]
    /// for test only
    pub fn get_state(&self) -> (u64, FuserLogicBuf) {
        #[cfg(not(test))]
        panic!(
            "This panic is called from  TrickyBMaker<FuserLogicBuf>  because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option< TrickyBMaker<FuserLogicBuf> > = None;"
        );
        #[cfg(test)]
        (
            *self
                .counter_pack
                .try_borrow()
                .expect("unreal state in test code self.counter_pack"),
            self.user_logic_buffer_clone
                .try_borrow()
                .expect("unreal state in test code self.user_logic_buffer_clone")
                .clone(),
        )
    }
}

impl Randomer for DumpRandomer {
    fn new(_key: &[u8]) -> Result<Self, String> {
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
            let mut x = [0];
            bpg(&mut self.t, &mut x);
            self.t as u32
        }
    }

    fn gen_rand_usize(&mut self) -> usize {
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
            #![allow(clippy::as_conversions)]
            let mut x = [0];
            bpg(&mut self.t, &mut x);
            self.t as usize
        }
    }
}

impl EncWis for DumpEnc {
    fn new(_key: &[u8]) -> Result<Self, String> {
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
    ) -> Result<(), String> {
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
    ) -> Result<StatusDecrypt, String> {
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

#[derive(Debug, Clone, PartialEq)]
///dump
pub struct DumpEndCrypt {
    ///dump
    pub _data: Box<[u8]>,
}

impl EndCryptStuctor for DumpEndCrypt {
    fn get_symmetric_key_byte_vec(&self) -> Box<[u8]> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpEndCrypt because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        self._data.clone()
    }
    fn new() -> Self {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpEndCrypt because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }
        #[cfg(test)]
        Self {
            _data: vec![].into_boxed_slice(),
        }
    }
    #[allow(unused_variables)]
    fn set_symmetric_key_byte_vec(&mut self, data: &[u8]) -> Result<(), String> {
        #[cfg(not(test))]
        {
            panic!(
                "This panic is called from DumpEndCrypt because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpHandMaker> = None;"
            );
        }

        #[cfg(test)]
        {
            self._data = Box::from(data);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
///
pub struct DumpHandMaker<T>
where
    T: crate::w1types::EndCryptStuctor + std::clone::Clone,
{
    _in_state: Box<[AtomHandFile<T>]>,
    _ptr_in_state: usize,
    _role: MyRole,
    _private_key: u64,
    ///for test
    pub _private_seed: Box<[u8]>,
}

/*  */

impl<T> HandMaker<T> for DumpHandMaker<T>
where
    T: crate::w1types::EndCryptStuctor + std::clone::Clone + std::fmt::Debug,
{
    fn new(_my_role: MyRole, _seed: &[u8]) -> Result<Self, String> {
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
                    AtomHandFile::EndOfHandMake(T::new()), // терминальный маркер
                ]
                .to_vec()
                .into_boxed_slice(),
                _ptr_in_state: 0,
                _role: _my_role,
                _private_key: staka,
                _private_seed: _seed.into(),
            })
        }
    }

    fn send(&mut self) -> Result<Rcc<Box<[u8]>>, String> {
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

                return match curent_step {
                    AtomHandFile::InitiatorFileSize(x) | AtomHandFile::PassiveFileSize(x) => {
                        match x {
                            2 => Ok(Rcc::new([t1, t2].to_vec().into_boxed_slice())),
                            3 => {
                                self._private_key = self._private_key.wrapping_add(t3 as u64);

                                let ret_box = [t1, t2, t3].to_vec().into_boxed_slice();

                                Ok(Rcc::new(ret_box))
                            },
                            _ => {
                                panic!("its unreal state")
                            },
                        }
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
        or for the passive to send files to the initiator!"
                    .to_string(),
            )
        }
    }

    fn recv(&mut self, _file: Rcc<Box<[u8]>>) -> Result<(), String> {
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
        or for the passive to send files to the initiator!"
                    .to_string(),
            )
        }
    }

    fn next(&mut self) -> Option<AtomHandFile<T>> {
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
            let temp = self._in_state.get(self._ptr_in_state).cloned();

            if let Some(x) = &temp {
                if x.is_end() {
                    let mut terminal = T::new();

                    terminal
                        .set_symmetric_key_byte_vec(&self._private_key.to_be_bytes())
                        .expect(
                            "err .set_symmetric_key_byte_vec(&self._private_key.to_be_bytes())",
                        );

                    self._ptr_in_state = self
                        ._ptr_in_state
                        .checked_add(1)
                        .expect("err self._ptr_in_state =self._ptr_in_state.checked_add(1).expect");
                    Some(AtomHandFile::EndOfHandMake(terminal))
                } else {
                    temp
                }
            } else {
                temp
            }
        }
    }
}
