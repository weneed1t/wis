#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

//use crate::wutils::{
//    bytes_to_u16, bytes_to_u32, bytes_to_u64, extract_bits, insert_bits, u16_to_bytes,
//    u32_to_bytes, u64_to_bytes,
//};

use crate::wutils::add_u64_i64;

use crate::package;

const TIME_LEN_IN_BYTES: usize = 4;
const HEAD_DATA_LEN_IN_BYTES: usize = 3;
#[derive(Debug)]
pub enum WPascageMode {
    NotACK,
    WaitPackages,
    FastACKQeuqe,
    KillConnect,
}

impl WPascageMode {
    pub fn to_2bits(inp: &WPascageMode) -> u8 {
        return match inp {
            WPascageMode::NotEPV => 0,
            WPascageMode::WaitPackages => 1,
            WPascageMode::FastEPVQeuqe => 2,
            WPascageMode::KillConnect => 3,
        };
    }

    pub fn bits2_to_me(inp: u8) -> Result<Self, &'static str> {
        return match inp {
            0 => Ok(WPascageMode::NotEPV),
            1 => Ok(WPascageMode::WaitPackages),
            2 => Ok(WPascageMode::FastEPVQeuqe),
            3 => Ok(WPascageMode::KillConnect),
            _ => Err("inp:u8 is not in range 0-3"),
        };
    }
}

impl PartialEq for WPascageMode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (WPascageMode::NotEPV, WPascageMode::NotEPV) => true,
            (WPascageMode::WaitPackages, WPascageMode::WaitPackages) => true,
            (WPascageMode::FastEPVQeuqe, WPascageMode::FastEPVQeuqe) => true,
            (WPascageMode::KillConnect, WPascageMode::KillConnect) => true,
            _ => false,
        }
    }
}

/*type1 fn(&[u8], &mut [u8], &mut [u8], u32) -> Result<(), &'static str>
where &[u8] is the head, the data that is not encrypted,
the first &mut [u8] is the body, the data that is encrypted
the second &mut [u8] is the place where the authentication tag from head + body should be placed

type 2 fn(&mut[u8],usize,usize, u32) -> Result<(), &'static str>
&mut[u8] is the full mutable packet
the first usize is the index of the start of the body, so [0..(first usize)] is the head
the second usize is the index of the start of tag, so [(first usize)..(second usize)] is the body
the tag field, it is [(second usize)..] is the place for the tag

this enum is needed for maximum compatibility with the encryption libraries that are on the rust
they both return -> Result<(), &'static str>
ok() means that the data was encrypted successfully
and there were no errors, &'static str reports some error,
 when it is called, the preparation of the packet for sending
 will be interrupted and it will not be sent
*/

#[derive(Debug, Clone)]
pub enum EncTypeGetMode {
    Type1SplitMutSlices(fn(&[u8], &mut [u8], &mut [u8], u32) -> Result<(), &'static str>),
    Type2FullArrAndIndexes(fn(&mut [u8], usize, usize, u32) -> Result<(), &'static str>),
}

#[derive(Debug, Clone)]
pub enum DecrptTypeGetMode {
    Type1SplitMutSlices(fn(&[u8], &mut [u8], &[u8], u32) -> Result<(), &'static str>),
    Type2FullArrAndIndexes(fn(&mut [u8], usize, usize, u32) -> Result<(), &'static str>),
}

#[derive(Debug, Clone)]
pub struct DataOwned {
    is_fback: bool,
    is_epv: bool,
    __data: Box<[u8]>,
    real_head_startpos: usize,
    id_startpos: usize,
    content_startpos: usize,
    tag_startpos: usize,
}
impl DataOwned {
    #[inline(always)]
    pub fn new(
        fake_head_len: usize,
        is_fback: bool,
        data: Box<[u8]>,
        is_epv: bool,
        real_head_len: usize,
        id_len: usize,
        content_len: usize,
    ) -> Result<Self, &'static str> {
        //if the packet has is_fback true, its structure will be 1 byte of head data,
        //id field from 0 to 8 bytes. sometimes id may not be this is normal,
        //time fields of length TIME_LEN_IN_BYTES, data field of variable length,
        //since in this case the data is a sequence of u16 counters that occupy 2 bytes,
        //the data field must be a multiple of two,
        //the final tag field of variable length but not zero

        //if s_fback false
        //the structure will have 1 byte of head,
        //1 packet counter of 2 bytes, id field from 0 to 8 bytes,
        //and an arbitrary tag field

        //if the packet has is_fback true then its data field must
        //exactly contain TIME_LEN_IN_BYTES time field and
        //at least 1 counter 2 bytes long
        //if the packet has is_fback false then the data field
        // must be greater than zero, in this case parity is not important

        if content_len == 0 {
            return Err("content_len must be greater than zero");
        }

        if is_fback {
            if content_len <= TIME_LEN_IN_BYTES + 2 {
                return  Err("content_len <= TIME_LEN_IN_BYTES  +2  time(TIME_LEN_IN_BYTES) + 1 coumter miniumum(2)" );
            }
            if content_len & 1 == 1 {
                return Err("content length must be even in feedback mode");
            }
        }

        let id_startpos = fake_head_len + real_head_len;
        let content_startpos: usize = id_startpos + id_len;
        let tag_startpos: usize = content_len + content_startpos;

        if tag_startpos >= data.len() {
            return Err("tag start position exceeds data length");
        }
        Ok(Self {
            is_fback,
            is_epv,
            __data: data,
            id_startpos,
            real_head_startpos: fake_head_len,
            content_startpos,
            tag_startpos,
        })
    }

    pub fn id_mut(&mut self) -> &mut [u8] {
        &mut self.__data[self.id_startpos..self.content_startpos]
    }

    pub fn content_mut(&mut self) -> &mut [u8] {
        &mut self.__data[self.content_startpos..self.tag_startpos]
    }

    pub fn tag_mut(&mut self) -> &mut [u8] {
        &mut self.__data[self.tag_startpos..]
    }

    pub fn id(&self) -> &[u8] {
        &self.__data[self.id_startpos..self.content_startpos]
    }

    pub fn content(&self) -> &[u8] {
        &self.__data[self.content_startpos..self.tag_startpos]
    }

    pub fn tag(&self) -> &[u8] {
        &self.__data[self.tag_startpos..]
    }

    pub fn id_len(&self) -> usize {
        self.content_startpos - self.id_startpos
    }

    pub fn content_len(&self) -> usize {
        self.tag_startpos - self.content_startpos
    }

    pub fn tag_len(&self) -> usize {
        self.__data.len() - self.tag_startpos
    }

    pub fn real_head_len(&self) -> usize {
        self.id_startpos - self.real_head_startpos
    }

    pub fn fake_head_len(&self) -> usize {
        self.real_head_startpos
    }

    pub fn countr_get(&self) -> Result<u16, &'static str> {
        if self.is_fback {
            return Err("counters are not supported in feedback mode");
        }

        if self.__data.len() < HEAD_DATA_LEN_IN_BYTES {
            return Err("self.__data.len() < HEAD_DATA_LEN_IN_BYTES");
        }

        bytes_to_u16(
            &self.__data
                [self.real_head_startpos + 1..self.real_head_startpos + HEAD_DATA_LEN_IN_BYTES],
        )
    }

    pub fn countr_set(&mut self, countr: u16) -> Result<(), &'static str> {
        if self.is_fback {
            return Err("is fback havent set_countr");
        }
        if self.__data.len() < HEAD_DATA_LEN_IN_BYTES {
            return Err("is datata or self.__data.len()<HEAD_DATA_LEN_IN_BYTES");
        }
        u16_to_bytes(
            countr,
            &mut self.__data
                [self.real_head_startpos + 1..self.real_head_startpos + HEAD_DATA_LEN_IN_BYTES],
        )?;
        Ok(())
    }

    pub fn get_time(&self) -> Result<u32, &'static str> {
        if !self.is_fback {
            return Err("is content, content havent is_fback");
        }
        if self.content_startpos + TIME_LEN_IN_BYTES > self.__data.len() {
            return Err("self.content_startpos + TIME_LEN_IN_BYTES > self.__data.len()");
        }
        bytes_to_u32(&self.__data[self.content_startpos..self.content_startpos + TIME_LEN_IN_BYTES])
    }

    pub fn set_time(&mut self, time_sleep: u32) -> Result<(), &'static str> {
        if self.__data.len() < HEAD_DATA_LEN_IN_BYTES {
            return Err("is f datata or self.__data.len()<HEAD_DATA_LEN_IN_BYTES");
        }
        u32_to_bytes(
            time_sleep,
            &mut self.__data[self.content_startpos..self.content_startpos + TIME_LEN_IN_BYTES],
        )?;
        Ok(())
    }

    pub fn is_epv(&self) -> bool {
        if self.is_fback {
            return false;
        }
        self.is_epv
    }

    pub fn is_fback(&self) -> bool {
        self.is_fback
    }

    pub fn data(&self) -> &[u8] {
        &self.__data
    }

    pub fn data_box(&self) -> &Box<[u8]> {
        &self.__data
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.__data
    }

    pub fn data_box_mut(&mut self) -> &mut Box<[u8]> {
        &mut self.__data
    }

    pub fn fake_head_mut(&mut self) -> &mut [u8] {
        &mut self.__data[..self.real_head_startpos]
    }

    pub fn fake_head(&self) -> &[u8] {
        &self.__data[..self.real_head_startpos]
    }

    pub fn counters_fback_len(&self) -> Result<usize, &'static str> {
        if !self.is_fback {
            return Err("is not fback");
        }
        if self.tag_startpos <= self.content_startpos + TIME_LEN_IN_BYTES {
            return Ok(0);
        }
        Ok((self.tag_startpos - (self.content_startpos + TIME_LEN_IN_BYTES)) >> 1)
    }

    pub fn counter_fback_get(&self, index: usize) -> Result<u16, &'static str> {
        if index >= self.counters_fback_len()? {
            return Err("index is outside the array");
        }

        let pos: usize = self.content_startpos + TIME_LEN_IN_BYTES + (index << 1);

        if pos + 2 > self.__data.len() {
            return Err("Index out of bounds");
        }

        bytes_to_u16(&self.__data[pos..pos + 2])
    }

    pub fn tag_start_pos(&self) -> usize {
        return self.tag_startpos;
    }

    pub fn content_start_pos(&self) -> usize {
        return self.content_startpos;
    }

    pub fn head_byte_get(&self) -> u8 {
        return self.__data[self.real_head_startpos];
    }

    pub fn head_byte_set(&mut self, inp: u8) {
        self.__data[self.real_head_startpos] = inp;
    }
}

#[derive(Debug, Clone)]
pub struct PaskageParser {
    mtu: usize,
    fake_head_len: usize,
    id_len: usize,
    tag_len: usize,
    enc_and_tag: EncTypeGetMode,
    decypt_func: DecrptTypeGetMode,
    countr16_to32: fn(u16,u32) -> Result<u32, &'static str>,
}

impl PaskageParser {
    pub fn new(
        mtu: usize,
        fake_head_len: usize,
        id_len: usize,
        tag_len: usize,
        enc_and_tag: EncTypeGetMode,
        decypt_func: DecrptTypeGetMode,
        countr16_to32: fn(u16,u32) -> Result<u32, &'static str>,
    ) -> Self {
        PaskageParser {
            mtu,
            fake_head_len,
            id_len,
            tag_len,
            enc_and_tag,
            decypt_func,
            countr16_to32,
        }
    }
}

impl PaskageParser {
    pub fn content_to_data_p(
        &self,
        fake_head: Option<&[u8]>,
        content: &[u8],
        is_epv: bool,
        key_id: u64,
        countr: u32,
        pac_mode: WPascageMode,
    ) -> Result<DataOwned, &'static str> {
        let fake_head_len = fake_head.map(|slice| slice.len()).unwrap_or(0);
        let total_len: usize =
            fake_head_len + HEAD_DATA_LEN_IN_BYTES + content.len() + self.id_len + self.tag_len;

        if total_len > self.mtu {
            return Err("failed data.len()>mtu");
        }
        if self.tag_len == 0 {
            return Err("failed tag_len == 0");
        }
        if self.id_len > 8 {
            return Err("Id is incoreect id is big  > 8");
        }

        let content_len: usize = content.len();
        let data_arr: Box<[u8]> = vec![0_u8; total_len].into_boxed_slice();

        let mut reta: DataOwned = DataOwned::new(
            fake_head_len,
            false,
            data_arr,
            is_epv,
            HEAD_DATA_LEN_IN_BYTES,
            self.id_len,
            content_len,
        )?;

        reta.head_byte_set(
            ((is_epv as u8) << 6) | ((false as u8) << 7) | (WPascageMode::to_2bits(&pac_mode) << 4),
        );

        reta.countr_set((countr & 0x0000FFFF) as u16)?;

        reta.content_mut().copy_from_slice(&content);

        if fake_head.is_some() {
            if fake_head.unwrap().len() != self.fake_head_len {
                return Err("fake_head.unwrap().len() != self.fake_head_len");
            }
            reta.fake_head_mut().copy_from_slice(&fake_head.unwrap());
        }

        if self.id_len > 0 {
            let mut temp: [u8; 8] = [0_u8; 8];
            if u64_to_bytes(key_id, &mut temp).is_err() {
                return Err("u64 to 8 bytes convert error");
            }

            reta.id_mut()
                .copy_from_slice(&temp[temp.len() - self.id_len..]);
        }
        //println!("reta: {:x?}", reta);
        //  ENCRYPT AND MAC GENERATE!
        let pos_mac: usize = reta.tag_start_pos();
        let pos_content: usize = reta.content_start_pos();
        match self.enc_and_tag {
            EncTypeGetMode::Type1SplitMutSlices(fnce) => {
                let (free_data, mac_only) = reta.data_mut().split_at_mut(pos_mac);
                let (head, to_enc_only) = free_data.split_at_mut(pos_content);
                fnce(&head, to_enc_only, mac_only, countr)?;
            }
            EncTypeGetMode::Type2FullArrAndIndexes(fnce) => {
                fnce(&mut reta.data_mut(), pos_content, pos_mac, countr)?;
            }
        };

        match self.decypt_func {
            DecrptTypeGetMode::Type1SplitMutSlices(fnce) => {
                let (free_data, mac_only) = reta.data_mut().split_at_mut(pos_mac);
                let mut hollow_arr = [0_u8; 0];

                fnce(&free_data, &mut hollow_arr, mac_only, 0)?;
            }
            DecrptTypeGetMode::Type2FullArrAndIndexes(fnce) => {
                fnce(&mut reta.data_mut(), pos_mac, pos_mac, 0)?;
            }
        };


        return Ok(reta);
    }

    pub fn data_to_content_p(
        &self,
        last_confirmed_counter:u32,
        data: Box<[u8]>,
    ) -> Result<(DataOwned, Option<WPascageMode>), &'static str> {
        let data_len: usize = data.len();
        if data_len > self.mtu {
            return Err("failed data.len()>mtu");
        }
        if self.tag_len == 0 {
            return Err("failed tag_len == 0");
        }
        if self.id_len > 8 {
            return Err("Id is incoreect id is big  > 8");
        }

        let head_byte = data[self.fake_head_len];

        let is_fback: bool = (head_byte & 0b10000000) == 0b10000000_u8;
        let is_epv: bool = (head_byte & 0b01000000) == 0b01000000_u8;

        let real_head_len = if is_fback { 1 } else { HEAD_DATA_LEN_IN_BYTES };

        let _: Option<u16> = if is_fback {
            None
        } else {
            match bytes_to_u16(
                &data[self.fake_head_len + 1..self.fake_head_len + HEAD_DATA_LEN_IN_BYTES],
            ) {
                Err(_) => return Err("failed to extract countr"),
                Ok(x) => Some(x),
            }
        };
        return if is_fback {
            let ower_head = self.fake_head_len + 1 + self.id_len + self.tag_len;

            if ower_head >= data_len {
                return Err("Fdata is small ower_head>=data.len()");
            }

            let mut reta = DataOwned::new(
                self.fake_head_len,
                is_fback,
                data,
                is_epv,
                if is_fback { 1 } else { HEAD_DATA_LEN_IN_BYTES },
                self.id_len,
                data_len - ower_head,
            )?;

            //MAC CHEK!@@@@@@@@@@@@@@@@
            //since the fbak packet is not encrypted but only authenticated
            //in both implementations the size of "data" is zero
            let pos_mac: usize = reta.tag_start_pos();
            let pos_content: usize = reta.content_start_pos();
            match self.decypt_func {
                DecrptTypeGetMode::Type1SplitMutSlices(fnce) => {
                    let (free_data, mac_only) = reta.data_mut().split_at_mut(pos_mac);
                    let mut hollow_arr = [0_u8; 0];

                    fnce(&free_data, &mut hollow_arr, mac_only, 0)?;
                }
                DecrptTypeGetMode::Type2FullArrAndIndexes(fnce) => {
                    fnce(&mut reta.data_mut(), pos_mac, pos_mac, 0)?;
                }
            };

            Ok((reta, None))
        } else {
            let mut reta: DataOwned = DataOwned::new(
                self.fake_head_len,
                is_fback,
                data,
                is_epv,
                real_head_len,
                self.id_len,
                data_len - (self.id_len + real_head_len + self.tag_len + self.fake_head_len),
            )?;

            //  DECRYPT AND MAC CHECK!
            let pos_mac: usize = reta.tag_start_pos();
            let pos_content: usize = reta.content_start_pos();
            let countr_norml = (self.countr16_to32)(reta.countr_get()?,last_confirmed_counter)?;
            match self.decypt_func {
                DecrptTypeGetMode::Type1SplitMutSlices(fnce) => {
                    let (free_data, mac_only) = reta.data_mut().split_at_mut(pos_mac);
                    let (head, to_enc_only) = free_data.split_at_mut(pos_content);

                    fnce(&head, to_enc_only, mac_only, countr_norml)?;
                }
                DecrptTypeGetMode::Type2FullArrAndIndexes(fnce) => {
                    fnce(&mut reta.data_mut(), pos_content, pos_mac, countr_norml)?;
                }
            };

            if is_fback && reta.content_len() % 2 == 1 {
                return Err(" result.content_len()%2 ==1");
            }
            Ok((
                reta,
                Some(WPascageMode::bits2_to_me((head_byte >> 4) & 0b11)?),
            ))
        };
    }

    pub fn fback_from_content(
        &self,
        fake_head: Option<&[u8]>,
        time_sleep: u32,
        counters: &[u16],
        id: u64,
    ) -> Result<DataOwned, &'static str> {
        let fake_head_len = fake_head.map(|slice| slice.len()).unwrap_or(0);

        let id_pos_start: usize = fake_head_len + 1;
        let id_pos_end: usize = id_pos_start + self.id_len;
        let time_pos_end: usize = id_pos_end + TIME_LEN_IN_BYTES;

        let counters_len: usize = counters.len() << 1;
        let counters_pos_end: usize = time_pos_end + counters_len;

        let total_len: usize = time_pos_end + counters_len + self.tag_len;

        if total_len > self.mtu {
            return Err("failed data.len()>mtu");
        }

        let data: Box<[u8]> = vec![0; total_len].into_boxed_slice();

        let mut reta = DataOwned::new(
            fake_head_len,
            true,
            data,
            false,
            1,
            self.id_len,
            counters_len + TIME_LEN_IN_BYTES,
        )?;

        if fake_head.is_some() {
            reta.fake_head_mut().copy_from_slice(&fake_head.unwrap())
        }
        reta.head_byte_set(((false as u8) << 6) | ((true as u8) << 7));

        //id insert
        if self.id_len > 8 {
            return Err("Id is incoreect id is big  > 8");
        }
        if self.id_len > 0 {
            let mut temp: [u8; 8] = [0_u8; 8];
            u64_to_bytes(id, &mut temp)?;
            reta.id_mut()
                .copy_from_slice(&temp[temp.len() - self.id_len..])
        }

        //time insetr
        reta.set_time(time_sleep)?;

        {
            let counters_slise: &mut [u8] = &mut reta.content_mut()[TIME_LEN_IN_BYTES..];

            for (x, countr) in counters.iter().enumerate() {
                let x: usize = x << 1;

                u16_to_bytes(*countr, &mut counters_slise[x..x + 2])?;
            }
        }

        //MAC GENERATE!
        let pos_mac: usize = counters_pos_end;
        match self.enc_and_tag {
            EncTypeGetMode::Type1SplitMutSlices(fnce) => {
                let (free_data, mac_only) = reta.__data.split_at_mut(pos_mac);
                let mut hollow_arr = [0_u8; 0];

                fnce(&free_data, &mut hollow_arr, mac_only, 0)?;
            }
            EncTypeGetMode::Type2FullArrAndIndexes(fnce) => {
                fnce(&mut reta.__data, pos_mac, pos_mac, 0)?;
            }
        };

        Ok(reta)
    }

    pub fn max_size_of_payload(&self) -> usize {
        self.mtu - (self.fake_head_len + 3 + self.id_len + self.tag_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_countr16_to32(counter: u16,last_aprows_counr:u32) -> Result<u32, &'static str> {
        Ok(counter as u32)
    }

    fn dummy_enc_and_tagt1(
        head: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        countr: u32,
    ) -> Result<(), &'static str> {
        //enc
        for x in data.iter_mut() {
            *x ^= 0xDD ^ countr as u8;
        }
        let mut tag_mac = 0xFAFAFAFA_u32;
        let mut enumic = 0_u32;
        //tag of head
        for x in head.iter() {
            tag_mac = tag_mac.wrapping_add(*x as u32);
            tag_mac ^= tag_mac.rotate_left(17);
            tag_mac ^= enumic;
            enumic += 1;
        }
        //tag of data
        for x in data.iter() {
            tag_mac = tag_mac.wrapping_add(*x as u32);
            tag_mac ^= tag_mac.rotate_left(17);
            tag_mac ^= enumic;
            enumic += 1;
        }

        //tag fill
        for b in tag.iter_mut() {
            *b = tag_mac as u8;
        }
        Ok(())
    }

    fn dummy_enc_and_tagt2(
        fulldata: &mut [u8],
        datastart: usize,
        tagstart: usize,
        countr: u32,
    ) -> Result<(), &'static str> {
        //enc
        for x in fulldata[datastart..tagstart].iter_mut() {
            *x ^= 0xDD ^ countr as u8;
        }

        let mut tag_mac = 0xFAFAFAFA_u32;
        //get tag val
        for x in fulldata[..tagstart].iter().enumerate() {
            tag_mac = tag_mac.wrapping_add(*x.1 as u32);
            tag_mac ^= tag_mac.rotate_left(17);
            tag_mac ^= x.0 as u32;
        }

        //println!("af tag: {:x?}", fulldata[..tagstart].iter());
        //tag fill
        for b in fulldata[tagstart..].iter_mut() {
            *b = tag_mac as u8;
        }

        //println!("indexinng enc {} {} {} {} ",fulldata.len(),datastart,tagstart, countr);
        //println!("enc tag: {:x?}", fulldata[tagstart..].iter());
        //println!("fd enc: {:x?}", fulldata.iter());
        Ok(())
    }

    fn dummy_dec_and_tagt2(
        fulldata: &mut [u8],
        datastart: usize,
        tagstart: usize,
        countr: u32,
    ) -> Result<(), &'static str> {
        let mut tag_mac = 0xFAFAFAFA_u32;

        for x in fulldata[..tagstart].iter().enumerate() {
            tag_mac = tag_mac.wrapping_add(*x.1 as u32);
            tag_mac ^= tag_mac.rotate_left(17);
            tag_mac ^= x.0 as u32;
        }

        //tag check
        for &b in fulldata[tagstart..].iter() {
            //println!("tag: {:x?} {:x?}",b,tag_mac  as u8);
            if b != tag_mac as u8 {
                return Err("tag is inncorect!!");
            }
        }

        //dec
        for x in fulldata[datastart..tagstart].iter_mut() {
            *x ^= 0xDD ^ countr as u8;
        }
        Ok(())
    }

    fn __dummy_dec_and_tagt1(
        head: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        countr: u32,
    ) -> Result<(), &'static str> {
        let mut tag_mac = 0xFAFAFAFA_u32;
        let mut enumic = 0_u32;
        //tag of head
        for x in head.iter() {
            tag_mac = tag_mac.wrapping_add(*x as u32);
            tag_mac ^= tag_mac.rotate_left(17);
            tag_mac ^= enumic;
            enumic += 1;
        }
        //tag of data
        for x in data.iter() {
            tag_mac = tag_mac.wrapping_add(*x as u32);
            tag_mac ^= tag_mac.rotate_left(17);
            tag_mac ^= enumic;
            enumic += 1;
        }

        //tag fill
        for b in tag.iter_mut() {
            *b = tag_mac as u8;
        }

        //dec
        for x in data.iter_mut() {
            *x ^= 0xDD ^ countr as u8;
        }
        Ok(())
    }

    fn fake_head() -> Option<&'static [u8]> {
        Some(&[1, 2, 3, 4, 5, 6])
    }

    #[test]
    fn test_dummu() {
        let mut ablx = [0_u8; 30];

        for x in ablx.iter_mut().enumerate() {
            *x.1 = x.0 as u8;
        }
        let ret1 = dummy_enc_and_tagt2(&mut ablx, 3, 20, 12);
        let ret2 = dummy_dec_and_tagt2(&mut ablx, 3, 20, 12);

        if ret1.is_err() {
            panic!("{:?}", ret1);
        }
        if ret2.is_err() {
            panic!("{:?}", ret2);
        }

        assert_eq!(ret1.is_ok(), true);
        assert_eq!(ret2.is_ok(), true);

        for i in 0..ablx.len() {
            ablx[i] ^= 1;
            {
                assert_eq!(dummy_dec_and_tagt2(&mut ablx, 3, 20, 12).is_err(), true);
            }
            ablx[i] ^= 1;
        }
    }

    #[test]
    fn test_data() {
        let mtu: usize = 1400;
        let id = 0x1122334455667788_u64;
        let cou = 0xaabb_u32;

        let lens_id: Vec<usize> = vec![0_usize, 4, 6, 8];
        let lens_continsi: Vec<usize> = vec![1_usize, 3, 321];
        let lens_tag: Vec<usize> = vec![8_usize, 16, 24, 32];
        let epvs: Vec<bool> = vec![true, false];

        let mut test_valid: bool = true;

        //let mut aha =1;
        for idsi in lens_id.iter() {
            for hihsi in lens_tag.iter() {
                for epivis in epvs.iter() {
                    for contisi in lens_continsi.iter() {
                        let content = vec![21_u8; *contisi].into_boxed_slice();

                        let parse = PaskageParser::new(
                            mtu,
                            fake_head().unwrap().len(),
                            *idsi,
                            *hihsi,
                            EncTypeGetMode::Type2FullArrAndIndexes(dummy_enc_and_tagt2),
                            DecrptTypeGetMode::Type2FullArrAndIndexes(dummy_dec_and_tagt2),
                            dummy_countr16_to32,
                        );

                        let t1 = parse.content_to_data_p(
                            fake_head(),
                            &content,
                            *epivis,
                            id,
                            cou,
                            WPascageMode::FastEPVQeuqe,
                        );

                        match t1 {
                            Err(x) => {
                                test_valid = false;

                                println!("ERR WIS PASCAGE! Err(x) = : {}", x);
                                println!(
                                    "-----> Params: epv: {}   taglen: {}   idlen: {}   contlen: {} ",
                                    *epivis, *hihsi, *idsi, *contisi
                                );
                                println!(" ");
                            }
                            Ok(x) => {}
                        }
                    }
                }
            }
        }
        if !test_valid {
            panic!("ERR IN PARAMS^^^^^^^^^^^^^")
        }
    }

    #[test]
    fn test_new_valid_data() {
        let data = vec![0u8; 20].into_boxed_slice();
        let offseth = 1;
        let id_len = 2;
        let content_len = 10;

        let result = DataOwned::new(
            fake_head().unwrap().len(),
            false,
            data.clone(),
            false,
            offseth,
            id_len,
            content_len,
        );
        assert!(result.is_ok());

        let data_owned = result.unwrap();
        assert_eq!(
            data_owned.id_startpos,
            offseth + fake_head().map(|slice| slice.len()).unwrap_or(0)
        );
        assert_eq!(
            data_owned.content_startpos,
            offseth + id_len + fake_head().map(|slice| slice.len()).unwrap_or(0)
        );
        assert_eq!(
            data_owned.tag_startpos,
            offseth + id_len + content_len + fake_head().map(|slice| slice.len()).unwrap_or(0)
        );
    }

    #[test]
    fn test_new_invalid_content_len() {
        let data = vec![0u8; 20].into_boxed_slice();
        let offseth = 1;
        let id_len = 2;

        let result = DataOwned::new(
            fake_head().unwrap().len(),
            true,
            data.clone(),
            false,
            offseth,
            id_len,
            0,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "content_len must be greater than zero");

        let result = DataOwned::new(
            fake_head().unwrap().len(),
            true,
            data.clone(),
            false,
            offseth,
            id_len,
            TIME_LEN_IN_BYTES + 1,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "content_len <= TIME_LEN_IN_BYTES  +2  time(TIME_LEN_IN_BYTES) + 1 coumter miniumum(2)"
        );

        let result = DataOwned::new(
            fake_head().unwrap().len(),
            true,
            data.clone(),
            false,
            offseth,
            id_len,
            TIME_LEN_IN_BYTES + 3,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "content length must be even in feedback mode"
        );
    }

    #[test]
    fn test_errors_in_feedback_mode() {
        let data = vec![0u8; 20].into_boxed_slice();
        let offseth = 1;
        let id_len = 2;
        let content_len = 10;

        let data_owned = DataOwned::new(
            fake_head().unwrap().len(),
            true,
            data.clone(),
            false,
            offseth,
            id_len,
            content_len,
        )
        .unwrap();

        let result = data_owned.counter_fback_get(10);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "index is outside the array");

        let data_owned = DataOwned::new(
            fake_head().unwrap().len(),
            false,
            data.clone(),
            false,
            offseth,
            id_len,
            content_len,
        )
        .unwrap();
        let result = data_owned.counters_fback_len();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "is not fback");
    }

    #[test]
    fn test_parser_fdata() {
        let ctrs = [
            0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888_u16,
        ];

        let parse = PaskageParser::new(
            999,
            fake_head().unwrap().len(),
            7,
            10,
            EncTypeGetMode::Type2FullArrAndIndexes(dummy_enc_and_tagt2),
            DecrptTypeGetMode::Type2FullArrAndIndexes(dummy_dec_and_tagt2),
            dummy_countr16_to32,
        );

        let teee = parse
            .fback_from_content(fake_head(), 0xFF00FF99, &ctrs, 0xAABBAABBAABBAABB_u64)
            .unwrap();

        //println!("d1: {:x?} ",teee.__data);
        //println!("tt {:x?} ",teee.set_time(0x77777777).unwrap());
        //println!("tt {:x?} ",teee.get_time().unwrap());
        //println!("d1: {:x?} ",teee.__data);

        assert_eq!(0xFF00FF99, teee.get_time().unwrap());

        assert_eq!(teee.counters_fback_len().unwrap(), ctrs.len());
        for (i, x) in ctrs.iter().enumerate() {
            assert_eq!(*x, teee.counter_fback_get(i).unwrap());
        }

        //for x in teee.__data.iter(){
        //    print!("{:x} ",*x);
        //}

        assert_eq!(teee.tag_len(), 10);

        for x in teee.tag().iter() {
            //print!("{:x} ",*x);
            assert_eq!(*x, 104);
        }

        //for i in 0..8 {
        //    println!("{:?} {:x?}",teee.counters_len(), teee.counter_get(i));
        //}

        let teee2 = parse.data_to_content_p(teee.__data).unwrap();

        assert_eq!(teee2.0.is_fback(), true);
        assert_eq!(teee2.0.is_epv(), false);
        assert_eq!(teee2.0.counters_fback_len().unwrap(), ctrs.len());

        for (i, &x) in ctrs.iter().enumerate() {
            assert_eq!(x, teee2.0.counter_fback_get(i).unwrap());
        }
    }

    #[test]
    fn test_parser_content() {
        let content = [
            0x6_u8, 0x23, 0x41, 0x14, 0x83, 0x75, 0x76, 0x65, 0x53, 0x32, 21,
        ];

        let parse = PaskageParser::new(
            600,
            fake_head().unwrap().len(),
            1,
            16,
            EncTypeGetMode::Type2FullArrAndIndexes(dummy_enc_and_tagt2),
            DecrptTypeGetMode::Type2FullArrAndIndexes(dummy_dec_and_tagt2),
            dummy_countr16_to32,
        );

        let teee = parse
            .content_to_data_p(
                fake_head(),
                &content,
                true,
                0xAABBAABBAABBAABB_u64,
                0xFFFF,
                WPascageMode::FastEPVQeuqe,
            )
            .unwrap();

        //println!("{:x?}",  teee);
        //println!("{:?}", teee.countr());
        assert_eq!(0xFFFF, teee.countr_get().unwrap());

        assert_eq!(teee.content().len(), content.len());
        assert_eq!(teee.tag_len(), 16);
        assert_eq!(teee.id_len(), 1);

        let teee2 = parse.data_to_content_p(teee.data_box().clone()).unwrap();

        assert_eq!(teee2.1.unwrap(), WPascageMode::FastEPVQeuqe);
        assert_eq!(teee.content().len(), teee2.0.content().len());

        for (&x1, &x2) in teee2.0.content().iter().zip(content.iter()) {
            assert_eq!(x1, x2);
        }
    }

    #[test]
    fn test_parser_content_attac() {
        let content = [
            0x6_u8, 0x23, 0x41, 0x14, 0x83, 0x75, 0x76, 0x65, 0x53, 0x32, 21,
        ];

        let parse = PaskageParser::new(
            999,
            fake_head().unwrap().len(),
            2,
            6,
            EncTypeGetMode::Type2FullArrAndIndexes(dummy_enc_and_tagt2),
            DecrptTypeGetMode::Type2FullArrAndIndexes(dummy_dec_and_tagt2),
            dummy_countr16_to32,
        );

        let teee = parse
            .content_to_data_p(
                fake_head(),
                &content,
                true,
                0xAABBAABBAABBAABB_u64,
                0xFFFF,
                WPascageMode::WaitPackages,
            )
            .unwrap();

        //println!("{:#x?}",  teee);
        assert_eq!(0xFFFF, teee.countr_get().unwrap());
        assert_eq!(teee.content().len(), content.len());
        assert_eq!(teee.tag_len(), 6);
        assert_eq!(teee.id_len(), 2);

        let datatic_temp = teee.data_box().clone();

        for x in 0..datatic_temp.len() {
            let mut datatic = datatic_temp.clone();

            datatic[x] ^= 2;

            let teee2 = parse.data_to_content_p(datatic).is_err();
            assert_eq!(teee2, true);
        }

        let datatic = datatic_temp.clone();

        let teee2 = parse.data_to_content_p(datatic).is_err();
        assert_eq!(teee2, false);
    }

    #[test]
    fn test_parser_fdata_attac() {
        let id_len = 7;
        let tag_len = 9;

        let ctrs = [
            0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888_u16,
        ];

        let parse = PaskageParser::new(
            999,
            fake_head().unwrap().len(),
            7,
            9,
            EncTypeGetMode::Type2FullArrAndIndexes(dummy_enc_and_tagt2),
            DecrptTypeGetMode::Type2FullArrAndIndexes(dummy_dec_and_tagt2),
            dummy_countr16_to32,
        );

        let teee = parse
            .fback_from_content(fake_head(), 0xFF00FF99, &ctrs, 0xAABBAABBAABBAABB_u64)
            .unwrap();

        let datatic_temp = teee.data_box().clone();

        for x in 0..datatic_temp.len() {
            let mut datatic = datatic_temp.clone();

            datatic[x] ^= 0x4;

            let teee2 = parse.data_to_content_p(datatic).is_err();

            assert_eq!(teee2, true);
        }

        let datatic = datatic_temp.clone();
        let teee2 = parse.data_to_content_p(datatic).is_err();
        assert_eq!(teee2, false);
    }
}
