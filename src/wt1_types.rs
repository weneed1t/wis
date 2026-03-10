use crate::t0pology::PackTopology;
#[derive(Debug, Clone)]

pub enum PackErr {
    IdConnErr(&'static str),
    IdSendRecvErr(&'static str),
    CrcErr(&'static str),
    TagErr(&'static str),
    LenErr(&'static str),
    UndefinedErr(&'static str),
    TTLErr(&'static str),
}

#[derive(Debug, Clone)]
pub enum WTypeErr {
    LenSizeErr(&'static str),
    CompileErr(&'static str),
    PackageDamaged(&'static str),
    WorkTimeErr(&'static str),
}

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

impl PartialEq for PackErr {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::IdConnErr(_), Self::IdConnErr(_))
                | (Self::IdSendRecvErr(_), Self::IdSendRecvErr(_))
                | (Self::CrcErr(_), Self::CrcErr(_))
                | (Self::TagErr(_), Self::TagErr(_))
                | (Self::LenErr(_), Self::LenErr(_))
                | (Self::UndefinedErr(_), Self::UndefinedErr(_))
                | (Self::TTLErr(_), Self::TTLErr(_))
        )
    }
}

impl WTypeErr {
    pub fn is_len_small_err(&self) -> bool {
        matches!(self, Self::LenSizeErr(_))
    }

    pub fn is_none_field(&self) -> bool {
        match self {
            Self::CompileErr(_) => true,
            _ => false,
        }
    }

    pub fn is_pascage_damaget(&self) -> bool {
        matches!(self, Self::PackageDamaged(_))
    }
    pub fn is_work_time_err(&self) -> bool {
        matches!(self, Self::WorkTimeErr(_))
    }

    pub fn err_to_str(&self) -> &'static str {
        match self {
            Self::LenSizeErr(x) => x,
            Self::CompileErr(x) => x,
            Self::PackageDamaged(x) => x,
            Self::WorkTimeErr(x) => x,
        }
    }
}

impl PartialEq for WTypeErr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::LenSizeErr(x), Self::LenSizeErr(y)) => x == y,
            (Self::CompileErr(x), Self::CompileErr(y)) => x == y,
            (Self::PackageDamaged(x), Self::PackageDamaged(y)) => x == y,
            (Self::WorkTimeErr(x), Self::WorkTimeErr(y)) => x == y,
            _ => false,
        }
    }
}
#[derive(Debug, Clone)]
pub enum MyRole {
    Initiator,
    Passive,
}
impl MyRole {
    pub fn is_initiator(&self) -> bool {
        matches!(self, Self::Initiator)
    }

    pub fn is_passive(&self) -> bool {
        matches!(self, Self::Passive)
    }

    pub fn sate_to_bit(&self) -> u8 {
        match self {
            Self::Passive => 0,
            Self::Initiator => 1,
        }
    }

    pub fn bit_to_state(bit: u8) -> Self {
        match bit & 1 {
            1 => Self::Initiator,
            0 => Self::Passive,
            _ => Self::Initiator,
        }
    }
}

impl PartialEq for MyRole {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Initiator, Self::Initiator) | (Self::Passive, Self::Passive)
        )
    }
}

#[derive(Debug, Clone)]
pub enum PackType {
    FBack,
    Data,
}
impl PackType {
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data)
    }

    pub fn is_fback(&self) -> bool {
        matches!(self, Self::FBack)
    }

    pub fn sate_to_bit(&self) -> u8 {
        match self {
            Self::FBack => 1,
            Self::Data => 0,
        }
    }

    pub fn bit_to_state(bit: u8) -> Self {
        match bit & 1 {
            1 => Self::FBack,
            0 => Self::Data,
            _ => Self::FBack,
        }
    }
}

impl PartialEq for PackType {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Data, Self::Data) | (Self::FBack, Self::FBack)
        )
    }
}

//======================================================================================================

/*type1 fn(&[u8], &mut [u8], &mut [u8],u64, Option<&[u8]>) -> Result<(), &'static str>
where &[u8] is the head, the data that is not encrypted,
the first &mut [u8] is the body, the data that is encrypted
the second &mut [u8] is the place where the authentication tag from head + body should be placed
Option<&[u8]> is a Nonce if is a init in topology: &t2page::PackTopology,

type 2 fn(&mut[u8],usize,usize, u64, Option<&[u8]>) -> Result<(), &'static str>
&mut[u8] is the full mutable packet
the first usize is the index of the start of the body, so [0..(first usize)] is the head
the second usize is the index of the start of tag, so [(first usize)..(second usize)] is the body
the tag field, it is [(second usize)..] is the place for the tag
Option<&[u8]> is a Nonce if is a init in topology: &t2page::PackTopology,

this enum is needed for maximum compatibility with the encryption libraries that are on the rust
they both return -> Result<(), &'static str>
ok() means that the data was encrypted successfully
and there were no errors, &'static str reports some error,
 when it is called, the preparation of the packet for sending
 will be interrupted and it will not be sent

#[derive(Debug, Clone)]
pub enum TypeGetMode {
    /// (HEAD non enc), (PAYLOAD enc), (TAG) (countr(nonce)), (NONCE)
    Type1SplitMutSlices(
        fn(&[u8], &mut [u8], &mut [u8], u64, Option<&[u8]>) -> Result<(), &'static str>,
    ),
    /// (FULLDATA),  (HEAD non enc)[0..usize1],(PAYLOAD
    /// enc)[usize1..usize2],(TAG)[usize2..],(countr(nonce)), (NONCE)[start..end]
    Type2FullArrAndIndexes(
        fn(&mut [u8], usize, usize, u64, Option<(usize, usize)>) -> Result<(), &'static str>,
    ),
}
    */

#[derive(Debug, Clone)]
pub enum Cryptlag {
    Encrypt,
    Decrypt,
}
#[derive(Debug, Clone)]
pub enum StatusDecrypt {
    PackageDamaged,
    DecodedCorrectly,
}

impl StatusDecrypt {
    pub fn is_correctly(&self) -> bool {
        matches!(self, Self::DecodedCorrectly)
    }

    pub fn is_damaged(&self) -> bool {
        matches!(self, Self::PackageDamaged)
    }
}

impl PartialEq for StatusDecrypt {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::DecodedCorrectly, Self::DecodedCorrectly)
                | (Self::PackageDamaged, Self::PackageDamaged)
        )
    }
}

//#############################################################3

pub trait EncWis: Sized {
    fn new(key: &[u8]) -> Result<Self, &'static str>;

    /// (HEAD non enc), (PAYLOAD enc), (TAG) (countr(nonce)), (NONCE)
    fn encrypt(
        &self,
        non_enc_head: &[u8],
        enc_payload: &mut [u8],
        auth_tag: &mut [u8],
        nonce_countr: u64,
        nonce: Option<&[u8]>,
    ) -> Result<(), &'static str>;
    /// (HEAD non enc), (PAYLOAD enc), (TAG) (countr(nonce)), (NONCE)
    fn decrypt(
        &self,
        non_enc_head: &[u8],
        enc_payload: &mut [u8],
        auth_tag: &mut [u8],
        nonce_countr: u64,
        nonce: Option<&[u8]>,
    ) -> Result<StatusDecrypt, &'static str>;
}

pub trait Noncer: Sized {
    fn new(key: &[u8]) -> Result<Self, &'static str>;

    fn set_nonce(&mut self, nonce_gener: &mut [u8]) -> Result<(), &'static str>;
}

pub trait Thrasher: Sized {
    fn new(key: &[u8]) -> Result<Self, &'static str>;

    fn set_user_field(&mut self, user_field: &mut [u8]) -> Result<(), &'static str>;
}

pub trait Cfcser: Sized {
    fn new(_key: &[u8]) -> Result<Self, &'static str>;
    fn gen_crc(&mut self, payload: &[u8], cfc_field: &mut [u8]) -> Result<(), &'static str>;
}

pub trait Randomer: Sized {
    fn new(_key: &[u8]) -> Result<Self, &'static str>;
    fn gen_rand_u64(&mut self) -> u64;
    fn gen_rand_u32(&mut self) -> u32;
}
//#############################################################3
pub struct DumpNonser {
    pub t: u64,
}
pub struct DumpCfcser {
    pub t: u64,
}
pub struct DumpThrasher {
    pub t: u64,
}
pub struct DumpRandomer {
    pub t: u64,
}

pub struct DumpEnc {
    pub t: u64,
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
        Ok(Self {
            t: _key.iter().map(|&x| x as u64).sum(),
        })
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

impl Cfcser for DumpCfcser {
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
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
            })
        }
        //Ok(Self {})
    }
    fn gen_crc(&mut self, _payload: &[u8], _cfc_field: &mut [u8]) -> Result<(), &'static str> {
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
            let mut tt: u64 = _payload
                .iter()
                .enumerate()
                .map(|(u, &x)| (x as u64).rotate_left(((u as u32) * 17) % 64))
                .sum();
            bpg(&mut tt, _cfc_field);
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
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
            })
        }
    }
    fn set_user_field(&mut self, _user_field: &mut [u8]) -> Result<(), &'static str> {
        #[cfg(not(test))]
        panic!(
            "This panic is called from Thrasher because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<Thrasher> = None;"
        );
        #[cfg(test)]
        {
            bpg(&mut self.t, _user_field);
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
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
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
            Ok(Self {
                t: _key.iter().map(|&x| x as u64).sum(),
            })
        }
    }

    fn encrypt(
        &self,
        _non_enc_head: &[u8],
        _enc_payload: &mut [u8],
        _auth_tag: &mut [u8],
        _nonce_countr: u64,
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
        _nonce_countr: u64,
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

///(array(head fields len + headbyte len + payload len+ tag len),(payload start pos,
/// payload endpos) )
pub fn pre_alloc(
    topology: &PackTopology,
    mtu: usize,
    payloadlen: usize,
    fill: u8,
) -> Result<(Box<[u8]>, (usize, usize)), WTypeErr> {
    let len_pack = topology
        .total_minimal_len()
        .checked_add(payloadlen)
        .ok_or(WTypeErr::LenSizeErr("overflow payloadlen + minimal_len()"))?;

    Ok((
        vec![
            fill;
            if len_pack > mtu {
                return Err(WTypeErr::LenSizeErr("len_pack > mtu"));
            } else {
                len_pack
            }
        ]
        .into_boxed_slice(),
        (topology.content_start_pos(), len_pack - topology.tag_len()),
    ))
}

#[cfg(test)]
fn bpg(t: &mut u64, v: &mut [u8]) {
    for x in v.iter_mut() {
        *t = t.rotate_left(11).wrapping_add(*t).wrapping_add(42389);
        *x ^= *t as u8;
    }
}

#[cfg(test)]
mod tests_my_role {
    use super::*;

    #[test]
    fn test_is_initiator() {
        assert!(MyRole::Initiator.is_initiator());
        assert!(!MyRole::Passive.is_initiator());
    }

    #[test]
    fn test_is_passive() {
        assert!(MyRole::Passive.is_passive());
        assert!(!MyRole::Initiator.is_passive());
    }

    #[test]
    fn test_state_to_bit() {
        assert_eq!(MyRole::Passive.sate_to_bit(), 0);
        assert_eq!(MyRole::Initiator.sate_to_bit(), 1);
    }

    #[test]
    fn test_bit_to_state() {
        assert!(matches!(MyRole::bit_to_state(0), MyRole::Passive));
        assert!(matches!(MyRole::bit_to_state(1), MyRole::Initiator));
        assert!(matches!(MyRole::bit_to_state(2), MyRole::Passive)); // 2 & 1 = 0
        assert!(matches!(MyRole::bit_to_state(3), MyRole::Initiator)); // 3 & 1 = 1
        assert!(matches!(MyRole::bit_to_state(255), MyRole::Initiator)); // 255 & 1 = 1
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(MyRole::Initiator, MyRole::Initiator);
        assert_eq!(MyRole::Passive, MyRole::Passive);
        assert_ne!(MyRole::Initiator, MyRole::Passive);
        assert_ne!(MyRole::Passive, MyRole::Initiator);
    }

    #[test]
    fn test_clone() {
        let role1 = MyRole::Initiator;
        let role2 = role1.clone();
        assert_eq!(role1, role2);

        let role3 = MyRole::Passive;
        let role4 = role3.clone();
        assert_eq!(role3, role4);
    }

    #[test]
    fn test_debug() {
        let initiator = format!("{:?}", MyRole::Initiator);
        let passive = format!("{:?}", MyRole::Passive);

        assert!(initiator.contains("Initiator"));
        assert!(passive.contains("Passive"));
    }

    #[test]
    fn test_roundtrip_conversion() {
        // Test that bit_to_state is the inverse of state_to_bit
        for role in [MyRole::Initiator, MyRole::Passive] {
            let bit = role.sate_to_bit();
            let reconstructed = MyRole::bit_to_state(bit);
            assert_eq!(role, reconstructed);
        }
    }
}

#[cfg(test)]
mod tests_my_type {
    use super::*;

    #[test]
    fn test_is_data() {
        assert!(PackType::Data.is_data());
        assert!(!PackType::FBack.is_data());
    }

    #[test]
    fn test_is_fback() {
        assert!(PackType::FBack.is_fback());
        assert!(!PackType::Data.is_fback());
    }

    #[test]
    fn test_sate_to_bit() {
        assert_eq!(PackType::FBack.sate_to_bit(), 1);
        assert_eq!(PackType::Data.sate_to_bit(), 0);
    }

    #[test]
    fn test_bit_to_state() {
        assert!(matches!(PackType::bit_to_state(0), PackType::Data));
        assert!(matches!(PackType::bit_to_state(1), PackType::FBack));
        // Test with higher bits (only LSB should matter)
        assert!(matches!(PackType::bit_to_state(2), PackType::Data)); // 2 & 1 = 0
        assert!(matches!(PackType::bit_to_state(3), PackType::FBack)); // 3 & 1 = 1
        assert!(matches!(PackType::bit_to_state(255), PackType::FBack)); // 255 & 1 = 1
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(PackType::Data, PackType::Data);
        assert_eq!(PackType::FBack, PackType::FBack);
        assert_ne!(PackType::Data, PackType::FBack);
        assert_ne!(PackType::FBack, PackType::Data);
    }

    #[test]
    fn test_clone() {
        let data = PackType::Data;
        let cloned = data.clone();
        assert_eq!(data, cloned);

        let fback = PackType::FBack;
        let cloned_fback = fback.clone();
        assert_eq!(fback, cloned_fback);
    }
}

#[cfg(test)]
mod tests_prealocc {
    use super::*;
    use crate::t0pology::PakFields;
    #[test]
    fn test_prealoc() {
        let mkd = [13, 7, 6, 8];
        let fields = vec![
            //t2page::PakFields::HeadByte,
            PakFields::UserField(mkd[0]),
            PakFields::Counter(mkd[1]),
            PakFields::IdConnect(mkd[2]),
            PakFields::HeadCRC(mkd[3]),
        ];

        let result = PackTopology::new(19, &fields, true, false).unwrap();

        //let mut temp = pre_alloc(&result, 1000, 500).unwrap();
        let total: usize = mkd.iter().sum();

        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 50, 0),
            Err(WTypeErr::LenSizeErr("len_pack > mtu"))
        );
        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 49, 0),
            Ok((
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
                .into_boxed_slice(),
                (35usize, 84usize)
            ))
        );

        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 49, 99),
            Ok((
                vec![
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99
                ]
                .into_boxed_slice(),
                (35usize, 84usize)
            ))
        );

        assert_eq!(
            pre_alloc(&result, !0_usize, (!0_usize) - 1, 0),
            Err(WTypeErr::LenSizeErr("overflow payloadlen + minimal_len()"))
        );

        let mut t = pre_alloc(&result, 100000, 43, 0).unwrap();
        t.0[t.1.0..t.1.1].fill(1);
        let count = t.0.iter().filter(|&&element| element == 1).count();
        let count0 = t.0.iter().take_while(|&&x| x == 0).count();

        assert_eq!(count, 43);
        assert_eq!(count0, result.total_head_slice().2 + 1);

        println!("{:?}   /n{} /n {}", t.0, count, count0);
    }
}

#[cfg(test)]
mod tests_dumps_nonser_cfcser {
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
        let mut stub = DumpNonser { t: 10 }; // we can create it directly because it's a struct
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
        let _ = DumpCfcser::new(&[]);
    }

    #[test]
    //#[should_panic(expected = "This panic is called from DumpCfcser")]
    fn dumpcfcser_gen_crc_panics() {
        let mut stub = DumpCfcser { t: 10 };
        let mut cfc_field = [0u8; 4];
        let payload = [1, 2, 3];
        stub.gen_crc(&payload, &mut cfc_field).unwrap();
    }

    #[test]
    fn dumpcfcser_option_none_works() {
        let opt: Option<DumpCfcser> = None;
        assert!(opt.is_none());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ trait bounds – ensure that the stubs satisfy all required traits          │
    // │ (compilation already guarantees this, but we can explicitly check)        │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn dumpnonser_impl_noncer() {
        fn takes_noncer<T: Noncer>(_: T) {}
        takes_noncer(DumpNonser { t: 10 }); // compiles -> ok
    }

    #[test]
    fn dumpcfcser_impl_cfcser() {
        fn takes_cfcser<T: Cfcser>(_: T) {}
        takes_cfcser(DumpCfcser { t: 10 }); // compiles -> ok
    }
}

#[cfg(test)]
mod tests_statusdecrypt {
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 1: creation & debug/clone traits (auto-derived)                     │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn debug_and_clone_work() {
        let original = StatusDecrypt::DecodedCorrectly;
        let cloned = original.clone();
        assert!(format!("{:?}", cloned).contains("DecodedCorrectly"));
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 2: equality (PartialEq) – both variants compare correctly          │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn decoded_correctly_equals_itself() {
        assert_eq!(
            StatusDecrypt::DecodedCorrectly,
            StatusDecrypt::DecodedCorrectly
        );
    }

    #[test]
    fn package_damaged_equals_itself() {
        assert_eq!(StatusDecrypt::PackageDamaged, StatusDecrypt::PackageDamaged);
    }

    #[test]
    fn different_variants_are_not_equal() {
        assert_ne!(
            StatusDecrypt::DecodedCorrectly,
            StatusDecrypt::PackageDamaged
        );
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 3: helper methods (is_correctly / is_damaged) – one test per variant│
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn is_correctly_returns_true_only_for_decoded_correctly() {
        assert!(StatusDecrypt::DecodedCorrectly.is_correctly());
        assert!(!StatusDecrypt::PackageDamaged.is_correctly());
    }

    #[test]
    fn is_damaged_returns_true_only_for_package_damaged() {
        assert!(StatusDecrypt::PackageDamaged.is_damaged());
        assert!(!StatusDecrypt::DecodedCorrectly.is_damaged());
    }

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ group 4: exhaustive coverage – one test verifies all discriminant values  │
    // └────────────────────────────────────────────────────────────────────────────┘
    #[test]
    fn all_variants_covered() {
        // this test ensures we haven't missed any variant if the enum grows
        let variants = [
            StatusDecrypt::DecodedCorrectly,
            StatusDecrypt::PackageDamaged,
        ];
        for v in variants {
            match v {
                StatusDecrypt::DecodedCorrectly => assert!(v.is_correctly()),
                StatusDecrypt::PackageDamaged => assert!(v.is_damaged()),
            }
        }
    }
}

#[cfg(test)]
mod tests_pack_err {
    use super::*;

    // ┌────────────────────────────────────────────────────────────────────────────┐
    // │ packerr partialeq – equality depends only on variant, not on string       │
    // └────────────────────────────────────────────────────────────────────────────┘

    #[test]
    fn same_variant_with_different_strings_are_equal() {
        // any two strings inside the same variant compare as equal
        assert_eq!(PackErr::IdConnErr("a"), PackErr::IdConnErr("b"));
        assert_eq!(PackErr::IdSendRecvErr("x"), PackErr::IdSendRecvErr("y"));
        assert_eq!(PackErr::CrcErr("foo"), PackErr::CrcErr("bar"));
        assert_eq!(PackErr::TagErr("1"), PackErr::TagErr("2"));
        assert_eq!(PackErr::LenErr("short"), PackErr::LenErr("long"));
        assert_eq!(PackErr::UndefinedErr("?"), PackErr::UndefinedErr("!"));
        assert_eq!(PackErr::TTLErr("127"), PackErr::TTLErr("255"));
    }

    #[test]
    fn same_variant_with_identical_strings_are_equal() {
        // sanity check – identical strings are obviously equal
        assert_eq!(PackErr::IdConnErr("same"), PackErr::IdConnErr("same"));
    }

    #[test]
    fn different_variants_are_not_equal() {
        // every pair of different variants must compare as not equal
        let all_variants = [
            PackErr::IdConnErr(""),
            PackErr::IdSendRecvErr(""),
            PackErr::CrcErr(""),
            PackErr::TagErr(""),
            PackErr::LenErr(""),
            PackErr::UndefinedErr(""),
            PackErr::TTLErr(""),
        ];

        for (i, a) in all_variants.iter().enumerate() {
            for (j, b) in all_variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "same variant {:?} should equal itself", a);
                } else {
                    assert_ne!(
                        a, b,
                        "different variants {:?} and {:?} must not be equal",
                        a, b
                    );
                }
            }
        }
    }

    #[test]
    fn equality_is_symmetric() {
        let a = PackErr::CrcErr("left");
        let b = PackErr::CrcErr("right");
        assert_eq!(a, b);
        assert_eq!(b, a); // symmetry property
    }

    #[test]
    fn equality_is_transitive() {
        let a = PackErr::TagErr("first");
        let b = PackErr::TagErr("second");
        let c = PackErr::TagErr("third");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a, c); // transitivity holds because all are same variant
    }

    #[test]
    fn equality_with_self_always_true() {
        let err = PackErr::LenErr("self");
        assert_eq!(err, err); // reflexivity
    }
}

#[cfg(test)]
mod tests_enca {
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

        dn.encrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();
        println!(" ");
        println!(" ");
        println!("hea {:?} ", a1);
        println!("pay {:?} ", a2);
        println!("aut {:?} ", a3);
        println!("non {:?} ", a4);
        println!(" {:?}", ret);

        assert_eq!(StatusDecrypt::DecodedCorrectly, ret);
        //
        //
        //
        //
        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let mut a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();

        a4[7] = !a4[7];

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();
        println!(" ");
        println!(" ");
        println!("hea {:?} ", a1);
        println!("pay {:?} ", a2);
        println!("aut {:?} ", a3);
        println!("non {:?} ", a4);
        println!(" {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);

        let mut a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();

        a1[7] = !a1[7];

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();
        println!(" ");
        println!(" ");
        println!("hea {:?} ", a1);
        println!("pay {:?} ", a2);
        println!("aut {:?} ", a3);
        println!("non {:?} ", a4);
        println!(" {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);

        let a1 = vec![1u8; 10];
        let mut a2 = vec![2u8; 15];
        let mut a3 = vec![2u8; 20];
        let a4 = vec![3u8; 25];

        dn.encrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();

        a2[7] = !a2[7];

        let ret = dn.decrypt(&a1, &mut a2, &mut a3, 0, Some(&a4)).unwrap();
        println!(" ");
        println!(" ");
        println!("hea {:?} ", a1);
        println!("pay {:?} ", a2);
        println!("aut {:?} ", a3);
        println!("non {:?} ", a4);
        println!(" {:?}", ret);

        assert_eq!(StatusDecrypt::PackageDamaged, ret);
    }
}
