use crate::t0pology::PackTopology;
#[derive(Debug, Clone)]
pub enum WTypeErr {
    LenSizeErr(&'static str),
    NoneFieldErr(&'static str),
    PackageDamaged(&'static str),
    WorkTimeErr(&'static str),
}

impl WTypeErr {
    pub fn is_len_small_err(&self) -> bool {
        matches!(self, Self::LenSizeErr(_))
    }

    pub fn is_none_field(&self) -> bool {
        match self {
            Self::NoneFieldErr(_) => true,
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
            Self::NoneFieldErr(x) => x,
            Self::PackageDamaged(x) => x,
            Self::WorkTimeErr(x) => x,
        }
    }
}

impl PartialEq for WTypeErr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::LenSizeErr(x), Self::LenSizeErr(y)) => x == y,
            (Self::NoneFieldErr(x), Self::NoneFieldErr(y)) => x == y,
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

pub struct DumpNonser {}

impl Noncer for DumpNonser {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        panic!(
            "This panic is called from DumpNonser because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpNonser> = None;"
        );
        //Ok(Self {})
    }
    fn set_nonce(&mut self, _nonce_gener: &mut [u8]) -> Result<(), &'static str> {
        panic!(
            "This panic is called from DumpNonser because it is a stub class,
         none of its methods should be called in normal code and this class only
          serves to indicate it as None in variable:Option<DumpNonser> = None;"
        );
        //Ok(())
    }
}

pub trait Cfcser: Sized {
    fn new(_key: &[u8]) -> Result<Self, &'static str>;
    fn gen_crc(&mut self, cfc_field: &mut [u8], payload: &[u8]) -> Result<(), &'static str>;
}

pub struct DumpCfcser {}

impl Cfcser for DumpCfcser {
    fn new(_key: &[u8]) -> Result<Self, &'static str> {
        panic!(
            "This panic is called from DumpCfcser because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<DumpCfcser> = None;"
        );
        //Ok(Self {})
    }
    fn gen_crc(&mut self, _cfc_field: &mut [u8], _payload: &[u8]) -> Result<(), &'static str> {
        panic!(
            "This panic is called from DumpCfcser because it is a stub class,
            none of its methods should be called in normal code and this class only
            serves to indicate it as None in variable:Option<DumpCfcser> = None;"
        );
        //Ok(())
    }
}

///(array(head fields len + headbyte len + payload len+ tag len),(payload start pos,
/// payload endpos) )
pub fn pre_alloc(
    topology: &PackTopology,
    mtu: usize,
    payloadlen: usize,
) -> Result<(Box<[u8]>, (usize, usize)), WTypeErr> {
    let len_pack = topology
        .total_minimal_len()
        .checked_add(payloadlen)
        .ok_or(WTypeErr::LenSizeErr("overflow payloadlen + minimal_len()"))?;

    Ok((
        vec![
            0;
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
            pre_alloc(&result, total + 50 + 19, 50),
            Err(WTypeErr::LenSizeErr("len_pack > mtu"))
        );
        assert_eq!(
            pre_alloc(&result, total + 50 + 19, 49),
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
            pre_alloc(&result, !0_usize, (!0_usize) - 1),
            Err(WTypeErr::LenSizeErr("overflow payloadlen + minimal_len()"))
        );

        let mut t = pre_alloc(&result, 100000, 43).unwrap();
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
    #[should_panic(expected = "This panic is called from DumpNonser")]
    fn dumpnonser_new_panics() {
        let _ = DumpNonser::new(&[]);
    }

    #[test]
    #[should_panic(expected = "This panic is called from DumpNonser")]
    fn dumpnonser_set_nonce_panics() {
        let mut stub = DumpNonser {}; // we can create it directly because it's a struct
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
    #[should_panic(expected = "This panic is called from DumpCfcser")]
    fn dumpcfcser_new_panics() {
        let _ = DumpCfcser::new(&[]);
    }

    #[test]
    #[should_panic(expected = "This panic is called from DumpCfcser")]
    fn dumpcfcser_gen_crc_panics() {
        let mut stub = DumpCfcser {};
        let mut cfc_field = [0u8; 4];
        let payload = [1, 2, 3];
        stub.gen_crc(&mut cfc_field, &payload).unwrap();
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
        takes_noncer(DumpNonser {}); // compiles -> ok
    }

    #[test]
    fn dumpcfcser_impl_cfcser() {
        fn takes_cfcser<T: Cfcser>(_: T) {}
        takes_cfcser(DumpCfcser {}); // compiles -> ok
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
