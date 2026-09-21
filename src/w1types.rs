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
//use std::rc::Rc;
use std::sync::Arc;

use crate::t0grouper::GroupTopology;
use crate::t0pology::PackTopology;
///
///You can switch from Rc to Arc
pub type Rcc<T> = Arc<T>;
//pub type InFile<T> = Arc<Vec<T>>;

#[derive(Clone, Debug, PartialEq)]
///all id
pub struct Identified {
    ///The identifier of a specific device—it doesn't really matter what this value is,
    ///  since it's just for the user's convenience and isn't passed on when the device is
    /// transferred;  it could be a TCP port number or a physical address.
    pub my_metall_id: u64,
    /// reed Ids doc
    pub my_s_r_id: Option<Ids>,
    ///identifier  connection role + value id
    pub id_conn: Option<(u64, MyRole)>,
}

/// defines the packet type for `grouptopology`.
///
/// each set of fields has three options for usage:
/// * `fback` — for packets that return an acknowledgment.
/// * `data` — for data packets.
/// * `any` — for both `data` and `fback` packets.
///
/// # why is this necessary?
///
/// `grouptopology` has methods for obtaining the minimum packet length:
/// `fback_max_minimal_len` and `data_max_minimal_len`.
///
/// these values are required for the following context:
///
/// warning: the information below describes another package and may be outdated.
///
/// in `pub struct wsrecvqueuectrs::new`, the maximum capacity is strictly limited
/// by `payload_mtu`. this parameter is defined as:
/// `network mtu - packtopology::total_minimal_len()`.
///
/// since packets for `fback` and `data` may contain different fields (for example,
/// `fback` packets do not have a `crc` or `nonce` field), the payload length
/// will be greater.
///
/// # network constraints
///
/// * **internet networks (mtu ~1400–1500 bytes):** this functionality is redundant.
/// * **mesh or iot networks (e.g., bluetooth ble with 26-byte payload):** saving
///   a few extra bytes of free space provides a significant benefit.
#[derive(Debug, PartialEq, Clone)]
pub enum PackTypeGroup {
    /// packets that return an acknowledgment.
    Fback,
    /// data packets.
    Data,
    /// both data and fback packets.
    Any,
}

#[derive(Debug, PartialEq, Clone)]
///PackaddedStatus displays the status of adding a package to the queue.
pub enum PackAddedStatus {
    ///The package was added to both queues as expected, everything is fine.
    WasAdded,
    ///The packet wasn't added because WSFbackQueue is full.
    ///To clear it, an fback packet must be sent.
    FbackQueueIsfull,
    ///The package wasn't added because the package counter is too high to be added to WSUdpLike.
    UdpQueueCtrIsBig,
}

#[derive(Debug, Clone, PartialEq)]
///WSQueueState is needed to inform the user whether a packet has been added to the queue or not.<br>
/// In this context, "added" logically means that a packet with such a counter was,<br>
/// once in this queue and should not be added, as the queue is responsible for restoring the packet<br>
/// order and ensuring that there are no missed packets or duplicates.<br>
/// This is necessary for determining whether a packet should be placed in Fback.<br>
/// If the packet's status is NOT ElemIdIsBig,<br>
/// then its counter should be placed in the Fback queue.<br>
/// If the status is ElemIdIsBig, then such a packet should not be placed in Fback,<br>
/// as it cannot be processed at the current state of the algorithm.<br>
pub enum WSQueueState {
    /// this means that the packet counter is too<br>
    ///  large and the packet was not added physically and logically<br>
    ElemIdIsBig,
    ///ElemIdIsSmall means that the packet counter is too small to be added,<br>
    ///and the queue has been moved forward.Since the queue cannot skip packets,<br>
    ///this means that the packet is a duplicate of an old packet that was present in the past,<br>
    ///and can be considered logically added.<br>
    ElemIdIsSmall,
    ///This means that a packet with such a counter is already in the queue,<br>
    ///  that is, it is a duplicate, logically added but not physically<br>
    ElemIsAlreadyIn,
    ///This means that there is no package with such a counter, and it was successfully added.
    SuccessfulInsertion,
}

#[derive(Debug, PartialEq, Clone)]
///It is used to select a mode:
///a single topology for all connections,
///or a mix of different topologies for different connections.
///Actually, I could have used GroupTopology everywhere,
///which would have had only one topology.
/// But I decided to make things a little more complicated
///  for myself so that the code would run just a tiny bit faster.
pub enum PackScheme {
    ///OnePack is needed when it is necessary to use only when there is only one package topology,
    ///and all packages have the same field parameters
    OnePack(PackTopology),
    ///GroupPack is needed when different packet topologies are used in the same network,
    ///and different packets have different fields in different packets.
    GroupPack(GroupTopology),
}

impl PackScheme {
    ///get topol If `OnePack` is passed as an argument,
    ///it will return `PackTopology` regardless of the value of `tbyte`.
    pub fn get_topol(&self, tbyte: u8, group_pack_type: PackTypeGroup) -> Option<&PackTopology> {
        match self {
            Self::GroupPack(x) => x.get_from_u8(tbyte, group_pack_type),
            Self::OnePack(x) => Some(x),
        }
    }
    /// if i am GroupPack retutn true
    pub fn is_group(&self) -> bool {
        matches!(self, Self::GroupPack(_))
    }
    /// if i am OnePack retutn true
    pub fn is_one(&self) -> bool {
        matches!(self, Self::OnePack(_))
    }
}

#[derive(Clone, Debug, PartialEq)]
///id sender and recv
pub struct Ids {
    ///
    pub id_sender: u64,
    ///
    pub id_receiver: u64,
}
/// ttl max, ttl start, ttl edit
#[derive(Clone, Debug, PartialEq, Copy)]
pub struct Ttl {
    /// ttl max
    max: u64,
    /// ttl add or sub
    edit: i64,
    ///start ttl num
    start: u64,
    /// true pruning if ttl from pack + ttl_edit > ttl max
    /// false -> generate err
    forced_pruning: bool,
}

impl Ttl {
    /// true pruning if ttl from pack + ttl_edit > ttl max
    /// max >0 , start >0 , edit !=0, max > start
    pub fn new(max: u64, edit: i64, start: u64, forced_pruning: bool) -> Result<Self, String> {
        if max == 0 {
            return Err("max == 0".to_string());
        }

        if max <= start {
            return Err("max <= start".to_string());
        }
        if edit == 0 {
            return Err("ttl_edit == 0".to_string());
        }
        if start == 0 {
            return Err("start == 0".to_string());
        }

        Ok(Self {
            max,
            edit,
            start,
            forced_pruning,
        })
    }
    ///get max ttl
    pub fn max(&self) -> u64 {
        self.max
    }
    ///get edil num
    pub fn edit(&self) -> i64 {
        self.edit
    }
    ///get statrt
    pub fn start(&self) -> u64 {
        self.start
    }
    /// if orced_pruning == true ret true
    pub fn forced_pruning(&self) -> bool {
        self.forced_pruning
    }
}

///use in handmaker
#[derive(Debug, Clone, PartialEq)]
pub enum AtomHandFile {
    ///the file size generated by the session initiator and received by the passive
    /// participant
    InitiatorFileSize(usize),
    ///the file size generated by a passive session participant, and they accept this
    /// file and the session
    PassiveFileSize(usize),
}

impl AtomHandFile {
    /// Returns `true` if the variant is `InitiatorFileSize`.
    pub fn is_initiator(&self) -> bool {
        matches!(self, Self::InitiatorFileSize(_))
    }

    /// Returns `true` if the variant is `PassiveFileSize`.
    pub fn is_passive(&self) -> bool {
        matches!(self, Self::PassiveFileSize(_))
    }

    /// Returns the inner `usize` value regardless of the variant.
    pub fn size(&self) -> usize {
        match self {
            Self::InitiatorFileSize(s) | Self::PassiveFileSize(s) => *s,
        }
    }
}

/// A compact bit‑field structure that stores 8 boolean flags in a single byte.
///
/// Each flag occupies a fixed bit position:
/// - bit 0 → `is_fake`
/// - bit 1 → `is_kill`
/// - bits 2..=7 → reserved fields `reserve_2` … `reserve_7`
///
/// This representation minimises memory footprint and enables fast bitwise operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeadByteStruct {
    state: u8,
}

// Bit masks for each field (used internally)
impl HeadByteStruct {
    const MASK_FAKE: u8 = 0b0000_0001;
    const MASK_NEDT: u8 = 0b0000_0010; //need triim
    const MASK_KILL: u8 = 0b0000_0100;
    const MASK_RES3: u8 = 0b0000_1000;
    const MASK_RES4: u8 = 0b0001_0000;
    const MASK_RES5: u8 = 0b0010_0000;
    const MASK_RES6: u8 = 0b0100_0000;
    const MASK_RES7: u8 = 0b1000_0000;

    /// Creates a new instance with all bits cleared to `false`.
    pub fn new() -> Self {
        Self { state: 0 }
    }

    /// Initialises the structure from a raw byte.
    pub fn from_byte(byte: u8) -> Self {
        Self { state: byte }
    }

    /// Returns the raw byte representation.
    pub fn to_byte(&self) -> u8 {
        self.state
    }

    // ─── Getters and setters ───

    /// Returns the `is_fake` flag (bit 0).
    pub fn is_fake(&self) -> bool {
        (self.state & Self::MASK_FAKE) != 0
    }

    /// Sets the `is_fake` flag (bit 0).
    pub fn set_is_fake(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_FAKE;
        } else {
            self.state &= !Self::MASK_FAKE;
        }
    }

    /// Returns the `is_kill` flag (bit 1).
    pub fn is_kill(&self) -> bool {
        (self.state & Self::MASK_KILL) != 0
    }

    /// Sets the `is_kill` flag (bit 1).
    pub fn set_is_kill(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_KILL;
        } else {
            self.state &= !Self::MASK_KILL;
        }
    }

    /// Returns the reserved bit 2.
    pub fn need_trim(&self) -> bool {
        (self.state & Self::MASK_NEDT) != 0
    }

    /// Sets the reserved bit 2.
    pub fn set_need_trim_is_pad(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_NEDT;
        } else {
            self.state &= !Self::MASK_NEDT;
        }
    }

    /// Returns the reserved bit 3.
    pub fn reserve_3(&self) -> bool {
        (self.state & Self::MASK_RES3) != 0
    }

    /// Sets the reserved bit 3.
    pub fn set_reserve_3(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_RES3;
        } else {
            self.state &= !Self::MASK_RES3;
        }
    }

    /// Returns the reserved bit 4.
    pub fn reserve_4(&self) -> bool {
        (self.state & Self::MASK_RES4) != 0
    }

    /// Sets the reserved bit 4.
    pub fn set_reserve_4(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_RES4;
        } else {
            self.state &= !Self::MASK_RES4;
        }
    }

    /// Returns the reserved bit 5.
    pub fn reserve_5(&self) -> bool {
        (self.state & Self::MASK_RES5) != 0
    }

    /// Sets the reserved bit 5.
    pub fn set_reserve_5(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_RES5;
        } else {
            self.state &= !Self::MASK_RES5;
        }
    }

    /// Returns the reserved bit 6.
    pub fn reserve_6(&self) -> bool {
        (self.state & Self::MASK_RES6) != 0
    }

    /// Sets the reserved bit 6.
    pub fn set_reserve_6(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_RES6;
        } else {
            self.state &= !Self::MASK_RES6;
        }
    }

    /// Returns the reserved bit 7.
    pub fn reserve_7(&self) -> bool {
        (self.state & Self::MASK_RES7) != 0
    }

    /// Sets the reserved bit 7.
    pub fn set_reserve_7(&mut self, value: bool) {
        if value {
            self.state |= Self::MASK_RES7;
        } else {
            self.state &= !Self::MASK_RES7;
        }
    }
}

///error type
#[derive(Debug, Clone)]

pub enum WTypeErr {
    ///A problem with the length—either an array index out of bounds or a length mismatch
    LenSizeErr(String),
    ///Inconsistency regarding the presence of fields:
    ///in one place it is stated that a field exists, while in another it is stated that it does not.
    CompileFieldsErr(String),
    ///The packet data is corrupted
    PackageDamaged(String),
    ///WorkTimeErr: various types of errors for which there is no solution
    WorkTimeErr(String),
}

#[cfg_attr(test, derive(Debug))]
///
pub enum WisErr<WarT, CritT> {
    ///#### An error that does not lead to irreparable situations and is mitigated by the program's
    ///#### algorithms; the program can continue to operate.
    Warning(WarT),
    ///## Critical Error. The program received data or a condition that cannot be resolved normally.
    ///## Further operation of the module that returned Critical is unsafe and unstable.
    ///## The instance of the crash or the data that resulted in this error must be cleared.
    Critical(CritT),
}

impl<WarT, CritT> WisErr<WarT, CritT> {
    ///
    pub fn is_critical(&self) -> bool {
        match self {
            Self::Critical(_) => true,
            Self::Warning(_) => false,
        }
    }
    ///
    pub fn is_warning(&self) -> bool {
        !self.is_critical()
    }
}
impl<WarT: PartialEq, CritT: PartialEq> PartialEq for WisErr<WarT, CritT> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Warning(x), Self::Warning(y)) => x == y,
            (Self::Critical(x), Self::Critical(y)) => x == y,
            _ => false,
        }
    }
}

impl WTypeErr {
    ///
    pub fn is_len_small_err(&self) -> bool {
        matches!(self, Self::LenSizeErr(_))
    }
    ///
    pub fn is_none_field(&self) -> bool {
        matches!(self, Self::CompileFieldsErr(_))
    }
    ///
    // pub fn is_pascage_damaget(&self) -> bool {
    //     matches!(self, Self::PackageDamaged(_))
    // }
    ///
    //pub fn is_work_time_err(&self) -> bool {
    //    matches!(self, Self::WorkTimeErr(_))
    //}
    ///
    pub fn err_to_str(&self) -> String {
        match self {
            Self::LenSizeErr(x) => x,
            Self::CompileFieldsErr(x) => x,
            Self::PackageDamaged(x) => x,
            Self::WorkTimeErr(x) => x,
        }
        .clone()
    }
}

impl PartialEq for WTypeErr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::LenSizeErr(x), Self::LenSizeErr(y)) => x == y,
            (Self::CompileFieldsErr(x), Self::CompileFieldsErr(y)) => x == y,
            (Self::PackageDamaged(x), Self::PackageDamaged(y)) => x == y,
            (Self::WorkTimeErr(x), Self::WorkTimeErr(y)) => x == y,
            _ => false,
        }
    }
}
///
#[derive(Debug, Clone, PartialEq)]
pub enum MyRole {
    ///
    Initiator,
    ///
    Passive,
}
impl MyRole {
    ///
    pub fn is_initiator(&self) -> bool {
        matches!(self, Self::Initiator)
    }
    ///
    pub fn is_passive(&self) -> bool {
        matches!(self, Self::Passive)
    }
    ///
    pub fn sate_to_bit(&self) -> u8 {
        match self {
            Self::Passive => 0,
            Self::Initiator => 1,
        }
    }
    ///
    pub fn bit_to_state(bit: u8) -> Self {
        match bit & 1 {
            1 => Self::Initiator,
            0 => Self::Passive,
            _ => Self::Initiator,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
///PackType is used when setting the counter bit.
/// It is needed to separate packets into acknowledgement packets and data packets.
pub enum PackType {
    ///packet tick in which the confirmation counters of received packets are transmitted
    Fback,
    ///a packet type that is fake, indistinguishable from Data,
    ///also requires confirmation, but it is filled with garbage,
    ///its head_byte has fake_bit = 1, so the packet data is not used in any way.
    Data,
}
impl PackType {
    ///
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data)
    }
    ///
    pub fn is_fback(&self) -> bool {
        matches!(self, Self::Fback)
    }
    ///
    pub fn sate_to_bit(&self) -> u8 {
        match self {
            Self::Fback => 1,
            Self::Data => 0,
        }
    }
    ///
    pub fn bit_to_state(bit: u8) -> Self {
        match bit & 1 {
            1 => Self::Fback,
            0 => Self::Data,
            _ => Self::Fback,
        }
    }
}

//======================================================================================================

/*type1 fn(&[u8], &mut [u8], &mut [u8],u64, Option<&[u8]>) -> Result<(), String>
where &[u8] is the head, the data that is not encrypted,
the first &mut [u8] is the body, the data that is encrypted
the second &mut [u8] is the place where the authentication tag from head + body should be placed
Option<&[u8]> is a Nonce if is a init in topology: &t2page::PackTopology,

type 2 fn(&mut[u8],usize,usize, u64, Option<&[u8]>) -> Result<(), String>
&mut[u8] is the full mutable packet
the first usize is the index of the start of the body, so [0..(first usize)] is the head
the second usize is the index of the start of tag, so [(first usize)..(second usize)] is the body
the tag field, it is [(second usize)..] is the place for the tag
Option<&[u8]> is a Nonce if is a init in topology: &t2page::PackTopology,

this enum is needed for maximum compatibility with the encryption libraries that are on the rust
they both return -> Result<(), String>
ok() means that the data was encrypted successfully
and there were no errors, &'static str reports some error,
 when it is called, the preparation of the packet for sending
 will be interrupted and it will not be sent

#[derive(Debug, Clone)]
pub enum TypeGetMode {
    /// (HEAD non enc), (PAYLOAD enc), (TAG) (countr(nonce)), (NONCE)
    Type1SplitMutSlices(
        fn(&[u8], &mut [u8], &mut [u8], u64, Option<&[u8]>) -> Result<(), String>,
    ),
    /// (FULLDATA),  (HEAD non enc)[0..usize1],(PAYLOAD
    /// enc)[usize1..usize2],(TAG)[usize2..],(countr(nonce)), (NONCE)[start..end]
    Type2FullArrAndIndexes(
        fn(&mut [u8], usize, usize, u64, Option<(usize, usize)>) -> Result<(), String>,
    ),
}
    */

#[derive(Debug, Clone)]
///
pub enum Cryptlag {
    ///
    Encrypt,
    ///
    Decrypt,
}
#[derive(Debug, Clone, PartialEq)]
///
pub enum StatusDecrypt {
    ///
    PackageDamaged,
    ///
    DecodedCorrectly,
}

impl StatusDecrypt {
    ///
    pub fn is_correctly(&self) -> bool {
        matches!(self, Self::DecodedCorrectly)
    }

    ///
    pub fn is_damaged(&self) -> bool {
        matches!(self, Self::PackageDamaged)
    }
}

//#############################################################3
///

pub trait EncWis: Sized {
    ///
    fn new(key: &[u8]) -> Result<Self, String>;

    /// (HEAD non enc), (PAYLOAD enc), (TAG) (countr(nonce)), (NONCE)
    fn encrypt(
        &self,
        non_enc_head: &[u8],
        enc_payload: &mut [u8],
        auth_tag: &mut [u8],
        nonce_countr: &u64,
        nonce: Option<&[u8]>,
    ) -> Result<(), String>;
    /// (HEAD non enc), (PAYLOAD enc), (TAG) (countr(nonce)), (NONCE)
    fn decrypt(
        &self,
        non_enc_head: &[u8],
        enc_payload: &mut [u8],
        auth_tag: &mut [u8],
        nonce_countr: &u64,
        nonce: Option<&[u8]>,
    ) -> Result<StatusDecrypt, String>;
}
///
pub trait Noncer: Sized {
    ///
    fn new(seed: &[u8]) -> Result<Self, String>;
    ///

    fn set_nonce(&mut self, nonce_gener: &mut [u8]) -> Result<(), String>;
}
///
pub trait Thrasher<FuserLogicBuf>: Sized {
    ///
    fn new(seed: &[u8]) -> Result<Self, String>;
    ///

    fn set_user_field(
        &mut self,
        user_field: &mut [u8],
        counter_of_pack: &u64,
        len_of_pack: &usize,
        counter_field_in_pack: &usize,
        topoligy: &PackTopology,
        user_logic_buffer: Option<&mut FuserLogicBuf>,
    ) -> Result<(), String>;
}
///
pub trait Crcser: Sized {
    ///
    fn new(seed: &[u8]) -> Result<Self, String>;
    ///
    fn gen_crc(&mut self, payload: &[u8], crc_field: &mut [u8]) -> Result<(), String>;
}
///
pub trait Randomer: Sized {
    ///
    fn new(seed: &[u8]) -> Result<Self, String>;
    ///
    fn gen_rand_usize(&mut self) -> usize;
    ///
    fn gen_rand_u32(&mut self) -> u32;
}
///It's too complicated to explain. I hope I don't forget to add this as an example for
/// clarity.
pub trait HandMaker: Sized {
    ///
    fn new(my_role: MyRole, seed: &[u8]) -> Result<Self, String>;
    ///
    fn file_sheme(&self) -> &[AtomHandFile];
    ///
    fn send(&mut self) -> Result<Rcc<Box<[u8]>>, String>;
    ///
    fn recv(&mut self, file: Rcc<Box<[u8]>>) -> Result<(), String>;
    ///
    fn get_private_key(&mut self) -> Result<Box<[u8]>, String>;
}

///It's too complicated to explain. I hope I don't forget to add this as an example for
/// clarity.
pub trait TrickyBMaker<FuserLogicBuf>: Sized {
    ///
    fn new(seed: &[u8], pack_sheme: PackScheme) -> Result<Self, String>;
    ///
    fn get_tricky_byte(
        &self,
        pack_type: PackType,
        ctr: &u64,
        user_logic_buffer: Option<&mut FuserLogicBuf>,
    ) -> u8;
}

///Be sure to use it in production once before configuring your algorithm to verify that
/// HandMaker is working properly.
pub fn hand_maker_tester<Thm: HandMaker + Clone>() -> Result<(), String> {
    for k_len in [0, 17, 80] {
        for gamma in [0, 77, 255] {
            let mut intua = Thm::new(MyRole::Initiator, &vec![gamma; k_len])?;

            let mut passve = Thm::new(MyRole::Passive, &vec![gamma; k_len])?;

            if !intua
                .file_sheme()
                .first()
                .ok_or("ERROR! The file_scheme() array is EMPTY")?
                .is_initiator()
            {
                #[cfg(test)]
                {
                    println!("Initiator:   {:?}", intua.file_sheme());
                }
                return Err(
                    "error in initiator in file_sheme()[0], initiator must always send data first!"
                        .to_string(),
                );
            }
            if !passve
                .file_sheme()
                .first()
                .ok_or("ERROR! The file_scheme() array is EMPTY")?
                .is_initiator()
            {
                #[cfg(test)]
                {
                    println!("Passive:   {:?}", passve.file_sheme());
                }
                return Err(
                    "error in passive in file_sheme()[0], initiator must always send data first!"
                        .to_string(),
                );
            }

            let p_s = passve.file_sheme().to_vec().into_boxed_slice();
            let i_s = intua.file_sheme().to_vec().into_boxed_slice();

            if p_s != i_s {
                #[cfg(test)]
                {
                    println!("Initiator: {:?}", i_s);
                    println!("Passive:   {:?}", p_s);
                }
                return Err(
                    "file_sheme() of the initiator differs from file_sheme() of the passive"
                        .to_string(),
                );
            }

            for cur in p_s {
                #[cfg(test)]
                {
                    println!();
                    println!();
                    println!("len seed: {} , fill seed {} , cur {:?}", k_len, gamma, cur);
                }
                if cur.is_initiator() {
                    let mut temp_passive = passve.clone();
                    //
                    passve.recv(intua.send()?)?;

                    //ivverse test
                    if temp_passive.send().is_ok() {
                        return Err("Passive send() returned the correct value when the \
                                    Initiator send() was in the queue at that moment"
                            .to_string());
                    }
                } else {
                    let mut temp_init = intua.clone();
                    //
                    intua.recv(passve.send()?)?;
                    //inverse test

                    if temp_init.send().is_ok() {
                        return Err("Initiator send() returned the correct value when the \
                                    Passive send() was in the queue at that moment"
                            .to_string());
                    }
                }
            }

            let i_pas = intua.get_private_key()?;
            let p_pas = passve.get_private_key()?;

            if i_pas != p_pas {
                #[cfg(test)]
                {
                    println!("Initiator: {:?}", i_pas);
                    println!("Passive:   {:?}", p_pas);
                }
                return Err("At the end of the exchange of all files, 
                when generating the final private key,
                the initiator and passive keys do not match"
                    .to_string());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests_my_role {
    #![allow(clippy::as_conversions)]
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
    #![allow(clippy::as_conversions)]
    use super::*;

    #[test]
    fn test_is_data() {
        assert!(PackType::Data.is_data());
        assert!(!PackType::Fback.is_data());
    }

    #[test]
    fn test_is_fback() {
        assert!(PackType::Fback.is_fback());
        assert!(!PackType::Data.is_fback());
    }

    #[test]
    fn test_sate_to_bit() {
        assert_eq!(PackType::Fback.sate_to_bit(), 1);
        assert_eq!(PackType::Data.sate_to_bit(), 0);
    }

    #[test]
    fn test_bit_to_state() {
        assert!(matches!(PackType::bit_to_state(0), PackType::Data));
        assert!(matches!(PackType::bit_to_state(1), PackType::Fback));
        // Test with higher bits (only LSB should matter)
        assert!(matches!(PackType::bit_to_state(2), PackType::Data)); // 2 & 1 = 0
        assert!(matches!(PackType::bit_to_state(3), PackType::Fback)); // 3 & 1 = 1
        assert!(matches!(PackType::bit_to_state(255), PackType::Fback)); // 255 & 1 = 1
    }

    #[test]
    fn test_partial_eq() {
        assert_eq!(PackType::Data, PackType::Data);
        assert_eq!(PackType::Fback, PackType::Fback);
        assert_ne!(PackType::Data, PackType::Fback);
        assert_ne!(PackType::Fback, PackType::Data);
    }

    #[test]
    fn test_clone() {
        let data = PackType::Data;
        let cloned = data.clone();
        assert_eq!(data, cloned);

        let fback = PackType::Fback;
        let cloned_fback = fback.clone();
        assert_eq!(fback, cloned_fback);
    }
}

#[cfg(test)]
mod tests_statusdecrypt {
    #![allow(clippy::as_conversions)]
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

/*
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
*/

//_! Implementation of RSA encryption algorithm using only the Rust standard library.
//_! For demonstration purposes only – not secure for real-world use.
//_! Assumes availability of trusted prime numbers (obtained externally).
//_! Uses u64 for all values; intermediate multiplications use u128 to avoid overflow.

/// Structure representing an RSA key pair.
#[cfg(test)]
pub struct RsaTest {
    n: u64, // modulus (product of p and q)
    e: u64, // public exponent (usually 65537)
    d: u64, // private exponent
}
#[cfg(test)]
impl RsaTest {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    /// Creates a new RSA instance from two prime numbers `p` and `q`.
    /// The public exponent `e` is fixed to 65537.
    /// Returns `Err` if the provided primes are invalid (e.g., equal, or (p-1)*(q-1) not
    /// coprime with e).
    pub fn new(p: u64, q: u64) -> Result<Self, String> {
        if p == q {
            return Err("p and q must be different".to_string());
        }
        let n = p * q;
        let phi = (p - 1) * (q - 1); // Euler's totient

        // Commonly used public exponent
        let e = 65537;

        // Ensure e is coprime with phi
        if Self::gcd(phi, e) != 1 {
            return Err("e and φ(n) are not coprime".to_string());
        }

        // Compute private exponent d = e⁻¹ mod φ(n)
        let d = match Self::mod_inv(e, phi) {
            Some(val) => val,
            None => return Err("modular inverse not found".to_string()),
        };

        Ok(Self { n, e, d })
    }

    /// Encrypts a plaintext message `m` (must be less than `n`).
    /// Returns ciphertext.
    pub fn encrypt(e: u64, n: u64, m: u64) -> u64 {
        Self::mod_pow(m, e, n)
    }

    /// Decrypts a ciphertext `c` (must be less than `n`).
    /// Returns plaintext.
    pub fn decrypt(&self, c: u64) -> u64 {
        Self::mod_pow(c, self.d, self.n)
    }
    ///
    pub fn get_e(&self) -> u64 {
        self.e
    }
    ///
    pub fn get_n(&self) -> u64 {
        self.n
    }

    // ---------- helper functions ----------

    /// Modular exponentiation: (base^exp) % modulus using exponentiation by squaring.
    fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
        if modulus == 1 {
            return 0;
        }
        let mut result = 1;
        base %= modulus;
        while exp > 0 {
            if exp % 2 == 1 {
                result = ((result as u128) * (base as u128) % (modulus as u128)) as u64;
            }
            base = ((base as u128) * (base as u128) % (modulus as u128)) as u64;
            exp >>= 1;
        }
        result
    }

    /// Computes the greatest common divisor of two numbers.
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    /// Computes the modular inverse of `a` modulo `m` using the extended Euclidean
    /// algorithm. Returns `Some(inverse)` if exists, else `None`.
    fn mod_inv(a: u64, m: u64) -> Option<u64> {
        let (mut t, mut new_t) = (0i64, 1i64);
        let (mut r, mut new_r) = (m as i64, a as i64);
        while new_r != 0 {
            let quotient = r / new_r;
            (t, new_t) = (new_t, t - quotient * new_t);
            (r, new_r) = (new_r, r - quotient * new_r);
        }
        if r > 1 {
            return None; // not invertible
        }
        if t < 0 {
            t += m as i64;
        }
        Some(t as u64)
    }
}

#[cfg(test)]
mod tests_rsa {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_rsa_encrypt_decrypt() {
        // Two small primes (for demonstration only – use much larger ones in practice)
        let p = 8811653;
        let q = 9539867;
        let rsa = RsaTest::new(p, q).unwrap();
        let eee = rsa.get_e();
        let nnn = rsa.get_n();
        //
        //
        //
        let message = 123456;
        let cipher = RsaTest::encrypt(eee, nnn, message);

        let plain = rsa.decrypt(cipher);
        assert_eq!(message, plain);
    }

    #[test]
    fn test_invalid_primes() {
        assert!(RsaTest::new(61, 61).is_err()); // equal primes
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(RsaTest::mod_pow(4, 13, 497), 445); // known example
    }
}

#[cfg(test)]
mod test_for_hand_maker_tester {
    use super::*;
    use crate::t1dumb_srct::DumpHandMaker;
    #[test]
    fn t1_() {
        assert_eq!(hand_maker_tester::<DumpHandMaker>(), Ok(()));
    }
}

#[cfg(test)]
mod tests_atomic_files {
    use super::*;

    #[test]
    fn test_is_initiator() {
        let init = AtomHandFile::InitiatorFileSize(42);
        let pass = AtomHandFile::PassiveFileSize(100);
        assert!(init.is_initiator());
        assert!(!pass.is_initiator());
    }

    #[test]
    fn test_is_passive() {
        let init = AtomHandFile::InitiatorFileSize(42);
        let pass = AtomHandFile::PassiveFileSize(100);
        assert!(pass.is_passive());
        assert!(!init.is_passive());
    }

    #[test]
    fn test_size() {
        assert_eq!(AtomHandFile::InitiatorFileSize(42).size(), 42);
        assert_eq!(AtomHandFile::PassiveFileSize(100).size(), 100);
    }

    #[test]
    fn test_partial_eq() {
        let a = AtomHandFile::InitiatorFileSize(10);
        let b = AtomHandFile::InitiatorFileSize(10);
        let c = AtomHandFile::InitiatorFileSize(20);
        let d = AtomHandFile::PassiveFileSize(10);

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(c, d);
    }
}

#[cfg(test)]
mod tests_headbytestruct {
    use super::*;

    #[test]
    fn test_combinations() {
        let mut h = HeadByteStruct::new();

        for i in 0..255 {
            h.set_reserve_7(i & (1 << 7) > 0);
            h.set_reserve_6(i & (1 << 6) > 0);
            h.set_reserve_5(i & (1 << 5) > 0);
            h.set_reserve_4(i & (1 << 4) > 0);
            h.set_reserve_3(i & (1 << 3) > 0);
            h.set_is_kill(i & (1 << 2) > 0);
            h.set_need_trim_is_pad(i & (1 << 1) > 0);
            h.set_is_fake(i & (1 << 0) > 0);

            assert_eq!(h.to_byte(), i);

            assert_eq!(h.reserve_7(), (i & (1 << 7) > 0));
            assert_eq!(h.reserve_6(), (i & (1 << 6) > 0));
            assert_eq!(h.reserve_5(), (i & (1 << 5) > 0));
            assert_eq!(h.reserve_4(), (i & (1 << 4) > 0));
            assert_eq!(h.reserve_3(), (i & (1 << 3) > 0));
            assert_eq!(h.is_kill(), (i & (1 << 2) > 0));
            assert_eq!(h.need_trim(), (i & (1 << 1) > 0));
            assert_eq!(h.is_fake(), (i & (1 << 0) > 0));

            assert_eq!(h, HeadByteStruct::from_byte(i))
        }
    }
}
#[cfg(test)]
mod tests_wis_err {
    use super::*;

    #[test]
    fn test_is_critical() {
        let warning: WisErr<&str, i32> = WisErr::Warning("Low disk space");
        let critical: WisErr<&str, i32> = WisErr::Critical(500);

        assert!(!warning.is_critical());
        assert!(critical.is_critical());
    }

    #[test]
    fn test_is_warning() {
        let warning: WisErr<&str, i32> = WisErr::Warning("Low disk space");
        let critical: WisErr<&str, i32> = WisErr::Critical(500);

        assert!(warning.is_warning());
        assert!(!critical.is_warning());
    }

    #[test]
    fn test_partial_eq_same_variants() {
        let warn1: WisErr<&str, i32> = WisErr::Warning("Timeout");
        let warn2: WisErr<&str, i32> = WisErr::Warning("Timeout");
        let warn3: WisErr<&str, i32> = WisErr::Warning("Connection lost");

        let crit1: WisErr<&str, i32> = WisErr::Critical(404);
        let crit2: WisErr<&str, i32> = WisErr::Critical(404);
        let crit3: WisErr<&str, i32> = WisErr::Critical(500);

        assert_eq!(warn1, warn2);
        assert_eq!(crit1, crit2);

        assert_ne!(warn1, warn3);
        assert_ne!(crit1, crit3);
    }

    #[test]
    fn test_partial_eq_different_variants() {
        let warning: WisErr<&str, i32> = WisErr::Warning("Database error");
        let critical: WisErr<&str, i32> = WisErr::Critical(101);
        assert_ne!(warning, critical);
    }
}

#[cfg(test)]
mod test_ttl {
    use super::*;

    #[test]

    fn test_ttl_initialization_and_getters() {
        #![allow(clippy::unwrap_used)]
        let ttl = Ttl::new(64, -2, 128, true);

        assert_eq!(ttl, Err("max <= start".to_string()));

        let ttl = Ttl::new(64, -2, 64, true);
        assert_eq!(ttl, Err("max <= start".to_string()));

        let ttl = Ttl::new(1000, -1, 0, true);
        assert_eq!(ttl, Err("start == 0".to_string()));

        let ttl = Ttl::new(0, -1, 1, true);
        assert_eq!(ttl, Err("max == 0".to_string()));

        let ttl = Ttl::new(65, 0, 64, true);
        assert_eq!(ttl, Err("ttl_edit == 0".to_string()));

        let ttl = Ttl::new(65, -2, 64, true).unwrap();

        assert_eq!(ttl.max(), 65);
        assert_eq!(ttl.edit(), -2);
        assert_eq!(ttl.start(), 64);
        assert!(ttl.forced_pruning());
        //
        let ttl = Ttl::new(65, -2, 64, false).unwrap();
        assert!(!ttl.forced_pruning());
    }
}

#[cfg(test)]
mod test_pack_sheme {

    use super::*;
    use crate::t0pology::*;
    use crate::w1types::PackTypeGroup as PF;

    #[test]
    fn main() {
        #![allow(clippy::unwrap_used)]
        let f1 = [
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::UserField(1),
        ];
        let f2 = [
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::UserField(2),
        ];
        let f3 = [
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::UserField(3),
        ];

        let bx: [(Box<[PackFields]>, PF, u8); 3] = [
            (Box::new(f1.clone()), PF::Any, 1_u8),
            (Box::new(f2), PF::Any, 2_u8),
            (Box::new(f3), PF::Any, 3_u8),
        ];

        let p1 = PackTopology::new(10, &f1, true, false).unwrap();

        let mo = PackScheme::OnePack(p1.clone());

        let mg = PackScheme::GroupPack(GroupTopology::new(&bx, 10, true, false).unwrap());

        assert!(mo.is_one());
        assert!(!mo.is_group());
        assert!(mg.is_group());
        assert!(!mg.is_one());

        for i in 0..10 {
            assert_eq!(*mo.get_topol(i, PF::Any).unwrap(), p1);
        }

        let t1 = mg
            .get_topol(1, PF::Any)
            .unwrap()
            .trash_content_slice()
            .unwrap()
            .first()
            .unwrap()
            .2;

        let t2 = mg
            .get_topol(2, PF::Any)
            .unwrap()
            .trash_content_slice()
            .unwrap()
            .first()
            .unwrap()
            .2;

        let t3 = mg
            .get_topol(3, PF::Any)
            .unwrap()
            .trash_content_slice()
            .unwrap()
            .first()
            .unwrap()
            .2;
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert_eq!(t3, 3);
    }
}
