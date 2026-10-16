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

#[derive(Clone, Debug, PartialEq, Copy)]
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
#[derive(Debug, PartialEq, Clone, Copy)]
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

#[derive(Clone, Debug, PartialEq, Copy)]
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
pub enum AtomHandFile<T: EndCryptStuctor + Clone> {
    ///the file size generated by the session initiator and received by the passive
    /// participant
    InitiatorFileSize(usize),
    ///the file size generated by a passive session participant, and they accept this
    /// file and the session
    PassiveFileSize(usize),
    EndOfHandMake(T),
}

pub trait EndCryptStuctor {
    fn get_symmetric_key_byte_vec(&self) -> Box<[u8]>;
    fn new() -> Self;
    fn set_symmetric_key_byte_vec(&mut self, data: &[u8]) -> Result<(), String>;
}

impl<T: EndCryptStuctor + Clone> AtomHandFile<T> {
    /// Returns `true` if the variant is `InitiatorFileSize`.
    pub fn is_initiator(&self) -> bool {
        matches!(self, Self::InitiatorFileSize(_))
    }

    /// Returns `true` if the variant is `PassiveFileSize`.
    pub fn is_passive(&self) -> bool {
        matches!(self, Self::PassiveFileSize(_))
    }

    /// Returns `true` if the variant is `EndOfHandMake`.
    pub fn is_end(&self) -> bool {
        matches!(self, Self::EndOfHandMake(_))
    }
    /// Returns the inner `usize` value for the size variants.
    ///
    /// # Panics
    /// Panics if called on `EndOfHandMake`, which does not carry a size.
    pub fn size(&self) -> usize {
        match self {
            Self::InitiatorFileSize(s) | Self::PassiveFileSize(s) => *s,
            Self::EndOfHandMake(_) => {
                panic!("AtomHandFile::size() called on EndOfHandMake, which has no size")
            },
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
#[derive(Debug, Clone, PartialEq, Copy)]
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

#[derive(Debug, Clone, PartialEq, Copy)]
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
pub trait HandMaker<T: Clone + EndCryptStuctor>: Sized {
    ///
    fn new(my_role: MyRole, seed: &[u8]) -> Result<Self, String>;
    ///
    fn next(&mut self) -> Option<AtomHandFile<T>>;
    ///
    fn send(&mut self) -> Result<Rcc<Box<[u8]>>, String>;
    ///
    fn recv(&mut self, file: Rcc<Box<[u8]>>) -> Result<(), String>;
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

use std::fmt::Debug;

/// Verifies that a user-provided `HandMaker<T>` implementation correctly
/// implements the handshake protocol.
///
/// This function is meant to be invoked FROM THE USER'S OWN TESTS, not from
/// the library's internal tests: it validates the user's `HandMaker<T>`
/// implementation, not the library itself.
///
/// Contract that every implementation must satisfy:
///   * `next()` is a peek: it returns the current step and does NOT advance
///     state, except for the single terminal step, where it advances once so
///     that the following `next()` returns `None`.
///   * `send()` / `recv()` consume the current step and advance state.
///   * Both sides must return `Some(EndOfHandMake(_))` on exactly the same
///     iteration, and `None` on exactly the same iteration right after.
///   * The first step is always `InitiatorFileSize(_)`.
///   * On an `InitiatorFileSize(_)` step only the initiator may `send()`;
///     on a `PassiveFileSize(_)` step only the passive may `send()`.
///   * The final symmetric keys of both sides must be byte-for-byte equal.
pub fn hand_maker_tester<Thm, T>() -> Result<(), String>
where
    Thm: HandMaker<T> + Clone,
    T: EndCryptStuctor + Clone + Debug,
{
    for k_len in [0usize, 17, 80] {
        for gamma in [0u8, 77, 255] {
            let mut intua = Thm::new(MyRole::Initiator, &vec![gamma; k_len])?;
            let mut passve = Thm::new(MyRole::Passive, &vec![gamma; k_len])?;

            let mut step_index: usize = 0;
            let mut end_seen: usize = 0;
            let mut perma_kill: u32 = 0;
            loop {
                perma_kill = perma_kill
                    .checked_add(1)
                    .ok_or("err perma_kill = perma_kill.checked_add(1")?;
                if perma_kill > 100_000 {
                    panic!(
                        "This error likely means that you forgot to increment the counter when calling a `next`, `send`, or `recv` method on the trait."
                    )
                }

                // ---- 1. peek step: both sides ask "what comes next?" ----
                let i_step = intua.next();
                let p_step = passve.next();

                // ---- 2. termination: both must exhaust simultaneously ----
                if i_step.is_none() && p_step.is_none() {
                    break;
                }
                if i_step.is_none() != p_step.is_none() {
                    #[cfg(test)]
                    {
                        println!("Initiator: {:?}", i_step);
                        println!("Passive:   {:?}", p_step);
                    }
                    return Err("The initiator and the passive disagree on the end of the \
                         handshake: one of them returned None from next(), while the \
                         other returned Some(_). Both must exhaust the sequence at \
                         the same iteration."
                        .to_string());
                }

                // ---- 3. the very first step must be InitiatorFileSize ----
                if step_index == 0 {
                    match (&i_step, &p_step) {
                        (
                            Some(AtomHandFile::InitiatorFileSize(_)),
                            Some(AtomHandFile::InitiatorFileSize(_)),
                        ) => {},
                        _ => {
                            #[cfg(test)]
                            {
                                println!("Initiator: {:?}", i_step);
                                println!("Passive:   {:?}", p_step);
                            }
                            return Err("Error in the first step of the handshake: the \
                                 initiator must always send data first, so the first \
                                 call to next() must return InitiatorFileSize(_) on \
                                 BOTH sides."
                                .to_string());
                        },
                    }
                }

                // ---- 4. dispatch on the current step ----
                match (i_step, p_step) {
                    (
                        Some(AtomHandFile::InitiatorFileSize(_)),
                        Some(AtomHandFile::InitiatorFileSize(_)),
                    ) => {
                        // Initiator sends, passive receives. Inverse check: the
                        // passive must NOT be allowed to send on this step. We
                        // clone the passive BEFORE recv(), so its pointer still
                        // points at the current step, and its send() must fail.
                        let mut temp_passive = passve.clone();
                        passve.recv(intua.send()?)?;
                        if temp_passive.send().is_ok() {
                            return Err("Passive send() returned Ok while the Initiator's \
                                 send() was the one in queue at that moment. On an \
                                 InitiatorFileSize step only the initiator may send."
                                .to_string());
                        }
                    },
                    (
                        Some(AtomHandFile::PassiveFileSize(_)),
                        Some(AtomHandFile::PassiveFileSize(_)),
                    ) => {
                        // Passive sends, initiator receives. Inverse check:
                        // the initiator must NOT be allowed to send on this step.
                        let mut temp_init = intua.clone();
                        intua.recv(passve.send()?)?;
                        if temp_init.send().is_ok() {
                            return Err("Initiator send() returned Ok while the Passive's \
                                 send() was the one in queue at that moment. On a \
                                 PassiveFileSize step only the passive may send."
                                .to_string());
                        }
                    },
                    (
                        Some(AtomHandFile::EndOfHandMake(t_i)),
                        Some(AtomHandFile::EndOfHandMake(t_p)),
                    ) => {
                        // End of handshake: compare the derived symmetric keys.
                        let k_i = t_i.get_symmetric_key_byte_vec();
                        let k_p = t_p.get_symmetric_key_byte_vec();
                        if k_i != k_p {
                            #[cfg(test)]
                            {
                                println!("Initiator: {:?}", k_i);
                                println!("Passive:   {:?}", k_p);
                            }
                            return Err("At the end of the exchange of all files, when \
                                 generating the final symmetric key, the \
                                 initiator's and the passive's keys do not match."
                                .to_string());
                        }
                        //do not remove duplicates!
                        if k_i == T::new().get_symmetric_key_byte_vec()
                            || k_p == T::new().get_symmetric_key_byte_vec()
                        {
                            return Err("The error is that, after initialization, 
                            the result of `.get_symmetric_key_byte_vec()`
                             is identical to that of `T::new().get_symmetric_key_byte_vec()`;
                              this means they are not actually
                               being set during the initialization process!"
                                .to_string());
                        }

                        // The next loop iteration will verify that both sides
                        // now return None from next().
                        end_seen = end_seen
                            .checked_add(1)
                            .ok_or("test err end_seen = end_seen.checked_add(1).ok_or")?;
                    },

                    (_i_step, _p_step) => {
                        #[cfg(test)]
                        {
                            println!("Initiator: {:?}", _i_step);
                            println!("Passive:   {:?}", _p_step);
                        }
                        return Err("The initiator and the passive disagree on the current \
                             step of the handshake. The only legal combinations \
                             are: (InitiatorFileSize, InitiatorFileSize) — \
                             initiator sends, passive receives; (PassiveFileSize, \
                             PassiveFileSize) — passive sends, initiator \
                             receives; (EndOfHandMake, EndOfHandMake) — both \
                             sides finish simultaneously."
                            .to_string());
                    },
                }

                step_index = step_index
                    .checked_add(1)
                    .ok_or("err step_index = step_index.checked_add(1)".to_string())?;
            }

            // The terminal step must have appeared exactly once on each side.
            if end_seen != 1 {
                return Err(format!(
                    "EndOfHandMake(_) must be returned exactly once by each side, but it \
         was observed {} time(s). The sequence must terminate with a single \
         EndOfHandMake(_), followed by None on every subsequent next() call.",
                    end_seen
                ));
            }

            // After the terminal step, every further next() must be None on both sides.
            for _extra_peek in 0..3 {
                let i_extra = intua.next();
                let p_extra = passve.next();
                if i_extra.is_some() || p_extra.is_some() {
                    #[cfg(test)]
                    {
                        println!("extra peek #{}: Initiator: {:?}", _extra_peek, i_extra);
                        println!("extra peek #{}: Passive:   {:?}", _extra_peek, p_extra);
                    }
                    return Err(
                        "After EndOfHandMake(_) every subsequent call to next() must \
             return None on both sides; at least one side returned Some(_)."
                            .to_string(),
                    );
                }
            }
        }
    }

    Ok(())
}
