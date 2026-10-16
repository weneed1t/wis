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
use crate::EXPCP;
#[cfg(test)]
const PRINT_TOPOLOGY_IN_TEST: bool = false;
//using in other files
///
pub const MAXIMAL_CRC_LEN: usize = 32; //maxiaml 512 bits
///
pub const MAXIMAL_TTL_LEN: usize = 8; //8 bytes is u64 max size
///
pub const MAXIMAL_NONCE_LEN: usize = 32; //maxiaml 512 bits
const fn maxval(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

///Did I fucking get this right—that in this fucking programming language for morons,
/// you can’t fucking use `result<>`
/// in constants and have to use `“as”` with `#[allow(clippy::as_conversions)]`???????
/// Are you fucking out of your minds over there?
///There's no real hard limit, but if you need that many user fields,
///  you're probably doing something wrong.
#[allow(clippy::as_conversions)]
pub const MAXIMAL_NUMS_USER_FIELDS: usize = 16 & (u8::MAX as usize);
///
pub const MAX_BUF_SIZE: usize = maxval(MAXIMAL_CRC_LEN, maxval(MAXIMAL_TTL_LEN, MAXIMAL_NONCE_LEN));

#[derive(Debug, Clone)]
/// public packet fields enumeration contains mandatory and optional fields<br>
/// the only mandatory field is the counter, which must always be present and can be 1 to 8<br>
/// bytes in size user id and receiver id, if present, must have the same size — from 0 to<br>
/// 8 bytes (0 means absent, 8 means 64-bit) used in mesh networks where intermediate nodes<br>
/// handle traffic routing length field indicates total packet length including headers and<br>
/// data, used in reliable stream protocols for integrity and ordering counter field is<br>
/// mandatory, 1–8 bytes, holds a unique packet number that increments by one for each new<br>
/// packet if counter size is limited, special mechanisms restore the full counter value on<br>
/// client and server user data field is optional and can be of arbitrary size; absence<br>
/// means zero length used to obscure packet structure and prevent traffic filtering or<br>
/// blocking in networks header crc is optional, up to 32 bytes (256 bits), used to verify<br>
/// integrity of header data in unreliable protocols ttl (time to live) field is 1–8 bytes,<br>
/// used in multi-hop networks to limit packet lifetime and prevent infinite loops<br>
/// nonce field is optional, up to 32 bytes, used for cryptographic operations and secure<br>
/// communication idconnect field is used to associate packets with a specific connection<br>
/// or session all size constants are defined to support maximum required lengths for<br>
/// secure and flexible packet handling<br>
///PackFields
/// # (for developers) IF YOU ADD A NEW FIELD HERE, YOU MUST ADD PROCESSING to pub fn GroupTopology::new()
pub enum PackFields {
    ///id of sender
    IdSender(usize),
    ///id of receiver
    IdReceiver(usize),

    ///id of connect
    IdConnect(usize),

    ///id of connect
    ///len
    Len(usize),
    ///Counter
    Counter(usize),
    ///UserField(trash field)
    UserField(usize),
    ///Head control sum
    HeadCRC(usize),
    ///Time To Live
    TTL(usize),
    ///nonce for encrypt
    Nonce(usize),
    ///Tricky Byte
    TrickyByte,
}

impl PartialEq for PackFields {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::IdSender(_), Self::IdSender(_))
                | (Self::IdReceiver(_), Self::IdReceiver(_))
                | (Self::Len(_), Self::Len(_))
                | (Self::Counter(_), Self::Counter(_))
                | (Self::UserField(_), Self::UserField(_))
                | (Self::HeadCRC(_), Self::HeadCRC(_))
                | (Self::Nonce(_), Self::Nonce(_))
                | (Self::TTL(_), Self::TTL(_))
                | (Self::IdConnect(_), Self::IdConnect(_))
                | (Self::TrickyByte, Self::TrickyByte)
        )
    }
}

type Fld = Option<(usize, usize, usize)>;

#[derive(Debug, Clone, PartialEq)]
///See the description of the `new` method
pub struct PackTopology {
    // _phantom_time:PhantomData<&'a bool>,
    all_fields: Box<[PackFields]>,
    tag_len: usize,
    encrypt_start_pos: usize,
    content_start_pos: usize,
    counter_slice: Fld,        // (pos_start, pos_end, len)
    id_of_sender_slice: Fld,   // (pos_start, pos_end, len)
    id_of_receiver_slice: Fld, // (pos_start, pos_end, len)
    len_slice: Fld,            // (pos_start, pos_end, len)
    trash_content_slices_vec: Option<Box<[(usize, usize, usize)]>>, // (pos_start, pos_end, len)
    crc_slice: Fld,            // (pos_start, pos_end, len)
    nonce_slice: Fld,          // (pos_start, pos_end, len)
    ttl_slice: Fld,            // (pos_start, pos_end, len)
    idconn_slice: Fld,         // (pos_start, pos_end, len)
    tricky_byte: Option<usize>, //(pos)
    total_minimal_len: usize,
    //is_tcp_like: bool,
    //data_save: bool,
}

impl PackTopology {
    /// [packet topology structure defines the layout and metadata of a packet's header
    /// fields  ] [all fields are optional except counter, which is mandatory and must
    /// be present     ] [each field slice is represented as (start_index, end_index,
    /// length) in bytes   ] [tag_len is the length of the authentication tag (e.g.,
    /// from AEAD encryption), located at the end   ] [encrypt_start_pos marks the
    /// beginning of encrypted section INCLUDING header byte] [content_start_pos marks
    /// the start of user payload AFTER header byte] [counter_slice must always be set
    /// — it holds the packet sequence number (1–8 bytes)     ] [id_of_sender_slice
    /// and id_of_receiver_slice, if present, must both exist and have equal length (0–8
    /// bytes)   ] [len_slice is required in tcp-like mode to delimit packet
    /// boundaries in stream protocols    ] [trash_content_slice is unencrypted
    /// optional data used to obfuscate packet structure from DPI systems       ]
    /// [crc_slice is used when data integrity is not guaranteed (e.g., UDP), protects
    /// only the header (up to 32 bytes)    ] [nonce_slice provides cryptographic
    /// nonce for encryption (up to 32 bytes), must be unique per packet    ]
    /// [ttl_slice limits packet lifetime in multi-hop networks (1–8 bytes, max u64)    ]
    /// [idconn_slice identifies a connection or session (1–8 bytes)    ]
    /// [total_minimal_len is the minimum size of the packet: content_start_pos + tag_len
    /// ] [is_tcp_like indicates stream-oriented, reliable transport (requires Len
    /// field)     ] [data_save indicates whether the channel preserves data integrity
    /// (if false, HeadCRC is required)       ] [during construction, fields are
    /// processed in order — their position determines layout in the packet    ]
    /// [duplicate fields are rejected; all length validations are enforced (e.g., max 8
    /// bytes for ids, counters)   ] [the final packet layout is: [header fields][head
    /// byte][encrypted user data][tag]   ] [head byte (1 byte) is fixed and marks
    /// transition to encrypted section, not exposed in public fields    ] [validation
    /// ensures consistent configuration: tcp_mode requires Len, missing data_save
    /// requires CRC, etc.   ] [all possible fields are defined in enum PackFields and
    /// passed via &[PackFields]; order matters   ] [UserField (trash_content_slice) is
    /// non-encrypted and used for traffic mimicry or DPI evasion   ] [the structure
    /// supports flexible configuration for use in various network environments (UDP-like
    /// or TCP-like)   ]
    pub fn new(
        tag_len: usize,
        fields: &[PackFields],
        data_save: bool,
        tcp_mode: bool,
    ) -> Result<Self, String> {
        let mut id_of_sender_slice: Fld = None;
        let mut id_of_receiver_slice: Fld = None;
        let mut len_slice: Fld = None;
        let mut crc_slice: Fld = None;
        let mut nonce_slice: Fld = None;
        let mut counter_slice: Fld = None;
        let mut ttl_slice: Fld = None;
        let mut idconn_slice: Fld = None;
        let mut tricky_byte: Option<usize> = None; //poss
        let mut trash_content_slices_vec = vec![];
        let mut shift: usize = 0_usize;

        for x in fields.iter() {
            shift = shift
                .checked_add(match *x {
                    PackFields::UserField(le) => {
                        if EXPCP!(
                            trash_content_slices_vec.len().checked_add(1),
                            "overwlow err"
                        ) > MAXIMAL_NUMS_USER_FIELDS
                        {
                            return Err("userfield nums > MAXIMAL_NUMS_USER_FIELDS".to_string());
                        }

                        if le == 0 || le > (usize::MAX >> 1) {
                            //done just in case, maximum length limit
                            return Err("userfield value is 0".to_string());
                        }
                        trash_content_slices_vec.push((
                            shift,
                            shift.checked_add(le).ok_or("shift+le overflow")?,
                            le,
                        ));
                        le
                    },

                    PackFields::IdConnect(le) => {
                        if idconn_slice.is_some() {
                            return Err("duplicate idconn".to_string());
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idconn value exceeds 8".to_string());
                        }
                        idconn_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },

                    PackFields::TrickyByte => {
                        if tricky_byte.is_some() {
                            return Err("duplicate tricky_byte".to_string());
                        }

                        tricky_byte = Some(shift);
                        1 //tricky_byte = 1 byte
                    },

                    PackFields::Len(le) => {
                        if len_slice.is_some() {
                            return Err("duplicate len".to_string());
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("len value exceeds 8".to_string());
                        }

                        len_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },
                    PackFields::Counter(le) => {
                        if counter_slice.is_some() {
                            return Err("duplicate counter".to_string());
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("counter value exceeds 8".to_string());
                        }
                        counter_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },
                    PackFields::IdSender(le) => {
                        if id_of_sender_slice.is_some() {
                            return Err("duplicate IdSender".to_string());
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("IdSender value exceeds 8".to_string());
                        }
                        id_of_sender_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },
                    PackFields::IdReceiver(le) => {
                        if id_of_receiver_slice.is_some() {
                            return Err("duplicate idreceiver".to_string());
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idreceiver value exceeds 8".to_string());
                        }
                        id_of_receiver_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },
                    PackFields::HeadCRC(le) => {
                        if crc_slice.is_some() {
                            return Err("duplicate crc".to_string());
                        }

                        if le > MAXIMAL_CRC_LEN || le == 0 {
                            return Err(
                                "crc len is  le > MAXIMAL_CRC_LEN or crc len is 0".to_string()
                            );
                        }

                        crc_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },
                    PackFields::Nonce(le) => {
                        if le == 0 || le > MAXIMAL_NONCE_LEN {
                            return Err("nonce len is 0".to_string());
                        }

                        if nonce_slice.is_some() {
                            return Err("duplicate nonce".to_string());
                        }

                        nonce_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },

                    PackFields::TTL(le) => {
                        if ttl_slice.is_some() {
                            return Err("duplicate ttl".to_string());
                        }
                        if le > MAXIMAL_TTL_LEN || le == 0 {
                            return Err("TTL value exceeds MAXIMAL_TTL_LEN or  == 0".to_string());
                        }

                        ttl_slice =
                            Some((shift, shift.checked_add(le).ok_or("shift+le overflow")?, le));
                        le
                    },
                })
                .ok_or("header size exceeds addressable memory")?;
        }

        if !data_save && tcp_mode {
            return Err(
                "channel cannot be both tcp_mode and have data instability (!data_save == false \
                 && tcp_mode == true)"
                    .to_string(),
            );
        }

        if tag_len == 0 {
            return Err("!!tag_len ==0".to_string());
        }

        if counter_slice.is_none() {
            return Err("the structure must have either a Counter field".to_string());
        }

        if !data_save && (crc_slice.is_none()) {
            return Err(
                "If you do not guarantee that the packet can be broken during \
                 transport(!data_save), you should use HeadCRC(usize)"
                    .to_string(),
            );
        }

        if tcp_mode && (len_slice.is_none()) {
            return Err(
                "If your data channel is like TCP, you should specify the Len(usize) field."
                    .to_string(),
            );
        }

        match (id_of_sender_slice, id_of_receiver_slice) {
            (Some(_), None) | (None, Some(_)) => {
                return Err("sender and receiver IDs must both exist or both be absent".to_string());
            },
            _ => (),
        }

        if let (Some(re), Some(se)) = (id_of_receiver_slice, id_of_sender_slice)
            && re.2 != se.2
        {
            return Err(
                "id_of_receiver_slice and id_of_sender_slice must be the same length".to_string(),
            );
        }

        let content_start_pos = shift
            .checked_add(1)
            .ok_or("total packet size exceeds addressable memory")?; //len is 1 byte of HeadByte

        let topology = Self {
            // _phantom_time: PhantomData,
            all_fields: fields.to_vec().into_boxed_slice(),
            tag_len,
            encrypt_start_pos: shift,
            content_start_pos,
            counter_slice,
            id_of_sender_slice,
            id_of_receiver_slice,
            len_slice,
            trash_content_slices_vec: if trash_content_slices_vec.is_empty() {
                None
            } else {
                Some(trash_content_slices_vec.into_boxed_slice())
            },
            crc_slice,
            nonce_slice,
            ttl_slice,
            idconn_slice,
            tricky_byte,
            total_minimal_len: content_start_pos
                .checked_add(tag_len)
                .ok_or("total packet size exceeds addressable memory")?,
            //is_tcp_like: tcp_mode,
            //data_save,
        };

        #[cfg(test)]
        {
            if PRINT_TOPOLOGY_IN_TEST {
                topology.display_layout_with_separators();
            }
        }

        Ok(topology)
    }
}

impl PackTopology {
    ///len of tag
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// - |nnnnnnnnnnn|eeeeeeeeeeeeeeeeeeeeeeeeeeeeee|eee|
    /// - |head fields|head byte|payload(aka content)|tag|
    /// - "n" non encpypt , "e" encrypt
    pub fn encrypt_start_pos(&self) -> usize {
        self.encrypt_start_pos
    }
    ///content_start_pos (payload)
    pub fn content_start_pos(&self) -> usize {
        self.content_start_pos
    }
    ///tricky_byte position
    pub fn tricky_byte(&self) -> Option<usize> {
        self.tricky_byte
    }
    /// head_byte position
    pub fn head_byte_pos(&self) -> usize {
        self.encrypt_start_pos
    }
    /// (start pos, end pos, len of slise)
    pub fn counter_slice(&self) -> Fld {
        self.counter_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn idconn_slice(&self) -> Fld {
        self.idconn_slice
    }
    ///(start pos, end pos, len of slise)
    pub fn id_of_sender_slice(&self) -> Fld {
        self.id_of_sender_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn ttl_slice(&self) -> Fld {
        self.ttl_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn id_of_receiver_slice(&self) -> Fld {
        self.id_of_receiver_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn len_slice(&self) -> Fld {
        self.len_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn trash_content_slice(&self) -> Option<&Box<[(usize, usize, usize)]>> {
        self.trash_content_slices_vec.as_ref()
    }
    /// (start pos, end pos, len of slise)
    pub fn head_crc_slice(&self) -> Fld {
        self.crc_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn nonce_slice(&self) -> Fld {
        self.nonce_slice
    }
    /// head fields len + 1 byte HEAL ken + tag len
    pub fn overhead_len(&self) -> usize {
        self.total_minimal_len
    }
    /// head fields len
    /// (start pos, end pos, len of slise)
    pub fn total_head_slice(&self) -> (usize, usize, usize) {
        (0, self.encrypt_start_pos, self.encrypt_start_pos)
    }

    //pub fn is_tcp(&self) -> bool {
    //    self.is_tcp_like
    //}
    //pub fn data_save(&self) -> bool {
    //    self.data_save
    //}
}

#[cfg(test)]
impl PackTopology {
    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_edit_ctr(&mut self, ctr: Fld) {
        self.counter_slice = ctr;
    }

    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_total_minimum_len_edit(&mut self, lenn: usize) {
        self.total_minimal_len = lenn;
    }

    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_edit_ttl(&mut self, ttl: Fld) {
        self.ttl_slice = ttl;
    }

    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_edit_crc(&mut self, crc: Fld) {
        self.crc_slice = crc;
    }
    ///It visually demonstrates what the topology with fields looks like in this
    /// structure using println!().  The code is pretty shoddy—it's only meant for
    /// debugging, so I don't recommend using it in production.
    pub fn display_layout_with_separators(&self) {
        let total_len = self.total_minimal_len;

        let st_data = "PAYLOADENC".to_string();
        let mut layout: Vec<String> = vec![
            '-'.to_string();
            total_len
                .checked_add(st_data.len())
                .expect("total_len + st_data overflow")
        ];

        for i in (self.content_start_pos()
            ..self
                .content_start_pos()
                .checked_add(st_data.len())
                .expect("content_start_pos + st_data overflow"))
            .zip(st_data.chars())
        {
            let t = layout.get_mut(i.0).expect("unreal state");
            *t = i.1.to_string();
        }

        // Helper function to fill the layout with field representation
        let mut sf = 0;

        let mut vector_legend = vec![];

        fn fill_field(
            layout: &mut [String],
            start: usize,
            end: usize,
            label: char,
            sf: &mut usize,
        ) {
            let t = layout
                .get_mut(
                    sf.checked_add(start).expect("sf + end overflow")
                        ..sf.checked_add(end).expect("sf + end overflow"),
                )
                .expect("unreal state");
            t.fill(label.to_string());
            let t2 = layout
                .get_mut(
                    sf.checked_add(end.checked_sub(1).expect("-1 end overflow"))
                        .expect("sf  overflow"),
                )
                .expect("unreal_state");
            *t2 += "_";
        }
        {
            // Fill Counter
            if let Some((start, end, lenme)) = self.counter_slice {
                fill_field(&mut layout, start, end, 'C', &mut sf);
                vector_legend.push(format!(" [C - {} bytes] - Counter", lenme));
            }

            // Fill IDCONN
            if let Some((start, end, lenme)) = self.idconn_slice {
                fill_field(&mut layout, start, end, 'I', &mut sf);
                vector_legend.push(format!(" [I - {} bytes] - IDCONN", lenme));
            }

            // Fill IdSender
            if let Some((start, end, lenme)) = self.id_of_sender_slice {
                fill_field(&mut layout, start, end, 'S', &mut sf);
                vector_legend.push(format!(" [S - {} bytes] - IdSender", lenme));
            }

            // Fill IdOfReceiver
            if let Some((start, end, lenme)) = self.id_of_receiver_slice {
                fill_field(&mut layout, start, end, 'R', &mut sf);
                vector_legend.push(format!(" [R - {} bytes] - IdOfReceiver", lenme));
            }

            // Fill Len
            if let Some((start, end, lenme)) = self.len_slice {
                fill_field(&mut layout, start, end, 'L', &mut sf);
                vector_legend.push(format!(" [L - {} bytes] - Len", lenme));
            }

            // Fill TrashContent
            if let Some(usrr) = self.trash_content_slice() {
                for &(start, end, lenme) in usrr.iter() {
                    fill_field(&mut layout, start, end, 'U', &mut sf);
                    vector_legend.push(format!(
                        "  [U - {} bytes] - UserField (TrashContent)",
                        lenme
                    ));
                }
            }

            // Fill CRC
            if let Some((start, end, lenme)) = self.crc_slice {
                fill_field(&mut layout, start, end, '*', &mut sf);
                vector_legend.push(format!(" [* - {} bytes] - CRC", lenme));
            }

            // Fill Nonce
            if let Some((start, end, lenme)) = self.nonce_slice {
                fill_field(&mut layout, start, end, 'N', &mut sf);
                vector_legend.push(format!(" [N - {} bytes] - Nonce", lenme));
            }

            // Fill TTL
            if let Some((start, end, lenme)) = self.ttl_slice {
                fill_field(&mut layout, start, end, 'T', &mut sf);
                vector_legend.push(format!(" [T - {} bytes] - TTL", lenme));
            }

            let t2 = layout.get_mut(self.head_byte_pos()).expect("unreal state");
            *t2 = "@_".to_string();

            // Convert the layout to a string and print it
            println!("|.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-|");
            let layout_str: String = layout.join("");
            println!("Memory Layout:");
            println!("{}", layout_str);

            // Print legend
            println!("Legend:");
            for x in vector_legend {
                println!("{x}");
            }

            println!(" [- {} bytes] - tag", self.tag_len());
            println!(" [@ ...] - Head Byte");
            println!("|.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-|");
        }
    }
}

impl PackTopology {
    /// compare two packet topologies for protocol-level equality.
    ///
    /// this method checks only the fields that affect packet processing:
    /// `tag_len`, `tricky_byte`, and all slice fields (`counter`, `id_of_sender`,
    /// `id_of_receiver`, `len`, `crc`, `nonce`, `ttl`, `idconn`).
    ///
    /// # important invariants
    /// - slice equality is based **only on presence and length**, not on start/end
    ///   positions.
    /// - fields ignored by the comparison: `all_fields`, `encrypt_start_pos`,
    ///   `content_start_pos`, `trash_content_slices_vec`, `total_minimal_len`.
    /// - `tricky_byte` is compared by exact position (or absence).
    ///
    /// # examples
    /// ```
    /// # use wis::t0pology::PackTopology;
    /// # use wis::t0pology::PackFields;
    /// let topo1 = PackTopology::new(16, &[PackFields::Len(4),PackFields::UserField(32),PackFields::Counter(8),PackFields::IdSender(6),PackFields::IdReceiver(6),PackFields::UserField(10),PackFields::HeadCRC(4),PackFields::UserField(1),PackFields::Nonce(8),PackFields::TTL(3),PackFields::UserField(3),PackFields::IdConnect(7)], true, false).unwrap();
    /// let topo2 = PackTopology::new(16, &[PackFields::IdConnect(7),PackFields::Counter(8),PackFields::UserField(100),PackFields::HeadCRC(4),PackFields::IdReceiver(6),PackFields::TTL(3),PackFields::Len(4),PackFields::Nonce(8),PackFields::IdSender(6),], true, false).unwrap();
    /// assert!(topo1.is_proto_equal(&topo2));
    ///
    /// let topo3 = PackTopology::new(32, &[PackFields::Counter(4)], true, false).unwrap();
    /// assert!(!topo1.is_proto_equal(&topo3)); // different tag_len
    /// ```
    pub fn is_proto_equal(&self, t: &Self) -> bool {
        let Self {
            all_fields: _,
            tag_len,
            encrypt_start_pos: _,
            content_start_pos: _,
            counter_slice,
            id_of_sender_slice,
            id_of_receiver_slice,
            len_slice,
            trash_content_slices_vec: _,
            crc_slice,
            nonce_slice,
            ttl_slice,
            idconn_slice,
            tricky_byte,
            total_minimal_len: _,
        } = self;

        self.eq_len_field(idconn_slice, &t.idconn_slice)
            && self.eq_len_field(ttl_slice, &t.ttl_slice)
            && self.eq_len_field(nonce_slice, &t.nonce_slice)
            && self.eq_len_field(crc_slice, &t.crc_slice)
            && self.eq_len_field(len_slice, &t.len_slice)
            && self.eq_len_field(id_of_receiver_slice, &t.id_of_receiver_slice)
            && self.eq_len_field(id_of_sender_slice, &t.id_of_sender_slice)
            && self.eq_len_field(counter_slice, &t.counter_slice)
            //other
            && tricky_byte == &t.tricky_byte
            && tag_len == &t.tag_len
    }

    fn eq_len_field(&self, t1: &Fld, t2: &Fld) -> bool {
        if t1.is_none() && t2.is_none() {
            return true;
        }

        if let (Some(tt1), Some(tt2)) = (*t1, *t2)
            && tt1.2 == tt2.2
        {
            return true;
        }

        false
    }
}
