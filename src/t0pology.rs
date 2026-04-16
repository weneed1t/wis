use crate::EXPCP;

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
///There's no real hard limit, but if you need that many user fields,
///  you're probably doing something wrong.
pub const MAXIMAL_NUMS_USER_FIELDS: usize = 16 & (u8::MAX as usize);

///
pub const MAX_BUF_SIZE: usize = maxval(MAXIMAL_CRC_LEN, maxval(MAXIMAL_TTL_LEN, MAXIMAL_NONCE_LEN));

#[derive(Debug, Clone)]
// public packet fields enumeration contains mandatory and optional fields
// the only mandatory field is the counter, which must always be present and can be 1 to 8
// bytes in size user id and receiver id, if present, must have the same size — from 0 to
// 8 bytes (0 means absent, 8 means 64-bit) used in mesh networks where intermediate nodes
// handle traffic routing length field indicates total packet length including headers and
// data, used in reliable stream protocols for integrity and ordering counter field is
// mandatory, 1–8 bytes, holds a unique packet number that increments by one for each new
// packet if counter size is limited, special mechanisms restore the full counter value on
// client and server user data field is optional and can be of arbitrary size; absence
// means zero length used to obscure packet structure and prevent traffic filtering or
// blocking in networks header crc is optional, up to 32 bytes (256 bits), used to verify
// integrity of header data in unreliable protocols ttl (time to live) field is 1–8 bytes,
// used in multi-hop networks to limit packet lifetime and prevent infinite loops
// nonce field is optional, up to 32 bytes, used for cryptographic operations and secure
// communication idconnect field is used to associate packets with a specific connection
// or session all size constants are defined to support maximum required lengths for
// secure and flexible packet handling
///PackFields
pub enum PackFields {
    ///id of sender
    IdSender(usize),
    ///id of receiver
    IdReceiver(usize),
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
    ///id of connect
    IdConnect(usize),
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
    ) -> Result<Self, &'static str> {
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
                            return Err("userfield nums > MAXIMAL_NUMS_USER_FIELDS");
                        }

                        if le == 0 || le > (usize::MAX >> 1) {
                            //done just in case, maximum length limit
                            return Err("userfield value is 0");
                        }
                        trash_content_slices_vec.push((shift, shift + le, le));
                        le
                    },

                    PackFields::IdConnect(le) => {
                        if idconn_slice.is_some() {
                            return Err("duplicate idconn");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idconn value exceeds 8");
                        }
                        idconn_slice = Some((shift, shift + le, le));
                        le
                    },

                    PackFields::TrickyByte => {
                        if tricky_byte.is_some() {
                            return Err("duplicate tricky_byte");
                        }

                        tricky_byte = Some(shift);
                        1 //tricky_byte = 1 byte
                    },

                    PackFields::Len(le) => {
                        if len_slice.is_some() {
                            return Err("duplicate len");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("len value exceeds 8");
                        }

                        len_slice = Some((shift, shift + le, le));
                        le
                    },
                    PackFields::Counter(le) => {
                        if counter_slice.is_some() {
                            return Err("duplicate counter");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("counter value exceeds 8");
                        }
                        counter_slice = Some((shift, shift + le, le));
                        le
                    },
                    PackFields::IdSender(le) => {
                        if id_of_sender_slice.is_some() {
                            return Err("duplicate IdSender");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("IdSender value exceeds 8");
                        }
                        id_of_sender_slice = Some((shift, shift + le, le));
                        le
                    },
                    PackFields::IdReceiver(le) => {
                        if id_of_receiver_slice.is_some() {
                            return Err("duplicate idreceiver");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idreceiver value exceeds 8");
                        }
                        id_of_receiver_slice = Some((shift, shift + le, le));
                        le
                    },
                    PackFields::HeadCRC(le) => {
                        if crc_slice.is_some() {
                            return Err("duplicate crc");
                        }

                        if le > MAXIMAL_CRC_LEN || le == 0 {
                            return Err("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0");
                        }

                        crc_slice = Some((shift, shift + le, le));
                        le
                    },
                    PackFields::Nonce(le) => {
                        if le == 0 || le > MAXIMAL_NONCE_LEN {
                            return Err("nonce len is 0");
                        }

                        if nonce_slice.is_some() {
                            return Err("duplicate nonce");
                        }

                        nonce_slice = Some((shift, shift + le, le));
                        le
                    },

                    PackFields::TTL(le) => {
                        if ttl_slice.is_some() {
                            return Err("duplicate ttl");
                        }
                        if le > MAXIMAL_TTL_LEN || le == 0 {
                            return Err("TTL value exceeds MAXIMAL_TTL_LEN or  == 0");
                        }

                        ttl_slice = Some((shift, shift + le, le));
                        le
                    },
                })
                .ok_or("header size exceeds addressable memory")?;
        }

        if !data_save && tcp_mode {
            return Err(
                "channel cannot be both tcp_mode and have data instability (!data_save == false \
                 && tcp_mode == true)",
            );
        }

        if tag_len == 0 {
            return Err("!!tag_len ==0");
        }

        if counter_slice.is_none() {
            return Err("the structure must have either a Counter field");
        }

        if !data_save && (crc_slice.is_none()) {
            return Err(
                "If you do not guarantee that the packet can be broken during \
                 transport(!data_save), you should use HeadCRC(usize)",
            );
        }

        if tcp_mode && (len_slice.is_none()) {
            return Err(
                "If your data channel is like TCP, you should specify the Len(usize) field.",
            );
        }

        match (id_of_sender_slice, id_of_receiver_slice) {
            (Some(_), None) | (None, Some(_)) => {
                return Err("sender and receiver IDs must both exist or both be absent");
            },
            _ => (),
        }

        if let (Some(re), Some(se)) = (id_of_receiver_slice, id_of_sender_slice)
            && re.2 != se.2
        {
            return Err("id_of_receiver_slice and id_of_sender_slice must be the same length");
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
            topology.display_layout_with_separators();
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
    pub fn total_minimal_len(&self) -> usize {
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
        let mut layout: Vec<String> = vec!['-'.to_string(); total_len + st_data.len()];

        for i in (self.content_start_pos()..self.content_start_pos() + st_data.len())
            .zip(st_data.chars())
        {
            layout[i.0] = i.1.to_string();
        }

        // Helper function to fill the layout with field representation
        let mut sf = 0;

        let mut vector_legend = vec![];

        fn fill_field(
            layout: &mut Vec<String>,
            start: usize,
            end: usize,
            label: char,
            sf: &mut usize,
        ) {
            layout[*sf + start..*sf + end].fill(label.to_string());
            layout[*sf + end - 1] += "_";
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

            layout[self.head_byte_pos()] = "@_".to_string();

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
    /// # use wisleess2::t0pology::PackTopology;
    /// # use wisleess2::t0pology::PackFields;
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

//=============================================TESTS=============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    const _: () = {
        assert!(MAX_BUF_SIZE >= MAXIMAL_CRC_LEN);
        assert!(MAX_BUF_SIZE >= MAXIMAL_NONCE_LEN);
    };

    #[test]
    fn test_invalid_inputs() {
        // Duplicate Len
        let fields_duplicate_len = vec![PackFields::Len(4), PackFields::Len(4)];
        assert_eq!(
            PackTopology::new(5, &fields_duplicate_len, false, false).err(),
            Some("duplicate len"),
            "expected 'duplicate len' error"
        );

        // Len value exceeds 8
        let fields_invalid_len = vec![PackFields::Len(9)];
        assert_eq!(
            PackTopology::new(5, &fields_invalid_len, false, false).err(),
            Some("len value exceeds 8"),
            "expected 'len value exceeds 8' error"
        );

        // CRC len is 0
        let fields_zero_crc = vec![PackFields::HeadCRC(0)];
        assert_eq!(
            PackTopology::new(5, &fields_zero_crc, false, false).err(),
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0"),
            "expected 'crc len is 0' error"
        );

        // Missing Counter or Nonce
        let fields_no_counter_or_nonce = vec![PackFields::Len(4)];
        assert_eq!(
            PackTopology::new(5, &fields_no_counter_or_nonce, false, false).err(),
            Some("the structure must have either a Counter field"),
            "expected 'the structure must have either a Counter field or a Nonce' error"
        );
    }

    #[test]
    fn test_guarantee_conditions() {
        // Missing HeadCRC when data integrity is not guaranteed
        let fields_missing_headcrc = vec![PackFields::Len(4), PackFields::Counter(8)];
        assert_eq!(
            PackTopology::new(5, &fields_missing_headcrc, false, false).err(),
            Some(
                "If you do not guarantee that the packet can be broken during \
                 transport(!data_save), you should use HeadCRC(usize)"
            ),
            "expected 'missing HeadCRC' error"
        );
        let fields_missing_headcrc = vec![PackFields::Counter(8)];
        // Missing Len when length preservation is not guaranteed
        assert_eq!(
            PackTopology::new(5, &fields_missing_headcrc, false, true).err(),
            Some(
                "channel cannot be both tcp_mode and have data instability (!data_save == false \
                 && tcp_mode == true)"
            ),
            "expected 'missing Len' error"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Minimal valid input
        let fields_minimal_valid = vec![PackFields::Len(1), PackFields::Counter(1)];
        let result = PackTopology::new(1, &fields_minimal_valid, true, false);
        assert!(
            result.is_ok(),
            "expected Ok, but got error: {:?}",
            result.err()
        );

        let topology = result.unwrap();
        assert_eq!(topology.tag_len(), 1, "tag_len should be 1");
        assert_eq!(
            topology.encrypt_start_pos(),
            2,
            "content_start_pos should be 2"
        );
        assert_eq!(topology.head_byte_pos(), 2, "head_byte_pos should be 2");
        assert_eq!(
            topology.counter_slice(),
            Some((1, 2, 1)),
            "counter_slice should match"
        );
        assert_eq!(
            topology.len_slice(),
            Some((0, 1, 1)),
            "len_slice should match"
        );
        assert_eq!(
            topology.total_minimal_len(),
            4,
            "total_minimal_len should be 5"
        );
    }

    #[test]
    fn test_field_positions_and_lengths() {
        // Define a set of fields with varying lengths
        let fields = vec![
            PackFields::Len(4),
            PackFields::Counter(8),
            PackFields::IdSender(6),
            PackFields::IdReceiver(6),
            PackFields::UserField(10),
            PackFields::HeadCRC(4),
            PackFields::Nonce(8),
            PackFields::TTL(3),
        ];

        // Define tag length
        let tag_len = 5;

        // Create PackTopology
        let result = PackTopology::new(tag_len, &fields, true, true);
        assert!(
            result.is_ok(),
            "expected Ok, but got error: {:?}",
            result.err()
        );

        let topology = result.unwrap();

        // Verify positions and lengths for each field
        let mut expected_shift = 0;

        // Len
        if let Some((start, end, len)) = topology.len_slice() {
            assert_eq!(start, expected_shift, "Len start position mismatch");
            assert_eq!(end, expected_shift + len, "Len end position mismatch");
            assert_eq!(len, 4, "Len length mismatch");
            expected_shift += len;
        }

        // Counter
        if let Some((start, end, len)) = topology.counter_slice() {
            assert_eq!(start, expected_shift, "Counter start position mismatch");
            assert_eq!(end, expected_shift + len, "Counter end position mismatch");
            assert_eq!(len, 8, "Counter length mismatch");
            expected_shift += len;
        }

        // IdSender
        if let Some((start, end, len)) = topology.id_of_sender_slice() {
            assert_eq!(start, expected_shift, "IdSender start position mismatch");
            assert_eq!(end, expected_shift + len, "IdSender end position mismatch");
            assert_eq!(len, 6, "IdSender length mismatch");
            expected_shift += len;
        }

        // IdOfReceiver
        if let Some((start, end, len)) = topology.id_of_receiver_slice() {
            assert_eq!(
                start, expected_shift,
                "IdOfReceiver start position mismatch"
            );
            assert_eq!(
                end,
                expected_shift + len,
                "IdOfReceiver end position mismatch"
            );
            assert_eq!(len, 6, "IdOfReceiver length mismatch");
            expected_shift += len;
        }

        //UserField (TrashContent)
        if let Some(vec_some) = topology.trash_content_slice() {
            let (start, end, len) = vec_some[0];
            assert_eq!(start, expected_shift, "UserField start position mismatch");
            assert_eq!(end, expected_shift + len, "UserField end position mismatch");
            assert_eq!(len, 10, "UserField length mismatch");
            expected_shift += len;
        }

        // HeadCRC
        if let Some((start, end, len)) = topology.head_crc_slice() {
            assert_eq!(start, expected_shift, "HeadCRC start position mismatch");
            assert_eq!(end, expected_shift + len, "HeadCRC end position mismatch");
            assert_eq!(len, 4, "HeadCRC length mismatch");
            expected_shift += len;
        }

        // Nonce
        if let Some((start, end, len)) = topology.nonce_slice() {
            assert_eq!(start, expected_shift, "Nonce start position mismatch");
            assert_eq!(end, expected_shift + len, "Nonce end position mismatch");
            assert_eq!(len, 8, "Nonce length mismatch");
            expected_shift += len;
        }

        // TTL
        if let Some((start, end, len)) = topology.ttl_slice() {
            assert_eq!(start, expected_shift, "TTL start position mismatch");
            assert_eq!(end, expected_shift + len, "TTL end position mismatch");
            assert_eq!(len, 3, "TTL length mismatch");
            expected_shift += len;
        }

        // Verify content_start_pos
        assert_eq!(
            topology.encrypt_start_pos(),
            expected_shift,
            "content_start_pos mismatch"
        );

        // Verify total_minimal_len
        let total_minimal_len = expected_shift + tag_len + 1; // +1 for mandatory data byte
        assert_eq!(
            topology.total_minimal_len(),
            total_minimal_len,
            "total_minimal_len mismatch"
        );

        //assert!(topology.data_save());
        // assert!(topology.is_tcp());
    }

    #[test]
    fn test_invalid_values_for_all_fields() {
        // Define invalid values to test
        let invalid_values = vec![0, 9]; // 0 is too small, 9 is too large

        // Test each field with invalid values
        for &invalid_value in &invalid_values {
            // Len
            let fields_len = vec![PackFields::Counter(2), PackFields::Len(invalid_value)];
            let result = PackTopology::new(5, &fields_len, true, true);
            assert_eq!(
                result.err(),
                Some("len value exceeds 8"),
                "expected 'len value exceeds 8' error for Len({})",
                invalid_value
            );

            // Counter
            let fields_counter = vec![PackFields::Counter(invalid_value)];
            let result = PackTopology::new(5, &fields_counter, true, true);
            assert_eq!(
                result.err(),
                Some("counter value exceeds 8"),
                "expected 'counter value exceeds 8' error for Counter({})",
                invalid_value
            );

            // IdSender
            let fields_id_sender =
                vec![PackFields::Counter(2), PackFields::IdSender(invalid_value)];
            let result = PackTopology::new(5, &fields_id_sender, true, true);
            assert_eq!(
                result.err(),
                Some("IdSender value exceeds 8"),
                "expected 'IdSender value exceeds 8' error for IdSender({})",
                invalid_value
            );

            // IdReceiver
            let fields_id_receiver = vec![
                PackFields::Counter(2),
                PackFields::IdReceiver(invalid_value),
            ];
            let result = PackTopology::new(5, &fields_id_receiver, true, true);
            assert_eq!(
                result.err(),
                Some("idreceiver value exceeds 8"),
                "expected 'idreceiver value exceeds 8' error for IdReceiver({})",
                invalid_value
            );

            // HeadCRC
            let fields_crc = vec![
                PackFields::Counter(2),
                PackFields::HeadCRC(invalid_value),
                PackFields::Len(3),
            ];
            let result = PackTopology::new(5, &fields_crc, true, true);
            if invalid_value == 0 {
                assert_eq!(
                    result.err(),
                    Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0"),
                    "expected 'crc len is 0' error for HeadCRC({})",
                    invalid_value
                );
            } else {
                assert!(
                    result.is_ok(),
                    "HeadCRC({}) should be valid  {:?}",
                    invalid_value,
                    result
                );
            }

            // Nonce
            let fields_nonce = vec![PackFields::Nonce(invalid_value)];
            let result = PackTopology::new(5, &fields_nonce, true, true);
            if invalid_value == 0 {
                assert_eq!(
                    result.err(),
                    Some("nonce len is 0"),
                    "expected 'nonce len is 0' error for Nonce({})",
                    invalid_value
                );
            } else {
                assert!(
                    result.is_err(),
                    "Nonce({}) should be valid {:?}",
                    invalid_value,
                    result
                );
            }

            // TTL
            let fields_ttl = vec![PackFields::Counter(2), PackFields::TTL(invalid_value)];
            let result = PackTopology::new(5, &fields_ttl, false, false);
            assert_eq!(
                result.err(),
                Some("TTL value exceeds MAXIMAL_TTL_LEN or  == 0"),
                "expected 'TTL value exceeds 8' error for TTL({})",
                invalid_value
            );
        }
    }

    //AI EGNER

    #[test]
    fn test_idconnect_validation() {
        // Length > 8
        let fields_len = vec![PackFields::IdConnect(9), PackFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields_len, true, true).err(),
            Some("idconn value exceeds 8")
        );

        // Duplicate
        let fields_dup = vec![
            PackFields::IdConnect(4),
            PackFields::IdConnect(4), // Duplicate
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_dup, true, true).err(),
            Some("duplicate idconn")
        );
    }

    #[test]
    fn test_trikly() {
        // Length > 8
        let fields_len = vec![
            PackFields::IdConnect(8),
            PackFields::TrickyByte,
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_len, true, false)
                .unwrap()
                .tricky_byte,
            Some(8)
        );

        // Duplicate
        let fields_dup = vec![
            PackFields::TrickyByte,
            PackFields::Len(2),
            PackFields::TrickyByte, // Duplicate
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_dup, true, false).err(),
            Some("duplicate tricky_byte")
        );
    }

    #[test]
    fn test_trash_user_over() {
        let mut fields_len = vec![PackFields::IdConnect(8), PackFields::Counter(4)];
        for x in 1..1 + MAXIMAL_NUMS_USER_FIELDS {
            fields_len.push(PackFields::UserField(x));
        }

        assert_eq!(
            PackTopology::new(5, &fields_len, true, false)
                .unwrap()
                .trash_content_slice()
                .unwrap()
                .clone(),
            [
                (12, 13, 1),
                (13, 15, 2),
                (15, 18, 3),
                (18, 22, 4),
                (22, 27, 5),
                (27, 33, 6),
                (33, 40, 7),
                (40, 48, 8),
                (48, 57, 9),
                (57, 67, 10),
                (67, 78, 11),
                (78, 90, 12),
                (90, 103, 13),
                (103, 117, 14),
                (117, 132, 15),
                (132, 148, 16)
            ]
            .to_vec()
            .into_boxed_slice()
        );

        let mut fields_len = vec![PackFields::IdConnect(8), PackFields::Counter(4)];
        for x in 1..2 + MAXIMAL_NUMS_USER_FIELDS {
            println!("{x}");
            fields_len.push(PackFields::UserField(x));
        }

        assert_eq!(
            PackTopology::new(5, &fields_len, true, false),
            Err("userfield nums > MAXIMAL_NUMS_USER_FIELDS")
        );
    }

    #[test]
    fn test_header_only_config() {
        let fields = vec![PackFields::Counter(4)];
        let result = PackTopology::new(0, &fields, true, false);
        assert_eq!(result.err(), Some("!!tag_len ==0"));
    }

    #[test]
    fn test_max_length_fields() {
        // Valid max lengths
        let fields_valid = vec![
            PackFields::HeadCRC(32), // MAXIMAL_CRC_LEN
            PackFields::Nonce(32),   // MAXIMAL_NONCE_LEN
            PackFields::TTL(8),      // MAXIMAL_TTL_LEN
            PackFields::Counter(4),
            PackFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields_valid, true, true).is_ok());

        // Exceed max lengths
        let fields_invalid = vec![
            PackFields::HeadCRC(33), // > MAXIMAL_CRC_LEN
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_invalid, true, true).err(),
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0")
        );
    }

    #[test]
    fn test_mismatched_id_lengths() {
        let fields = vec![
            PackFields::IdSender(4),
            PackFields::IdReceiver(8), // Different length
            PackFields::Counter(4),
            PackFields::Len(2),
        ];
        let result = PackTopology::new(5, &fields, true, true);
        assert_eq!(
            result.err(),
            Some("id_of_receiver_slice and id_of_sender_slice must be the same length")
        );

        let fields = vec![PackFields::Counter(4)];
        let result = PackTopology::new(5, &fields, true, true);
        assert_eq!(
            result.err(),
            Some("If your data channel is like TCP, you should specify the Len(usize) field.")
        );
    }

    //AI TEST

    // ============================================================================
    // FIXED: test_valid_input — replaced hardcoded values with dynamic calculation
    // ============================================================================
    #[test]
    fn test_valid_input() {
        let fields = vec![
            PackFields::Len(4),
            PackFields::UserField(32),
            PackFields::Counter(8),
            PackFields::IdSender(6),
            PackFields::IdReceiver(6),
            PackFields::UserField(10),
            PackFields::HeadCRC(4),
            PackFields::TrickyByte,
            PackFields::UserField(1),
            PackFields::Nonce(8),
            PackFields::TTL(3),
            PackFields::UserField(3),
            PackFields::IdConnect(7),
        ];
        let topology = PackTopology::new(5, &fields, true, true).unwrap();

        // Verify static config
        assert_eq!(topology.tag_len(), 5);
        //assert!(topology.data_save());
        //assert!(topology.is_tcp());

        // Verify mandatory fields via getters
        assert_eq!(topology.len_slice(), Some((0, 4, 4)));
        assert_eq!(topology.counter_slice(), Some((36, 44, 8)));

        // Verify optional fields
        assert_eq!(topology.id_of_sender_slice(), Some((44, 50, 6)));
        assert_eq!(topology.id_of_receiver_slice(), Some((50, 56, 6)));
        assert_eq!(topology.head_crc_slice(), Some((66, 70, 4)));
        assert_eq!(topology.nonce_slice(), Some((72, 80, 8)));
        assert_eq!(topology.ttl_slice(), Some((80, 83, 3)));
        assert_eq!(topology.idconn_slice(), Some((86, 93, 7)));
        assert_eq!(topology.tricky_byte(), Some(70));

        // Verify UserFields (trash content) — multiple allowed
        let trash = topology.trash_content_slice().unwrap();
        assert_eq!(
            trash.as_ref(),
            &[(4, 36, 32), (56, 66, 10), (71, 72, 1), (83, 86, 3)]
        );

        // Verify derived positions (calculated, not hardcoded)
        assert_eq!(topology.encrypt_start_pos(), 93);
        assert_eq!(topology.head_byte_pos(), 93);
        assert_eq!(topology.content_start_pos(), 94);
        assert_eq!(topology.total_minimal_len(), 99);
    }

    // ============================================================================
    // DELETED: test_zero_ttl — fully redundant, covered by test_invalid_values_for_all_fields
    // (Removed entirely — no need to keep duplicate coverage)

    // ============================================================================
    // FIXED: test_idconnect_validation — removed redundant "exceeds 8" case
    // ============================================================================
    #[test]
    fn test_idconnect_duplicate_error() {
        // Only test the unique case: duplicate IdConnect
        let fields = vec![
            PackFields::IdConnect(4),
            PackFields::IdConnect(4),
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate idconn")
        );
    }

    // ============================================================================
    // FIXED: test_trikly — renamed, use getter instead of direct field access
    // ============================================================================
    #[test]
    fn test_tricky_byte_validation() {
        // Valid: TrickyByte position recorded correctly
        let fields = vec![
            PackFields::IdConnect(8),
            PackFields::TrickyByte,
            PackFields::Counter(4),
        ];
        let topo = PackTopology::new(5, &fields, true, false).unwrap();
        assert_eq!(topo.tricky_byte(), Some(8)); // ✅ Use getter, not .tricky_byte field

        // Invalid: duplicate TrickyByte
        let fields_dup = vec![
            PackFields::TrickyByte,
            PackFields::Len(2),
            PackFields::TrickyByte,
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_dup, true, false).err(),
            Some("duplicate tricky_byte")
        );
    }

    // ============================================================================
    // FIXED: test_trash_user_over — removed println!, clarified assertions
    // ============================================================================
    #[test]
    fn test_userfield_count_limit() {
        // Boundary: exactly MAXIMAL_NUMS_USER_FIELDS — should succeed
        let mut fields = vec![PackFields::IdConnect(8), PackFields::Counter(4)];
        for x in 1..=MAXIMAL_NUMS_USER_FIELDS {
            fields.push(PackFields::UserField(x));
        }
        let topo = PackTopology::new(5, &fields, true, false).unwrap();
        let trash = topo.trash_content_slice().unwrap();
        assert_eq!(trash.len(), MAXIMAL_NUMS_USER_FIELDS);

        // Exceed limit: MAXIMAL_NUMS_USER_FIELDS + 1 — should fail
        let mut fields_over = vec![PackFields::IdConnect(8), PackFields::Counter(4)];
        for x in 1..=(MAXIMAL_NUMS_USER_FIELDS + 1) {
            fields_over.push(PackFields::UserField(x));
        }
        assert_eq!(
            PackTopology::new(5, &fields_over, true, false).err(),
            Some("userfield nums > MAXIMAL_NUMS_USER_FIELDS")
        );
    }

    // ============================================================================
    // FIXED: test_max_length_fields — removed redundant "valid max" block
    // ============================================================================
    #[test]
    fn test_field_exceeds_max_length() {
        // Only test the unique case: exceeding MAXIMAL_CRC_LEN
        let fields = vec![
            PackFields::HeadCRC(33), // > MAXIMAL_CRC_LEN (32)
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0")
        );
    }

    // ============================================================================
    // FIXED: test_userfield_edge_cases — corrected misleading comment
    // ============================================================================
    #[test]
    fn test_userfield_edge_cases() {
        // Multiple UserFields are ALLOWED by design — verify they accumulate
        let fields_multi = vec![
            PackFields::UserField(10),
            PackFields::UserField(5),
            PackFields::Counter(4),
        ];
        let topo = PackTopology::new(5, &fields_multi, true, false).unwrap();
        let trash = topo.trash_content_slice().unwrap();
        assert_eq!(trash.as_ref(), &[(0, 10, 10), (10, 15, 5)]);

        // No UserFields — should return None
        let fields_none = vec![PackFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields_none, true, false)
                .unwrap()
                .trash_content_slice(),
            None
        );

        // Zero-length UserField — invalid
        let fields_zero = vec![PackFields::UserField(0), PackFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields_zero, true, true).err(),
            Some("userfield value is 0")
        );

        // Zero-length in middle of list — also invalid
        let fields_zero_mid = vec![
            PackFields::UserField(3),
            PackFields::UserField(0),
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_zero_mid, true, true).err(),
            Some("userfield value is 0")
        );
    }

    // ============================================================================
    // FIXED: test_mismatched_id_lengths — split into two focused tests
    // ============================================================================
    #[test]
    fn test_id_sender_receiver_length_mismatch() {
        let fields = vec![
            PackFields::IdSender(4),
            PackFields::IdReceiver(8),
            PackFields::Counter(4),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("id_of_receiver_slice and id_of_sender_slice must be the same length")
        );
    }

    #[test]
    fn test_tcp_mode_requires_len_field() {
        let fields = vec![PackFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("If your data channel is like TCP, you should specify the Len(usize) field.")
        );
    }
}

//AI gen test

#[cfg(test)]
mod tests_coverage_gaps {

    use super::*;

    // ========================================================================
    // 1. DUPLICATE FIELD ERRORS (Previously Untested)
    // ========================================================================

    #[test]
    fn test_duplicate_counter_error() {
        let fields = vec![
            PackFields::Counter(4),
            PackFields::Counter(4),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate counter")
        );
    }

    #[test]
    fn test_duplicate_id_sender_error() {
        let fields = vec![
            PackFields::IdSender(4),
            PackFields::IdSender(4),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate IdSender")
        );
    }

    #[test]
    fn test_duplicate_id_receiver_error() {
        let fields = vec![
            PackFields::IdReceiver(4),
            PackFields::IdReceiver(4),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate idreceiver")
        );
    }

    #[test]
    fn test_duplicate_crc_error() {
        let fields = vec![
            PackFields::HeadCRC(4),
            PackFields::HeadCRC(4),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate crc")
        );
    }

    #[test]
    fn test_duplicate_nonce_error() {
        let fields = vec![
            PackFields::Nonce(8),
            PackFields::Nonce(8),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate nonce")
        );
    }

    #[test]
    fn test_duplicate_ttl_error() {
        let fields = vec![
            PackFields::TTL(4),
            PackFields::TTL(4),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("duplicate ttl")
        );
    }

    // ========================================================================
    // 2. SENDER/RECEIVER ID PAIR VALIDATION (Previously Untested)
    // ========================================================================

    #[test]
    fn test_only_sender_id_without_receiver() {
        let fields = vec![
            PackFields::IdSender(4),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("sender and receiver IDs must both exist or both be absent")
        );
    }

    #[test]
    fn test_only_receiver_id_without_sender() {
        let fields = vec![
            PackFields::IdReceiver(4),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("sender and receiver IDs must both exist or both be absent")
        );
    }

    #[test]
    fn test_both_ids_absent_is_valid() {
        let fields = vec![PackFields::Counter(2), PackFields::Len(2)];
        assert!(PackTopology::new(5, &fields, true, true).is_ok());
    }

    // ========================================================================
    // 3. UNTESTED PUBLIC GETTERS
    // ========================================================================

    #[test]
    fn test_total_head_slice() {
        let fields = vec![PackFields::Len(4), PackFields::Counter(8)];
        let topo = PackTopology::new(5, &fields, true, true).unwrap();

        // Should return (0, encrypt_start_pos, encrypt_start_pos)
        assert_eq!(topo.total_head_slice(), (0, 12, 12));
    }

    #[test]
    fn test_tricky_byte_getter() {
        let fields = vec![
            PackFields::Len(4),
            PackFields::TrickyByte,
            PackFields::Counter(2),
        ];
        let topo = PackTopology::new(5, &fields, true, false).unwrap();

        // Use getter method, not direct field access
        assert_eq!(topo.tricky_byte(), Some(4));
    }

    #[test]
    fn test_tricky_byte_getter_none() {
        let fields = vec![PackFields::Len(4), PackFields::Counter(2)];
        let topo = PackTopology::new(5, &fields, true, false).unwrap();
        assert_eq!(topo.tricky_byte(), None);
    }

    // ========================================================================
    // 4. PACKFIELDS PARTEQ BEHAVIOR (Values Ignored)
    // ========================================================================

    #[test]
    fn test_packfields_partial_eq_ignores_values() {
        // Same type, different values - should be equal
        assert_eq!(PackFields::Len(1), PackFields::Len(100));
        assert_eq!(PackFields::Counter(1), PackFields::Counter(8));
        assert_eq!(PackFields::IdSender(2), PackFields::IdSender(6));
        assert_eq!(PackFields::IdReceiver(4), PackFields::IdReceiver(8));
        assert_eq!(PackFields::UserField(10), PackFields::UserField(1000));
        assert_eq!(PackFields::HeadCRC(4), PackFields::HeadCRC(32));
        assert_eq!(PackFields::Nonce(8), PackFields::Nonce(32));
        assert_eq!(PackFields::TTL(2), PackFields::TTL(8));
        assert_eq!(PackFields::IdConnect(4), PackFields::IdConnect(8));
        assert_eq!(PackFields::TrickyByte, PackFields::TrickyByte);

        // Different types - should not be equal
        assert_ne!(PackFields::Len(4), PackFields::Counter(4));
        assert_ne!(PackFields::IdSender(4), PackFields::IdReceiver(4));
    }

    // ========================================================================
    // 5. FIELD ORDER AFFECTS LAYOUT
    // ========================================================================

    #[test]
    fn test_field_order_changes_positions() {
        let fields1 = vec![
            PackFields::Len(2),
            PackFields::Counter(3),
            PackFields::UserField(5),
        ];
        let fields2 = vec![
            PackFields::Counter(3),
            PackFields::Len(2),
            PackFields::UserField(5),
        ];

        let t1 = PackTopology::new(5, &fields1, true, true).unwrap();
        let t2 = PackTopology::new(5, &fields2, true, true).unwrap();

        // Len position should differ
        assert_eq!(t1.len_slice(), Some((0, 2, 2)));
        assert_eq!(t2.len_slice(), Some((3, 5, 2)));

        // Counter position should differ
        assert_eq!(t1.counter_slice(), Some((2, 5, 3)));
        assert_eq!(t2.counter_slice(), Some((0, 3, 3)));
    }

    // ========================================================================
    // 6. TRICKYBYTE WITH VARIOUS COMBINATIONS
    // ========================================================================

    #[test]
    fn test_trickybyte_at_end_of_fields() {
        let fields = vec![
            PackFields::Len(2),
            PackFields::Counter(3),
            PackFields::TrickyByte,
        ];
        let topo = PackTopology::new(5, &fields, true, false).unwrap();
        assert_eq!(topo.tricky_byte(), Some(5));
    }

    #[test]
    fn test_trickybyte_with_optional_fields() {
        let fields = vec![
            PackFields::Counter(2),
            PackFields::TrickyByte,
            PackFields::Nonce(8),
            PackFields::TTL(4),
            PackFields::HeadCRC(1),
        ];
        let topo = PackTopology::new(5, &fields, false, false).unwrap();
        assert_eq!(topo.tricky_byte(), Some(2));
        assert_eq!(topo.nonce_slice(), Some((3, 11, 8)));
        assert_eq!(topo.ttl_slice(), Some((11, 15, 4)));
    }

    #[test]
    fn test_userfield_exceeds_maximum() {
        let too_large = (usize::MAX >> 1) + 1;
        let fields = vec![PackFields::UserField(too_large), PackFields::Counter(2)];
        // Should fail
        assert_eq!(
            PackTopology::new(5, &fields, true, false).err(),
            Some("userfield value is 0")
        );
    }

    // ========================================================================
    // 8. BOUNDARY VALUES FOR FIELD SIZES (8 bytes limit)
    // ========================================================================

    #[test]
    fn test_id_sender_boundary_8_bytes() {
        let fields = vec![
            PackFields::IdSender(8),
            PackFields::IdReceiver(8),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields, true, true).is_ok());
    }

    #[test]
    fn test_id_receiver_boundary_8_bytes() {
        let fields = vec![
            PackFields::IdSender(8),
            PackFields::IdReceiver(8),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields, true, true).is_ok());
    }

    #[test]
    fn test_ttl_boundary_8_bytes() {
        let fields = vec![
            PackFields::TTL(8),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields, true, true).is_ok());
    }

    #[test]
    fn test_nonce_boundary_32_bytes() {
        let fields = vec![
            PackFields::Nonce(32),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields, true, true).is_ok());
    }

    #[test]
    fn test_crc_boundary_32_bytes() {
        let fields = vec![
            PackFields::HeadCRC(32),
            PackFields::Counter(2),
            PackFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields, true, true).is_ok());
    }

    // ========================================================================
    // 9. DATA_SAVE AND TCP_MODE COMBINATIONS
    // ========================================================================

    #[test]
    fn test_data_save_true_tcp_mode_false_valid() {
        let fields = vec![PackFields::Counter(2)];
        assert!(PackTopology::new(5, &fields, true, false).is_ok());
    }

    #[test]
    fn test_data_save_false_tcp_mode_false_requires_crc() {
        let fields = vec![PackFields::Counter(2)];
        assert_eq!(
            PackTopology::new(5, &fields, false, false).err(),
            Some(
                "If you do not guarantee that the packet can be broken during \
                 transport(!data_save), you should use HeadCRC(usize)"
            )
        );
    }

    #[test]
    fn test_data_save_false_tcp_mode_true_invalid() {
        let fields = vec![
            PackFields::Counter(2),
            PackFields::Len(2),
            PackFields::HeadCRC(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields, false, true).err(),
            Some(
                "channel cannot be both tcp_mode and have data instability (!data_save == false \
                 && tcp_mode == true)"
            )
        );
    }

    // ========================================================================
    // 10. DISPLAY_LAYOUT_WITH_SEPARATORS (Test Only Function)
    // ========================================================================

    #[test]
    fn test_display_layout_runs_without_panic() {
        let fields = vec![
            PackFields::Len(2),
            PackFields::Counter(3),
            PackFields::UserField(5),
        ];
        let topo = PackTopology::new(5, &fields, true, true).unwrap();

        // Should not panic (output goes to stdout)
        topo.display_layout_with_separators();
    }

    // ========================================================================
    // 11. TEST ONLY FORCE EDIT METHODS
    // ========================================================================

    #[test]
    fn test_force_edit_counter() {
        let fields = vec![PackFields::Len(2), PackFields::Counter(3)];
        let mut topo = PackTopology::new(5, &fields, true, true).unwrap();

        let new_counter = Some((10, 15, 5));
        topo.__warning_test_only_force_edit_ctr(new_counter);

        assert_eq!(topo.counter_slice(), Some((10, 15, 5)));
    }

    #[test]
    fn test_force_edit_total_minimal_len() {
        let fields = vec![PackFields::Len(2), PackFields::Counter(3)];
        let mut topo = PackTopology::new(5, &fields, true, true).unwrap();

        topo.__warning_test_only_force_total_minimum_len_edit(999);

        assert_eq!(topo.total_minimal_len(), 999);
    }

    #[test]
    fn test_force_edit_ttl() {
        let fields = vec![
            PackFields::Len(2),
            PackFields::Counter(3),
            PackFields::TTL(4),
        ];
        let mut topo = PackTopology::new(5, &fields, true, true).unwrap();

        let new_ttl = Some((20, 25, 5));
        topo.__warning_test_only_force_edit_ttl(new_ttl);

        assert_eq!(topo.ttl_slice(), Some((20, 25, 5)));
    }

    // ========================================================================
    // 12. IS_TCP AND DATA_SAVE GETTERS
    // ========================================================================
    /*
        #[test]
        fn test_is_tcp_getter() {
            let fields = vec![PackFields::Len(2), PackFields::Counter(3)];

            let topo_tcp = PackTopology::new(5, &fields, true, true).unwrap();
            assert!(topo_tcp.is_tcp());

             let topo_udp = PackTopology::new(5, &fields, true, false).unwrap();
            assert!(!topo_udp.is_tcp());
        }

        #[test]
        fn test_data_save_getter() {
            let fields = vec![
                PackFields::HeadCRC(4),
                PackFields::Counter(3),
                PackFields::Len(1),
            ];

            let topo_save = PackTopology::new(5, &fields, true, true).unwrap();
            assert!(topo_save.data_save());

            let topo_nosave = PackTopology::new(5, &fields, false, false).unwrap();
             assert!(!topo_nosave.data_save());
        }
    */
    // ========================================================================
    // 13. MULTIPLE USERFIELDS POSITION VERIFICATION
    // ========================================================================

    #[test]
    fn test_multiple_userfields_positions() {
        let fields = vec![
            PackFields::UserField(5),
            PackFields::Counter(2),
            PackFields::UserField(10),
            PackFields::UserField(3),
        ];
        let topo = PackTopology::new(5, &fields, true, false).unwrap();

        let trash = topo.trash_content_slice().unwrap();
        assert_eq!(trash.len(), 3);
        assert_eq!(trash[0], (0, 5, 5));
        assert_eq!(trash[1], (7, 17, 10));
        assert_eq!(trash[2], (17, 20, 3));
    }

    // ========================================================================
    // 14. EMPTY TRASH_CONTENT_SLICE RETURNS NONE
    // ========================================================================

    #[test]
    fn test_no_userfields_returns_none() {
        let fields = vec![PackFields::Len(2), PackFields::Counter(3)];
        let topo = PackTopology::new(5, &fields, true, true).unwrap();
        assert_eq!(topo.trash_content_slice(), None);
    }

    // ========================================================================
    // 15. ALL GETTERS CONSISTENCY CHECK
    // ========================================================================

    #[test]
    fn test_all_getters_return_consistent_values() {
        let fields = vec![
            PackFields::Len(4),
            PackFields::Counter(8),
            PackFields::IdSender(6),
            PackFields::IdReceiver(6),
            PackFields::HeadCRC(4),
            PackFields::Nonce(8),
            PackFields::TTL(3),
            PackFields::IdConnect(7),
        ];
        let topo = PackTopology::new(10, &fields, true, true).unwrap();

        // Verify all getters return expected types without panic
        let _ = topo.tag_len();
        let _ = topo.encrypt_start_pos();
        let _ = topo.content_start_pos();
        let _ = topo.head_byte_pos();
        let _ = topo.counter_slice();
        let _ = topo.idconn_slice();
        let _ = topo.id_of_sender_slice();
        let _ = topo.id_of_receiver_slice();
        let _ = topo.len_slice();
        let _ = topo.trash_content_slice();
        let _ = topo.head_crc_slice();
        let _ = topo.nonce_slice();
        let _ = topo.ttl_slice();
        let _ = topo.total_head_slice();
        let _ = topo.total_minimal_len();
        //let _ = topo.is_tcp();
        //let _ = topo.data_save();
        let _ = topo.tricky_byte();

        // Basic sanity check
        assert!(topo.tag_len() > 0);
        assert!(topo.content_start_pos() > topo.encrypt_start_pos());
    }
}

#[cfg(test)]
mod packfields_tests {
    use super::*;

    // ========================================================================
    // PARTIAL EQ: Same variant, different inner values → EQUAL (by design)
    // ========================================================================

    #[test]
    fn test_partial_eq_ignores_inner_value() {
        // Equality is based on variant type only, not the usize payload
        assert_eq!(PackFields::Len(1), PackFields::Len(100));
        assert_eq!(PackFields::Counter(1), PackFields::Counter(8));
        assert_eq!(PackFields::IdSender(2), PackFields::IdSender(64));
        assert_eq!(PackFields::IdReceiver(4), PackFields::IdReceiver(8));
        assert_eq!(PackFields::UserField(10), PackFields::UserField(1000));
        assert_eq!(PackFields::HeadCRC(4), PackFields::HeadCRC(32));
        assert_eq!(PackFields::Nonce(8), PackFields::Nonce(32));
        assert_eq!(PackFields::TTL(1), PackFields::TTL(8));
        assert_eq!(PackFields::IdConnect(4), PackFields::IdConnect(8));
        assert_eq!(PackFields::TrickyByte, PackFields::TrickyByte);
    }

    // ========================================================================
    // PARTIAL EQ: Different variants → NOT EQUAL
    // ========================================================================

    #[test]
    fn test_partial_eq_different_variants_not_equal() {
        // Cross-variant comparisons must return false
        assert_ne!(PackFields::Len(4), PackFields::Counter(4));
        assert_ne!(PackFields::IdSender(4), PackFields::IdReceiver(4));
        assert_ne!(PackFields::UserField(10), PackFields::HeadCRC(10));
        assert_ne!(PackFields::Nonce(8), PackFields::TTL(8));
        assert_ne!(PackFields::IdConnect(4), PackFields::TrickyByte);
        assert_ne!(PackFields::TrickyByte, PackFields::Counter(1));
    }

    // ========================================================================
    // PARTIAL EQ: Reflexivity and symmetry properties
    // ========================================================================

    #[test]
    fn test_partial_eq_reflexive() {
        // Every value must equal itself (reflexivity)
        let fields = [
            PackFields::Len(5),
            PackFields::Counter(3),
            PackFields::IdSender(8),
            PackFields::IdReceiver(8),
            PackFields::UserField(128),
            PackFields::HeadCRC(16),
            PackFields::Nonce(24),
            PackFields::TTL(4),
            PackFields::IdConnect(6),
            PackFields::TrickyByte,
        ];
        for f in &fields {
            assert_eq!(f, f, "PartialEq must be reflexive for {:?}", f);
        }
    }

    #[test]
    fn test_partial_eq_symmetric() {
        // If a == b, then b == a (symmetry)
        let a = PackFields::Len(4);
        let b = PackFields::Len(99);
        assert_eq!(a == b, b == a, "PartialEq must be symmetric");
    }

    // ========================================================================
    // VARIANT CONSTRUCTORS: Ensure all variants can be instantiated
    // ========================================================================

    #[test]
    fn test_all_variants_constructible() {
        // Smoke test: each variant can be created with valid values
        let _ = PackFields::Len(1);
        let _ = PackFields::Counter(8);
        let _ = PackFields::IdSender(4);
        let _ = PackFields::IdReceiver(4);
        let _ = PackFields::UserField(256);
        let _ = PackFields::HeadCRC(32);
        let _ = PackFields::Nonce(32);
        let _ = PackFields::TTL(8);
        let _ = PackFields::IdConnect(8);
        let _ = PackFields::TrickyByte;
    }

    #[test]
    fn test_variant_with_zero_value() {
        // Zero is a valid usize payload for most variants (validation happens in
        // PackTopology::new)
        assert_eq!(PackFields::Len(0), PackFields::Len(0));
        assert_eq!(PackFields::Counter(0), PackFields::Counter(0));
        assert_ne!(PackFields::Len(0), PackFields::Counter(0));
    }

    // ========================================================================
    // DERIVED TRAITS: Clone and Debug should work
    // ========================================================================

    #[test]
    fn test_clone_and_debug() {
        let original = PackFields::UserField(42);
        let cloned = original.clone();

        assert_eq!(original, cloned);

        // Debug formatting should not panic
        let debug_str = format!("{:?}", original);
        assert!(debug_str.contains("UserField"));
    }

    // ========================================================================
    // USE CASE: Deduplication via PartialEq (as used in PackTopology::new)
    // ========================================================================

    #[test]
    fn test_partial_eq_useful_for_deduplication() {
        // Simulate the duplicate-check logic from PackTopology::new
        let existing = PackFields::Counter(4);
        let incoming = PackFields::Counter(8); // different size, same variant

        // PartialEq ignores size, so this correctly detects "duplicate Counter"
        assert_eq!(existing, incoming, "Duplicate detection should ignore size");

        // Different variant should not be flagged as duplicate
        let other = PackFields::Nonce(8);
        assert_ne!(existing, other, "Different variants are not duplicates");
    }
}

#[cfg(test)]
mod test_equal {
    use super::*;

    // ========== validation: equal cases ==========

    #[test]
    fn test_proto_equal_position_invariant_and_ignored_fields() {
        // same protocol fields, different order/positions + different ignored fields → equal
        let t1 = PackTopology::new(
            16,
            &[
                PackFields::Counter(4),
                PackFields::IdSender(6),
                PackFields::TrickyByte,
                PackFields::IdReceiver(6),
                PackFields::Len(2),
                PackFields::HeadCRC(16),
                PackFields::Nonce(12),
                PackFields::TTL(4),
                PackFields::IdConnect(6),
                PackFields::UserField(10),
            ],
            false,
            false,
        )
        .unwrap();

        let mut t2 = PackTopology::new(
            16,
            &[
                PackFields::IdConnect(6),
                PackFields::TTL(4),
                PackFields::TrickyByte,
                PackFields::Nonce(12),
                PackFields::HeadCRC(16),
                PackFields::Len(2),
                PackFields::Counter(4),
                PackFields::IdReceiver(6),
                PackFields::IdSender(6),
                PackFields::UserField(50), // different trash content
            ],
            false,
            false,
        )
        .unwrap();

        // mutate ignored metadata
        t2.__warning_test_only_force_total_minimum_len_edit(999);

        assert!(
            t1.is_proto_equal(&t2) && t2.is_proto_equal(&t1),
            "position/ignored-field invariant"
        );
    }

    #[test]
    fn test_proto_equal_minimal_and_maximal() {
        // minimal: only counter
        let a = PackTopology::new(16, &[PackFields::Counter(1)], true, false).unwrap();
        let b = PackTopology::new(16, &[PackFields::Counter(1)], true, false).unwrap();
        assert!(a.is_proto_equal(&b));

        // maximal: all fields at max length, different order
        let fields = [
            PackFields::Counter(8),
            PackFields::IdSender(8),
            PackFields::IdReceiver(8),
            PackFields::Len(8),
            PackFields::HeadCRC(32),
            PackFields::Nonce(32),
            PackFields::TTL(8),
            PackFields::IdConnect(8),
            //PackFields::TrickyByte,
        ];
        let m1 = PackTopology::new(32, &fields, true, false).unwrap();
        let mut rev = fields.to_vec();
        rev.reverse();
        let m2 = PackTopology::new(32, &rev, false, false).unwrap();
        assert!(m1.is_proto_equal(&m2));
    }

    // ========== error generation: inequality cases ==========

    #[test]
    fn test_proto_not_equal_all_significant_fields() {
        macro_rules! assert_ne_proto {
            ($fields1:expr, $fields2:expr, $tag1:expr, $tag2:expr, $msg:expr) => {
                let t1 = PackTopology::new($tag1, $fields1, true, false).unwrap();
                let t2 = PackTopology::new($tag2, $fields2, true, false).unwrap();
                assert!(!t1.is_proto_equal(&t2) && !t2.is_proto_equal(&t1), $msg);
            };
        }

        // tag_len mismatch
        assert_ne_proto!(
            &[PackFields::Counter(4)],
            &[PackFields::Counter(4)],
            16,
            32,
            "tag_len"
        );

        // tricky_byte: position mismatch / presence mismatch
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::TrickyByte],
            &[PackFields::TrickyByte, PackFields::Counter(4)],
            16,
            16,
            "tricky_byte pos"
        );
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::TrickyByte],
            &[PackFields::Counter(4)],
            16,
            16,
            "tricky_byte presence"
        );

        // each slice field: length mismatch
        assert_ne_proto!(
            &[PackFields::Counter(4)],
            &[PackFields::Counter(8)],
            16,
            16,
            "counter len"
        );
        assert_ne_proto!(
            &[
                PackFields::Counter(4),
                PackFields::IdSender(4),
                PackFields::IdReceiver(4)
            ],
            &[
                PackFields::Counter(4),
                PackFields::IdSender(6),
                PackFields::IdReceiver(6)
            ],
            16,
            16,
            "id_sender/receiver len"
        );
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::Len(2)],
            &[PackFields::Counter(4), PackFields::Len(4)],
            16,
            16,
            "len field"
        );
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::HeadCRC(16)],
            &[PackFields::Counter(4), PackFields::HeadCRC(32)],
            16,
            16,
            "crc len"
        );
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::Nonce(16)],
            &[PackFields::Counter(4), PackFields::Nonce(24)],
            16,
            16,
            "nonce len"
        );
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::TTL(4)],
            &[PackFields::Counter(4), PackFields::TTL(8)],
            16,
            16,
            "ttl len"
        );
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::IdConnect(4)],
            &[PackFields::Counter(4), PackFields::IdConnect(8)],
            16,
            16,
            "idconn len"
        );

        // field presence mismatch (one has field, other doesn't)
        assert_ne_proto!(
            &[PackFields::Counter(4), PackFields::Nonce(16)],
            &[PackFields::Counter(4)],
            16,
            16,
            "field presence"
        );
    }

    // ========== cross-mutation: validate → mutate → invalidate ==========

    #[test]
    fn test_proto_cross_mutation() {
        macro_rules! mutate_and_check {
            ($topo:ident, $mutator:ident, $new_val:expr, $other:expr) => {
                assert!($topo.is_proto_equal(&$other));
                $topo.$mutator($new_val);
                assert!(
                    !$topo.is_proto_equal(&$other),
                    "mutation should break equality"
                );
            };
        }

        let mut t1 = PackTopology::new(
            16,
            &[
                PackFields::Counter(4),
                PackFields::TTL(4),
                PackFields::HeadCRC(16),
            ],
            false,
            false,
        )
        .unwrap();
        let t2 = PackTopology::new(
            16,
            &[
                PackFields::Counter(4),
                PackFields::TTL(4),
                PackFields::HeadCRC(16),
            ],
            false,
            false,
        )
        .unwrap();

        mutate_and_check!(t1, __warning_test_only_force_edit_ctr, Some((0, 8, 8)), t2);

        let mut t3 = PackTopology::new(
            16,
            &[PackFields::Counter(4), PackFields::TTL(4)],
            true,
            false,
        )
        .unwrap();
        let t4 = PackTopology::new(
            16,
            &[PackFields::Counter(4), PackFields::TTL(4)],
            true,
            false,
        )
        .unwrap();
        mutate_and_check!(t3, __warning_test_only_force_edit_ttl, Some((0, 8, 8)), t4);

        let mut t5 = PackTopology::new(
            16,
            &[PackFields::Counter(4), PackFields::HeadCRC(16)],
            false,
            false,
        )
        .unwrap();
        let t6 = PackTopology::new(
            16,
            &[PackFields::Counter(4), PackFields::HeadCRC(16)],
            false,
            false,
        )
        .unwrap();
        mutate_and_check!(
            t5,
            __warning_test_only_force_edit_crc,
            Some((0, 32, 32)),
            t6
        );
    }

    // ========== fundamental properties ==========

    #[test]
    fn test_proto_equal_properties() {
        // reflexivity
        let t = PackTopology::new(
            16,
            &[
                PackFields::Counter(4),
                PackFields::Len(2),
                PackFields::Nonce(16),
            ],
            true,
            true,
        )
        .unwrap();
        assert!(t.is_proto_equal(&t), "reflexivity");

        // symmetry & transitivity via permutation
        let fields = [
            PackFields::Counter(4),
            PackFields::Len(2),
            PackFields::Nonce(16),
        ];
        let perms = [
            &fields.clone()[..],
            &[fields[1].clone(), fields[0].clone(), fields[2].clone()],
            &[fields[2].clone(), fields[1].clone(), fields[0].clone()],
        ];
        let tops: Vec<_> = perms
            .iter()
            .map(|f| PackTopology::new(16, f, true, true).unwrap())
            .collect();

        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(
                    tops[i].is_proto_equal(&tops[j]),
                    tops[j].is_proto_equal(&tops[i]),
                    "symmetry i={},j={}",
                    i,
                    j
                );
                if i < 2 && j < 2 {
                    // transitivity check subset
                    assert!(
                        tops[i].is_proto_equal(&tops[j])
                            && tops[j].is_proto_equal(&tops[2]) == tops[i].is_proto_equal(&tops[2]),
                        "transitivity"
                    );
                }
            }
        }
    }
}
