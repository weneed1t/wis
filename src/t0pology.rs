use std::usize;

//using in other files

pub const MAXIMAL_CRC_LEN: usize = 32; //maxiaml 512 bits
pub const MAXIMAL_TTL_LEN: usize = 8; //8 bytes is u64 max size
pub const MAXIMAL_NONCE_LEN: usize = 32; //maxiaml 512 bits
const fn maxval(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

pub const MAX_BUF_SIZE: usize = maxval(MAXIMAL_CRC_LEN, maxval(MAXIMAL_TTL_LEN, MAXIMAL_NONCE_LEN));

#[derive(Debug, Clone)]

// public packet fields enumeration contains mandatory and optional fields
// the only mandatory field is the counter, which must always be present and can be 1 to 8 bytes in size
// user id and receiver id, if present, must have the same size — from 0 to 8 bytes (0 means absent, 8 means 64-bit)
// used in mesh networks where intermediate nodes handle traffic routing
// length field indicates total packet length including headers and data, used in reliable stream protocols for integrity and ordering
// counter field is mandatory, 1–8 bytes, holds a unique packet number that increments by one for each new packet
// if counter size is limited, special mechanisms restore the full counter value on client and server
// user data field is optional and can be of arbitrary size; absence means zero length
// used to obscure packet structure and prevent traffic filtering or blocking in networks
// header crc is optional, up to 32 bytes (256 bits), used to verify integrity of header data in unreliable protocols
// ttl (time to live) field is 1–8 bytes, used in multi-hop networks to limit packet lifetime and prevent infinite loops
// nonce field is optional, up to 32 bytes, used for cryptographic operations and secure communication
// idconnect field is used to associate packets with a specific connection or session
// all size constants are defined to support maximum required lengths for secure and flexible packet handling
pub enum PakFields {
    IdOfSender(usize),
    IdReceiver(usize),
    Len(usize),
    Counter(usize),
    UserField(usize),
    HeadCRC(usize),
    TTL(usize),
    Nonce(usize),
    IdConnect(usize),
}

impl PartialEq for PakFields {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::IdOfSender(_), Self::IdOfSender(_)) => true,
            (Self::IdReceiver(_), Self::IdReceiver(_)) => true,
            (Self::Len(_), Self::Len(_)) => true,
            (Self::Counter(_), Self::Counter(_)) => true,
            (Self::UserField(_), Self::UserField(_)) => true,
            (Self::HeadCRC(_), Self::HeadCRC(_)) => true,
            (Self::Nonce(_), Self::Nonce(_)) => true,
            //(PakFields::HeadByte, PakFields::HeadByte) => true,
            (Self::TTL(_), Self::TTL(_)) => true,
            (Self::IdConnect(_), Self::IdConnect(_)) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PackTopology {
    all_fields: Box<[PakFields]>,
    tag_len: usize,
    encrypt_start_pos: usize,
    content_start_pos: usize,
    counter_slice: Option<(usize, usize, usize)>, // (pos_start, pos_end, len)
    id_of_sender_slice: Option<(usize, usize, usize)>, // (pos_start, pos_end, len)
    id_of_receiver_slice: Option<(usize, usize, usize)>, // (pos_start, pos_end, len)
    len_slice: Option<(usize, usize, usize)>,     // (pos_start, pos_end, len)
    trash_content_slice: Option<(usize, usize, usize)>, // (pos_start, pos_end, len)
    crc_slice: Option<(usize, usize, usize)>,     // (pos_start, pos_end, len)
    nonce_slice: Option<(usize, usize, usize)>,   // (pos_start, pos_end, len)
    ttl_slice: Option<(usize, usize, usize)>,     // (pos_start, pos_end, len)
    idconn_slice: Option<(usize, usize, usize)>,  // (pos_start, pos_end, len)
    total_minimal_len: usize,
    is_tcp_like: bool,
    data_save: bool,
}

impl PackTopology {
    /// [packet topology structure defines the layout and metadata of a packet's header fields  ]
    /// [all fields are optional except counter, which is mandatory and must be present     ]
    /// [each field slice is represented as (start_index, end_index, length) in bytes   ]
    /// [tag_len is the length of the authentication tag (e.g., from AEAD encryption), located at the end   ]
    /// [encrypt_start_pos marks the beginning of encrypted section INCLUDING header byte]
    /// [content_start_pos marks the start of user payload AFTER header byte]
    /// [counter_slice must always be set — it holds the packet sequence number (1–8 bytes)     ]
    /// [id_of_sender_slice and id_of_receiver_slice, if present, must both exist and have equal length (0–8 bytes)   ]
    /// [len_slice is required in tcp-like mode to delimit packet boundaries in stream protocols    ]
    /// [trash_content_slice is unencrypted optional data used to obfuscate packet structure from DPI systems       ]
    /// [crc_slice is used when data integrity is not guaranteed (e.g., UDP), protects only the header (up to 32 bytes)    ]
    /// [nonce_slice provides cryptographic nonce for encryption (up to 32 bytes), must be unique per packet    ]
    /// [ttl_slice limits packet lifetime in multi-hop networks (1–8 bytes, max u64)    ]
    /// [idconn_slice identifies a connection or session (1–8 bytes)    ]
    /// [total_minimal_len is the minimum size of the packet: content_start_pos + tag_len   ]
    /// [is_tcp_like indicates stream-oriented, reliable transport (requires Len field)     ]
    /// [data_save indicates whether the channel preserves data integrity (if false, HeadCRC is required)       ]
    /// [during construction, fields are processed in order — their position determines layout in the packet    ]
    /// [duplicate fields are rejected; all length validations are enforced (e.g., max 8 bytes for ids, counters)   ]
    /// [the final packet layout is: [header fields][head byte][encrypted user data][tag]   ]
    /// [head byte (1 byte) is fixed and marks transition to encrypted section, not exposed in public fields    ]
    /// [validation ensures consistent configuration: tcp_mode requires Len, missing data_save requires CRC, etc.   ]
    /// [all possible fields are defined in enum PakFields and passed via &[PakFields]; order matters   ]
    /// [UserField (trash_content_slice) is non-encrypted and used for traffic mimicry or DPI evasion   ]
    /// [the structure supports flexible configuration for use in various network environments (UDP-like or TCP-like)   ]
    pub fn new(
        tag_len: usize,
        fields: &[PakFields],
        data_save: bool,
        tcp_mode: bool,
    ) -> Result<Self, &'static str> {
        let mut id_of_sender_slice: Option<(usize, usize, usize)> = None;
        let mut id_of_receiver_slice: Option<(usize, usize, usize)> = None;
        let mut len_slice: Option<(usize, usize, usize)> = None;
        let mut trash_content_slice: Option<(usize, usize, usize)> = None;
        let mut crc_slice: Option<(usize, usize, usize)> = None;
        let mut nonce_slice: Option<(usize, usize, usize)> = None;
        let mut counter_slice: Option<(usize, usize, usize)> = None;
        let mut ttl_slice: Option<(usize, usize, usize)> = None;
        let mut idconn_slice: Option<(usize, usize, usize)> = None;

        let mut shift: usize = 0_usize;

        for x in fields.iter() {
            shift = shift
                .checked_add(match *x {
                    PakFields::UserField(le) => {
                        if trash_content_slice.is_some() {
                            return Err("duplicate userfield");
                        }

                        if le == 0 || le > (usize::MAX >> 1) {
                            //done just in case, maximum length limit
                            return Err("userfield value is 0");
                        }
                        trash_content_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::IdConnect(le) => {
                        if idconn_slice.is_some() {
                            return Err("duplicate idconn");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idconn value exceeds 8");
                        }
                        idconn_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::Len(le) => {
                        if len_slice.is_some() {
                            return Err("duplicate len");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("len value exceeds 8");
                        }

                        len_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::Counter(le) => {
                        if counter_slice.is_some() {
                            return Err("duplicate counter");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("counter value exceeds 8");
                        }
                        counter_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::IdOfSender(le) => {
                        if id_of_sender_slice.is_some() {
                            return Err("duplicate idofsender");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idofsender value exceeds 8");
                        }
                        id_of_sender_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::IdReceiver(le) => {
                        if id_of_receiver_slice.is_some() {
                            return Err("duplicate idreceiver");
                        }
                        if matches!(le, 0 | 9..) {
                            return Err("idreceiver value exceeds 8");
                        }
                        id_of_receiver_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::HeadCRC(le) => {
                        if crc_slice.is_some() {
                            return Err("duplicate crc");
                        }

                        if le > MAXIMAL_CRC_LEN || le == 0 {
                            return Err("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0");
                        }

                        crc_slice = Some((shift, shift + le, le));
                        le
                    }
                    PakFields::Nonce(le) => {
                        if le == 0 || le > MAXIMAL_NONCE_LEN {
                            return Err("nonce len is 0");
                        }

                        if nonce_slice.is_some() {
                            return Err("duplicate nonce");
                        }

                        nonce_slice = Some((shift, shift + le, le));
                        le
                    }
                    //PakFields::HeadByte => {
                    //    if head_byte_pos.is_some() {
                    //        return Err("duplicate headbyte");
                    //    }
                    //    head_byte_pos = Some(shift);
                    //    shift += 1;
                    //}
                    // it was decided to move the HeadByte to the encrypted part of the data
                    //HeadByte was moved to the encrypted part because the HeadByte field is mandatory,
                    // always comes at the end of the head, and its encryption increases reliability and security
                    PakFields::TTL(le) => {
                        if ttl_slice.is_some() {
                            return Err("duplicate ttl");
                        }
                        if le > MAXIMAL_TTL_LEN || le == 0 {
                            return Err("TTL value exceeds MAXIMAL_TTL_LEN or  == 0");
                        }

                        ttl_slice = Some((shift, shift + le, le));
                        le
                    }
                })
                .ok_or("header size exceeds addressable memory")?;
        }

        if !data_save && tcp_mode {
            return Err(
                "channel cannot be both tcp_mode and have data instability (!data_save == false && tcp_mode == true)",
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
                "If you do not guarantee that the packet can be broken during transport(!data_save), you should use HeadCRC(usize)",
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
            }
            _ => (),
        }

        if let (Some(re), Some(se)) = (id_of_receiver_slice, id_of_sender_slice) {
            if re.2 != se.2 {
                return Err("id_of_receiver_slice and id_of_sender_slice must be the same length");
            }
        }

        let content_start_pos = shift
            .checked_add(1)
            .ok_or("total packet size exceeds addressable memory")?; //len is 1 byte of HeadByte

        let topology = Self {
            all_fields: fields.to_vec().into_boxed_slice(),
            tag_len,
            encrypt_start_pos: shift,
            content_start_pos: content_start_pos,
            counter_slice,
            id_of_sender_slice,
            id_of_receiver_slice,
            len_slice,
            trash_content_slice,
            crc_slice,
            nonce_slice,
            ttl_slice,
            idconn_slice,
            total_minimal_len: content_start_pos
                .checked_add(tag_len)
                .ok_or("total packet size exceeds addressable memory")?,
            is_tcp_like: tcp_mode,
            data_save,
        };

        #[cfg(any(test))]
        {
            topology.display_layout_with_separators();
        }

        Ok(topology)
    }
}

impl PackTopology {
    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    ///- |nnnnnnnnnnn|eeeeeeeeeeeeeeeeeeeeeeeeeeeeee|eee|
    ///- |head fields|head byte|payload(aka content)|tag|
    ///- "n" non encpypt , "e" encrypt
    pub fn encrypt_start_pos(&self) -> usize {
        self.encrypt_start_pos
    }
    pub fn content_start_pos(&self) -> usize {
        self.content_start_pos
    }

    pub fn head_byte_pos(&self) -> usize {
        self.encrypt_start_pos
    }
    /// (start pos, end pos, len of slise)
    pub fn counter_slice(&self) -> Option<(usize, usize, usize)> {
        self.counter_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn idconn_slice(&self) -> Option<(usize, usize, usize)> {
        self.idconn_slice
    }
    ///(start pos, end pos, len of slise)
    pub fn id_of_sender_slice(&self) -> Option<(usize, usize, usize)> {
        self.id_of_sender_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn ttl_slice(&self) -> Option<(usize, usize, usize)> {
        self.ttl_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn id_of_receiver_slice(&self) -> Option<(usize, usize, usize)> {
        self.id_of_receiver_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn len_slice(&self) -> Option<(usize, usize, usize)> {
        self.len_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn trash_content_slice(&self) -> Option<(usize, usize, usize)> {
        self.trash_content_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn head_crc_slice(&self) -> Option<(usize, usize, usize)> {
        self.crc_slice
    }
    /// (start pos, end pos, len of slise)
    pub fn nonce_slice(&self) -> Option<(usize, usize, usize)> {
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

    pub fn is_tcp(&self) -> bool {
        self.is_tcp_like
    }
    pub fn data_save(&self) -> bool {
        self.data_save
    }
}

#[cfg(any(test))]
impl PackTopology {
    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_edit_ctr(&mut self, ctr: Option<(usize, usize, usize)>) {
        self.counter_slice = ctr;
    }

    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_total_minimum_len_edit(&mut self, lenn: usize) {
        self.total_minimal_len = lenn;
    }

    ///<h1>NO USE IN PROD! IS TEST ONLY TEST ONLY
    ///<h1> !IS TEST ONLY TEST ONLY!
    pub fn __warning_test_only_force_edit_ttl(&mut self, ttl: Option<(usize, usize, usize)>) {
        self.ttl_slice = ttl;
    }

    pub fn display_layout_with_separators(&self) {
        let total_len = self.total_minimal_len;

        let st_data: &[u8] = "PAYLOAD_ENC".as_bytes();
        let mut layout: Vec<char> = vec!['-'; total_len + st_data.len()];

        for i in
            (self.content_start_pos()..self.content_start_pos() + st_data.len()).zip(st_data.iter())
        {
            layout[i.0] = *i.1 as char;
        }

        // Helper function to fill the layout with field representation
        let mut sf = 0;

        let mut vector_legend = vec![];

        fn fill_field(
            layout: &mut Vec<char>,
            start: usize,
            end: usize,
            label: char,
            sf: &mut usize,
        ) {
            layout[*sf + start..*sf + end].fill(label);
        }
        {
            // Fill HeadByte
            if let Some(pos) = Some(self.encrypt_start_pos) {
                //println!("Pos: {}", pos);
                fill_field(&mut layout, pos, pos + 1, 'H', &mut sf);
                //println!("Pos: {:?}", layout);
            }

            // Fill Tag (assuming it starts after content_start_pos)
            //let tag_start = self.encrypt_start_pos + st_data.len();
            //let tag_end = tag_start + self.total_minimal_len();
            //fill_field(&mut layout, tag_start, tag_end, '-', &mut sf);

            // Fill Counter
            if let Some((start, end, lenme)) = self.counter_slice {
                fill_field(&mut layout, start, end, 'C', &mut sf);
                vector_legend.push(format!("  [C - {} bytes] - Counter", lenme));
            }

            // Fill IDCONN
            if let Some((start, end, lenme)) = self.idconn_slice {
                fill_field(&mut layout, start, end, 'I', &mut sf);
                vector_legend.push(format!("  [I - {} bytes] - IDCONN", lenme));
            }

            // Fill IdOfSender
            if let Some((start, end, lenme)) = self.id_of_sender_slice {
                fill_field(&mut layout, start, end, 'S', &mut sf);
                vector_legend.push(format!("  [S - {} bytes] - IdOfSender", lenme));
            }

            // Fill IdOfReceiver
            if let Some((start, end, lenme)) = self.id_of_receiver_slice {
                fill_field(&mut layout, start, end, 'R', &mut sf);
                vector_legend.push(format!("  [R - {} bytes] - IdOfReceiver", lenme));
            }

            // Fill Len
            if let Some((start, end, lenme)) = self.len_slice {
                fill_field(&mut layout, start, end, 'L', &mut sf);
                vector_legend.push(format!("  [L - {} bytes] - Len", lenme));
            }

            // Fill TrashContent
            if let Some((start, end, lenme)) = self.trash_content_slice {
                fill_field(&mut layout, start, end, 'U', &mut sf);
                vector_legend.push(format!(
                    "  [U - {} bytes] - UserField (TrashContent)",
                    lenme
                ));
            }

            // Fill CRC
            if let Some((start, end, lenme)) = self.crc_slice {
                fill_field(&mut layout, start, end, '*', &mut sf);
                vector_legend.push(format!("  [* - {} bytes] - CRC", lenme));
            }

            // Fill Nonce
            if let Some((start, end, lenme)) = self.nonce_slice {
                fill_field(&mut layout, start, end, 'N', &mut sf);
                vector_legend.push(format!("  [N - {} bytes] - Nonce", lenme));
            }

            // Fill TTL
            if let Some((start, end, lenme)) = self.ttl_slice {
                fill_field(&mut layout, start, end, 'T', &mut sf);
                vector_legend.push(format!("  [T - {} bytes] - TTL", lenme));
            }

            layout[self.head_byte_pos()] = '@';

            // Convert the layout to a string and print it
            println!("|.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-|");
            let layout_str: String = layout.iter().collect();
            println!("Memory Layout:");
            println!("{}", layout_str);

            // Print legend
            println!("Legend:");
            for x in vector_legend {
                println!("{x}");
            }

            println!("  [- {} bytes] - tag", self.tag_len());
            println!("  [@ ...] - Head Byte");
            println!("|.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-|");
        }
    }
}

//=============================================TESTS=========================================================================================
//=============================================TESTS=========================================================================================
//=============================================TESTS=========================================================================================
//=============================================TESTS=========================================================================================
//=============================================TESTS=========================================================================================
//=============================================TESTS=========================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    const _: () = {
        assert!(MAX_BUF_SIZE >= MAXIMAL_CRC_LEN);
        assert!(MAX_BUF_SIZE >= MAXIMAL_NONCE_LEN);
    };

    #[test]
    fn test_valid_input() {
        // Test valid input with all unique fields and correct values
        let fields = vec![
            PakFields::Len(4),
            PakFields::Counter(8),
            PakFields::IdOfSender(6),
            PakFields::IdReceiver(6),
            PakFields::UserField(10),
            PakFields::HeadCRC(4),
            PakFields::Nonce(8),
            PakFields::TTL(3),
            PakFields::IdConnect(7),
        ];
        let result = PackTopology::new(5, &fields, true, true);

        let topology = result.unwrap();
        // Verify getters for mandatory fields
        assert_eq!(topology.tag_len(), 5, "tag_len should be 5");
        assert_eq!(
            topology.content_start_pos(),
            57,
            "content_start_pos should be 57"
        );
        assert_eq!(topology.head_byte_pos(), 56, "head_byte_pos should be 56");

        // Verify getters for optional fields
        assert_eq!(
            topology.counter_slice(),
            Some((4, 12, 8)),
            "counter_slice should match"
        );
        assert_eq!(
            topology.id_of_sender_slice(),
            Some((12, 18, 6)),
            "id_of_sender_slice should match"
        );
        assert_eq!(
            topology.ttl_slice(),
            Some((46, 49, 3)),
            "ttl_slice should match"
        );
        assert_eq!(
            topology.id_of_receiver_slice(),
            Some((18, 24, 6)),
            "id_of_receiver_slice should match"
        );
        assert_eq!(
            topology.len_slice(),
            Some((0, 4, 4)),
            "len_slice should match"
        );
        assert_eq!(
            topology.trash_content_slice(),
            Some((24, 34, 10)),
            "trash_content_slice should match"
        );
        assert_eq!(
            topology.head_crc_slice(),
            Some((34, 38, 4)),
            "head_crc_slice should match"
        );
        assert_eq!(
            topology.nonce_slice(),
            Some((38, 46, 8)),
            "nonce_slice should match"
        );

        assert_eq!(
            topology.idconn_slice(),
            Some((49, 56, 7)),
            "idconn_slice should match"
        );
        // Verify total_minimal_len
        assert_eq!(
            topology.total_minimal_len(),
            62,
            "total_minimal_len should be 62"
        );
        assert_eq!(topology.data_save(), true);
        assert_eq!(topology.is_tcp(), true);
    }

    #[test]
    fn test_invalid_inputs() {
        // Duplicate Len
        let fields_duplicate_len = vec![PakFields::Len(4), PakFields::Len(4)];
        assert_eq!(
            PackTopology::new(5, &fields_duplicate_len, false, false).err(),
            Some("duplicate len"),
            "expected 'duplicate len' error"
        );

        // Len value exceeds 8
        let fields_invalid_len = vec![PakFields::Len(9)];
        assert_eq!(
            PackTopology::new(5, &fields_invalid_len, false, false).err(),
            Some("len value exceeds 8"),
            "expected 'len value exceeds 8' error"
        );

        // CRC len is 0
        let fields_zero_crc = vec![PakFields::HeadCRC(0)];
        assert_eq!(
            PackTopology::new(5, &fields_zero_crc, false, false).err(),
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0"),
            "expected 'crc len is 0' error"
        );

        // Missing Counter or Nonce
        let fields_no_counter_or_nonce = vec![PakFields::Len(4)];
        assert_eq!(
            PackTopology::new(5, &fields_no_counter_or_nonce, false, false).err(),
            Some("the structure must have either a Counter field"),
            "expected 'the structure must have either a Counter field or a Nonce' error"
        );
    }

    #[test]
    fn test_guarantee_conditions() {
        // Missing HeadCRC when data integrity is not guaranteed
        let fields_missing_headcrc = vec![PakFields::Len(4), PakFields::Counter(8)];
        assert_eq!(
            PackTopology::new(5, &fields_missing_headcrc, false, false).err(),
            Some(
                "If you do not guarantee that the packet can be broken during transport(!data_save), you should use HeadCRC(usize)"
            ),
            "expected 'missing HeadCRC' error"
        );
        let fields_missing_headcrc = vec![PakFields::Counter(8)];
        // Missing Len when length preservation is not guaranteed
        assert_eq!(
            PackTopology::new(5, &fields_missing_headcrc, false, true).err(),
            Some(
                "channel cannot be both tcp_mode and have data instability (!data_save == false && tcp_mode == true)"
            ),
            "expected 'missing Len' error"
        );
    }

    #[test]
    fn test_edge_cases() {
        // Minimal valid input
        let fields_minimal_valid = vec![PakFields::Len(1), PakFields::Counter(1)];
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
            PakFields::Len(4),
            PakFields::Counter(8),
            PakFields::IdOfSender(6),
            PakFields::IdReceiver(6),
            PakFields::UserField(10),
            PakFields::HeadCRC(4),
            PakFields::Nonce(8),
            PakFields::TTL(3),
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

        // IdOfSender
        if let Some((start, end, len)) = topology.id_of_sender_slice() {
            assert_eq!(start, expected_shift, "IdOfSender start position mismatch");
            assert_eq!(
                end,
                expected_shift + len,
                "IdOfSender end position mismatch"
            );
            assert_eq!(len, 6, "IdOfSender length mismatch");
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

        // UserField (TrashContent)
        if let Some((start, end, len)) = topology.trash_content_slice() {
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

        assert_eq!(topology.data_save(), true);
        assert_eq!(topology.is_tcp(), true);
    }

    #[test]
    fn test_invalid_values_for_all_fields() {
        // Define invalid values to test
        let invalid_values = vec![0, 9]; // 0 is too small, 9 is too large

        // Test each field with invalid values
        for &invalid_value in &invalid_values {
            // Len
            let fields_len = vec![PakFields::Counter(2), PakFields::Len(invalid_value)];
            let result = PackTopology::new(5, &fields_len, true, true);
            assert_eq!(
                result.err(),
                Some("len value exceeds 8"),
                "expected 'len value exceeds 8' error for Len({})",
                invalid_value
            );

            // Counter
            let fields_counter = vec![PakFields::Counter(invalid_value)];
            let result = PackTopology::new(5, &fields_counter, true, true);
            assert_eq!(
                result.err(),
                Some("counter value exceeds 8"),
                "expected 'counter value exceeds 8' error for Counter({})",
                invalid_value
            );

            // IdOfSender
            let fields_id_sender =
                vec![PakFields::Counter(2), PakFields::IdOfSender(invalid_value)];
            let result = PackTopology::new(5, &fields_id_sender, true, true);
            assert_eq!(
                result.err(),
                Some("idofsender value exceeds 8"),
                "expected 'idofsender value exceeds 8' error for IdOfSender({})",
                invalid_value
            );

            // IdReceiver
            let fields_id_receiver =
                vec![PakFields::Counter(2), PakFields::IdReceiver(invalid_value)];
            let result = PackTopology::new(5, &fields_id_receiver, true, true);
            assert_eq!(
                result.err(),
                Some("idreceiver value exceeds 8"),
                "expected 'idreceiver value exceeds 8' error for IdReceiver({})",
                invalid_value
            );

            // HeadCRC
            let fields_crc = vec![
                PakFields::Counter(2),
                PakFields::HeadCRC(invalid_value),
                PakFields::Len(3),
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
            let fields_nonce = vec![PakFields::Nonce(invalid_value)];
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
            let fields_ttl = vec![PakFields::Counter(2), PakFields::TTL(invalid_value)];
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
        let fields_len = vec![PakFields::IdConnect(9), PakFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields_len, true, true).err(),
            Some("idconn value exceeds 8")
        );

        // Duplicate
        let fields_dup = vec![
            PakFields::IdConnect(4),
            PakFields::IdConnect(4), // Duplicate
            PakFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_dup, true, true).err(),
            Some("duplicate idconn")
        );
    }

    #[test]
    fn test_header_only_config() {
        let fields = vec![PakFields::Counter(4)];
        let result = PackTopology::new(0, &fields, true, false);
        assert_eq!(result.err(), Some("!!tag_len ==0"));
    }

    #[test]
    fn test_zero_ttl() {
        let fields = vec![PakFields::TTL(0), PakFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some("TTL value exceeds MAXIMAL_TTL_LEN or  == 0")
        );
    }

    #[test]
    fn test_max_length_fields() {
        // Valid max lengths
        let fields_valid = vec![
            PakFields::HeadCRC(32), // MAXIMAL_CRC_LEN
            PakFields::Nonce(32),   // MAXIMAL_NONCE_LEN
            PakFields::TTL(8),      // MAXIMAL_TTL_LEN
            PakFields::Counter(4),
            PakFields::Len(2),
        ];
        assert!(PackTopology::new(5, &fields_valid, true, true).is_ok());

        // Exceed max lengths
        let fields_invalid = vec![
            PakFields::HeadCRC(33), // > MAXIMAL_CRC_LEN
            PakFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_invalid, true, true).err(),
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0")
        );
    }

    #[test]
    fn test_userfield_edge_cases() {
        // Duplicate
        let fields_dup = vec![
            PakFields::UserField(10),
            PakFields::UserField(5), // Duplicate
            PakFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_dup, true, true).err(),
            Some("duplicate userfield")
        );

        // Zero length
        let fields_zero = vec![
            PakFields::UserField(0), // Invalid
            PakFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_zero, true, true).err(),
            Some("userfield value is 0")
        );
    }

    #[test]
    fn test_mismatched_id_lengths() {
        let fields = vec![
            PakFields::IdOfSender(4),
            PakFields::IdReceiver(8), // Different length
            PakFields::Counter(4),
            PakFields::Len(2),
        ];
        let result = PackTopology::new(5, &fields, true, true);
        assert_eq!(
            result.err(),
            Some("id_of_receiver_slice and id_of_sender_slice must be the same length")
        );

        let fields = vec![PakFields::Counter(4)];
        let result = PackTopology::new(5, &fields, true, true);
        assert_eq!(
            result.err(),
            Some("If your data channel is like TCP, you should specify the Len(usize) field.")
        );
    }
}
