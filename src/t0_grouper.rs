use crate::t0pology::*;

pub struct GroupTopology {
    topologs: Box<[PackTopology]>,
    indexer: usize,
    max_min_len: usize,
    min_min_len: usize,
    //
    all_have_len: bool,
    all_have_crc: bool,
    all_have_idconn: bool,
    all_have_id_rec_send: bool,
    all_have_ttl: bool,
    all_have_ctr: bool,
    all_have_nonce: bool,
}

impl GroupTopology {
    pub fn new(
        input_topoler: &[(Box<[PackFields]>, u8)],
        tag_len: usize,
        data_save: bool,
        tcp_mode: bool,
    ) -> Result<Self, &'static str> {
        let mut all_have_len = true;
        let mut all_have_crc = true;
        let mut all_have_idconn = true;
        let mut all_have_id_rec_send = true;
        let mut all_have_ttl = true;
        let mut all_have_ctr = true;
        let mut all_have_nonce = true;
        //
        let mut max_min_len = 0;
        let mut min_min_len = !0;
        //

        let mut pos_tbyte = None;
        let mut ret_ve = vec![];

        let mut ret_ve_temp = vec![];

        for x in input_topoler.iter() {
            let ret = PackTopology::new(tag_len, &x.0, data_save, tcp_mode)?;

            all_have_crc &= ret.crc_slice.is_some();
            all_have_len &= ret.len_slice.is_some();
            all_have_idconn &= ret.idconn_slice().is_some();
            all_have_ttl &= ret.ttl_slice.is_some();
            all_have_nonce &= ret.nonce_slice.is_some();
            all_have_id_rec_send &= ret.id_of_receiver_slice.is_some();
            all_have_ctr &= ret.counter_slice.is_some();

            if let Some(ttbb) = ret.tricky_byte() {
                if ttbb != pos_tbyte.unwrap_or(ttbb) {
                    return Err(
                        "in all topology variants, tricky_byte must occupy the same position relative to the beginning of the packet",
                    );
                }
                pos_tbyte = Some(ttbb)
            } else {
                return Err("All packet topology variants must have tricky_byte()");
            }

            if max_min_len < ret.total_minimal_len() {
                max_min_len = ret.total_minimal_len()
            }
            if min_min_len > ret.total_minimal_len() {
                min_min_len = ret.total_minimal_len()
            }

            ret_ve.push(ret);
            ret_ve_temp.push(x.1);
        }

        Ok(Self {
            topologs: ret_ve.into_boxed_slice(),
            indexer: 0,
            max_min_len,
            min_min_len,
            all_have_len,
            all_have_crc,
            all_have_idconn,
            all_have_id_rec_send,
            all_have_ttl,
            all_have_ctr,
            all_have_nonce,
        })
    }
}

fn check(input_topoler: &[(Box<[PackFields]>, u8)]) -> Result<usize, &'static str> {
    // Sorted list of prime numbers. u8::MAX serves as a sentinel to ensure
    // we always have a value >= any possible input length (since a length is a usize,
    // but here we only compare with u8 values; u8::MAX = 255 is safe as an upper bound).
    let prime_num = [
        2,
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
        137,
        139,
        149,
        151,
        157,
        163,
        167,
        173,
        179,
        181,
        191,
        193,
        197,
        199,
        211,
        223,
        227,
        229,
        233,
        239,
        241,
        251,
        u8::MAX,
    ];

    let target_len = input_topoler.len();

    // Binary search for the first prime >= target_len.
    // partition_point returns the index where the predicate (p < target_len) becomes false.
    let index = prime_num.partition_point(|&p| (p as usize) < target_len);

    if index == prime_num.len() {
        panic!(
            "No suitable prime number (target length {} > u8::MAX)",
            target_len
        );
    }

    // Determine how many primes to print: up to 5, but not beyond the array end.
    let end = (index + 5).min(prime_num.len());
    let primes_to_show = &prime_num[index..end];

    for ii in primes_to_show {
        let mut temp_bit_check = vec![0; *ii as usize];

        let mut is_corect_len = true;

        for topl in input_topoler {
            temp_bit_check[(topl.1 as usize) % (*ii)] += 1;
            if temp_bit_check[topl.1 as usize] > 1 {
                is_corect_len = false;
                break;
            }
            if is_corect_len {
                return Ok(*ii as usize);
            }
        }
    }
    // Print the found primes. Example: for target_len = 239, prints [239, 241, 251, 255]
    //println!("Primes >= {} (max 5): {:?}", target_len, primes_to_show);
    Err(
        "Unfortunately, for such a data set, namely, the u8 values in the Box<[PackFields]>, u8 array, it is not possible to create a short and efficient enough array of values to accommodate all the topology variants, or perhaps you have several identical u8 values.",
    )
}
