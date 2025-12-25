use crate::t1pology::PackTopology;

use crate::t1fields;

/*

    IdOfSender(usize),
    IdReceiver(usize),
    Len(usize),
    Counter(usize),
    UserField(usize),
    HeadCRC(usize),
    TTL(usize),
    Nonce(usize),
    IdConnect(usize),

*/
pub struct Ids {
    pub id_sender: u64,
    pub id_receiver: u64,
}
///The UserField and Nonce fields are deliberately omitted here so as not to tempt users to enter sensitive data in these fields,
///  since Nonce is an entropy field that is only needed for encryption.
///The UserField field can only contain gibberish and 0% useful information.
pub struct PubFields {
    pub my_len: Option<usize>,
    pub my_rs_id: Option<Ids>,
    pub my_idconn: Option<u64>,
    pub my_ttl: Option<u64>,
    pub my_ctr: u64,
    pub is_fback: bool,
}

pub fn get_public_fields(topology: &PackTopology) {}

//trait  {

//}
