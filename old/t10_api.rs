enum Errs {
    PaskageIsDecryptFall,
}

struct Wisless {}

impl Wisless {
    pub fn new_conn() -> Result<bool, bool> {
        Ok(true)
    }

    pub fn pack_to_send(
        if_tcp_stream_id: Option<u64>,
        id_of_conn: &u64,
        packages_to_send: &Box<Box<[u8]>>,
    ) -> Result<bool, bool> {
        Ok(true)
    }

    pub fn recv_to_data(
        if_tcp_stream_id: Option<u64>,
        id_of_conn: &u64,
        packages_to_send: &Box<Box<[u8]>>,
    ) -> Result<bool, bool> {
        Ok(true)
    }

    pub fn kill_conn(id_of_conn: &u64) -> Result<bool, bool> {
        Ok(true)
    }
}
