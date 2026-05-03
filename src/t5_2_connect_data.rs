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
include!("t5_connect_data.rs");
use crate::wt1types::{InFile, WTypeErr};
impl<
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
    TCfcser: Crcser,
    Hmaker: HandMaker,
> WsConnection<Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer, TCfcser, Hmaker>
{
    ///Create a new file to send; if a file already exists or the transfer is incomplete,
    /// an error will occur
    pub fn paste_file(&mut self, file: InFile<u8>) -> Result<(), WTypeErr> {
        self.file_splitter
            .write_new_rc_file(file)
            .map_err(WTypeErr::WorkTimeErr)
    }

    pub fn send_pack<F>(&mut self, _send_api: F) -> Result<(), WTypeErr>
    where
        F: FnMut(&[u8], bool) -> Result<(), &'static str>,
    {
        Ok(())
    }
    pub fn recv_pack(&mut self, _pack: &[u8], _full_id_of_pack: &Identified) {}
    pub fn send_fake_pack() {}

    fn get_blank_pack(&self, _minimal_usize: &usize) {
        //self.connect_param.

        //pre_alloc(topology, self.connect_param.mtu(), payloadlen, 0);
    }
}
