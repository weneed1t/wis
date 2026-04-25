#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]

include!("t5_connect_data.rs");

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
    pub fn paste_file() {}

    pub fn send_pack() {}
    pub fn recv_pack(&mut self, _pack: &[u8], _full_id_of_pack: &Identified) {
        //
        //id cherck old
        //
        /*
                let (ctr_frend, type_pack) = get_counter(
                    pack,
                    self.connect_param().pack_topology(),
                    self.frend_ctr_fback,
                    self.frend_ctr_data,
                )
                .unwrap();

        match type_pack {
            wt1types::PackType::Data => {},
            wt1types::PackType::FBack => {},
        }
         */
    }
    pub fn send_fake_pack() {}
}
