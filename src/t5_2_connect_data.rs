use crate::t5_connect_data::*;
use crate::wt1types::*;

impl<
    Tnoncer: Noncer,
    TThrasher: Thrasher,
    Tudp: Clone,
    Twait: Clone,
    Tencrypt: EncWis,
    TRandomer: Randomer,
    TCfcser: Cfcser,
    Hmaker: HandMaker,
> WsConnection<Tnoncer, TThrasher, Tudp, Twait, Tencrypt, TRandomer, TCfcser, Hmaker>
{
}
