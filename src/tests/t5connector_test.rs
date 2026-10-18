use crate::t1queues::{WSFbackQueue, WSUdpLike};
use crate::t5conn_new::*;

use crate::impl_ws_connection;
use crate::w1types::{
    Crcser, EncWis, EndCryptStuctor, HandMaker, Identified, MyRole, Noncer, PackScheme, Randomer,
    Thrasher, TrickyBMaker, WisErr,
};
//EndCpt: EndCryptStuctor + Clone,
//#[cfg(test)]
use crate::w1types::PackAddedStatus;
use std::rc::Rc;

#[cfg(test)]
type Dumdwcn = WsConnection<
    DumpNonser,
    DumpThrasher<String>, // Передали <u32> внутрь структуры заглушки
    DumpEnc,
    DumpRandomer,
    DumpCrcser,
    DumpHandMaker<DumpEndCrypt>,
    DumpTricker<String>, // Заменили трейт TrickyBMaker на конкретный тип-заглушку
    String,
    DumpEndCrypt,
>;

#[cfg(test)]
use crate::t1dumb_srct::*;
#[cfg(test)]
use crate::{t0pology, t4param};
#[cfg(test)]
///for test only
///
#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::float_cmp)]
pub fn fast_wconn_maker() -> Dumdwcn {
    use crate::w1types::Ttl;

    let fields = vec![
        //t2page::PackFields::HeadByte,
        t0pology::PackFields::Counter(7),
        t0pology::PackFields::IdConnect(6),
        t0pology::PackFields::UserField(10),
        t0pology::PackFields::HeadCRC(4),
        t0pology::PackFields::TTL(4),
    ];

    let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();

    let ttl = Ttl::new(100, -1, 20, false).unwrap();

    let result = t4param::base_builder_pub(po)
        .ttl_max_start_cost(ttl)
        .build()
        .unwrap();

    let seeds = Seeds {
        nonce: Some(Box::new([2, 2, 2, 2])),
        random: Some(Box::new([3, 3, 3, 3])),
        user_field: Some(Box::new([5, 5, 5, 5u8])),
        crc: Some(Box::new([6, 4, 4, 4])),
        handmaker: Box::new([9, 9, 9, 9u8]),
        tricky: Some(Box::new([7, 7, 7, 7u8])),
    };

    let ret = <Dumdwcn>::new(
        &result,
        &[1, 1, 1, 1],
        MyRole::Initiator,
        &seeds,
        &Identified {
            my_metall_id: 999,
            my_s_r_id: None,
            id_conn: Some((999, MyRole::Initiator)),
        },
    )
    .unwrap();
    ret.clone()
}

#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod test_new {

    use super::*;

    use crate::w1types::{Ids, Ttl};
    use crate::{t0pology, t4param};
    #[test]
    fn idconn_slice() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };
        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "connect_param.pack_topology().idconn_slice().is_some() == identified.id_conn.is_none()\
                 you need to set a value".to_string()
            )
        );
    }

    #[test]
    fn idconn_slice_inv() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .mtu(9876)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Dumdwcn = <Dumdwcn>::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: Some((999, MyRole::Initiator)),
            },
        )
        .unwrap();

        let mut a0 = 1;
        let mut a10000 = 100000;
        let mut aerr = (!0u64) ^ 0b1;

        assert_eq!(te1.connect_param().mtu(), 9876);

        assert_eq!(te1.non_alloc_buf.len(), te1.connect_param().mtu());
        //   assert_eq!(te1.non_alloc_buf.0, None);

        assert_eq!(add_two(&mut a0), Ok(()));
        assert_eq!(add_two(&mut a10000), Ok(()));
        assert_eq!(
            add_two(&mut aerr),
            Err(
                "The capacity limit of the main counter u64 has been reached, so it is no longer \
                 possible to send new messages over this connection. The connection must be \
                 closed!"
                    .to_string()
            )
        );

        assert_eq!(a0, 3);
        assert_eq!(a10000, 100002)
    }

    #[test]
    fn id_of_sender_slice() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "connect_param.pack_topology().id_of_sender_slice().is_some()!= identified.my_s_r_id.is_some() you need to set a value for identified.my_s_r_id".to_string()
            )
        );
    }

    #[test]
    fn id_of_sender_slice_inv1() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3333,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "identified.id_receiver == identified.id_sender The sender and recipient IDs must \
                 be different!"
                    .to_string()
            )
        );
    }

    #[test]
    fn id_of_sender_slice_inv2() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();
        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };
        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.is_ok());
    }

    #[test]
    fn nonce_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
            t0pology::PackFields::Nonce(10),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: None, //Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "nonce_seed is none but connect_param.pack_topology().nonce_slice().is_some() == \
                 true"
                    .to_string()
            )
        );
    }

    #[test]
    fn nonce_gener_inv() {
        let fields = vec![
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
            t0pology::PackFields::Nonce(10),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.is_ok());
        let ty2 = &te1.unwrap();

        assert!(!ty2.was_killed);

        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .nonce_gener
                .as_ref()
                .unwrap()
                .v,
            vec![2, 2, 2, 2]
        );
        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .user_field_gener
                .as_ref()
                .unwrap()
                .v,
            vec![5, 5, 5, 5u8]
        );
        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .crc_gener
                .as_ref()
                .unwrap()
                .v,
            vec![6, 4, 4, 4]
        )
    }

    #[test]
    fn user_field_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: None, // Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "user_field_seed is none but \
                 connect_param.pack_topology().trash_content_slice().is_some() == true, \
                 `trash_content_slice() is user_field` "
                    .to_string()
            )
        );
    }

    #[test]
    fn user_field_gener_inv() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.is_ok());
        let ty2 = &te1.unwrap();

        assert!(!ty2.was_killed);

        assert_eq!(
            ty2.fuck_mut_struct
                .try_borrow()
                .unwrap()
                .user_field_gener
                .as_ref()
                .unwrap()
                .v,
            vec![5, 5, 5, 5]
        );
        assert_eq!(ty2.enrypaaa._private_seed, [9, 9, 9, 9u8].into());
    }

    #[test]
    fn random_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(Some(0.3))
            .length_trimming_range(Some(11))
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, // Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "random_seed is none but connect_param.need_init_random() == true".to_string()
            )
        );
    }

    #[test]
    fn random_gener_inv1() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(Some(0.3))
            //.percent_fake_fback_packets(Some(0.3))
            //.percent_len_random_coefficient(Some(0.3))
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(te1.unwrap().random_gener.unwrap().v, vec![3, 3, 3, 3]);
    }

    #[test]
    fn random_gener_inv2() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, //Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.unwrap().random_gener.is_none());
    }

    #[test]
    fn cfc_gener() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, // Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: None, //Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.err().unwrap(),
            WisErr::Critical(
                "crc_seed is none but connect_param.pack_topology().head_crc_slice().is_some() == \
                 true"
                    .to_string()
            )
        );
    }

    #[test]
    fn cfc_gener_inv1() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: None, // Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([5, 5, 5, 5])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert_eq!(
            te1.unwrap()
                .fuck_mut_struct
                .try_borrow()
                .unwrap()
                .crc_gener
                .clone()
                .unwrap()
                .v,
            vec![5, 5, 5, 5]
        );
    }

    #[test]
    fn cfc_gener_inv2() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdReceiver(6),
            t0pology::PackFields::IdSender(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .percent_fake_any_packets(None)
            .length_trimming_range(None)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        assert!(!result.need_init_random());

        let seeds = Seeds {
            nonce: None,  // Some(Box::new([2, 2, 2, 2])),
            random: None, //Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let te1: Result<Dumdwcn, WisErr<String, String>> = WsConnection::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: Some(Ids {
                    id_receiver: 3333,
                    id_sender: 3331,
                }),

                id_conn: None,
            },
        );

        assert!(te1.unwrap().random_gener.is_none());
    }

    #[test]
    fn add_to() {
        let mut h = 1;
        assert!(add_two(&mut h).is_ok());
        assert_eq!(h, 3);
        assert!(add_two(&mut h).is_ok());
        assert_eq!(h, 5);

        h = u64::MAX - 1;

        assert_eq!(
            add_two(&mut h),
            Err(
                "The capacity limit of the main counter u64 has been reached, so it is no longer \
                 possible to send new messages over this connection. The connection must be \
                 closed!"
                    .to_string()
            )
        );
    }
}

#[allow(clippy::items_after_test_module)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::float_cmp)]
#[cfg(test)]
mod test_api {

    use super::*;
    use crate::w1types::Ttl;
    use crate::{t0pology, t4param};

    #[test]
    fn api_tets() {
        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::Counter(7),
            t0pology::PackFields::IdConnect(6),
            t0pology::PackFields::UserField(10),
            t0pology::PackFields::HeadCRC(4),
            t0pology::PackFields::TTL(4),
        ];

        let po = t0pology::PackTopology::new(5, &fields, true, false).unwrap();
        let ttl = Ttl::new(100, -1, 20, false).unwrap();
        let result = t4param::base_builder_pub(po)
            .ttl_max_start_cost(ttl)
            .build()
            .unwrap();

        let seeds = Seeds {
            nonce: Some(Box::new([2, 2, 2, 2])),
            random: Some(Box::new([3, 3, 3, 3])),
            user_field: Some(Box::new([5, 5, 5, 5u8])),
            crc: Some(Box::new([6, 4, 4, 4])),
            handmaker: Box::new([9, 9, 9, 9u8]),
            tricky: Some(Box::new([7, 7, 7, 7u8])),
        };

        let mut te1: Dumdwcn = <Dumdwcn>::new(
            &result,
            &[1, 1, 1, 1],
            MyRole::Initiator,
            &seeds,
            &Identified {
                my_metall_id: 999,
                my_s_r_id: None,
                id_conn: Some((999, MyRole::Initiator)),
            },
        )
        .unwrap();

        assert_eq!(DATA_START_CTR, te1.frend_ctr_data());
        assert_eq!(DATA_START_CTR, te1.my_ctr_data());
        assert_eq!(FBACK_START_CTR, te1.frend_ctr_fback());
        assert_eq!(FBACK_START_CTR, te1.my_ctr_fback());

        te1.ctrs.frend_data = 1000;
        te1.ctrs.my_data = 1111;
        te1.ctrs.frend_fback = 2222;
        te1.ctrs.my_fback = 3333;

        assert_eq!(1000, te1.frend_ctr_data());
        assert_eq!(1111, te1.my_ctr_data());
        assert_eq!(2222, te1.frend_ctr_fback());
        assert_eq!(3333, te1.my_ctr_fback());

        //===========
        assert_eq!(MyRole::Initiator, te1.my_role());

        te1.my_role = MyRole::Passive;

        assert_eq!(MyRole::Passive, te1.my_role());

        assert_eq!(te1.handshake_is_end(), te1.handshake_is_end);

        assert!(!te1.handshake_is_end());

        te1.handshake_is_end = true;

        assert!(te1.handshake_is_end());
        //===========
        assert_eq!(te1.network_latency, te1.network_latency());
        assert_eq!(te1.network_latency, 0.0);
        te1.network_latency = 1234567.1;
        assert_eq!(1234567.1, te1.network_latency());

        //===========

        assert_eq!(te1.network_unstability, te1.network_unstability());
        assert_eq!(te1.network_unstability, 0.0);
        te1.network_unstability = 98765.0;
        assert_eq!(98765.0, te1.network_unstability());

        //===========

        assert_eq!(
            te1.measurement_window_latency,
            te1.measurement_window_latency()
        );
        te1.measurement_window_latency = 11198765.0;
        assert_eq!(11198765.0, te1.measurement_window_latency());

        //===========

        assert_eq!(te1.identified().clone(), te1.identified.clone());
        te1.identified.my_metall_id = 999_111_222;

        assert_eq!((te1.identified()).my_metall_id, 999_111_222);

        //===========
        let x1 = te1.connect_param().clone();
        let x2 = te1.connect_param.clone();
        assert_eq!(x1, x2);

        let mut tx = 0;
        add_two(&mut tx).unwrap();

        assert_eq!(tx, 2);
        add_two(&mut tx).unwrap();

        assert_eq!(tx, 4);
        add_two(&mut tx).unwrap();

        assert_eq!(tx, 6);
    }
}

#[cfg(test)]
mod tests_get_needy_pack_param {
    #![allow(clippy::unwrap_used)]
    use super::*; // Imports the items from the outer module (PackScheme, get_needy_pack_param, etc.)
    use crate::{
        t0grouper::GroupTopology, t0pology::PackFields, t0pology::PackTopology,
        w1types::PackTypeGroup,
    };

    // Helper to create a PackTopology with default parameters.
    // - tag_len = 16 (arbitrary, but valid)
    // - data_save = true (so HeadCRC is not required)
    // - tcp_mode = false (so Len is not required)
    fn make_topology(fields: &[PackFields]) -> PackTopology {
        PackTopology::new(16, fields, true, false).unwrap()
    }

    // Expected NeedyParam for a single PackTopology.
    fn expected_from_topo(topo: &PackTopology) -> NeedyParam {
        NeedyParam {
            idconn_slice_any: topo.idconn_slice().is_some(),
            id_of_sender_slice_any: topo.id_of_sender_slice().is_some(),
            counter_slice_any: topo.counter_slice().unwrap().2, // safe: always Some
            head_crc_slice_any: topo.head_crc_slice().is_some(),
            nonce_slice_any: topo.nonce_slice().is_some(),
            any_trash_content_slice: topo.trash_content_slice().is_some(),
            need_tricky: false,
        }
    }

    // Expected NeedyParam for a GroupTopology.
    // Note: for GroupPack, the “any” flags are true if the field exists in *any* topology.
    fn expected_from_group(group: &GroupTopology) -> NeedyParam {
        NeedyParam {
            idconn_slice_any: group.all_have_idconn_field().is_some(),
            id_of_sender_slice_any: group.all_have_id_sender_receiver_fields().is_some(),
            counter_slice_any: group.all_have_counter_field().unwrap().1, // safe: always Some
            head_crc_slice_any: group.all_have_crc_field().is_some(),
            nonce_slice_any: group.all_have_nonce_field().is_some(),
            any_trash_content_slice: group.any_have_trash_field(),
            need_tricky: group.how_elems_in_me() > 1,
        }
    }

    // Compare results from OnePack and GroupPack for the same single topology.
    #[test]
    fn single_topology_consistency() {
        // Define a variety of field combinations (Counter is always present).
        let field_sets = vec![
            vec![PackFields::Counter(1)],
            vec![PackFields::Counter(1), PackFields::IdConnect(1)],
            vec![
                PackFields::Counter(1),
                PackFields::IdSender(1),
                PackFields::IdReceiver(1),
            ],
            vec![PackFields::Counter(1), PackFields::HeadCRC(1)],
            vec![PackFields::Counter(1), PackFields::Nonce(1)],
            vec![PackFields::Counter(1), PackFields::UserField(1)],
            vec![
                PackFields::Counter(1),
                PackFields::IdConnect(1),
                PackFields::HeadCRC(1),
                PackFields::Nonce(1),
                PackFields::UserField(1),
                PackFields::IdSender(1),
                PackFields::IdReceiver(1),
            ],
            // Additional combination: id_sender/receiver without idconn, etc.
            vec![
                PackFields::Counter(1),
                PackFields::IdSender(1),
                PackFields::IdReceiver(1),
                PackFields::HeadCRC(1),
            ],
            vec![
                PackFields::Counter(1),
                PackFields::IdConnect(1),
                PackFields::Nonce(1),
                PackFields::UserField(1),
            ],
        ];

        for fields in field_sets {
            let topo = make_topology(&fields);

            // Test OnePack
            let scheme_one = PackScheme::OnePack(topo.clone());
            let result_one = get_needy_pack_param(&scheme_one).unwrap();
            let expected_one = expected_from_topo(&topo);
            assert_eq!(result_one, expected_one);

            // Build a GroupTopology containing exactly this topology (key = 0)
            let group_input = vec![(fields.clone().into_boxed_slice(), PackTypeGroup::Any, 0)];
            let topo = GroupTopology::new(&group_input, 16, true, false).unwrap();

            // Test GroupPack
            let scheme_group = PackScheme::GroupPack(topo.clone());
            let mut result_group = get_needy_pack_param(&scheme_group).unwrap();
            let mut expected_group = expected_from_group(&topo);

            assert_ne!(result_group, expected_group);

            assert!(result_group.need_tricky);
            assert!(!expected_group.need_tricky);

            result_group.need_tricky = false;
            expected_group.need_tricky = false;

            assert_eq!(result_group, expected_group);
            // Both schemes must produce identical results for a single topology.
            assert_eq!(result_one, result_group);
        }
    }

    // Test GroupPack with multiple topologies where fields differ.
    #[test]
    fn group_multiple_topologies() {
        // Case 1: two topologies with disjoint fields.
        let fields1 = vec![
            PackFields::Counter(1),
            PackFields::TrickyByte,
            PackFields::IdConnect(1),
        ];
        let fields2 = vec![
            PackFields::IdConnect(1),
            PackFields::TrickyByte,
            PackFields::Counter(1),
        ];
        let group_input = vec![
            (fields1.into_boxed_slice(), PackTypeGroup::Any, 0),
            (fields2.into_boxed_slice(), PackTypeGroup::Any, 1),
        ];
        let topo = GroupTopology::new(&group_input, 16, true, false).unwrap();
        let result = get_needy_pack_param(&PackScheme::GroupPack(topo.clone())).unwrap();
        let expected = expected_from_group(&topo);
        assert_eq!(result, expected);
        // idconn exists in at least one, nonce exists in at least one,
        // but id_of_sender and head_crc and trash are absent from all.
        assert!(result.idconn_slice_any);
        assert!(!result.id_of_sender_slice_any);
        assert!(!result.nonce_slice_any);
        assert!(!result.head_crc_slice_any);
        assert!(!result.any_trash_content_slice);

        // Case 2: one topology has trash, another does not.
        let fields3 = vec![
            PackFields::Counter(1),
            PackFields::TrickyByte,
            PackFields::UserField(1),
        ];
        let fields4 = vec![PackFields::Counter(1), PackFields::TrickyByte];
        let group_input2 = vec![
            (fields3.into_boxed_slice(), PackTypeGroup::Any, 0),
            (fields4.into_boxed_slice(), PackTypeGroup::Any, 1),
        ];
        let topo = GroupTopology::new(&group_input2, 16, true, false).unwrap();
        let result2 = get_needy_pack_param(&PackScheme::GroupPack(topo.clone())).unwrap();
        let expected2 = expected_from_group(&topo);
        assert_eq!(result2, expected2);
        assert!(result2.any_trash_content_slice);
    }

    // Verify that counter length is correctly extracted for both schemes.
    #[test]
    fn counter_length_extraction() {
        let len = 4;
        let fields = vec![PackFields::Counter(len)];
        let topo = make_topology(&fields);

        // OnePack
        let result_one = get_needy_pack_param(&PackScheme::OnePack(topo.clone())).unwrap();
        assert_eq!(result_one.counter_slice_any, len);

        // GroupPack (single topology)
        let group_input = vec![(fields.clone().into_boxed_slice(), PackTypeGroup::Any, 0)];
        let topo = GroupTopology::new(&group_input, 16, true, false).unwrap();
        let result_group = get_needy_pack_param(&PackScheme::GroupPack(topo.clone())).unwrap();
        assert_eq!(result_group.counter_slice_any, len);
    }
}

#[cfg(test)]

impl_ws_connection! {
    #[cfg(test)]
    ///get_udp f
    pub fn test_get_fback(&mut self) -> &mut WSFbackQueue<f32> {
        &mut self.fback_queue
    }
    #[cfg(test)]
    ///get_udp
    pub fn test_get_udp(&mut self) -> &mut WSUdpLike<Rc<[u8]>> {
        &mut self.udp_queue
    }
    #[cfg(test)]
    ///swap_udp fb
    pub fn test_swap_fback(&mut self, fb: WSFbackQueue<f32>) {
        self.fback_queue = fb;
    }
    #[cfg(test)]
    ///swap_udp q
    pub fn test_swap_udp(&mut self, udp: WSUdpLike<Rc<[u8]>>) {
        self.udp_queue = udp;
    }
}

#[cfg(test)]
mod test_get_queque_process {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    //#![deny(clippy::expect_used)]
    #![allow(clippy::unreachable)]
    #![allow(clippy::todo)]
    #![allow(clippy::float_cmp)]
    use super::*;
    use std::rc::Rc;

    #[test]
    fn test_get_queque_process() {
        let mut tw = fast_wconn_maker();

        let mut vv: Vec<(usize, f32, Rc<[u8]>)> = Vec::with_capacity(90);

        for x in 0..vv.capacity() {
            vv.push((x, x as f32 * 1.234, Rc::from(vec![1; 10])));
        }
        for len_f in [7, 17, 30] {
            for len_u in [7, 17, 30] {
                let fb = WSFbackQueue::<f32>::new(3, len_f, 1000).unwrap();
                let ud = WSUdpLike::new(len_u).unwrap();

                tw.test_swap_udp(ud);
                tw.test_swap_fback(fb);

                for (i, d) in vv.iter().enumerate() {
                    let mut need_clean = true;

                    let test = tw.get_queque_process(d.0 as u64, d.1, d.2.clone()).unwrap();

                    // println!("{:?}, i {}  lf {}   lu {}", test.clone(), i, len_f, len_u);
                    let min = std::cmp::min(len_f, len_u);
                    if test == PackAddedStatus::WasAdded {
                        need_clean = false;

                        //println!("{}", i % (min + 1));
                        assert_ne!(i % (min + 1), min)
                    } else {
                        assert_ne!(i % std::cmp::min(len_f, len_u), min);
                        assert_eq!(i % (min + 1), min);
                        // println!(" =========== qq {}", min);
                        if len_f <= len_u {
                            assert_eq!(test, PackAddedStatus::FbackQueueIsfull);
                        } else if len_f > len_u {
                            assert_eq!(test, PackAddedStatus::UdpQueueCtrIsBig);
                        } else {
                            panic!("inreal test state!");
                        }
                    }

                    if need_clean {
                        {
                            let ffb = tw.test_get_fback();
                            let _ = ffb.get_ctrs_as_byte_pack_vec();
                        }

                        let uud = tw.test_get_udp();

                        let _ = uud.insert(d.0 as u64, &d.2.clone());
                        let _ = uud.get_queue(None);
                        let _ = uud.insert(d.0 as u64, &d.2.clone()); //double add double dell
                        let _ = uud.get_queue(None); // double dell
                    }
                    // println!("{:?}", test);
                }
            }
        }
    }

    #[test]
    fn test_one_shuf() {
        let mut x1 = vec![];
        for i in 0..10000 {
            x1.push(i);
        }
        let x = x1.clone();

        for m in [3isize, 10, 14, 20].iter() {
            let mut etalon = x.clone();

            let mut ct = 0;
            shuffle_with_limited_displacement(&mut etalon, *m as usize);

            for yy in etalon.iter().zip(x.iter()) {
                let mut r = *yy.0 - *yy.1;

                if r < 0 {
                    r *= -1;
                }

                assert!(r <= *m, "{m}");

                ct += (*yy.0 == *yy.1) as i32;
            }
            assert!(0.38 > (ct as f32 / x.len() as f32)); //first m = 3, 1/3 =0.33333, 0.38 > 0.33 +-0.05
            println!("{}", ct as f32 / x.len() as f32);
        }
    }

    fn shuffle_with_limited_displacement<T>(vec: &mut [T], mm: usize) {
        let n = vec.len();
        if n == 0 || mm == 0 {
            return;
        }

        let block_size = mm + 1;
        let mut seed = 123456789u64; //seed

        let mut start = 0;
        while start < n {
            let end = (start + block_size).min(n);
            let _len = end - start;

            // Перемешивание блока [start, end) алгоритмом Фишера-Йетса
            for i in (start..end).rev() {
                // Генерация псевдослучайного числа в диапазоне [start, i]
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                let offset = (seed >> 16) as usize % (i - start + 1);
                let j = start + offset;
                vec.swap(i, j);
            }

            start = end;
        }
    }
}

#[cfg(test)]
mod test_sender {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    //#![deny(clippy::expect_used)]
    #![allow(clippy::unreachable)]
    #![allow(clippy::todo)]
    #![allow(clippy::float_cmp)]

    #[test]
    fn test_get_queque_process() {}
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::as_conversions)]
    #![allow(clippy::arithmetic_side_effects)]
    #![allow(clippy::integer_division)]
    //#![deny(clippy::expect_used)]
    #![allow(clippy::unreachable)]
    #![allow(clippy::todo)]
    #![allow(clippy::float_cmp)]

    use super::*;

    use crate::w1types::*;

    type TestConn = Dumdwcn;

    fn make_test_conn() -> TestConn {
        fast_wconn_maker()
    }

    fn rc_bytes(bytes: &[u8]) -> Rcc<Box<[u8]>> {
        Rcc::new(bytes.to_vec().into_boxed_slice())
    }

    #[test]
    fn paste_file_errors_if_connection_killed() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = true;
        conn.was_killed = true;

        let err = conn.paste_file(rc_bytes(b"abc")).unwrap_err();

        assert!(matches!(
            err,
            WTypeErr::WorkTimeErr(ref s) if s == "connect_is kill"
        ));
    }

    #[test]
    fn paste_file_errors_before_handshake() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = false;
        conn.was_killed = false;

        let err = conn.paste_file(rc_bytes(b"abc")).unwrap_err();

        assert!(matches!(
            err,
            WTypeErr::WorkTimeErr(ref s)
                if s == "connection during the key installation process"
        ));
    }

    #[test]
    fn paste_file_maps_file_splitter_error() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = true;
        conn.was_killed = false;

        let err = conn.paste_file(rc_bytes(b"")).unwrap_err();

        assert!(matches!(
            err,
            WTypeErr::WorkTimeErr(ref s) if s.contains("greater than zero")
        ));
    }

    #[test]
    fn paste_file_ok_after_handshake() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = true;
        conn.was_killed = false;

        conn.paste_file(rc_bytes(b"abc")).unwrap();

        assert!(conn.file_splitter.i_have_some_send());
    }

    #[test]
    fn paste_file_errors_if_file_already_exists() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = true;
        conn.was_killed = false;

        conn.paste_file(rc_bytes(b"abc")).unwrap();

        let err = conn.paste_file(rc_bytes(b"def")).unwrap_err();

        assert!(matches!(err, WTypeErr::WorkTimeErr(_)));
    }

    #[test]
    fn check_paste_file_false_if_killed() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = true;
        conn.was_killed = true;

        assert!(!conn.check_paste_file());
    }

    #[test]
    fn check_paste_file_false_before_handshake() {
        let mut conn = make_test_conn();
        conn.handshake_is_end = false;
        conn.was_killed = false;

        assert!(!conn.check_paste_file());
    }

    #[test]
    fn check_paste_file_false_if_killed_even_when_file_exists() {
        let mut conn = make_test_conn();
        conn.file_splitter
            .write_new_rc_file(rc_bytes(b"abc"))
            .unwrap();

        conn.handshake_is_end = true;
        conn.was_killed = true;

        assert!(!conn.check_paste_file());
    }

    #[test]
    fn check_paste_file_false_before_handshake_even_when_file_exists() {
        let mut conn = make_test_conn();
        conn.file_splitter
            .write_new_rc_file(rc_bytes(b"abc"))
            .unwrap();

        conn.handshake_is_end = false;
        conn.was_killed = false;

        assert!(!conn.check_paste_file());
    }

    #[test]
    fn check_paste_file_current_behavior_is_true_when_file_exists() {
        let mut conn = make_test_conn();

        conn.handshake_is_end = true;
        conn.was_killed = false;

        assert!(conn.check_paste_file());

        conn.paste_file(rc_bytes(b"abc")).unwrap();

        assert!(!conn.check_paste_file());
    }
}
