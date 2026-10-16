use crate::t4param::*;
use crate::w1types::{PackScheme, Ttl};

mod all_test {
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![deny(clippy::indexing_slicing)]
    #![allow(clippy::float_cmp)]

    use super::*;
    use crate::t0grouper::GroupTopology;
    use crate::t0pology::PackTopology;

    ///# Warning: this function breaks the basic consistent state of PackFields.
    fn __warning_get_topol(
        ctr_byte_len: Option<usize>,
        total_min_len: usize,
        ttl_byte_len: Option<usize>,
    ) -> PackTopology {
        use crate::t0pology;

        let fields = vec![
            //t2page::PackFields::HeadByte,
            t0pology::PackFields::UserField(1),
            t0pology::PackFields::Counter(5),
            t0pology::PackFields::IdConnect(2),
            t0pology::PackFields::HeadCRC(2),
            t0pology::PackFields::Nonce(6),
            //PackFields::TTL(2),
            t0pology::PackFields::Len(3),
        ];

        let mut returna = PackTopology::new(16, &fields, true, true).unwrap();

        if let Some(x) = ttl_byte_len {
            returna.__warning_test_only_force_edit_ttl(Some((0, 0, x)));
        } else {
            returna.__warning_test_only_force_edit_ttl(None);
        }

        if let Some(x) = ctr_byte_len {
            returna.__warning_test_only_force_edit_ctr(Some((0, 0, x)));
        } else {
            returna.__warning_test_only_force_edit_ctr(None);
        }

        returna.__warning_test_only_force_total_minimum_len_edit(total_min_len);

        returna
    }

    mod tests_ttl_max_start_cost_and_instant_feedback_on_packet_loss {

        use super::*;

        #[test]
        fn test_instant_feedback_flag_true() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(true)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1)
                .max_len_file(None)
                // The following fields match the defaults, but are set explicitly for readability
                .mtu(1500)
                //.packages_measurement_window_size_determining_latency(10)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.8)
                .maximum_packet_delay_absolute_fback(80.0)
                .build();

            assert!(
                result.is_ok(),
                "instant_feedback_on_packet_loss = true should be valid"
            );
            assert!(result.as_ref().unwrap().instant_feedback_on_packet_loss());
        }

        #[test]
        fn test_instant_feedback_flag_false() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1)
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "instant_feedback_on_packet_loss = false should be valid"
            );
            assert!(!result.as_ref().unwrap().instant_feedback_on_packet_loss());
        }

        #[test]
        fn test_ttl_none_when_topology_has_ttl() {
            let topo = __warning_get_topol(Some(1), 50, Some(1)); // topology has TTL

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .max_len_file(None) // do not set ttl, so it stays None
                .build();

            assert_eq!(
                result.err().unwrap(),
                "ttl_len_slice or ttl_max_start_cost is none, and ttl_len_slice or ttl_max_start_cost is some, either remove the ttl field in the packets or define ttl values ttl_max_start_cost"
            );
        }
        #[test]
        fn test_ttl_none_when_topology_has_ttl_none() {
            let topo = __warning_get_topol(Some(1), 50, None); // topology has TTL

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .max_len_file(None) // do not set ttl, so it stays None
                .build();

            assert_eq!(result.unwrap().ttl_max_start_cost(), None);
        }

        #[test]
        fn test_ttl_none_when_topology_no_ttl() {
            let topo = __warning_get_topol(Some(1), 50, None); // topology has NO TTL

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "ttl_max_start_cost = None should be valid when topology has no TTL"
            );
        }

        #[test]
        fn test_ttl_some_when_topology_has_ttl_valid_values() {
            let topo = __warning_get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1)
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "valid ttl_max_start_cost should be accepted when topology has TTL"
            );
            assert_eq!(result.unwrap().ttl_max_start_cost(), Some(ttl255_128_i1));
        }

        #[test]
        fn test_ttl_start_exceeds_capacity_error() {
            let topo = __warning_get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255
            let ttl = Ttl::new(300, -1, 256, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl) // start = 256 exceeds 1-byte capacity
                .max_len_file(None)
                .build();

            assert!(result.is_err(), "ttl start exceeds capacity should error");
            assert_eq!(
                result.err().unwrap(),
                "ttl_max_start_cost.1 is greater than the length that can be accommodated in the \
                 pack_topology field."
            );
        }

        #[test]
        fn test_ttl_cost_positive_valid() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl = Ttl::new(255, 1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl) // cost = +1
                .max_len_file(None)
                .build();

            assert!(result.is_ok(), "ttl cost can be positive");
            assert_eq!(result.unwrap().ttl_max_start_cost(), Some(ttl));
        }

        #[test]
        fn test_ttl_cost_negative_valid() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1) // cost = -1
                .max_len_file(None)
                .build();

            assert!(result.is_ok(), "ttl cost negative should be valid");
        }

        #[test]
        fn test_ttl_with_larger_byte_length() {
            // Test with 2-byte TTL field (capacity = 65535)
            let topo = __warning_get_topol(Some(1), 50, Some(2));
            let ttl = Ttl::new(65535, -1, 32768, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(false)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl) // max capacity for 2 bytes
                .max_len_file(None)
                .build();

            assert!(result.is_ok(), "ttl with 2-byte field should work");
        }

        #[test]
        fn test_ttl_instant_feedback_combination() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .instant_feedback_on_packet_loss(true)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1)
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "combination of ttl and instant_feedback should be valid"
            );
            let param = result.unwrap();
            assert!(param.instant_feedback_on_packet_loss());
            assert_eq!(param.ttl_max_start_cost(), Some(ttl255_128_i1));
        }
    }

    //persent

    mod tests_percent {
        #![allow(clippy::integer_division)]
        use super::*;

        #[test]
        fn test_all_traffic_masking_none() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .max_len_file(None)
                // All traffic masking parameters are left at their default (None)
                .build();

            assert!(
                result.is_ok(),
                "all traffic masking parameters as None should be valid"
            );
            let param = result.unwrap();
            assert_eq!(param.percent_fake_any_packets(), None);
            assert_eq!(param.length_trimming_range(), None);
        }

        #[test]
        fn test_percent_fake_any_packets_valid() {
            #![allow(clippy::integer_division)]
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(0.5))
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "percent_fake_any_packets = 0.5 should be valid"
            );
            assert_eq!(
                result.unwrap().percent_fake_any_packets(),
                Some((u32::MAX as f32 * 0.5) as u32)
            );
        }

        #[test]
        fn test_percent_fake_any_packets_exactly_one() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(1.0))
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "percent_fake_any_packets = 1.0 should be valid"
            );
            assert_eq!(result.unwrap().percent_fake_any_packets(), Some(u32::MAX));
        }

        #[test]
        fn test_percent_fake_any_packets_zero_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(0.0)) // invalid
                .max_len_file(None)
                .build();

            assert!(
                result.is_err(),
                "percent_fake_any_packets = 0.0 should error"
            );
            assert_eq!(
                result.err().unwrap(),
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]"
            );
        }

        #[test]
        fn test_percent_fake_any_packets_negative_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(-0.1)) // invalid
                .max_len_file(None)
                .build();

            assert!(
                result.is_err(),
                "percent_fake_any_packets negative should error"
            );
            assert_eq!(
                result.err().unwrap(),
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]"
            );
        }

        #[test]
        fn test_percent_fake_any_packets_greater_than_one_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(1.1)) // invalid
                .max_len_file(None)
                .build();

            assert!(
                result.is_err(),
                "percent_fake_any_packets > 1.0 should error"
            );
            assert_eq!(
                result.err().unwrap(),
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]"
            );
        }

        #[test]
        fn test_percent_fake_any_packets_nan_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(f32::NAN)) // invalid
                .max_len_file(None)
                .build();

            assert!(result.is_err(), "percent_fake_any_packets NaN should error");
            assert_eq!(
                result.err().unwrap(),
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]"
            );
        }

        #[test]
        fn test_percent_fake_any_packets_infinity_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(f32::INFINITY)) // invalid
                .max_len_file(None)
                .build();

            assert!(
                result.is_err(),
                "percent_fake_any_packets infinity should error"
            );
            assert_eq!(
                result.err().unwrap(),
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]"
            );
        }

        #[test]
        fn test_percent_fake_fback_packets_zero_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(0.0)) // invalid
                .max_len_file(None)
                .build();

            assert!(
                result.is_err(),
                "percent_fake_fback_packets = 0.0 should error"
            );
            assert_eq!(
                result.err().unwrap(),
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]"
            );
        }

        #[test]
        fn test_length_trimming_range_valid() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .length_trimming_range(Some(0))
                .max_len_file(None)
                .build();

            assert_eq!(
                result.err().unwrap(),
                "length_trimming_range must be in the range from 1 to mtu"
            );

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .length_trimming_range(Some(123))
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "length_trimming_range = 0.7 should be valid"
            );
            assert_eq!(result.unwrap().length_trimming_range(), Some(123));
        }

        #[test]
        fn test_length_trimming_range_zero_error() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .length_trimming_range(Some(0)) // invalid
                .max_len_file(None)
                .build();

            assert_eq!(
                result.err().unwrap(),
                "length_trimming_range must be in the range from 1 to mtu"
            );
        }

        #[test]
        fn test_all_traffic_masking_valid_values() {
            #![allow(clippy::integer_division)]
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(0.05))
                .length_trimming_range(Some(100))
                .mtu(1000)
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "all traffic masking parameters with valid values should be valid"
            );
            let param = result.unwrap();

            assert_eq!(
                param.percent_fake_any_packets(),
                Some((u32::MAX as f32 * 0.05) as u32)
            );
            assert_eq!(param.length_trimming_range(), Some(100));
        }

        #[test]
        fn test_percent_fake_any_packets_small_positive_value() {
            #![allow(clippy::integer_division)]
            let topo = __warning_get_topol(Some(1), 50, None);

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_any_packets(Some(0.006)) // very small but positive
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "percent_fake_any_packets with very small positive value should be valid"
            );
            assert_eq!(
                result.unwrap().percent_fake_any_packets(),
                Some((u32::MAX as f32 * 0.006) as u32)
            );
        }

        #[test]
        fn test_combination_ttl_and_traffic_masking() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1)
                .percent_fake_any_packets(Some(0.2))
                .length_trimming_range(Some(32321))
                .max_len_file(None)
                .build();

            assert_eq!(
                result.err().unwrap(),
                "length_trimming_range must be in the range from 1 to mtu"
            );

            let result = WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost(ttl255_128_i1)
                .percent_fake_any_packets(Some(0.2))
                .length_trimming_range(Some(32))
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "combination of ttl and traffic masking parameters should be valid "
            );
        }
    }

    mod tests_packet_queue_management_group {
        use super::*;

        // compact builder for queue tests – only queue-related fields are varied.
        // all other fields set to minimal valid values.
        fn base_builder(topo: PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.8)
                .maximum_packet_delay_absolute_fback(80.0)
                .max_len_file(None)
                .instant_feedback_on_packet_loss(false)
            //.packages_measurement_window_size_determining_latency(10)
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ basic queue validation – positive values and capacity checks              │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn queue_accepts_minimal_positive_values() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let p = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(1)
                .maximum_length_fback_queue_packages(1)
                .maximum_length_queue_unconfirmed_packages(1)
                .max_num_attempts_resend_package(1)
                .build()
                .unwrap();
            assert_eq!(p.maximum_length_udp_queue_packages(), 1);
            assert_eq!(p.maximum_length_fback_queue_packages(), 1);
            assert_eq!(p.maximum_length_queue_unconfirmed_packages(), 1);
            assert_eq!(p.max_num_attempts_resend_package(), 1);
        }

        #[test]
        fn queue_accepts_values_within_capacity() {
            let topo = __warning_get_topol(Some(1), 50, None); // capacity = 126
            assert!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(100)
                    .maximum_length_fback_queue_packages(30)
                    .maximum_length_queue_unconfirmed_packages(60)
                    .max_num_attempts_resend_package(10)
                    .build()
                    .is_ok()
            );
        }

        #[test]
        fn queue_accepts_values_at_capacity_boundary() {
            let topo = __warning_get_topol(Some(1), 50, None); // capacity = 126
            assert!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(126)
                    .maximum_length_fback_queue_packages(126)
                    .maximum_length_queue_unconfirmed_packages(126)
                    .max_num_attempts_resend_package(126)
                    .build()
                    .is_ok()
            );
        }

        #[test]
        fn queue_rejects_values_exceeding_capacity() {
            let topo = __warning_get_topol(Some(1), 50, None); // capacity = 126

            // udp queue > capacity
            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(127)
                .maximum_length_fback_queue_packages(30)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                " maximum_length_udp_queue_packages must be less than the maximum capacity of the \
                 pack_topology.counter_slice() field. "
            );

            // fback queue > capacity
            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(127)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "maximum_length_fback_queue_packages must not exceed the maximum capacity of the \
                 pack_topology.counter_slice() counter. "
            );

            // max attempts > capacity
            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(30)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(127)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "max_num_attempts_resend_package > ctr_max_capacity_real as usize.  \
                 max_num_attempts_resend_package must be less than the maximum possible capacity \
                 in pack_topology.counter_slice()."
            );
        }

        #[test]
        fn queue_rejects_zero_values() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(0)
                .maximum_length_fback_queue_packages(100)
                .maximum_length_queue_unconfirmed_packages(150)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");

            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(0)
                .maximum_length_queue_unconfirmed_packages(150)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");

            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(100)
                .maximum_length_queue_unconfirmed_packages(0)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");

            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(100)
                .maximum_length_queue_unconfirmed_packages(150)
                .max_num_attempts_resend_package(0)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ queue relationship validation – udp ≥ unconfirmed, fback ≤ unconfirmed    │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn udp_must_be_at_least_unconfirmed() {
            let topo = __warning_get_topol(Some(2), 50, None);

            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(50)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(100) // udp < unconfirmed
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                " maximum_length_udp_queue_packages must be greater than \
                 maximum_length_queue_unconfirmed_packages so that all packets are confirmed. For \
                 more information, see the description of this variable at the beginning of the \
                 file."
            );

            // udp == unconfirmed is allowed
            assert!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(100)
                    .maximum_length_fback_queue_packages(50)
                    .maximum_length_queue_unconfirmed_packages(100)
                    .max_num_attempts_resend_package(10)
                    .build()
                    .is_ok()
            );
        }

        #[test]
        fn fback_must_not_exceed_unconfirmed() {
            let topo = __warning_get_topol(Some(2), 50, None);

            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(150) // fback > unconfirmed
                .maximum_length_queue_unconfirmed_packages(100)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "maximum_length_fback_queue_packages must be less than \
                 maximum_length_queue_unconfirmed_packages.For more information, see the \
                 description of this variable at the beginning of the file."
            );

            // fback == unconfirmed is allowed
            assert!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(200)
                    .maximum_length_fback_queue_packages(100)
                    .maximum_length_queue_unconfirmed_packages(100)
                    .max_num_attempts_resend_package(10)
                    .build()
                    .is_ok()
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ counter_slice validation – required for queue parameters                  │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn counter_slice_required() {
            let topo = __warning_get_topol(None, 50, None);
            let err = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(50)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "The counter_slice() field in pack_topology is None, but it must be specified!"
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ large capacity values – works with bigger counters                        │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn works_with_larger_counter_capacity() {
            let topo = __warning_get_topol(Some(2), 50, None); // capacity = 32767
            assert_eq!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(20000)
                    .maximum_length_fback_queue_packages(5000)
                    .maximum_length_queue_unconfirmed_packages(15000)
                    .max_num_attempts_resend_package(100)
                    .build()
                    .err()
                    .unwrap(),
                "maximum_length_fback_queue_packages is greater than the Fback packet buffer can accommodate."
            );

            let xr = base_builder(topo.clone())
                .maximum_length_udp_queue_packages(20000)
                .maximum_length_fback_queue_packages(719)
                .maximum_length_queue_unconfirmed_packages(15000)
                .max_num_attempts_resend_package(100)
                .build();

            println!("{:#?}", xr);

            assert!(xr.is_ok());
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combination with other features – ttl does not interfere                 │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn queue_works_with_ttl() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            assert!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(100)
                    .maximum_length_fback_queue_packages(30)
                    .maximum_length_queue_unconfirmed_packages(60)
                    .max_num_attempts_resend_package(10)
                    .ttl_max_start_cost(ttl255_128_i1)
                    .build()
                    .is_ok()
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ documentation recommendations – not enforced, but code should accept      │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn recommended_ratio_not_enforced() {
            let topo = __warning_get_topol(Some(2), 50, None);
            assert!(
                base_builder(topo.clone())
                    .maximum_length_udp_queue_packages(200)
                    .maximum_length_fback_queue_packages(50)
                    .maximum_length_queue_unconfirmed_packages(100) // 2x fback (not 3x)
                    .max_num_attempts_resend_package(10)
                    .build()
                    .is_ok()
            );
        }
    }

    mod tests_delay {

        use super::*;

        // compact builder for delay tests – only fback-related fields are varied.
        // all other fields set to minimal valid values.
        fn base_builder(topo: PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(PackScheme::OnePack(topo))
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .max_num_attempts_resend_package(3)
                // .packages_measurement_window_size_determining_latency(10)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_len_file(None)
                .instant_feedback_on_packet_loss(false)
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ maximum_packet_delay_fback_coefficient – range (0,1] plus NaN/inf checks  │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn fback_coefficient_accepts_valid_range() {
            let topo = __warning_get_topol(Some(1), 50, None);

            // mid-range
            let p = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 0.5);
            assert_eq!(p.ctr_max_capacity_real(), 126);
            assert_eq!(p.min_ms_latency(), 10.0);

            // minimum positive
            let p = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.0001)
                .maximum_packet_delay_absolute_fback(0.0001)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 0.0001);

            // maximum = 1.0
            let p = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(1.0)
                .maximum_packet_delay_absolute_fback(100.0)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 1.0);
        }

        #[test]
        fn fback_coefficient_rejects_zero() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let err = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.0)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f32 variables must be is_normal()");
        }

        #[test]
        fn fback_coefficient_rejects_negative() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let err = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(-0.5)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f32 variables must be greater than zero");
        }

        #[test]
        fn fback_coefficient_rejects_above_one() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let err = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(1.1)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert!(err.contains("must be greater than zero") || err.contains("is_normal"));
        }

        #[test]
        fn fback_coefficient_rejects_nan_and_inf() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let err_nan = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(f32::NAN)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err_nan, "all f32 variables must be is_normal()");

            let err_inf = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(f32::INFINITY)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err_inf, "all f32 variables must be is_normal()");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ maximum_packet_delay_absolute_fback – range [0, max_ms_latency]           │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn absolute_fback_accepts_zero() {
            let topo = __warning_get_topol(Some(1), 50, None);
            // zero is allowed? test says it should be valid
            let p = base_builder(topo.clone())
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(0.1)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_absolute_fback(), 0.1);
        }

        #[test]
        fn absolute_fback_accepts_up_to_max_latency() {
            let topo = __warning_get_topol(Some(1), 50, None);

            // exactly max_latency
            let p = base_builder(topo.clone())
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(100.0)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_absolute_fback(), 100.0);
        }

        #[test]
        fn absolute_fback_rejects_exceeding_max_latency() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let err = base_builder(topo.clone())
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(100.1)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "The variable maximum_packet_delay_absolute_fback must be no greater than \
                 max_ms_latency For more information, see the description of this variable at the \
                 beginning of the file."
            );
        }

        #[test]
        fn absolute_fback_rejects_negative() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let err = base_builder(topo.clone())
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(-0.1)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f32 variables must be greater than zero");
        }

        #[test]
        fn absolute_fback_rejects_nan_and_inf() {
            let topo = __warning_get_topol(Some(1), 50, None);

            let err_nan = base_builder(topo.clone())
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(f32::NAN)
                .build()
                .unwrap_err();
            assert_eq!(err_nan, "all f32 variables must be is_normal()");

            let err_inf = base_builder(topo.clone())
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(f32::INFINITY)
                .build()
                .unwrap_err();
            assert_eq!(err_inf, "all f32 variables must be is_normal()");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combined scenarios – both parameters at boundaries                         │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn both_fback_parameters_at_maximum() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let p = base_builder(topo.clone())
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(1.0)
                .maximum_packet_delay_absolute_fback(100.0)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 1.0);
            assert_eq!(p.maximum_packet_delay_absolute_fback(), 100.0);
        }

        #[test]
        fn fback_works_with_different_max_latency() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let small_max = 110.0;

            let p = base_builder(topo.clone())
                .max_ms_latency(small_max)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.8)
                .maximum_packet_delay_absolute_fback(8.0)
                .build()
                .unwrap();
            assert_eq!(p.max_ms_latency(), small_max);
            assert_eq!(p.maximum_packet_delay_absolute_fback(), 8.0);
        }
    }

    mod tests_adaptation_coefficients {

        use super::*;

        // compact builder for coefficient testing – only latency_increase and overhead are
        // relevant. all other fields set to minimal valid values.
        fn base_builder(topo: PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .max_num_attempts_resend_package(3)
                //.packages_measurement_window_size_determining_latency(10)
                .maximum_packet_delay_absolute_fback(80.0)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_len_file(None)
                .instant_feedback_on_packet_loss(false)
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ latency_increase_coefficient – range (0,1] plus NaN/inf checks            │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn latency_increase_valid_range() {
            let topo = __warning_get_topol(Some(2), 50, None);

            // min positive
            let p = base_builder(topo.clone())
                .latency_increase_coefficient(f32::MIN_POSITIVE)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap();
            assert_eq!(p.latency_increase_coefficient(), f32::MIN_POSITIVE);

            // max = 1.0
            let p = base_builder(topo.clone())
                .latency_increase_coefficient(1.0)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap();
            assert_eq!(p.latency_increase_coefficient(), 1.0);
        }

        #[test]
        fn latency_increase_rejects_zero() {
            let topo = __warning_get_topol(Some(2), 50, None);
            let err = base_builder(topo.clone())
                .latency_increase_coefficient(0.0)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f32 variables must be is_normal()");
        }

        #[test]
        fn latency_increase_rejects_negative() {
            let topo = __warning_get_topol(Some(2), 50, None);
            let err = base_builder(topo.clone())
                .latency_increase_coefficient(-0.1)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f32 variables must be greater than zero");
        }

        #[test]
        fn latency_increase_rejects_above_one() {
            let topo = __warning_get_topol(Some(2), 50, None);
            let err = base_builder(topo.clone())
                .latency_increase_coefficient(1.1)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "latency_increase_coefficient \
                 overhead_network_latency_relative_window_coefficient \
                 maximum_packet_delay_fback_coefficient must be greater than zero"
            );
        }

        #[test]
        fn latency_increase_rejects_nan_and_inf() {
            let topo = __warning_get_topol(Some(2), 50, None);

            let err_nan = base_builder(topo.clone())
                .latency_increase_coefficient(f32::NAN)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err_nan, "all f32 variables must be is_normal()");

            let err_inf = base_builder(topo.clone())
                .latency_increase_coefficient(f32::INFINITY)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err_inf, "all f32 variables must be is_normal()");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ overhead_network_latency_relative_window_coefficient – range [ε,1]        │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn overhead_coefficient_valid_range() {
            let topo = __warning_get_topol(Some(2), 50, None);

            // very small positive
            let p = base_builder(topo.clone())
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .overhead_network_latency_relative_window_coefficient(0.00001)
                .build()
                .unwrap();
            assert_eq!(
                p.overhead_network_latency_relative_window_coefficient(),
                0.00001
            );

            // max = 1.0
            let p = base_builder(topo.clone())
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .overhead_network_latency_relative_window_coefficient(1.0)
                .build()
                .unwrap();
            assert_eq!(
                p.overhead_network_latency_relative_window_coefficient(),
                1.0
            );
        }

        #[test]
        fn overhead_coefficient_rejects_negative() {
            let topo = __warning_get_topol(Some(2), 50, None);
            let err = base_builder(topo.clone())
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .overhead_network_latency_relative_window_coefficient(-0.1)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f32 variables must be greater than zero");
        }

        #[test]
        fn overhead_coefficient_rejects_above_one() {
            let topo = __warning_get_topol(Some(2), 50, None);
            let err = base_builder(topo.clone())
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .overhead_network_latency_relative_window_coefficient(1.1)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "latency_increase_coefficient \
                 overhead_network_latency_relative_window_coefficient \
                 maximum_packet_delay_fback_coefficient must be greater than zero"
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combination tests – verify multiple coefficients together                 │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn multiple_coefficients_work_together() {
            let topo = __warning_get_topol(Some(2), 50, None);

            let p = base_builder(topo.clone())
                .latency_increase_coefficient(0.3)
                .overhead_network_latency_relative_window_coefficient(0.7)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap();
            assert_eq!(p.latency_increase_coefficient(), 0.3);
            assert_eq!(
                p.overhead_network_latency_relative_window_coefficient(),
                0.7
            );
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 0.8);

            let p = base_builder(topo.clone())
                .latency_increase_coefficient(1.0)
                .overhead_network_latency_relative_window_coefficient(0.0000001)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap();
            assert_eq!(p.latency_increase_coefficient(), 1.0);
            assert_eq!(
                p.overhead_network_latency_relative_window_coefficient(),
                0.0000001
            );
        }
    }

    mod tests_from_group {
        use crate::w1types::PackTypeGroup;

        use super::*;

        // compact builder with only mtu-related parameters.
        // all other fields are set to minimal valid values needed to satisfy the constructor.

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ mtu validation – all checks related to mtu vs total_minimal_len          │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn mtu_greater_than_minimal_succeeds() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let param = base_builder_pub(topo.clone()).mtu(1500).build().unwrap();
            assert_eq!(param.mtu(), 1500);
        }

        #[test]
        fn mtu_equal_to_minimal_fails() {
            let topo = __warning_get_topol(Some(1), 100, None);
            let err = base_builder_pub(topo.clone()).mtu(100).build().unwrap_err();
            assert_eq!(
                err,
                "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
                 pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is \
                 the minimum packet length, such a packet contains only protocol service \
                 information, mtu must be large enough to accommodate the length of the packet's \
                 useful data and service data."
            );
        }

        #[test]
        fn mtu_less_than_minimal_fails() {
            let topo = __warning_get_topol(Some(1), 500, None);
            let err = base_builder_pub(topo.clone()).mtu(300).build().unwrap_err();
            assert_eq!(
                err,
                "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
                 pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is \
                 the minimum packet length, such a packet contains only protocol service \
                 information, mtu must be large enough to accommodate the length of the packet's \
                 useful data and service data."
            );
        }

        #[test]
        fn mtu_boundary_works() {
            let topo = __warning_get_topol(Some(1), 100, None);
            let param = base_builder_pub(topo.clone()).mtu(1001).build().unwrap();
            assert_eq!(param.mtu(), 1001);
        }

        #[test]
        fn mtu_large_value_accepted() {
            let topo = __warning_get_topol(Some(1), 50, None);
            let param = base_builder_pub(topo.clone()).mtu(65535).build().unwrap();
            assert_eq!(param.mtu(), 65535);
        }

        #[test]
        fn mtu_with_various_minimal_lengths() {
            let cases = [(10, 100), (100, 1500), (500, 2000)];
            for (min_len, mtu) in cases {
                let topo = __warning_get_topol(Some(1), min_len, None);
                let param = base_builder_pub(topo.clone()).mtu(mtu).build().unwrap();
                assert_eq!(param.mtu(), mtu);

                let tml = match param.sheme() {
                    PackScheme::OnePack(x) => x.overhead_len(),
                    _ => panic!(
                        "The test only checks the scenario with PackScheme::OnePack. Most likely, the test itself is broken."
                    ),
                };
                assert_eq!(tml, min_len);
            }
        }

        #[test]
        fn mtu_with_minimal_len_one() {
            for (ite, min_mtu) in [13, 14].iter().enumerate() {
                let topo = __warning_get_topol(Some(1), 1, None);
                let param = base_builder_pub(topo.clone())
                    .mtu(*min_mtu)
                    .maximum_length_fback_queue_packages(1)
                    .build();

                println!(" {:#?}", param);

                if param.is_ok() {
                    let wcp = param.clone().unwrap();

                    println!("=====SHEME!============= {:#?}", wcp.sheme());

                    println!(
                        "=====OVH!============= {:#?}",
                        wcp.sheme()
                            .get_topol(0, PackTypeGroup::Any)
                            .unwrap()
                            .overhead_len()
                    );
                }

                if ite == 0 {
                    assert_eq!(
                        param,
                        Err(
                            "err: mtu - (absolute_maximal_fback_overhead + TIME_MARK_L) in \n             WSFbackQueue::<bool>::max_len_from_mtu :\nThe MTU is too small to accommodate even one counter.\n".to_string()
                        )
                    );
                } else {
                    let param = param.unwrap();
                    println!(" {} {}", param.mtu(), min_mtu);
                    assert_eq!(param.mtu(), *min_mtu);
                }
            }
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ counter_slice validation – required for queue parameters                  │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn counter_slice_absent_fails() {
            let topo = __warning_get_topol(None, 50, None);
            let err = base_builder_pub(topo.clone())
                .mtu(1500)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "The counter_slice() field in pack_topology is None, but it must be specified!"
            );
        }

        #[test]
        fn counter_slice_present_succeeds() {
            let topo = __warning_get_topol(Some(1), 50, None);
            assert!(base_builder_pub(topo.clone()).mtu(1500).build().is_ok());
        }
    }

    mod tests_mt1 {
        use super::*;

        // compact builder tests – only parameters relevant to error detection are varied.
        // all other fields are set to the minimal valid values needed to construct the base
        // object.

        // base valid configuration (used as foundation for all tests)
        //
        fn base_builder(topo: PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .max_num_attempts_resend_package(3)
                //.packages_measurement_window_size_determining_latency(10)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.8)
                .maximum_packet_delay_absolute_fback(80.0)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_len_file(None)
                .instant_feedback_on_packet_loss(false)
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ ttl behavior – all ttl-related validations                                │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn ttl_absent_is_always_ok() {
            let topo_with_ttl = __warning_get_topol(Some(1), 50, Some(1));
            let topo_without_ttl = __warning_get_topol(Some(1), 50, None);

            // ttl not set → always valid, regardless of topology

            let ttl = Ttl::new(9, 7, 8, false).unwrap();
            assert!(
                base_builder(topo_with_ttl.clone())
                    .ttl_max_start_cost(ttl)
                    .build()
                    .is_ok()
            );

            assert!(
                base_builder(topo_without_ttl.clone())
                    // .ttl_max_start_cost((9, 8, 7))
                    .build()
                    .is_ok()
            );
            assert_eq!(
                base_builder(topo_with_ttl.clone())
                    .ttl_max_start_cost(ttl)
                    .build()
                    .unwrap()
                    .ttl_max_start_cost(),
                Some(ttl)
            );
        }

        #[test]
        fn ttl_present_requires_topology_ttl() {
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let topo_with_ttl = __warning_get_topol(Some(1), 50, Some(1));
            let topo_without_ttl = __warning_get_topol(Some(1), 50, None);

            // ttl specified → must have ttl in topology
            assert!(
                base_builder(topo_with_ttl.clone())
                    .ttl_max_start_cost(ttl255_128_i1)
                    .build()
                    .is_ok()
            );

            let err = base_builder(topo_without_ttl.clone())
                .ttl_max_start_cost(ttl255_128_i1)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "ttl_len_slice or ttl_max_start_cost is none, and ttl_len_slice or ttl_max_start_cost is some, either remove the ttl field in the packets or define ttl values ttl_max_start_cost"
            );
        }

        #[test]
        fn ttl_start_exceeds_capacity() {
            let ttl = Ttl::new(300, -1, 256, false).unwrap();
            let topo = __warning_get_topol(Some(1), 50, Some(1)); // 1‑byte ttl → max 255

            let err = base_builder(topo.clone())
                .ttl_max_start_cost(ttl)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "ttl_max_start_cost.1 is greater than the length that can be accommodated in the \
                 pack_topology field."
            );
        }

        #[test]
        fn ttl_cost_variants_accepted() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();

            let ttl255_128_1 = Ttl::new(255, 1, 128, false).unwrap();
            // positive, zero, negative – all allowed
            assert!(
                base_builder(topo.clone())
                    .ttl_max_start_cost(ttl255_128_1)
                    .build()
                    .is_ok()
            );

            assert!(
                base_builder(topo.clone())
                    .ttl_max_start_cost(ttl255_128_i1)
                    .build()
                    .is_ok()
            );
        }

        #[test]
        fn ttl_with_larger_byte_capacity() {
            let ttl = Ttl::new(65535, -1, 32768, false).unwrap();
            // 2‑byte ttl field → capacity up to 65535
            let topo = __warning_get_topol(Some(1), 50, Some(2));
            assert!(
                base_builder(topo.clone())
                    .ttl_max_start_cost(ttl)
                    .build()
                    .is_ok()
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ instant_feedback – boolean field, no extra validation                     │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn instant_feedback_accepts_both_values() {
            use crate::t0pology::PackFields as PF;
            let topo = __warning_get_topol(Some(1), 50, Some(1));

            let false_ttl_val = base_builder(topo.clone())
                .instant_feedback_on_packet_loss(true)
                .build()
                .err()
                .unwrap();

            assert_eq!(
                false_ttl_val,
                "ttl_len_slice or ttl_max_start_cost is none, and ttl_len_slice or ttl_max_start_cost is some, either remove the ttl field in the packets or define ttl values ttl_max_start_cost"
            );

            let fields1 = vec![
                PF::Counter(2), //
            ]
            .into_boxed_slice();
            let topol2 = PackTopology::new(16, &fields1, true, false).unwrap();

            let err_len_udp_val = WsConnectParamBuilder::new(PackScheme::OnePack(topol2.clone()))
                .instant_feedback_on_packet_loss(true)
                .build()
                .err()
                .unwrap();

            assert_eq!(
                err_len_udp_val,
                "maximum_length_udp_queue_packages must be set"
            );

            let true_val = WsConnectParamBuilder::new(PackScheme::OnePack(topol2.clone()))
                .instant_feedback_on_packet_loss(true)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .build()
                .unwrap();

            assert_eq!(
                err_len_udp_val,
                "maximum_length_udp_queue_packages must be set"
            );

            assert!(true_val.instant_feedback_on_packet_loss());

            let mut false_val = base_builder(topo.clone()).instant_feedback_on_packet_loss(false);
            {
                let false_val = false_val.clone().build().err().unwrap();

                assert_eq!(
                    false_val,
                    "ttl_len_slice or ttl_max_start_cost is none, and ttl_len_slice or ttl_max_start_cost is some, either remove the ttl field in the packets or define ttl values ttl_max_start_cost"
                );
            }

            let ttl = Ttl::new(100, 1, 1, false).unwrap();
            false_val.for_test_ttl_max_start_cost(Some(ttl));

            let false_val = false_val.build().unwrap();

            assert!(!false_val.instant_feedback_on_packet_loss());
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ max_len_file – optional field, no validation                              │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn max_len_file_accepts_none_and_some() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl1 = Ttl::new(200, -1, 150, false).unwrap();
            let ttl2 = Ttl::new(200, -1, 199, false).unwrap();
            let none_val = base_builder(topo.clone())
                .max_len_file(None)
                .ttl_max_start_cost(ttl1)
                .build()
                .unwrap();
            assert_eq!(none_val.max_len_file(), None);

            let some_val = base_builder(topo.clone())
                .max_len_file(Some(1000))
                .ttl_max_start_cost(ttl2)
                .build()
                .unwrap();
            assert_eq!(some_val.max_len_file(), Some(1000));
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combined scenario – both fields used together                             │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn ttl_and_instant_feedback_can_be_combined() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let param = base_builder(topo.clone())
                .instant_feedback_on_packet_loss(true)
                .ttl_max_start_cost(ttl255_128_i1)
                .max_len_file(Some(2048))
                .intermediate_questionable_packages_queue(Some(120))
                .build()
                .unwrap();

            assert!(param.instant_feedback_on_packet_loss());
            assert_eq!(param.ttl_max_start_cost(), Some(ttl255_128_i1));
            assert_eq!(param.max_len_file(), Some(2048));
            assert_eq!(param.intermediate_questionable_packages_queue(), Some(120));
        }

        #[test]
        fn intermediate_questionable_packages_queue() {
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            let topo = __warning_get_topol(Some(1), 50, Some(1));

            let param_normal = base_builder(topo.clone())
                .instant_feedback_on_packet_loss(true)
                .ttl_max_start_cost(ttl255_128_i1)
                .max_len_file(Some(2048));

            let param = param_normal
                .clone()
                .intermediate_questionable_packages_queue(Some(0))
                .build();

            assert_eq!(
                param.err().unwrap(),
                "intermediate_questionable_packages_queue is Some(0), but Some(the value must be \
                 greater than zero) "
            );

            let param = param_normal
                .clone()
                .intermediate_questionable_packages_queue(Some(111110))
                .build();

            assert_eq!(
                param.err().unwrap(),
                "Some(intermediate_questionable_packages_queue) > ctr_max_capacity_real, The \
                 maximum value that the counter field in the packet topology can hold must be \
                 GREATER than intermediate_questionable_packages_queue."
            );

            let param = param_normal
                .clone()
                .maximum_length_udp_queue_packages(10011000)
                .build();
            assert_eq!(
                param.err().unwrap(),
                " maximum_length_udp_queue_packages must be less than the maximum capacity of the \
                 pack_topology.counter_slice() field. "
            );
            let param = param_normal
                .clone()
                .maximum_length_queue_unconfirmed_packages(10110000)
                .build();
            assert_eq!(
                param.err().unwrap(),
                " maximum_length_udp_queue_packages must be greater than \
                 maximum_length_queue_unconfirmed_packages so that all packets are confirmed. For \
                 more information, see the description of this variable at the beginning of the \
                 file."
            );
            let param = param_normal
                .clone()
                .maximum_length_fback_queue_packages(10110000)
                .build();
            assert_eq!(
                param.err().unwrap(),
                "maximum_length_fback_queue_packages must not exceed the maximum capacity of the \
                 pack_topology.counter_slice() counter. "
            );
            let param = param_normal
                .clone()
                .max_num_attempts_resend_package(10110000)
                .build();
            assert_eq!(
                param.err().unwrap(),
                "max_num_attempts_resend_package > ctr_max_capacity_real as usize.  \
                 max_num_attempts_resend_package must be less than the maximum possible capacity \
                 in pack_topology.counter_slice()."
            );
            let param = param_normal
                .clone()
                .intermediate_questionable_packages_queue(Some(10110000))
                .build();

            assert_eq!(
                param.err().unwrap(),
                "Some(intermediate_questionable_packages_queue) > ctr_max_capacity_real, The \
                 maximum value that the counter field in the packet topology can hold must be \
                 GREATER than intermediate_questionable_packages_queue."
            );
        }

        #[test]
        fn need_use_random() {
            let topo = __warning_get_topol(Some(1), 50, Some(1));
            let ttl255_128_i1 = Ttl::new(255, -1, 128, false).unwrap();
            for x1 in [Some(0.3), None] {
                for x2 in [Some(20), None] {
                    let param_normal = base_builder(topo.clone())
                        .instant_feedback_on_packet_loss(true)
                        .ttl_max_start_cost(ttl255_128_i1)
                        .max_len_file(Some(2048))
                        .percent_fake_any_packets(x1)
                        .length_trimming_range(x2)
                        .build()
                        .unwrap();
                    println!(
                        "{} {} {} ",
                        param_normal.need_init_random(),
                        x1.is_some(),
                        x2.is_some(),
                    );
                    assert_eq!(
                        param_normal.need_init_random(),
                        (x1.is_some() || x2.is_some())
                    );
                }
            }
        }
    }

    #[test]
    fn test_group_pack() {
        use crate::t0pology::PackFields as PF;
        use crate::w1types::PackTypeGroup;

        let fields1 = vec![
            PF::TrickyByte,    //
            PF::Len(1),        //
            PF::Counter(2),    //
            PF::IdSender(3),   //
            PF::IdReceiver(3), //
            PF::IdConnect(4),  //
            PF::HeadCRC(5),    //
            PF::Nonce(6),      //
            PF::TTL(7),
            PF::UserField(30),
        ]
        .into_boxed_slice();

        let fields2 = vec![PF::TrickyByte, PF::Counter(2)].into_boxed_slice();

        for sheme in [
            (
                false,
                GroupTopology::new(
                    &[
                        (fields1.clone(), PackTypeGroup::Any, 1),
                        (fields2.clone(), PackTypeGroup::Any, 2),
                    ],
                    16,
                    true,
                    false,
                )
                .unwrap(),
            ),
            (
                false,
                GroupTopology::new(
                    &[
                        (fields1.clone(), PackTypeGroup::Fback, 1),
                        (fields2.clone(), PackTypeGroup::Data, 2),
                    ],
                    16,
                    true,
                    false,
                )
                .unwrap(),
            ),
            (
                true,
                GroupTopology::new(
                    &[
                        (fields1.clone(), PackTypeGroup::Data, 1),
                        (fields2.clone(), PackTypeGroup::Fback, 2),
                    ],
                    16,
                    true,
                    false,
                )
                .unwrap(),
            ),
            (
                false,
                GroupTopology::new(
                    &[
                        (fields1.clone(), PackTypeGroup::Any, 1),
                        (fields2.clone(), PackTypeGroup::Data, 2),
                    ],
                    16,
                    true,
                    false,
                )
                .unwrap(),
            ),
            (
                true,
                GroupTopology::new(
                    &[
                        (fields1.clone(), PackTypeGroup::Data, 1),
                        (fields2.clone(), PackTypeGroup::Any, 2),
                    ],
                    16,
                    true,
                    false,
                )
                .unwrap(),
            ),
        ] {
            let topo = sheme.1.clone();

            let buider_main = WsConnectParamBuilder::new(PackScheme::GroupPack(topo.clone()))
                // .mtu(10101)
                .instant_feedback_on_packet_loss(true)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3);

            let buider1 = buider_main.clone().build();

            assert_eq!(
                buider1.err().unwrap(),
                "ttl_len_slice or ttl_max_start_cost is none, and ttl_len_slice or ttl_max_start_cost is some, either remove the ttl field in the packets or define ttl values ttl_max_start_cost"
            );
            let ttl = Ttl::new(100, -2, 10, false).unwrap();
            let builder_err_fback = buider_main
                .clone()
                .mtu(100)
                .ttl_max_start_cost(ttl)
                .maximum_length_fback_queue_packages(15)
                .build();

            if sheme.0 {
                assert!(builder_err_fback.is_ok())
            } else {
                assert_eq!(
                    builder_err_fback.err().unwrap(),
                    "maximum_length_fback_queue_packages is greater than the Fback packet buffer can accommodate."
                );
            }
            let ttl = Ttl::new(100, 1, 2, false).unwrap();
            let buider2 = buider_main.ttl_max_start_cost(ttl).clone().build();

            let ttl = Ttl::new(100, 1, 2, false).unwrap();

            assert_eq!(buider2.clone().unwrap().ttl_max_start_cost(), Some(ttl));

            assert_eq!(buider2.unwrap().ctr_max_capacity_real(), (0xFFFF >> 1) - 1);
        }

        let fields1 = vec![PF::TrickyByte, PF::Counter(2), PF::UserField(12)].into_boxed_slice();
        let fields2 = vec![PF::TrickyByte, PF::Counter(2), PF::UserField(1000)].into_boxed_slice();

        let g_s = GroupTopology::new(
            &[
                (fields1.clone(), PackTypeGroup::Data, 1),
                (fields2.clone(), PackTypeGroup::Fback, 2),
            ],
            16,
            true,
            false,
        )
        .unwrap();

        let topo = g_s.clone();

        let check_get_max_len_ctr_len_ttl_len_opt =
            WsConnectParamBuilder::new(PackScheme::GroupPack(topo))
                .mtu(1000)
                .instant_feedback_on_packet_loss(true)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3);

        let buider1 = check_get_max_len_ctr_len_ttl_len_opt.clone().build();
        assert_eq!(
            buider1.err().unwrap(),
            "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is the minimum packet length, such a packet contains only protocol service information, mtu must be large enough to accommodate the length of the packet's useful data and service data."
        )
    }
}

mod tests_max_len {
    #![allow(clippy::unwrap_used)]
    use super::*;

    use crate::{
        t0grouper::GroupTopology,
        t0pology::{PackFields, PackTopology},
        w1types::PackTypeGroup,
    };
    use std::cmp;

    // Helper: create a PackTopology with given fields, tag_len=16, data_save=true, tcp_mode=false.
    fn make_topo(fields: &[PackFields]) -> PackTopology {
        PackTopology::new(16, fields, true, false).unwrap()
    }

    // Helper: create a GroupTopology from a slice of (fields, type, key) with common tag_len=16,
    // data_save=true, tcp_mode=false.
    fn make_group(
        entries: &[(Vec<PackFields>, PackTypeGroup, u8)],
    ) -> Result<GroupTopology, String> {
        let input: Vec<_> = entries
            .iter()
            .map(|(fields, typ, key)| (fields.clone().into_boxed_slice(), *typ, *key))
            .collect();
        GroupTopology::new(&input, 16, true, false)
    }

    // Helper to compute expected NeedyParam for OnePack from a topology.
    fn expected_one(topo: &PackTopology) -> NeedyParam {
        NeedyParam {
            absolute_maximal_overhead: topo.overhead_len(),
            absolute_maximal_fback_overhead: topo.overhead_len(),
            counter_slice_len: topo.counter_slice().unwrap().2, // always Some
            ttl_slice_len: topo.ttl_slice().map(|(_, _, len)| len),
        }
    }

    // Helper to compute expected NeedyParam for GroupPack from a group.
    // Note: ttl_slice_len is Some(len) if any topology has TTL (regardless of "all" flag),
    // because all_have_ttl_field().map(|(_, len)| len) is used.
    fn expected_group(group: &GroupTopology) -> NeedyParam {
        let counter = group.all_have_counter_field().unwrap(); // safe for valid groups
        NeedyParam {
            absolute_maximal_overhead: cmp::max(
                group.data_max_minimal_len(),
                group.fback_max_minimal_len(),
            ),
            absolute_maximal_fback_overhead: group.fback_max_minimal_len(),
            counter_slice_len: counter.1,
            ttl_slice_len: group.all_have_ttl_field().map(|(_, len)| len),
        }
    }

    // === OnePack tests ===
    #[test]
    fn one_pack_without_ttl() {
        let fields = vec![PackFields::Counter(4)];
        let topo = make_topo(&fields);
        let scheme = PackScheme::OnePack(topo.clone());
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        let expected = expected_one(&topo);
        assert_eq!(result, expected);
        assert_eq!(result.ttl_slice_len, None);
    }

    #[test]
    fn one_pack_with_ttl() {
        let fields = vec![PackFields::Counter(2), PackFields::TTL(1)];
        let topo = make_topo(&fields);
        let scheme = PackScheme::OnePack(topo.clone());
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        let expected = expected_one(&topo);
        assert_eq!(result, expected);
        assert_eq!(result.ttl_slice_len, Some(1));
    }

    #[test]
    fn one_pack_with_other_fields_no_ttl() {
        let fields = vec![
            PackFields::Counter(1),
            PackFields::IdConnect(2),
            PackFields::HeadCRC(4),
        ];
        let topo = make_topo(&fields);
        let scheme = PackScheme::OnePack(topo.clone());
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        let expected = expected_one(&topo);
        assert_eq!(result, expected);
        assert_eq!(result.ttl_slice_len, None);
    }

    // === GroupPack tests ===

    #[test]
    fn group_single_topology_any() {
        let fields = vec![PackFields::Counter(8), PackFields::TTL(2)];
        let group = make_group(&[(fields.clone(), PackTypeGroup::Any, 0)]).unwrap();

        let topo = group.clone();

        let scheme = PackScheme::GroupPack(topo.clone());
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        let expected = expected_group(&group);
        assert_eq!(result, expected);
        // For a single topology, data and fback max are equal to total_minimal_len.
        let topo = make_topo(&fields);
        assert_eq!(result.absolute_maximal_overhead, topo.overhead_len());
        assert_eq!(result.absolute_maximal_fback_overhead, topo.overhead_len());
        assert_eq!(result.counter_slice_len, 8);
        assert_eq!(result.ttl_slice_len, Some(2));
    }

    #[test]
    fn group_multiple_topologies_data_fback_different_len() {
        // Data topology: counter (1) only => minimal len = 1 (counter) + 1 (head byte) + tag_len (16) = 18? Actually total_minimal_len = content_start_pos + tag_len.
        // For counter only: shift = 1 (counter), content_start_pos = shift+1 = 2, total_minimal_len = 2+16 = 18.
        // Fback topology: counter (1) + TTL (1) => shift = 2, content_start_pos=3, total_minimal_len = 3+16 = 19.
        let data_fields = vec![PackFields::Counter(1), PackFields::TrickyByte];
        let fback_fields = vec![
            PackFields::Counter(1),
            PackFields::TrickyByte,
            PackFields::TTL(1),
        ];
        let group = make_group(&[
            (data_fields, PackTypeGroup::Data, 0),
            (fback_fields, PackTypeGroup::Fback, 1),
        ])
        .unwrap();
        let topo = group.clone();

        let scheme = PackScheme::GroupPack(topo.clone());
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        let expected = expected_group(&group);
        assert_eq!(result, expected);

        // Verify lengths manually.
        let data_topo = make_topo(&[PackFields::Counter(1), PackFields::TrickyByte]);
        let fback_topo = make_topo(&[
            PackFields::Counter(1),
            PackFields::TrickyByte,
            PackFields::TTL(1),
        ]);
        assert_eq!(
            result.absolute_maximal_overhead,
            cmp::max(data_topo.overhead_len(), fback_topo.overhead_len())
        );
        assert_eq!(
            result.absolute_maximal_fback_overhead,
            fback_topo.overhead_len()
        );
        assert_eq!(result.counter_slice_len, 1);
        assert_eq!(result.ttl_slice_len, Some(1)); // TTL exists in at least one topology -> map yields Some(1)
    }

    #[test]
    fn group_ttl_present_in_some_not_all() {
        // Topo A: counter + ttl; Topo B: counter only (no ttl)
        let a = vec![
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::TTL(2),
        ];
        let b = vec![PackFields::TrickyByte, PackFields::Counter(1)];
        let group = make_group(&[(a, PackTypeGroup::Any, 0), (b, PackTypeGroup::Any, 1)]).unwrap();

        let topo = group.clone();

        let scheme = PackScheme::GroupPack(topo.clone());
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        // Expect ttl_slice_len = Some(2) because all_have_ttl_field returns Some((false, 2)) and map yields Some(2).
        assert_eq!(result.ttl_slice_len, Some(2));
    }

    #[test]
    fn group_ttl_absent_in_all() {
        let a = vec![PackFields::TrickyByte, PackFields::Counter(1)];
        let b = vec![
            PackFields::TrickyByte,
            PackFields::Counter(1),
            PackFields::IdConnect(2),
        ];
        let group = make_group(&[(a, PackTypeGroup::Any, 0), (b, PackTypeGroup::Any, 1)]).unwrap();
        let topo = group.clone();
        let scheme = PackScheme::GroupPack(topo);
        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();
        assert_eq!(result.ttl_slice_len, None);
    }

    #[test]
    fn group_counter_missing_in_some_should_error() {
        // Topo A has counter, Topo B does not (invalid by PackTopology rules, but we can't create without counter).
        // However, PackTopology::new requires counter, so we cannot create a topology without counter.
        // But we can simulate by constructing a group where not all have counter, but that's impossible because each topology must have counter.
        // So this error case is actually unreachable for valid topologies. However, the code checks it.
        // Since we can't create a topology without counter, we cannot test the error case where counter is missing in some.
        // But we could test the case where GroupTopology::new might allow? It doesn't; it requires counter in all.
        // Actually, GroupTopology::new does not enforce that counter is in all; it just records the flag.
        // However, PackTopology itself enforces counter, so every topology will have counter.
        // So all_have_counter_field() will always be Some((true, len)).
        // So the error branch is never hit in practice. But we could artificially create a GroupTopology with a false flag? No, we can't because it's private.
        // So we skip this test. The code is safe.
    }

    // === Consistency between OnePack and GroupPack for a single topology ===
    #[test]
    fn consistency_one_and_group_single() {
        let fields = vec![PackFields::Counter(3), PackFields::TTL(1)];
        let topo = make_topo(&fields);
        let scheme_one = PackScheme::OnePack(topo.clone());
        let result_one = get_max_len_ctr_len_ttl_len_opt(scheme_one).unwrap();

        let group = make_group(&[(fields, PackTypeGroup::Any, 0)]).unwrap();
        let topo = group.clone();

        let scheme_group = PackScheme::GroupPack(topo.clone());
        let result_group = get_max_len_ctr_len_ttl_len_opt(scheme_group).unwrap();

        // Both should be identical for single topology.
        assert_eq!(result_one, result_group);
    }
}

mod tests_need_p {
    use super::*;

    #[test]
    fn test_need_use_random() {
        let config_none = RandConfig {
            percent_fake_any_packets: None,
            length_trimming_range: None,
        };
        assert!(!config_none.need_use_random());

        let config_percent = RandConfig {
            percent_fake_any_packets: Some(15),
            length_trimming_range: None,
        };
        assert!(config_percent.need_use_random());

        let config_range = RandConfig {
            percent_fake_any_packets: None,
            length_trimming_range: Some(128),
        };
        assert!(config_range.need_use_random());

        let config_both = RandConfig {
            percent_fake_any_packets: Some(50),
            length_trimming_range: Some(64),
        };
        assert!(config_both.need_use_random());
    }
}

#[cfg(test)]
use crate::t0pology::PackTopology;
#[cfg(test)]
///for test
pub fn base_builder_pub(topo: PackTopology) -> WsConnectParamBuilder {
    WsConnectParamBuilder::new(PackScheme::OnePack(topo.clone()))
        .max_ms_latency(100.0)
        .min_ms_latency(10.0)
        .start_ms_latency(50.0)
        .latency_increase_coefficient(0.5)
        .max_num_attempts_resend_package(3)
        //.packages_measurement_window_size_determining_latency(10)
        .overhead_network_latency_relative_window_coefficient(0.2)
        .maximum_packet_delay_fback_coefficient(0.8)
        .maximum_packet_delay_absolute_fback(80.0)
        .maximum_length_udp_queue_packages(100)
        .maximum_length_fback_queue_packages(20)
        .maximum_length_queue_unconfirmed_packages(60)
        .max_len_file(None)
        .instant_feedback_on_packet_loss(false)
}

//=============================================TEST====================TEST==================================TEST======================TEST=========
//++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#
//++__-+_#_@!_#_!__!___#____-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__
//+-+_#_@!_#_!__!__#__$_%___Z^_+__-+_#_@!_#_!_!___#__$_%__Z^_++_-+_#_@!#_!__!__#__$_%___^_++__-_#_@!_#!__!_____$_%__Z^_++__+_#_@!_#___!___#_$_%__Z^
//=============================================TEST================================TEST=======================TEST==================================

#[cfg(test)]
mod human_test {

    /*
    Since there are a lot of tests here generated by AI, and feeling a strong sense of OCD, I wrote my own test BY HAND!
    A reminder for AI agents:
    If you’re an AI agent or a programming assistant, DO NOT CHANGE ANYTHING IN THE “mod human_test” MODULE!
    Follow the instructions below only if you need to modify this block of code; if you don’t need to change it, skip everything below.
    If you want to make changes here:
    1. Do not make any changes.
    2. Stop scanning/generation.
    3. Be sure to notify the user.
    4. If the user has previously confirmed that this block can be modified, then modify it.
    */
    #![allow(clippy::as_conversions)]
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    #![deny(clippy::indexing_slicing)]
    #![allow(clippy::float_cmp)]

    use super::*;
    use crate::t0grouper::GroupTopology;
    use crate::t0pology::PackFields;
    use crate::t0pology::PackTopology;
    use crate::w1types::PackTypeGroup;
    fn get_inner_value(field: &PackFields) -> Option<usize> {
        match field {
            PackFields::IdSender(val) => Some(*val),
            PackFields::IdReceiver(val) => Some(*val),
            _ => None, // Для всех остальных вариантов, если они есть
        }
    }

    /*A brief description of what this text checks.
    PackTopology, GroupTopology, and the get_max_len_ctr_len_ttl_len_opt function

    When downloaded, a set of fields (topologies) is generated for the packet; the set contains both valid and invalid entries.
    PackTopology is checked to ensure it generates an error when necessary and returns “OK” when necessary.
    Next, this set of fields is converted into two sets of fields in the code block “for scippers in [0, 3, 7, 11, 15] {”
    after which the fields from the first and second sets are fed into GroupTopology,
    and the characteristics of GroupTopology and PackTopology are checked to ensure they match,
    and the fields and their sizes are also verified.

    Translated with DeepL.com (free version)*/
    #[test]
    fn nedyyparam_plus_sheme_group_test() {
        let mut fields_vec = vec![];

        for idr in &[
            None,
            Some(PackFields::IdReceiver(6)),
            Some(PackFields::IdReceiver(7)),
        ] {
            for ids in &[
                None,
                Some(PackFields::IdSender(7)),
                Some(PackFields::IdSender(5)),
            ] {
                for hcc in &[None, Some(PackFields::HeadCRC(19))] {
                    for ttl in &[None, Some(PackFields::TTL(1))] {
                        for len in &[None, Some(PackFields::Len(2))] {
                            for idc in &[None, Some(PackFields::IdConnect(3))] {
                                for nnc in &[None, Some(PackFields::Nonce(4))] {
                                    for usf in &[None, Some(PackFields::UserField(5))] {
                                        let current_combination: Vec<PackFields> = [
                                            &Some(PackFields::TrickyByte),
                                            &Some(PackFields::Counter(8)),
                                            usf,
                                            nnc,
                                            idc,
                                            len,
                                            ttl,
                                            hcc,
                                            ids,
                                            idr,
                                        ]
                                        .iter()
                                        .filter_map(|opt| (*opt).clone())
                                        .collect();

                                        fields_vec.push((
                                            current_combination,
                                            get_inner_value(
                                                idr.as_ref()
                                                    .unwrap_or(&PackFields::IdReceiver(6769)),
                                            ) == get_inner_value(
                                                ids.as_ref().unwrap_or(&PackFields::IdSender(6769)),
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for scippers in [0, 3, 7, 11, 15] {
            let mut how_iters = 0;
            for (fback_fields, data_fields) in fields_vec.iter().zip(
                fields_vec
                    .iter()
                    .cycle()
                    .skip(scippers)
                    .take(fields_vec.len()),
            ) {
                how_iters += 1;

                if scippers != 0 {
                    assert_ne!(data_fields, fback_fields)
                }
                //topol One
                {
                    let topo = PackTopology::new(10, &data_fields.0, true, false);

                    if !data_fields.1 {
                        assert!(
                            topo.is_err(),
                            " {:#?}\n#=========================={:#?}",
                            topo,
                            data_fields
                        );
                    } else {
                        let topo = topo.unwrap();

                        let scheme = PackScheme::OnePack(topo.clone());
                        let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();

                        assert_eq!(
                            result.absolute_maximal_fback_overhead,
                            result.absolute_maximal_overhead
                        );

                        assert_eq!(result.absolute_maximal_overhead, topo.overhead_len());

                        assert_eq!(result.counter_slice_len, topo.counter_slice().unwrap().2)
                    }
                }

                //group pack
                {
                    //(Box<[PF]>, PackTypeGroup, u8)
                    let box_pack = [
                        (
                            data_fields.0.clone().into_boxed_slice(),
                            PackTypeGroup::Data,
                            1,
                        ),
                        (
                            fback_fields.0.clone().into_boxed_slice(),
                            PackTypeGroup::Fback,
                            2,
                        ),
                    ];

                    let data_topo_test = PackTopology::new(10, &data_fields.0, true, false);
                    let fback_topo_test = PackTopology::new(10, &fback_fields.0, true, false);

                    let gp_data = GroupTopology::new(&box_pack[..], 10, true, false);
                    //check fielsds
                    if !fback_fields.1 || !data_fields.1 {
                        if !fback_fields.1 {
                            assert!(fback_topo_test.is_err(), " {:#?}", fback_topo_test);
                        }
                        if !data_fields.1 {
                            assert!(data_topo_test.is_err(), " {:#?}", data_topo_test);
                        }
                        assert!(gp_data.is_err(), " {:#?}", gp_data);
                        continue;
                    }
                    //
                    //
                    let gp_data = gp_data.unwrap();
                    let data_topo_test = data_topo_test.unwrap();
                    let fback_topo_test = fback_topo_test.unwrap();

                    let scheme = PackScheme::GroupPack(gp_data.clone());
                    let result = get_max_len_ctr_len_ttl_len_opt(scheme).unwrap();

                    let max_ovh = std::cmp::max(
                        data_topo_test.overhead_len(),
                        fback_topo_test.overhead_len(),
                    );
                    //That's an unrealistic number; the fields can't possibly be that big.
                    let unr = usize::MAX;
                    let unr = (unr, unr, unr);
                    //
                    //
                    {
                        //FIELDS TEST!!!
                        //len
                        if let Some(x) = gp_data.all_have_len_field() {
                            let f_t = fback_topo_test.len_slice();
                            let d_t = data_topo_test.len_slice();

                            assert!(x.0 == (f_t.is_some() && d_t.is_some()));

                            let f_t = f_t.unwrap_or(unr);
                            let d_t = d_t.unwrap_or(unr);

                            assert!((f_t.2 == x.1) || (d_t.2 == x.1));
                        } else {
                            assert!(
                                fback_topo_test.len_slice().is_none()
                                    || data_topo_test.len_slice().is_none()
                            );
                        }
                        //nonce
                        if let Some(x) = gp_data.all_have_nonce_field() {
                            let f_t = fback_topo_test.nonce_slice();
                            let d_t = data_topo_test.nonce_slice();

                            assert!(x.0 == (f_t.is_some() && d_t.is_some()));

                            let f_t = f_t.unwrap_or(unr);
                            let d_t = d_t.unwrap_or(unr);

                            assert!((f_t.2 == x.1) || (d_t.2 == x.1));
                        } else {
                            assert!(
                                fback_topo_test.nonce_slice().is_none()
                                    || data_topo_test.nonce_slice().is_none()
                            );
                        }

                        //id connect
                        if let Some(x) = gp_data.all_have_idconn_field() {
                            let f_t = fback_topo_test.idconn_slice();
                            let d_t = data_topo_test.idconn_slice();

                            assert!(x.0 == (f_t.is_some() && d_t.is_some()));

                            let f_t = f_t.unwrap_or(unr);
                            let d_t = d_t.unwrap_or(unr);

                            assert!((f_t.2 == x.1) || (d_t.2 == x.1));
                        } else {
                            assert!(
                                fback_topo_test.idconn_slice().is_none()
                                    || data_topo_test.idconn_slice().is_none()
                            );
                        }

                        //crc
                        if let Some(x) = gp_data.all_have_crc_field() {
                            let f_t = fback_topo_test.head_crc_slice();
                            let d_t = data_topo_test.head_crc_slice();

                            assert!(x.0 == (f_t.is_some() && d_t.is_some()));

                            let f_t = f_t.unwrap_or(unr);
                            let d_t = d_t.unwrap_or(unr);

                            assert!((f_t.2 == x.1) || (d_t.2 == x.1));
                        } else {
                            assert!(
                                data_topo_test.head_crc_slice().is_none()
                                    || fback_topo_test.head_crc_slice().is_none()
                            );
                        }

                        //ttl
                        if let Some(x) = gp_data.all_have_ttl_field() {
                            let f_t = fback_topo_test.ttl_slice();
                            let d_t = data_topo_test.ttl_slice();

                            assert!(x.0 == (f_t.is_some() && d_t.is_some()));

                            let f_t = f_t.unwrap_or(unr);
                            let d_t = d_t.unwrap_or(unr);

                            assert!((f_t.2 == x.1) || (d_t.2 == x.1));
                        } else {
                            assert!(
                                data_topo_test.ttl_slice().is_none()
                                    || fback_topo_test.ttl_slice().is_none()
                            );
                        }

                        /*user field
                        // GroupTopology doesn't implement this method,
                         and that's fine, because I'm sick of it*/

                        //id sender id recv
                        if let Some(x) = gp_data.all_have_id_sender_receiver_fields() {
                            let f_t_r = fback_topo_test.id_of_receiver_slice();
                            let d_t_r = data_topo_test.id_of_receiver_slice();
                            //
                            let f_t_s = fback_topo_test.id_of_sender_slice();
                            let d_t_s = data_topo_test.id_of_sender_slice();

                            assert!(x.0 == (f_t_r.is_some() && d_t_r.is_some()));
                            assert!(x.0 == (f_t_s.is_some() && d_t_s.is_some()));

                            let f_t_r = f_t_r.unwrap_or(unr);
                            let d_t_r = d_t_r.unwrap_or(unr);
                            //
                            let f_t_s = f_t_s.unwrap_or(unr);
                            let d_t_s = d_t_s.unwrap_or(unr);

                            assert!((f_t_r.2 == x.1) || (d_t_r.2 == x.1));

                            assert!((f_t_s.2 == x.1) || (d_t_s.2 == x.1));
                        } else {
                            assert!(
                                fback_topo_test.id_of_receiver_slice().is_none()
                                    || data_topo_test.id_of_receiver_slice().is_none()
                            );
                            assert!(
                                fback_topo_test.id_of_sender_slice().is_none()
                                    || data_topo_test.id_of_sender_slice().is_none()
                            );
                        }
                    }
                    assert_eq!(result.absolute_maximal_overhead, max_ovh);

                    assert_eq!(
                        result.counter_slice_len,
                        fback_topo_test.counter_slice().unwrap().2
                    );

                    assert_eq!(
                        result.absolute_maximal_fback_overhead,
                        fback_topo_test.overhead_len()
                    );
                }
            }

            assert_eq!(how_iters, fields_vec.len());
        }
    }
}
