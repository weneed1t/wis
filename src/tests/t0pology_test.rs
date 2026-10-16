use crate::t0pology::*;
mod tests {

    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
    use super::*;

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
            Some("duplicate len".to_string()),
            "expected 'duplicate len' error"
        );

        // Len value exceeds 8
        let fields_invalid_len = vec![PackFields::Len(9)];
        assert_eq!(
            PackTopology::new(5, &fields_invalid_len, false, false).err(),
            Some("len value exceeds 8".to_string()),
            "expected 'len value exceeds 8' error"
        );

        // CRC len is 0
        let fields_zero_crc = vec![PackFields::HeadCRC(0)];
        assert_eq!(
            PackTopology::new(5, &fields_zero_crc, false, false).err(),
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0".to_string()),
            "expected 'crc len is 0' error"
        );

        // Missing Counter or Nonce
        let fields_no_counter_or_nonce = vec![PackFields::Len(4)];
        assert_eq!(
            PackTopology::new(5, &fields_no_counter_or_nonce, false, false).err(),
            Some("the structure must have either a Counter field".to_string()),
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
                    .to_string()
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
                    .to_string()
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
        assert_eq!(topology.overhead_len(), 4, "total_minimal_len should be 4");
    }

    #[test]
    fn test_edge_cases2() {
        // Minimal valid input
        let fields_minimal_valid = vec![PackFields::Counter(1)];
        let result = PackTopology::new(1, &fields_minimal_valid, true, false);

        let topology = result.unwrap();
        assert_eq!(topology.overhead_len(), 3, "total_minimal_len should be 3");
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
            topology.overhead_len(),
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
                Some("len value exceeds 8".to_string()),
                "expected 'len value exceeds 8' error for Len({})",
                invalid_value
            );

            // Counter
            let fields_counter = vec![PackFields::Counter(invalid_value)];
            let result = PackTopology::new(5, &fields_counter, true, true);
            assert_eq!(
                result.err(),
                Some("counter value exceeds 8".to_string()),
                "expected 'counter value exceeds 8' error for Counter({})",
                invalid_value
            );

            // IdSender
            let fields_id_sender =
                vec![PackFields::Counter(2), PackFields::IdSender(invalid_value)];
            let result = PackTopology::new(5, &fields_id_sender, true, true);
            assert_eq!(
                result.err(),
                Some("IdSender value exceeds 8".to_string()),
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
                Some("idreceiver value exceeds 8".to_string()),
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
                    Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0".to_string()),
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
                    Some("nonce len is 0".to_string()),
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
                Some("TTL value exceeds MAXIMAL_TTL_LEN or  == 0".to_string()),
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
            Some("idconn value exceeds 8".to_string())
        );

        // Duplicate
        let fields_dup = vec![
            PackFields::IdConnect(4),
            PackFields::IdConnect(4), // Duplicate
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_dup, true, true).err(),
            Some("duplicate idconn".to_string())
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
                .tricky_byte(),
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
            Some("duplicate tricky_byte".to_string())
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
            Err("userfield nums > MAXIMAL_NUMS_USER_FIELDS".to_string())
        );
    }

    #[test]
    fn test_header_only_config() {
        let fields = vec![PackFields::Counter(4)];
        let result = PackTopology::new(0, &fields, true, false);
        assert_eq!(result.err(), Some("!!tag_len ==0".to_string()));
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
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0".to_string())
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
            Some("id_of_receiver_slice and id_of_sender_slice must be the same length".to_string())
        );

        let fields = vec![PackFields::Counter(4)];
        let result = PackTopology::new(5, &fields, true, true);
        assert_eq!(
            result.err(),
            Some(
                "If your data channel is like TCP, you should specify the Len(usize) field."
                    .to_string()
            )
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
        assert_eq!(topology.overhead_len(), 99);
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
            Some("duplicate idconn".to_string())
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
            Some("duplicate tricky_byte".to_string())
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
            Some("userfield nums > MAXIMAL_NUMS_USER_FIELDS".to_string())
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
            Some("crc len is  le > MAXIMAL_CRC_LEN or crc len is 0".to_string())
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
            Some("userfield value is 0".to_string())
        );

        // Zero-length in middle of list — also invalid
        let fields_zero_mid = vec![
            PackFields::UserField(3),
            PackFields::UserField(0),
            PackFields::Counter(4),
        ];
        assert_eq!(
            PackTopology::new(5, &fields_zero_mid, true, true).err(),
            Some("userfield value is 0".to_string())
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
            Some("id_of_receiver_slice and id_of_sender_slice must be the same length".to_string())
        );
    }

    #[test]
    fn test_tcp_mode_requires_len_field() {
        let fields = vec![PackFields::Counter(4)];
        assert_eq!(
            PackTopology::new(5, &fields, true, true).err(),
            Some(
                "If your data channel is like TCP, you should specify the Len(usize) field."
                    .to_string()
            )
        );
    }
}

//AI gen test

mod tests_coverage_gaps {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]

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
            Some("duplicate counter".to_string())
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
            Some("duplicate IdSender".to_string())
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
            Some("duplicate idreceiver".to_string())
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
            Some("duplicate crc".to_string())
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
            Some("duplicate nonce".to_string())
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
            Some("duplicate ttl".to_string())
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
            Some("sender and receiver IDs must both exist or both be absent".to_string())
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
            Some("sender and receiver IDs must both exist or both be absent".to_string())
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
            Some("userfield value is 0".to_string())
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
                    .to_string()
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
                    .to_string()
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

        assert_eq!(topo.overhead_len(), 999);
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
        let _ = topo.overhead_len();
        //let _ = topo.is_tcp();
        //let _ = topo.data_save();
        let _ = topo.tricky_byte();

        // Basic sanity check
        assert!(topo.tag_len() > 0);
        assert!(topo.content_start_pos() > topo.encrypt_start_pos());
    }
}

mod packfields_tests {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
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

mod test_equal {
    #![allow(clippy::indexing_slicing)]
    #![allow(clippy::unwrap_used)]
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
