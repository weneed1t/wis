enum RoleWS {
    Initiator,
    Follower,
}

struct ConnectWS {
    how_of_slep_insert: u32,
    countr_of_slep_insert: u32,
    //
    sleep_in_micro_sec: u32,
    //
    countr_of_send_pack: u64,
    countr_of_fback_pack: u64,
    //
    my_role: RoleWS,
    my_cost_in_ttl: u32,
    count_of_loss_packets: u64,
    max_of_break_packets: u64,
    countr_of_break_packets: u64,
    max_queue_len: usize,
    counters_of_received_packets: Vec<u64>,
    queue_pack: Vec<(u32, Box<[u8]>)>,
}
