use std::usize;
//Gaoo~~~ :3
use crate::t1fields::{DumpNonser, EncWis, Noncer};
use crate::t1pology::PackTopology;

pub struct WsPackagesParam<Tenc: EncWis> {
    ///maximum packet size in bytes on the network
    mtu: usize,
    pack_topology: PackTopology,
    crypt_class: Tenc,
    crc_fnc: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    nonce_gener_fnc: Option<Option<fn(&mut [u8]) -> Result<(), &'static str>>>,
    user_trash_fnc: Option<fn(&mut [u8], u64, usize) -> Result<(), &'static str>>,
}

pub struct WsConnectParam {
    ///maximum packet size in bytes on the network
    mtu: usize,
    //
    ///After sending the packet, the sender waits for a certain amount of time X.
    ///  If no confirmation is received within the specified time X,
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient.
    ///  The value of X changes dynamically during the operation of the algorithm,
    ///  and the values of max_ms_latency and min_ms_latency
    ///  limit its limits so that the sender does not wait forever or wait 0.0 ms.
    max_ms_latency: f32,
    //
    ///see description max_ms_latency ^^^
    min_ms_latency: f32,
    //
    ///see description max_ms_latency ^^^ +
    /// initial latency must be between max_ms_latency: f32 and min_ms_latency: f32,
    start_ms_latency: f32,
    //
    ///see description max_ms_latency ^^^+
    ///  if confirmation of the packet has not arrived within the waiting time X,
    ///  the packet is sent again,
    ///  and the waiting time for confirmation of this packet is set to this value
    latency_increase_coefficient: f32,
    //
    ///If confirmation of the packet has not been received,
    ///  it is sent again. If confirmation of the packet is not received several
    ///  times in a row, the connection is terminated. If the number of attempts
    ///  to send the packet equals max_num_attempts_resend_package,
    ///  the connection is terminated.
    max_num_attempts_resend_package: usize,
    //
    ///The connection dynamically changes the latency time.
    ///  To do this, it calculates the average latency of
    ///  the last packages_measurement_window_size_determining_latency packets.
    ///  The smaller this number is,
    ///  the faster the algorithm will respond to changes in latency.
    packages_measurement_window_size_determining_latency: usize,
    //
    ///see description max_ms_latency ^^^ and packages_measurement_window_size_determining_latency +
    ///Network latency is determined dynamically during algorithm execution when a
    ///  packet is sent and the sender waits for confirmation within: average latency
    ///  of the last
    /// (packages_measurement_window_size_determining_latency) network packets *
    ///  overhead_network_latency_relative_window (overhead_network_latency_relative_window>= 1.0).
    ///  This value is necessary so that packets are not resent in case of minor network instability.
    overhead_network_latency_relative_window: f32,
    //
    ///ttl is a standard field for TTL (Through The Line) Internet protocol algorithms.
    ///  The first usize is the maximum number that the counter can accept; if it is greater
    ///  , the packet is considered incorrect. The second usize is the starting ttl,
    ///  which is set for the packet by its sender and must always be less than the first usize.
    ///  The third i64 is the price of passing the packet through the node. In normal networks,
    ///  when a packet passes through a node, its TTL is reduced by -1.
    ///  If the third i64 is negative, the TTL counter will be reduced by this number
    ///  . If the third i64 is positive,
    ///  the TTL counter value will be increased by this number.
    ///  I don't know in what situations you need to increase it,
    ///  but it may be necessary.
    ///  Carefully study the basics of Internet networks so you don't do anything stupid ;)
    ttl_max_start_cost: Option<(usize, usize, i64)>,
    //

    //
    maximum_length_fback_queue_packages: usize,
    coefficient_maximum_length_queue_unconfirmed_packages: f32,
    //

    //
    //
    percent_fake_packets: Option<f32>,
    percent_scatter_random_long_trash_padding_in_data_packs: Option<f32>,
    percent_scatter_random_long_trash_padding_in_fback_packs: Option<f32>,
    //key_gen_data_scheme:(usize,[usize;]),
}

//struct WsAllParam {}
