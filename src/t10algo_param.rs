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
    ///maximum packet size in bytes on the network</br>
    mtu: usize,
    //
    ///After sending the packet, the sender waits for a certain amount of time X.</br>
    ///  If no confirmation is received within the specified time X,</br>
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient.</br>
    ///  The value of X changes dynamically during the operation of the algorithm,</br>
    ///  and the values of max_ms_latency and min_ms_latency</br>
    ///  limit its limits so that the sender does not wait forever or wait 0.0 ms.</br>
    max_ms_latency: f32,
    //
    ///see description max_ms_latency ^^^</br></br>
    min_ms_latency: f32,
    //
    ///see description max_ms_latency ^^^ +</br></br>
    /// initial latency must be between max_ms_latency: f32 and min_ms_latency: f32,</br>
    start_ms_latency: f32,
    //
    ///see description max_ms_latency ^^^+</br></br>
    ///  if confirmation of the packet has not arrived within the waiting time X,</br>
    ///  the packet is sent again,</br>
    ///  and the waiting time for confirmation of this packet is set to this value</br>
    latency_increase_coefficient: f32,
    //
    ///If confirmation of the packet has not been received,</br>
    ///  it is sent again. If confirmation of the packet is not received several</br>
    ///  times in a row, the connection is terminated. If the number of attempts</br>
    ///  to send the packet equals max_num_attempts_resend_package,</br>
    ///  the connection is terminated.</br>
    max_num_attempts_resend_package: usize,
    //
    ///The connection dynamically changes the latency time.</br>
    ///  To do this, it calculates the average latency of</br>
    ///  the last packages_measurement_window_size_determining_latency packets.</br>
    ///  The smaller this number is,</br>
    ///  the faster the algorithm will respond to changes in latency.</br>
    packages_measurement_window_size_determining_latency: usize,
    //
    ///see description max_ms_latency ^^^ and packages_measurement_window_size_determining_latency +
    ///Network latency is determined dynamically during algorithm execution when a</br>
    ///  packet is sent and the sender waits for confirmation within: average latency</br>
    ///  of the last
    /// (packages_measurement_window_size_determining_latency) network packets *
    ///  overhead_network_latency_relative_window (overhead_network_latency_relative_window>= 1.0).</br>
    ///  This value is necessary so that packets are not resent in case of minor network instability.</br>
    overhead_network_latency_relative_window: f32,
    //
    ///ttl is a standard field for TTL (Through The Line) Internet protocol algorithms.</br>
    ///  The first usize is the maximum number that the counter can accept; if it is greater</br>
    ///  , the packet is considered incorrect. The second usize is the starting ttl,</br>
    ///  which is set for the packet by its sender and must always be less than the first usize.</br>
    ///  The third i64 is the price of passing the packet through the node. In normal networks,</br>
    ///  when a packet passes through a node, its TTL is reduced by -1.</br>
    ///  If the third i64 is negative, the TTL counter will be reduced by this number</br>
    ///  . If the third i64 is positive,</br>
    ///  the TTL counter value will be increased by this number.</br>
    ///  I don't know in what situations you need to increase it,</br>
    ///  but it may be necessary.</br>
    ///  Carefully study the basics of Internet networks so you don't do anything stupid ;)</br>
    ttl_max_start_cost: Option<(usize, usize, i64)>,
    //
    //
    ///The maximum_length_udp_queue_packages value is used in the WSUdpLike class.</br>
    ///  For more details, see the WSUdpLike API. In short,</br>
    ///  WSUdpLike is needed to restore the sequence of packets</br>
    ///  if some packets arrived out of order/were duplicated/or to wait for lost packets.</br>
    ///  Ideally, maximum_length_udp_queue_packages should be greater than or equal to maximum_length_queue_unconfirmed_package.</br>
    ///  This is because if maximum_length_queue_unconfirmed_package is larger,</br>
    ///  a situation may arise where the WSUdpLike queue overflows and valid packets are rejected.</br>
    ///  This will lead to an increase in network load.</br>
    maximum_length_udp_queue_packages: usize,
    //
    //
    ///maximum_length_fback_queue_packages is a value used in WSRecvQueueCtrs.</br>
    ///  For more information, see WSRecvQueueCtrs API. Brief information.</br>
    /// When a node receives a packet, it must send a confirmation, analogous to an ACK packet in TCP.</br>
    ///  In this algorithm, it is called “fback”.</br>
    ///  The fback acknowledgment packet contains the numbers of the packet counters that were received.</br>
    ///  The maximum number of counters is determined by maximum_length_fback_queue_packages. However,</br>
    ///  the fback packet must fit entirely within the network MTU.</br>
    ///  If the calculated size in bytes of the fback packet does not fit within the MTU,</br>
    ///  maximum_length_fback_queue_packages will be forcibly reduced when the instance is created.  </br>
    maximum_length_fback_queue_packages: usize,
    //
    //
    ///maximum_length_queue_unconfirmed_packages is required for use in WSWaitQueue. </br>
    ///  For complete information, see the WSWaitQueue API.</br></br>
    ///  In short, when the sender sends a packet, in addition to sending it,</br>
    ///  this packet is sent to storage in WSWaitQueue. When the sender receives the fback packet,</br>
    ///  it deletes all packets from fback that are in WSWaitQueue.</br>
    ///  Periodically, the sender checks WSWaitQueue for packets with expired confirmation times and resends them.</br>
    ///  It is recommended that maximum_length_queue_unconfirmed_packages be</br>
    ///  three times larger than maximum_length_fback_queue_packages.</br>
    ///  Logically, packets can be divided into:</br>
    ///#### 1 those that are still in transit from the sender to the recipient.
    ///#### 2 those that have been received and are stored in fback.
    ///#### 3 those that have been sent to fback from the recipient to the sender to confirm receipt.
    maximum_length_queue_unconfirmed_packages: usize,
    //

    //
    //
    percent_fake_packets: Option<f32>,
    percent_scatter_random_long_trash_padding_in_data_packs: Option<f32>,
    percent_scatter_random_long_trash_padding_in_fback_packs: Option<f32>,
    //key_gen_data_scheme:(usize,[usize;]),
}

//struct WsAllParam {}
