use std::f32::consts::E;
use std::usize;
//Gaoo~~~ :3
use crate::t1fields::{DumpNonser, EncWis, Noncer};
use crate::t1pology::PackTopology;
use crate::wutils;

pub struct WsConnectParam {
    pack_topology: PackTopology,
    ///maximum packet size in bytes on the network</br>
    mtu: usize,
    //
    //
    ///After sending the packet, the sender waits for a certain amount of time X.</br>
    ///  If no confirmation is received within the specified time X,</br>
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient.</br>
    ///  The value of X changes dynamically during the operation of the algorithm,</br>
    ///  and the values of max_ms_latency and min_ms_latency</br>
    ///  limit its limits so that the sender does not wait forever or wait 0.0 ms.</br>
    max_ms_latency: f32,
    //
    //
    ///see description max_ms_latency ^^^</br></br>
    min_ms_latency: f32,
    //
    //
    ///see description max_ms_latency ^^^ +</br></br>
    /// initial latency must be between max_ms_latency: f32 and min_ms_latency: f32,</br>
    start_ms_latency: f32,
    //
    //
    ///see description max_ms_latency ^^^+</br></br>
    ///  if confirmation of the packet has not arrived within the waiting time X,</br>
    ///  the packet is sent again,</br>
    ///  and the waiting time for confirmation of this packet is set to this value</br>
    latency_increase_coefficient: f32,
    //
    //
    ///If confirmation of the packet has not been received,</br>
    ///  it is sent again. If confirmation of the packet is not received several</br>
    ///  times in a row, the connection is terminated. If the number of attempts</br>
    ///  to send the packet equals max_num_attempts_resend_package,</br>
    ///  the connection is terminated.</br>
    max_num_attempts_resend_package: usize,
    //
    //
    ///The connection dynamically changes the latency time.</br>
    ///  To do this, it calculates the average latency of</br>
    ///  the last packages_measurement_window_size_determining_latency packets.</br>
    ///  The smaller this number is,</br>
    ///  the faster the algorithm will respond to changes in latency.</br>
    packages_measurement_window_size_determining_latency: usize,
    //
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
    //
    ///maximum_packet_delay_coefficient_fback This is the coefficient needed to calculate how long</br>
    ///  to wait before sending a packet confirmation.</br>
    ///  It must be greater than 0, but not greater than 2.</br>
    ///  After the packet has been received by the recipient,</br>
    ///  the recipient must send an fback confirmation packet,</br>
    ///  but fback may contain several counters of received packets,</br>
    ///  so the packet recipient waits for some time before sending the fback confirmation packet,</br>
    ///  as it expects that more packets may arrive,</br>
    ///  and the recipient will add several counters of received packets</br>
    ///  to fback and send confirmation of several packets instead of one.</br></br>
    ///The waiting time is calculated as</br>
    ///  maximum_packet_delay_coefficient_fback multiplied by the current network delay time.</br>
    ///  The maximum value of 2 is chosen for reasonableness,</br>
    /// so that the maximum waiting time for sending fback is not very long.</br>
    maximum_packet_delay_coefficient_fback: f32,
    //
    //
    ///ttl is a standard field for TTL (Through The Line) Internet protocol algorithms.</br>
    ///  The first u64 is the maximum number that the counter can accept; if it is greater</br>
    ///  , the packet is considered incorrect. The second u64 is the starting ttl,</br>
    ///  which is set for the packet by its sender and must always be less than the first usize.</br>
    ///  The third i64 is the price of passing the packet through the node. In normal networks,</br>
    ///  when a packet passes through a node, its TTL is reduced by -1.</br>
    ///  If the third i64 is negative, the TTL counter will be reduced by this number</br>
    ///  . If the third i64 is positive,</br>
    ///  the TTL counter value will be increased by this number.</br>
    ///  I don't know in what situations you need to increase it,</br>
    ///  but it may be necessary.</br>
    ///  Carefully study the basics of Internet networks so you don't do anything stupid ;)</br>
    /// <h4>The maximum value of this field is limited by the maximum capacity of the field from the PackTopology structure:
    ///  (ttl).</h4>
    ttl_max_start_cost: Option<(u64, u64, i64)>,
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
    /// <h4>The maximum value of this field is limited by the maximum capacity of the field from the PackTopology structure:
    ///  (field counter).</h4>
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
    /// <h4>The maximum value of this field is limited by the maximum capacity of the field from the PackTopology structure:
    ///  (field counter +  length field, if such a field exists; if it does not exist, then the packet length is limited only by the MTU).</h4>
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
    ///#### 3 those that have been sent to fback from the recipient to the sender to confirm receipt.</br></br>
    /// <h4>The maximum value of this field is limited by the maximum capacity of the field from the PackTopology structure:
    ///  (field counter).</h4>
    maximum_length_queue_unconfirmed_packages: usize,
    //
    //
    ///percent_fake_data_packets can be greater than 0 and less than 1.0.
    ///  It is needed so that the protocol sends fake packets to make it difficult for traffic censorship
    ///  tools to detect them. When creating a useful data packet, there is a chance that a packet of
    ///  junk data will appear with the percent_fake_data_packets value.
    percent_fake_data_packets: Option<f32>,
    //
    ///see description percent_fake_data_packets^^^
    /// similar behavior for fback-type packets
    percent_fake_fback_packets: Option<f32>,
    //
    //
    ///percent_scatter_random_long_trash_padding_in_data_packs also serves to add junk data to the end of a data packet.
    ///  This is necessary to hide the actual size of the packet, especially fback packets,
    ///  since such packets are often much shorter than data packets.
    ///  usize is responsible for the maximum number of junk bytes added. As a result,
    ///  a random number of bytes from 0 to usize will be added to the end of the packet.
    percent_scatter_random_long_trash_padding_in_data_packs: Option<usize>,
    ///see description percent_scatter_random_long_trash_padding_in_data_packs^^^
    /// similar behavior for fback-type packets
    percent_scatter_random_long_trash_padding_in_fback_packs: Option<usize>,
}

impl WsConnectParam {
    ///<h2>Each variable is described in detail at the beginning of this file. Open the beginning of the file and read what is written there to avoid mistakes.
    fn new(
        pack_topology: PackTopology,
        mtu: usize,
        max_ms_latency: f32,
        min_ms_latency: f32,
        start_ms_latency: f32,
        latency_increase_coefficient: f32,
        max_num_attempts_resend_package: usize,
        packages_measurement_window_size_determining_latency: usize,
        overhead_network_latency_relative_window: f32,
        maximum_packet_delay_coefficient_fback: f32,
        maximum_length_udp_queue_packages: usize,
        maximum_length_fback_queue_packages: usize,
        maximum_length_queue_unconfirmed_packages: usize,
        percent_fake_data_packets: Option<f32>,
        percent_fake_fback_packets: Option<f32>,
        ttl_max_start_cost: Option<(u64, u64, i64)>,
        percent_scatter_random_long_trash_padding_in_data_packs: Option<usize>,
        percent_scatter_random_long_trash_padding_in_fback_packs: Option<usize>,
    ) -> Result<Self, &'static str> {
        //latency cheak
        {
            if (min_ms_latency < 0.0)
                || (max_ms_latency < 0.0)
                || (start_ms_latency < 0.0)
                || (latency_increase_coefficient < 0.0)
            {
                return Err("min_ms_latency , max_ms_latency, start_ms_latency, latency_increase_coefficient all these variables must be greater than zero");
            }

            if min_ms_latency > max_ms_latency {
                return Err("min_ms_latency > max_ms_latency The minimum start_ms_latency < min_ms_latency must be less than or equal to the maximum latency.");
            }

            if start_ms_latency > max_ms_latency {
                return Err("start_ms_latency > max_ms_latency The start latency must be less than or equal to the maximum.");
            }

            if start_ms_latency < min_ms_latency {
                return Err("start_ms_latency < min_ms_latency The start latency  must be greater than or equal to the minimum.");
            }
            if latency_increase_coefficient <= 1.0 {
                return Err("latency_increase_coefficient must be greater than or equal to 1.0. For more information, please refer to the description of this variable.");
            }

            if latency_increase_coefficient > 10.0 {
                return Err("latency_increase_coefficient should be less than or equal to 10, as it is not advisable to use a higher value. For more information, please refer to the description of this variable.");
            }
        }

        if max_num_attempts_resend_package < 1 {
            return Err("max_num_attempts_resend_package must be greater than zero. For more information, see the description of this variable at the beginning of the file.");
        }

        if packages_measurement_window_size_determining_latency < 1 {
            return Err("packages_measurement_window_size_determining_latency must be greater than zero. For more information, see the description of this variable at the beginning of the file.");
        }

        if overhead_network_latency_relative_window < 1.0 {
            return Err("overhead_network_latency_relative_window must be greater than 1.0. For more information, see the description of this variable at the beginning of the file.");
        }

        if maximum_packet_delay_coefficient_fback < 0.0 {
            return Err("maximum_packet_delay_coefficient_fback must be greater than zero. For more information, see the description of this variable at the beginning of the file.");
        }
        if maximum_packet_delay_coefficient_fback > 2.0 {
            return Err("maximum_packet_delay_coefficient_fback should be less than or equal to 2.0. For more information, see the description of this variable at the beginning of the file.");
        }
        if let Some(ttl_me) = ttl_max_start_cost {
            if let Some(ttl_in_topology) = pack_topology.ttl_slice() {
                let max_cap = wutils::len_byte_maximal_capacity_cheak(ttl_in_topology.2);
            } else {
                return Err("The ttl_max_start_cost field is defined as Some(), but in pack_topology this field is None.");
            }
        }

        Ok(Self {
            pack_topology,                                        //
            mtu,                                                  //
            max_ms_latency,                                       //
            min_ms_latency,                                       //
            start_ms_latency,                                     //
            latency_increase_coefficient,                         //
            max_num_attempts_resend_package,                      //
            packages_measurement_window_size_determining_latency, //
            overhead_network_latency_relative_window,             //
            maximum_packet_delay_coefficient_fback,               //
            ttl_max_start_cost,
            maximum_length_udp_queue_packages,
            maximum_length_fback_queue_packages,
            maximum_length_queue_unconfirmed_packages,
            percent_fake_data_packets,
            percent_fake_fback_packets,
            percent_scatter_random_long_trash_padding_in_data_packs,
            percent_scatter_random_long_trash_padding_in_fback_packs,
        })

        //Err("")
    }
}

pub struct WsPackagesParam<Tenc: EncWis> {
    ///maximum packet size in bytes on the network
    mtu: usize,
    // pack_topology: PackTopology,
    crypt_class: Tenc,
    crc_fnc: Option<fn(&[u8], &mut [u8]) -> Result<(), &'static str>>,
    nonce_gener_fnc: Option<Option<fn(&mut [u8]) -> Result<(), &'static str>>>,
    user_trash_fnc: Option<fn(&mut [u8], u64, usize) -> Result<(), &'static str>>,
}
