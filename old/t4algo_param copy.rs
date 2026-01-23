//Gaoo~~~ :3
use crate::t1fields::{DumpNonser, EncWis, Noncer};
use crate::t1pology::PackTopology;
use crate::wutils;

#[derive(Debug, PartialEq)]
pub struct WsConnectParam {
    pack_topology: PackTopology,
    ///maximum packet size in bytes on the network</br>
    mtu: usize,
    //
    //
    ///After sending the packet, the sender waits for a certain amount of time X.</br>
    ///  If no confirmation is received within the specified time X,</br>
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient. X = X+X*latency_increase_coefficient</br>
    ///  The value of X changes dynamically during the operation of the algorithm,</br>
    ///  and the values of max_ms_latency and min_ms_latency</br>
    ///  limit its limits so that the sender does not wait forever or wait 0.0 ms.</br>
    max_ms_latency: f64,
    //
    //
    ///see description max_ms_latency ^^^</br></br>
    min_ms_latency: f64,
    //
    //
    ///see description max_ms_latency ^^^ +</br></br>
    /// initial latency must be between max_ms_latency: f64 and min_ms_latency: f64,</br>
    start_ms_latency: f64,
    //
    //
    ///see description max_ms_latency ^^^+</br></br>
    ///  if confirmation of the packet has not arrived within the waiting time X,</br>
    ///  the packet is sent again,</br>
    ///  and the waiting time for confirmation of this packet is set to this value</br>
    /// 1.0 >= latency_increase_coefficient >0
    latency_increase_coefficient: f64,
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
    ///not related to other parameters, the lower the value, the more the adjustment will occur while waiting for confirmation
    packages_measurement_window_size_determining_latency: usize,
    //
    //
    ///see description max_ms_latency ^^^ and packages_measurement_window_size_determining_latency +
    ///Network latency is determined dynamically during algorithm execution when a</br>
    ///  packet is sent and the sender waits for confirmation within: average latency</br>
    ///  of the last
    /// (packages_measurement_window_size_determining_latency) network packets *
    ///  overhead_network_latency_relative_window_coefficient  (1.0 >= overhead_network_latency_relative_window_coefficient >= 0.0).</br>
    ///  This value is necessary so that packets are not resent in case of minor network instability.</br>
    overhead_network_latency_relative_window_coefficient: f64,
    //
    //
    ///maximum_packet_delay_fback_coefficient This is the coefficient needed to calculate how long</br>
    ///  to wait before sending a packet confirmation.</br>
    ///  It must be greater than 0, but not greater than 1.0.</br>
    ///  After the packet has been received by the recipient,</br>
    ///  the recipient must send an fback confirmation packet,</br>
    ///  but fback may contain several counters of received packets,</br>
    ///  so the packet recipient waits for some time before sending the fback confirmation packet,</br>
    ///  as it expects that more packets may arrive,</br>
    ///  and the recipient will add several counters of received packets</br>
    ///  to fback and send confirmation of several packets instead of one.</br></br>
    ///The waiting time is calculated as</br>
    ///  maximum_packet_delay_fback_coefficient multiplied by the current network delay time.</br>
    ///  The maximum value of 1.0 is chosen for reasonableness,</br>
    /// so that the maximum waiting time for sending fback is not very long.</br>
    maximum_packet_delay_fback_coefficient: f64,
    //
    //
    ///see description maximum_packet_delay_fback_coefficient ^^^
    ///This is the maximum absolute value that the fback packet will wait before being sent.
    ///The value must be between 0 and max_ms_latency.
    maximum_packet_delay_absolute_fback: f64,
    //
    //
    ///ttl is a standard field for TTL (Time To Live) Internet protocol algorithms.</br>
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
    /// This is a recommendation, not a mandatory value, and it depends on the parameters and properties of the external environment.</br></br>
    ///  Logically, packets can be divided into:</br>
    ///#### 1 those that are still in transit from the sender to the recipient.
    ///#### 2 those that have been received and are stored in fback.
    ///#### 3 those that have been sent to fback from the recipient to the sender to confirm receipt.</br></br>
    /// <h4>The maximum value of this field is limited by the maximum capacity of the field from the PackTopology structure:
    ///  (field counter).</h4>
    maximum_length_queue_unconfirmed_packages: usize,
    //
    //
    ///percent_fake_data_packets can be in  0 > && <= 1.0.
    ///  It is needed so that the protocol sends fake packets to make it difficult for traffic censorship
    ///  tools to detect them. When creating a useful data packet, there is a chance that a packet of
    ///  junk data will appear with the percent_fake_data_packets value.
    percent_fake_data_packets: Option<f64>,
    //
    ///see description percent_fake_data_packets^^^
    /// similar behavior for fback-type packets
    percent_fake_fback_packets: Option<f64>,
    //
    //
    ///bytes_scatter_random_long_trash_padding_in_data_packs also serves to add junk data to the end of a data packet.
    ///  This is necessary to hide the actual size of the packet, especially fback packets,
    ///  since such packets are often much shorter than data packets.
    ///  usize is responsible for the maximum number of junk bytes added. As a result,
    ///  a random number of bytes from 0 to usize will be added to the end of the packet.
    /// The garbage consists only of ZERO BYTES
    ///garbage is added to the end of ENCRYPTED data,
    ///  which makes it impossible to determine the actual length of the packet based on the packet length field (if any)
    ///  until the packet is decrypted. Garbage can only be added to the end of a complete file,
    ///  which is a continuous segment of useful data of any length, often longer than the data packet.
    ///  Garbage can only be inserted into the last packet of the file.
    ///  To randomize the length of packets in the middle of the file, use “percent_len_random_coefficient”.
    percent_add_rand_nums_bytes_data_packs: Option<f64>,
    ///see description percent_add_rand_nums_bytes_data_packs^^^
    /// similar behavior for fback-type packets
    /// The fback packet must always be and is a packet that transmits complete data,
    ///  i.e., junk data can be added to any fback packet.
    percent_add_rand_nums_bytes_fback_packs: Option<f64>,

    ///percent_len_random_coefficient is needed to randomize the length to which packets will be cut,<br><br>
    ///  for example, file length = 1000 bytes, your network's MTU = 100 bytes,<br>
    ///  the packet's working fields occupy 20 bytes, then to transfer the file,<br>
    ///  you need 12 full packets of 100 bytes (20 bytes of service bytes  + 80 useful bytes)<br>
    ///  and 1 packet of 60 bytes (20 service bytes + 40 useful bytes).<br>
    ///  If the value of percent_len_random_coefficient Some(1.0>= x > 0.0) is,<br>
    ///  for example, 0.3, then the packet length will not be 100 bytes,<br>
    ///  but 100-20 (MTU - minimum packet size) * 0.3 = 24.<br>
    ///  Each packet will have a length from MTU - 24 to MTU.<br>
    percent_len_random_coefficient: Option<f64>,

    ///instant_feedback_on_packet_loss is needed so that when packet loss is detected,<br>
    ///fback is immediately returned with confirmed packets. For example,<br>
    ///the recipient received packets numbered 11, 12, 13, 15, 16, and 17.<br>
    ///and sees that packet number 15 is missing,<br>
    ///sends fback with confirmation of receipt of 11, 12, 13, 15, 16, and 17.<br>
    ///The sender sees that the recipient<br>
    ///did not receive packet 15 and sends packet 15 immediately after receiving fback.<br>
    ///If instant_feedback_on_packet_los == false,<br>
    ///then if the sender receives confirmation of receipt of packets 11,12,13,15,16,17,<br>
    ///it will NOT send packet 15, but will wait for the packet confirmation timeout<br>
    ///(see the latency_increase_coefficient and max_ms_latency documentation)<br>
    ///and only after the timeout will it resend packet 15.<br>
    instant_feedback_on_packet_loss: bool,
}

impl WsConnectParam {
    ///<h2>Each variable is described in detail at the beginning of this file. Open the beginning of the file and read what is written there to avoid mistakes.
    pub fn new(
        pack_topology: &PackTopology,
        mtu: usize,
        instant_feedback_on_packet_loss: bool,
        packages_measurement_window_size_determining_latency: usize,
        maximum_length_udp_queue_packages: usize,
        maximum_length_fback_queue_packages: usize,
        maximum_length_queue_unconfirmed_packages: usize,
        max_num_attempts_resend_package: usize,
        max_ms_latency: f64,   //>0
        min_ms_latency: f64,   //>0
        start_ms_latency: f64, //>0
        latency_increase_coefficient: f64,
        overhead_network_latency_relative_window_coefficient: f64,
        maximum_packet_delay_fback_coefficient: f64,
        maximum_packet_delay_absolute_fback: f64,
        ttl_max_start_cost: Option<(u64, u64, i64)>,
        percent_fake_data_packets: Option<f64>,
        percent_fake_fback_packets: Option<f64>,
        percent_add_rand_nums_bytes_data_packs: Option<f64>,
        percent_add_rand_nums_bytes_fback_packs: Option<f64>,
        percent_len_random_coefficient: Option<f64>,
    ) -> Result<Self, &'static str> {
        if pack_topology.total_minimal_len() > mtu {
            return Err("pack_topology.total_minimal_len() > mtu mtu must be significantly larger than pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is the minimum packet length, such a packet contains only protocol service information, mtu must be large enough to accommodate the length of the packet's useful data and service data.");
        }
        if !min_ms_latency.is_normal()
            || !max_ms_latency.is_normal()
            || !start_ms_latency.is_normal()
            || !latency_increase_coefficient.is_normal()
            || !maximum_packet_delay_absolute_fback.is_normal()
            || !overhead_network_latency_relative_window_coefficient.is_normal()
            || !maximum_packet_delay_fback_coefficient.is_normal()
        {
            return Err("all f64 variables must be is_normal()");
        }
        if (min_ms_latency <= 0.0)
            || (max_ms_latency <= 0.0)
            || (start_ms_latency <= 0.0)
            || (latency_increase_coefficient <= 0.0)
            || (maximum_packet_delay_absolute_fback < 0.0)
            || (overhead_network_latency_relative_window_coefficient < 0.0)
            || (maximum_packet_delay_fback_coefficient <= 0.0)
        {
            return Err("all f64 variables must be greater than zero");
        }

        if (maximum_length_udp_queue_packages < 1)
            || (maximum_length_fback_queue_packages < 1)
            || (maximum_length_queue_unconfirmed_packages < 1)
            || (packages_measurement_window_size_determining_latency < 1)
            || (max_num_attempts_resend_package < 1)
        {
            return Err("all usize variables must be greater than zero");
        }

        if (latency_increase_coefficient > 1.0)
            || (overhead_network_latency_relative_window_coefficient > 1.0)
            || (maximum_packet_delay_fback_coefficient > 1.0)
        {
            return Err("latency_increase_coefficient overhead_network_latency_relative_window_coefficient maximum_packet_delay_fback_coefficient must be greater than zero");
        }

        //latency check
        {
            if min_ms_latency > max_ms_latency {
                return Err("min_ms_latency > max_ms_latency The minimum start_ms_latency < min_ms_latency must be less than or equal to the maximum latency.");
            }

            if start_ms_latency > max_ms_latency {
                return Err("start_ms_latency > max_ms_latency The start latency must be less than or equal to the maximum.");
            }

            if start_ms_latency < min_ms_latency {
                return Err("start_ms_latency < min_ms_latency The start latency  must be greater than or equal to the minimum.");
            }
        }

        {
            let ctr_max_capacity = wutils::len_byte_maximal_capacity_check(
            pack_topology
                .counter_slice()
                .ok_or(
                    "The counter_slice() field in pack_topology is None, but it must be specified!",
                )?
                .2,
        );
            //See the description of the pub fn set_counter function in the pub mod t1fields file
            // to understand why this logic for obtaining maximum capacity is used here.
            let ctr_max_capacity_real = (ctr_max_capacity.0 >> 1).checked_sub(1).expect("(ctr_max_capacity.0 >> 1) - 1 < 0 error, impossible behavior, since the minimum length of counter_slice() is 1, 1 byte is 255 maximum value, 255 >>1 - 127, 127 is greater than 1.");

            //https://github.com/ilostmyg1thubkey You dumbass,
            //this shit will only work if ctr_max_capacity_real is not greater than 32 bits, even on 32-bit systems, bitch.
            if ctr_max_capacity_real > usize::MAX as u64 {
                return Err("ctr_max_capacity_real > usize::MAX as u64, Counter capacity exceeds system's usize limit");
            }

            if maximum_length_udp_queue_packages > ctr_max_capacity_real as usize {
                return Err(" maximum_length_udp_queue_packages must be less than the maximum capacity of the pack_topology.counter_slice() field. ");
            }
            if maximum_length_udp_queue_packages < maximum_length_queue_unconfirmed_packages {
                return Err(" maximum_length_udp_queue_packages must be greater than maximum_length_queue_unconfirmed_packages so that all packets are confirmed. For more information, see the description of this variable at the beginning of the file.");
            }

            if maximum_length_fback_queue_packages > ctr_max_capacity_real as usize {
                return Err("maximum_length_fback_queue_packages must not exceed the maximum capacity of the pack_topology.counter_slice() counter. ");
            }

            if max_num_attempts_resend_package > ctr_max_capacity_real as usize {
                return Err("max_num_attempts_resend_package > ctr_max_capacity_real as usize.  max_num_attempts_resend_package must be less than the maximum possible capacity in pack_topology.counter_slice().");
            }
        }

        if maximum_packet_delay_absolute_fback > max_ms_latency {
            return Err("The variable maximum_packet_delay_absolute_fback must be no greater than max_ms_latency For more information, see the description of this variable at the beginning of the file.");
        }
        //ttl
        if let Some(ttl_me) = ttl_max_start_cost {
            if let Some(ttl_in_topology) = pack_topology.ttl_slice() {
                let max_cap = wutils::len_byte_maximal_capacity_check(ttl_in_topology.2);

                if ttl_me.0 < ttl_me.1 {
                    return Err("err:ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum ttl value. For more information, see the description of this variable at the beginning of the file.");
                }
                if ttl_me.0 == 0 {
                    return Err("ttl_max_start_cost.0 must be greater than zero. For more information, see the description of this variable at the beginning of the file.");
                }

                if ttl_me.1 == 0 {
                    return Err("ttl_max_start_cost.1 must be greater than zero. For more information, see the description of this variable at the beginning of the file.");
                }

                if ttl_me.1 > max_cap.0 {
                    return Err("ttl_max_start_cost.1 is greater than the length that can be accommodated in the pack_topology field.");
                }
            } else {
                return Err("The ttl_max_start_cost field is defined as Some(), but in pack_topology this field is None.");
            }
        }

        if maximum_length_fback_queue_packages > maximum_length_queue_unconfirmed_packages {
            return Err(" maximum_length_fback_queue_packages must be less than maximum_length_queue_unconfirmed_packages.For more information, see the description of this variable at the beginning of the file.");
        }
        //percent

        if let Some(x) = percent_fake_data_packets {
            if !x.is_normal() || x > 1.0 || x <= 0.0 {
                return Err("percent_fake_data_packets must be in the range from (0.0 to 1.0]");
            }
        }

        if let Some(x) = percent_fake_fback_packets {
            if !x.is_normal() || x > 1.0 || x <= 0.0 {
                return Err("percent_fake_fback_packets must be in the range from (0.0 to 1.0]");
            }
        }

        if let Some(x) = percent_len_random_coefficient {
            if !x.is_normal() || x > 1.0 || x <= 0.0 {
                return Err(
                    "percent_len_random_coefficient must be in the range from (0.0 to 1.0]",
                );
            }
        }

        if let Some(x) = percent_add_rand_nums_bytes_data_packs {
            if !x.is_normal() || x > 1.0 || x <= 0.0 {
                return Err("percent_add_rand_nums_bytes_data_packs must be in the range from (0.0 to 1.0] For more information, see the description of this variable at the beginning of the file.");
            }
        }
        if let Some(x) = percent_add_rand_nums_bytes_fback_packs {
            if !x.is_normal() || x > 1.0 || x <= 0.0 {
                return Err("percent_add_rand_nums_bytes_fback_packs must be in the range from (0.0 to 1.0] For more information, see the description of this variable at the beginning of the file.");
            }
        }

        Ok(Self {
            pack_topology: pack_topology.clone(), //
            /**/
            mtu,
            /**/                                                  //
            max_ms_latency,                                       //
            min_ms_latency,                                       //
            start_ms_latency,                                     //
            latency_increase_coefficient,                         //
            max_num_attempts_resend_package,                      //
            packages_measurement_window_size_determining_latency, //
            overhead_network_latency_relative_window_coefficient, //
            /**/
            maximum_packet_delay_fback_coefficient, //
            maximum_packet_delay_absolute_fback,
            /**/
            ttl_max_start_cost, //
            /**/
            maximum_length_udp_queue_packages,         //
            maximum_length_fback_queue_packages,       //
            maximum_length_queue_unconfirmed_packages, //
            /**/
            percent_fake_data_packets,               //
            percent_fake_fback_packets,              //
            percent_add_rand_nums_bytes_data_packs,  //
            percent_add_rand_nums_bytes_fback_packs, //
            instant_feedback_on_packet_loss,
            percent_len_random_coefficient,
        })
    }
}

///interface
impl WsConnectParam {
    pub fn pack_topology(&self) -> &PackTopology {
        &self.pack_topology
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn max_ms_latency(&self) -> f64 {
        self.max_ms_latency
    }

    pub fn min_ms_latency(&self) -> f64 {
        self.min_ms_latency
    }

    pub fn start_ms_latency(&self) -> f64 {
        self.start_ms_latency
    }

    pub fn latency_increase_coefficient(&self) -> f64 {
        self.latency_increase_coefficient
    }

    pub fn max_num_attempts_resend_package(&self) -> usize {
        self.max_num_attempts_resend_package
    }

    pub fn packages_measurement_window_size_determining_latency(&self) -> usize {
        self.packages_measurement_window_size_determining_latency
    }

    pub fn overhead_network_latency_relative_window_coefficient(&self) -> f64 {
        self.overhead_network_latency_relative_window_coefficient
    }

    pub fn maximum_packet_delay_fback_coefficient(&self) -> f64 {
        self.maximum_packet_delay_fback_coefficient
    }

    pub fn maximum_packet_delay_absolute_fback(&self) -> f64 {
        self.maximum_packet_delay_absolute_fback
    }

    pub fn ttl_max_start_cost(&self) -> Option<(u64, u64, i64)> {
        self.ttl_max_start_cost
    }

    pub fn maximum_length_udp_queue_packages(&self) -> usize {
        self.maximum_length_udp_queue_packages
    }

    pub fn maximum_length_fback_queue_packages(&self) -> usize {
        self.maximum_length_fback_queue_packages
    }

    pub fn maximum_length_queue_unconfirmed_packages(&self) -> usize {
        self.maximum_length_queue_unconfirmed_packages
    }

    pub fn percent_fake_data_packets(&self) -> Option<f64> {
        self.percent_fake_data_packets
    }

    pub fn percent_fake_fback_packets(&self) -> Option<f64> {
        self.percent_fake_fback_packets
    }

    pub fn percent_add_rand_nums_bytes_data_packs(&self) -> Option<f64> {
        self.percent_add_rand_nums_bytes_data_packs
    }

    pub fn percent_add_rand_nums_bytes_fback_packs(&self) -> Option<f64> {
        self.percent_add_rand_nums_bytes_fback_packs
    }

    pub fn percent_len_random_coefficient(&self) -> Option<f64> {
        self.percent_len_random_coefficient
    }

    pub fn instant_feedback_on_packet_loss(&self) -> bool {
        self.instant_feedback_on_packet_loss
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

#[cfg(test)]
mod test_new_ws_param {

    use super::*;
    use crate::t1pology::PackTopology;
    use crate::t1pology::PakFields;
    fn get_topol() -> PackTopology {
        let fields = vec![
            //t2page::PakFields::HeadByte,
            PakFields::UserField(1),
            PakFields::Counter(5),
            PakFields::IdConnect(2),
            PakFields::HeadCRC(2),
            PakFields::Nonce(6),
            //PakFields::TTL(2),
            PakFields::Len(3),
        ];

        PackTopology::new(16, &fields, true, true).unwrap()
    }

    #[test]
    fn t1() {
        let topol = get_topol();

        let generator = [-0.1, 0.0, 0.5, 1.0];
        let mut i = 0;
        for x0 in generator.iter() {
            for x1 in generator.iter() {
                for x2 in generator.iter() {
                    for x3 in generator.iter() {
                        let resulta = WsConnectParam::new(
                            &topol, //pack_topology,
                            100,    //mtu,
                            *x0,    //max_ms_latency,
                            *x1,    //min_ms_latency,
                            *x2,    //start_ms_latency,
                            *x3,    //latency_increase_coefficient,
                            1,      //max_num_attempts_resend_package,
                            1,      //packages_measurement_window_size_determining_latency,
                            2000.1, //overhead_network_latency_relative_window_coefficient ,
                            1.1,    //maximum_packet_delay_fback_coefficient,
                            1.1, 1,    //maximum_length_udp_queue_packages,
                            1,    //maximum_length_fback_queue_packages,
                            1,    //maximum_length_queue_unconfirmed_packages,
                            None, //percent_fake_data_packets,
                            None, //percent_fake_fback_packets,
                            None, //ttl_max_start_cost,
                            None, //bytes_scatter_random_long_trash_padding_in_data_packs,
                            None, //percent_add_rand_nums_bytes_fback_packs
                        );
                        //if resulta.is_err() {
                        //println!("(/*{}*/ /*max*/ {},  /*min*/ {},  /*start*/ {},  /*coeff*/ {},  /*res*/ {:?}),",i,x0,x1,x2,x3,resulta);
                        println!("(/*{}*/ /*max*/ {:.3},  /*min*/ {:.3},  /*start*/ {:.3},  /*coeff*/ {:.3},  /*res*/ {:?}),",i,x0,x1,x2,x3,resulta.is_ok());
                        i += 1;
                        //} else {
                        //println!("");
                        //println!("");
                        //println!("");
                        //println!("");
                        //}
                    }
                }
            }
        }
        return;
    }

    fn dump_param_gen(
        x0: f64,
        x1: f64,
        x2: f64,
        x3: f64,
        x4: f64,
    ) -> Result<WsConnectParam, &'static str> {
        WsConnectParam::new(
            &get_topol(), //pack_topology,
            100,          //mtu,
            x0,           //max_ms_latency,
            x1,           //min_ms_latency,
            x2,           //start_ms_latency,
            x3,           //latency_increase_coefficient,
            1,            //max_num_attempts_resend_package,
            1,            //packages_measurement_window_size_determining_latency,
            2000.1,       //overhead_network_latency_relative_window_coefficient ,
            1.1,          //maximum_packet_delay_fback_coefficient,
            x4,
            1,    //maximum_length_udp_queue_packages,
            1,    //maximum_length_fback_queue_packages,
            1,    //maximum_length_queue_unconfirmed_packages,
            None, //percent_fake_data_packets,
            None, //percent_fake_fback_packets,
            None, //ttl_max_start_cost,
            None, //bytes_scatter_random_long_trash_padding_in_data_packs,
            None, //percent_add_rand_nums_bytes_fback_packs
        )
    }
    // #[test]
    fn _generator() {
        let generator = [f64::INFINITY, -0.1, 0.0, f64::NAN, 0.01, 0.5, 1.0_f64];
        let mut i = 0;

        for x0 in generator.iter() {
            for x1 in generator.iter() {
                for x2 in generator.iter() {
                    for x3 in generator.iter() {
                        for x4 in generator.iter() {
                            let resulta = dump_param_gen(*x0, *x1, *x2, *x3, *x4);

                            if resulta.is_ok() {
                                //println!("(/*{}*/ /*max*/ {},  /*min*/ {},  /*start*/ {},  /*coeff*/ {},  /*res*/ {:?}),",i,x0,x1,x2,x3,resulta);
                                println!("({}, /*mx*/ {:.2}, /*mn*/ {:.2}, /*sr*/ {:.2}, /*cf*/ {:.2},  /*lt*/ {:.2}, /*rs*/ {:?}),",i,x0,x1,x2,x3,x4,resulta.is_ok());
                            } else {
                                //println!("");
                                //println!("");
                                //println!("");
                                //println!("");
                            }
                            i += 1;
                        }
                    }
                }
            }
        }
        return;
    }

    #[test]
    fn latency_test() {
        let mut etaline = [
            (
                11204, /*mx*/ 0.01, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                11211, /*mx*/ 0.01, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                11218, /*mx*/ 0.01, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13605, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13606, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13607, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                13612, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13613, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13614, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                13619, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13620, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13621, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                13654, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13655, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13656, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                13661, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13662, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13663, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                13668, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13669, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13670, /*mx*/ 0.50, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                13997, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                13998, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                13999, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                14004, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                14005, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                14006, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                14011, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                14012, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                14013, /*mx*/ 0.50, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16006, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16007, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16008, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16013, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16014, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16015, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16020, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16021, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16022, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.01, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16055, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16056, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16057, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16062, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16063, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16064, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16069, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16070, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16071, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16104, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16105, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16106, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16111, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16112, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16113, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16118, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16119, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16120, /*mx*/ 1.00, /*mn*/ 0.01, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16398, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16399, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16400, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16405, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16406, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16407, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16412, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16413, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16414, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 0.50, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16447, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16448, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16449, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16454, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16455, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16456, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16461, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16462, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16463, /*mx*/ 1.00, /*mn*/ 0.50, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16790, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16791, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16792, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 0.01,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16797, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16798, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16799, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 0.50,
                /*lt*/ 1.00, /*rs*/ true,
            ),
            (
                16804, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 0.01, /*rs*/ true,
            ),
            (
                16805, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 0.50, /*rs*/ true,
            ),
            (
                16806, /*mx*/ 1.00, /*mn*/ 1.00, /*sr*/ 1.00, /*cf*/ 1.00,
                /*lt*/ 1.00, /*rs*/ true,
            ),
        ]
        .iter();

        let generator = [-0.1, 0.0, 0.01, 0.5, 1.0];

        for x0 in generator.iter() {
            for x1 in generator.iter() {
                for x2 in generator.iter() {
                    for x3 in generator.iter() {
                        for x4 in generator.iter() {
                            let resulta = dump_param_gen(*x0, *x1, *x2, *x3, *x4);

                            if resulta.is_ok() {
                                let temp = etaline.next().unwrap();
                                assert_eq!(temp.1, *x0);
                                assert_eq!(temp.2, *x1);
                                assert_eq!(temp.3, *x2);
                                assert_eq!(temp.4, *x3);
                                assert_eq!(temp.5, *x4);
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(etaline.next(), None); //was all used
        return;
    }
}

#[cfg(test)]
mod tests_from_clode_ai {
    use crate::t1pology::PackTopology;
    use crate::t1pology::PakFields;

    use super::*;

    fn get_topol(
        ctr_byte_len: Option<usize>,
        total_min_len: usize,
        ttl_byte_len: Option<usize>,
    ) -> PackTopology {
        let fields = vec![
            //t2page::PakFields::HeadByte,
            PakFields::UserField(1),
            PakFields::Counter(5),
            PakFields::IdConnect(2),
            PakFields::HeadCRC(2),
            PakFields::Nonce(6),
            //PakFields::TTL(2),
            PakFields::Len(3),
        ];

        let mut returna = PackTopology::new(16, &fields, true, true).unwrap();

        if let Some(x) = ttl_byte_len {
            returna.__warning_test_only_force_edit_ttl(Some((0, 0, x)));
        }

        if let Some(x) = ctr_byte_len {
            returna.__warning_test_only_force_edit_ctr(Some((0, 0, x)));
        }

        returna.__warning_test_only_force_total_minimum_len_edit(total_min_len);

        returna
    }

    // Вспомогательная функция для создания базовых валидных параметров
    fn create_valid_params() -> (
        PackTopology,
        usize,                   // mtu
        f64,                     // max_ms_latency
        f64,                     // min_ms_latency
        f64,                     // start_ms_latency
        f64,                     // latency_increase_coefficient
        usize,                   // max_num_attempts_resend_package
        usize,                   // packages_measurement_window_size_determining_latency
        f64,                     // overhead_network_latency_relative_window_coefficient
        f64,                     // maximum_packet_delay_fback_coefficient
        f64,                     // maximum_packet_delay_absolute_fback
        usize,                   // maximum_length_udp_queue_packages
        usize,                   // maximum_length_fback_queue_packages
        usize,                   // maximum_length_queue_unconfirmed_packages
        Option<f64>,             // percent_fake_data_packets
        Option<f64>,             // percent_fake_fback_packets
        Option<(u64, u64, i64)>, // ttl_max_start_cost
        Option<usize>,           // percent_add_rand_nums_bytes_data_packs
        Option<usize>,           // percent_add_rand_nums_bytes_fback_packs
    ) {
        // Создаем PackTopology с счетчиком 1 байт (макс емкость = 126)
        let pack_topology = get_topol(Some(1), 50, Some(1)); // counter=1 byte, min_len=50, ttl=1 byte

        (
            pack_topology.clone(),
            1500,                 // mtu - значительно больше total_minimal_len()
            100.0,                // max_ms_latency
            10.0,                 // min_ms_latency
            50.0,                 // start_ms_latency - между min и max
            1.5,                  // latency_increase_coefficient < 10.0
            3,                    // max_num_attempts_resend_package
            10,                   // packages_measurement_window_size_determining_latency
            0.2,                  // overhead_network_latency_relative_window_coefficient
            1.5,                  // maximum_packet_delay_fback_coefficient < 2.0
            150.0,                // maximum_packet_delay_absolute_fback < 100.0 * 2.0 = 200.0
            50,                   // maximum_length_udp_queue_packages < 126
            20,                   // maximum_length_fback_queue_packages < 126
            60,                   // maximum_length_queue_unconfirmed_packages > 20
            Some(0.1),            // percent_fake_data_packets в диапазоне (0, 1]
            Some(0.05),           // percent_fake_fback_packets в диапазоне (0, 1]
            Some((255, 128, -1)), // ttl_max_start_cost корректный
            Some(100),            // percent_add_rand_nums_bytes_data_packs >= 1
            Some(50),             // percent_add_rand_nums_bytes_fback_packs >= 1
        )
    }

    // Тесты на успешное создание (20% тестов)
    // =========================================

    #[test]
    fn test_successful_creation() {
        let params = create_valid_params();

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_ok(),
            "Должно создаваться успешно: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_successful_creation_with_none_values() {
        let mut params = create_valid_params();
        // Устанавливаем все Optional значения в None
        params.14 = None; // percent_fake_data_packets
        params.15 = None; // percent_fake_fback_packets
        params.16 = None; // ttl_max_start_cost
        params.17 = None; // percent_add_rand_nums_bytes_data_packs
        params.18 = None; // percent_add_rand_nums_bytes_fback_packs

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_ok(), "Должно создаваться с None значениями");
    }

    #[test]
    fn test_successful_creation_minimum_values() {
        // Используем минимальные допустимые значения
        let pack_topology = get_topol(Some(1), 10, None);

        let result = WsConnectParam::new(
            &pack_topology,
            100,          // mtu
            1.0,          // max_ms_latency
            0.1,          // min_ms_latency
            0.5,          // start_ms_latency
            0.01,         // latency_increase_coefficient
            1,            // max_num_attempts_resend_package (минимальное)
            1,            // packages_measurement_window_size_determining_latency (минимальное)
            0.001, // overhead_network_latency_relative_window_coefficient  (минимальное положительное)
            0.001, // maximum_packet_delay_fback_coefficient (минимальное)
            0.001, // maximum_packet_delay_absolute_fback (минимальное)
            1,     // maximum_length_udp_queue_packages (минимальное)
            1,     // maximum_length_fback_queue_packages (минимальное)
            2,     // maximum_length_queue_unconfirmed_packages (больше чем fback)
            Some(0.0001), // percent_fake_data_packets (близко к 0)
            None,  // percent_fake_fback_packets = None
            None,  // ttl_max_start_cost = None
            Some(1), // percent_add_rand_nums_bytes_data_packs (минимальное)
            None,  // percent_add_rand_nums_bytes_fback_packs = None
        );

        assert!(
            result.is_ok(),
            "Должно создаваться с минимальными значениями"
        );
    }

    // Тесты на ошибки (80% тестов)
    // =============================

    // 1. Тесты на PackTopology и MTU
    // ------------------------------

    #[test]
    fn test_mtu_smaller_than_minimal_packet_length() {
        let mut params = create_valid_params();
        let pack_topology = get_topol(Some(1), 1000, None); // total_min_len = 1000
        params.0 = pack_topology;
        params.1 = 500; // mtu меньше чем total_min_len

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда MTU < total_minimal_len"
        );
    }

    #[test]
    fn test_mtu_equal_to_minimal_packet_length() {
        let mut params = create_valid_params();
        let pack_topology = get_topol(Some(1), 1500, None); // total_min_len = 1500
        params.0 = pack_topology;
        params.1 = 1500; // mtu равно total_min_len (должно быть больше)

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда MTU == total_minimal_len"
        );
    }

    #[test]
    fn test_pack_topology_without_counter_slice() {
        let pack_topology = get_topol(None, 50, None); // counter_slice() вернет None
        let mut params = create_valid_params();
        params.0 = pack_topology;

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда counter_slice() = None"
        );
    }

    // 2. Тесты на f64 значения (NaN, infinite, отрицательные, нулевые)
    // ----------------------------------------------------------------

    #[test]
    fn test_infinite_values() {
        let mut params = create_valid_params();

        // Тестируем положительную бесконечность
        params.2 = f64::INFINITY; // max_ms_latency

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_err(), "Должна быть ошибка на INFINITY");

        // Тестируем отрицательную бесконечность
        params.2 = f64::NEG_INFINITY;

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_err(), "Должна быть ошибка на NEG_INFINITY");
    }

    #[test]
    fn test_negative_f64_values() {
        let mut params = create_valid_params();

        // Тестируем отрицательные значения
        params.2 = -1.0; // max_ms_latency

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка на отрицательные значения"
        );
    }

    // 3. Тесты на usize значения (равные 0)
    // -------------------------------------

    // 4. Тесты на емкость счетчика
    // -----------------------------

    #[test]
    fn test_exceeding_counter_capacity() {
        // Создаем PackTopology с counter = 1 байт (макс емкость = 126)
        let pack_topology = get_topol(Some(1), 50, None);
        let mut params = create_valid_params();
        params.0 = pack_topology;

        // Устанавливаем значения больше максимальной емкости
        params.11 = 127; // maximum_length_udp_queue_packages > 126

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка при превышении емкости счетчика"
        );
    }

    #[test]
    fn test_counter_capacity_at_limit() {
        // 1 байт счетчика: (255 >> 1) - 1 = 126
        let pack_topology = get_topol(Some(1), 50, None);
        let mut params = create_valid_params();

        params.16 = None;
        params.0 = pack_topology;

        // Устанавливаем значения на границе емкости
        params.11 = 126; // maximum_length_udp_queue_packages == 126
        params.12 = 60; // maximum_length_fback_queue_packages == 126
        params.6 = 126; // max_num_attempts_resend_package == 126

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, //
            params.4, params.5, params.6, params.7, params.8, //
            params.9, params.10, params.11, //
            params.12, params.13, params.14, params.15, params.16, params.17, params.18,
        );

        println!("{:?}", result);
        assert!(result.is_ok(), "Должно работать на границе емкости");
    }

    // 5. Тесты на latency_increase_coefficient
    // ----------------------------------------

    #[test]
    fn test_latency_increase_coefficient_too_large() {
        let mut params = create_valid_params();
        params.5 = 10.1; // больше 10.0

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда latency_increase_coefficient > 10.0"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_at_limit() {
        let mut params = create_valid_params();
        params.5 = 10.0; // на границе

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_ok(), "Должно работать на границе 10.0");
    }

    // 6. Тесты на параметры fback
    // ---------------------------

    #[test]
    fn test_maximum_packet_delay_fback_coefficient_exceeds_limit() {
        let mut params = create_valid_params();
        params.9 = 1.0 + 0.1; // больше 2.0

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда coefficient_fback > MAX_COOFITIENT_FBACK_WAIT"
        );
    }

    #[test]
    fn test_maximum_packet_delay_absolute_fback_exceeds_limit() {
        let mut params = create_valid_params();
        // max_ms_latency = 100.0, MAX_COOFITIENT_FBACK_WAIT = 2.0
        // Максимально допустимое: 100.0 * 2.0 = 200.0
        params.10 = 200.1; // больше чем max_ms_latency * MAX_COOFITIENT_FBACK_WAIT

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда absolute_fback превышает лимит"
        );
    }

    #[test]
    fn test_absolute_fback_at_limit() {
        let mut params = create_valid_params();
        params.10 = params.2; // на границе

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_ok(), "Должно работать на границе absolute_fback");

        let mut params = create_valid_params();
        params.10 = params.2 + 0.001; // на границе

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_err());
    }

    // 7. Тесты на TTL
    // ---------------

    #[test]
    fn test_ttl_without_ttl_in_topology() {
        let pack_topology = get_topol(Some(1), 50, None); // ttl_slice() вернет None
        let mut params = create_valid_params();
        params.0 = pack_topology;
        params.16 = Some((255, 128, -1)); // Указываем ttl_max_start_cost

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда ttl задан, но в топологии нет ttl поля"
        );
    }

    #[test]
    fn test_ttl_start_greater_than_max() {
        let pack_topology = get_topol(Some(1), 50, Some(1)); // ttl_slice() есть
        let mut params = create_valid_params();
        params.0 = pack_topology;
        params.16 = Some((100, 101, -1)); // start (101) > max (100)

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда ttl_start > ttl_max"
        );
    }

    #[test]
    fn test_ttl_start_equal_to_max() {
        let pack_topology = get_topol(Some(1), 50, Some(1)); // ttl_slice() есть
        let mut params = create_valid_params();
        params.0 = pack_topology;
        params.16 = Some((100, 100, -1)); // start == max (допустимо)

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(result.is_ok(), "Должно работать когда ttl_start == ttl_max");
    }

    #[test]
    fn test_ttl_zero_values() {
        let pack_topology = get_topol(Some(1), 50, Some(1));
        let mut params = create_valid_params();
        params.0 = pack_topology;

        // Тест 1: max = 0
        params.16 = Some((0, 100, -1));
        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );
        assert!(result.is_err(), "Должна быть ошибка когда ttl_max = 0");

        // Тест 2: start = 0
        params.16 = Some((255, 0, -1));
        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );
        assert!(result.is_err(), "Должна быть ошибка когда ttl_start = 0");
    }

    #[test]
    fn test_ttl_exceeds_capacity() {
        // Для 1 байта ttl: макс значение = 255
        let pack_topology = get_topol(Some(1), 50, Some(1));
        let mut params = create_valid_params();
        params.0 = pack_topology;
        params.16 = Some((256, 128, -1)); // start (128) < max (256), но max > 255

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда ttl_start превышает емкость поля"
        );
    }

    // 8. Тесты на иерархию очередей
    // ------------------------------

    #[test]
    fn test_fback_queue_larger_than_unconfirmed_queue() {
        let mut params = create_valid_params();
        params.12 = 100; // maximum_length_fback_queue_packages
        params.13 = 50; // maximum_length_queue_unconfirmed_packages (меньше!)

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда fback_queue > unconfirmed_queue"
        );
    }

    #[test]
    fn test_fback_queue_equal_to_unconfirmed_queue() {
        let mut params = create_valid_params();
        params.12 = 50; // maximum_length_fback_queue_packages
        params.13 = 50; // maximum_length_queue_unconfirmed_packages (равно)

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_ok(),
            "Должно работать когда fback_queue == unconfirmed_queue"
        );
    }

    // 9. Тесты на проценты фейковых пакетов
    // --------------------------------------

    #[test]
    fn test_percent_fake_data_packets_nan() {
        let mut params = create_valid_params();
        params.14 = Some(f64::NAN);

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда percent_fake_data_packets = NaN"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_zero() {
        let mut params = create_valid_params();
        params.14 = Some(0.0);

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда percent_fake_data_packets = 0.0"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_negative() {
        let mut params = create_valid_params();
        params.14 = Some(-0.1);

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда percent_fake_data_packets < 0"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_greater_than_one() {
        let mut params = create_valid_params();
        params.14 = Some(1.1);

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда percent_fake_data_packets > 1.0"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_exactly_one() {
        let mut params = create_valid_params();
        params.14 = Some(1.0); // Граничное значение

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_ok(),
            "Должно работать когда percent_fake_data_packets = 1.0"
        );
    }

    // 10. Тесты на мусорные байты
    // ----------------------------

    #[test]
    fn test_bytes_scatter_zero() {
        let mut params = create_valid_params();
        params.17 = Some(0); // percent_add_rand_nums_bytes_data_packs = 0

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка когда bytes_scatter = 0"
        );
    }

    // 11. Комплексные тесты на несколько ошибок одновременно
    // ------------------------------------------------------

    #[test]
    fn test_multiple_invalid_parameters() {
        let pack_topology = get_topol(Some(1), 1000, None); // total_min_len = 1000
        let mut params = create_valid_params();
        params.0 = pack_topology;

        // Устанавливаем несколько невалидных значений
        params.1 = 500; // mtu меньше total_min_len
        params.2 = -1.0; // отрицательный max_ms_latency
        params.11 = 0; // zero maximum_length_udp_queue_packages
        params.12 = 100; // maximum_length_fback_queue_packages
        params.13 = 50; // меньше чем fback_queue

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        assert!(
            result.is_err(),
            "Должна быть ошибка при множественных невалидных параметрах"
        );
    }

    // 12. Тесты на граничные случаи с большими значениями
    // ---------------------------------------------------

    #[test]
    fn test_large_counter_byte_length() {
        // 8 байт счетчика - максимальная емкость
        // Для 8 байт: max_value = 2^64 - 1
        // ctr_max_capacity_real = (max_value >> 1) - 1
        // Это очень большое число, должно помещаться в usize на 64-битных системах
        let pack_topology = get_topol(Some(8), 50, None);
        let mut params = create_valid_params();
        params.0 = pack_topology;

        // Используем разумные значения (меньше чем usize::MAX)
        params.11 = 1000;
        params.12 = 1000;
        params.6 = 1000;

        let result = WsConnectParam::new(
            &params.0, params.1, params.2, params.3, params.4, params.5, params.6, params.7,
            params.8, params.9, params.10, params.11, params.12, params.13, params.14, params.15,
            params.16, params.17, params.18,
        );

        // На 64-битных системах должно работать
        if usize::MAX > u32::MAX as usize {
            // 64-битная система
            match result {
                Ok(_) => {}
                Err(x) => panic!("Должно работать на 64-битных системах {}", x),
            }
        } else {
            // 32-битная система - может быть ошибка если ctr_max_capacity_real > usize::MAX
            // В этом случае проверим, что результат либо Ok, либо Err с соответствующим сообщением
            match result {
                Ok(_) => println!("Успех на 32-битной системе"),
                Err(e) => {
                    assert!(
                        e.contains("Counter capacity exceeds system's usize limit")
                            || e.contains("must be less than the maximum capacity"),
                        "Неожиданная ошибка: {}",
                        e
                    );
                }
            }
        }
    }
    //==============================================================================================================================================

    #[test]
    fn test_getters_return_correct_values() {
        // Создаем тестовые данные
        let pack_topology = get_topol(Some(2), 100, Some(2));

        let params = WsConnectParam::new(
            &pack_topology,
            1500,                 // mtu
            200.0,                // max_ms_latency
            20.0,                 // min_ms_latency
            100.0,                // start_ms_latency
            1.5,                  // latency_increase_coefficient
            5,                    // max_num_attempts_resend_package
            10,                   // packages_measurement_window_size_determining_latency
            0.2,                  // overhead_network_latency_relative_window_coefficient
            1.8,                  // maximum_packet_delay_fback_coefficient
            300.0,                // maximum_packet_delay_absolute_fback
            50,                   // maximum_length_udp_queue_packages
            20,                   // maximum_length_fback_queue_packages
            60,                   // maximum_length_queue_unconfirmed_packages
            Some(0.1),            // percent_fake_data_packets
            Some(0.05),           // percent_fake_fback_packets
            Some((255, 128, -1)), // ttl_max_start_cost
            Some(100),            // percent_add_rand_nums_bytes_data_packs
            Some(50),             // percent_add_rand_nums_bytes_fback_packs
        )
        .expect("Должно создаться успешно");

        // Проверяем все геттеры
        assert_eq!(params.mtu(), 1500);
        assert_eq!(params.max_ms_latency(), 200.0);
        assert_eq!(params.min_ms_latency(), 20.0);
        assert_eq!(params.start_ms_latency(), 100.0);
        assert_eq!(params.latency_increase_coefficient(), 1.5);
        assert_eq!(params.max_num_attempts_resend_package(), 5);
        assert_eq!(
            params.packages_measurement_window_size_determining_latency(),
            10
        );
        assert_eq!(
            params.overhead_network_latency_relative_window_coefficient(),
            0.2
        );
        assert_eq!(params.maximum_packet_delay_fback_coefficient(), 1.8);
        assert_eq!(params.maximum_packet_delay_absolute_fback(), 300.0);
        assert_eq!(params.maximum_length_udp_queue_packages(), 50);
        assert_eq!(params.maximum_length_fback_queue_packages(), 20);
        assert_eq!(params.maximum_length_queue_unconfirmed_packages(), 60);
        assert_eq!(params.percent_fake_data_packets(), Some(0.1));
        assert_eq!(params.percent_fake_fback_packets(), Some(0.05));
        assert_eq!(params.ttl_max_start_cost(), Some((255, 128, -1)));
        assert_eq!(
            params.bytes_scatter_random_long_trash_padding_in_data_packs(),
            Some(100)
        );
        assert_eq!(params.percent_add_rand_nums_bytes_fback_packs(), Some(50));

        // Проверяем pack_topology отдельно (так как это ссылка на клон)
        assert_eq!(
            params.pack_topology().total_minimal_len(),
            pack_topology.total_minimal_len()
        );
    }

    #[test]
    fn test_getters_with_none_values() {
        let pack_topology = get_topol(Some(2), 100, None);

        let params = WsConnectParam::new(
            &pack_topology,
            1500,  // mtu
            200.0, // max_ms_latency
            20.0,  // min_ms_latency
            100.0, // start_ms_latency
            1.5,   // latency_increase_coefficient
            5,     // max_num_attempts_resend_package
            10,    // packages_measurement_window_size_determining_latency
            0.2,   // overhead_network_latency_relative_window_coefficient
            1.8,   // maximum_packet_delay_fback_coefficient
            300.0, // maximum_packet_delay_absolute_fback
            50,    // maximum_length_udp_queue_packages
            20,    // maximum_length_fback_queue_packages
            60,    // maximum_length_queue_unconfirmed_packages
            None,  // percent_fake_data_packets
            None,  // percent_fake_fback_packets
            None,  // ttl_max_start_cost
            None,  // percent_add_rand_nums_bytes_data_packs
            None,  // percent_add_rand_nums_bytes_fback_packs
        )
        .expect("Должно создаться успешно");

        // Проверяем Option поля
        assert_eq!(params.percent_fake_data_packets(), None);
        assert_eq!(params.percent_fake_fback_packets(), None);
        assert_eq!(params.ttl_max_start_cost(), None);
        assert_eq!(
            params.bytes_scatter_random_long_trash_padding_in_data_packs(),
            None
        );
        assert_eq!(params.percent_add_rand_nums_bytes_fback_packs(), None);

        // Проверяем, что не-None поля все еще корректны
        assert_eq!(params.mtu(), 1500);
        assert_eq!(params.max_ms_latency(), 200.0);
        assert_eq!(params.maximum_length_udp_queue_packages(), 50);
    }

    #[test]
    fn test_getters_edge_cases() {
        let pack_topology = get_topol(Some(1), 10, None);

        // Минимальные допустимые значения
        let params = WsConnectParam::new(
            &pack_topology,
            100,          // mtu
            1.0,          // max_ms_latency
            0.1,          // min_ms_latency
            0.5,          // start_ms_latency
            0.01,         // latency_increase_coefficient
            1,            // max_num_attempts_resend_package
            1,            // packages_measurement_window_size_determining_latency
            0.001,        // overhead_network_latency_relative_window_coefficient
            0.001,        // maximum_packet_delay_fback_coefficient
            0.001,        // maximum_packet_delay_absolute_fback
            1,            // maximum_length_udp_queue_packages
            1,            // maximum_length_fback_queue_packages
            2,            // maximum_length_queue_unconfirmed_packages
            Some(0.0001), // percent_fake_data_packets (близко к 0)
            None,         // percent_fake_fback_packets
            None,         // ttl_max_start_cost
            Some(1),      // percent_add_rand_nums_bytes_data_packs (минимальное)
            None,         // percent_add_rand_nums_bytes_fback_packs
        )
        .expect("Должно создаться успешно");

        // Проверяем минимальные значения
        assert_eq!(params.mtu(), 100);
        assert_eq!(params.max_ms_latency(), 1.0);
        assert_eq!(params.min_ms_latency(), 0.1);
        assert_eq!(params.start_ms_latency(), 0.5);
        assert_eq!(params.latency_increase_coefficient(), 0.01);
        assert_eq!(params.max_num_attempts_resend_package(), 1);
        assert_eq!(
            params.packages_measurement_window_size_determining_latency(),
            1
        );
        assert_eq!(
            params.overhead_network_latency_relative_window_coefficient(),
            0.001
        );
        assert_eq!(params.maximum_packet_delay_fback_coefficient(), 0.001);
        assert_eq!(params.maximum_packet_delay_absolute_fback(), 0.001);
        assert_eq!(params.maximum_length_udp_queue_packages(), 1);
        assert_eq!(params.maximum_length_fback_queue_packages(), 1);
        assert_eq!(params.maximum_length_queue_unconfirmed_packages(), 2);
        assert_eq!(params.percent_fake_data_packets(), Some(0.0001));
        assert_eq!(params.percent_fake_fback_packets(), None);
        assert_eq!(params.ttl_max_start_cost(), None);
        assert_eq!(
            params.bytes_scatter_random_long_trash_padding_in_data_packs(),
            Some(1)
        );
        assert_eq!(params.percent_add_rand_nums_bytes_fback_packs(), None);
    }

    #[test]
    fn test_getters_maximum_values() {
        let pack_topology = get_topol(Some(8), 500, Some(8));

        // Максимальные или граничные значения
        let params = WsConnectParam::new(
            &pack_topology,
            65535,                                    // mtu
            10000.0,                                  // max_ms_latency
            1.0,                                      // min_ms_latency
            5000.0,                                   // start_ms_latency
            10.0,                                     // latency_increase_coefficient (максимум)
            1000,                                     // max_num_attempts_resend_package
            100,       // packages_measurement_window_size_determining_latency
            10.0,      // overhead_network_latency_relative_window_coefficient
            2.0,       // maximum_packet_delay_fback_coefficient (максимум)
            20000.0,   // maximum_packet_delay_absolute_fback (10000.0 * 2.0 = 20000.0)
            10000,     // maximum_length_udp_queue_packages
            5000,      // maximum_length_fback_queue_packages
            15000,     // maximum_length_queue_unconfirmed_packages
            Some(1.0), // percent_fake_data_packets (максимум)
            Some(1.0), // percent_fake_fback_packets (максимум)
            Some((u64::MAX, u64::MAX / 2, i64::MIN)), // ttl_max_start_cost
            Some(usize::MAX), // percent_add_rand_nums_bytes_data_packs
            Some(usize::MAX), // percent_add_rand_nums_bytes_fback_packs
        )
        .expect("Должно создаться успешно на 64-битной системе");

        // Проверяем максимальные/граничные значения
        assert_eq!(params.mtu(), 65535);
        assert_eq!(params.max_ms_latency(), 10000.0);
        assert_eq!(params.min_ms_latency(), 1.0);
        assert_eq!(params.start_ms_latency(), 5000.0);
        assert_eq!(params.latency_increase_coefficient(), 10.0);
        assert_eq!(params.max_num_attempts_resend_package(), 1000);
        assert_eq!(
            params.packages_measurement_window_size_determining_latency(),
            100
        );
        assert_eq!(
            params.overhead_network_latency_relative_window_coefficient(),
            10.0
        );
        assert_eq!(params.maximum_packet_delay_fback_coefficient(), 2.0);
        assert_eq!(params.maximum_packet_delay_absolute_fback(), 20000.0);
        assert_eq!(params.maximum_length_udp_queue_packages(), 10000);
        assert_eq!(params.maximum_length_fback_queue_packages(), 5000);
        assert_eq!(params.maximum_length_queue_unconfirmed_packages(), 15000);
        assert_eq!(params.percent_fake_data_packets(), Some(1.0));
        assert_eq!(params.percent_fake_fback_packets(), Some(1.0));
        assert_eq!(
            params.ttl_max_start_cost(),
            Some((u64::MAX, u64::MAX / 2, i64::MIN))
        );
        assert_eq!(
            params.bytes_scatter_random_long_trash_padding_in_data_packs(),
            Some(usize::MAX)
        );
        assert_eq!(
            params.percent_add_rand_nums_bytes_fback_packs(),
            Some(usize::MAX)
        );
    }

    #[test]
    fn test_all_getters_present() {
        // Этот тест проверяет, что мы действительно протестировали все геттеры
        let pack_topology = get_topol(Some(2), 100, Some(2));

        let params = WsConnectParam::new(
            &pack_topology,
            1500,
            200.0,
            20.0,
            100.0,
            1.5,
            5,
            10,
            0.2,
            1.8,
            300.0,
            50,
            20,
            60,
            Some(0.1),
            Some(0.05),
            Some((255, 128, -1)),
            Some(100),
            Some(50),
        )
        .unwrap();

        // Вызываем все геттеры (компилятор проверит, что они существуют)
        let _ = params.pack_topology();
        let _ = params.mtu();
        let _ = params.max_ms_latency();
        let _ = params.min_ms_latency();
        let _ = params.start_ms_latency();
        let _ = params.latency_increase_coefficient();
        let _ = params.max_num_attempts_resend_package();
        let _ = params.packages_measurement_window_size_determining_latency();
        let _ = params.overhead_network_latency_relative_window_coefficient();
        let _ = params.maximum_packet_delay_fback_coefficient();
        let _ = params.maximum_packet_delay_absolute_fback(); // Добавленный геттер
        let _ = params.ttl_max_start_cost();
        let _ = params.maximum_length_udp_queue_packages();
        let _ = params.maximum_length_fback_queue_packages();
        let _ = params.maximum_length_queue_unconfirmed_packages();
        let _ = params.percent_fake_data_packets();
        let _ = params.percent_fake_fback_packets();
        let _ = params.bytes_scatter_random_long_trash_padding_in_data_packs();
        let _ = params.percent_add_rand_nums_bytes_fback_packs();

        // Если компилируется, значит все геттеры определены
        assert!(true);
    }
}
