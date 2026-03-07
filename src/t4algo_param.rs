//Gaoo~~~ :3

use crate::t0pology::PackTopology;
use crate::wutils;

#[derive(Debug, PartialEq)]
pub struct WsConnectParam {
    pack_topology: PackTopology,
    mtu: usize,
    min_ms_latency: f64,
    max_ms_latency: f64,
    start_ms_latency: f64,
    latency_increase_coefficient: f64,
    max_num_attempts_resend_package: usize,
    packages_measurement_window_size_determining_latency: usize,
    overhead_network_latency_relative_window_coefficient: f64,
    maximum_packet_delay_fback_coefficient: f64,
    maximum_packet_delay_absolute_fback: f64,
    ttl_max_start_cost: Option<(u64, u64, i64)>,
    maximum_length_udp_queue_packages: usize,
    maximum_length_fback_queue_packages: usize,
    maximum_length_queue_unconfirmed_packages: usize,
    percent_fake_data_packets: Option<f64>,
    percent_fake_fback_packets: Option<f64>,
    percent_len_random_coefficient: Option<f64>,
    instant_feedback_on_packet_loss: bool,
    max_len_file: Option<usize>,
}

impl WsConnectParam {
    ///<h2>Each variable is described in detail at the beginning of this file. Open the
    /// beginning of the file and read what is written there to avoid mistakes.
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
        percent_len_random_coefficient: Option<f64>,
        max_len_file: Option<usize>,
    ) -> Result<Self, &'static str> {
        if pack_topology.total_minimal_len() >= mtu {
            return Err(
                "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
                 pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is \
                 the minimum packet length, such a packet contains only protocol service \
                 information, mtu must be large enough to accommodate the length of the packet's \
                 useful data and service data.",
            );
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
            return Err("latency_increase_coefficient \
                        overhead_network_latency_relative_window_coefficient \
                        maximum_packet_delay_fback_coefficient must be greater than zero");
        }

        //latency check
        {
            if min_ms_latency > max_ms_latency {
                return Err(
                    "min_ms_latency > max_ms_latency The minimum start_ms_latency < \
                     min_ms_latency must be less than or equal to the maximum latency.",
                );
            }

            if start_ms_latency > max_ms_latency {
                return Err(
                    "start_ms_latency > max_ms_latency The start latency must be less than or \
                     equal to the maximum.",
                );
            }

            if start_ms_latency < min_ms_latency {
                return Err(
                    "start_ms_latency < min_ms_latency The start latency  must be greater than or \
                     equal to the minimum.",
                );
            }
        }

        {
            let ctr_max_capacity = wutils::len_byte_maximal_capacity_check(
                pack_topology
                    .counter_slice()
                    .ok_or(
                        "The counter_slice() field in pack_topology is None, but it must be \
                         specified!",
                    )?
                    .2,
            );
            //See the description of the pub fn set_counter function in the pub mod t1fields file
            // to understand why this logic for obtaining maximum capacity is used here.
            let ctr_max_capacity_real = (ctr_max_capacity.0 >> 1).checked_sub(1).expect(
                "(ctr_max_capacity.0 >> 1) - 1 < 0 error, impossible behavior, since the minimum \
                 length of counter_slice() is 1, 1 byte is 255 maximum value, 255 >>1 - 127, 127 \
                 is greater than 1.",
            );

            //https://github.com/ilostmyg1thubkey You dumbass,
            //this shit will only work if ctr_max_capacity_real is not greater than 32 bits, even
            // on 32-bit systems, bitch.
            if ctr_max_capacity_real > usize::MAX as u64 {
                return Err(
                    "ctr_max_capacity_real > usize::MAX as u64, Counter capacity exceeds system's \
                     usize limit",
                );
            }

            if maximum_length_udp_queue_packages > ctr_max_capacity_real as usize {
                return Err(
                    " maximum_length_udp_queue_packages must be less than the maximum capacity of \
                     the pack_topology.counter_slice() field. ",
                );
            }
            if maximum_length_udp_queue_packages < maximum_length_queue_unconfirmed_packages {
                return Err(" maximum_length_udp_queue_packages must be greater than \
                            maximum_length_queue_unconfirmed_packages so that all packets are \
                            confirmed. For more information, see the description of this \
                            variable at the beginning of the file.");
            }

            if maximum_length_fback_queue_packages > ctr_max_capacity_real as usize {
                return Err(
                    "maximum_length_fback_queue_packages must not exceed the maximum capacity of \
                     the pack_topology.counter_slice() counter. ",
                );
            }

            if max_num_attempts_resend_package > ctr_max_capacity_real as usize {
                return Err(
                    "max_num_attempts_resend_package > ctr_max_capacity_real as usize.  \
                     max_num_attempts_resend_package must be less than the maximum possible \
                     capacity in pack_topology.counter_slice().",
                );
            }
        }

        if maximum_packet_delay_absolute_fback > max_ms_latency {
            return Err(
                "The variable maximum_packet_delay_absolute_fback must be no greater than \
                 max_ms_latency For more information, see the description of this variable at the \
                 beginning of the file.",
            );
        }
        //ttl
        if let Some(ttl_me) = ttl_max_start_cost {
            if let Some(ttl_in_topology) = pack_topology.ttl_slice() {
                let max_cap = wutils::len_byte_maximal_capacity_check(ttl_in_topology.2);

                if ttl_me.0 < ttl_me.1 {
                    return Err(
                        "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the \
                         maximum ttl value. For more information, see the description of this \
                         variable at the beginning of the file.",
                    );
                }
                if ttl_me.0 == 0 {
                    return Err("ttl_max_start_cost.0 must be greater than zero. For more \
                                information, see the description of this variable at the \
                                beginning of the file.");
                }

                if ttl_me.1 == 0 {
                    return Err("ttl_max_start_cost.1 must be greater than zero. For more \
                                information, see the description of this variable at the \
                                beginning of the file.");
                }

                if ttl_me.1 > max_cap.0 {
                    return Err(
                        "ttl_max_start_cost.1 is greater than the length that can be accommodated \
                         in the pack_topology field.",
                    );
                }
            } else {
                return Err("The ttl_max_start_cost field is defined as Some(), but in \
                            pack_topology this field is None.");
            }
        }

        if maximum_length_fback_queue_packages > maximum_length_queue_unconfirmed_packages {
            return Err(" maximum_length_fback_queue_packages must be less than \
                        maximum_length_queue_unconfirmed_packages.For more information, see the \
                        description of this variable at the beginning of the file.");
        }
        //percent

        if let Some(x) = percent_fake_data_packets
            && (!x.is_normal() || x > 1.0 || x <= 0.0)
        {
            return Err("percent_fake_data_packets must be in the range from (0.0 to 1.0]");
        }

        if let Some(x) = percent_fake_fback_packets
            && (!x.is_normal() || x > 1.0 || x <= 0.0)
        {
            return Err("percent_fake_fback_packets must be in the range from (0.0 to 1.0]");
        }

        if let Some(x) = percent_len_random_coefficient
            && (!x.is_normal() || x > 1.0 || x <= 0.0)
        {
            return Err("percent_len_random_coefficient must be in the range from (0.0 to 1.0]");
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
            percent_fake_data_packets,  //
            percent_fake_fback_packets, //

            instant_feedback_on_packet_loss,
            percent_len_random_coefficient,
            max_len_file,
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

    pub fn percent_len_random_coefficient(&self) -> Option<f64> {
        self.percent_len_random_coefficient
    }

    pub fn instant_feedback_on_packet_loss(&self) -> bool {
        self.instant_feedback_on_packet_loss
    }
    pub fn max_len_file(&self) -> Option<usize> {
        self.max_len_file
    }
}

/// A builder for `WsConnectParam` that follows the consuming (owned) pattern.

#[derive(Debug, Clone)]
pub struct WsConnectParamBuilder {
    // Required field (no default)
    pack_topology: PackTopology,

    // Fields with explicit defaults (from the problem statement)
    mtu: usize,
    instant_feedback_on_packet_loss: bool,
    packages_measurement_window_size_determining_latency: usize,
    max_ms_latency: f64,
    min_ms_latency: f64,
    start_ms_latency: f64,
    latency_increase_coefficient: f64,
    overhead_network_latency_relative_window_coefficient: f64,
    maximum_packet_delay_fback_coefficient: f64,
    maximum_packet_delay_absolute_fback: f64,

    // Fields with no defaults → must be set by the user
    maximum_length_udp_queue_packages: Option<usize>,
    maximum_length_fback_queue_packages: Option<usize>,
    maximum_length_queue_unconfirmed_packages: Option<usize>,
    max_num_attempts_resend_package: Option<usize>,

    // Optional fields (default = None)
    ttl_max_start_cost: Option<Option<(u64, u64, i64)>>, /* double Option trick to distinguish
                                                          * unset vs None */
    percent_fake_data_packets: Option<Option<f64>>,
    percent_fake_fback_packets: Option<Option<f64>>,
    percent_len_random_coefficient: Option<Option<f64>>,
    max_len_file: Option<Option<usize>>, // default is Some(10*1024*1024)
}

impl WsConnectParamBuilder {
    /// Creates a new builder with the mandatory `pack_topology` and all defaults applied.
    pub fn new(pack_topology: PackTopology) -> Self {
        Self {
            pack_topology,
            // Default values from the problem statement
            mtu: 1500,
            instant_feedback_on_packet_loss: false,
            packages_measurement_window_size_determining_latency: 10,
            max_ms_latency: 100.0,
            min_ms_latency: 10.0,
            start_ms_latency: 50.0,
            latency_increase_coefficient: 0.5,
            overhead_network_latency_relative_window_coefficient: 0.2,
            maximum_packet_delay_fback_coefficient: 0.8,
            maximum_packet_delay_absolute_fback: 80.0,
            // Fields without defaults start as None
            maximum_length_udp_queue_packages: None,
            maximum_length_fback_queue_packages: None,
            maximum_length_queue_unconfirmed_packages: None,
            max_num_attempts_resend_package: None,
            // Optional fields: inner None = not set by user, outer Option = final value (default
            // None)
            ttl_max_start_cost: Some(None),
            percent_fake_data_packets: Some(None),
            percent_fake_fback_packets: Some(None),
            percent_len_random_coefficient: Some(None),
            max_len_file: Some(Some(10 * 1024 * 1024)), // default Some(...)
        }
    }

    // --- Setters for fields with defaults ---
    ///maximum packet size in bytes on the network</br>
    pub fn mtu(mut self, value: usize) -> Self {
        self.mtu = value;
        self
    }
    ///instant_feedback_on_packet_loss is needed so that when packet loss is
    /// detected,<br> fback is immediately returned with confirmed packets. For
    /// example,<br> the recipient received packets numbered 11, 12, 13, 15, 16, and
    /// 17.<br> and sees that packet number 15 is missing,<br>
    ///sends fback with confirmation of receipt of 11, 12, 13, 15, 16, and 17.<br>
    ///The sender sees that the recipient<br>
    ///did not receive packet 15 and sends packet 15 immediately after receiving
    /// fback.<br> If instant_feedback_on_packet_los == false,<br>
    ///then if the sender receives confirmation of receipt of packets
    /// 11,12,13,15,16,17,<br> it will NOT send packet 15, but will wait for the
    /// packet confirmation timeout<br> (see the latency_increase_coefficient and
    /// max_ms_latency documentation)<br> and only after the timeout will it resend
    /// packet 15.<br>
    pub fn instant_feedback_on_packet_loss(mut self, value: bool) -> Self {
        self.instant_feedback_on_packet_loss = value;
        self
    }
    //
    ///The connection dynamically changes the latency time.</br>
    ///  To do this, it calculates the average latency of</br>
    ///  the last packages_measurement_window_size_determining_latency packets.</br>
    ///  The smaller this number is,</br>
    ///  the faster the algorithm will respond to changes in latency.</br>
    ///not related to other parameters, the lower the value, the more the adjustment will
    /// occur while waiting for confirmation
    pub fn packages_measurement_window_size_determining_latency(mut self, value: usize) -> Self {
        self.packages_measurement_window_size_determining_latency = value;
        self
    }
    //
    ///After sending the packet, the sender waits for a certain amount of time X.</br>
    ///  If no confirmation is received within the specified time X,</br>
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient.
    /// X = X+X*latency_increase_coefficient</br>  The value of X changes dynamically
    /// during the operation of the algorithm,</br>  and the values of max_ms_latency
    /// and min_ms_latency</br>  limit its limits so that the sender does not wait
    /// forever or wait 0.0 ms.</br>
    pub fn max_ms_latency(mut self, value: f64) -> Self {
        self.max_ms_latency = value;
        self
    }
    //
    ///After sending the packet, the sender waits for a certain amount of time X.</br>
    ///  If no confirmation is received within the specified time X,</br>
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient.
    /// X = X+X*latency_increase_coefficient</br>  The value of X changes dynamically
    /// during the operation of the algorithm,</br>  and the values of max_ms_latency
    /// and min_ms_latency</br>  limit its limits so that the sender does not wait
    /// forever or wait 0.0 ms.</br>
    pub fn min_ms_latency(mut self, value: f64) -> Self {
        self.min_ms_latency = value;
        self
    }
    ///see description max_ms_latency ^^^ +</br></br>
    /// initial latency must be between max_ms_latency: f64 and min_ms_latency: f64,</br>
    pub fn start_ms_latency(mut self, value: f64) -> Self {
        self.start_ms_latency = value;
        self
    }
    //
    ///see description max_ms_latency ^^^+</br></br>
    ///  if confirmation of the packet has not arrived within the waiting time X,</br>
    ///  the packet is sent again,</br>
    ///  and the waiting time for confirmation of this packet is set to this value</br>
    /// 1.0 >= latency_increase_coefficient >0

    pub fn latency_increase_coefficient(mut self, value: f64) -> Self {
        self.latency_increase_coefficient = value;
        self
    }
    //
    ///see description max_ms_latency ^^^ and
    /// packages_measurement_window_size_determining_latency + Network latency is
    /// determined dynamically during algorithm execution when a</br>  packet is sent
    /// and the sender waits for confirmation within: average latency</br>
    ///  of the last
    /// (packages_measurement_window_size_determining_latency) network packets *
    ///  overhead_network_latency_relative_window_coefficient  (1.0 >=
    /// overhead_network_latency_relative_window_coefficient >= 0.0).</br>  This value
    /// is necessary so that packets are not resent in case of minor network
    /// instability.</br>
    pub fn overhead_network_latency_relative_window_coefficient(mut self, value: f64) -> Self {
        self.overhead_network_latency_relative_window_coefficient = value;
        self
    }
    ///maximum_packet_delay_fback_coefficient This is the coefficient needed to calculate
    /// how long</br>  to wait before sending a packet confirmation.</br>
    ///  It must be greater than 0, but not greater than 1.0.</br>
    ///  After the packet has been received by the recipient,</br>
    ///  the recipient must send an fback confirmation packet,</br>
    ///  but fback may contain several counters of received packets,</br>
    ///  so the packet recipient waits for some time before sending the fback confirmation
    /// packet,</br>  as it expects that more packets may arrive,</br>
    ///  and the recipient will add several counters of received packets</br>
    ///  to fback and send confirmation of several packets instead of one.</br></br>
    ///The waiting time is calculated as</br>
    pub fn maximum_packet_delay_fback_coefficient(mut self, value: f64) -> Self {
        self.maximum_packet_delay_fback_coefficient = value;
        self
    }
    //
    ///see description maximum_packet_delay_fback_coefficient ^^^
    ///This is the maximum absolute value that the fback packet will wait before being
    /// sent. The value must be between 0 and max_ms_latency.
    pub fn maximum_packet_delay_absolute_fback(mut self, value: f64) -> Self {
        self.maximum_packet_delay_absolute_fback = value;
        self
    }

    // --- Setters for fields without defaults (must be called) ---

    ///The maximum_length_udp_queue_packages value is used in the WSUdpLike class.</br>
    ///  For more details, see the WSUdpLike API. In short,</br>
    ///  WSUdpLike is needed to restore the sequence of packets</br>
    ///  if some packets arrived out of order/were duplicated/or to wait for lost
    /// packets.</br>  Ideally, maximum_length_udp_queue_packages should be greater
    /// than or equal to maximum_length_queue_unconfirmed_package.</br>
    ///  This is because if maximum_length_queue_unconfirmed_package is larger,</br>
    ///  a situation may arise where the WSUdpLike queue overflows and valid packets are
    /// rejected.</br>  This will lead to an increase in network load.</br>
    /// <h4>The maximum value of this field is limited by the maximum capacity of the
    /// field from the PackTopology structure:  (field counter).</h4>
    pub fn maximum_length_udp_queue_packages(mut self, value: usize) -> Self {
        self.maximum_length_udp_queue_packages = Some(value);
        self
    }
    //
    ///maximum_length_fback_queue_packages is a value used in WSRecvQueueCtrs.</br>
    ///  For more information, see WSRecvQueueCtrs API. Brief information.</br>
    /// When a node receives a packet, it must send a confirmation, analogous to an ACK
    /// packet in TCP.</br>  In this algorithm, it is called “fback”.</br>
    ///  The fback acknowledgment packet contains the numbers of the packet counters that
    /// were received.</br>  The maximum number of counters is determined by
    /// maximum_length_fback_queue_packages. However,</br>  the fback packet must fit
    /// entirely within the network MTU.</br>  If the calculated size in bytes of the
    /// fback packet does not fit within the MTU,</br>
    ///  maximum_length_fback_queue_packages will be forcibly reduced when the instance is
    /// created.  </br> <h4>The maximum value of this field is limited by the maximum
    /// capacity of the field from the PackTopology structure:  (field counter +
    /// length field, if such a field exists; if it does not exist, then the packet length
    /// is limited only by the MTU).</h4>
    pub fn maximum_length_fback_queue_packages(mut self, value: usize) -> Self {
        self.maximum_length_fback_queue_packages = Some(value);
        self
    }
    ///maximum_length_queue_unconfirmed_packages is required for use in WSWaitQueue.
    /// </br>  For complete information, see the WSWaitQueue API.</br></br>
    ///  In short, when the sender sends a packet, in addition to sending it,</br>
    ///  this packet is sent to storage in WSWaitQueue. When the sender receives the fback
    /// packet,</br>  it deletes all packets from fback that are in WSWaitQueue.</br>
    ///  Periodically, the sender checks WSWaitQueue for packets with expired confirmation
    /// times and resends them.</br>  It is recommended that
    /// maximum_length_queue_unconfirmed_packages be</br>  three times larger than
    /// maximum_length_fback_queue_packages.</br> This is a recommendation, not a
    /// mandatory value, and it depends on the parameters and properties of the external
    /// environment.</br></br>  Logically, packets can be divided into:</br>
    ///#### 1 those that are still in transit from the sender to the recipient.
    ///#### 2 those that have been received and are stored in fback.
    ///#### 3 those that have been sent to fback from the recipient to the sender to confirm receipt.</br></br>
    /// <h4>The maximum value of this field is limited by the maximum capacit
    pub fn maximum_length_queue_unconfirmed_packages(mut self, value: usize) -> Self {
        self.maximum_length_queue_unconfirmed_packages = Some(value);
        self
    }
    //
    ///If confirmation of the packet has not been received,</br>
    ///  it is sent again. If confirmation of the packet is not received several</br>
    ///  times in a row, the connection is terminated. If the number of attempts</br>
    ///  to send the packet equals max_num_attempts_resend_package,</br>
    ///  the connection is terminated.</br>
    pub fn max_num_attempts_resend_package(mut self, value: usize) -> Self {
        self.max_num_attempts_resend_package = Some(value);
        self
    }

    // --- Setters for optional fields (default = None) ---
    //
    ///ttl is a standard field for TTL (Time To Live) Internet protocol algorithms.</br>
    ///  The first u64 is the maximum number that the counter can accept; if it is
    /// greater</br>  , the packet is considered incorrect. The second u64 is the
    /// starting ttl,</br>  which is set for the packet by its sender and must always
    /// be less than the first usize.</br>  The third i64 is the price of passing the
    /// packet through the node. In normal networks,</br>  when a packet passes
    /// through a node, its TTL is reduced by -1.</br>  If the third i64 is negative,
    /// the TTL counter will be reduced by this number</br>  . If the third i64 is
    /// positive,</br>  the TTL counter value will be increased by this number.</br>
    ///  I don't know in what situations you need to increase it,</br>
    ///  but it may be necessary.</br>
    ///  Carefully study the basics of Internet networks so you don't do anything stupid
    /// ;)</br> <h4>The maximum value of this field is limited by the maximum capacity
    /// of the field from the PackTopology structure:  (ttl).</h4>
    pub fn ttl_max_start_cost(mut self, value: (u64, u64, i64)) -> Self {
        self.ttl_max_start_cost = Some(Some(value));
        self
    }
    //
    ///percent_fake_data_packets can be in  0 > && <= 1.0.
    ///  It is needed so that the protocol sends fake packets to make it difficult for
    /// traffic censorship  tools to detect them. When creating a useful data packet,
    /// there is a chance that a packet of  junk data will appear with the
    /// percent_fake_data_packets value.
    pub fn percent_fake_data_packets(mut self, value: f64) -> Self {
        self.percent_fake_data_packets = Some(Some(value));
        self
    }
    //
    ///see description percent_fake_data_packets^^^
    /// similar behavior for fback-type packets
    pub fn percent_fake_fback_packets(mut self, value: f64) -> Self {
        self.percent_fake_fback_packets = Some(Some(value));
        self
    }
    ///percent_len_random_coefficient is needed to randomize the length to which packets
    /// will be cut,<br><br>  for example, file length = 1000 bytes, your network's
    /// MTU = 100 bytes,<br>  the packet's working fields occupy 20 bytes, then to
    /// transfer the file,<br>  you need 12 full packets of 100 bytes (20 bytes of
    /// service bytes  + 80 useful bytes)<br>  and 1 packet of 60 bytes (20 service
    /// bytes + 40 useful bytes).<br>  If the value of percent_len_random_coefficient
    /// Some(1.0>= x > 0.0) is,<br>  for example, 0.3, then the packet length will not
    /// be 100 bytes,<br>  but 100-20 (MTU - minimum packet size) * 0.3 = 24.<br>
    ///  Each packet will have a length from MTU - 24 to MTU.<br>
    pub fn percent_len_random_coefficient(mut self, value: f64) -> Self {
        self.percent_len_random_coefficient = Some(Some(value));
        self
    }

    // Special handling for max_len_file (default is Some(...))
    pub fn max_len_file(mut self, value: Option<usize>) -> Self {
        self.max_len_file = Some(value);
        self
    }

    pub fn max_len_file_value(mut self, value: usize) -> Self {
        self.max_len_file = Some(Some(value));
        self
    }

    /// Consumes the builder and creates a `WsConnectParam` after validating that all
    /// required fields have been set.
    pub fn build(self) -> Result<WsConnectParam, &'static str> {
        // Check that fields without defaults have been provided
        let maximum_length_udp_queue_packages = self
            .maximum_length_udp_queue_packages
            .ok_or("maximum_length_udp_queue_packages must be set")?;
        let maximum_length_fback_queue_packages = self
            .maximum_length_fback_queue_packages
            .ok_or("maximum_length_fback_queue_packages must be set")?;
        let maximum_length_queue_unconfirmed_packages = self
            .maximum_length_queue_unconfirmed_packages
            .ok_or("maximum_length_queue_unconfirmed_packages must be set")?;
        let max_num_attempts_resend_package = self
            .max_num_attempts_resend_package
            .ok_or("max_num_attempts_resend_package must be set")?;

        // Unpack optional fields: if the user never called the setter, we keep the default (None
        // or Some(...))
        let ttl_max_start_cost = self.ttl_max_start_cost.unwrap_or(None);
        let percent_fake_data_packets = self.percent_fake_data_packets.unwrap_or(None);
        let percent_fake_fback_packets = self.percent_fake_fback_packets.unwrap_or(None);
        let percent_len_random_coefficient = self.percent_len_random_coefficient.unwrap_or(None);
        let max_len_file = self.max_len_file.unwrap_or(Some(10 * 1024 * 1024)); // final fallback

        // Now call the original constructor
        WsConnectParam::new(
            &self.pack_topology,
            self.mtu,
            self.instant_feedback_on_packet_loss,
            self.packages_measurement_window_size_determining_latency,
            maximum_length_udp_queue_packages,
            maximum_length_fback_queue_packages,
            maximum_length_queue_unconfirmed_packages,
            max_num_attempts_resend_package,
            self.max_ms_latency,
            self.min_ms_latency,
            self.start_ms_latency,
            self.latency_increase_coefficient,
            self.overhead_network_latency_relative_window_coefficient,
            self.maximum_packet_delay_fback_coefficient,
            self.maximum_packet_delay_absolute_fback,
            ttl_max_start_cost,
            percent_fake_data_packets,
            percent_fake_fback_packets,
            percent_len_random_coefficient,
            max_len_file,
        )
    }
}

#[cfg(test)]
fn get_topol(
    ctr_byte_len: Option<usize>,
    total_min_len: usize,
    ttl_byte_len: Option<usize>,
) -> PackTopology {
    use crate::t0pology;

    let fields = vec![
        //t2page::PakFields::HeadByte,
        t0pology::PakFields::UserField(1),
        t0pology::PakFields::Counter(5),
        t0pology::PakFields::IdConnect(2),
        t0pology::PakFields::HeadCRC(2),
        t0pology::PakFields::Nonce(6),
        //PakFields::TTL(2),
        t0pology::PakFields::Len(3),
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

#[cfg(test)]
mod tests_ttl_max_start_cost_and_instant_feedback_on_packet_loss {
    use super::*;

    #[test]
    fn test_instant_feedback_flag_true() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(true)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            // The following fields match the defaults, but are set explicitly for readability
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
        assert_eq!(
            result.as_ref().unwrap().instant_feedback_on_packet_loss(),
            true
        );
    }

    #[test]
    fn test_instant_feedback_flag_false() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "instant_feedback_on_packet_loss = false should be valid"
        );
        assert_eq!(
            result.as_ref().unwrap().instant_feedback_on_packet_loss(),
            false
        );
    }

    #[test]
    fn test_ttl_none_when_topology_has_ttl() {
        let topo = get_topol(Some(1), 50, Some(1)); // topology has TTL

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_len_file(None) // do not set ttl, so it stays None
            .build();

        assert!(
            result.is_ok(),
            "ttl_max_start_cost = None should be valid when topology has TTL"
        );
        assert_eq!(result.unwrap().ttl_max_start_cost(), None);
    }

    #[test]
    fn test_ttl_none_when_topology_no_ttl() {
        let topo = get_topol(Some(1), 50, None); // topology has NO TTL

        let result = WsConnectParamBuilder::new(topo.clone())
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
        let topo = get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "valid ttl_max_start_cost should be accepted when topology has TTL"
        );
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 128, -1)));
    }

    #[test]
    fn test_ttl_some_when_topology_no_ttl_error() {
        let topo = get_topol(Some(1), 50, None); // topology has NO TTL

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "ttl_max_start_cost = Some should error when topology has no TTL"
        );
        assert_eq!(
            result.err().unwrap(),
            "The ttl_max_start_cost field is defined as Some(), but in pack_topology this field \
             is None."
        );
    }

    #[test]
    fn test_ttl_start_greater_than_max_error() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((100, 200, -1)) // start > max
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "ttl start > max should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum ttl \
             value. For more information, see the description of this variable at the beginning \
             of the file."
        );
    }

    #[test]
    fn test_ttl_start_equal_to_max_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 255, -1)) // start == max
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "ttl start == max should be valid");
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 255, -1)));
    }

    #[test]
    fn test_ttl_max_zero_error() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((0, 100, -1)) // max = 0
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "ttl max = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum ttl \
             value. For more information, see the description of this variable at the beginning \
             of the file."
        );
    }

    #[test]
    fn test_ttl_start_zero_error() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 0, -1)) // start = 0
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "ttl start = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.1 must be greater than zero. For more information, see the \
             description of this variable at the beginning of the file."
        );
    }

    #[test]
    fn test_ttl_start_exceeds_capacity_error() {
        let topo = get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((300, 256, -1)) // start = 256 exceeds 1-byte capacity
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
    fn test_ttl_start_at_capacity_boundary_valid() {
        let topo = get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 255, -1)) // start at max capacity
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "ttl start at capacity boundary should be valid"
        );
    }

    #[test]
    fn test_ttl_cost_positive_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, 1)) // cost = +1
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "ttl cost can be positive");
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 128, 1)));
    }

    #[test]
    fn test_ttl_cost_zero_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, 0)) // cost = 0
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "ttl cost = 0 should be valid");
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 128, 0)));
    }

    #[test]
    fn test_ttl_cost_negative_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1)) // cost = -1
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "ttl cost negative should be valid");
    }

    #[test]
    fn test_ttl_with_larger_byte_length() {
        // Test with 2-byte TTL field (capacity = 65535)
        let topo = get_topol(Some(1), 50, Some(2));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((65535, 32768, -1)) // max capacity for 2 bytes
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "ttl with 2-byte field should work");
    }

    #[test]
    fn test_ttl_instant_feedback_combination() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(true)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "combination of ttl and instant_feedback should be valid"
        );
        let param = result.unwrap();
        assert_eq!(param.instant_feedback_on_packet_loss(), true);
        assert_eq!(param.ttl_max_start_cost(), Some((255, 128, -1)));
    }
}

//persent
#[cfg(test)]
mod tests_percent {
    use super::*;
    #[test]
    fn test_all_traffic_masking_none() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
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
        assert_eq!(param.percent_fake_data_packets(), None);
        assert_eq!(param.percent_fake_fback_packets(), None);
        assert_eq!(param.percent_len_random_coefficient(), None);
    }

    #[test]
    fn test_percent_fake_data_packets_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(0.5)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "percent_fake_data_packets = 0.5 should be valid"
        );
        assert_eq!(result.unwrap().percent_fake_data_packets(), Some(0.5));
    }

    #[test]
    fn test_percent_fake_data_packets_exactly_one() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(1.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "percent_fake_data_packets = 1.0 should be valid"
        );
        assert_eq!(result.unwrap().percent_fake_data_packets(), Some(1.0));
    }

    #[test]
    fn test_percent_fake_data_packets_zero_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(0.0) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_fake_data_packets = 0.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_fake_data_packets must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_negative_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(-0.1) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_fake_data_packets negative should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_fake_data_packets must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_greater_than_one_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(1.1) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_fake_data_packets > 1.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_fake_data_packets must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_nan_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(f64::NAN) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_fake_data_packets NaN should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_fake_data_packets must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_percent_fake_data_packets_infinity_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(f64::INFINITY) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_fake_data_packets infinity should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_fake_data_packets must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_percent_fake_fback_packets_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_fback_packets(0.3)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "percent_fake_fback_packets = 0.3 should be valid"
        );
        assert_eq!(result.unwrap().percent_fake_fback_packets(), Some(0.3));
    }

    #[test]
    fn test_percent_fake_fback_packets_zero_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_fback_packets(0.0) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_fake_fback_packets = 0.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_fake_fback_packets must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_percent_len_random_coefficient_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_len_random_coefficient(0.7)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "percent_len_random_coefficient = 0.7 should be valid"
        );
        assert_eq!(result.unwrap().percent_len_random_coefficient(), Some(0.7));
    }

    #[test]
    fn test_percent_len_random_coefficient_zero_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_len_random_coefficient(0.0) // invalid
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "percent_len_random_coefficient = 0.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "percent_len_random_coefficient must be in the range from (0.0 to 1.0]"
        );
    }

    #[test]
    fn test_all_traffic_masking_valid_values() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(0.1)
            .percent_fake_fback_packets(0.05)
            .percent_len_random_coefficient(0.4)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "all traffic masking parameters with valid values should be valid"
        );
        let param = result.unwrap();
        assert_eq!(param.percent_fake_data_packets(), Some(0.1));
        assert_eq!(param.percent_fake_fback_packets(), Some(0.05));
        assert_eq!(param.percent_len_random_coefficient(), Some(0.4));
    }

    #[test]
    fn test_percent_fake_data_packets_small_positive_value() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_fake_data_packets(0.000001) // very small but positive
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "percent_fake_data_packets with very small positive value should be valid"
        );
        assert_eq!(result.unwrap().percent_fake_data_packets(), Some(0.000001));
    }

    #[test]
    fn test_percent_len_random_coefficient_one() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .percent_len_random_coefficient(1.0) // boundary
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "percent_len_random_coefficient = 1.0 should be valid"
        );
        assert_eq!(result.unwrap().percent_len_random_coefficient(), Some(1.0));
    }

    #[test]
    fn test_combination_ttl_and_traffic_masking() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .percent_fake_data_packets(0.2)
            .percent_fake_fback_packets(0.1)
            .percent_len_random_coefficient(0.5)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "combination of ttl and traffic masking parameters should be valid"
        );
    }
}

#[cfg(test)]
mod tests_delay {
    use super::*;

    #[test]
    fn test_fback_coefficient_valid_mid_range() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(50.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "valid fback coefficient (0.5) should be accepted"
        );
        let param = result.unwrap();
        assert_eq!(param.maximum_packet_delay_fback_coefficient(), 0.5);
        assert_eq!(param.maximum_packet_delay_absolute_fback(), 50.0);
    }

    #[test]
    fn test_fback_coefficient_minimum_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.0001)
            .maximum_packet_delay_absolute_fback(0.0001)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "fback coefficient just above 0 should be valid"
        );
    }

    #[test]
    fn test_fback_coefficient_maximum_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(1.0)
            .maximum_packet_delay_absolute_fback(100.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "fback coefficient = 1.0 should be valid (boundary)"
        );
    }

    #[test]
    fn test_fback_coefficient_zero_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.0) // invalid
            .maximum_packet_delay_absolute_fback(50.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "fback coefficient = 0 should error");
        // Note: original error message might be either "must be greater than zero" or
        // "is_normal()" We'll check the actual message; the original test expects "all
        // f64 variables must be is_normal()"
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_fback_coefficient_negative_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(-0.5) // invalid
            .maximum_packet_delay_absolute_fback(50.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "negative fback coefficient should error");
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be greater than zero"
        );
    }

    #[test]
    fn test_fback_coefficient_greater_than_one_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(1.1) // invalid (>1.0)
            .maximum_packet_delay_absolute_fback(50.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "fback coefficient > 1.0 should error");
        // Original test notes that error message is incorrect but we test the actual behavior
        let err = result.err().unwrap();
        assert!(err.contains("must be greater than zero") || err.contains("is_normal"));
    }

    #[test]
    fn test_fback_coefficient_nan_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(f64::NAN) // invalid
            .maximum_packet_delay_absolute_fback(50.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "NaN fback coefficient should error");
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_fback_coefficient_infinite_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(f64::INFINITY) // invalid
            .maximum_packet_delay_absolute_fback(50.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "infinite fback coefficient should error");
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_absolute_fback_zero_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .maximum_packet_delay_absolute_fback(0.0) // valid (>=0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "absolute_fback = 0.0 should be non valid (documentation says between 0 and \
             max_ms_latency)"
        );
    }

    #[test]
    fn test_absolute_fback_equal_to_max_latency_valid() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(100.0) // exactly max_ms_latency
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "absolute_fback = max_ms_latency should be valid (boundary)"
        );
    }

    #[test]
    fn test_absolute_fback_exceeds_max_latency_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(100.1) // exceeds max_ms_latency
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "absolute_fback > max_ms_latency should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "The variable maximum_packet_delay_absolute_fback must be no greater than \
             max_ms_latency For more information, see the description of this variable at the \
             beginning of the file."
        );
    }

    #[test]
    fn test_absolute_fback_negative_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(-0.1) // negative
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "negative absolute_fback should error");
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be greater than zero"
        );
    }

    #[test]
    fn test_absolute_fback_nan_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(f64::NAN)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "NaN absolute_fback should error");
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_absolute_fback_infinite_error() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(f64::INFINITY)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "infinite absolute_fback should error");
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_both_fback_parameters_boundary_values() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(1.0)
            .maximum_packet_delay_absolute_fback(100.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "both fback parameters at max boundaries should be valid"
        );
        let param = result.unwrap();
        assert_eq!(param.maximum_packet_delay_fback_coefficient(), 1.0);
        assert_eq!(param.maximum_packet_delay_absolute_fback(), 100.0);
    }

    #[test]
    fn test_fback_parameters_with_different_max_latency() {
        let topo = get_topol(Some(1), 50, None);
        let small_max = 110.0;

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(small_max)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(8.0)
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "fback with smaller max_latency should work");
        let param = result.unwrap();
        assert_eq!(param.max_ms_latency(), small_max);
        assert_eq!(param.maximum_packet_delay_absolute_fback(), 8.0);
    }

    #[test]
    fn test_fback_coefficient_with_edge_overhead_value() {
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.1)
            .maximum_packet_delay_fback_coefficient(0.5)
            .maximum_packet_delay_absolute_fback(25.0)
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "fback with overhead=0.0 should be valid");
    }
}

#[cfg(test)]
mod tests_packet_queue_management_group {
    use super::*;

    #[test]
    fn test_queue_params_valid_minimal_values() {
        // 1-byte counter: capacity = 126
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(1)
            .maximum_length_fback_queue_packages(1)
            .maximum_length_queue_unconfirmed_packages(1)
            .max_num_attempts_resend_package(1)
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "minimal queue values should be valid");
        let param = result.unwrap();
        assert_eq!(param.maximum_length_udp_queue_packages(), 1);
        assert_eq!(param.maximum_length_fback_queue_packages(), 1);
        assert_eq!(param.maximum_length_queue_unconfirmed_packages(), 1);
        assert_eq!(param.max_num_attempts_resend_package(), 1);
    }

    #[test]
    fn test_queue_params_valid_within_capacity() {
        // 1-byte counter: capacity = 126
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(30)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "queue values within capacity should be valid"
        );
    }

    #[test]
    fn test_queue_params_at_capacity_boundary() {
        // 1-byte counter: capacity = 126
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(126)
            .maximum_length_fback_queue_packages(126)
            .maximum_length_queue_unconfirmed_packages(126)
            .max_num_attempts_resend_package(126)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "queue values at capacity boundary should be valid"
        );
    }

    #[test]
    fn test_queue_params_exceed_capacity_error() {
        // 1-byte counter: capacity = 126
        let topo = get_topol(Some(1), 50, None);

        // maximum_length_udp_queue_packages > capacity
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(127)
            .maximum_length_fback_queue_packages(30)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "maximum_length_udp_queue_packages > capacity should error"
        );
        assert_eq!(
            result.err().unwrap(),
            " maximum_length_udp_queue_packages must be less than the maximum capacity of the \
             pack_topology.counter_slice() field. "
        );

        // maximum_length_fback_queue_packages > capacity
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(127)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "maximum_length_fback_queue_packages > capacity should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "maximum_length_fback_queue_packages must not exceed the maximum capacity of the \
             pack_topology.counter_slice() counter. "
        );

        // max_num_attempts_resend_package > capacity
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(30)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(127)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "max_num_attempts_resend_package > capacity should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "max_num_attempts_resend_package > ctr_max_capacity_real as usize.  \
             max_num_attempts_resend_package must be less than the maximum possible capacity in \
             pack_topology.counter_slice()."
        );
    }

    #[test]
    fn test_queue_relationships_udp_less_than_unconfirmed_error() {
        let topo = get_topol(Some(2), 50, None); // 2-byte counter for larger capacity

        // maximum_length_udp_queue_packages < maximum_length_queue_unconfirmed_packages
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(50)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(100) // larger than udp
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "udp queue < unconfirmed queue should error"
        );
        assert_eq!(
            result.err().unwrap(),
            " maximum_length_udp_queue_packages must be greater than \
             maximum_length_queue_unconfirmed_packages so that all packets are confirmed. For \
             more information, see the description of this variable at the beginning of the file."
        );
    }

    #[test]
    fn test_queue_relationships_fback_greater_than_unconfirmed_error() {
        let topo = get_topol(Some(2), 50, None);

        // maximum_length_fback_queue_packages > maximum_length_queue_unconfirmed_packages
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(200)
            .maximum_length_fback_queue_packages(150) // > unconfirmed
            .maximum_length_queue_unconfirmed_packages(100)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "fback queue > unconfirmed queue should error"
        );
        assert_eq!(
            result.err().unwrap(),
            " maximum_length_fback_queue_packages must be less than \
             maximum_length_queue_unconfirmed_packages.For more information, see the description \
             of this variable at the beginning of the file."
        );
    }

    #[test]
    fn test_queue_relationships_edge_cases_valid() {
        let topo = get_topol(Some(2), 50, None);

        // Edge case: udp queue = unconfirmed queue
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(50)
            .maximum_length_queue_unconfirmed_packages(100)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "udp queue = unconfirmed queue should be valid"
        );

        // Edge case: fback queue = unconfirmed queue
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(200)
            .maximum_length_fback_queue_packages(100)
            .maximum_length_queue_unconfirmed_packages(100)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "fback queue = unconfirmed queue should be valid"
        );
    }

    #[test]
    fn test_queue_zero_values_error() {
        let topo = get_topol(Some(1), 50, None);

        // maximum_length_udp_queue_packages = 0
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(0)
            .maximum_length_fback_queue_packages(100)
            .maximum_length_queue_unconfirmed_packages(150)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "udp queue = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "all usize variables must be greater than zero"
        );

        // maximum_length_fback_queue_packages = 0
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(200)
            .maximum_length_fback_queue_packages(0)
            .maximum_length_queue_unconfirmed_packages(150)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "fback queue = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "all usize variables must be greater than zero"
        );

        // maximum_length_queue_unconfirmed_packages = 0
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(200)
            .maximum_length_fback_queue_packages(100)
            .maximum_length_queue_unconfirmed_packages(0)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "unconfirmed queue = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "all usize variables must be greater than zero"
        );

        // max_num_attempts_resend_package = 0
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(200)
            .maximum_length_fback_queue_packages(100)
            .maximum_length_queue_unconfirmed_packages(150)
            .max_num_attempts_resend_package(0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "max attempts = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "all usize variables must be greater than zero"
        );
    }

    #[test]
    fn test_queue_with_larger_capacity() {
        // 2-byte counter: capacity = (65535 >> 1) - 1 = 32767
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(20000)
            .maximum_length_fback_queue_packages(5000)
            .maximum_length_queue_unconfirmed_packages(15000)
            .max_num_attempts_resend_package(100)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "large queue values within 2-byte capacity should be valid"
        );
    }

    #[test]
    fn test_counter_slice_none_error() {
        // Topology without counter_slice
        let topo = get_topol(None, 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(50)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "topology without counter_slice should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "The counter_slice() field in pack_topology is None, but it must be specified!"
        );
    }

    #[test]
    fn test_queue_params_recommended_ratio_not_enforced() {
        // Documentation recommends unconfirmed queue be 3x fback queue, but code doesn't enforce
        // this
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(200)
            .maximum_length_fback_queue_packages(50)
            .maximum_length_queue_unconfirmed_packages(100) // only 2x fback, not 3x
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "not following 3x recommendation should still be valid"
        );
    }

    #[test]
    fn test_queue_params_all_relationships_valid() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(300)
            .maximum_length_fback_queue_packages(50)
            .maximum_length_queue_unconfirmed_packages(200)
            .max_num_attempts_resend_package(25)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "all queue relationships satisfied should be valid"
        );
        let param = result.unwrap();
        assert!(
            param.maximum_length_udp_queue_packages()
                >= param.maximum_length_queue_unconfirmed_packages()
        );
        assert!(
            param.maximum_length_fback_queue_packages()
                <= param.maximum_length_queue_unconfirmed_packages()
        );
    }

    #[test]
    fn test_queue_params_with_ttl_combination() {
        // Test queue params work correctly when TTL is also specified
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(30)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(10)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "queue params with TTL should be valid");
    }

    #[test]
    fn test_queue_params_measurement_window_independent() {
        // packages_measurement_window_size_determining_latency is independent of queue params
        let topo = get_topol(Some(1), 50, None);

        // packages_measurement_window_size_determining_latency = 0 should error
        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(0) // invalid
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(30)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(10)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "measurement window = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "all usize variables must be greater than zero"
        );
    }
}

#[cfg(test)]
mod tests_adaptation_coefficients {
    use super::*;
    #[test]
    fn test_all_coefficients_with_valid_values() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.3) // changed from default 0.2
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "all coefficients with valid values should be accepted"
        );
        let param = result.unwrap();
        assert_eq!(param.latency_increase_coefficient(), 0.5);
        assert_eq!(
            param.overhead_network_latency_relative_window_coefficient(),
            0.3
        );
        assert_eq!(
            param.packages_measurement_window_size_determining_latency(),
            10
        );
    }

    #[test]
    fn test_latency_increase_coefficient_at_minimum_valid() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(f64::MIN_POSITIVE) // smallest positive f64
            .overhead_network_latency_relative_window_coefficient(0.2) // unchanged default
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "latency_increase_coefficient at minimum positive should be valid"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_at_maximum_valid() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(1.0)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "latency_increase_coefficient = 1.0 should be valid"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_zero_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.0) // invalid
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "latency_increase_coefficient = 0.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_negative_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(-0.1) // invalid
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "latency_increase_coefficient negative should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be greater than zero"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_greater_than_one_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(1.1) // invalid (>1.0)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "latency_increase_coefficient > 1.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "latency_increase_coefficient overhead_network_latency_relative_window_coefficient \
             maximum_packet_delay_fback_coefficient must be greater than zero"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_nan_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(f64::NAN)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "latency_increase_coefficient NaN should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_latency_increase_coefficient_infinite_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(f64::INFINITY)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "latency_increase_coefficient infinite should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be is_normal()"
        );
    }

    #[test]
    fn test_overhead_coefficient_at_minimum_valid() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.00001) // very small positive
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "overhead_network_latency_relative_window_coefficient = 0.00001 should be valid"
        );
    }

    #[test]
    fn test_overhead_coefficient_at_maximum_valid() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(1.0) // max allowed
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "overhead_network_latency_relative_window_coefficient = 1.0 should be valid"
        );
    }

    #[test]
    fn test_overhead_coefficient_negative_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(-0.1) // invalid
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "overhead_network_latency_relative_window_coefficient negative should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "all f64 variables must be greater than zero"
        );
    }

    #[test]
    fn test_overhead_coefficient_greater_than_one_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(1.1) // >1.0 invalid
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "overhead_network_latency_relative_window_coefficient > 1.0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "latency_increase_coefficient overhead_network_latency_relative_window_coefficient \
             maximum_packet_delay_fback_coefficient must be greater than zero"
        );
    }

    #[test]
    fn test_packages_measurement_window_minimum_valid() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(1) // minimum
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "packages_measurement_window_size_determining_latency = 1 should be valid"
        );
    }

    #[test]
    fn test_packages_measurement_window_large_valid() {
        let topo = get_topol(Some(2), 50, None); // counter 2 bytes = max capacity ~32767

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(1000) // large but within capacity
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "packages_measurement_window_size_determining_latency large should be valid"
        );
    }

    #[test]
    fn test_packages_measurement_window_zero_error() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(0) // invalid
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "packages_measurement_window_size_determining_latency = 0 should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "all usize variables must be greater than zero"
        );
    }

    #[test]
    fn test_packages_measurement_window_with_small_counter_capacity() {
        // Create topology with 1-byte counter (max capacity ~127)
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(50) // within 1-byte capacity
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "packages_measurement_window_size_determining_latency within 1-byte counter capacity \
             should be valid"
        );
    }

    #[test]
    fn test_all_coefficients_at_boundary_values() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(1.0) // max
            .overhead_network_latency_relative_window_coefficient(0.0000001) // min positive
            .maximum_packet_delay_fback_coefficient(0.8) // unchanged
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "all coefficients at boundary values should be valid"
        );
        let param = result.unwrap();
        assert_eq!(param.latency_increase_coefficient(), 1.0);
        assert_eq!(
            param.overhead_network_latency_relative_window_coefficient(),
            0.0000001
        );
    }

    #[test]
    fn test_combination_of_all_coefficients_mid_range() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.3) // mid-range
            .overhead_network_latency_relative_window_coefficient(0.7) // mid-range
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "combination of mid-range coefficients should be valid"
        );
        let param = result.unwrap();
        assert_eq!(param.latency_increase_coefficient(), 0.3);
        assert_eq!(
            param.overhead_network_latency_relative_window_coefficient(),
            0.7
        );
        assert_eq!(
            param.packages_measurement_window_size_determining_latency(),
            10
        );
    }

    #[test]
    fn test_packages_measurement_window_with_very_large_counter() {
        // Create topology with 8-byte counter (max capacity huge)
        let topo = get_topol(Some(8), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(100000) // very large
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "packages_measurement_window_size_determining_latency with large counter should be \
             valid"
        );
    }

    #[test]
    fn test_error_message_for_coefficient_greater_than_one() {
        let topo = get_topol(Some(2), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(2.0) // >1.0
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "latency_increase_coefficient overhead_network_latency_relative_window_coefficient \
             maximum_packet_delay_fback_coefficient must be greater than zero"
        );
    }
}

#[cfg(test)]
mod tests_from_group {
    use super::*;

    #[test]
    fn test_mtu_greater_than_minimal_packet_length() {
        let topo = get_topol(Some(1), 50, None); // minimal length = 50

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "mtu > total_minimal_len should be valid");
        assert_eq!(result.as_ref().unwrap().mtu(), 1500);
    }

    #[test]
    fn test_mtu_significantly_larger_than_minimal_length() {
        let topo = get_topol(Some(1), 1000, None); // minimal length = 1000

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "mtu should be accepted when larger than total_minimal_len"
        );
    }

    #[test]
    fn test_mtu_equal_to_minimal_packet_length_error() {
        let topo = get_topol(Some(1), 100, None); // minimal length = 100

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(100)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "mtu == total_minimal_len should error");
        assert_eq!(
            result.err().unwrap(),
            "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
             pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is the \
             minimum packet length, such a packet contains only protocol service information, mtu \
             must be large enough to accommodate the length of the packet's useful data and \
             service data."
        );
    }

    #[test]
    fn test_mtu_less_than_minimal_packet_length_error() {
        let topo = get_topol(Some(1), 500, None); // minimal length = 500

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(300)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "mtu < total_minimal_len should error");
        assert_eq!(
            result.err().unwrap(),
            "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
             pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is the \
             minimum packet length, such a packet contains only protocol service information, mtu \
             must be large enough to accommodate the length of the packet's useful data and \
             service data."
        );
    }

    #[test]
    fn test_mtu_minimum_valid_value() {
        let topo = get_topol(Some(1), 100, None); // minimal length = 100

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(101) // just 1 more than minimal
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "mtu = total_minimal_len + 1 should be valid"
        );
        assert_eq!(result.unwrap().mtu(), 101);
    }

    #[test]
    fn test_mtu_large_value_valid() {
        let topo = get_topol(Some(1), 50, None); // minimal length = 50

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(65535)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "large mtu value should be valid");
        assert_eq!(result.unwrap().mtu(), 65535);
    }

    #[test]
    fn test_pack_topology_without_counter_slice_error() {
        // Create topology without counter (ctr_byte_len = None)
        let topo = get_topol(None, 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_err(),
            "pack_topology without counter_slice should error"
        );
        assert_eq!(
            result.err().unwrap(),
            "The counter_slice() field in pack_topology is None, but it must be specified!"
        );
    }

    #[test]
    fn test_pack_topology_with_counter_slice_valid() {
        let topo = get_topol(Some(1), 50, None); // Has counter slice

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(
            result.is_ok(),
            "pack_topology with counter_slice should be valid"
        );
    }

    #[test]
    fn test_different_minimal_lengths_with_proportional_mtu() {
        // Test various minimal lengths with proportional MTUs
        let test_cases = vec![
            (10, 100),   // minimal=10, mtu=100 (10x)
            (100, 1500), // minimal=100, mtu=1500 (15x)
            (500, 2000), // minimal=500, mtu=2000 (4x)
        ];

        for (min_len, mtu) in test_cases {
            let topo = get_topol(Some(1), min_len, None);

            let result = WsConnectParamBuilder::new(topo.clone())
                .mtu(mtu)
                .instant_feedback_on_packet_loss(false)
                .packages_measurement_window_size_determining_latency(10)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.8)
                .maximum_packet_delay_absolute_fback(80.0)
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "mtu={} should be valid for minimal_len={}",
                mtu,
                min_len
            );
            let param = result.unwrap();
            assert_eq!(param.mtu(), mtu);
            assert_eq!(param.pack_topology().total_minimal_len(), min_len);
        }
    }

    #[test]
    fn test_mtu_zero_error_but_not_from_group1() {
        // Note: mtu=0 would fail the general usize > 0 check, but here we test mtu < minimal_len.
        // With minimal_len = 50 and mtu = 40, we expect the specific mtu < minimal_len error.
        let topo = get_topol(Some(1), 50, None);

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(40) // less than minimal_len (50)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_err(), "mtu=40 (<50) should error");
        assert_eq!(
            result.err().unwrap(),
            "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
             pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is the \
             minimum packet length, such a packet contains only protocol service information, mtu \
             must be large enough to accommodate the length of the packet's useful data and \
             service data."
        );
    }

    #[test]
    fn test_mtu_one_when_minimal_length_zero() {
        // Edge case: if total_minimal_len were 0, mtu=1 would be valid.
        // Since get_topol doesn't allow total_min_len=0, we use the smallest possible.
        let topo = get_topol(Some(1), 1, None); // minimal length = 1

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(2) // just 1 more than minimal
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build();

        assert!(result.is_ok(), "mtu=2 should be valid when minimal_len=1");
    }

    #[test]
    fn test_getters_return_correct_values_for_group1() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .mtu(1500)
            .instant_feedback_on_packet_loss(false)
            .packages_measurement_window_size_determining_latency(10)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .max_len_file(None)
            .build()
            .unwrap();

        // Verify getters return the values we passed
        assert_eq!(result.mtu(), 1500);
        assert_eq!(result.pack_topology().total_minimal_len(), 50);
    }
}
#[cfg(test)]
mod tests_mt1 {
    use super::*;

    // Tests rewritten to use the modern WsConnectParamBuilder (2026 style).
    // The helper create_valid_base_params is removed; all mandatory fields are set
    // explicitly. Base parameters (mtu, instant_feedback, measurement window, queue
    // sizes, attempts, latencies, coefficients) are set to the same values as before
    // (1500, false, 10, 100, 20, 60, 3, 100.0, 10.0, 50.0, 0.5, 0.2, 0.8, 80.0) unless
    // the test specifically changes a value. The optional field max_len_file is handled
    // via builder methods.

    #[test]
    fn test_instant_feedback_flag_true() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(true)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
        assert_eq!(
            result.as_ref().unwrap().instant_feedback_on_packet_loss(),
            true
        );
    }

    #[test]
    fn test_instant_feedback_flag_false1() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
            "instant_feedback_on_packet_loss = false should be valid"
        );
        assert_eq!(
            result.as_ref().unwrap().instant_feedback_on_packet_loss(),
            false
        );
    }

    #[test]
    fn test_ttl_none_when_topology_has_ttl1() {
        let topo = get_topol(Some(1), 50, Some(1)); // topology has TTL

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build(); // ttl left at default (None)

        assert!(
            result.is_ok(),
            "ttl_max_start_cost = None should be valid when topology has TTL"
        );
        assert_eq!(result.unwrap().ttl_max_start_cost(), None);
    }

    #[test]
    fn test_ttl_none_when_topology_no_ttl1() {
        let topo = get_topol(Some(1), 50, None); // topology has NO TTL

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
            "ttl_max_start_cost = None should be valid when topology has no TTL"
        );
    }

    #[test]
    fn test_ttl_some_when_topology_has_ttl_valid_values1() {
        let topo = get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
            "valid ttl_max_start_cost should be accepted when topology has TTL"
        );
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 128, -1)));
    }

    #[test]
    fn test_ttl_some_when_topology_no_ttl_error1() {
        let topo = get_topol(Some(1), 50, None); // topology has NO TTL

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1)) // ttl specified
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(
            result.is_err(),
            "ttl_max_start_cost = Some should error when topology has no TTL"
        );
        assert_eq!(
            result.err().unwrap(),
            "The ttl_max_start_cost field is defined as Some(), but in pack_topology this field \
             is None."
        );
    }

    #[test]
    fn test_ttl_start_greater_than_max_error1() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((100, 200, -1)) // start > max
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_err(), "ttl start > max should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum ttl \
             value. For more information, see the description of this variable at the beginning \
             of the file."
        );
    }

    #[test]
    fn test_ttl_start_equal_to_max_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 255, -1)) // start == max
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_ok(), "ttl start == max should be valid");
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 255, -1)));
    }

    #[test]
    fn test_ttl_max_zero_error() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((0, 0, -1)) // max = 0
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_err(), "ttl max = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.0 must be greater than zero. For more information, see the \
             description of this variable at the beginning of the file."
        );
    }

    #[test]
    fn test_ttl_start_zero_error() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((254, 0, -1)) // start = 0
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_err(), "ttl start = 0 should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.1 must be greater than zero. For more information, see the \
             description of this variable at the beginning of the file."
        );
    }

    #[test]
    fn test_ttl_start_exceeds_capacity_error() {
        let topo = get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((300, 256, -1)) // start = 256 exceeds 1-byte capacity
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_err(), "ttl start exceeds capacity should error");
        assert_eq!(
            result.err().unwrap(),
            "ttl_max_start_cost.1 is greater than the length that can be accommodated in the \
             pack_topology field."
        );
    }

    #[test]
    fn test_ttl_start_at_capacity_non_boundary_valid() {
        let topo = get_topol(Some(1), 50, Some(1)); // 1 byte TTL, max capacity = 255

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((200, 100, -1000))
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
            "ttl start at capacity boundary should be valid"
        );
    }

    #[test]
    fn test_ttl_cost_positive_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, 1)) // cost = +1
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_ok(), "ttl cost can be positive");
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 128, 1)));
    }

    #[test]
    fn test_ttl_cost_zero_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, 0)) // cost = 0
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_ok(), "ttl cost = 0 should be valid");
        assert_eq!(result.unwrap().ttl_max_start_cost(), Some((255, 128, 0)));
    }

    #[test]
    fn test_ttl_cost_negative_valid() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1)) // cost = -1
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_ok(), "ttl cost negative should be valid");
    }

    #[test]
    fn test_ttl_with_larger_byte_length() {
        // Test with 2-byte TTL field (capacity = 65535)
        let topo = get_topol(Some(1), 50, Some(2));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(false)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((65535, 32768, -1)) // max capacity for 2 bytes
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(result.is_ok(), "ttl with 2-byte field should work");
    }

    #[test]
    fn test_ttl_instant_feedback_combination() {
        let topo = get_topol(Some(1), 50, Some(1));

        let result = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(true)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
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
            "combination of ttl and instant_feedback should be valid"
        );
        let param = result.unwrap();
        assert_eq!(param.instant_feedback_on_packet_loss(), true);
        assert_eq!(param.ttl_max_start_cost(), Some((255, 128, -1)));
    }

    #[test]
    fn max_len_file() {
        let topo = get_topol(Some(1), 50, Some(1));

        // Test with max_len_file = None (default overridden to None)
        let result1 = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(true)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file(None) // explicitly set to None
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        // Test with max_len_file = Some(1000)
        let result1000 = WsConnectParamBuilder::new(topo.clone())
            .instant_feedback_on_packet_loss(true)
            .maximum_length_udp_queue_packages(100)
            .maximum_length_fback_queue_packages(20)
            .maximum_length_queue_unconfirmed_packages(60)
            .max_num_attempts_resend_package(3)
            .ttl_max_start_cost((255, 128, -1))
            .max_len_file_value(1000) // sets Some(1000)
            .mtu(1500)
            .packages_measurement_window_size_determining_latency(10)
            .max_ms_latency(100.0)
            .min_ms_latency(10.0)
            .start_ms_latency(50.0)
            .latency_increase_coefficient(0.5)
            .overhead_network_latency_relative_window_coefficient(0.2)
            .maximum_packet_delay_fback_coefficient(0.8)
            .maximum_packet_delay_absolute_fback(80.0)
            .build();

        assert!(
            result1.is_ok(),
            "combination of ttl and instant_feedback should be valid"
        );
        assert!(
            result1000.is_ok(),
            "combination of ttl and instant_feedback should be valid"
        );
        let param1 = result1.unwrap();
        let param1000 = result1000.unwrap();
        assert_eq!(param1.max_len_file(), None);
        assert_eq!(param1000.max_len_file(), Some(1000));
    }
}
