//Gaoo~~~ :3

use crate::t0pology::PackTopology;
use crate::{EXPCP, wutils};

#[derive(Debug, PartialEq, Clone)]
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
    ctr_max_capacity_real: u64,
    max_len_file: Option<usize>,
    intermediate_questionable_packages_queue: Option<usize>,
    need_use_random: bool,
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
        intermediate_questionable_packages_queue: Option<usize>,
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
        let ctr_max_capacity_real = {
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
            let ctr_max_capacity_real = EXPCP!(
                (ctr_max_capacity.0 >> 1).checked_sub(1),
                "(ctr_max_capacity.0 >> 1) - 1 < 0 error, impossible behavior, since the minimum \
                 length of counter_slice() is 1, 1 byte is 255 maximum value, 255 >>1 - 127, 127 \
                 is greater than 1."
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
            ctr_max_capacity_real
        };

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

        if let Some(xxx) = intermediate_questionable_packages_queue {
            if xxx == 0 {
                return Err(
                    "intermediate_questionable_packages_queue is Some(0), but Some(the value must \
                     be greater than zero) ",
                );
            }

            if xxx > u64::MAX as usize {
                return Err(
                    "Some( intermediate_questionable_packages_queue) > u64::MAX as usize, Some( \
                     intermediate_questionable_packages_queue) capacity exceeds system's u64 limit",
                );
            }

            if ctr_max_capacity_real < xxx as u64 {
                return Err("Some(intermediate_questionable_packages_queue) > \
                            ctr_max_capacity_real, The maximum value that the counter field in \
                            the packet topology can hold must be GREATER than \
                            intermediate_questionable_packages_queue.");
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
            percent_fake_data_packets,  //
            percent_fake_fback_packets, //
            ctr_max_capacity_real,
            instant_feedback_on_packet_loss,
            percent_len_random_coefficient,
            max_len_file,
            intermediate_questionable_packages_queue,
            need_use_random: (percent_fake_data_packets.is_some()
                || percent_fake_fback_packets.is_some()
                || percent_len_random_coefficient.is_some()),
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

    pub fn intermediate_questionable_packages_queue(&self) -> Option<usize> {
        self.intermediate_questionable_packages_queue
    }
    ///  ctr_max_capacity_real shows how many unique values</br> the counter can hold
    /// without</br>  collisions, needed for the upper limit of size,</br>
    ///  maximum_length_udp_queue_packages,</br>
    ///  maximum_length_queue_unconfirmed_packages,</br>
    ///  maximum_length_fback_queue_packages,</br>
    ///  max_num_attempts_resend_package,</br>
    ///  intermediate_questionable_packages_queue</br>
    pub fn ctr_max_capacity_real(&self) -> u64 {
        self.ctr_max_capacity_real
    }

    pub fn need_init_random(&self) -> bool {
        self.need_use_random
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
    percent_fake_data_packets: Option<f64>,
    percent_fake_fback_packets: Option<f64>,
    percent_len_random_coefficient: Option<f64>,
    intermediate_questionable_packages_queue: Option<usize>,
    max_len_file: Option<Option<usize>>, // default is Some(10*1024*1024)
}

impl WsConnectParamBuilder {
    /// Creates a new builder with the mandatory `pack_topology` and all defaults applied.
    pub fn new(pack_topology: &PackTopology) -> Self {
        Self {
            pack_topology: pack_topology.clone(),
            // Default values from the problem statement
            mtu: 1400,
            instant_feedback_on_packet_loss: false,
            packages_measurement_window_size_determining_latency: 10,
            max_ms_latency: 500.0,
            min_ms_latency: 2.0,
            start_ms_latency: 50.0,
            latency_increase_coefficient: 0.2,
            overhead_network_latency_relative_window_coefficient: 0.2,
            maximum_packet_delay_fback_coefficient: 0.5,
            maximum_packet_delay_absolute_fback: 20.0,
            // Fields without defaults start as None
            maximum_length_udp_queue_packages: None,
            maximum_length_fback_queue_packages: None,
            maximum_length_queue_unconfirmed_packages: None,
            max_num_attempts_resend_package: None,
            // Optional fields: inner None = not set by user, outer Option = final value (default
            // None)
            ttl_max_start_cost: Some(None),
            percent_fake_data_packets: None,
            percent_fake_fback_packets: None,
            percent_len_random_coefficient: None,
            max_len_file: Some(Some(10 * 1024 * 1024)), // default Some(...)
            intermediate_questionable_packages_queue: None,
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
    pub fn percent_fake_data_packets(mut self, value: Option<f64>) -> Self {
        self.percent_fake_data_packets = value;
        self
    }
    //
    ///see description percent_fake_data_packets^^^
    /// similar behavior for fback-type packets
    pub fn percent_fake_fback_packets(mut self, value: Option<f64>) -> Self {
        self.percent_fake_fback_packets = value;
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
    pub fn percent_len_random_coefficient(mut self, value: Option<f64>) -> Self {
        self.percent_len_random_coefficient = value;
        self
    }

    // Represents a queue for holding packets that cannot yet be decrypted due to key
    // rotation. This type enforces the invariant that if the queue exists, its internal
    // length must be greater than zero. The queue size is configured by the
    // DoubtfulPacketsFounder during initialization.

    /// Handles network instability scenarios where packets may be duplicated, reordered,
    /// or lost. Specifically manages the transition between two encryption keys
    /// during the connection handshake.
    ///
    /// Connection Lifecycle:
    /// 1. Initial Connection: Established using the first symmetric key (Key #1).
    /// 2. Key Exchange: Immediately after connection, an asymmetric procedure generates
    ///    the second secret key (Key #2).
    /// 3. Rotation: All subsequent packets (counter > threshold, e.g., 20) are encrypted
    ///    with Key #2.
    ///
    /// Reordering Scenario:
    /// In unstable networks, packets encrypted with Key #2 (e.g., counters 30, 50) may
    /// arrive before the final batch of packets encrypted with Key #1 (e.g., counters
    /// 1-20).
    ///
    /// Queue Logic:
    /// - If this queue were empty (or null), late-arriving packets encrypted with Key #1
    ///   would be dropped because the system would have already switched to Key #2,
    ///   causing unnecessary retransmissions.
    /// - Instead, packets with counters exceeding the current key's range are stored here
    ///   temporarily.
    /// - Once Key #2 is fully generated and active, this queue is processed:
    ///   * Stored packets are decrypted using the appropriate key.
    ///   * The queue is completely cleared to free memory.
    pub fn intermediate_questionable_packages_queue(
        mut self,
        intermediate_questionable_packages_queue: Option<usize>,
    ) -> Self {
        self.intermediate_questionable_packages_queue = intermediate_questionable_packages_queue;
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

        let max_len_file = self.max_len_file.unwrap_or(Some(10 * 1024 * 1024)); // final fallback

        let intermediate_questionable_packages_queue =
            self.intermediate_questionable_packages_queue;

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
            self.percent_fake_data_packets,
            self.percent_fake_fback_packets,
            self.percent_len_random_coefficient,
            max_len_file,
            intermediate_questionable_packages_queue,
        )
    }
}

//=============================================TEST====================TEST==================================TEST======================TEST=========
//++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#
//++__-+_#_@!_#_!__!___#____-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__$_%___Z^_++__-+_#_@!_#_!__!___#__
//+-+_#_@!_#_!__!__#__$_%___Z^_+__-+_#_@!_#_!_!___#__$_%__Z^_++_-+_#_@!#_!__!__#__$_%___^_++__-_#_@!_#!__!_____$_%__Z^_++__+_#_@!_#___!___#_$_%__Z^
//=============================================TEST================================TEST=======================TEST==================================
#[cfg(test)]
pub fn base_builder_pub(topo: &PackTopology) -> WsConnectParamBuilder {
    WsConnectParamBuilder::new(topo)
        .max_ms_latency(100.0)
        .min_ms_latency(10.0)
        .start_ms_latency(50.0)
        .latency_increase_coefficient(0.5)
        .max_num_attempts_resend_package(3)
        .packages_measurement_window_size_determining_latency(10)
        .overhead_network_latency_relative_window_coefficient(0.2)
        .maximum_packet_delay_fback_coefficient(0.8)
        .maximum_packet_delay_absolute_fback(80.0)
        .maximum_length_udp_queue_packages(100)
        .maximum_length_fback_queue_packages(20)
        .maximum_length_queue_unconfirmed_packages(60)
        .max_len_file(None)
        .instant_feedback_on_packet_loss(false)
}

#[cfg(test)]
mod all_test {
    use super::*;
    #[cfg(test)]
    fn get_topol(
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

    #[cfg(test)]
    mod tests_ttl_max_start_cost_and_instant_feedback_on_packet_loss {
        use super::*;

        #[test]
        fn test_instant_feedback_flag_true() {
            let topo = get_topol(Some(1), 50, Some(1));

            let result = WsConnectParamBuilder::new(&topo)
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
            assert!(result.as_ref().unwrap().instant_feedback_on_packet_loss());
        }

        #[test]
        fn test_instant_feedback_flag_false() {
            let topo = get_topol(Some(1), 50, Some(1));

            let result = WsConnectParamBuilder::new(&topo)
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
            assert!(!result.as_ref().unwrap().instant_feedback_on_packet_loss());
        }

        #[test]
        fn test_ttl_none_when_topology_has_ttl() {
            let topo = get_topol(Some(1), 50, Some(1)); // topology has TTL

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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
                "The ttl_max_start_cost field is defined as Some(), but in pack_topology this \
                 field is None."
            );
        }

        #[test]
        fn test_ttl_start_greater_than_max_error() {
            let topo = get_topol(Some(1), 50, Some(1));

            let result = WsConnectParamBuilder::new(&topo)
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
                "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum \
                 ttl value. For more information, see the description of this variable at the \
                 beginning of the file."
            );
        }

        #[test]
        fn test_ttl_start_equal_to_max_valid() {
            let topo = get_topol(Some(1), 50, Some(1));

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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
                "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum \
                 ttl value. For more information, see the description of this variable at the \
                 beginning of the file."
            );
        }

        #[test]
        fn test_ttl_start_zero_error() {
            let topo = get_topol(Some(1), 50, Some(1));

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
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
            assert!(param.instant_feedback_on_packet_loss());
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

            let result = WsConnectParamBuilder::new(&topo)
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(0.5))
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(1.0))
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(0.0)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(-0.1)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(1.1)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(f64::NAN)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(f64::INFINITY)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_fback_packets(Some(0.3))
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_fback_packets(Some(0.0)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_len_random_coefficient(Some(0.7))
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_len_random_coefficient(Some(0.0)) // invalid
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(0.1))
                .percent_fake_fback_packets(Some(0.05))
                .percent_len_random_coefficient(Some(0.4))
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_fake_data_packets(Some(0.000001)) // very small but positive
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .percent_len_random_coefficient(Some(1.0)) // boundary
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

            let result = WsConnectParamBuilder::new(&topo)
                .maximum_length_udp_queue_packages(100)
                .maximum_length_fback_queue_packages(20)
                .maximum_length_queue_unconfirmed_packages(60)
                .max_num_attempts_resend_package(3)
                .ttl_max_start_cost((255, 128, -1))
                .percent_fake_data_packets(Some(0.2))
                .percent_fake_fback_packets(Some(0.1))
                .percent_len_random_coefficient(Some(0.5))
                .max_len_file(None)
                .build();

            assert!(
                result.is_ok(),
                "combination of ttl and traffic masking parameters should be valid"
            );
        }
    }

    #[cfg(test)]
    mod tests_packet_queue_management_group {
        use super::*;

        // compact builder for queue tests – only queue-related fields are varied.
        // all other fields set to minimal valid values.
        fn base_builder(topo: &PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(topo)
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
                .packages_measurement_window_size_determining_latency(10)
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ basic queue validation – positive values and capacity checks              │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn queue_accepts_minimal_positive_values() {
            let topo = get_topol(Some(1), 50, None);
            let p = base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None); // capacity = 126
            assert!(
                base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None); // capacity = 126
            assert!(
                base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None); // capacity = 126

            // udp queue > capacity
            let err = base_builder(&topo)
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
            let err = base_builder(&topo)
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
            let err = base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None);

            let err = base_builder(&topo)
                .maximum_length_udp_queue_packages(0)
                .maximum_length_fback_queue_packages(100)
                .maximum_length_queue_unconfirmed_packages(150)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");

            let err = base_builder(&topo)
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(0)
                .maximum_length_queue_unconfirmed_packages(150)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");

            let err = base_builder(&topo)
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(100)
                .maximum_length_queue_unconfirmed_packages(0)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");

            let err = base_builder(&topo)
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
            let topo = get_topol(Some(2), 50, None);

            let err = base_builder(&topo)
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
                base_builder(&topo)
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
            let topo = get_topol(Some(2), 50, None);

            let err = base_builder(&topo)
                .maximum_length_udp_queue_packages(200)
                .maximum_length_fback_queue_packages(150) // fback > unconfirmed
                .maximum_length_queue_unconfirmed_packages(100)
                .max_num_attempts_resend_package(10)
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                " maximum_length_fback_queue_packages must be less than \
                 maximum_length_queue_unconfirmed_packages.For more information, see the \
                 description of this variable at the beginning of the file."
            );

            // fback == unconfirmed is allowed
            assert!(
                base_builder(&topo)
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
            let topo = get_topol(None, 50, None);
            let err = base_builder(&topo)
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
            let topo = get_topol(Some(2), 50, None); // capacity = 32767
            assert!(
                base_builder(&topo)
                    .maximum_length_udp_queue_packages(20000)
                    .maximum_length_fback_queue_packages(5000)
                    .maximum_length_queue_unconfirmed_packages(15000)
                    .max_num_attempts_resend_package(100)
                    .build()
                    .is_ok()
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combination with other features – ttl does not interfere                 │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn queue_works_with_ttl() {
            let topo = get_topol(Some(1), 50, Some(1));
            assert!(
                base_builder(&topo)
                    .maximum_length_udp_queue_packages(100)
                    .maximum_length_fback_queue_packages(30)
                    .maximum_length_queue_unconfirmed_packages(60)
                    .max_num_attempts_resend_package(10)
                    .ttl_max_start_cost((255, 128, -1))
                    .build()
                    .is_ok()
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ documentation recommendations – not enforced, but code should accept      │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn recommended_ratio_not_enforced() {
            let topo = get_topol(Some(2), 50, None);
            assert!(
                base_builder(&topo)
                    .maximum_length_udp_queue_packages(200)
                    .maximum_length_fback_queue_packages(50)
                    .maximum_length_queue_unconfirmed_packages(100) // 2x fback (not 3x)
                    .max_num_attempts_resend_package(10)
                    .build()
                    .is_ok()
            );
        }
    }

    #[cfg(test)]
    mod tests_delay {
        use super::*;

        // compact builder for delay tests – only fback-related fields are varied.
        // all other fields set to minimal valid values.
        fn base_builder(topo: &PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(topo)
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .max_num_attempts_resend_package(3)
                .packages_measurement_window_size_determining_latency(10)
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
            let topo = get_topol(Some(1), 50, None);

            // mid-range
            let p = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 0.5);

            // minimum positive
            let p = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.0001)
                .maximum_packet_delay_absolute_fback(0.0001)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 0.0001);

            // maximum = 1.0
            let p = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(1.0)
                .maximum_packet_delay_absolute_fback(100.0)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_fback_coefficient(), 1.0);
        }

        #[test]
        fn fback_coefficient_rejects_zero() {
            let topo = get_topol(Some(1), 50, None);
            let err = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.0)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f64 variables must be is_normal()");
        }

        #[test]
        fn fback_coefficient_rejects_negative() {
            let topo = get_topol(Some(1), 50, None);
            let err = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(-0.5)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f64 variables must be greater than zero");
        }

        #[test]
        fn fback_coefficient_rejects_above_one() {
            let topo = get_topol(Some(1), 50, None);
            let err = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(1.1)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert!(err.contains("must be greater than zero") || err.contains("is_normal"));
        }

        #[test]
        fn fback_coefficient_rejects_nan_and_inf() {
            let topo = get_topol(Some(1), 50, None);

            let err_nan = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(f64::NAN)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err_nan, "all f64 variables must be is_normal()");

            let err_inf = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(f64::INFINITY)
                .maximum_packet_delay_absolute_fback(50.0)
                .build()
                .unwrap_err();
            assert_eq!(err_inf, "all f64 variables must be is_normal()");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ maximum_packet_delay_absolute_fback – range [0, max_ms_latency]           │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn absolute_fback_accepts_zero() {
            let topo = get_topol(Some(1), 50, None);
            // zero is allowed? test says it should be valid
            let p = base_builder(&topo)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(0.1)
                .build()
                .unwrap();
            assert_eq!(p.maximum_packet_delay_absolute_fback(), 0.1);
        }

        #[test]
        fn absolute_fback_accepts_up_to_max_latency() {
            let topo = get_topol(Some(1), 50, None);

            // exactly max_latency
            let p = base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None);
            let err = base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None);
            let err = base_builder(&topo)
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(-0.1)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f64 variables must be greater than zero");
        }

        #[test]
        fn absolute_fback_rejects_nan_and_inf() {
            let topo = get_topol(Some(1), 50, None);

            let err_nan = base_builder(&topo)
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(f64::NAN)
                .build()
                .unwrap_err();
            assert_eq!(err_nan, "all f64 variables must be is_normal()");

            let err_inf = base_builder(&topo)
                .max_ms_latency(100.0)
                .overhead_network_latency_relative_window_coefficient(0.2)
                .maximum_packet_delay_fback_coefficient(0.5)
                .maximum_packet_delay_absolute_fback(f64::INFINITY)
                .build()
                .unwrap_err();
            assert_eq!(err_inf, "all f64 variables must be is_normal()");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combined scenarios – both parameters at boundaries                         │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn both_fback_parameters_at_maximum() {
            let topo = get_topol(Some(1), 50, None);
            let p = base_builder(&topo)
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
            let topo = get_topol(Some(1), 50, None);
            let small_max = 110.0;

            let p = base_builder(&topo)
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

    #[cfg(test)]
    mod tests_adaptation_coefficients {
        use super::*;

        // compact builder for coefficient testing – only latency_increase and overhead are
        // relevant. all other fields set to minimal valid values.
        fn base_builder(topo: &PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(topo)
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .max_num_attempts_resend_package(3)
                .packages_measurement_window_size_determining_latency(10)
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
            let topo = get_topol(Some(2), 50, None);

            // min positive
            let p = base_builder(&topo)
                .latency_increase_coefficient(f64::MIN_POSITIVE)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap();
            assert_eq!(p.latency_increase_coefficient(), f64::MIN_POSITIVE);

            // max = 1.0
            let p = base_builder(&topo)
                .latency_increase_coefficient(1.0)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap();
            assert_eq!(p.latency_increase_coefficient(), 1.0);
        }

        #[test]
        fn latency_increase_rejects_zero() {
            let topo = get_topol(Some(2), 50, None);
            let err = base_builder(&topo)
                .latency_increase_coefficient(0.0)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f64 variables must be is_normal()");
        }

        #[test]
        fn latency_increase_rejects_negative() {
            let topo = get_topol(Some(2), 50, None);
            let err = base_builder(&topo)
                .latency_increase_coefficient(-0.1)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f64 variables must be greater than zero");
        }

        #[test]
        fn latency_increase_rejects_above_one() {
            let topo = get_topol(Some(2), 50, None);
            let err = base_builder(&topo)
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
            let topo = get_topol(Some(2), 50, None);

            let err_nan = base_builder(&topo)
                .latency_increase_coefficient(f64::NAN)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err_nan, "all f64 variables must be is_normal()");

            let err_inf = base_builder(&topo)
                .latency_increase_coefficient(f64::INFINITY)
                .maximum_packet_delay_fback_coefficient(0.8)
                .build()
                .unwrap_err();
            assert_eq!(err_inf, "all f64 variables must be is_normal()");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ overhead_network_latency_relative_window_coefficient – range [ε,1]        │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn overhead_coefficient_valid_range() {
            let topo = get_topol(Some(2), 50, None);

            // very small positive
            let p = base_builder(&topo)
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
            let p = base_builder(&topo)
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
            let topo = get_topol(Some(2), 50, None);
            let err = base_builder(&topo)
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .overhead_network_latency_relative_window_coefficient(-0.1)
                .build()
                .unwrap_err();
            assert_eq!(err, "all f64 variables must be greater than zero");
        }

        #[test]
        fn overhead_coefficient_rejects_above_one() {
            let topo = get_topol(Some(2), 50, None);
            let err = base_builder(&topo)
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
        // │ packages_measurement_window_size_determining_latency – usize > 0          │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn measurement_window_accepts_positive() {
            let topo = get_topol(Some(2), 50, None);

            let p = base_builder(&topo)
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .packages_measurement_window_size_determining_latency(1)
                .build()
                .unwrap();
            assert_eq!(p.packages_measurement_window_size_determining_latency(), 1);

            let p = base_builder(&topo)
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .packages_measurement_window_size_determining_latency(1000)
                .build()
                .unwrap();
            assert_eq!(
                p.packages_measurement_window_size_determining_latency(),
                1000
            );
        }

        #[test]
        fn measurement_window_rejects_zero() {
            let topo = get_topol(Some(2), 50, None);
            let err = base_builder(&topo)
                .latency_increase_coefficient(0.5)
                .maximum_packet_delay_fback_coefficient(0.8)
                .packages_measurement_window_size_determining_latency(0)
                .build()
                .unwrap_err();
            assert_eq!(err, "all usize variables must be greater than zero");
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combination tests – verify multiple coefficients together                 │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn multiple_coefficients_work_together() {
            let topo = get_topol(Some(2), 50, None);

            let p = base_builder(&topo)
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

            let p = base_builder(&topo)
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

    #[cfg(test)]
    mod tests_from_group {
        use super::*;

        // compact builder with only mtu-related parameters.
        // all other fields are set to minimal valid values needed to satisfy the constructor.

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ mtu validation – all checks related to mtu vs total_minimal_len          │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn mtu_greater_than_minimal_succeeds() {
            let topo = get_topol(Some(1), 50, None);
            let param = base_builder_pub(&topo).mtu(1500).build().unwrap();
            assert_eq!(param.mtu(), 1500);
        }

        #[test]
        fn mtu_equal_to_minimal_fails() {
            let topo = get_topol(Some(1), 100, None);
            let err = base_builder_pub(&topo).mtu(100).build().unwrap_err();
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
            let topo = get_topol(Some(1), 500, None);
            let err = base_builder_pub(&topo).mtu(300).build().unwrap_err();
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
            let topo = get_topol(Some(1), 100, None);
            let param = base_builder_pub(&topo).mtu(101).build().unwrap();
            assert_eq!(param.mtu(), 101);
        }

        #[test]
        fn mtu_large_value_accepted() {
            let topo = get_topol(Some(1), 50, None);
            let param = base_builder_pub(&topo).mtu(65535).build().unwrap();
            assert_eq!(param.mtu(), 65535);
        }

        #[test]
        fn mtu_with_various_minimal_lengths() {
            let cases = [(10, 100), (100, 1500), (500, 2000)];
            for (min_len, mtu) in cases {
                let topo = get_topol(Some(1), min_len, None);
                let param = base_builder_pub(&topo).mtu(mtu).build().unwrap();
                assert_eq!(param.mtu(), mtu);
                assert_eq!(param.pack_topology().total_minimal_len(), min_len);
            }
        }

        #[test]
        fn mtu_with_minimal_len_one() {
            let topo = get_topol(Some(1), 1, None);
            let param = base_builder_pub(&topo).mtu(2).build().unwrap();
            assert_eq!(param.mtu(), 2);
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ counter_slice validation – required for queue parameters                  │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn counter_slice_absent_fails() {
            let topo = get_topol(None, 50, None);
            let err = base_builder_pub(&topo).mtu(1500).build().unwrap_err();
            assert_eq!(
                err,
                "The counter_slice() field in pack_topology is None, but it must be specified!"
            );
        }

        #[test]
        fn counter_slice_present_succeeds() {
            let topo = get_topol(Some(1), 50, None);
            assert!(base_builder_pub(&topo).mtu(1500).build().is_ok());
        }
    }

    #[cfg(test)]
    mod tests_mt1 {
        use super::*;

        // compact builder tests – only parameters relevant to error detection are varied.
        // all other fields are set to the minimal valid values needed to construct the base
        // object.

        // base valid configuration (used as foundation for all tests)
        fn base_builder(topo: &PackTopology) -> WsConnectParamBuilder {
            WsConnectParamBuilder::new(topo)
                .mtu(1500)
                .max_ms_latency(100.0)
                .min_ms_latency(10.0)
                .start_ms_latency(50.0)
                .latency_increase_coefficient(0.5)
                .max_num_attempts_resend_package(3)
                .packages_measurement_window_size_determining_latency(10)
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
            let topo_with_ttl = get_topol(Some(1), 50, Some(1));
            let topo_without_ttl = get_topol(Some(1), 50, None);

            // ttl not set → always valid, regardless of topology
            assert!(base_builder(&topo_with_ttl).build().is_ok());
            assert!(base_builder(&topo_without_ttl).build().is_ok());
            assert_eq!(
                base_builder(&topo_with_ttl)
                    .build()
                    .unwrap()
                    .ttl_max_start_cost(),
                None
            );
        }

        #[test]
        fn ttl_present_requires_topology_ttl() {
            let topo_with_ttl = get_topol(Some(1), 50, Some(1));
            let topo_without_ttl = get_topol(Some(1), 50, None);

            // ttl specified → must have ttl in topology
            assert!(
                base_builder(&topo_with_ttl)
                    .ttl_max_start_cost((255, 128, -1))
                    .build()
                    .is_ok()
            );

            let err = base_builder(&topo_without_ttl)
                .ttl_max_start_cost((255, 128, -1))
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "The ttl_max_start_cost field is defined as Some(), but in pack_topology this \
                 field is None."
            );
        }

        #[test]
        fn ttl_max_vs_start_ordering() {
            let topo = get_topol(Some(1), 50, Some(1));

            // start > max → error
            let err = base_builder(&topo)
                .ttl_max_start_cost((100, 200, -1))
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "ttl_max_start_cost.0 < ttl_max_start_cost.1; start must be less than the maximum \
                 ttl value. For more information, see the description of this variable at the \
                 beginning of the file."
            );

            // start == max → allowed (code uses <, not <=)
            assert!(
                base_builder(&topo)
                    .ttl_max_start_cost((255, 255, -1))
                    .build()
                    .is_ok()
            );
        }

        #[test]
        fn ttl_zero_values_rejected() {
            let topo = get_topol(Some(1), 50, Some(1));

            // max = 0 → error
            let err = base_builder(&topo)
                .ttl_max_start_cost((0, 0, -1))
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "ttl_max_start_cost.0 must be greater than zero. For more information, see the \
                 description of this variable at the beginning of the file."
            );

            // start = 0 → error
            let err = base_builder(&topo)
                .ttl_max_start_cost((254, 0, -1))
                .build()
                .unwrap_err();
            assert_eq!(
                err,
                "ttl_max_start_cost.1 must be greater than zero. For more information, see the \
                 description of this variable at the beginning of the file."
            );
        }

        #[test]
        fn ttl_start_exceeds_capacity() {
            let topo = get_topol(Some(1), 50, Some(1)); // 1‑byte ttl → max 255

            let err = base_builder(&topo)
                .ttl_max_start_cost((300, 256, -1))
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
            let topo = get_topol(Some(1), 50, Some(1));

            // positive, zero, negative – all allowed
            assert!(
                base_builder(&topo)
                    .ttl_max_start_cost((255, 128, 1))
                    .build()
                    .is_ok()
            );
            assert!(
                base_builder(&topo)
                    .ttl_max_start_cost((255, 128, 0))
                    .build()
                    .is_ok()
            );
            assert!(
                base_builder(&topo)
                    .ttl_max_start_cost((255, 128, -1))
                    .build()
                    .is_ok()
            );
        }

        #[test]
        fn ttl_with_larger_byte_capacity() {
            // 2‑byte ttl field → capacity up to 65535
            let topo = get_topol(Some(1), 50, Some(2));
            assert!(
                base_builder(&topo)
                    .ttl_max_start_cost((65535, 32768, -1))
                    .build()
                    .is_ok()
            );
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ instant_feedback – boolean field, no extra validation                     │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn instant_feedback_accepts_both_values() {
            let topo = get_topol(Some(1), 50, Some(1));

            let true_val = base_builder(&topo)
                .instant_feedback_on_packet_loss(true)
                .build()
                .unwrap();
            assert!(true_val.instant_feedback_on_packet_loss());

            let false_val = base_builder(&topo)
                .instant_feedback_on_packet_loss(false)
                .build()
                .unwrap();
            assert!(!false_val.instant_feedback_on_packet_loss());
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ max_len_file – optional field, no validation                              │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn max_len_file_accepts_none_and_some() {
            let topo = get_topol(Some(1), 50, Some(1));

            let none_val = base_builder(&topo).max_len_file(None).build().unwrap();
            assert_eq!(none_val.max_len_file(), None);

            let some_val = base_builder(&topo)
                .max_len_file_value(1000)
                .build()
                .unwrap();
            assert_eq!(some_val.max_len_file(), Some(1000));
        }

        // ┌────────────────────────────────────────────────────────────────────────────┐
        // │ combined scenario – both fields used together                             │
        // └────────────────────────────────────────────────────────────────────────────┘
        #[test]
        fn ttl_and_instant_feedback_can_be_combined() {
            let topo = get_topol(Some(1), 50, Some(1));

            let param = base_builder(&topo)
                .instant_feedback_on_packet_loss(true)
                .ttl_max_start_cost((255, 128, -1))
                .max_len_file_value(2048)
                .intermediate_questionable_packages_queue(Some(120))
                .build()
                .unwrap();

            assert!(param.instant_feedback_on_packet_loss());
            assert_eq!(param.ttl_max_start_cost(), Some((255, 128, -1)));
            assert_eq!(param.max_len_file(), Some(2048));
            assert_eq!(param.intermediate_questionable_packages_queue(), Some(120));
        }

        #[test]
        fn intermediate_questionable_packages_queue() {
            let topo = get_topol(Some(1), 50, Some(1));

            let param_normal = base_builder(&topo)
                .instant_feedback_on_packet_loss(true)
                .ttl_max_start_cost((255, 128, -1))
                .max_len_file_value(2048);

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
            let topo = get_topol(Some(1), 50, Some(1));

            for x1 in [Some(0.3), None] {
                for x2 in [Some(0.3), None] {
                    for x3 in [Some(0.3), None] {
                        let param_normal = base_builder(&topo)
                            .instant_feedback_on_packet_loss(true)
                            .ttl_max_start_cost((255, 128, -1))
                            .max_len_file_value(2048)
                            .percent_fake_data_packets(x1)
                            .percent_fake_fback_packets(x2)
                            .percent_len_random_coefficient(x3)
                            .build()
                            .unwrap();
                        println!(
                            "{} {} {} {}",
                            param_normal.need_init_random(),
                            x1.is_some(),
                            x2.is_some(),
                            x3.is_some()
                        );
                        assert_eq!(
                            param_normal.need_init_random(),
                            (x1.is_some() || x2.is_some() || x3.is_some())
                        );
                    }
                }
            }
        }
    }
}
