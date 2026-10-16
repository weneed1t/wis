//Gaoo~~~ :3
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::as_conversions)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::integer_division)]
//#![deny(clippy::expect_used)]
#![deny(clippy::unreachable)]
#![deny(clippy::todo)]
#![deny(clippy::float_cmp)]
#![forbid(unsafe_code)]
use std::cmp;

use crate::t1queues::WSFbackQueue;
use crate::w1types::{PackScheme, Ttl};
use crate::w1utils::float_to_u32_scaled;

use crate::{EXPCP, checked_cast, w1utils};

/// for WsConnectParam
#[derive(Debug, PartialEq, Clone)]
pub struct RandConfig {
    /// for WsConnectParam
    pub percent_fake_any_packets: Option<u32>,
    /// for WsConnectParam
    pub length_trimming_range: Option<usize>,
}

impl RandConfig {
    /// for WsConnectParam
    pub fn need_use_random(&self) -> bool {
        self.percent_fake_any_packets.is_some() || self.length_trimming_range.is_some()
    }
}

#[derive(Debug, PartialEq, Clone)]
///no cm
pub struct NeedyParam {
    ///no cm
    pub absolute_maximal_overhead: usize,
    ///no cm
    pub absolute_maximal_fback_overhead: usize,
    ///no cm
    pub counter_slice_len: usize,
    ///no cm
    pub ttl_slice_len: Option<usize>,
}

/// (absolute_maximal_len_in_sheme,absolute_maximal_len_in_sheme_only_fback, counter_slice_len, ttl_len_slice)
pub fn get_max_len_ctr_len_ttl_len_opt(scheme: PackScheme) -> Result<NeedyParam, String> {
    Ok(match scheme {
        PackScheme::GroupPack(x) => {
            let counter_slice_len = x.all_have_counter_field().ok_or("PackScheme::GroupPack x.all_have_counter_field() == None; for this algorithm to work, all package topologies must have a counter field!")?;

            if !counter_slice_len.0 {
                return Err(
                    "PackScheme::GroupPack x.all_have_counter_field() == some(false, size), false ->; for this algorithm to work, all package topologies must have a counter field!".to_string(),
                );
            }

            NeedyParam {
                absolute_maximal_overhead: cmp::max(
                    x.data_max_minimal_len(),
                    x.fback_max_minimal_len(),
                ),
                absolute_maximal_fback_overhead: x.fback_max_minimal_len(),
                counter_slice_len: counter_slice_len.1,
                ttl_slice_len: x.all_have_ttl_field().map(|(_, third)| third),
            }
        },
        PackScheme::OnePack(x) => NeedyParam {
            absolute_maximal_overhead: x.overhead_len(),
            absolute_maximal_fback_overhead: x.overhead_len(), //the zeroth and first values ​​of the tuple are the same, since the same topology is used for data and fback
            counter_slice_len: x
                .counter_slice()
                .ok_or(
                    "The counter_slice() field in pack_topology is None, but it must be \
                         specified!",
                )?
                .2,
            ttl_slice_len: x.ttl_slice().map(|(_, _, third)| third),
        },
    })
}

#[derive(Debug, PartialEq, Clone)]
///static algorithm settings that do not change—in other words, constants
pub struct WsConnectParam {
    scheme: PackScheme,
    mtu: usize,
    min_ms_latency: f32,
    max_ms_latency: f32,
    start_ms_latency: f32,
    latency_increase_coefficient: f32,
    max_num_attempts_resend_package: usize,
    overhead_network_latency_relative_window_coefficient: f32,
    maximum_packet_delay_fback_coefficient: f32,
    maximum_packet_delay_absolute_fback: f32,
    ttl: Option<Ttl>,
    maximum_length_udp_queue_packages: usize,
    maximum_length_fback_queue_packages: usize,
    maximum_length_queue_unconfirmed_packages: usize,
    instant_feedback_on_packet_loss: bool,
    ctr_max_capacity_real: u64,
    max_len_file: Option<usize>,
    intermediate_questionable_packages_queue: Option<usize>,
    need_use_random: RandConfig,
}

impl WsConnectParam {
    ///<h2>Each variable is described in detail at the beginning of this file. Open the
    /// beginning of the file and read what is written there to avoid mistakes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scheme: PackScheme,
        mtu: usize,
        instant_feedback_on_packet_loss: bool,
        //packages_measurement_window_size_determining_latency: usize,
        /*
        // Queue size relationships:
        // - maximum_length_fback_queue_packages < maximum_length_queue_unconfirmed_packages <= maximum_length_udp_queue_packages
        // - All three are bounded by the counter capacity (ctr_max_capacity_real_usize) derived from the packet topology.
        // - maximum_length_fback_queue_packages is further limited by the Fback receive buffer size, which depends on MTU.
        // - intermediate_questionable_packages_queue, if provided, must be > 0 and also ≤ the counter capacity.
         */
        maximum_length_udp_queue_packages: usize,
        maximum_length_fback_queue_packages: usize,
        maximum_length_queue_unconfirmed_packages: usize,
        max_num_attempts_resend_package: usize,
        max_ms_latency: f32,   //>0
        min_ms_latency: f32,   //>0
        start_ms_latency: f32, //>0
        latency_increase_coefficient: f32,
        overhead_network_latency_relative_window_coefficient: f32,
        maximum_packet_delay_fback_coefficient: f32,
        maximum_packet_delay_absolute_fback: f32,
        ttl: Option<Ttl>,
        //rands
        percent_fake_any_packets: Option<f32>,
        length_trimming_range: Option<usize>,
        //rands
        max_len_file: Option<usize>,
        intermediate_questionable_packages_queue: Option<usize>,
    ) -> Result<Self, String> {
        let needy_param = get_max_len_ctr_len_ttl_len_opt(scheme.clone())?;

        if needy_param.absolute_maximal_overhead >= mtu {
            return Err(
                "pack_topology.total_minimal_len() > mtu mtu must be significantly larger than \
                 pack_topology.total_minimal_len(). Since pack_topology.total_minimal_len() is \
                 the minimum packet length, such a packet contains only protocol service \
                 information, mtu must be large enough to accommodate the length of the packet's \
                 useful data and service data."
                    .to_string(),
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
            return Err("all f32 variables must be is_normal()".to_string());
        }
        if (min_ms_latency <= 0.0)
            || (max_ms_latency <= 0.0)
            || (start_ms_latency <= 0.0)
            || (latency_increase_coefficient <= 0.0)
            || (maximum_packet_delay_absolute_fback < 0.0)
            || (overhead_network_latency_relative_window_coefficient < 0.0)
            || (maximum_packet_delay_fback_coefficient <= 0.0)
        {
            return Err("all f32 variables must be greater than zero".to_string());
        }

        if (maximum_length_udp_queue_packages < 1)
            || (maximum_length_fback_queue_packages < 1)
            || (maximum_length_queue_unconfirmed_packages < 1)
            //|| (packages_measurement_window_size_determining_latency < 1)
            || (max_num_attempts_resend_package < 1)
        {
            return Err("all usize variables must be greater than zero".to_string());
        }

        if (latency_increase_coefficient > 1.0)
            || (overhead_network_latency_relative_window_coefficient > 1.0)
            || (maximum_packet_delay_fback_coefficient > 1.0)
        {
            return Err("latency_increase_coefficient \
                        overhead_network_latency_relative_window_coefficient \
                        maximum_packet_delay_fback_coefficient must be greater than zero"
                .to_string());
        }

        //latency check
        {
            if min_ms_latency > max_ms_latency {
                return Err(
                    "min_ms_latency > max_ms_latency The minimum start_ms_latency < \
                     min_ms_latency must be less than or equal to the maximum latency."
                        .to_string(),
                );
            }

            if start_ms_latency > max_ms_latency {
                return Err(
                    "start_ms_latency > max_ms_latency The start latency must be less than or \
                     equal to the maximum."
                        .to_string(),
                );
            }

            if start_ms_latency < min_ms_latency {
                return Err(
                    "start_ms_latency < min_ms_latency The start latency  must be greater than or \
                     equal to the minimum."
                        .to_string(),
                );
            }
        }

        let (ctr_max_capacity_real, ctr_max_capacity_real_usize) = {
            let ctr_max_capacity =
                w1utils::len_byte_maximal_capacity_check(needy_param.counter_slice_len);
            //See the description of the pub fn set_counter function in the pub mod t1fields file
            // to understand why this logic for obtaining maximum capacity is used here.
            let ctr_max_capacity_real = EXPCP!(
                (ctr_max_capacity.0 >> 1).checked_sub(1),
                "(ctr_max_capacity.0 >> 1) - 1 < 0 error, impossible behavior, since the minimum \
                 length of counter_slice() is 1, 1 byte is 255 maximum value, 255 >>1 - 127, 127 \
                 is greater than 1."
            );

            let ctr_max_capacity_real_usize = checked_cast!(ctr_max_capacity_real => usize, err "ctr_max_capacity_real conversion to usize failed")?;

            if maximum_length_udp_queue_packages > ctr_max_capacity_real_usize {
                return Err(
                    " maximum_length_udp_queue_packages must be less than the maximum capacity of \
                     the pack_topology.counter_slice() field. "
                        .to_string(),
                );
            }
            if maximum_length_udp_queue_packages < maximum_length_queue_unconfirmed_packages {
                return Err(" maximum_length_udp_queue_packages must be greater than \
                            maximum_length_queue_unconfirmed_packages so that all packets are \
                            confirmed. For more information, see the description of this \
                            variable at the beginning of the file."
                    .to_string());
            }

            if maximum_length_fback_queue_packages > ctr_max_capacity_real_usize {
                return Err(
                    "maximum_length_fback_queue_packages must not exceed the maximum capacity of \
                     the pack_topology.counter_slice() counter. "
                        .to_string(),
                );
            }

            let max_fback_for_recv_len_buff = WSFbackQueue::<f32>::max_len_from_mtu(
                //bool bool is a placeholder type in this situation and is not used to calculate maximum capacity.
                needy_param.counter_slice_len,
                mtu.checked_sub(needy_param.absolute_maximal_fback_overhead)
                    .ok_or("mtu - absolute_maximal_len_in_sheme_only_fback < 0!")?,
            )
            .map_err(|x| {
                format!(
                    "err: mtu - (absolute_maximal_fback_overhead + TIME_MARK_L) in 
             WSFbackQueue::<bool>::max_len_from_mtu :\n{}\n",
                    x
                )
            })?;

            if maximum_length_fback_queue_packages > max_fback_for_recv_len_buff {
                return Err(
                    "maximum_length_fback_queue_packages is greater than the Fback packet buffer can accommodate.".to_string(),
                );
            }

            if max_num_attempts_resend_package > ctr_max_capacity_real_usize {
                return Err(
                    "max_num_attempts_resend_package > ctr_max_capacity_real as usize.  \
                     max_num_attempts_resend_package must be less than the maximum possible \
                     capacity in pack_topology.counter_slice()."
                        .to_string(),
                );
            }
            (ctr_max_capacity_real, ctr_max_capacity_real_usize)
        };

        if maximum_packet_delay_absolute_fback > max_ms_latency {
            return Err(
                "The variable maximum_packet_delay_absolute_fback must be no greater than \
                 max_ms_latency For more information, see the description of this variable at the \
                 beginning of the file."
                    .to_string(),
            );
        }

        //0 xor 0 == 0
        //1 xor 1 == 0
        //If something is certain and something is not certain, an error is thrown.
        if ttl.is_some() ^ needy_param.ttl_slice_len.is_some() {
            return Err(
                "ttl_len_slice or ttl_max_start_cost is none, and ttl_len_slice or ttl_max_start_cost is some, either remove the ttl field in the packets or define ttl values ttl_max_start_cost".to_string(),
            );
        }

        //ttl
        if let Some(ttl_me) = ttl {
            if let Some(ttl_in_topology) = needy_param.ttl_slice_len {
                let max_cap = w1utils::len_byte_maximal_capacity_check(ttl_in_topology);

                if ttl_me.max() > max_cap.0 {
                    return Err(
                        "ttl_max_start_cost.1 is greater than the length that can be accommodated \
                         in the pack_topology field."
                            .to_string(),
                    );
                }
            } else {
                return Err("The ttl_max_start_cost field is defined as Some(), but in \
                            pack_topology this field is None."
                    .to_string());
            }
        }

        if maximum_length_fback_queue_packages > maximum_length_queue_unconfirmed_packages {
            return Err("maximum_length_fback_queue_packages must be less than \
                        maximum_length_queue_unconfirmed_packages.For more information, see the \
                        description of this variable at the beginning of the file."
                .to_string());
        }
        //percent

        if let Some(x) = percent_fake_any_packets
            && (!x.is_normal() || x > 1.0 || x <= 0.0)
        {
            return Err(
                "percent_fake_any_packets must be in the range from (0.0 to 1.0]".to_string(),
            );
        }

        if let Some(x) = length_trimming_range
            && ((x > mtu) || (x < 1))
        {
            return Err("length_trimming_range must be in the range from 1 to mtu".to_string());
        }

        if let Some(xxx) = intermediate_questionable_packages_queue {
            if xxx == 0 {
                return Err(
                    "intermediate_questionable_packages_queue is Some(0), but Some(the value must \
                     be greater than zero) "
                        .to_string(),
                );
            }

            if ctr_max_capacity_real_usize < xxx {
                return Err("Some(intermediate_questionable_packages_queue) > \
                            ctr_max_capacity_real, The maximum value that the counter field in \
                            the packet topology can hold must be GREATER than \
                            intermediate_questionable_packages_queue."
                    .to_string());
            }
        }

        fn none_or_some_f32_as_u32(num: Option<f32>) -> Result<Option<u32>, String> {
            num.map(float_to_u32_scaled).transpose()
        }

        debug_assert!(
            needy_param.absolute_maximal_overhead < mtu,
            "ABS_nedep: {:?} \nmtu{}",
            needy_param,
            mtu
        );

        debug_assert!(
            needy_param.absolute_maximal_fback_overhead < mtu,
            "F_nedep: {:?} \nmtu{}",
            needy_param,
            mtu
        );

        Ok(Self {
            scheme,
            /**/
            mtu,
            /**/                                                  //
            max_ms_latency,                  //
            min_ms_latency,                  //
            start_ms_latency,                //
            latency_increase_coefficient,    //
            max_num_attempts_resend_package, //
            //packages_measurement_window_size_determining_latency, //
            overhead_network_latency_relative_window_coefficient, //
            /**/
            maximum_packet_delay_fback_coefficient, //
            maximum_packet_delay_absolute_fback,
            /**/
            ttl, //
            /**/
            maximum_length_udp_queue_packages,         //
            maximum_length_fback_queue_packages,       //
            maximum_length_queue_unconfirmed_packages, //
            /**/
            ctr_max_capacity_real,
            instant_feedback_on_packet_loss,
            max_len_file,
            intermediate_questionable_packages_queue,
            need_use_random: RandConfig {
                percent_fake_any_packets: none_or_some_f32_as_u32(percent_fake_any_packets)?,
                length_trimming_range,
            },
        })
    }
}

///interface
impl WsConnectParam {
    ///returns the corresponding value
    pub fn sheme(&self) -> &PackScheme {
        &self.scheme
    }
    ///returns the corresponding value
    pub fn mtu(&self) -> usize {
        self.mtu
    }
    ///returns the corresponding value
    pub fn max_ms_latency(&self) -> f32 {
        self.max_ms_latency
    }
    ///returns the corresponding value
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
    ///returns the corresponding value
    pub fn need_init_random(&self) -> bool {
        self.need_use_random.need_use_random()
    }
    ///returns the corresponding value
    pub fn min_ms_latency(&self) -> f32 {
        self.min_ms_latency
    }
    ///returns the corresponding value
    pub fn start_ms_latency(&self) -> f32 {
        self.start_ms_latency
    }
    ///returns the corresponding value
    pub fn latency_increase_coefficient(&self) -> f32 {
        self.latency_increase_coefficient
    }
    ///returns the corresponding value
    pub fn max_num_attempts_resend_package(&self) -> usize {
        self.max_num_attempts_resend_package
    }
    // ///returns the corresponding value
    //pub fn packages_measurement_window_size_determining_latency(&self) -> usize {
    //    self.packages_measurement_window_size_determining_latency
    //}
    ///returns the corresponding value
    pub fn overhead_network_latency_relative_window_coefficient(&self) -> f32 {
        self.overhead_network_latency_relative_window_coefficient
    }
    ///returns the corresponding value
    pub fn maximum_packet_delay_fback_coefficient(&self) -> f32 {
        self.maximum_packet_delay_fback_coefficient
    }
    ///returns the corresponding value
    pub fn maximum_packet_delay_absolute_fback(&self) -> f32 {
        self.maximum_packet_delay_absolute_fback
    }
    ///returns the corresponding value
    pub fn ttl_max_start_cost(&self) -> Option<Ttl> {
        self.ttl
    }
    ///returns the corresponding value
    pub fn maximum_length_udp_queue_packages(&self) -> usize {
        self.maximum_length_udp_queue_packages
    }
    ///returns the corresponding value
    pub fn maximum_length_fback_queue_packages(&self) -> usize {
        self.maximum_length_fback_queue_packages
    }
    ///returns the corresponding value
    pub fn maximum_length_queue_unconfirmed_packages(&self) -> usize {
        self.maximum_length_queue_unconfirmed_packages
    }
    ///returns the corresponding value
    //    pub fn percent_fake_any_packets(&self) -> Option<u32> {
    //        self.percent_fake_any_packets
    //    }
    ///returns the corresponding value
    pub fn percent_fake_any_packets(&self) -> Option<u32> {
        self.need_use_random.percent_fake_any_packets
    }
    ///returns the corresponding value
    pub fn length_trimming_range(&self) -> Option<usize> {
        self.need_use_random.length_trimming_range
    }
    ///returns the corresponding value
    pub fn instant_feedback_on_packet_loss(&self) -> bool {
        self.instant_feedback_on_packet_loss
    }
    ///returns the corresponding value
    pub fn max_len_file(&self) -> Option<usize> {
        self.max_len_file
    }
}

/// A builder for `WsConnectParam` that follows the consuming (owned) pattern.

#[derive(Debug, Clone)]
pub struct WsConnectParamBuilder {
    // Required field (no default)
    scheme: PackScheme,

    // Fields with explicit defaults (from the problem statement)
    mtu: usize,
    instant_feedback_on_packet_loss: bool,
    // packages_measurement_window_size_determining_latency: usize,
    max_ms_latency: f32,
    min_ms_latency: f32,
    start_ms_latency: f32,
    latency_increase_coefficient: f32,
    overhead_network_latency_relative_window_coefficient: f32,
    maximum_packet_delay_fback_coefficient: f32,
    maximum_packet_delay_absolute_fback: f32,

    // Fields with no defaults → must be set by the user
    maximum_length_udp_queue_packages: Option<usize>,
    maximum_length_fback_queue_packages: Option<usize>,
    maximum_length_queue_unconfirmed_packages: Option<usize>,
    max_num_attempts_resend_package: Option<usize>,

    // Optional fields (default = None)
    ttl_max_start_cost: Option<Ttl>, /* double Option trick to distinguish
                                      * unset vs None */

    percent_fake_any_packets: Option<f32>,
    length_trimming_range: Option<usize>,
    intermediate_questionable_packages_queue: Option<usize>,
    max_len_file: Option<Option<usize>>, // default is Some(10*1024*1024)
}

impl WsConnectParamBuilder {
    #[cfg(test)]
    ///for test only
    pub fn for_test_ttl_max_start_cost(&mut self, tttl: Option<Ttl>) {
        self.ttl_max_start_cost = tttl
    }
}
impl WsConnectParamBuilder {
    /// Creates a new builder with the mandatory `pack_topology` and all defaults applied.
    pub fn new(scheme: PackScheme) -> Self {
        Self {
            scheme,
            // Default values from the problem statement
            mtu: 1400,
            instant_feedback_on_packet_loss: false,
            // packages_measurement_window_size_determining_latency: 10,
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
            ttl_max_start_cost: None,
            percent_fake_any_packets: None,
            length_trimming_range: None,
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
    ///# deprecated !
    ///### The entire description of packages_measurement_window_size_determining_latency is correct,
    ///### but now packages_measurement_window_size_determining_latency is always equal to 1,
    ///###  since the Fback parcel only transmits the delay of the last packet, in order to save space and reduce the Fback packet size.
    ///The connection dynamically changes the latency time.</br>
    ///  To do this, it calculates the average latency of</br>
    ///  the last packages_measurement_window_size_determining_latency packets.</br>
    ///  The smaller this number is,</br>
    ///  the faster the algorithm will respond to changes in latency.</br>
    ///not related to other parameters, the lower the value, the more the adjustment will
    /// occur while waiting for confirmation
    pub fn packages1_measurement_window_size_determining_latency(self, _value: usize) -> Self {
        panic!("packages_measurement_window_size_determining_latency # deprecated ! read  doc");
        //self.packages_measurement_window_size_determining_latency = value;
        //self
    }
    //
    ///After sending the packet, the sender waits for a certain amount of time X.</br>
    ///  If no confirmation is received within the specified time X,</br>
    ///  the waiting time X is increased by the latency_increase_coefficient coefficient.
    /// X = X+X*latency_increase_coefficient</br>  The value of X changes dynamically
    /// during the operation of the algorithm,</br>  and the values of max_ms_latency
    /// and min_ms_latency</br>  limit its limits so that the sender does not wait
    /// forever or wait 0.0 ms.</br>
    pub fn max_ms_latency(mut self, value: f32) -> Self {
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
    pub fn min_ms_latency(mut self, value: f32) -> Self {
        self.min_ms_latency = value;
        self
    }
    ///see description max_ms_latency ^^^ +</br></br>
    /// initial latency must be between max_ms_latency: f32 and min_ms_latency: f32,</br>
    pub fn start_ms_latency(mut self, value: f32) -> Self {
        self.start_ms_latency = value;
        self
    }
    //
    ///see description max_ms_latency ^^^+</br></br>
    ///  if confirmation of the packet has not arrived within the waiting time X,</br>
    ///  the packet is sent again,</br>
    ///  and the waiting time for confirmation of this packet is set to this value</br>
    /// 1.0 >= latency_increase_coefficient >0
    pub fn latency_increase_coefficient(mut self, value: f32) -> Self {
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
    pub fn overhead_network_latency_relative_window_coefficient(mut self, value: f32) -> Self {
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
    pub fn maximum_packet_delay_fback_coefficient(mut self, value: f32) -> Self {
        self.maximum_packet_delay_fback_coefficient = value;
        self
    }
    //
    ///see description maximum_packet_delay_fback_coefficient ^^^
    ///This is the maximum absolute value that the fback packet will wait before being
    /// sent. The value must be between 0 and max_ms_latency.
    pub fn maximum_packet_delay_absolute_fback(mut self, value: f32) -> Self {
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
    ///maximum_length_fback_queue_packages is a value used in WSFbackQueue.</br>
    ///  For more information, see WSFbackQueue API. Brief information.</br>
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
    pub fn ttl_max_start_cost(mut self, value: Ttl) -> Self {
        self.ttl_max_start_cost = Some(value);
        self
    }
    //
    ///percent_fake_any_packets can be in  0 > && <= 1.0.
    ///  It is needed so that the protocol sends fake packets to make it difficult for
    /// traffic censorship  tools to detect them. When creating a useful packet,
    /// there is a chance that a packet of  junk  will appear with the
    pub fn percent_fake_any_packets(mut self, value: Option<f32>) -> Self {
        self.percent_fake_any_packets = value;
        self
    }

    /*
    ///length_trimming_range is needed to randomize the length to which packets
    /// will be cut,<br><br>  for example, file length = 1000 bytes, your network's
    /// MTU = 100 bytes,<br>  the packet's working fields occupy 20 bytes, then to
    /// transfer the file,<br>  you need 12 full packets of 100 bytes (20 bytes of
    /// service bytes  + 80 useful bytes)<br>  and 1 packet of 60 bytes (20 service
    /// bytes + 40 useful bytes).<br>  If the value of length_trimming_range
    /// Some(1.0>= x > 0.0) is,<br>  for example, 0.3, then the packet length will not
    /// be 100 bytes,<br>  but 100-20 (MTU - minimum packet size) * 0.3 = 24.<br>
    ///  Each packet will have a length from 20+24 to MTU.<br>
     */
    ///Fuck, I'm sick of thinking about how this number will be used,<br>
    ///since fucking Rust doesn't have normal, fast, safe f32-to-usize conversions.<br><br>
    ///
    ///### HOW EXACTLY THIS NUMBER WILL WORK, SEE w1utils.rs::fuck_coeff_of_rand_pack_trim
    pub fn length_trimming_range(mut self, value: Option<usize>) -> Self {
        self.length_trimming_range = value;
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
    /// Special handling for max_len_file (default is Some(...))
    pub fn max_len_file(mut self, value: Option<usize>) -> Self {
        self.max_len_file = Some(value);
        self
    }

    /// Consumes the builder and creates a `WsConnectParam` after validating that all
    /// required fields have been set.
    pub fn build(self) -> Result<WsConnectParam, String> {
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
        let ttl = self.ttl_max_start_cost;

        let max_len_file = self.max_len_file.unwrap_or(Some(10 * 1024 * 1024)); // final fallback

        let intermediate_questionable_packages_queue =
            self.intermediate_questionable_packages_queue;

        // Now call the original constructor
        WsConnectParam::new(
            self.scheme,
            self.mtu,
            self.instant_feedback_on_packet_loss,
            //self.packages_measurement_window_size_determining_latency,
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
            ttl,
            self.percent_fake_any_packets,
            self.length_trimming_range,
            max_len_file,
            intermediate_questionable_packages_queue,
        )
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
