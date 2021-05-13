use super::{JammerStateBasic, StateParameters};
use crate::jambler::{hardware_traits::JamblerRestrictedTimer, state::IntervalTimerRequirements};
use crate::jambler::state::StateMessage;
use crate::jambler::JamblerState;
use crate::jambler::StateReturn;
use heapless::{Vec};

use heapless::pool::singleton::{Box, Pool};

// TODO for using the pdu buffer
use crate::jambler::{PDU, PDU_SIZE};

//use super::super::util::TimeStamp;

use super::super::{BlePhy, JamblerRadio};
use super::JammerState;

//use rtt_target::rprintln;

/// A struct holding all relevant information regarding a harvested packet
/// necessary for recovering the connection parameters.
/// TODO HAS TO BE AS SMALL AS POSSIBLE IS COPIED COUPLE OF TIMES TO RETURN TASK
pub struct HarvestedSubEvent {
    /// Channel the packet was caught on
    pub channel: u8,
    /// The system time the packet was caught on in milliseconds.
    pub time: u64,
    /// The time listened on this channel before the packet was caught,
    pub time_on_the_channel: u32,
    /// packet
    pub packet: HarvestedPacket,
    /// response
    pub response: Option<HarvestedPacket>,
}

/// Implementing display for it because it is very necessary for debugging
impl core::fmt::Display for HarvestedSubEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let time = self.time;
        let time_on_the_channel = self.time_on_the_channel as u64;
        match &self.response {
            Some(response) => {
                write!(f, "\nReceived full subevent on channel {} at {} after listening for {} on it:\nMaster{}\nSlave{}\n", self.channel, time, time_on_the_channel, self.packet, response)
            }
            None => {
                write!(f, "\nReceived partial subevent on channel {} at {} after listening for {} on it:\nPacket{}\n", self.channel, time, time_on_the_channel, self.packet)
            }
        }
    }
}

impl core::fmt::Debug for HarvestedSubEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

/// A harvested packet
pub struct HarvestedPacket {
    pub pdu: Box<PDU>,
    pub phy: BlePhy,
    pub crc: u32,
    pub rssi: i8,
}

impl core::fmt::Display for HarvestedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let three_byte_header: bool = self.pdu[0] & 0b0010_0000 != 0;
        if three_byte_header {
            write!(
                f,
                "\n|         Header      | ... Payload ... |   CRC   |  RSSI   | PHY
                       \n|{:08b} {:3} {:08b}| ...{:3} bytes... | 0x{:06X}| {:>4}dBm | {:?}
                       ",
                self.pdu[0], self.pdu[1], self.pdu[2], self.pdu[1], self.crc, self.rssi, self.phy
            )
        } else {
            write!(
                f,
                "\n|   Header   | ... Payload ... |   CRC   |  RSSI   | PHY
                       \n|{:08b} {:3}| ...{:3} bytes... | 0x{:06X}| {:>4}dBm | {:?}
                       ",
                self.pdu[0], self.pdu[1], self.pdu[1], self.crc, self.rssi, self.phy
            )
        }
    }
}

impl core::fmt::Debug for HarvestedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

// TODO IMPORTANT, DO NOT ACCEPT THE REVERSED CRC AT ONCE!!! IT MIGHT HAVE BEEN WRONG BECAUSE OF BIT FLIPS ON AIR! CHECK IT MULTIPLE TIMES! TO REVERSE YOU NEED THE WHOLE PDU + CRC. SO INCLUDING THE HEADER

/// A struct representing the state for harvesting packets of a given access address.
#[derive(Debug)]
pub struct HarvestPackets {
    /// The access address to be listening for.
    access_address: u32,
    /// The PHY the sniffer is listening to
    phy: BlePhy,
    /// The PHY of the slave
    slave_phy: BlePhy,
    /// The channels the listener will listen for.
    /// Must not be empty and all elements must be between 0 and 37.
    channel_chain: Vec<u8, 64>,
    /// The current minimum connection interval in microseconds.
    /// Must be a multiple of 1.25 ms (1250 micros), between 7.5 milliseconds and 4 seconds.
    current_min_conn_interval: u32,
    /// The number of intervals the sniffer is supposed to listen on 1 channel before changing channels.
    number_of_intervals: u8,
    // Current channel (index into channel chain).
    // Must always be a legal index for channel chain.
    current_channel: usize,
    /// The crc init value, used for the connection, if recovered already.
    /// 24-bit
    crc_init: Option<u32>,
    /// The start time of listinening on the current channel
    start_time_current_channel: u64,
    /// The clock drift in ppm of the interval timer.
    interval_timer_ppm: u32,
    /// The clock drift in ppm of the long term timer which provides the current_time in the parameters.
    long_term_timer_ppm: u32,
    /// an indicator necessary for flagging the interval timer interrupt we have to change to timer to periodic, as we will have used a countdown to reuse the time we were already listening on that channel!
    request_periodic_timer_on_next_interval_timer_interrupt: bool,
    /// a cache so we do not need to recalculate with floats on every interval timer interrupt
    time_on_one_channel_cache: u32,
    /// A box for our static pseudo heap to keep the packet in.
    /// A pointer (mutable reference) to this will be provided to jamblerhal to fill it.
    first_caught_packet: Box<PDU>,
    /// Another buffer for the jamblerhal to write the possibly second packet in an event to
    second_caught_packet: Box<PDU>,
}

impl HarvestPackets {
    /// Calculates the worst case interval in microseconds to wait for with the window widening specified in the specification.
    /// See specification page 2930
    #[inline]
    fn calculate_receiving_interval(&self) -> u32 {
        // The theoretical perfect case
        let mut total_time = self.current_min_conn_interval * self.number_of_intervals as u32;

        // Add other side worst case (500ppm sleep clock accuracy) clock drift
        total_time += (total_time as f32 * (500_f32 / 1_000_000_f32)) as u32 + 1;

        // Add the instant tolerance worst case (2 for active, 16 for sleep)
        total_time += 16;

        // Add range delay = 2*D*4 nanoseconds with D the distance in meters
        // This is 24 microseconds for 3km distance
        total_time += 24;

        // Add my own worst case interval timer clock accuracy
        total_time +=
            (total_time as f32 * (self.interval_timer_ppm as f32 / 1_000_000_f32)) as u32 + 1;

        total_time
    }

    /// Lets the radio listen on the next channel.
    /// Return true if the channel chain was completed and wrapped.
    #[inline]
    fn next_channel(&mut self, radio: &mut impl JamblerRadio, current_time: u64) -> bool {
        let old_channel = self.channel_chain[self.current_channel];

        // Change channel
        // Could do modulo, but I think it is very slow so I do it this way
        self.current_channel += 1;
        let wrapped;
        // Wrap around chain when necessary
        if self.current_channel >= self.channel_chain.len() {
            self.current_channel = 0;
            wrapped = true;
        } else {
            wrapped = false;
        }

        // reconfigure the radio channel
        let channel = self.channel_chain[self.current_channel];

        radio.prepare_for_config_change();
        // Config the radio
        radio.harvest_packets_quick_config(
            self.access_address,
            self.phy,
            channel,
            self.crc_init,
            &mut self.first_caught_packet,
        );
        radio.receive();

        // set the start time to the new channel
        self.start_time_current_channel = current_time;

        //rprintln!("Changing channel {}->{}.", old_channel, channel);

        wrapped
    }
}

impl Default for HarvestPackets {
    fn default() -> Self {
        HarvestPackets {
            // Dummy address is the advertising access address.
            access_address: 0x8E89BED6,
            phy: BlePhy::Uncoded1M,
            slave_phy: BlePhy::Uncoded1M,
            channel_chain: Vec::new(),
            current_min_conn_interval: 4_000_000,
            number_of_intervals: 100,
            current_channel: 0,
            crc_init: None,
            start_time_current_channel: 0,
            interval_timer_ppm: 500,
            long_term_timer_ppm: 500,
            request_periodic_timer_on_next_interval_timer_interrupt: false,
            time_on_one_channel_cache: 0, // invalid value
            first_caught_packet: PDU::alloc().expect("Cannot allocate a PDU buffer for the first packet for harvesting packets. A minimum of 3 PDUs is needed for this state to work, 6 to work properly.").init([0; PDU_SIZE]),
            second_caught_packet: PDU::alloc().expect("Cannot allocate a PDU buffer for the second packet for harvesting packets. A minimum of 3 PDUs is needed for this state to work, 6 to work properly.").init([0; PDU_SIZE]),
        }
    }
}

impl JammerStateBasic for HarvestPackets {

    /// Is it valid to go from the self state to the new state.
    /// self -> new_state valid?
    /// Can only go to idle or start harvesting patterns.
    fn is_valid_transition_to(&mut self, new_state: &JamblerState) {
        match new_state {
            // TODO allow for transition to TestingParameters
            JamblerState::Idle => {
                // Can go to idle
            }
            _ => panic!(
                "Can only go to idle state or start testing parameters after harvesting packets"
            ),
        }
    }

    /// Is it valid to go to the self state from the old_state
    /// new_state -> self valid?
    fn is_valid_transition_from(&mut self, old_state: &JamblerState) {
        match old_state {
            JamblerState::Idle => {
                // Can come here from Idle
            }
            _ => panic!("Can start harvesting packets from the Idle state"),
        }
    }
}

impl<R: JamblerRadio,T: JamblerRestrictedTimer> JammerState<R,T> for HarvestPackets {

    /// Returns an error if a required config parameter was missing.
    fn config(&mut self, 
        radio: &mut R,
        timer: &mut T, parameters: &mut StateParameters) {
        let config = parameters
            .config
            .as_ref()
            .expect("Config necessary for harvesting packets.");

        // set access address
        self.access_address = config
            .access_address
            .expect("Access address not provided for harvesting packets.");

        // set phy
        self.phy = config
            .phy
            .expect("PHY not provided for harvesting packets.");

        // set slave phy
        self.slave_phy = config
            .slave_phy
            .expect("Slave PHY not provided for harvesting packets.");

        // set channel chain
        self.channel_chain = config
            .channel_chain
            .clone()
            .expect("Channels not provided for harvesting packets.");

        // set interval
        self.current_min_conn_interval = config
            .interval
            .expect("Interval not provided for harvesting packets.");

        // set number of intervals
        self.number_of_intervals = config
            .number_of_intervals
            .expect("Number of intervals not provided for harvesting packets.");

        // if a crcInit is given, set it
        // Can just copy because is option as well
        self.crc_init = config.crc_init;

        // set interval timer ppm
        self.interval_timer_ppm = config
            .interval_timer_ppm
            .expect("Interval timer ppm not provided for harvesting packets.");

        // set interval timer ppm
        self.long_term_timer_ppm = config
            .long_term_timer_ppm
            .expect("Long term timer ppm not provided for harvesting packets.");

        // check if channel chain is not empty
        // Because of the way it is constructed there will be 64 elements at most, don't check upper bound.
        if self.channel_chain.is_empty() {
            panic!("Channel chain empty for harvesting packets.");
        }

        self.current_channel = 0;
        // Check if all channels are legal
        while self.current_channel < self.channel_chain.len() {
            let channel: u8 = self.channel_chain[self.current_channel];
            if channel > 36 {
                panic!("Illegal channel in channel chain for harvesting packets.");
            }
            self.current_channel += 1;
        }

        // will always be legal value
        self.current_channel = 0;

        // check if interval is at least 7.5 milliseconds
        // and not larger than 4 seconds and a multiple of 1.25 ms
        // (the minimum for conInterval)
        if self.current_min_conn_interval < 7_500 {
            panic!("Interval for discovering AAs was shorter than the minimum connection interval (7.5 ms).");
        } else if self.current_min_conn_interval > 4_000_000 {
            panic!("Interval for discovering AAs was longer than the maximum connection interval (4s).");
        } else if self.current_min_conn_interval % 1_250 != 0 {
            panic!("Interval for discovering AAs was not a multiple of 1.25 milliseconds.");
        }

        // Everything was ok and is set
    }

    /// Functions as a reset + start!
    /// Configures the radio to be ready for listening on the first channel of the channel chain.
    /// Assumes the radio has been correctly configured.
    fn initialise(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // TODO example of getting an unitialisee master pdu you can use
        // To get a pointer I have to initialise them, which takes a lot of time...
        let mut master_pdu = PDU::alloc().unwrap().init([0; 258]);
        let slave_pdu = PDU::alloc().unwrap().init([0; 258]);
        let master_ref = &mut master_pdu;
        // The buffer pointer you should give to your peripheral
        let p = master_ref.as_ptr() as u32;

        drop(master_pdu);
        drop(slave_pdu);

        // set start time for this channel
        self.start_time_current_channel = parameters.current_time;

        // start listening on channel 0
        self.current_channel = 0;

        // Get the current channel from the channel chain
        let channel: u8 = self.channel_chain[self.current_channel];

        // Config the radio
        radio.prepare_for_config_change();

        // Config the radio
        radio.harvest_packets_quick_config(
            self.access_address,
            self.phy,
            channel,
            self.crc_init,
            &mut self.first_caught_packet,
        );
        //rprintln!("Init to harvesting for packets: channel {}.", channel);

        // Cache the time we will wait
        self.time_on_one_channel_cache = self.calculate_receiving_interval();

        return_value.timing_requirements = Some(IntervalTimerRequirements::Periodic(
            self.time_on_one_channel_cache,
        ));

        // Signal the host it should forget all previously harvested information and restart
        // IMPORTANT this means you cannot reconfigure this state by restarting it!!
        /*
        NOPE, jambler's responsability
        return_value.state_message = Some(StateMessage::ResetDeducingConnectionParameters(
            self.access_address,
            self.phy,
            self.slave_phy,
        ));
        */
    }

    fn launch(&mut self,
        radio: &mut R,
        timer: &mut T, parameters: &mut StateParameters) {
        //TimeStamp::rprint_normal_with_micros_from_microseconds(parameters.current_time);
        //rprintln!("Launched harvesting for packets: \n{:?}.", &self);

        // launch the radio
        radio.receive();
    }

    /// Used for updating the state.
    ///
    /// Harvesting packets is able to update the following parameters:
    ///     - current_min_conn_interval (interval)
    ///     - crc_init
    ///
    /// An access address, phy change, channel chain would require starting from scratch anyway.
    /// The ppm, number of intervals etc will not be changed either, just restart.
    fn update_state(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // remember the current channel index
        let cur_chan = self.current_channel;

        let interval_change;

        // TODO channel_chain update. For multiple devices, after this one has done its job so he can help with more unlucky ones which had a lot of unused channels. However, maybe just let this state finish? You will always rely on outside jambler sources to transition which is basically a new task. I dunno, see later

        let c = parameters
            .config
            .as_mut()
            .expect("No config provided for harvesting packets update");

        // assign necessary but unupdatable parameters

        // return error if any of these are not None
        if !(c.access_address.is_none()
            && c.phy.is_none()
            && c.number_of_intervals.is_none()
            && c.interval_timer_ppm.is_none()
            && c.channel_chain.is_none())
        {
            panic!("Illegal update parameters provided for harvesting packets update");
        }
        c.access_address = Some(self.access_address);
        c.phy = Some(self.phy);
        c.number_of_intervals = Some(self.number_of_intervals);
        c.interval_timer_ppm = Some(self.interval_timer_ppm);
        c.channel_chain = Some(self.channel_chain.clone());

        // Check for interval
        match c.interval {
            None => {
                // No new interval given, give it current one
                c.interval = Some(self.current_min_conn_interval);
                interval_change = false;
            }
            Some(new_interval) => {
                if new_interval >= self.current_min_conn_interval {
                    panic!("Interval update for harvesting packets update was not shorter");
                }
                interval_change = true;
            }
        };

        // Check for crc init change
        match c.crc_init {
            None => {
                // No new phy given, give it current one
                // Do not wrap in option, it already is one
                c.crc_init = self.crc_init;
            }
            Some(_) => {}
        };

        // set the new configuration to this local struct, validating them as well
        self.config(radio, timer, parameters);

        // restore channel index from config
        self.current_channel = cur_chan;

        //TimeStamp::rprint_normal_with_micros_from_microseconds(parameters.current_time);
        /*
        rprintln!(
            "Harvesting packets state update: interval change {}",
            interval_change
        ); */

        if interval_change {
            // There was an interval change
            // refresh the cache
            self.time_on_one_channel_cache = self.calculate_receiving_interval();
            let listening_time_on_this_channel =
                (parameters.current_time - self.start_time_current_channel) as u32;

            if self.time_on_one_channel_cache <= listening_time_on_this_channel {
                // new time to change is shorter than the time already on this channel
                // Change the channel with new periodic timer

                // Change channel
                self.next_channel(radio, parameters.current_time);

                return_value.timing_requirements = Some(IntervalTimerRequirements::Periodic(
                    self.time_on_one_channel_cache,
                ));
            } else {
                // new time to change is longer than the time we are already listening on this channel
                // lets reuse that!
                // Countdown until the end of this cycle

                // Set flag so that interval timer will now it has to set the timer back to periodic
                self.request_periodic_timer_on_next_interval_timer_interrupt = true;

                // ask for a countdown timer until then
                return_value.timing_requirements = Some(IntervalTimerRequirements::Countdown(
                    self.time_on_one_channel_cache - listening_time_on_this_channel,
                ));
            }
        } else {

            // We will be able to reverse the crc either way once we settled on one.

            // only crc change, nothing to report or change
        }
    }

    /// TODO use this for dropping pdu buffers on the pdu heap!
    fn stop(&mut self, 
        radio: &mut R,
        timer: &mut T) {
        // the state.rs reset the radio

        // TODO use the stop() in states to drop any buffer they are still holding
        // The buffers are not dropped because I do not want them to be options.
        // They are just statically allocated somewhere, taking 2*PDU_SIZE (half a kilobyte, we have 264 in nrf52840).
    }

    /// Will be called when a packet is captured on the configured channel, access address and phy.
    /// The responsibility of this state is to collect the packets with all necessary parameters.
    /// To reduce complexity all decisions are made in the background process.
    ///  
    #[inline]
    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Get the packet from the hal
        // radio is responsible for timing out
        let hal_ret = radio.harvest_packets_busy_wait_slave_response(
            self.slave_phy,
            &mut self.first_caught_packet,
            &mut self.second_caught_packet,
        );

        match hal_ret {
            None => {
                // The interrupt fired for another reason, not giving us a packet.
                // Just return
                //rprintln!("Did not result in harvested packet (yet).");
            }
            Some(((master_crc, master_rssi), slave_response_option)) => {
                // We received a packet and possibly its response

                let channel = self.channel_chain[self.current_channel as usize];

                // Predict channel chain complete, we cannot use the next channel function here because it messes with the buffers...
                let will_wrap: bool;
                if self.current_channel == self.channel_chain.len() - 1 {
                    will_wrap = true;
                } else {
                    will_wrap = false;
                }

                // Only return if we can allocate new buffers.
                // However still move on so we do not falsely return unused channels!

                // Return the subevent
                match slave_response_option {
                    None => {
                        // Only received one packet
                        // Try to allocate a new buffer, if we can't the harvested packet will be dropped
                        if let Some(new_buffer) = PDU::alloc() {
                            // We were able to allocate a new buffer
                            // Return the subevent, replacing the first buffer we will send of with the newly allocated one
                            return_value.state_message = Some(StateMessage::HarvestedSubevent(
                                HarvestedSubEvent {
                                    channel,
                                    time: parameters.current_time,
                                    time_on_the_channel: (parameters.current_time
                                        - self.start_time_current_channel)
                                        as u32,
                                    packet: HarvestedPacket {
                                        pdu: core::mem::replace(
                                            &mut self.first_caught_packet,
                                            new_buffer.init([0; PDU_SIZE]),
                                        ),
                                        phy: self.phy,
                                        crc: master_crc,
                                        rssi: master_rssi,
                                    },
                                    response: None,
                                },
                                will_wrap,
                            ));
                        }
                        else {
                            //rprintln!("WARNING: harvest packet flooding, dropped harvested subevent because there was no more room for a new buffer")
                        }
                    }
                    Some((slave_crc, slave_rssi)) => {
                        // Received both packets in the subevent
                        // Try to allocate 2 new buffers, if we can't the harvested packets will be dropped
                        if let Some(new_buffer) = PDU::alloc() {
                            // We were able to allocate a new buffer
                            // Try to get a second one
                            match PDU::alloc() {
                                Some(second_new_buffer) => {
                                    return_value.state_message =
                                        Some(StateMessage::HarvestedSubevent(
                                            HarvestedSubEvent {
                                                channel,
                                                time: parameters.current_time,
                                                time_on_the_channel: (parameters.current_time
                                                    - self.start_time_current_channel)
                                                    as u32,
                                                packet: HarvestedPacket {
                                                    pdu: core::mem::replace(
                                                        &mut self.first_caught_packet,
                                                        new_buffer.init([0; PDU_SIZE]),
                                                    ),
                                                    phy: self.phy,
                                                    crc: master_crc,
                                                    rssi: master_rssi,
                                                },
                                                response: Some(HarvestedPacket {
                                                    pdu: core::mem::replace(
                                                        &mut self.second_caught_packet,
                                                        second_new_buffer.init([0; PDU_SIZE]),
                                                    ),
                                                    phy: self.slave_phy,
                                                    crc: slave_crc,
                                                    rssi: slave_rssi,
                                                }),
                                            },
                                            will_wrap,
                                        ));
                                }
                                None => {
                                    // could not get the second buffer
                                    // Only send the first one and send a warning
                                    return_value.state_message =
                                        Some(StateMessage::HarvestedSubevent(
                                            HarvestedSubEvent {
                                                channel,
                                                time: parameters.current_time,
                                                time_on_the_channel: (parameters.current_time
                                                    - self.start_time_current_channel)
                                                    as u32,
                                                packet: HarvestedPacket {
                                                    pdu: core::mem::replace(
                                                        &mut self.first_caught_packet,
                                                        new_buffer.init([0; PDU_SIZE]),
                                                    ),
                                                    phy: self.phy,
                                                    crc: master_crc,
                                                    rssi: master_rssi,
                                                },
                                                response: None,
                                            },
                                            will_wrap,
                                        ));
                                    //rprintln!("WARNING: harvest packet flooding, dropped the response packet of a full harvested subevent because there was no more room for a new buffer, sending partial instead")
                                }
                            }
                        }
                        else {
                            /*
                            rprintln!("WARNING: harvest packet flooding, dropped full harvested subevent because there was no more room for a new buffer")
                            */
                        }
                    }
                }

                // next channel
                let channel_chain_completed = self.next_channel(radio, parameters.current_time);
                assert_eq!(channel_chain_completed, will_wrap);

                // And request a periodic timer
                // The interval timer must be reset by this as well!! We do not want an interrupt from the countdown after this!!
                // This is the responsibility of the interval_timer_hal
                return_value.timing_requirements = Some(IntervalTimerRequirements::Periodic(
                    self.time_on_one_channel_cache,
                ));

                // Reset that we requested for this
                self.request_periodic_timer_on_next_interval_timer_interrupt = false;
            }
        }

        /*
        rprintln!("PDU bufs @ END radio int.: first {:?} | {}, second {:?} | {}", self.first_caught_packet.as_ptr(), self.first_caught_packet[0], self.second_caught_packet.as_ptr(), self.second_caught_packet[0]);
        if let Some(ref m) = &return_value.state_message {
            if let StateMessage::HarvestedSubevent(ref p, w) = m {
                rprintln!("Return packet: {:?} | {}", p.packet.pdu.as_ptr(), p.packet.pdu[0]);
                if let Some(ref r) = p.response {
                    rprintln!("Response: {:?} | {}", r.pdu.as_ptr(), r.pdu[0]);
                }
            }
        }
        */
    }

    /// Will get called when we have to change channel and consider this one unused.
    #[inline]
    fn handle_interval_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        /*
        TimeStamp::rprintln_normal_with_micros_from_microseconds(parameters.current_time);
        */
        let will_wrap: bool;
        if self.current_channel == self.channel_chain.len() - 1 {
            will_wrap = true;
        } else {
            will_wrap = false;
        }

        // If we asked a countdown timer because of an interval update, still ask for periodic one
        if self.request_periodic_timer_on_next_interval_timer_interrupt {
            // reset flag
            self.request_periodic_timer_on_next_interval_timer_interrupt = false;
            // Ask for a periodic timer
            return_value.timing_requirements = Some(IntervalTimerRequirements::Periodic(
                self.time_on_one_channel_cache,
            ));
        }

        // TODO remove from channel chain? This will cause us to capture more packets quickly if we wrap but do not have enough information for anchorpoints etc...

        /*
        rprintln!(
            "Timeout on channel {}, consider unused",
            self.channel_chain[self.current_channel]
        );
        */
        return_value.state_message = Some(StateMessage::UnusedChannel(
            self.channel_chain[self.current_channel],
            will_wrap,
        ));

        // Change channel (don't worry, the handle get a lock on self)
        let channel_chain_completed = self.next_channel(radio, parameters.current_time);

        assert_eq!(channel_chain_completed, will_wrap);
    }
}
