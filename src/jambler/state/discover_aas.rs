use super::{JammerStateBasic, StateParameters};
use crate::jambler::{hardware_traits::JamblerRestrictedTimer, state::DiscoveredAccessAddress};
use crate::jambler::state::IntervalTimerRequirements;
use crate::jambler::state::StateMessage;
use crate::jambler::JamblerState;
use crate::jambler::StateReturn;
use heapless::{spsc::Queue, Vec};
use core::default::Default;

//use super::super::util::TimeStamp;

use super::super::{BlePhy, JamblerRadio};
use super::JammerState;

//use rtt_target::rprintln;

/// Struct used to hold state for sniffing access adresses on data channels.
pub struct DiscoverAas {
    /// Cache for adresses already seen.
    /// A queue holding the access address as an unsigned 32 bit.
    aa_cache: Queue<u32, 255>,
    /// The PHY the sniffer is listening to
    phy: BlePhy,
    /// The channels the listener will listen for.
    /// Must not be empty and all elements must be between 0 and 37.
    channel_chain: Vec<u8, 64>,
    /// Time when started to listen on this channel in microseconds.
    /// Must be longer than 1.25 ms (1250 micros).
    interval: u32,
    // Current channel (index into channel chain).
    // Must always be a legal index for channel chain.
    current_channel: usize,
    /// The minimum rssi to accept a packet
    minimum_rssi: Option<i8>,
}

impl Default for DiscoverAas {
    fn default() -> Self {
        DiscoverAas {
            aa_cache: Queue::new(),
            phy: BlePhy::Uncoded1M,
            channel_chain: Vec::new(),
            interval: 0,
            current_channel: 0,
            minimum_rssi: None,
        }
    }
}

impl JammerStateBasic for DiscoverAas {

    /// Should only go to the idle state.
    fn is_valid_transition_to(&mut self, new_state: &JamblerState) {
        match new_state {
            JamblerState::Idle => {
                // Can go back to idle
            }
            _ => panic!("Can only transition to Idle from discover AAs."),
        }
    }

    /// Should only transition to this from the idle state.
    fn is_valid_transition_from(&mut self, old_state: &JamblerState) {
        match old_state {
            JamblerState::Idle => {
                // Can come here from idle state
            }
            _ => panic!("Can only start discovering AAs starting from the Idle state."),
        }
    }
}

impl<R: JamblerRadio,T: JamblerRestrictedTimer> JammerState<R,T> for DiscoverAas {

    /// Configure the parameters for this state.
    /// Sets the PHY, channels and interval to be snooping for
    fn config(&mut self, radio: &mut R, timer: &mut T, parameters: &mut StateParameters) {
        let config = parameters
            .config
            .as_ref()
            .expect("Config necessary for discovering AAs but not provided.");

        // set phy
        self.phy = config.phy.expect("PHY not provided for discovering AAs");
        // set channel chain
        self.channel_chain = config
            .channel_chain
            .clone()
            .expect("Channels not provided for discovering AAs");
        // set interval
        self.interval = config
            .interval
            .expect("Interval not provided for discovering AAs");
        // set rssi
        self.minimum_rssi = config.minimum_rssi;

        // check if channel chain is not empty
        // Because of the way it is constructed there will be 64 elements at most, don't check upper bound.
        if self.channel_chain.is_empty() {
            panic!("Channel chain empty for discovering AAs");
        }

        self.current_channel = 0;
        // Check if all channels are legal
        while self.current_channel < self.channel_chain.len() {
            let channel: u8 = self.channel_chain[self.current_channel];
            if channel > 39 {
                panic!("Illegal channel in channel chain for discovering AAs");
            }
            self.current_channel += 1;
        }

        // will always be legal value
        self.current_channel = 0;

        // Everything was ok and is set
    }

    /// Start listening on first channel.
    /// Empty AA cache
    fn initialise(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Fresh cache
        self.aa_cache = Queue::new();
        // start listening on channel 0
        self.current_channel = 0;

        // Get the current channel from the channel chain
        let channel: u8 = self.channel_chain[self.current_channel];

        // Config the radio
        radio.prepare_for_config_change();
        radio.config_discover_access_addresses(self.phy, channel, self.minimum_rssi);

        // Set us up to receive an interval timer interrupt every self.interval microseconds
        return_value.timing_requirements = Some(IntervalTimerRequirements::Periodic(self.interval));
    }

    /// Starts receiving
    #[inline]
    fn launch(&mut self, 
        radio: &mut R,
        timer: &mut T, parameters: &mut StateParameters) {
        //rprintln!("Launched sniffing for AAs.");

        // launch the radio
        radio.receive();
    }

    /// Updates the given parameters of the radio without changing the cache
    /// and only resetting the interval timer if the interval changed.
    /// It is not very efficient but as long as its not a problem I don't care.
    fn update_state(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // remember the current channel index
        let cur_chan = self.current_channel;
        // Remember what got changed. Default is it got changed but it will be checked.
        let mut interval_change = true;
        let mut channel_chain_change = true;
        let mut phy_change = true;

        // change the state struct to a valid one if the required parameters are missing by keeping them the same

        let mut c = parameters
            .config
            .as_mut()
            .expect("No config provided for discovering AAs update");

        // Check for interval
        match c.interval {
            None => {
                // No new interval given, give it current one
                c.interval = Some(self.interval);
                interval_change = false;
            }
            Some(_) => {}
        };

        // Check for phy change
        match c.phy {
            None => {
                // No new phy given, give it current one
                c.phy = Some(self.phy);
                phy_change = false;
            }
            Some(_) => {}
        };

        // Check for channel_chain change
        match c.channel_chain {
            None => {
                // No new channel_chain given, give it current one
                c.channel_chain = Some(self.channel_chain.clone());
                channel_chain_change = false;
            }
            Some(_) => {}
        };

        // set the new configuration to this local struct, validating them as well
        self.config(radio, timer, parameters);

        if !channel_chain_change {
            // if the channel chain did not change, reset the current channel index
            self.current_channel = cur_chan;
        }

        // if the channels or the phy changed, alter the radio
        if channel_chain_change || phy_change {
            // Get the channel to change to
            let channel: u8 = self.channel_chain[self.current_channel];

            // Configure the radio
            radio.prepare_for_config_change();
            radio.config_discover_access_addresses(self.phy, channel, self.minimum_rssi);

            // Launch the radio
            self.launch(radio, timer, parameters);
        }

        // If the interval changed, return a timingrequest for it
        // Otherwise return nothing
        if interval_change {
            return_value.timing_requirements =
                Some(IntervalTimerRequirements::Periodic(self.interval));
        }
    }

    fn stop(&mut self, 
        radio: &mut R,
        timer: &mut T,) {
        //rprintln!("Stopped sniffing for AAs.");
        // reset is done while changing states, I don't really have to do anything
    }

    /// Handle a radio interrupt
    #[inline]
    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // TODO let the function return whether or not it was found by the master
        if let Some((aa, rssi)) = radio.read_discovered_access_address(timer, parameters.current_time) {
            //TimeStamp::rprint_normal_with_micros_from_microseconds(parameters.current_time);
            //rprintln!("Found access address {:#010x} with rssi {}", aa, rssi);

            // TODO add to aa_cache, pop oldest if full
            // It just depends on whether you want the most recent knowledge
            // and want to remember master or slave etc... if you would do this

            // Build discovered access address

            return_value.state_message =
                Some(StateMessage::AccessAddress(DiscoveredAccessAddress {
                    address: aa,
                    phy: self.phy,
                    channel: self.channel_chain[self.current_channel],
                    time: parameters.current_time,
                    rssi,
                    sent_by_master: None,
                }));
        } else {
            // Delete later
            //TimeStamp::rprint_normal_with_micros_from_microseconds(instant_in_microseconds);
            //rprintln!("Discovering aas radio interrupt but not valid packet.");
        }
    }

    /// Will get called every 3 seconds
    #[inline]
    fn handle_interval_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Change channel
        // Could do modulo, but I think it is very slow so I do it this way
        self.current_channel += 1;
        // Wrap around chain when necessary
        if self.current_channel >= self.channel_chain.len() {
            self.current_channel = 0;
        }

        let channel = self.channel_chain[self.current_channel];

        // Do the config change and return error if necessary.
        radio.prepare_for_config_change();
        radio.config_discover_access_addresses(self.phy, channel, self.minimum_rssi);
        radio.receive();

        // TODO delete this later
        //TimeStamp::rprint_normal_with_micros_from_microseconds(parameters.current_time);
        //rprintln!(" listening for AAs on channel {}", channel);
    }

}
