pub mod calibrate_interval_timer;
pub mod discover_aas;
pub mod harvest_packets;
pub mod idle;

/// Jammer states trait
/// This will handle the ugly truth of avoiding dynamic dispatch.
use crate::jambler::state::harvest_packets::HarvestedSubEvent;
use heapless::Vec;

use super::{JamblerHalError, hardware_traits::{JamblerRestrictedTimer}};
use super::{BlePhy, JamblerRadio, JamblerState};

/// Errors a state can give.
#[derive(Clone, Debug)]
pub enum StateError {
    InvalidStateTransition(&'static str),
    InvalidConfig(&'static str),
    MissingConfig(&'static str),
    JamblerHalError(&'static str, JamblerHalError),
}

impl core::convert::From<super::hardware_traits::JamblerHalError> for StateError {
    fn from(jambler_hal_error: super::hardware_traits::JamblerHalError) -> StateError {
        StateError::JamblerHalError("HAL error was given: ", jambler_hal_error)
    }
}


/// Possible parameters a state might need to configure itself.
#[derive(Debug)]
pub struct StateConfig {
    pub phy: Option<BlePhy>,
    pub access_address: Option<u32>,
    pub channel_map: Option<[bool; 37]>,
    pub crc_init: Option<u32>,
    pub csa_version: Option<u8>,
    pub channel: Option<u8>,
    pub hop_interval: Option<u32>,
    pub hop_increment: Option<u32>,
    pub initial_counter_value: Option<u32>,
    pub counter: Option<u32>,
    pub previous_state: Option<JamblerState>,
    /// When it is needed to iterate through a bunch of channels.
    /// Can have 64 unsigned 8-bit integers, although it only needs 37.
    /// For a Queue, they say you get better performance if the size is a
    /// power of 2. This is not said for vectors, but for now I will still to it here.
    pub channel_chain: Option<Vec<u8, 64>>,
    /// The interval at which a state has to do something (like switching channel).
    pub interval: Option<u32>,
    /// Number of intervals to listen for (harvesting packets)
    pub number_of_intervals: Option<u8>,
    /// The clock drift in ppm of the interval timer
    pub interval_timer_ppm: Option<u32>,
    /// The clock drift in ppm of the long term timer, which provides the current_time timestamp.
    pub long_term_timer_ppm: Option<u32>,
    /// The phy of the slave
    pub slave_phy: Option<BlePhy>,
    /// Minimum rssi for discovering AAs
    pub minimum_rssi: Option<i8>,
}

impl StateConfig {
    /// Default constructor for quickly initialising a config
    /// without any parameters.
    pub fn new() -> StateConfig {
        StateConfig {
            phy: None,
            access_address: None,
            channel_map: None,
            crc_init: None,
            csa_version: None,
            channel: None,
            hop_interval: None,
            hop_increment: None,
            initial_counter_value: None,
            counter: None,
            previous_state: None,
            channel_chain: None,
            interval: None,
            number_of_intervals: None,
            interval_timer_ppm: None,
            long_term_timer_ppm: None,
            slave_phy: None,
            minimum_rssi: None,
        }
    }

    pub fn reset(&mut self) {
        self.phy = None;
        self.access_address = None;
        self.channel_map = None;
        self.crc_init = None;
        self.csa_version = None;
        self.channel = None;
        self.hop_interval = None;
        self.hop_increment = None;
        self.initial_counter_value = None;
        self.counter = None;
        self.previous_state = None;
        self.channel_chain = None;
        self.interval = None;
        self.number_of_intervals = None;
        self.interval_timer_ppm = None;
        self.long_term_timer_ppm = None;
        self.slave_phy = None;
        self.minimum_rssi = None;
    }
}

impl Default for StateConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Enum for returning feedback or a task from the state functions.
/// An enum in memory is always the size of its biggest variant,
/// that is why we can return it. Returning an impl which some structs implement
/// would not work because they can have different sizes at runtime which is not allowed.
/// Remember, no dynamic allocation.
//pub enum HandlerReturn {
//    OutputString(String<U256>),
//    NoReturn,
//}

/// Indicates to the controller which timing requirements you want after an interaction.
#[derive(Clone, Debug)]
pub enum IntervalTimerRequirements {
    NoIntervalTimer,
    NoChanges,
    Periodic(u32),
    Countdown(u32),
}

/// A struct holding information about a discovered access address.
#[derive(Clone, Debug)]
pub struct DiscoveredAccessAddress {
    /// The access address.
    address: u32,
    /// The phy on which the AA was discovered.
    phy: BlePhy,
    /// The channel on which the AA was discovered.
    channel: u8,
    /// The time at which the AA was discovered.
    time: u64,
    /// RSSI of the packet that discovered the AA
    rssi: i8,
    /// Indicates whether it was captured from the master or the slave if known,
    sent_by_master: Option<bool>,
}

/// For returning things the master should knkow
///
/// TODO HAS TO BE AS SMALL AS POSSIBLE, WILL GET COPIED MULTIPLE TIMES
#[derive(Debug)]
pub enum StateMessage {
    /// Returns the delays of the interval timer
    /// The integers inside represent the following
    /// (state_change_to_first_interrupt_delay, periodic_no_change_delay, interval_timer_change_delay)
    IntervalTimerDelays(i32, i32, i32),
    /// An access address discovered in the discover AA state.
    /// Parameters are in the following order:
    ///
    AccessAddress(DiscoveredAccessAddress),
    /// An enum holding a harvested packet and a boolean indicating whether or not the sniffer has completed listening on all the channels of his channel chain.
    HarvestedSubevent(HarvestedSubEvent, bool),
    /// Holds the channel index of an unused channel (listened for max_conn_interval * number_intervals and received nothing) and a boolean indicating whether or not the sniffer has completed listening on all the channels of his channel chain.
    UnusedChannel(u8, bool),
    /// Used to signal the jambler host that it has to throw away all
    /// previous harvested subevents and unused channel messages and
    /// completely restart deducing the connection parameters when new
    /// harvested subevents or unused channels follow.
    /// This is sent every time the harvested packet state is started
    /// Holds the access address for the next connection and the master and slave phy
    ResetDeducingConnectionParameters(u32, BlePhy, BlePhy),
}

/// Struct for letting a state return something
///
/// Return string was completely removed, the state/master main should do user output
pub struct StateReturn {
    pub timing_requirements: Option<IntervalTimerRequirements>,
    pub state_transition: Option<(JamblerState, Option<StateConfig>)>,
    pub state_message: Option<StateMessage>,
}

impl StateReturn {
    /// A convenience constructor.
    /// Everything None, change the fields manually to what is necessary.
    pub fn new() -> StateReturn {
        StateReturn {
            timing_requirements: None,
            state_transition: None,
            state_message: None,
        }
    }

    /// Resets the struct so it can be reused.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.state_message = None;
        self.state_transition = None;
        self.timing_requirements = None;
    }
}

/// Struct for passing parameters to a state.
/// Takes a mutable reference to a JamBLErHal which
/// must have a lifetime as long as the parameter lives
///
/// In all function where this is used it should be a mutable reference
/// that is passed to reduce stack size.
pub struct StateParameters {
    pub config: Option<StateConfig>,
    /// The time at which the call was made.
    /// Can be a special value for interrupts (binding timers to it etc..)
    /// For circumventing software delays
    pub current_time: u64,
}

impl StateParameters {
    pub fn new(instant_in_microseconds: u64, config: StateConfig) -> StateParameters {
        StateParameters {
            config: Some(config),
            current_time: instant_in_microseconds,
        }
    }

    pub fn new_no_config(instant_in_microseconds: u64) -> StateParameters {
        StateParameters {
            config: None,
            current_time: instant_in_microseconds,
        }
    }

    /// Resets the parameters, making it ready for reuse.
    /// Does not reset the current_time, as this has to be overwritten.
    /// Does not reset the radio as this should be initialised once and remain.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.config = None;
    }
}

pub trait JammerStateBasic : Default {

    /// Is it valid to go from the self state to the new state.
    /// self -> new_state valid?
    /// Panics on invalid transition
    /// TODO these checks should be deleted when you are sure everything works
    /// SHOULD PANIC ON INVALID TRANSITION
    fn is_valid_transition_to(
        &mut self, 
        new_state: &JamblerState
    );

    /// Is it valid to go to the self state from the old_state
    /// new_state -> self valid?
    /// SHOULD PANIC ON INVALID TRANSITION
    fn is_valid_transition_from(
        &mut self, 
        old_state: &JamblerState
    );
}

/// A JammerState has to be able to be started and stopped.
/// Inbetween that, it will handle all the radio interrupts.
/// It can also ask for a periodic timer interrupt or an interrupt after a certain interval.
/// This is necessary for for example changing interval after a certain period or for deciding you lost the connection.
///
/// Telling the controller what you want or what you know can only happen at interaction points.
/// These are after initialise, handle_interrupt and handle_interval_interrupt
///
/// Some of these will panic if you use them incorrectly and log the error message to RTT.
/// Any "errors" are unexpected and fatal (this is an embedded application), so intelligent error handling is not very high overhead and not worth it.
///
/// So how it works:
/// 1) call config on the state, then initialise which returns timing requirements
/// 2) The controller should start those timing requirements and then launch.
/// 3) The state will return a HandlerReturn return Value and timing requirements on every handle_interrupt (radio  interrupt) or handle_interval_timer_interrrupt
/// 4) Before this state is left, the stop function will be called, giving the state the opportunity to do cleanup.
///
/// # Example
/// ```
/// // dummy get created to allocate space for it
/// let state = JammerState::new();
///
///  // A state transitions to that state
/// state.is_valid_transition_from(&previous_state)?;
/// state.config(parameters)?;
/// state_return = state.initialise(parameters)?;
/// state.launch(parameters);
///
/// // interrupts are passed on to the state
/// state.handle_radio_interrupt(parameters)
/// state.handle_interval_timer_interrupt(parameters)
///
/// // State get update (!= restarted)
/// state.update_state(parameters)
///
///
/// // More interrupts are passed on to the state
/// state.handle_radio_interrupt(parameters)
/// state.handle_interval_timer_interrupt(parameters)
///
/// // Transition from this state to another state
/// state.is_valid_transition_to(&new_state)?;
/// state.stop(parameters);
///
/// ```
///
/// # Performance considerations
/// All these functions should only contain references as parameters and a reference to a return struct.
/// This is necessary for handling interrupts very quickly.
/// All interrupt handlers should be #[inline(always)] when you are done debugging them.
pub trait JammerState<R: JamblerRadio,T: JamblerRestrictedTimer>: JammerStateBasic {

    /// Returns an error if a required config parameter was missing.
    fn config(
        &mut self, 
        radio: &mut R, 
        timer: &mut T,
        parameters: &mut StateParameters
    );

    /// Functions as a reset + start!
    /// Every state should have a config method which you should call before this one.
    /// Should always return timing.
    fn initialise(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    );

    fn launch(
        &mut self, 
        radio: &mut R, 
        timer: &mut T,
        parameters: &mut StateParameters
    );

    /// Used for updating the state.
    /// For example, updating the connInterval while sniffing for packets,
    /// without completely restarting, thus not wasting the time you were listening on the current channel..
    /// Returns an error if you provided an illegal parameter.
    fn update_state(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    );

    /// Called when the state is left (might be preempted).
    /// TODO use this for dropping pdu buffers on the pdu heap!
    fn stop(
        &mut self, 
        radio: &mut R,
        timer: &mut T,
    );

    /// Handle a radio interrupt.
    /// ALWAYS INLINE IN IMPLEMENTATION!
    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    );

    /// Handle an interval timer interrupt.
    /// ALWAYS INLINE IN IMPLEMENTATION!
    fn handle_interval_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    );
}

/// Will hold a struct of every possible state.
/// Necessary to avoid dynamic allocation but leverage polymorphism
/// and use the state GOF pattern.
/// It will have a function that will return a reference to the right jammerstate implementation given the corresponding JamBLErState enum.
pub struct StateStore {
    current_state: JamblerState,
    idle: idle::Idle,
    discover_aas: discover_aas::DiscoverAas,
    harvest_packets: harvest_packets::HarvestPackets,
    calibrate_interval_timer: calibrate_interval_timer::CalibrateIntervalTimer,
}

/*
macro_rules! transistion_to {
    ($s:expr, $conf:expr, $hal:expr, $time:expr, $it:expr, $p:expr, $i:expr) => {
        $s.config($conf); //  if false rprintln
        $s.initialise(&mut $hal, $time);
        $it = $s.needs_interval_timer();
        $p = $s.needs_periodic_interrupt();
        $i = $s.timer_interval();

        $s.launch(&mut $hal, $time);
    };
}
*/
impl core::default::Default for StateStore {
    fn default() -> Self {
        StateStore {
            current_state: JamblerState::Idle,
            idle: idle::Idle::default(),
            discover_aas: discover_aas::DiscoverAas::default(),
            harvest_packets: harvest_packets::HarvestPackets::default(),
            calibrate_interval_timer: calibrate_interval_timer::CalibrateIntervalTimer::default(),
        }
    }

}

impl StateStore {
    /// Transitions state in the proper way, only for valid state transitions.
    /// This also serves as a way for me to protect me from myself and easily catch things I did not intend to happen.
    ///
    /// Calibrate interval timer should always be last
    pub fn state_transition<R: JamblerRadio, T: JamblerRestrictedTimer> (
        &mut self,
        radio: &mut R,
        timer: &mut T,
        new_state: &JamblerState,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // We will stop the previous state even though it can crash later in new state
        // However, leaving the system in an invalid state is not bad because it is a crash either way, an invalid transition

        // Reset the radio between states
        // TODO is this oke? Does this eliminate the need for stop?
        radio.reset();

        // Check if old -> new is valid for old and stop if if ok
        // The ? will make the function return early.
        match self.current_state {
            JamblerState::Idle => {
                let state = &mut self.idle;

                // This is identical for every case
                state.is_valid_transition_to(&new_state);
                // THESE ARE THE PARAMETERS FOR THE NEW STATE
                state.stop(radio, timer);
            }
            JamblerState::DiscoveringAAs => {
                let state = &mut self.discover_aas;

                state.is_valid_transition_to(&new_state);
                state.stop(radio, timer);
            }
            JamblerState::HarvestingPackets => {
                let state = &mut self.harvest_packets;

                state.is_valid_transition_to(&new_state);
                state.stop(radio, timer);
            }
            JamblerState::CalibrateIntervalTimer => {
                let state = &mut self.calibrate_interval_timer;

                state.is_valid_transition_to(&new_state);
                state.stop(radio, timer);
            }
        };

        // configure the state, initialise it, get its timing requirements
        // and launch it.
        match &new_state {
            JamblerState::Idle => {
                let state = &mut self.idle;

                // This is identical for every case
                state.is_valid_transition_from(&self.current_state);
                state.config(radio, timer, parameters);
                state.initialise(radio, timer, parameters, return_value);
                state.launch(radio, timer, parameters);
            }
            JamblerState::DiscoveringAAs => {
                let state = &mut self.discover_aas;

                state.is_valid_transition_from(&self.current_state);
                state.config(radio, timer, parameters);
                state.initialise(radio, timer, parameters, return_value);
                state.launch(radio, timer, parameters);
            }
            JamblerState::HarvestingPackets => {
                let state = &mut self.harvest_packets;

                state.is_valid_transition_from(&self.current_state);
                state.config(radio, timer, parameters);
                state.initialise(radio, timer, parameters, return_value);
                state.launch(radio, timer, parameters);
            }
            JamblerState::CalibrateIntervalTimer => {
                let state = &mut self.calibrate_interval_timer;

                state.is_valid_transition_from(&self.current_state);
                state.config(radio, timer, parameters);
                state.initialise(radio, timer, parameters, return_value);
                state.launch(radio, timer, parameters);
            }
        };

        self.current_state = new_state.clone();

        // The states will adapt the return value struct as needed
    }

    /// Updates the state.
    /// Returns an error if the config was invalid.
    #[inline]
    pub fn update_state<R: JamblerRadio, T: JamblerRestrictedTimer>(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        match &mut self.current_state {
            JamblerState::Idle => {
                let state = &mut self.idle;

                state.update_state(radio, timer, parameters, return_value)
            }
            JamblerState::DiscoveringAAs => {
                let state = &mut self.discover_aas;

                state.update_state(radio, timer, parameters, return_value)
            }
            JamblerState::HarvestingPackets => {
                let state = &mut self.harvest_packets;

                state.update_state(radio, timer, parameters, return_value)
            }
            JamblerState::CalibrateIntervalTimer => {
                let state = &mut self.calibrate_interval_timer;

                state.update_state(radio, timer, parameters, return_value)
            }
        }
    }

    /// Will dispatch the radio interrupt to the right jammerstate for the current jamblerstate.
    #[inline]
    pub fn handle_radio_interrupt<R: JamblerRadio, T: JamblerRestrictedTimer>(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        match self.current_state {
            JamblerState::Idle => {
                let state = &mut self.idle;

                // Following is same for every case
                state.handle_radio_interrupt(radio, timer, parameters, return_value)
            }
            JamblerState::DiscoveringAAs => {
                let state = &mut self.discover_aas;

                state.handle_radio_interrupt(radio, timer, parameters, return_value)
            }
            JamblerState::HarvestingPackets => {
                let state = &mut self.harvest_packets;

                state.handle_radio_interrupt(radio, timer, parameters, return_value)
            }
            JamblerState::CalibrateIntervalTimer => {
                let state = &mut self.calibrate_interval_timer;

                state.handle_radio_interrupt(radio, timer, parameters, return_value)
            }
        }
    }

    /// Will dispatch the interval timer interrupt to the right jammerstate for the current jamblerstate.
    #[inline]
    pub fn handle_interval_timer_interrupt<R: JamblerRadio, T: JamblerRestrictedTimer>(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        match self.current_state {
            JamblerState::Idle => {
                let state = &mut self.idle;

                // Following is same for every case
                state.handle_interval_timer_interrupt(radio, timer, parameters, return_value)
            }
            JamblerState::DiscoveringAAs => {
                let state = &mut self.discover_aas;

                state.handle_interval_timer_interrupt(radio, timer, parameters, return_value)
            }
            JamblerState::HarvestingPackets => {
                let state = &mut self.harvest_packets;

                state.handle_interval_timer_interrupt(radio, timer, parameters, return_value)
            }
            JamblerState::CalibrateIntervalTimer => {
                let state = &mut self.calibrate_interval_timer;

                state.handle_interval_timer_interrupt(radio, timer, parameters, return_value)
            }
        }
    }
}
