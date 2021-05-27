pub mod deduction;
mod hardware_traits;
mod state;

use crate::jambler::state::harvest_packets::HarvestedSubEvent;

// Re-export hardware implementations for user

use heapless::{Vec};

use hardware_traits::*;
use state::IntervalTimerRequirements;
use state::StateConfig;
use state::StateStore;
use state::{StateMessage, StateParameters, StateReturn};

//use rtt_target::rprintln;

use heapless::{pool, pool::singleton::Pool};

// This is a sort of heap I make myself, but it is not a general purpose heap
// I use it to transport packets
// IMPORTANT Pool is only Sync on x86_64 if the Cargo feature “x86-sync-pool” is enabled

/// The size (number of PDUs) that fit in our PDU heap.
/// Zero initially
pub static mut PDU_POOL_SIZE: usize = 0;
pub const PDU_SIZE: usize = 258;
pool!(
    // Buffers for when a packet gets caught
    PDU: [u8; PDU_SIZE]
);

/// Initialises the static PDU heap
///
/// Use of mutable statics is unsafe because of multithreading.
/// However, any chips that will be used by Jambler will most likely not have multiple threads and Jambler is a singleton.
pub fn initialise_pdu_heap(memory_pool: &'static mut [u8]) -> usize {
    unsafe { PDU_POOL_SIZE += PDU::grow(memory_pool) };
    unsafe { PDU_POOL_SIZE }
}

/// The generic implementation of the vulnerability.
/// This is supposed to hold the BLE vulnerability code, not chip specific code.
/// It will hold a field for every possible state, as you cannot abstract it to just the trait because this means this field could change size (the state struct size) and I have no heap. This is the simplest solution.
///
/// The JamBLEr controller is responsible for receiving tasks and following the correct state transitions for that task.
/// Whether the state itself indicates it wants to transition or because required background work is done.
/// The controller is responsible for proper task execution in the same way that the state store is responsible for proper state execution.
pub struct Jambler<R: JamblerRadio, T: JamblerTimer, I: JamblerIntervalTimer> {
    /// The abstraction of the radio peripheral
    jammer_hal: R,
    /// The abstraction of the long term timer
    jammer_timer: T,
    /// The abstraction of the interval timer
    jammer_interval_timer: I,
    /// The state store, holding exactly 1 struct for every state and dispatching calls to the current state.
    state_store: StateStore,
    /// The task currently being executed by Jambler.
    current_task: JamblerTask,
    /// The delays states suffer when they ask for different changes.
    timing_delays: TimingDelays,
    /// A reusable struct for state parameters
    /// TODO HAS TO BE RESET AT THE END OF USE, NOT AT BEGINNING, TO SPEED UP HANDLER RESPONSE
    state_parameters: StateParameters,
    /// A reusable struct for jambler returns (to avoid all the copying)
    /// TODO HAS TO BE RESET AT THE END OF USE, NOT AT BEGINNING, TO SPEED UP HANDLER RESPONSE
    state_return: StateReturn,
}

/// Holds the delays states suffer due to the framework when working with the interval timer.
/// Can be used to anticipate delays and recalculate timing requests.
struct TimingDelays {
    state_change_delay: i32,
    periodic_no_change_delay: i32,
    interval_timer_change_delay: i32,
}

/// TODO move to state.rs
#[derive(Clone, Debug)]
pub enum JamblerState {
    Idle,
    DiscoveringAAs,
    HarvestingPackets,
    CalibrateIntervalTimer,
}

/// Use this to pass parameters, which you can use in the state conf.
/// For example SniffAA(access address)
/// While JamblerState might have 5 states for recovering a connection given an access address
/// this will only contain a recover connection(aa) enum
///
/// One task is basically subdevided into multiple jammer states
///
/// See the diagram about task state diagrams to better understand this.
#[derive(Clone, Debug, Copy)]
pub enum JamblerTask {
    UserInterrupt,
    Idle,
    /// Phy, interval, channel chain, rssi threshold
    DiscoverAas(BlePhy, u32, u64, Option<i8>),
    Harvest(HarvestParameters),
    /// Special non-task: should be called on master by deduction task to signal it was found
    DeducedParameters(DeducedParameters),
    HarvestingUpdate(HarvestingUpdate)
}

#[derive(Clone, Debug, Copy)]
pub struct HarvestParameters {
    pub access_address : u32,
    pub master_phy : BlePhy,
    pub slave_phy : BlePhy,
    pub interval : u32,
    pub channel_chain : u64,
    pub crc_init : Option<u32>,
    pub number_of_intervals: u8,
}

#[derive(Clone, Debug, Copy)]
pub struct DeducedParameters {
    pub access_address : u32,
    pub master_phy : BlePhy,
    pub slave_phy : BlePhy,
    pub conn_interval : u32,
    pub channel_map : u64,
    pub crc_init : u32,
    pub first_capture_time : u64,
    pub drift_since_first_capture : i64,
    pub counter_at_first_capture: u16
}

#[derive(Clone, Debug, Copy)]
pub struct HarvestingUpdate {
    pub nb_packets : u32,
    pub crc_init : Option<u32>,
    pub interval : Option<u32>,
}

#[inline]
fn channel_chain_from_u64(chm: u64) -> Vec<u8, 64> {
    let mut mask = 0b1_u64;
    let mut v = Vec::new();
    for i in 0..37 {
        if mask & chm != 0 {
            v.push(i).expect("channel chain from u64 overflow");
        };
        mask <<= 1;
    }
    v
}

impl<H: JamblerRadio, T: JamblerTimer, I: JamblerIntervalTimer> Jambler<H, T, I> {
    pub fn new(jammer_hal: H, mut jammer_timer: T, jammer_interval_timer: I) -> Jambler<H, T, I> {
        // Start the timer
        jammer_timer.start();
        Jambler {
            jammer_hal,
            jammer_timer,
            jammer_interval_timer,
            state_store: StateStore::default(),
            current_task: JamblerTask::Idle,
            timing_delays: TimingDelays {
                state_change_delay: 0,
                periodic_no_change_delay: 0,
                interval_timer_change_delay: 0,
            },
            state_parameters: StateParameters {
                config: None,
                current_time: 0,
            },
            state_return: StateReturn::new(),
        }
    }

    pub fn get_time_us(&self) -> u64 {
        self.jammer_timer.get_time_micro_seconds()
    }

    pub fn get_interval_timer_delays(&self) -> (i32, i32, i32) {
        (
            self.timing_delays.state_change_delay,
            self.timing_delays.periodic_no_change_delay,
            self.timing_delays.interval_timer_change_delay,
        )
    }

    /// Should be called from main or whatever to make JamBLEr do what user wants.
    pub fn execute_task(&mut self, task: JamblerTask) -> Option<JamblerReturn> {
        #[cfg(debug)]
        rprintln!("Received task {:?}", task);
        let mut ret = None;
        let prev_task = self.current_task;
        self.current_task = task;
        // always start to idle first, because any state goes can transition to idle
        //self.state_transition(JamBLErState::Idle);
        // Not necessary because for a user to stop the current task,
        // they  have to interrupt, which will put the jambler in idle

        // These transition the jambler into the start state of the given task.
        // The current state should always be idle, except for a user interrupt.
        match self.current_task {
            JamblerTask::UserInterrupt => {
                self.user_interrupt();
            }
            JamblerTask::Idle => {
                self.state_transition(&JamblerState::Idle, StateConfig::new());
            }
            JamblerTask::DiscoverAas(phy, interval, channel_chain, rssi_option) => {
                let mut config = StateConfig::new();
                // for now, listen on legacy phy, all data channels and switch every 3 seconds
                config.phy = Some(phy);
                config.interval = Some(interval);
                config.minimum_rssi = rssi_option;
                config.channel_chain = Some(channel_chain_from_u64(channel_chain));
                //config.channel_chain = Some(Vec::from_slice(&[37, 38, 39]).unwrap());

                self.state_transition(&JamblerState::DiscoveringAAs, config);
            },
            JamblerTask::Harvest(params) => {
                // TODO specify all in command or I2C communication
                let mut config = StateConfig::new();

                // for now, listen on legacy phy, all data channels
                // max interval for 100, advertising AA
                config.access_address = Some(params.access_address);
                config.phy = Some(params.master_phy);
                config.slave_phy = Some(params.slave_phy);
                config.interval = Some(params.interval);
                config.channel_chain = Some(channel_chain_from_u64(params.channel_chain));
                config.interval = Some(params.interval);

                config.number_of_intervals = Some(params.number_of_intervals);

                // no crc init
                config.crc_init = params.crc_init;

                // interval timer 500 ppm so to speak
                config.interval_timer_ppm = Some(20);

                // interval timer 500 ppm so to speak
                config.long_term_timer_ppm = Some(20);

                self.state_transition(&JamblerState::HarvestingPackets, config);
                
                // Signal dcp reset
                ret = Some(JamblerReturn::ResetDeducingConnectionParameters(params.access_address, params.master_phy, params.slave_phy))
            }
            JamblerTask::HarvestingUpdate(params) => {
                // TODO do state update with them.

                if let Some(smallest_delta) = params.interval {
                    //rprintln!(
                    //    "Sniffed packet (in same chunk) {} -> New smallest delta: {}",
                    //    params.nb_packets,
                    //    smallest_delta
                    //);
                }

                if let Some(crc_init) = params.crc_init {
                    /*rprintln!(
                        "Sniffed packet (in same chunk) {} -> New crc init: {}",
                        params.nb_packets,
                        crc_init
                    );*/
                }

            }
            JamblerTask::DeducedParameters(params) => {
                // TODO whatever
                // Go to idle for now and print
                self.state_transition(&JamblerState::Idle, StateConfig::new());

                //rprintln!("Exactly one solution! Report back:\nConn_interval: {}\nChannel map: {:#039b}\nAbsolute start time: {}us\nDrift since start {}us\nCounter at start: {}\nCrc init: {:#08X}\nAccess Address {:#010x}\nMaster phy: {}\nSlave phy: {}", params.conn_interval, params.channel_map, params.first_capture_time, params.drift_since_first_capture, params.counter_at_first_capture, params.crc_init, params.access_address, params.master_phy, params.slave_phy);
            }
        };

        ret
    }

    /// What happens on a user interrupt.
    /// For now, just idle.
    fn user_interrupt(&mut self) {
        self.state_transition(&JamblerState::Idle, StateConfig::new());
    }

    /// Helper function for setting the interval timer.
    #[inline(always)]
    fn set_interval_timer(&mut self, req: &IntervalTimerRequirements) {
        // TODO incorporate timing delays in this. For requesting periodics, use a countdown first incorporating the known delay and the state processing delay you measured.
        //rprintln!("Setting interval timer: {:?}", &req);
        match req {
            IntervalTimerRequirements::NoChanges => {}
            IntervalTimerRequirements::NoIntervalTimer => {
                self.jammer_interval_timer.reset();
            }
            IntervalTimerRequirements::Countdown(interval) => {
                self.jammer_interval_timer.config(*interval, false);
                self.jammer_interval_timer.start();
            }
            IntervalTimerRequirements::Periodic(interval) => {
                self.jammer_interval_timer.config(*interval, true);
                self.jammer_interval_timer.start();
            }
        }
    }

    /// A state transition can reset the timer twice.
    /// It is first reset to prevent any new timer interrupts.
    /// The set_interval_timer will also reset the timer if it starts or reset the timer.
    /// Better safe than sorry for now.
    ///
    /// Resets the parameters and results after all is done.
    fn state_transition(&mut self, new_state: &JamblerState, config: StateConfig) {
        // Disable interval timer to prevent it preempting this in the middle.
        self.jammer_interval_timer.reset();

        // TODO set config before this, this is a whole bunch of extra copying
        self.state_parameters.config = Some(config);

        self.state_parameters.current_time = self.jammer_timer.get_time_micro_seconds();

        // Dispatch transition to the state store
        self.state_store.state_transition(
            &mut self.jammer_hal,
            &mut self.jammer_timer,
            new_state,
            &mut self.state_parameters,
            &mut self.state_return,
        );

        // Calculate how long it took the states
        let state_transition_duration =
            self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time;

        // Process any return or request
        // TODO parameter init result (deduce task reset) get LOST here!
        self.process_state_return_value(state_transition_duration);

        // Calculate the processing time
        let state_transition_return_processing_duration =
            self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time
                + state_transition_duration;

        // Reset reusable structs
        self.state_parameters.reset();
        self.state_return.reset();

        // TODO delete
        // debug feedback
        /*
        TimeStamp::rprint_normal_with_micros_from_microseconds(self.state_parameters.current_time);
        rprintln!(
            "Transitioning state: {:?} -> {:?}\nState transition took {} micros\nReturn value processing took {} micros",
            self.state_store.get_current_state(),
            new_state,
            state_transition_duration,
            state_transition_return_processing_duration
        );
        */
    }

    /// Radio interrupt received, dispatch it to the state
    #[inline(always)]
    pub fn handle_radio_interrupt(&mut self) -> Option<JamblerReturn> {
        // Get current time
        self.state_parameters.current_time = self.jammer_timer.get_time_micro_seconds();

        // Dispatch to state
        let state_return = self.state_store.handle_radio_interrupt(
            &mut self.jammer_hal,
            &mut self.jammer_timer,
            &mut self.state_parameters,
            &mut self.state_return,
        );

        // Calculate how long it took the state
        let state_radio_interrupt_duration =
            self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time;

        // Process whatever the state returned
        let jambler_return = self.process_state_return_value(state_radio_interrupt_duration);

        // Calculate the processing time
        let state_radio_interrupt_return_processing_duration =
            self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time
                + state_radio_interrupt_duration;

        // Reset reusable structs
        self.state_parameters.reset();
        self.state_return.reset();

        // TODO delete
        // debug feedback
        /*
        TimeStamp::rprint_normal_with_micros_from_microseconds(self.state_parameters.current_time);
        rprintln!(
            "State radio handler\nState took {} micros\nReturn value processing took {} micros",
            state_radio_interrupt_duration,
            state_radio_interrupt_return_processing_duration
        );
        */

        // Return
        jambler_return
    }

    /// Received interval timer interrupt, dispatch it to the state.
    ///
    /// Because this gets called in a closure, we have to send the return via a pointer that will be filled.
    ///
    /// TODO have to have the return as mutable to fill in because the lock closure cannot return anything
    #[inline(always)]
    pub fn handle_interval_timer_interrupt(&mut self, closure_return: &mut Option<JamblerReturn>) {
        // Necessary. At least for nrf because event needs to be reset.
        self.jammer_interval_timer.interrupt_handler();
        

        // Get current time
        self.state_parameters.current_time = self.jammer_timer.get_time_micro_seconds();

        // Dispatch it to the state
        let state_return = self.state_store.handle_interval_timer_interrupt(
            &mut self.jammer_hal,
            &mut self.jammer_timer,
            &mut self.state_parameters,
            &mut self.state_return,
        );

        // Calculate how long it took the state
        let state_interval_timer_interrupt_duration =
            self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time;

        // Process whatever the state returned
        let jambler_return =
            self.process_state_return_value(state_interval_timer_interrupt_duration);

        // Calculate the processing time
        let state_interval_timer_interrupt_return_processing_duration =
            self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time
                + state_interval_timer_interrupt_duration;

        // Reset reusable structs
        self.state_parameters.reset();
        self.state_return.reset();

        // TODO delete
        // debug feedback
        /*
        TimeStamp::rprint_normal_with_micros_from_microseconds(self.state_parameters.current_time);
        rprintln!(
            "State interval timer handler\nState took {} micros\nReturn value processing took {} micros",
            state_interval_timer_interrupt_duration,
            state_interval_timer_interrupt_return_processing_duration
        );
        */

        // Return
        *closure_return = jambler_return
    }

    /// Handler for the long term interrupt timer for when it wraps
    #[inline(always)]
    pub fn handle_timer_interrupt(&mut self, closure_return: &mut Option<JamblerReturn>) {
        if self.jammer_timer.interrupt_handler() {
            // Get current time
            self.state_parameters.current_time = self.jammer_timer.get_time_micro_seconds();

            // Dispatch it to the state
            let state_return = self.state_store.handle_interval_timer_interrupt(
                &mut self.jammer_hal,
                &mut self.jammer_timer,
                &mut self.state_parameters,
                &mut self.state_return,
            );

            // Calculate how long it took the state
            let state_interval_timer_interrupt_duration =
                self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time;

            // Process whatever the state returned
            let jambler_return =
                self.process_state_return_value(state_interval_timer_interrupt_duration);

            // Calculate the processing time
            let state_interval_timer_interrupt_return_processing_duration =
                self.jammer_timer.get_time_micro_seconds() - self.state_parameters.current_time
                    + state_interval_timer_interrupt_duration;

            // Reset reusable structs
            self.state_parameters.reset();
            self.state_return.reset();
            *closure_return = jambler_return
        }
        else {
            *closure_return = None
        }
    }

    /// Processes the return from a state, regardless from which interrupt.
    /// The state is telling the controller something here and should act accordingly.
    /// TODO ask for parameter for the time before and after the time the state processed the passthrough to enable for timer stuff
    /// TODO move the set interval timer here as well
    ///
    /// TODO PASS REFERENCE TO PARAMETERS AND RETURN!! THIS WILL MAKE FRAMEWORK MUCH MORE RESPONSIVE. ADDING THE HARVESTED PACKETS RESULTED IN 20% SLOWER RESPONSE TIME. I THINK THIS CAN BE REDUCED FROM 170 MICROS TO 20 THIS WAY (RETURN STRING ALSO TAKES 256 BYTES ETC...)
    ///
    ///
    ///
    /// TODO get rid of the clones in the if lets
    #[inline(always)]
    fn process_state_return_value(&mut self, handle_duration: u64) -> Option<JamblerReturn> {
        // If new timing requirements, execute them
        // TODO these enums get coppied
        if let Some(timing_requirements) = self.state_return.timing_requirements.clone() {
            self.set_interval_timer(&timing_requirements);
            self.state_return.timing_requirements = None;
        }

        let mut jambler_return = None;

        // Process any state return messages
        if let Some(m) = self.state_return.state_message.take() {
            match m {
                // Received a message from the state calibrating the timers telling use how much delay he suffered in each type of request
                // TODO calculate his time durations in this, will be bit hard because we did not account for this
                StateMessage::IntervalTimerDelays(
                    state_change_delay,
                    periodic_no_change_delay,
                    interval_timer_change_delay,
                ) => {
                    self.timing_delays = TimingDelays {
                        state_change_delay,
                        periodic_no_change_delay,
                        interval_timer_change_delay,
                    };

                    // TODO delete
                    // report back to debug
                    //rprintln!("State change delay: {} micros\nPeriodic without change delay: {} micros\nInterval timer change delay {} micros", state_change_delay, periodic_no_change_delay, interval_timer_change_delay);

                    // Tell RTIC we are done initialising
                    jambler_return = Some(JamblerReturn::InitialisationComplete);
                }
                // Received a harvested subevent, pass a command for processing its
                StateMessage::HarvestedSubevent(harvested, wrap) => {
                    jambler_return = Some(JamblerReturn::HarvestedSubEvent(harvested, wrap))
                }
                StateMessage::UnusedChannel(channel, wrap) => {
                    jambler_return = Some(JamblerReturn::HarvestedUnusedChannel(channel, wrap))
                }
                StateMessage::ResetDeducingConnectionParameters(new_access_address, mp, sp) => {
                    jambler_return = Some(JamblerReturn::ResetDeducingConnectionParameters(
                        new_access_address,
                        mp,
                        sp,
                    ))
                }
                StateMessage::AccessAddress(discovered_aa) => {
                    // TODO this state message will change in the future, when it is implemented and it will need the phy of the master and the phy of the slave (it might however be only on phy that is returned here as the chips who are working together will each do a phy on a channel and you will have to combine that knowledge)
                }
            }

            // Reset it
            self.state_return.state_message = None;
        }

        // If a state change request, do its
        if let Some((new_state, config_option)) = self.state_return.state_transition.take() {
            // TODO write the option to the parameters before this, so you don't need to do all this unnecessary copying
            // If config was None, give the default empty state config
            self.state_transition(&new_state, config_option.unwrap_or_default())
        }

        jambler_return
    }

    /// Initialise the jambler.
    /// For now, only calibrate the interval timer.
    pub fn initialise(&mut self) {
        // The calibration interval in microseconds
        // Take this as low as you can but still larger than any possible delay
        // => figure out by trial and error
        const CALIBRATION_INTERVAL: u32 = 10_000;

        let mut config = StateConfig::new();
        config.interval = Some(CALIBRATION_INTERVAL);

        // Start with calibration
        self.state_transition(&JamblerState::CalibrateIntervalTimer, config);
    }
}

/***************************************************/
/* // ***          EXPORTED STRUCTS            *** */
/***************************************************/

/// Jambler should never give an "output string", the slave/master code should parse and build an output string itself if it needs it.
/// TODO make a heap for these, they get big...
pub enum JamblerReturn {
    //OutputString(String<U256>),
    InitialisationComplete,
    /// Tell host to process a full (both packets received) subevent
    /// Contains the event and whether or not it did all its channels.
    HarvestedSubEvent(HarvestedSubEvent, bool),
    /// Indicates jambler timed out while listening on a channel
    HarvestedUnusedChannel(u8, bool),
    ResetDeducingConnectionParameters(u32, BlePhy, BlePhy),
    NoReturn,
}

impl core::fmt::Display for JamblerReturn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JamblerReturn::InitialisationComplete => {
                write!(f, "JamBLEr initialisation completed")
            }
            JamblerReturn::HarvestedSubEvent(harvested_subevent, completed_channel_chain) => {
                if *completed_channel_chain {
                    write!(
                        f,
                        "Harvested subevent, completed all assigned channels!{}",
                        harvested_subevent
                    )
                } else {
                    write!(f, "Harvested subevent{}", harvested_subevent)
                }
            }
            JamblerReturn::HarvestedUnusedChannel(channel, completed_channel_chain) => {
                if *completed_channel_chain {
                    write!(
                        f,
                        "Found channel {} is unused, completed all assigned channels!",
                        channel
                    )
                } else {
                    write!(f, "Found channel {} is unused", channel)
                }
            }
            JamblerReturn::ResetDeducingConnectionParameters(new_access_address, mp, sp) => {
                write!(
                    f,
                    "Reset deducing connection parameters with new access address 0x{:08X} and phys {} and {}",
                    new_access_address, mp, sp
                )
            }
            JamblerReturn::NoReturn => {
                write!(f, "No return value")
            }
        }
    }
}

impl core::fmt::Debug for JamblerReturn {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlePhy {
    Uncoded1M,
    Uncoded2M,
    CodedS2,
    CodedS8,
}

impl core::fmt::Display for BlePhy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlePhy::Uncoded1M => {
                write!(f, "uncoded 1Mbit/s (legacy)")
            }
            BlePhy::Uncoded2M => {
                write!(f, "uncoded 2Mbit/s (high speed)")
            }
            BlePhy::CodedS2 => {
                write!(f, "long range coded 500Kbit/s (s=2)")
            }
            BlePhy::CodedS8 => {
                write!(f, "long range coded 125Kbit/s (s=8)")
            }
        }
    }
}

impl core::fmt::Debug for BlePhy {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

/// A struct holding all important information a subevent can hold for reversing the parameters of a connection.
pub struct ConnectionSample {
    pub channel: u8,
    pub time: u64,
    pub time_on_channel: u32,
    pub packet: ConnectionSamplePacket,
    pub response: Option<ConnectionSamplePacket>,
}

/// Implementing display for it because it is very necessary for debugging
impl core::fmt::Display for ConnectionSample {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.response {
            Some(response) => {
                write!(
                    f,
                    "\nSubevent channel {} at {}\nMaster{}\nSlave{}\n",
                    self.channel, self.time, self.packet, response
                )
            }
            None => {
                write!(
                    f,
                    "\nPartial subevent channel {} at {}\nPacket\n{}\n",
                    self.channel, self.time, self.packet
                )
            }
        }
    }
}

impl core::fmt::Debug for ConnectionSample {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

/// Holds all information a packet belonging to a subevent can hold
pub struct ConnectionSamplePacket {
    /// The first header byte, holding important flags for helping determine if this was an anchorpoint or not
    pub first_header_byte: u8,
    /// The calculated reverse crc init we got on this packet.
    /// Remember, when we settle on a crc_init, this will be the true crc init if it was received correctly.
    pub reversed_crc_init: u32,
    /// The phy the packet was caught on (remember, in BLE5 master and slave can send on different PHYs)
    pub phy: BlePhy,
    /// The rssi at which the packet has been captured
    pub rssi: i8,
}

impl core::fmt::Display for ConnectionSamplePacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "\n|{:08b} ... | CRC INIT: 0x{:06X}, PHY {:?}, RSSI {}\n",
            self.first_header_byte, self.reversed_crc_init, self.phy, self.rssi
        )
    }
}

impl core::fmt::Debug for ConnectionSamplePacket {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}
