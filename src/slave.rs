mod hardware_traits;
mod state;

use crate::ble_algorithms::crc::reverse_calculate_crc_init;
use crate::deduction::deducer::{ConnectionSample, ConnectionSamplePacket};
use crate::master::{RadioTask, SlaveMessageType};
use crate::slave::state::harvest::HarvestedSubEvent;

// Re-export hardware implementations for user

use hardware_traits::*;
use state::StateStore;
use state::{StateParameters, StateReturn};

//use rtt_target::rprintln;

use heapless::{pool, pool::singleton::Pool, pool::Node};
use core::mem::MaybeUninit;


// This is a sort of heap I make myself, but it is not a general purpose heap
// I use it to transport packets
// IMPORTANT Pool is only Sync on x86_64 if the Cargo feature “x86-sync-pool” is enabled

/// The size (number of PDUs) that fit in our PDU heap.
/// Zero initially
const PDU_POOL_SIZE: usize = 10;
pub const PDU_SIZE: usize = 258;
pool!(
    // Buffers for when a packet gets caught
    PDU: [u8; PDU_SIZE]
);


pub type PduBuf = MaybeUninit<[Node<[u8;PDU_SIZE]>; PDU_POOL_SIZE]>;

/// Initialises the static PDU heap
///
/// Use of mutable statics is unsafe because of multithreading.
/// However, any chips that will be used by Jambler will most likely not have multiple threads and Jambler is a singleton.
pub fn initialise_pdu_heap(memory_pool: &'static mut PduBuf) {
    PDU::grow_exact(memory_pool);
}

/// The generic implementation of the vulnerability.
/// This is supposed to hold the BLE vulnerability code, not chip specific code.
/// It will hold a field for every possible state, as you cannot abstract it to just the trait because this means this field could change size (the state struct size) and I have no heap. This is the simplest solution.
///
/// The JamBLEr controller is responsible for receiving tasks and following the correct state transitions for that task.
/// Whether the state itself indicates it wants to transition or because required background work is done.
/// The controller is responsible for proper task execution in the same way that the state store is responsible for proper state execution.
pub struct Jambler<R: JamblerRadio> {
    /// The abstraction of the radio peripheral
    jammer_hal: R,
    /// The state store, holding exactly 1 struct for every state and dispatching calls to the current state.
    state_store: StateStore,
    /// The task currently being executed by Jambler.
    current_task: RadioTask,
    /// A reusable struct for state parameters
    /// TODO HAS TO BE RESET AT THE END OF USE, NOT AT BEGINNING, TO SPEED UP HANDLER RESPONSE
    state_parameters: StateParameters,
    /// A reusable struct for jambler returns (to avoid all the copying)
    /// TODO HAS TO BE RESET AT THE END OF USE, NOT AT BEGINNING, TO SPEED UP HANDLER RESPONSE
    state_return: StateReturn,
}

impl<H: JamblerRadio> Jambler<H> {
    pub fn new(mut jammer_hal: H, pdu_memory_pool :&'static mut PduBuf) -> Jambler<H> {
        // Grow memory pool
        initialise_pdu_heap(pdu_memory_pool);

        jammer_hal.reset();

        Jambler {
            jammer_hal,
            state_store: StateStore::default(),
            current_task: RadioTask::Idle,
            state_parameters: StateParameters {
                current_time: 0,
            },
            state_return: StateReturn::new(),
        }
    }

    /// Should be called from main or whatever to make JamBLEr do what user wants.
    /// Slaves are dumb. Only master controls because multiple sniffers is impossible otherwise.
    pub fn execute_task(&mut self, task: RadioTask, timer : &mut  impl JamblerTimer) {
        self.jammer_hal.reset();
        self.state_store.start(&task, &mut self.jammer_hal, timer);
        self.current_task = task;
    }

    /// What happens on a user interrupt.
    /// For now, just idle.
    fn reset(&mut self) {
        self.current_task = RadioTask::Idle;
        self.jammer_hal.reset();
        //self.state_store.reset();
    }

    /// Radio interrupt received, dispatch it to the state
    #[inline(always)]
    pub fn handle_radio_interrupt(&mut self, timer : &mut  impl JamblerTimer, interrupt_time : u64, closure_return: &mut Option<JamblerReturn>) {

        // Dispatch to state
        self.state_store.handle_radio_interrupt(
            &self.current_task,
            &mut self.jammer_hal,
            timer,
            interrupt_time,
            &mut self.state_return,
        );

        // Process whatever the state returned.
        // The return value is now in the state_return struct.
        *closure_return = self.state_return.jambler_return.take();

        self.state_return.jambler_return = None;

        // Reset reusable structs
        self.state_parameters.reset();
        self.state_return.reset();
    }

    /// Received interval timer interrupt, dispatch it to the state.
    ///
    /// Because this gets called in a closure, we have to send the return via a pointer that will be filled.
    ///
    /// TODO have to have the return as mutable to fill in because the lock closure cannot return anything
    #[inline(always)]
    pub fn handle_timer_interrupt(&mut self, timer : &mut  impl JamblerTimer, interrupt_time : u64, closure_return: &mut Option<JamblerReturn>) {

        // Dispatch it to the state
        let state_return = self.state_store.handle_interval_timer_interrupt(
            &self.current_task,
            &mut self.jammer_hal,
            timer,
            interrupt_time,
            &mut self.state_return,
        );

        // Process whatever the state returned.
        // The return value is now in the state_return struct.
        *closure_return = self.state_return.jambler_return.take();

        self.state_return.jambler_return = None;

        // Reset reusable structs
        self.state_parameters.reset();
        self.state_return.reset();
    }
}

pub fn out_of_interrupt_processing(work : RadioWork) -> Option<JamblerReturn> {
    match work {
        RadioWork::ConvertToConnectionSample(harvested) => {

            let packet_pdu_length: u16 = if harvested.packet.pdu[0] & 0b0010_0000 != 0 {
                3 + harvested.packet.pdu[1] as u16
            } else {
                2 + harvested.packet.pdu[1] as u16
            };

            let mut connection_sample = ConnectionSample {
                channel: harvested.channel,
                time: harvested.time,
                silence_time_on_channel: harvested.time_on_the_channel,
                packet: ConnectionSamplePacket {
                    first_header_byte: harvested.packet.pdu[0],
                    phy: harvested.packet.phy,
                    reversed_crc_init: reverse_calculate_crc_init(
                        harvested.packet.crc,
                        &harvested.packet.pdu[..],
                        packet_pdu_length,
                    ),
                    rssi: harvested.packet.rssi,
                },
                response: None,
            };

            if let Some(response) = harvested.response {
                let slave_pdu_length: u16;
                if response.pdu[0] & 0b0010_0000 != 0 {
                    slave_pdu_length = 3 + response.pdu[1] as u16;
                } else {
                    slave_pdu_length = 2 + response.pdu[1] as u16;
                }

                connection_sample.response = Some(ConnectionSamplePacket {
                    first_header_byte: response.pdu[0],
                    phy: response.phy,
                    reversed_crc_init: reverse_calculate_crc_init(
                        response.crc,
                        &response.pdu[..],
                        slave_pdu_length,
                    ),
                    rssi: response.rssi,
                });

                #[cfg(not(target_arch="x86_64"))]
                drop(response.pdu)
            }
            // Make sure to release the PDUs from the pdu heap
            // Although it should happen automatically
            #[cfg(not(target_arch="x86_64"))]
            drop(harvested.packet.pdu);

            Some(JamblerReturn::ToMaster(SlaveMessageType::SampleReport(connection_sample)))
        },
    }
}

/***************************************************/
/* // ***          EXPORTED STRUCTS            *** */
/***************************************************/

/// Jambler should never give an "output string", the slave/master code should parse and build an output string itself if it needs it.
/// TODO make a heap for these, they get big...
pub enum JamblerReturn {
    ToMaster(SlaveMessageType),
    RequiresProcessingOutOfInterrupt(RadioWork),
}

pub enum RadioWork {
    ConvertToConnectionSample(HarvestedSubEvent)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BlePhy {
    Uncoded1M,
    Uncoded2M,
    CodedS2,
    CodedS8,
}

impl Default for BlePhy {
    fn default() -> Self {
        BlePhy::Uncoded1M
    }
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

