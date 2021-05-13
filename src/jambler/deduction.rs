
use core::fmt::Debug;
use core::ops::Deref;
use self::{control::DeduceConnectionParametersControl, processing::{BruteForceParameters, DeductionCommand, DeductionState}};

use super::BlePhy;
use core::mem::{MaybeUninit};


use heapless::{pool::{Node, singleton::{Box, Pool}}, spsc::Queue};
use heapless::pool;
//use lazy_static::__Deref;


pub mod control;
pub mod processing;

// 2 size pool for zero copy DeducedParameters. Should grow_exact on store creation
const DPBUF_SIZE : usize = 2;
pool!(
    #[allow(non_upper_case_globals)]
    DeducedParametersBox: DeducedParameters
);
type DpBuf = [Node<DeducedParameters>; DPBUF_SIZE];
impl Debug for DeducedParametersBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deref().fmt(f)
    }
}

// 2 size pool for zero copy BruteForceParameters. Should grow_exact on store creation
const BFPBUF_SIZE : usize = 2;
pool!(
    #[allow(non_upper_case_globals)]
    BruteForceParametersBox: BruteForceParameters
);
type BfpBuf = [Node<BruteForceParameters>; BFPBUF_SIZE];
impl Debug for BruteForceParametersBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deref().fmt(f)
    }
}

#[derive(Debug)]
pub enum JamblerTask {
    /// Special non-task: should be called on master by deduction task to signal it was found
    DeducedParameters(Box<DeducedParametersBox>),
    HarvestingUpdate(HarvestingUpdate),
    /// Thoughout stages, use this to make sure sniffer does not listen on the same or unused channels.
    /// For stage one: used channel where a sniffer already is
    /// For stage two: unknown channels where is listening on should be listened to.
    /// For stage three: used channels where nobody is listening on, but use found channel map for this.
    DoNotListenOn(u64),
    /// Found smaller delay
    SmallerDelay(u32),
    /// Signal crc found
    HarvestingCrcFound(u32),
    /// Signal small delay found, start finding channel map
    /// (smallest delay, start position channels)
    /// Sniffer i takes the channel of the index of the ith 1 on the channel map
    StartChannelMap(u32, u64),
    /// Found channel map, sniffers should only listen to used positions.
    FoundChannelMap(u64),
    /// Signal distributed brute force request
    DistributedBruteForce(Box<BruteForceParametersBox>),
}


#[derive(Debug)]
/// A struct holding all important information a subevent can hold for reversing the parameters of a connection.
pub struct ConnectionSample {
    pub next_channel: u8,
    pub sniffer_id: u8,
    pub channel: u8,
    pub time: u64,
    pub time_on_channel: u32,
    pub packet: ConnectionSamplePacket,
    pub response: Option<ConnectionSamplePacket>,
}

pub struct UnusedChannel {
    pub channel: u8,
    pub next_channel: u8,
    pub sniffer_id: u8
}


#[derive(Debug)]
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


/********************* COMMUNICATION WITH OUTSIDE WORLD STRUCTS *********************************/

pub struct DeductionQueueStore {
    sample_queue : Queue<ConnectionSample,16>,
    unused_queue : Queue<UnusedChannel,16>,
    command_queue : Queue<DeductionCommand,16>,
}

impl DeductionQueueStore {
    pub const fn new() -> Self {

        DeductionQueueStore { 
            sample_queue: Queue::new(), 
            unused_queue: Queue::new(), 
            command_queue: Queue::new()}
    }

    #[allow(clippy::needless_lifetimes)]
    pub fn split<'a>(&'a mut self, dp_memory : &'static mut MaybeUninit<DpBuf>, bfp_memory : &'static mut MaybeUninit<BfpBuf>) -> (DeduceConnectionParametersControl<'a>, DeductionState<'a>) {
        DeducedParametersBox::grow_exact(dp_memory);
        BruteForceParametersBox::grow_exact(bfp_memory);

        // Split queues and hand them to producer and consumer.
        let (sample_prod, sample_cons) = self.sample_queue.split();
        let (unused_prod, unused_cons) = self.unused_queue.split();
        let (restart_prod, restart_cons) = self.command_queue.split();
    
        (
            DeduceConnectionParametersControl::new(sample_prod, unused_prod, restart_prod),
            DeductionState::new(sample_cons, unused_cons, restart_cons)
        )
    }
}
