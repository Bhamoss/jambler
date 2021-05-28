use heapless::spsc::Consumer;
use heapless::spsc::Producer;

use core::fmt::Debug;
use core::ops::Deref;

use super::brute_force::BfParam;
use super::brute_force::BruteForceParameters;
use super::brute_force::BruteForceResult;
use super::deducer::ConnectionSample;
use super::deducer::DeducedParameters;
use super::deducer::DeductionStartParameters;
use super::deducer::UnsureChannelEvent;
use super::deducer::UnusedChannel;
use super::{deducer::{DeductionState}};

use core::mem::{MaybeUninit};

#[cfg(not(target_arch="x86_64"))]
use heapless::pool::singleton::Box;

use heapless::{pool::{Node, singleton::Pool}, spsc::Queue};
use heapless::pool;
//use lazy_static::__Deref;


// Necessary for mutlithreading on x86
#[cfg(target_arch="x86_64")]
pub type DpParam = DeducedParameters;
#[cfg(not(target_arch="x86_64"))]
pub type DpParam = Box<DeducedParametersBox>;

#[inline(always)]
pub fn convert_deduced_param(p: &DeducedParameters) -> DpParam {
    #[cfg(target_arch="x86_64")]
    return *p;
    #[cfg(not(target_arch="x86_64"))]
    return DeducedParametersBox::alloc().expect("DeducedParametersBox heap overflow").init(*p);
}



// 2 size pool for zero copy DeducedParameters. Should grow_exact on store creation
const DPBUF_SIZE : usize = 2;
pool!(
    #[allow(non_upper_case_globals)]
    DeducedParametersBox: DeducedParameters
);
pub type DpBuf = MaybeUninit<[Node<DeducedParameters>; DPBUF_SIZE]>;
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
pub type BfpBuf = MaybeUninit<[Node<BruteForceParameters>; BFPBUF_SIZE]>;
impl Debug for BruteForceParametersBox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deref().fmt(f)
    }
}


/// Communication from the master to the deducer.
#[derive(Debug)]
pub enum MasterToDeducer {
    /// Reset. Stop deducing and go to idle.
    Reset,
    // Start deduction with the following parameters.
    Start(DeductionStartParameters)
}


/// Requests the deducer makes to the master.
/// The master is responsible for coordinating the sniffers as the deducer asks.
#[derive(Debug)]
pub enum DeducerToMaster {
    /// (time_to_switch) : Search for packets. Each sniffer should be on a separate channel.
    /// They should stay on the channel for time_to_switch us.
    SearchPacketsForCrcInit(u32),
    /// (time_to_switch, crc_init, used_channels_until_now) : Search for packets. Each sniffer should be on a separate channel.
    /// They should stay on the channel for time_to_switch us, and stay on the channel if the crc_init matches.
    SearchPacketsForConnInterval(u32, u32, u64),
    /// (time_to_listen_in_us, channels_todo, crc_init) : Request sniffers to listen for time_to_listen_in_us on the 1's in channels_todo.
    /// Do what you want with crc init, but give it so master does not have to keep state of this.
    StartChannelMap(u32, u64, u32),
    /// Signal distributed brute force request.
    /// Sniffer should listen on used channels, that is way the current seen channels have been given.
    DistributedBruteForce(BfParam, u64),
    /// Listen for the unsure channels, indicated by the u64.
    /// The channel map in the parameters will have 0 for the unsure channels -> XOR with todo and let channels follow as if normal.
    /// Then let master filter out unseen reports for the todo channel map.
    /// At this point the master is responsible for keeping the updated data (most recent seen packet to sync to when parameters are deduced).
    ListenForUnsureChannels(DpParam, u64),
    /// Special non-task: should be called on master by deduction task to signal it was found
    DeducedParameters(DpParam)
}




/********************* COMMUNICATION WITH OUTSIDE WORLD STRUCTS *********************************/

pub struct DeductionQueueStore {
    sample_queue : Queue<ConnectionSample,16>,
    unused_queue : Queue<UnusedChannel,16>,
    command_queue : Queue<MasterToDeducer,16>,
    request_queue : Queue<DeducerToMaster,16>,
    brute_force_result_queue : Queue<BruteForceResult,16>,
    unsure_channel_queue : Queue<UnsureChannelEvent,16>,
}

impl DeductionQueueStore {
    pub const fn new() -> Self {

        DeductionQueueStore { 
            sample_queue: Queue::new(), 
            unused_queue: Queue::new(), 
            command_queue: Queue::new(),
            request_queue : Queue::new(),
            brute_force_result_queue : Queue::new(),
            unsure_channel_queue : Queue::new(),}
    }

    #[allow(clippy::needless_lifetimes)]
    pub fn split<'a>(&'a mut self, dp_memory : &'static mut DpBuf, bfp_memory : &'static mut BfpBuf) -> (DeduceConnectionParametersControl<'a>, DeductionState<'a>) {
        DeducedParametersBox::grow_exact(dp_memory);
        BruteForceParametersBox::grow_exact(bfp_memory);

        // Split queues and hand them to producer and consumer.
        let (sample_prod, sample_cons) = self.sample_queue.split();
        let (unused_prod, unused_cons) = self.unused_queue.split();
        let (restart_prod, restart_cons) = self.command_queue.split();


        let (request_prod, request_cons) = self.request_queue.split();
        let (bf_prod, bf_cons) = self.brute_force_result_queue.split();
        let (uc_prod, uc_cons) = self.unsure_channel_queue.split();
    
        (
            DeduceConnectionParametersControl::new(sample_prod, unused_prod, restart_prod, request_cons, bf_prod, uc_prod),
            DeductionState::new(sample_cons, unused_cons, restart_cons, request_prod, bf_cons, uc_cons)
        )
    }
}




/// A wrapper for all necessary control information for the task used for deducing connection parameters.
/// This is the message passing struct between the host and the task.
pub struct DeduceConnectionParametersControl<'a> {
    sample_queue : Producer<'a, ConnectionSample,16>,
    unused_queue : Producer<'a, UnusedChannel,16>,
    command_queue : Producer<'a, MasterToDeducer,16>,
    request_queue : Consumer<'a, DeducerToMaster,16>,
    brute_force_result_queue : Producer<'a, BruteForceResult,16>,
    unsure_channel_queue : Producer<'a, UnsureChannelEvent,16>,
}

impl<'a> DeduceConnectionParametersControl<'a> {
    pub fn new(
        sample_queue : Producer<'a, ConnectionSample,16>,
        unused_queue : Producer<'a, UnusedChannel,16>,
        command_queue : Producer<'a, MasterToDeducer,16>,
        request_queue : Consumer<'a, DeducerToMaster,16>,
        brute_force_result_queue : Producer<'a, BruteForceResult,16>,
        unsure_channel_queue : Producer<'a, UnsureChannelEvent,16>,
    ) -> Self {
        DeduceConnectionParametersControl {
            sample_queue,
            unused_queue,
            command_queue,
            request_queue,
            brute_force_result_queue,
            unsure_channel_queue,
        }
    }

    /// Signals the task to reset
    pub fn reset(&mut self) {

        while self.request_queue.dequeue().is_some() {}
        self.command_queue.enqueue(MasterToDeducer::Reset).expect("Deduction command overflow, but should not happen. We cannot flush the queue with only the producer. Only last one matters");

    }

    pub fn start(&mut self, parameters: DeductionStartParameters) {

        while self.request_queue.dequeue().is_some() {}
        self.command_queue.enqueue(MasterToDeducer::Start(parameters)).expect("Deduction command overflow, but should not happen. We cannot flush the queue with only the producer. Only last one matters");

    }

    pub fn send_connection_sample(&mut self, sample: ConnectionSample) {
        if self.sample_queue.enqueue(sample).is_err() {
            //println!("Sample queue overflow, dropping packet.")
        }
    }

    pub fn send_unused_channel(&mut self, channel: UnusedChannel) {
        if self.unused_queue.enqueue(channel).is_err() {
            //println!("Channel queue overflow, dropping packet.")
        }
    }
    pub fn send_brute_force_result(&mut self, result: BruteForceResult) {
        if self.brute_force_result_queue.enqueue(result).is_err() {
            //println!("Channel queue overflow, dropping packet.")
        }
    }
    pub fn send_unsure_channel_event(&mut self, event: UnsureChannelEvent) {
        if self.unsure_channel_queue.enqueue(event).is_err() {
            //println!("Channel queue overflow, dropping packet.")
        }
    }


    pub fn get_deducer_request(&mut self) -> Option<DeducerToMaster> {
        self.request_queue.dequeue()
    }

}
