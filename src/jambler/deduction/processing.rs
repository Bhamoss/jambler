use core::cmp::Ordering;
use core::fmt::Debug;
use super::{BlePhy, ConnectionSample, DeducedParameters, JamblerTask, UnusedChannel};

use super::BruteForceParametersBox;
use super::DeducedParametersBox;

use crate::ble_algorithms::csa2::{csa2_no_subevent, calculate_channel_identifier, generate_channel_map_arrays};

use gcd::Gcd;
//use rtt_target::rprintln;
//use crate::ConnectionSample;

use heapless::{BinaryHeap, Vec, binary_heap::Max, binary_heap::Min, pool::{ singleton::{Box, Pool}}, spsc::Consumer, spsc::Queue};



const CRC_INIT_THRESSHOLD: u8 = 5;

/********************* INTERNAL DEDUCTION STRUCT HELPERS *********************************/

/// Current state of discovering channels
#[derive(Clone, Copy, PartialEq)]
enum ChannelMapEntry {
    Unknown,
    /// unused will be overwritten by used no matter what
    Unused,
    Used,
}

/// We want to end up with 1 interval with exactly 1 solution and all the rest NoSolutions.
/// NoSolutions means basically "finished", as does exactly one.
/// All NoSolutions means there is a contradiction.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CounterInterval {
    /// Acceptable end state if it is the only one.
    ExactlyOneSolution(u16),
    /// Indicates there were mutliple solutions and we need more information
    MultipleSolutions,
    /// If no solution for any slice error. Otherwise ok.
    NoSolutions,
}

/// Anchorpoint ordered on the time it was caught.
#[derive(Debug, Clone, Copy)]
pub struct AnchorPoint {
    /// The absolute time the anchorpoint was caught as a multiple of 1250. 2**16*1250 longer than 4_000_000
    pub channel: u8,
    pub time: u64,
}

impl PartialEq for AnchorPoint {
    fn eq(&self, other: &Self) -> bool {
        // Channel should always be same like this
        self.time == other.time
    }
}

impl Eq for AnchorPoint {

}

impl PartialOrd for AnchorPoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.time.partial_cmp(&other.time)
    }
}

impl Ord for AnchorPoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time.cmp(&other.time)
    }
}

/// Request a reset/restart and give the necessary information.
/// Can be dummy info if you just want to reset/stop.
#[derive(Debug)]
pub enum DeductionCommand {
    Reset,
    Start(DeductionStartParameters),
    /// (slave ID, version, brute force slice result)
    BruteForceResult(u8,u8,CounterInterval),
}

/// Necessary information to start deduction.
#[derive(Debug)]
pub struct DeductionStartParameters {
    access_address : u32,
    master_phy : BlePhy,
    master_rssi : i8,
    slave_phy : BlePhy,
    slave_rssi : i8,
    nb_slaves : u8
}
impl Default for DeductionStartParameters {
    fn default() -> Self {
        Self {
            access_address: u32::MAX,
            master_phy: BlePhy::Uncoded1M,
            master_rssi: i8::MAX,
            slave_phy: BlePhy::Uncoded1M,
            slave_rssi: i8::MAX,
            nb_slaves: 0
        }
    }
}

#[derive(Debug, Clone)]
/// Will be broadcast over i2c for distributed brute forcing.
pub struct BruteForceParameters {
    channel_map: u64,
    channel_id: u16,
    /// The version to avoid confusion when start or reset inbetween.
    version: u8,
    nb_sniffers: u8,
    relative_counters_and_channels : Vec<(u16,u8),256>
}

impl Default for BruteForceParameters {
    fn default() -> Self {
        Self {
            channel_map: u64::MAX,
            channel_id: u16::MAX,
            version: 0,
            nb_sniffers: 1,
            relative_counters_and_channels: Vec::new(),
        }
    }
}

/// Interval state when processing.
struct ProcessingState {
    params: BruteForceParameters,
    conn_interval: u32,
    drift: i64,
    offset: u64,
    distributed_processing_state: Vec<Option<CounterInterval>, 64>
}

impl Default for ProcessingState {
    fn default() -> Self {
        Self {
            params: BruteForceParameters::default(),
            conn_interval: 0,
            drift: 0,
            offset: 0,
            distributed_processing_state: Vec::new(),
        }
    }
}

#[derive(PartialEq, Debug)]
enum State {
    Idle,
    /// Capture a couple packets until there is a CRC.
    DeduceCrcInit,
    /// Capture packets until we are sure enough about the small delay.
    /// Holds the number of packet to wait for.
    SearchingSmallDelay,
    /// Recovering channel map.
    RecoveringChannelMap,
    /// Wait until enough packets to be sure enough we can get the counter interval.
    WaitingForConnIntervalThreshold,
    /// We are processing, this one but we may also be waiting on slaves.
    Processing
}


///
/// ## Everything is public for testing purposes
pub struct DeductionState<'a> {
    state: State,
    channel_map: [ChannelMapEntry; 37],
    start_parameters: DeductionStartParameters,
    crc_init: u32,
    // the maximum observed connection interval in microseconds
    // defaults to 4 seconds, which is the maximum according to the BLE specification
    smallest_time_delta: u32,
    recents_connection_samples: Queue<ConnectionSample, 10>,
    anchor_points: BinaryHeap<AnchorPoint, Min, 256>,
    processing_state: ProcessingState,
    total_packets: u32,

    sniffer_positions : u64,

    sample_queue : Consumer<'a, ConnectionSample,16>,
    unused_queue : Consumer<'a, UnusedChannel,16>,
    command_queue : Consumer<'a, DeductionCommand,16>,
}

impl<'a> DeductionState<'a> {
    /// Used for initialising the static variable
    pub fn new(
        sample_queue : Consumer<'a, ConnectionSample,16>,
        unused_queue : Consumer<'a, UnusedChannel,16>,
        command_queue : Consumer<'a, DeductionCommand,16>
    ) -> Self {
        DeductionState {
            state: State::Idle,
            channel_map: [ChannelMapEntry::Unknown; 37],
            crc_init: core::u32::MAX,
            smallest_time_delta: 4_000_000,
            recents_connection_samples: Queue::new(),
            anchor_points: BinaryHeap::new(),
            total_packets: 0,

            sample_queue,
            unused_queue,
            command_queue,

            sniffer_positions : 0,
            start_parameters: DeductionStartParameters::default(),
            processing_state: ProcessingState::default(),
        }
    }

    pub fn reset(&mut self, was_reset_command: bool) {
        self.state = State::Idle;
        self.channel_map = [ChannelMapEntry::Unknown; 37];
        self.crc_init = core::u32::MAX;
        // the maximum observed connection interval in microseconds
        // defaults to 4 seconds, which is the maximum according to the BLE specification
        self.smallest_time_delta = 4_000_000;
        self.recents_connection_samples = Queue::new();
        self.anchor_points = BinaryHeap::new();
        self.total_packets = 0;

        // Start parameters and state will just be overwritten when we get to their state.
        // They are large, waste no time



        if was_reset_command {
            // Flush packet queues
            while self.sample_queue.dequeue().is_some() {}
            while self.unused_queue.dequeue().is_some() {}
            self.state = State::Idle;
        }
    }

    pub fn start(&mut self, params: DeductionStartParameters) {

        // reset and flush queues
        self.reset(true);

        // Set info
        self.state = State::DeduceCrcInit;
        self.start_parameters = params;
    }

    /// Keep looping while second part is true. Service any jamblertasks inbetween
    pub fn deduction_loop(&mut self) -> (Option<JamblerTask>, bool) {

        // Check commands first
        // Check for a start or reset, the last one counts
        while let Some(command) = self.command_queue.dequeue() {
            match command {
                DeductionCommand::Reset => {self.reset(true)}
                DeductionCommand::Start(params) => {self.start(params)}
                DeductionCommand::BruteForceResult(slave_id, version, result) => {
                    // Only if we are processing and this is the version we are processing add it.
                    if self.state == State::Processing && self.processing_state.params.version == version {
                        // Assert the vector has been intialised properly by now.
                        self.processing_state.distributed_processing_state[slave_id as usize] = Some(result);
                    }
                }
            }
        }

        let (ret, transitioned) : (Option<JamblerTask>, bool) = match self.state {
            State::Idle => {(None, false)}
            State::DeduceCrcInit => {
                // Check if we have the crc yet
                if self.deduce_crc_init() {
                    // Found crc, go to next state
                    self.state = State::SearchingSmallDelay;
                    // Signal jambler
                    (Some(JamblerTask::HarvestingCrcFound(self.crc_init)), true)
                } 
                else {
                    // not found yet
                    (None, false)
                }
            }
            State::SearchingSmallDelay => {
                // Got enough packets to have a decent smallest delta as delay, move on to recovering channel map
                // Notice the unused channel queue should still be empty, jamblers should be jumping or staying desperately for packets.
                self.searching_small_delay()
            }
            State::RecoveringChannelMap => {
                // Searches the channel map.
                // Does not look for a smaller delay anymore (this requires 2times copy of all anchor points)
                // But also, it is just not worth it because you waited for a long time
                // in the best possible environment just before.
                self.search_channel_map()
            }
            State::WaitingForConnIntervalThreshold => {
                // Wait untill the conn interval thresshold is reached.
                // Will start brute force before transitioning
                self.wait_for_conn_thresshold()
            }
            State::Processing => {
                // Receive slave answers and do your own part
                // TODO If no solution, maybe check for BLE 4
                self.processing()
            }
        };

        (ret, self.ready_for_next_iteration(transitioned))
    }

    /// Returns whether or not the deduction loop would do something useful
    /// if it was to iterate again right now.
    pub fn ready_for_next_iteration(&self, transitioned: bool) -> bool {

        // If transitioned
        if transitioned {
            return true
        }

        // If new connection samples/info
        if self.sample_queue.ready() && self.state != State::Idle {
            return true
        }

        if self.unused_queue.ready() && ![State::Idle, State::DeduceCrcInit, State::SearchingSmallDelay].contains(&self.state) {
            return true
        }


        // If a new command is in the queue
        if self.command_queue.ready() {
            return true
        }

        false
    }

    pub fn get_nb_packets(&self) -> u32 {
        self.total_packets
    }


    fn deduce_crc_init(&mut self) -> bool {
        // Add connection samples to recent ones seen
        while let Some(sample) = self.sample_queue.dequeue() {
            if let Err(re_sample) = self.recents_connection_samples.enqueue(sample) {
                self.recents_connection_samples.dequeue().unwrap();
                self.recents_connection_samples.enqueue(re_sample).unwrap();
            }
        }

        // check crc
        let mut nb_occured: u8 = 0;
        let mut crcs : Vec<u32,20> = Vec::new(); 
        for sample in self.recents_connection_samples.iter() {
            crcs.push(sample.packet.reversed_crc_init).unwrap();
            if let Some(response) = sample.response.as_ref() {
                crcs.push(response.reversed_crc_init).unwrap();
            }
        }

        for crc_init in crcs.iter() {
            // Count how many times this one occurs in the recently seen crc inits
            for other_crc_inits in crcs.iter() {
                if crc_init == other_crc_inits {
                    nb_occured += 1;
                }
            }

            // If above threshold and not the same as the one we already have
            if nb_occured >= CRC_INIT_THRESSHOLD {
                // Found one that occurs as much as we want, save it internally and signal jambler
                self.crc_init = *crc_init;
                return true;
            }

            nb_occured = 0;
        }
        false
    }

    fn searching_small_delay_nb_samples_to_do(&self) -> u8 {
        //let nb_sniffers : u8 = self.start_parameters.nb_slaves + 1;
        //let master_py = self.start_parameters.master_phy;
        //let master_rssi = self.start_parameters.master_rssi;
        // TODO calculate
        10
    }

    fn searching_small_delay(&mut self) -> (Option<JamblerTask>, bool) {
        let new_samples = self.recents_connection_samples.peek().is_some() || self.sample_queue.peek().is_some();
        // Add all samples already seen by CRC init
        while let Some(sample) = self.recents_connection_samples.dequeue() {
            self.process_connection_sample(sample);
        }

        // Add all samples in queue
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }

        if self.anchor_points.len() >= self.searching_small_delay_nb_samples_to_do() as usize {
            // Only way to do this...
            let mut anchor_points_clone = self.anchor_points.clone();
            let mut prev_time = anchor_points_clone.pop().unwrap().time;
            while let Some(ap) = anchor_points_clone.pop() {
                if ap.time - prev_time < self.smallest_time_delta as u64 {
                    self.smallest_time_delta = (ap.time - prev_time) as u32;
                }
                prev_time = ap.time
            }        
            // Change state and signal jambler
            self.state = State::RecoveringChannelMap;    
            // Also set the sniffer positions
            self.sniffer_positions = !self.channel_map_forbidden_positions();
            // Turn off excess 1's
            let mut mask = 0b1;
            let mut nb_1 = 0;
            for _ in 0..37 {
                if nb_1 > self.start_parameters.nb_slaves + 1 {
                    self.sniffer_positions &= !mask;
                }
                else if self.sniffer_positions & mask != 0 {
                    nb_1 += 1;
                }
                mask <<= 1;
            }
            (Some(JamblerTask::StartChannelMap(self.smallest_time_delta, self.sniffer_positions)), true)
        }
        else if new_samples {
            // Recheck the channels they are allowed to use
            // Used channels already have sniffers on them, so no used channels.
            let mut not_allowed = 0u64;
            for (index, channel) in self.channel_map.iter().enumerate() {
                if let ChannelMapEntry::Used = channel {
                    not_allowed |= 0b1 << index
                }
            }
            (Some(JamblerTask::DoNotListenOn(not_allowed)), false)
        }
        else {
            (None, false)
        }
    }


    /// Turns the connection sample into an anchor point and adds it.
    /// NEED THE CRC INIT
    fn process_connection_sample(&mut self, sample: ConnectionSample) {
        // Only keep correctly received packets.
        // Might throw them away once I am sure what causes the false positives.
        if sample.packet.reversed_crc_init != self.crc_init {
            return
        }
        
        // Increment total packets
        self.total_packets += 1;
        // Set channel to used
        self.channel_map[sample.channel as usize] = ChannelMapEntry::Used;
        // Move the sniffer position
        self.sniffer_positions &= !(0b1 << sample.channel);
        self.sniffer_positions |= 0b1 << sample.next_channel;

        // Add to anchor points if it is an anchor point
        if self.is_anchor_point(&sample) {
            if self.anchor_points.iter().all(|ap| if ap.time < sample.time {
                sample.time - ap.time > 7000
            }
            else {
                ap.time - sample.time > 7000
            }
            ) {
                // Pop the oldest one if necessary
                if let Err(ap) = self.anchor_points.push(AnchorPoint{
                    channel: sample.channel,
                    time: sample.time,
                }) {
                    self.anchor_points.pop().unwrap();
                    self.anchor_points.push(ap).unwrap();
                }
            }
            else {
                //println!("Dropping anchor point because there was one within 7500ms, which means it came from 2 sniffers on the same channel")
            }
        }
    }

    fn channel_map_forbidden_positions(&self) -> u64 {
        let mut channels_per_sniffer = 0u64;
        let mut mask = 0b1;
        //let mut nb_unknown : u8 = 0;
        for channel in self.channel_map.iter() {
            if let ChannelMapEntry::Unknown = channel {
                channels_per_sniffer |= mask;
                mask <<= 1;
                //nb_unknown +=1; 
            }
        }
        channels_per_sniffer = !channels_per_sniffer;
        // If sniffers would not have a job, let them listen on used channels
        // There will only be used channels now
        /*
        if nb_unknown < self.
        mask = 0b1;
        for channel in self.channel_map.iter() {
            if let ChannelMapEntry::Used = channel {
                channels_per_sniffer &= !mask;
                mask <<= 1;
            }
        }
        */
        channels_per_sniffer
    }

    fn search_channel_map(&mut self) -> (Option<JamblerTask>, bool) {
        let new_samples = self.unused_queue.peek().is_some() || self.sample_queue.peek().is_some();
        // Process samples and update their positions
        while let Some(sample) = self.unused_queue.dequeue() {
            self.sniffer_positions &= !(0b1 << sample.channel);
            self.sniffer_positions |= 0b1 << sample.next_channel;
            self.channel_map[sample.channel as usize] = ChannelMapEntry::Unused;
        }

        // Add all samples in queue
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }

        if self.channel_map.iter().all(|c| *c != ChannelMapEntry::Unknown) {
            // Have channel map, move on
            let mut chm = 0_u64;
            let mut mask = 0b1;
            for channel in self.channel_map.iter() {
                if let ChannelMapEntry::Used = channel {
                    chm |= mask;
                    mask <<= 1;
                }
            }
            self.state = State::WaitingForConnIntervalThreshold;
            self.processing_state.params.channel_map = chm;
            (Some(JamblerTask::FoundChannelMap(self.processing_state.params.channel_map)), true)
        }
        else if new_samples {

            (Some(JamblerTask::DoNotListenOn(self.sniffer_positions | self.channel_map_forbidden_positions())), false)
        }
        else {
            (None,false)
        }
    }

    fn nb_conn_thresshold(&self) -> u16 {
        40
    }

    fn generate_brute_force_parameters(&mut self) -> Box<BruteForceParametersBox> {
        let bps = &mut self.processing_state.params;
        // Increment version
        bps.version =  bps.version.wrapping_add(1);
        bps.nb_sniffers = self.start_parameters.nb_slaves + 1;

        // Channel map
        let mut chm = 0_u64;
        let mut mask = 0b1;
        for channel in self.channel_map.iter() {
            if let ChannelMapEntry::Used = channel {
                chm |= mask;
                mask <<= 1;
            }
        }
        bps.channel_map = chm;
        // Channel id
        bps.channel_id = calculate_channel_identifier(self.start_parameters.access_address);


        // 5 smallest in a max heap
        const NB_ANCHORS_TO_CONSIDER : usize = 5;
        let mut n_smallest_time_deltas: BinaryHeap<(u32, u32), Max, NB_ANCHORS_TO_CONSIDER> =
            BinaryHeap::new();
        let mut sink = self.anchor_points.clone();
        sink.clear();
        self.processing_state.offset = self.anchor_points.peek().unwrap().time;
        let mut prev_time = self.processing_state.offset;
        sink.push(self.anchor_points.pop().unwrap()).unwrap();
        // Pour them into sink to get them in order
        while let Some(ap) = self.anchor_points.pop() {

            // fill until full
            let (current_time_diff, drift) =
                DeductionState::round_to_1250_with_abs_diff((ap.time - prev_time) as u32);
            if let Err((current_time_diff, drift)) =
                n_smallest_time_deltas.push((current_time_diff, drift))
            {
                // add if smaller than largest or less drift
                let (cur_max, cur_max_drift) = n_smallest_time_deltas.peek().unwrap();
                // If they are not 3250 apart, there is a big chance they have the same number of connection events in-between, take the one with smallest error to 1250
                if current_time_diff < *cur_max - 3750
                    || (current_time_diff < *cur_max + 3750 && drift < *cur_max_drift)
                {
                    n_smallest_time_deltas.pop().unwrap();
                    n_smallest_time_deltas
                        .push((current_time_diff, drift))
                        .unwrap();
                }
            }

            prev_time = ap.time;
            sink.push(ap).unwrap();
        };

        // Calculate gcd of n smallest. They come in random order!
        let fold_base = n_smallest_time_deltas.peek().unwrap().0;
        self.processing_state.conn_interval = n_smallest_time_deltas
            .into_iter()
            .fold(fold_base, |running_gcd, next_time_delta| {
                running_gcd.gcd(next_time_delta.0)
            });

        // Build the brute force pairs
        // and
        // Calculate drift from absolute time (first anchor point)
        bps.relative_counters_and_channels.clear();
        let first_sample = sink.peek().unwrap();
        prev_time = self.processing_state.offset;
        bps.relative_counters_and_channels.push((0, first_sample.channel)).unwrap();
        self.anchor_points.push(sink.pop().unwrap()).unwrap();

        let mut drift : i64 = 0;
        let mut running_counter = 0_u16;
        while let Some(ap) = self.anchor_points.pop() {
            let time_delta = ap.time - prev_time;
            let (rounded, event_counter_diff) = DeductionState::round_to_conn_interval(
                time_delta, self.processing_state.conn_interval);

            running_counter += event_counter_diff;
            drift += time_delta as i64 - rounded as i64;
            bps.relative_counters_and_channels.push((running_counter, ap.channel)).unwrap();

            prev_time = ap.time;
            self.anchor_points.push(ap).unwrap();
        }
        self.processing_state.drift = drift;

        // Clean distributed state
        self.processing_state.distributed_processing_state.clear();
        self.processing_state.distributed_processing_state.extend((0..(self.start_parameters.nb_slaves+1)).map(|_| None));
        
        //println!("Brute forcing with conn {}, id {}, map {:037b}, drift {}, offset {}, version {}", self.processing_state.conn_interval, bps.channel_id, bps.channel_map, self.processing_state.drift, self.processing_state.offset, bps.version);

        let b = BruteForceParametersBox::alloc().expect("BruteForceParameters heap overflow");
        b.init(bps.clone())

    }

    fn wait_for_conn_thresshold(&mut self) -> (Option<JamblerTask>, bool) {
        let new_samples = self.unused_queue.peek().is_some() || self.sample_queue.peek().is_some();
        while let Some(sample) = self.unused_queue.dequeue() {
            self.sniffer_positions &= !(0b1 << sample.channel);
            self.sniffer_positions |= 0b1 << sample.next_channel;
            self.channel_map[sample.channel as usize] = ChannelMapEntry::Unused;
        }
        // Add all samples in queue
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }
        
        if self.anchor_points.len() > self.nb_conn_thresshold() as usize {
            // start processing
            let ret = self.generate_brute_force_parameters();
            self.state = State::Processing;
            (Some(JamblerTask::DistributedBruteForce(ret)),true)
        }
        else if new_samples {
            (Some(JamblerTask::DoNotListenOn(self.sniffer_positions | !self.processing_state.params.channel_map)), false)

        }
        else {
            (None, false)
        }
    }

    fn processing(&mut self) -> (Option<JamblerTask>, bool) {
        let new_samples = self.unused_queue.peek().is_some() || self.sample_queue.peek().is_some();
        while let Some(sample) = self.unused_queue.dequeue() {
            self.sniffer_positions &= !(0b1 << sample.channel);
            self.sniffer_positions |= 0b1 << sample.next_channel;
            self.channel_map[sample.channel as usize] = ChannelMapEntry::Unused;
        }
        // Add all samples in queue
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }

        // If master did not do its work yet, do it now
        if self.processing_state.distributed_processing_state.first().unwrap().is_none() {
            // Do you part
            let master_slice_result = DeductionState::brute_force_slice(&self.processing_state.params, 0);
            self.processing_state.distributed_processing_state[0] = Some(master_slice_result);
        }
        
        if self.processing_state.distributed_processing_state.iter().all(|c| c.is_some()) {
            // They are all some, check if a solution was found, none or no yet.
            let mut aggregate_result = CounterInterval::NoSolutions;
            for brute_force_result in self.processing_state.distributed_processing_state.iter() {
                match brute_force_result.as_ref().unwrap() {
                    CounterInterval::ExactlyOneSolution(c) => {
                        // Multiple have 1 => multiple together
                        if let CounterInterval::ExactlyOneSolution(_) = aggregate_result {
                            aggregate_result = CounterInterval::MultipleSolutions;
                            break
                        }
                        else {
                            aggregate_result = CounterInterval::ExactlyOneSolution(*c);
                        }
                    }
                    CounterInterval::MultipleSolutions => {
                        aggregate_result = CounterInterval::MultipleSolutions;
                        break
                    }
                    CounterInterval::NoSolutions => {}
                }
            }

            match aggregate_result {
                CounterInterval::ExactlyOneSolution(counter) => {
                    // Found parameters
                    self.state = State::Idle;
                    let d = DeducedParameters {
                        access_address: self.start_parameters.access_address,
                        master_phy: self.start_parameters.master_phy,
                        slave_phy: self.start_parameters.slave_phy,
                        conn_interval: self.processing_state.conn_interval,
                        channel_map: self.processing_state.params.channel_map,
                        crc_init: self.crc_init,
                        first_capture_time: self.processing_state.offset,
                        drift_since_first_capture: self.processing_state.drift,
                        counter_at_first_capture: counter,

                    };
                    let b = DeducedParametersBox::alloc().expect("DeducedParameters heap overflow");
                    let b = b.init(d);
                    (Some(JamblerTask::DeducedParameters(b)), true)
                }
                CounterInterval::MultipleSolutions => {
                    // Recalculate brute force parameters and try again
                    while let Some(sample) = self.sample_queue.dequeue() {
                        self.process_connection_sample(sample);
                    }
                    let bf = self.generate_brute_force_parameters();
                    (Some(JamblerTask::DistributedBruteForce(bf)), true)
                }
                CounterInterval::NoSolutions => {
                    // Error, reset
                    //println!("No solutions");
                    self.reset(false);
                    panic!("no solutions");
                    //(None, true)
                }
            }
        }
        else if new_samples {
            (Some(JamblerTask::DoNotListenOn(self.sniffer_positions | !self.processing_state.params.channel_map)), false)

        }
        else {
            (None, false)
        }
    }

    fn brute_force_slice(parameters: &BruteForceParameters, sniffer_id: u8) -> CounterInterval {
        // Final one will take care of rest
        let interval_size = u16::MAX / (parameters.nb_sniffers as u16);
        // Both are inclusive
        let start = sniffer_id as u16 * interval_size;
        let end = if sniffer_id == parameters.nb_sniffers - 1 {
            u16::MAX
        }
        else {
            (sniffer_id + 1) as u16 * interval_size - 1
        };

        let (channel_map_bool_array, remapping_table, _, nb_used) =
            generate_channel_map_arrays(parameters.channel_map);


        let mut running_event_counter;

        let mut found_counter: Option<u32> = None;
        let mut inconsistency: bool;
        for potential_counter in start..=end {
            // reset inconsistency
            inconsistency = false;
            for (relative_counter, channel) in parameters.relative_counters_and_channels.iter() {
                running_event_counter =  potential_counter.wrapping_add(*relative_counter);
                let channel_potential_counter = csa2_no_subevent(
                    running_event_counter as u32,
                    parameters.channel_id as u32,
                    &channel_map_bool_array,
                    &remapping_table,
                    nb_used,
                );

                // If we get another one than expected, go to next counter
                if channel_potential_counter != *channel {
                    inconsistency = true;
                    break;
                }
            }

            // If there was no inconsistency for this potential counter save it
            if !inconsistency {
                match found_counter {
                    None => {
                        // the first one without inconsistency, save it
                        found_counter = Some(potential_counter as u32);
                    }
                    Some(_) => {
                        // There was already another one without inconstistency, we have multiple solutions
                        return CounterInterval::MultipleSolutions;
                    }
                }
            }
        }

        // The fact we get here, we did not find mutliple solutions, must be one or none.
        // Remember for exactly one you need to run through the whole range
        match found_counter {
            None => {
                // There were no solutions
                CounterInterval::NoSolutions
            }
            Some(counter) => 
                CounterInterval::ExactlyOneSolution(counter as u16),
        }
    }


    /// Something is an anchorpoint
    ///  when you were listening on the channel for longer than the worst case.
    /// The packet phy will always be the master phy and that is the one  
    fn is_anchor_point(&self, connection_sample: &ConnectionSample) -> bool {
        // declare the constants for each the on air time in micros of each phy
        // TODO account for state change time...
        static UNCODED_1M_SEND_TIME: u32 = 2128;
        static UNCODED_2M_SEND_TIME: u32 = 2128 / 2;
        static CODED_S2_SEND_TIME: u32 = 4542; // AA, CI, TERM1 in S8
        static CODED_S8_SEND_TIME: u32 = 17040;
        // TODO get from connection sample or also from reset
        let actual_slave_phy: BlePhy = self.start_parameters.slave_phy;
        let actual_master_phy: BlePhy = self.start_parameters.master_phy;

        // THE RADIO ONLY LISTENS ON MASTER PHY FIRST
        // Does not matter if you caught response or not
        // TODO changed: WRONG, the anchor point time you would take from the start of the slave would give you a wrong anchor point time.
        //let mut previous_packet_start: u32 = if actual_master_phy == actual_slave_phy {
        let mut previous_packet_start: u32 = if false {
            // If they are the same, return either one
            // You would have caught the previous packet either way because same phy
            match actual_master_phy {
                BlePhy::Uncoded1M => UNCODED_1M_SEND_TIME,
                BlePhy::Uncoded2M => UNCODED_2M_SEND_TIME,
                BlePhy::CodedS2 => CODED_S2_SEND_TIME,
                BlePhy::CodedS8 => CODED_S8_SEND_TIME,
            }
        } else {
            // If they are different, jambler would not have caught the previous one because it was listening on the wrong phy and we actually have to go back the full subevent
            let m_time = match actual_master_phy {
                BlePhy::Uncoded1M => UNCODED_1M_SEND_TIME,
                BlePhy::Uncoded2M => UNCODED_2M_SEND_TIME,
                BlePhy::CodedS2 => CODED_S2_SEND_TIME,
                BlePhy::CodedS8 => CODED_S8_SEND_TIME,
            };
            let s_time = match actual_slave_phy {
                BlePhy::Uncoded1M => UNCODED_1M_SEND_TIME,
                BlePhy::Uncoded2M => UNCODED_2M_SEND_TIME,
                BlePhy::CodedS2 => CODED_S2_SEND_TIME,
                BlePhy::CodedS8 => CODED_S8_SEND_TIME,
            };
            m_time + 150 + s_time
        };

        // account for clock drift. 50 ppm active clock drift + own clock drift
        // TODO would need own clock drift here. I know its less than 20 ppm tho for dongle.
        // Yes this incorporates range delay
        let extra_delay_percentage: f32 = 1.0 + (50.0 + 20.0) / 1_000_000.0;
        previous_packet_start =
            ((previous_packet_start as f32) * extra_delay_percentage) as u32 + 1;

        // account for active clock drift master and my clock drift and allowance
        // 2 ms allowance + range delay for 3 km
        previous_packet_start += 2 + 24;

        // If we listened for longer than the time it would have taken to reach this, return true
        previous_packet_start < connection_sample.time_on_channel
    }

    fn round_to_1250_with_abs_diff(number: u32) -> (u32, u32) {
        let mod_1_25_ms: u32 = number % 1250;
        // get it to the closest counter point from reference
        let discrete_relative_timepoint: u16;
        if mod_1_25_ms < (1250 / 2) {
            // closest to lower counter point, just let / drop it
            discrete_relative_timepoint = (number / 1250) as u16;
        } else {
            // closest to upper value counter point, round to upper by + 1
            discrete_relative_timepoint = (number / 1250) as u16 + 1;
        }
        let rounded: u32 = 1250 * discrete_relative_timepoint as u32;
        let diff = (number as i32 - rounded as i32).abs() as u32;
        (rounded, diff)
    }

    fn round_to_conn_interval(number: u64, conn_interval: u32) -> (u32, u16) {
        let mod_conn_int: u32 = (number % conn_interval as u64) as u32;
        // get it to the closest counter point from reference
        let discrete_relative_timepoint: u16;
        if mod_conn_int < (conn_interval / 2) {
            // closest to lower counter point, just let / drop it
            discrete_relative_timepoint = (number / conn_interval as u64) as u16;
        } else {
            // closest to upper value counter point, round to upper by + 1
            discrete_relative_timepoint = (number / conn_interval as u64) as u16 + 1;
        }
        let rounded: u32 = conn_interval * discrete_relative_timepoint as u32;
        (rounded, discrete_relative_timepoint)
    }

    /// Turns the channel map entries into a u64 bit mask
    fn channel_map_entries_to_mask(entries: &[ChannelMapEntry; 37]) -> u64 {
        let mut channel_map_in_u64: u64 = 0;
        (0..entries.len()).for_each(|channel| {
            if let ChannelMapEntry::Used = entries[channel] {
                channel_map_in_u64 |= 1 << channel;
            } else if entries[channel] != ChannelMapEntry::Unused {
                panic!("Channel map was not complete in used/unused when trying to create a u64 mask for it")
            }
        });
        channel_map_in_u64
    }
}