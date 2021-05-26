use core::fmt::Debug;
use super::{brute_force::{BruteForceParameters, BruteForceResult}, control::{DeducerToMaster, MasterToDeducer, BruteForceParametersBox, DeducedParametersBox}, distributions::{geo_qdf, prob_of_seeing_if_used}};
use crate::{ble_algorithms::csa2::{calculate_channel_identifier}, jambler::BlePhy};
// vscode gives fake warnings here, thinking we are using std for some reason...
#[allow(unused_imports)]
use num::{Integer, integer::{binomial, gcd}, traits::Float};

use heapless::{ Vec, pool::{ singleton::{Box, Pool}}, spsc::{Consumer, Producer}, spsc::Queue};



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
    /// (counter_first, channel map mask, unsure (to check) channels mask)
    ExactlyOneSolution(u16, u64, u64),
    /// Indicates there were mutliple solutions and we need more information
    MultipleSolutions,
    /// If no solution for any slice error. Otherwise ok.
    NoSolutions,
}


pub struct UnsureChannelEvent {
    pub channel: u8,
    pub time: u64,
    pub event_counter: u16,
    pub seen: bool
}


#[derive(Debug)]
/// A struct holding all important information a subevent can hold for reversing the parameters of a connection.
pub struct ConnectionSample {
    pub slave_id: u8,
    pub channel: u8,
    pub time: u64,
    pub silence_time_on_channel: u32,
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
    pub last_time : u64,
    pub last_counter: u16
}


/// Anchorpoint ordered on the time it was caught.
#[derive(Debug, Clone, Copy)]
pub struct AnchorPoint {
    /// The absolute time the anchorpoint was caught as a multiple of 1250. 2**16*1250 longer than 4_000_000
    pub channel: u8,
    pub time: u64,
}

/// Necessary information to start deduction.
#[derive(Debug, Clone, Copy)]
pub struct DeductionStartParameters {
    access_address : u32,
    master_phy : BlePhy,
    slave_phy : BlePhy,
    packet_loss : f32,
    nb_sniffers : u8,
    conn_interval_success_rate: f32,
    channel_map_success_rate: f32,
    anchor_point_success_rate: f32,
    silence_percentage: f32,
    max_brute_forces: u16
}
impl Default for DeductionStartParameters {
    fn default() -> Self {
        Self {
            access_address: u32::MAX,
            master_phy: BlePhy::Uncoded1M,
            slave_phy: BlePhy::Uncoded1M,
            packet_loss : f32::MAX,
            nb_sniffers: 0,
            conn_interval_success_rate: f32::MAX,
            channel_map_success_rate: f32::MAX,
            anchor_point_success_rate: f32::MAX,
            silence_percentage: f32::MAX,
            max_brute_forces: 0
        }
    }
}

/// Interval state when processing.
struct ProcessingState {
    params: BruteForceParameters,
    drift: i32,
    offset: u64,
    last_time: u64,
    last_counter: u16,
    distributed_processing_state: Vec<Option<CounterInterval>, 64>
}

impl Default for ProcessingState {
    fn default() -> Self {
        Self {
            params: BruteForceParameters::default(),
            drift: 0,
            offset: 0,
            last_time: 0,
            last_counter: 0,
            distributed_processing_state: Vec::new(),
        }
    }
}

#[derive(PartialEq, Debug)]
enum State {
    Idle,
    /// Capture a couple packets until there is a CRC.
    DeduceCrcInit,
    /// Recovering the conn interval
    RecoverConnInterval,
    /// Recovering channel map.
    RecoveringChannelMap,
    /// We are processing, this one but we may also be waiting on slaves.
    Processing,
    /// Wait for feedback from the jamblers that they did or did not hear a channel
    /// when it was supposed to appear.
    DecideUnsureChannels
}


///
/// ## Everything is public for testing purposes
pub struct DeductionState<'a> {
    state: State,
    start_parameters: DeductionStartParameters,
    capture_chance: f32,


    silence_time: u32,
    time_to_switch: u32,

    recents_connection_samples: Queue<ConnectionSample, 10>,
    crc_init: u32,
    
    anchor_points: Vec<AnchorPoint, 256>,
    nb_packets_first_single_interval : u32,
    nb_durations_gcd_thres : u32,
    connection_interval : u32,


    channel_map: [ChannelMapEntry; 37],
    fn_chance_threshold: f32,
    chm_nb_events_waited : u16,

    processing_state: ProcessingState,
    total_packets: u32,

    found_counter: u16,
    found_time: u64,
    found_chm_unsure: u64,
    unsure_channels_remaining_occurrences : [u8;37],

    sample_queue : Consumer<'a, ConnectionSample,16>,
    unused_queue : Consumer<'a, UnusedChannel,16>,
    command_queue : Consumer<'a, MasterToDeducer,16>,
    request_queue : Producer<'a, DeducerToMaster,16>,
    brute_force_result_queue : Consumer<'a, BruteForceResult,16>,
    unsure_channel_queue : Consumer<'a, UnsureChannelEvent,16>,
}

impl<'a> DeductionState<'a> {
    /// Used for initialising the static variable
    pub fn new(
        sample_queue : Consumer<'a, ConnectionSample,16>,
        unused_queue : Consumer<'a, UnusedChannel,16>,
        command_queue : Consumer<'a, MasterToDeducer,16>,
        request_queue : Producer<'a, DeducerToMaster,16>,
        brute_force_result_queue : Consumer<'a, BruteForceResult,16>,
        unsure_channel_queue : Consumer<'a, UnsureChannelEvent,16>,
    ) -> Self {
        DeductionState {
            state: State::Idle,
            channel_map: [ChannelMapEntry::Unknown; 37],
            fn_chance_threshold: f32::MAX,
            chm_nb_events_waited : u16::MAX,
            capture_chance: 0.0,
            crc_init: core::u32::MAX,
            time_to_switch: u32::MAX,
            silence_time: u32::MAX,
            recents_connection_samples: Queue::new(),
            anchor_points: Vec::new(),
            nb_packets_first_single_interval : u32::MAX,
            nb_durations_gcd_thres : u32::MAX,
            connection_interval : u32::MAX,

            total_packets: 0,


            found_counter: 0,
            found_time: 0,
            found_chm_unsure: 0,
            unsure_channels_remaining_occurrences : [0u8;37],

            sample_queue,
            unused_queue,
            command_queue,
            request_queue,
            brute_force_result_queue,
            unsure_channel_queue,

            start_parameters: DeductionStartParameters::default(),
            processing_state: ProcessingState::default(),
        }
    }

    pub fn reset(&mut self, was_reset_command: bool) {
        self.state = State::Idle;
        self.capture_chance = 0.0;
        self.channel_map = [ChannelMapEntry::Unknown; 37];
        self.fn_chance_threshold = f32::MAX;
        self.chm_nb_events_waited = 0;
        self.crc_init = core::u32::MAX;
        // the maximum observed connection interval in microseconds
        // defaults to 4 seconds, which is the maximum according to the BLE specification
        self.time_to_switch = u32::MAX;
        self.silence_time = u32::MAX;
        self.recents_connection_samples = Queue::new();
        self.anchor_points = Vec::new();
        self.nb_packets_first_single_interval = u32::MAX;
        self.nb_durations_gcd_thres = u32::MAX;
        self.connection_interval = u32::MAX;
        self.total_packets = 0;


        self.found_counter = 0;
        self.found_time = u64::MAX;
        self.found_chm_unsure = 0;
        self.unsure_channels_remaining_occurrences = [0u8;37];

        // Start parameters and state will just be overwritten when we get to their state.
        // They are large, waste no time



        if was_reset_command {
            // Flush packet queues
            while self.sample_queue.dequeue().is_some() {}
            while self.unused_queue.dequeue().is_some() {}
            while self.brute_force_result_queue.dequeue().is_some() {}
            while self.unsure_channel_queue.dequeue().is_some() {}
            self.state = State::Idle;
        }
    }

    fn request_master(&mut self, request: DeducerToMaster) {
        self.request_queue.enqueue(request).expect("Request queue flooded! Should never happen!!")
    }

    pub fn start(&mut self, params: DeductionStartParameters) {

        // reset and flush queues
        self.reset(true);

        // Set info
        self.state = State::DeduceCrcInit;
        self.start_parameters = params;

        // Calculate capture chance
        self.capture_chance = (1.0 - self.start_parameters.silence_percentage) * (1.0 - self.start_parameters.packet_loss) * (self.start_parameters.nb_sniffers as f32 / 37.0);

        // Return the time_to_switch
        let one_exchange_time = phy_to_max_time(&self.start_parameters.master_phy) + 152 + 24 + phy_to_max_time(&self.start_parameters.slave_phy) + 152 + 24;
        // If you want to be 90% sure a previous one would have occurred before if there were some, do this
        let necessary_exchanges = geo_qdf(1.0 - self.start_parameters.packet_loss, self.start_parameters.anchor_point_success_rate);
        self.silence_time = one_exchange_time * necessary_exchanges;
        self.time_to_switch = (self.silence_time as f32 / self.start_parameters.silence_percentage) as u32; // 0.05 = 0.95 percent of time listening

        // Ask master yourself.
        self.request_master(DeducerToMaster::SearchPacketsForCrcInit(self.time_to_switch));
    }

    /// Keep looping while second part is true.
    /// Wake the master task if first one is true.
    pub fn deduction_loop(&mut self) -> (bool, bool) {

        // Check commands first
        // Check for a start or reset, the last one counts
        let mut new_command = None;
        while let Some(command) = self.command_queue.dequeue() {new_command = Some(command)}
        if let Some(command) = new_command {
            match command {
                MasterToDeducer::Reset => {self.reset(true)}
                MasterToDeducer::Start(params) => {
                    self.start(params);
                    return (true, true)
                }
            }
        }

        let wake_master = match self.state {
            State::Idle => {false}
            State::DeduceCrcInit => {self.deduce_crc_init()}
            State::RecoverConnInterval => { self.recover_conn_interval()}
            State::RecoveringChannelMap => {self.search_channel_map()}
            State::Processing => { self.processing()}
            State::DecideUnsureChannels => {self.decide_unsure_channels()}
        };

        (wake_master, self.ready_for_next_iteration())
    }

    /// Returns whether or not the deduction loop would do something useful
    /// if it was to iterate again right now.
    pub fn ready_for_next_iteration(&self) -> bool {

        if self.command_queue.ready() {return true}

        match &self.state {
            State::Idle => {false}
            State::DeduceCrcInit => {self.sample_queue.ready()}
            State::RecoverConnInterval => {self.sample_queue.ready()}
            State::RecoveringChannelMap => {self.sample_queue.ready() || self.unsure_channel_queue.ready()}
            State::Processing => {self.brute_force_result_queue.ready()}
            State::DecideUnsureChannels => {self.unsure_channel_queue.ready()}
        }
    }

    pub fn get_nb_packets(&self) -> u32 {
        self.total_packets
    }


    fn deduce_crc_init(&mut self) -> bool {
        const CRC_INIT_THRESSHOLD : u8 = 3;

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

                // Add all samples already seen by CRC init
                while let Some(sample) = self.recents_connection_samples.dequeue() {
                    self.process_connection_sample(sample);
                }

                // Calculate the packet thresholds for GCD and first occurrence
                // + 1 because this is packet and we need durations
                self.nb_packets_first_single_interval = geo_qdf(self.capture_chance, self.start_parameters.conn_interval_success_rate) + 1;
                // The DURATIONS satisfying maximum time before PPM drift to high.
                self.nb_durations_gcd_thres = geo_qdf(1.0/2.0, self.start_parameters.conn_interval_success_rate) + 2;

                // To give master good start, give him the known used channels up until now
                let used_channels_until_now = self.channel_map.iter().enumerate()
                .filter_map(|(i, c)| if matches!(*c, ChannelMapEntry::Used) {Some(i)} else {None})
                .fold(0u64, |running_mask, channel| running_mask | (1 << channel));

                self.request_master(DeducerToMaster::SearchPacketsForConnInterval(self.time_to_switch, self.crc_init, used_channels_until_now));
                self.state = State::RecoverConnInterval;
                // Signal master to wake up.
                return true;
            }

            nb_occured = 0;
        }
        false
    }

    fn recover_conn_interval(&mut self) -> bool {
        const ROUND_THRES : u32 = (625f64 * (1000000f64 / (500f64+20f64))) as u32;

        // Add all samples in queue
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }

        // Check if there are enough duration below ROUND_THRES to do the GCD
        let nb_durations_below_round_thres = self.anchor_points.as_slice().windows(2).filter(|w| (w[1].time - w[0].time) as u32 <= ROUND_THRES).count() as u32;
        let conn_interval_found = if nb_durations_below_round_thres >= self.nb_durations_gcd_thres {
            // Calculate the GCD of first self.nb_durations_gcd_thres
            self.connection_interval = self.anchor_points.as_slice().windows(2)
                .map(|w| (w[1].time - w[0].time) as u32)
                .filter(|d| *d <= ROUND_THRES)
                .take(self.nb_durations_gcd_thres as usize)
                .map(round_to_1250)
                .reduce(gcd).expect("Tried to calculate GCD with no legal durations.");
            
            true
        } 
        else if self.anchor_points.len() as u32 >= self.nb_packets_first_single_interval {
            self.connection_interval = self.anchor_points.as_slice().windows(2)
            .map(|w| (w[1].time - w[0].time) as u32).min().unwrap();
            self.connection_interval = round_to_1250(self.connection_interval);
            true
        } 
        else {false};

        if conn_interval_found {
            // Get the mask of channels we still need to discover
            let todo_mask = self.channel_map.iter().enumerate()
                .filter_map(|(channel, entry)| if let ChannelMapEntry::Unknown = entry {Some(channel as u8)} else {None})
                .fold(0u64, |running_mask, channel| running_mask | (1 << channel));

            // Calculate the time to listen on each channel
            // Also calculates and sets the threshold.
            let time_to_listen_in_us = self.calculate_time_to_listen();

            // Send to master and finish
            self.request_master(DeducerToMaster::StartChannelMap(time_to_listen_in_us, todo_mask, self.crc_init));
            self.state = State::RecoveringChannelMap;
            return true;
        }

        false
    }

    fn calculate_time_to_listen(&mut self) -> u32 {
        // calculate number of events to wait and the thresshold
        let possible_nb_events = 40u16..1024;
        let threshes = (1..25).map(|i| 0.01 * i as f32).rev();
        // For the given brute force max, find the lowest number of events for which a thresshold exists, for which the max error is lower than the given one
        // Brute force this for now
        let found = possible_nb_events.filter_map(|nb_events| {
            // Lower the threshes (.rev() and take) as long as the threshold for this amount of events would require less then max brute forces.
            // .rev() and take_while is the same as not rev and skip while.
            // Lowering the threshold = higher amount of false negatives considered possible = more brute forces to account for this
            let mut bf_threshes = threshes.clone().take_while(|thresshold| {
                // Check if this would go over the BF thresh
                // Max over nb_unused -> this is the observed
                let nbu = (0u8..37).map(|nb_unused_seen| 
                    // Sum combo all above thresshold for the nb of false negatives it would be for this nb of unused
                    (0u8..=nb_unused_seen)
                    .filter_map(|nb_false_neg| 
                        if prob_of_seeing_if_used(nb_unused_seen, nb_false_neg,nb_events, 1.0 - self.start_parameters.packet_loss) >= *thresshold {
                            // binom will only be calculated for things above the threshold and lowering it will short circuit.
                            // Thus this will stop before overflow, because last sum bigger then max is ok.
                            // TODO check this
                            Some(binomial(nb_unused_seen as u32, nb_false_neg as u32))
                        } else {None}) // Packet loss only! 
                    .sum::<u32>()
                ).max().unwrap();
                nbu > (self.start_parameters.max_brute_forces as u32)
            });
 
             // You are given valid brute force thresholds, which go lower and lower. 
             // We need one for this amount of events to be ok.
             // Lower = more brute force work. -> we want highest. -> find first -> find.
             let found = bf_threshes.find(|thresshold| {
                     // Max over nb_used -> this is the unknown
                     let err =(1u8..=37).map(|nb_used| 
                         // Sum all below thresshold for the nb of false negatives possible
                         (0u8..=nb_used)
                         .map(|nb_false_neg|
                            prob_of_seeing_if_used(37 -nb_used + nb_false_neg, nb_false_neg,nb_events, 1.0 - self.start_parameters.packet_loss)
                                )
                         .filter(|fn_chance| *fn_chance < *thresshold).sum::<f32>()
                     ).reduce(|a,b| if a > b {a} else {b}).unwrap();
                     err <= self.start_parameters.channel_map_success_rate
             });
             found.map(|thress| (nb_events, thress))
         }).next();
 
         if let Some((nb_events, thres)) = found {
            self.chm_nb_events_waited = nb_events;
            self.fn_chance_threshold = thres;
            (nb_events as f32 * self.connection_interval as f32 * (1.0 + 520.0/1_000_000.0)).ceil() as u32
         }
         else {
             panic!("Impossible chance parameters, no nb events and threshold found for brute force")
         }
    }

    /// Turns the connection sample into an anchor point and adds it.
    fn process_connection_sample(&mut self, sample: ConnectionSample) {
        // Increment total packets
        self.total_packets += 1;
        // Only keep correctly received packets.
        // Might throw them away once I am sure what causes the false positives.
        if sample.packet.reversed_crc_init != self.crc_init {
            // TODO check if this was radio bug or not
            return
        }
        
        // Set channel to used
        self.channel_map[sample.channel as usize] = ChannelMapEntry::Used;
        
        // Add to anchor points if it is an anchor point
        if self.is_anchor_point(&sample) {
            let new_ap = AnchorPoint{
                channel: sample.channel,
                time: sample.time,
            };
            // Add anchor point. Bump out oldest if necessary.
            if let Err(retry) = self.anchor_points.push(new_ap) {
                // Bump out oldest one. Very inefficient but should never happen anyway.
                for i in 0..(self.anchor_points.len() - 1) {
                    self.anchor_points[i] = self.anchor_points[i + 1];
                }
                self.anchor_points.pop();
                self.anchor_points.push(retry).unwrap();
            }
            
            // New one is at the end and all previous are sorted.
            // Let it sink towards the head as long as it is earlier than the next packet
            for i in (0..(self.anchor_points.len() - 1)).rev() {
                if self.anchor_points[i].time > self.anchor_points[i + 1].time {
                    self.anchor_points.swap(i, i+1);
                }
            }
        }
    }


    fn search_channel_map(&mut self) -> bool {
        // Process unused and samples
        while let Some(sample) = self.unused_queue.dequeue() {
            self.channel_map[sample.channel as usize] = ChannelMapEntry::Unused;
        }
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }

        if self.channel_map.iter().all(|c| *c != ChannelMapEntry::Unknown) {
            // Have seen channel map, move on
            let bf_request_params = self.prepare_brute_force();
            self.state = State::Processing;
            let bf_chm = bf_request_params.seen_channel_map;
            self.request_master(DeducerToMaster::DistributedBruteForce(bf_request_params, bf_chm));
            return true;
        }
        false
    }


    fn prepare_brute_force(&mut self) -> Box<BruteForceParametersBox> {

        let bps = &mut self.processing_state.params;
        // Increment version
        bps.version =  bps.version.wrapping_add(1);
        bps.nb_sniffers = self.start_parameters.nb_sniffers;
        bps.threshold = self.fn_chance_threshold;
        bps.nb_events = self.chm_nb_events_waited;
        bps.packet_loss = self.start_parameters.packet_loss;

        bps.seen_channel_map = self.channel_map.iter().enumerate()
        .filter_map(|(i, c)| if matches!(*c, ChannelMapEntry::Used) {Some(i)} else {None})
        .fold(0u64, |running_mask, channel| running_mask | (1 << channel));

        // Channel id
        bps.channel_id = calculate_channel_identifier(self.start_parameters.access_address);


        // Build the brute force pairs
        // and
        // Calculate drift from absolute time (first anchor point)
        bps.relative_counters_and_channels.clear();
        bps.relative_counters_and_channels.push((0, self.anchor_points[0].channel)).unwrap();

        // Necessary borrows to prevent conflict with bps
        let anchor_points = & self.anchor_points;
        let connection_interval = self.connection_interval;

        let (drift, running_counter) = anchor_points.as_slice().windows(2)
            .map(|w|{ 
                let time_delta = (w[1].time - w[0].time) as u32;
                let (rounded, event_counter_diff) = round_to_conn_interval(
                    time_delta, connection_interval);
                (event_counter_diff, time_delta as i32 - rounded as i32, w[1].channel)
            })
            .fold((0i32, 0u16), |(drift, running_counter),(delta_events, new_drift, channel)|{
                bps.relative_counters_and_channels.push((running_counter, channel)).unwrap();
                (drift + new_drift, running_counter + delta_events)
            });

        // Processing state
        self.processing_state.offset = self.anchor_points[0].time;
        self.processing_state.drift = drift;
        self.processing_state.last_counter = running_counter;
        self.processing_state.last_time = self.anchor_points.last().unwrap().time;

        // Clean distributed state
        self.processing_state.distributed_processing_state.clear();
        self.processing_state.distributed_processing_state.extend((0..(self.start_parameters.nb_sniffers)).map(|_| None));
        
        //println!("Brute forcing with conn {}, id {}, map {:037b}, drift {}, offset {}, version {}", self.processing_state.conn_interval, bps.channel_id, bps.channel_map, self.processing_state.drift, self.processing_state.offset, bps.version);

        let b = BruteForceParametersBox::alloc().expect("BruteForceParameters heap overflow");
        b.init(bps.clone())

    }

    fn processing(&mut self) -> bool {


        // Add all samples in queue
        while let Some(sample) = self.sample_queue.dequeue() {
            self.process_connection_sample(sample);
        }
        // Check for results from brute forcers
        while let Some(bf_result) = self.brute_force_result_queue.dequeue() {
            // Only add if it is the current version
            if bf_result.version == self.processing_state.params.version {
                self.processing_state.distributed_processing_state[bf_result.slave_id as usize] = Some(bf_result.result);
            }
        }

        // Wait for all results to be in. Yes, you could preemptively restart on seeing 2 exactly ones or multiples, but this would make coordination much more difficult.
        // Just wait until they are all done.
        if self.processing_state.distributed_processing_state.iter().all(|c| c.is_some()) {
            // Brute forces will each check a slice of counter values -> when found only 1 will have exactly one solution -> no need to merge here, just check for all No or 1 Exactly
            let merged = self.processing_state.distributed_processing_state.iter().map(|c| c.unwrap())
                .reduce(|a,b| {
                    match a {
                        CounterInterval::ExactlyOneSolution(_,_,_) => {
                            match b {
                                CounterInterval::ExactlyOneSolution(_, _, _) => {CounterInterval::MultipleSolutions}
                                CounterInterval::MultipleSolutions => {CounterInterval::MultipleSolutions}
                                CounterInterval::NoSolutions => {a}
                            }
                        }
                        CounterInterval::MultipleSolutions => {CounterInterval::MultipleSolutions}
                        CounterInterval::NoSolutions => {b}
                    }
                }).unwrap();

            // Check final result. Master will always have to be notified
            match merged {
                CounterInterval::ExactlyOneSolution(counter, chm, chm_todo) => {
                    // Done, signal master for following todo channels

                    // Remember for next state
                    self.found_counter = counter.wrapping_add(self.processing_state.last_counter);
                    self.found_time = self.processing_state.last_time;
                    self.found_chm_unsure = chm;
                    
                    // Calculate amount of misses before we decide a channel is unused
                    let unsure_channels_unused_threshold = geo_qdf(1.0 - self.start_parameters.packet_loss, 0.95) as u8;
                    self.unsure_channels_remaining_occurrences = [0u8;37];
                    (0..37usize).for_each(|c| {
                        if (1u64 << c) & chm_todo != 0 {
                            self.unsure_channels_remaining_occurrences[c] = unsure_channels_unused_threshold;
                        }
                    });

                    self.state = State::DecideUnsureChannels;
                    
                    let conn_params = DeducedParameters {
                        access_address: self.start_parameters.access_address,
                        master_phy: self.start_parameters.master_phy,
                        slave_phy: self.start_parameters.slave_phy,
                        conn_interval: self.connection_interval,
                        channel_map: self.found_chm_unsure,
                        crc_init: self.crc_init,
                        last_time: self.found_time,
                        last_counter: self.found_counter,
                    };
                    let conn_params = DeducedParametersBox::alloc().expect("Deduced params overflow").init(conn_params);
                    self.request_master(DeducerToMaster::ListenForUnsureChannels(conn_params, chm_todo));
                }
                CounterInterval::MultipleSolutions => {
                    // REGEN bfs and hope for new packets
                    let new_bf = self.prepare_brute_force();
                    let new_bf_chm = new_bf.seen_channel_map;
                    self.request_master(DeducerToMaster::DistributedBruteForce(new_bf, new_bf_chm));
                }
                CounterInterval::NoSolutions => {
                    // RESET 
                    // Restart yourself with your own parameters
                    // TODO could check for BLE4 right here. You still have your anchor points. Could be another stage, maybe branch.
                    let own_start_params = self.start_parameters;
                    self.start(own_start_params); // <- will make a master request himself!
                }
            }
            true
        }
        else {
            // Do not have all results yet
            false
        }
    }

    fn decide_unsure_channels(&mut self) -> bool {
        // Get events where they should have occurred
        while let Some(unsure_event) = self.unsure_channel_queue.dequeue() {
            // Always count down the channel
            if self.unsure_channels_remaining_occurrences[unsure_event.channel as usize] != 0 {
                self.unsure_channels_remaining_occurrences[unsure_event.channel as usize] -= 1;
            }

            // If it was seen, remember in channel map, remove todo and remember as last occurrence
            if unsure_event.seen {
                self.found_chm_unsure |= 1 << unsure_event.channel;
                self.unsure_channels_remaining_occurrences[unsure_event.channel as usize] = 0;
                self.found_time = unsure_event.time;
                self.found_counter = unsure_event.event_counter;
            }
        }

        // Check if we found all
        if self.unsure_channels_remaining_occurrences.iter().all(|c| *c == 0) {
            
            let conn_params = DeducedParameters {
                access_address: self.start_parameters.access_address,
                master_phy: self.start_parameters.master_phy,
                slave_phy: self.start_parameters.slave_phy,
                conn_interval: self.connection_interval,
                channel_map: self.found_chm_unsure,
                crc_init: self.crc_init,
                last_time: self.found_time,
                last_counter: self.found_counter,
            };
            let conn_params = DeducedParametersBox::alloc().expect("Deduced params overflow").init(conn_params);

            self.request_master(DeducerToMaster::DeducedParameters(conn_params));

            self.state = State::Idle;

            true
        }
        else {
            false
        }
    }

    /// Something is an anchorpoint
    ///  when you were listening on the channel for longer than the worst case.
    /// This is the same as what happened before, the threshold is now just calculated at the start.
    /// Crc check occurs in process_samples.
    fn is_anchor_point(&self, connection_sample: &ConnectionSample) -> bool {
        self.silence_time < connection_sample.silence_time_on_channel
    }

   

}
const fn round_to_conn_interval(number: u32, conn_interval: u32) -> (u32, u16) {
    let mod_conn_int: u32 = number % conn_interval;
    // get it to the closest counter point from reference
    let discrete_relative_timepoint: u16;
    if mod_conn_int < (conn_interval / 2) {
        // closest to lower counter point, just let / drop it
        discrete_relative_timepoint = (number / conn_interval) as u16;
    } else {
        // closest to upper value counter point, round to upper by + 1
        discrete_relative_timepoint = (number / conn_interval) as u16 + 1;
    }
    let rounded: u32 = conn_interval * discrete_relative_timepoint as u32;
    (rounded, discrete_relative_timepoint)
}

fn phy_to_max_time(phy: &BlePhy) -> u32 {
    static UNCODED_1M_SEND_TIME: u32 = 2128;
    static UNCODED_2M_SEND_TIME: u32 = 2128 / 2 + 4;
    static CODED_S2_SEND_TIME: u32 = 4542; // AA, CI, TERM1 in S8
    static CODED_S8_SEND_TIME: u32 = 17040;
    match phy {
        BlePhy::Uncoded1M => {UNCODED_1M_SEND_TIME}
        BlePhy::Uncoded2M => {UNCODED_2M_SEND_TIME}
        BlePhy::CodedS2 => {CODED_S2_SEND_TIME}
        BlePhy::CodedS8 => {CODED_S8_SEND_TIME}
    }
}

fn phy_to_string_short(phy: &BlePhy) -> &str {
    match phy {
        BlePhy::Uncoded1M => {"1M"}
        BlePhy::Uncoded2M => {"2M"}
        BlePhy::CodedS2 => {"S2"}
        BlePhy::CodedS8 => {"S8"}
    }
}

fn round_to_1250(d : u32) -> u32 {
    let mod_1250 = d % 1250;
    if mod_1250 < 625 {
        d - mod_1250
    } 
    else {
        d + 1250 - mod_1250
    }
}

#[cfg(test)]
mod deducer_helper_tests {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn round_1250() {
        let target = 123 * 1250u32;
        ((target - 624)..(target+624)).for_each(|d| assert_eq!(round_to_1250(d), target));
    }
    #[test]
    fn round_con() {
        let conn_interval = 932 * 1250u32;
        let target = 123 * conn_interval;
        let border = conn_interval / 2 - 1;
        ((target - border)..(target+border)).map(|d| round_to_conn_interval(d, conn_interval))
            .for_each(|(rounded, in_con)| {
                assert_eq!(rounded, target);
                assert_eq!(in_con, 123);
            });
    }


    #[test]
    fn phy_time() {
        let target = vec![phy_to_max_time(&BlePhy::Uncoded1M), phy_to_max_time(&BlePhy::Uncoded2M), phy_to_max_time(&BlePhy::CodedS2), phy_to_max_time(&BlePhy::CodedS8)];
        target.iter().combinations(2).for_each(|d| assert_ne!(*d[0], *d[1]));
        assert_eq!(target[1], 2128 / 2 + 4);
    }
}