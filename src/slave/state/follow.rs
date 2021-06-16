use super::{JammerState};
use crate::{ble_algorithms::csa2::{calculate_channel_identifier, csa2_no_subevent, generate_channel_map_arrays}, deduction::deducer::{DeducedParameters, UnsureChannelEvent}, master::{RadioTask, SlaveMessageType}, slave::{JamblerReturn, hardware_traits::{CrcStatus, JamblerRadio, JamblerTimer, ListenParameters}}};
use crate::slave::StateReturn;


/// A struct representing the state for harvesting packets of a given access address.
#[derive(Debug)]
pub struct Follow {
    deduced_parameters : DeducedParameters,
    clock_drift_per_event: f32,
    channel_identifier : u16,
    channel_map_array: [bool; 37], 
    remapping_table: [u8; 37], 
    nb_used: u8,
    event_counter : u16,
    channel : u8,
    captured_previous: bool,
    captured_any: bool,
    perfect_next_time: u64,
}

impl Default for Follow {
    fn default() -> Self {
        Follow {
            deduced_parameters : DeducedParameters::default(),
            clock_drift_per_event: f32::default(),
            channel_identifier: u16::default(),
            channel_map_array: [false; 37],
            remapping_table: [u8::MAX; 37],
            nb_used: u8::MAX,
            event_counter: u16::MAX,
            channel: u8::MAX,
            captured_previous: false,
            captured_any: false,
            perfect_next_time: u64::MAX,
        }
    }
}

impl<R: JamblerRadio,T: JamblerTimer> JammerState<R,T> for Follow {

    fn start(
        &mut self, 
        task : &RadioTask,
        radio: &mut R, 
        timer: &mut T,
        //parameters: &mut StateParameters
    ) {
        if let RadioTask::Follow(p, _which_to_report) = task {


            #[cfg(target_arch="x86_64")]
            {self.deduced_parameters = *p;}
            #[cfg(not(target_arch="x86_64"))]
            {self.deduced_parameters = **p;}
            self.captured_any = false;
            self.captured_previous = false;

            // Derive some parameters from given information
            self.channel_identifier = calculate_channel_identifier(p.access_address);
            let (channel_map_array, remapping_table, _,nb_used) = generate_channel_map_arrays(p.channel_map);
            self.channel_map_array = channel_map_array;
            self.remapping_table = remapping_table;
            self.nb_used = nb_used;

            self.clock_drift_per_event = p.conn_interval as f32 * ((500.0 + timer.get_ppm() as f32)/1_000_000.0);

            // Calculate were to start listening
            // Take some margin for delays
            let cur_time = timer.get_time_micro_seconds();
            let time_since_last = (cur_time - p.last_time) as u32 + 2000;
            let next_event = p.last_counter.wrapping_add((time_since_last / p.conn_interval) as u16 + 1);
            // Make sure the event before and after have different channels, to avoid confusion.
            let (event_to_catch, prev_channel, extra_events) = (0..).map(|i| (next_event.wrapping_add(i), i)).filter_map(|(candidate_event, extra_events)| {
                let cur_channel = csa2_no_subevent(candidate_event as u32, self.channel_identifier as u32, &self.channel_map_array, &self.remapping_table, self.nb_used);
                let prev_channel = csa2_no_subevent(candidate_event.wrapping_sub(1) as u32, self.channel_identifier as u32, &self.channel_map_array, &self.remapping_table, self.nb_used);
                let next_channel = csa2_no_subevent(candidate_event.wrapping_add(1) as u32, self.channel_identifier as u32, &self.channel_map_array, &self.remapping_table, self.nb_used);
                if cur_channel != prev_channel && cur_channel != next_channel {
                    Some((candidate_event, prev_channel, extra_events))
                } else {None}
            }).next().unwrap();

            // We want sniffer to think we are at previous still
            self.event_counter = event_to_catch.wrapping_sub(1);
            self.channel = prev_channel;

            let events_since_last = if p.last_counter <= event_to_catch {event_to_catch - p.last_counter} else {p.last_counter - event_to_catch};
            self.perfect_next_time = p.last_time + (events_since_last as u32 * p.conn_interval) as u64;
            // Instead of clock drift, listen on next for the prev conn interval as well because of the anchor point problem.
            // We know the prev channel will be different. This has to go right: if a later one is caught it will be dissaligned always :/
            let imperfect_time = self.perfect_next_time - self.deduced_parameters.conn_interval as u64 + 100;

            // set timer to wake up then and start listening.
            // We listen for the whole connection event to do the best we can concerning packet loss.
            // We do go to sleep when a packet is captured until the next event.
            timer.request_interrupt_at(imperfect_time);

        } else {panic!("Harvest start called without radiotask being harvest")}
    }

    #[inline(always)]
    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        //parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        if let Some(packet) = radio.listen_radio_interrupt() {
            if let CrcStatus::Passed = packet.crc_status {
                // Check if it could be the anchorpoint
                let absolute_dif = if interrupt_time <= self.perfect_next_time {self.perfect_next_time - interrupt_time} else {interrupt_time - self.perfect_next_time};
                let events_since_last = if self.deduced_parameters.last_counter <= self.event_counter {self.event_counter - self.deduced_parameters.last_counter} else {self.deduced_parameters.last_counter - self.event_counter};

                if absolute_dif < (events_since_last as f32 * (self.clock_drift_per_event + 16.0)).ceil() as u64 {
                    // is our best guess this is the anchor point.
                    // Need to get lucky first time.
                    self.perfect_next_time = interrupt_time;
                    self.deduced_parameters.last_time = interrupt_time;
                    self.deduced_parameters.last_counter = self.event_counter;


                    // set timer interrupt on corrected wakeup?
                    let imperfect_time = self.perfect_next_time - (events_since_last as f32 * (self.clock_drift_per_event + 16.0)).ceil() as u64;
                    if imperfect_time > timer.get_time_micro_seconds() + 2000 {
                        timer.request_interrupt_at(imperfect_time);
                    }
                
                    self.captured_any = true;
                }

                // report as used 
                return_value.jambler_return = Some(JamblerReturn::ToMaster(SlaveMessageType::UnsureChannelEventReport(UnsureChannelEvent{
                    channel: self.channel,
                    time: self.deduced_parameters.last_time,
                    event_counter: self.deduced_parameters.last_counter,
                    seen: true,
                })));
                self.captured_previous = true;


                // Sleep until timer wakes up
                radio.reset();
            }
        }
    }

    #[inline(always)]
    fn handle_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        //parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Only report unused when already heard some
        if self.captured_any && !self.captured_previous {
            return_value.jambler_return = Some(JamblerReturn::ToMaster(SlaveMessageType::UnsureChannelEventReport(UnsureChannelEvent{
                channel: self.channel,
                event_counter: self.event_counter,
                seen: false,
                time : interrupt_time - self.deduced_parameters.conn_interval as u64
            })));
        }
        self.captured_previous = false;

        let prev_channel = self.channel;

        // Calculate next channel
        self.event_counter = self.event_counter.wrapping_add(1);
        self.channel = csa2_no_subevent(self.event_counter as u32, self.channel_identifier as u32, &self.channel_map_array, &self.remapping_table, self.nb_used);

        // Start radio
        let listen_params = ListenParameters {
            access_address: self.deduced_parameters.access_address,
            crc_init: Some(self.deduced_parameters.crc_init),
            channel: self.channel,
            phy: self.deduced_parameters.master_phy,
        };
        radio.listen_start(&&listen_params);

        // Determine when next timeout occurs
        let events_since_last = if self.deduced_parameters.last_counter <= self.event_counter {self.event_counter - self.deduced_parameters.last_counter} else {self.deduced_parameters.last_counter - self.event_counter};
        self.perfect_next_time += self.deduced_parameters.conn_interval as u64;
        let imperfect_time = self.perfect_next_time - (events_since_last as f32 * (self.clock_drift_per_event + 16.0)).ceil() as u64;

        timer.request_interrupt_at(imperfect_time);
    }
}
