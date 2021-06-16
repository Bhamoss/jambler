use super::{JammerState};
use crate::{deduction::deducer::{UnusedChannel}, master::{ListenUntil, RadioTask, SlaveMessageType}, slave::{JamblerReturn, RadioWork, hardware_traits::{HalHarvestedPacket, JamblerRadio, JamblerTimer, ListenParameters}}};
use crate::slave::StateReturn;

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
    pub packet: HalHarvestedPacket,
    /// response
    pub response: Option<HalHarvestedPacket>,
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


/// A struct representing the state for harvesting packets of a given access address.
#[derive(Debug)]
pub struct Harvest {
    start_time: u64,
    listen_until: ListenUntil,
    channel : u8,
}

impl Default for Harvest {
    fn default() -> Self {
        Harvest {
            start_time : u64::MAX,
            listen_until: ListenUntil::Indefinitely,
            channel : u8::MAX
        }
    }
}

impl<R: JamblerRadio,T: JamblerTimer> JammerState<R,T> for Harvest {
    fn start(
        &mut self, 
        task : &RadioTask,
        radio: &mut R, 
        timer: &mut T,
        //parameters: &mut StateParameters
    ) {
        if let RadioTask::Harvest(p) = task {

            // Start radio
            let listen_params = ListenParameters {
                access_address: p.access_address,
                crc_init: None,
                channel: p.channel,
                phy: p.master_phy,
            };
            radio.listen_start(&listen_params);

            // Remember time
            self.start_time = timer.get_time_micro_seconds();
            self.listen_until = p.listen_until.clone();
            self.channel = p.channel;

            // Set correct timeout
            match self.listen_until {
                ListenUntil::PacketReception(time_out) => {timer.request_interrupt_at(self.start_time + time_out as u64);},
                ListenUntil::TimeOut(time_out) => {timer.request_interrupt_at(self.start_time + time_out as u64);},
                ListenUntil::Indefinitely => {timer.cancel_interrupt();}, // Do nothing. No timer.
            }


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
            match self.listen_until {
                ListenUntil::PacketReception(_) => {
                    // TODO would be better to let hardware crc check...
                    // Timed out, report unused. Is also way for master to tell you timed out.
                    return_value.jambler_return = Some(JamblerReturn::ToMaster(SlaveMessageType::UnusedChannelReport(UnusedChannel {
                        channel: self.channel,
                    })));

                    radio.reset();
                    // stop the interrupt still going.
                    timer.cancel_interrupt()
                },
                ListenUntil::Indefinitely  | ListenUntil::TimeOut(_) => {
                    // Do nothing, just report the packet
                    return_value.jambler_return = Some(JamblerReturn::RequiresProcessingOutOfInterrupt(RadioWork::ConvertToConnectionSample(HarvestedSubEvent{
                        channel: self.channel,
                        time: self.start_time,
                        time_on_the_channel: (interrupt_time - self.start_time) as u32,
                        packet,
                        response: None,
                    })));
                }, 
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
        match self.listen_until {
            ListenUntil::PacketReception(_) | ListenUntil::TimeOut(_) => {
                // Timed out, report unused. Is also way for master to tell you timed out.
                return_value.jambler_return = Some(JamblerReturn::ToMaster(SlaveMessageType::UnusedChannelReport(UnusedChannel {
                    channel: self.channel,
                })));
                radio.reset();
            },
            ListenUntil::Indefinitely => {panic!("timer interrupt on indefinite listen");}, 
        }
    }
}




#[cfg(test)]
pub mod test {
    use crate::{master::HarvestParameters, slave::BlePhy};

    use super::super::super::{dummy_test_hals::{DummyRadio, DummyTimer}, ListenParameters};
    use super::*;
    fn setup() -> (DummyRadio, DummyTimer) {
        (DummyRadio {
            has_been_reset: false,
            params: ListenParameters {
                access_address: 0,
                crc_init: None,
                channel: 0,
                phy: crate::slave::BlePhy::Uncoded1M,
            },
            harvested_packet: vec![],
        },
        DummyTimer {
            time: 0,
            packet_received_time: 0,
            interrupt_time: 0,
            pending_interrupt: None,
        })
    }

    #[test]
    pub fn harvest_start() {
        let (mut radio_store, mut timer_store) = setup();
        let radio = &mut radio_store;
        let timer = &mut timer_store;
        let mut harvest = Harvest::default();

        harvest.start(&RadioTask::Harvest(HarvestParameters {
            channel: 5,
            access_address: 13,
            master_phy: BlePhy::CodedS8,
            slave_phy: BlePhy::Uncoded2M,
            listen_until: ListenUntil::PacketReception(200),
        }), radio, timer)
    }
}