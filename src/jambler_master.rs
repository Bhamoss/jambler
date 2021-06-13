use crate::jambler::{BlePhy, deduction::{brute_force::BruteForceResult, control::{BruteForceParametersBox, DeduceConnectionParametersControl, DeducedParametersBox, DeducerToMaster}, deducer::{ConnectionSample, DeductionStartParameters, UnsureChannelEvent, UnusedChannel}}};

use heapless::spsc::{Consumer, Producer};

#[derive(Debug)]
/// Master messages over the bus.
pub enum MasterMessage {
    /// A command which should be put through to the slave radio.
    RadioTaskRequest(RadioTask),
    /// Broadcast brute force to all sniffers.
    BruteForce(BruteForceParametersBox),
    /// Broadcast all sniffers to idle (sleep if they can)
    Idle
}

/// A command which should be put through to the slave radio.
#[derive(Debug)]
pub enum RadioTask {
    /// Sniffer with given id should listen according to the given parameters
    Harvest(u8, HarvestParameters),
    /// Sniffer(s) should follow the connection and report back when no packet was received for a connection event and channel.
    Follow(DeducedParametersBox),
}

#[derive(Debug)]
pub struct HarvestParameters {
    channel: u8,
    access_address: u32,
    master_phy : BlePhy,
    slave_phy : BlePhy,
    listen_until : ListenUntil
}

#[derive(Debug)]
pub enum ListenUntil {
    PacketReception,
    TimeOut(u32),
    Indefinitely
}

/// Messages expected back from the slaves over the buss.
/// Should contain the slave clock drift relative to the master (master will ADD it to its clock).
pub struct SlaveMessage {
    slave_id : u8, // TODO delete slave ID from deducer structs were not necessary. For processing it is.
    message : SlaveMessageType,
    relative_slave_drift : i32,
}

pub enum SlaveMessageType {
    /// u16 is the drift you should correct for
    SampleReport(ConnectionSample),
    UnusedChannelReport(UnusedChannel),
    UnsureChannelEventReport(UnsureChannelEvent),
    BruteForceResultReport(BruteForceResult)
}

pub struct MasterLoopReturn {
    wake_deducer_task: bool,
    wake_bus_transmitter: bool,
    wake_master: bool
}

pub enum JamblerCommand {
    Idle,
    Follow(DeductionStartParameters)
}

#[derive(Clone)]
enum MasterState {
    Idle,
    Deducing
}

enum SnifferOrchestration {
    NotDeducing,
    /// Just sequential timeout. Ignore unused, just use the ID to reassign. -> CRC init phase
    SequentialTimeOut(u32),
    /// (known_used, timeout, crc_init): indefinitely listen on used channels, ignore unused of timeout. Only remember used if CRC was ok.
    /// -> conn interal and while processing
    UsedAlwaysRestTimeOut(u64,u32,u32),
    /// (channels_todo, timeout, crc_init): listen on remaining channels until heard or timeout. CRC has to be ok.
    TimeOutRemaining(u64,u32,u32),
    /// Sniffer is following a connection. If true, report unused to deducer.
    Follow(bool)
}

/// A static struct which should get its own task.
pub struct JamblerMaster<'a> {
    /// Used to control the deducer.
    deduction_control : DeduceConnectionParametersControl<'a>,
    /// 
    nb_sniffers: u8,
    sniffer_positions: [u8;37],
    bus_tx : Producer<'a, MasterMessage, 64>,
    bus_rx : Consumer<'a, SlaveMessage, 64>,
    state: MasterState,
    sniffer_orchestration : SnifferOrchestration,
    start_parameters : DeductionStartParameters
}


impl<'a> JamblerMaster<'a> {
    pub fn new(deduction_control : DeduceConnectionParametersControl<'a>, 
        nb_sniffers: u8,
        bus_tx : Producer<'a, MasterMessage, 64>,
        bus_rx : Consumer<'a, SlaveMessage, 64>) -> Self {
            JamblerMaster {
                deduction_control,
                nb_sniffers,
                sniffer_positions: [0;37],
                bus_tx,
                bus_rx,
                state : MasterState::Idle,
                sniffer_orchestration : SnifferOrchestration::NotDeducing,
                start_parameters : DeductionStartParameters::default()
            }
    }

    /// Reset
    fn reset(&mut self) {
        // empty rx buf
        while self.bus_rx.dequeue().is_some() {}

        self.state = MasterState::Idle;
        self.sniffer_orchestration = SnifferOrchestration::NotDeducing;
    }

    /// Used to receive user commands.
    pub fn execute_command(&mut self, command : JamblerCommand) -> MasterLoopReturn {
        match command {
            JamblerCommand::Idle => {
                // reset self, deducer and broadcast idle to slaves
                self.reset();
                self.deduction_control.reset();
                self.bus_tx.enqueue(MasterMessage::Idle).expect("master bus tx overflow");
                MasterLoopReturn {
                    wake_deducer_task: true,
                    wake_bus_transmitter: true,
                    wake_master: false,
                }
            },
            JamblerCommand::Follow(params) => {
                // Signal deducer. Do nothing until you get an answer.
                self.reset();
                self.state = MasterState::Deducing;
                self.start_parameters = params;
                self.deduction_control.start(params);
                MasterLoopReturn {
                    wake_deducer_task: true,
                    wake_bus_transmitter: false,
                    wake_master: false,
                }
            },
        }
    }


    /// The loop the master task should execute and obey its return.
    pub fn master_loop(&mut self) -> MasterLoopReturn {
        match self.state {
            MasterState::Idle => {MasterLoopReturn { wake_deducer_task: false, wake_bus_transmitter: false, wake_master: false }},
            MasterState::Deducing => self.deducing(),
        }
    }

    fn deducing(&mut self) -> MasterLoopReturn {
        let mut wake_deducer_task = false;
        let mut wake_bus_transmitter = false;

        // Read message queues, but only post them if deducer has sent us request already.
        // Incorporate slave drift in comparison to this drift in message containing time.
        while let Some(slave_message) = self.bus_rx.dequeue() {
            if !matches!(self.sniffer_orchestration,SnifferOrchestration::NotDeducing) {
                let drift = slave_message.relative_slave_drift;
                match slave_message.message {
                    SlaveMessageType::SampleReport(mut c) => {
                        // TODO check last req and determine what to direct to slave now
                        c.time = (c.time as i64 + drift as i64) as u64;
                        wake_bus_transmitter = self.direct_slave_on_sample(&c);
                        self.deduction_control.send_connection_sample(c);
                        wake_deducer_task = true
                    },
                    SlaveMessageType::UnusedChannelReport(u) => {
                        // TODO check last req and determine what to direct to slave now
                        wake_bus_transmitter = self.direct_slave_on_unused(&u);
                        self.deduction_control.send_unused_channel(u);
                        wake_deducer_task = true
                    },
                    SlaveMessageType::UnsureChannelEventReport(mut u) => {
                        // TODO deducer already filters here I think... 
                        u.time = (u.time as i64 + drift as i64) as u64;
                        self.deduction_control.send_unsure_channel_event(u);
                        wake_deducer_task = true
                    },
                    SlaveMessageType::BruteForceResultReport(r) => {
                        self.deduction_control.send_brute_force_result(r);
                        wake_deducer_task = true
                    },
                }
            }
        }


        // Check for messages from deducer
        while let Some(req) = self.deduction_control.get_deducer_request() {
            // TODO handle the request -> instruct slaves. Set your orchestartion and do their init
            match req {
                DeducerToMaster::SearchPacketsForCrcInit(_) => todo!(),
                DeducerToMaster::SearchPacketsForConnInterval(_, _, _) => todo!(),
                DeducerToMaster::StartChannelMap(_, _, _) => todo!(),
                DeducerToMaster::DistributedBruteForce(_, _) => todo!(),
                DeducerToMaster::ListenForUnsureChannels(_, _) => todo!(),
                DeducerToMaster::DeducedParameters(_) => todo!(),
            }
        }

        MasterLoopReturn {
            wake_deducer_task,
            wake_bus_transmitter,
            wake_master: self.deduction_control.new_request() || self.bus_rx.peek().is_some(),
        }
    }

    /// Should return whether you have sent something on the bus
    fn direct_slave_on_sample(&mut self, sample : &ConnectionSample) -> bool {
        match self.sniffer_orchestration {
            SnifferOrchestration::NotDeducing => todo!(),
            SnifferOrchestration::SequentialTimeOut(_) => todo!(),
            SnifferOrchestration::UsedAlwaysRestTimeOut(_, _, _) => todo!(),
            SnifferOrchestration::TimeOutRemaining(_, _, _) => todo!(),
            SnifferOrchestration::Follow(_) => todo!(),
        }
    }

    /// Should return whether you have sent something on the bus
    fn direct_slave_on_unused(&mut self, unused_channel : &UnusedChannel) -> bool {
        match self.sniffer_orchestration {
            SnifferOrchestration::NotDeducing => todo!(),
            SnifferOrchestration::SequentialTimeOut(_) => todo!(),
            SnifferOrchestration::UsedAlwaysRestTimeOut(_, _, _) => todo!(),
            SnifferOrchestration::TimeOutRemaining(_, _, _) => todo!(),
            SnifferOrchestration::Follow(_) => todo!(),
        }
    }

}