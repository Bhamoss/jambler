use crate::jambler::{BlePhy, deduction::{brute_force::{BfParam, BruteForceResult}, control::{ DeduceConnectionParametersControl,  DeducerToMaster, DpParam}, deducer::{ConnectionSample, DeducedParameters, DeductionStartParameters, UnsureChannelEvent, UnusedChannel}}};

use heapless::{spsc::{Consumer, Producer}};

pub struct MasterMessage {
    recipient : BusRecipient,
    message : MasterMessageType
}

/// Master messages over the bus.
pub enum MasterMessageType {
    /// A command which should be put through to the slave radio.
    RadioTaskRequest(RadioTask),
    /// Broadcast brute force to all sniffers.
    BruteForce(BfParam),
    /// Broadcast all sniffers to idle (sleep if they can)
    Idle
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum BusRecipient {
    Broadcast,
    Slave(u8)
}

/// A command which should be put through to the slave radio.
pub enum RadioTask {
    /// Sniffer with given id should listen according to the given parameters
    Harvest(HarvestParameters),
    /// Sniffer(s) should follow the connection and report back when no packet was received for a connection event and channel.
    Follow(DpParam, Option<u64>),
}

pub struct HarvestParameters {
    channel: u8,
    access_address: u32,
    master_phy : BlePhy,
    slave_phy : BlePhy,
    listen_until : ListenUntil
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ListenUntil {
    // Until packet reception or timeout. Report sample or timeout.
    PacketReception(u32),
    // Until timeout. Keep listening on reception. Report timeout as unused channel.
    TimeOut(u32),
    // Always keep listening, report connection samples.
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

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MasterLoopReturn {
    pub wake_deducer_task: bool,
    pub wake_bus_transmitter: bool,
    pub wake_master: bool
}

pub enum JamblerCommand {
    Idle,
    Follow(DeductionStartParameters)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
enum MasterState {
    Idle,
    Deducing,
    Following
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
enum SnifferOrchestration {
    NotDeducing,
    /// Just sequential timeout. Ignore unused, just use the ID to reassign. -> CRC init phase
    SequentialTimeOut(u32),
    /// (time_to_switch, crc_init, used_channels_until_now): indefinitely listen on used channels, ignore unused of timeout. Only remember used if CRC was ok.
    /// -> conn interal and while processing
    UsedAlwaysRestTimeOut(u32,u32,u64),
    /// (time_to_listen_in_us, channels_todo, crc_init, known_used): listen on remaining channels until heard or timeout. CRC has to be ok.
    TimeOutRemaining(u32,u64,u32, u64),
    /// Sniffer is following a connection. If None, report all. If some, only report ones in mask.
    Follow(Option<u64>)
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
    start_parameters : DeductionStartParameters,
    connection_parameters : DeducedParameters,
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
                start_parameters : DeductionStartParameters::default(),
                connection_parameters : DeducedParameters::default()
            }
    }

    /// Reset
    fn reset(&mut self) {
        // empty rx buf
        while self.bus_rx.dequeue().is_some() {}

        self.deduction_control.reset();

        let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
        if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}

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
                // This instead of unwrap to avoid 20 derive debugs. 
                match self.bus_tx.enqueue(MasterMessage {recipient : BusRecipient::Broadcast , message: MasterMessageType::Idle}) {
                    Ok(it) => it,
                    _ => unreachable!(),
                };
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
            MasterState::Following => self.following(),
        }
    }

    fn deducing(&mut self) -> MasterLoopReturn {
        let mut wake_deducer_task = false;
        let mut wake_bus_transmitter = false;

        // Read message queues, but only post them if deducer has sent us request already.
        // Incorporate slave drift in comparison to this drift in message containing time.
        while let Some(slave_message) = self.bus_rx.dequeue() {
            if matches!(self.state, MasterState::Deducing) {
                let drift = slave_message.relative_slave_drift;
                match slave_message.message {
                    SlaveMessageType::SampleReport(mut c) => {
                        c.time = (c.time as i64 + drift as i64) as u64;
                        wake_bus_transmitter |= self.direct_slave_on_sample(slave_message.slave_id, &c);
                        self.deduction_control.send_connection_sample(c);
                        wake_deducer_task = true
                    },
                    SlaveMessageType::UnusedChannelReport(u) => {
                        // They will report always on timeout, but we only want to send unused when channel mapping -> timeoutRemaining
                        wake_bus_transmitter |= self.direct_slave_on_unused(slave_message.slave_id,&u);

                        if matches!(self.sniffer_orchestration, SnifferOrchestration::TimeOutRemaining(_, _, _, _)) 
                                && matches!(self.state, MasterState::Deducing) {
                            self.deduction_control.send_unused_channel(u);
                            wake_deducer_task = true
                        }
                    },
                    SlaveMessageType::UnsureChannelEventReport(mut u) => {
                        u.time = (u.time as i64 + drift as i64) as u64;

                        // Always remember the last seen event
                        if u.seen {
                            self.connection_parameters.last_counter = u.event_counter;
                            self.connection_parameters.last_time = u.time;
                        }

                        // report whether a channel was seen. Sniffer(s) is following and does not need extra information.
                        // This function only gets executed when deducing
                        let send_event = match self.sniffer_orchestration {
                            SnifferOrchestration::Follow(m) => if let Some(m) = m {
                                m & (1<< u.channel) != 0
                            } else {true}
                            _ => false
                        };

                        if send_event {
                            self.deduction_control.send_unsure_channel_event(u);
                            wake_deducer_task = true
                        }
                    },
                    SlaveMessageType::BruteForceResultReport(r) => {
                        self.deduction_control.send_brute_force_result(r);
                        wake_deducer_task = true
                    },
                }
            }
        }


        // Check for messages from deducer
        let mut last_req = None;
        while let Some(req) = self.deduction_control.get_deducer_request() {
            last_req = Some(req);
        }
        if let Some(req) = last_req {
            self.process_deducer_request(req);
            wake_bus_transmitter = true;
        }

        MasterLoopReturn {
            wake_deducer_task,
            wake_bus_transmitter,
            wake_master: self.deduction_control.new_request() || self.bus_rx.peek().is_some(),
        }
    }


    fn process_deducer_request(&mut self, req: DeducerToMaster) {
        match req {
            DeducerToMaster::SearchPacketsForCrcInit(time_to_switch) => {
                self.sniffer_positions = [u8::MAX; 37];
                let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
                if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}
                // let sniffers listen on on the respective channels
                self.sniffer_positions.iter_mut().take(self.nb_sniffers as usize).enumerate()
                    .for_each(|(index, position)| *position = index as u8);

                let poss = &self.sniffer_positions;
                let bustx = &mut self.bus_tx;
                let startps = &self.start_parameters;
                poss.iter().take(self.nb_sniffers as usize).enumerate()
                .for_each(|(sniffer_id, position)| if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(sniffer_id as u8),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                        access_address : startps.access_address,
                        channel : *position,
                        master_phy : startps.master_phy,
                        slave_phy: startps.slave_phy,
                        listen_until : ListenUntil::TimeOut(time_to_switch)
                    }))
                }).is_err() {panic!("master made bus overflow")});

                self.sniffer_orchestration = SnifferOrchestration::SequentialTimeOut(time_to_switch);
            },
            DeducerToMaster::SearchPacketsForConnInterval(time_to_switch, crc_init, used_channels_until_now) => {
                let nb_used = (used_channels_until_now & 0x1F_FF_FF_FF_FF).count_ones();

                // Put impossible values in position to recognised unnassigned sniffers
                self.sniffer_positions = [u8::MAX; 37];
                let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
                if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}

                // Assign as many sniffers to used channels as you can
                (0..37u8).filter(|c| used_channels_until_now & (1 << *c) != 0).take(self.nb_sniffers as usize).enumerate()
                    .for_each(|(sniffer_id, channel)| self.sniffer_positions[sniffer_id] = channel);

                // Assign the rest. For the last sniffers (nb more than used), assign them to remaining unused channels
                ((nb_used as usize)..(self.nb_sniffers as usize)).zip((0..37u8).filter(|c| used_channels_until_now & (1 << *c) == 0))
                    .for_each(|(sniffer_id, channel)| self.sniffer_positions[sniffer_id] = channel);

                // more then 37 sniffers are not supported, but you would need to assign them here. You can identify them because they have u8::MAX
                // You would also need to filter out when 2 sniffers on the same channel  both capture. 

                // send positions. first nb_used listen indefinitely.
                let poss = &self.sniffer_positions;
                let bustx = &mut self.bus_tx;
                let startps = &self.start_parameters;
                poss.iter().take(self.nb_sniffers as usize).enumerate()
                .for_each(|(sniffer_id, position)| if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(sniffer_id as u8),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                        access_address : startps.access_address,
                        channel : *position,
                        master_phy : startps.master_phy,
                        slave_phy: startps.slave_phy,
                        listen_until : if sniffer_id < nb_used as usize {ListenUntil::Indefinitely} else { 
                            ListenUntil::TimeOut(time_to_switch) // reception, because will then be told to stay forever
                        }
                    }))
                }).is_err() {panic!("master made bus overflow")});


                self.sniffer_orchestration = SnifferOrchestration::UsedAlwaysRestTimeOut(time_to_switch, crc_init, used_channels_until_now);
            },
            DeducerToMaster::StartChannelMap(time_to_listen_in_us, channels_todo, crc_init)  => {
                self.sniffer_positions = [u8::MAX; 37];
                let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
                if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}
                let nb_todo = (channels_todo & 0x1F_FF_FF_FF_FF).count_ones();
                // Assign as many sniffers to todo channels as you can. 
                (0..37u8).filter(|c| channels_todo & (1 << *c) != 0).take(self.nb_sniffers as usize).enumerate()
                    .for_each(|(sniffer_id, channel)| self.sniffer_positions[sniffer_id] = channel);

                // Assign other sniffers to known used channels. All done channels will be used as we do not send unused by this point.
                // Dirty trick, but let remaining thus listen on not todo channels
                //((nb_used as usize)..(self.nb_sniffers as usize)).zip((0..37u8).filter(|c| channels_todo & (1 << *c) == 0))
                //.for_each(|(sniffer_id, channel)| self.sniffer_positions[sniffer_id] = channel);

                // The channels being listened on are not to do anymore
                let updated_ch_todo = (0..self.nb_sniffers.min(nb_todo as u8)).map(|s| self.sniffer_positions[s as usize])
                    .fold(channels_todo, |rc, c| rc & (!(1 << c) & 0x1F_FF_FF_FF_FF));

                // Again, make sure no 2 on same channels, leave MAXs alone, they should not sniff

                // dispatch
                let poss = &self.sniffer_positions;
                let bustx = &mut self.bus_tx;
                let startps = &self.start_parameters;
                poss.iter().take(self.nb_sniffers as usize).enumerate()
                .for_each(|(sniffer_id, position)| if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(sniffer_id as u8),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                        access_address : startps.access_address,
                        channel : *position,
                        master_phy : startps.master_phy,
                        slave_phy: startps.slave_phy,
                        listen_until : if sniffer_id >= nb_todo as usize {ListenUntil::Indefinitely} else { ListenUntil::PacketReception(time_to_listen_in_us)}
                    }))
                }).is_err() {panic!("master made bus overflow")});

                self.sniffer_orchestration = SnifferOrchestration::TimeOutRemaining(time_to_listen_in_us, updated_ch_todo, crc_init, !channels_todo & 0x1F_FF_FF_FF_FF);
            },
            DeducerToMaster::DistributedBruteForce(bfparams, current_channel_map) => {
                self.sniffer_positions = [u8::MAX; 37];
                // Make sure they are all silent so no doubles.
                let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
                if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}

                // Let brute force and let sniffers listen on used channels, others silent
                (0..37u8).filter(|c| current_channel_map & (1 << *c) != 0).take(self.nb_sniffers as usize).enumerate()
                .for_each(|(sniffer_id, channel)| self.sniffer_positions[sniffer_id] = channel);

                let poss = &self.sniffer_positions;
                let bustx = &mut self.bus_tx;
                let startps = &self.start_parameters;
                poss.iter().take(self.nb_sniffers as usize).enumerate().filter(|(_,p)| **p != u8::MAX)
                .for_each(|(sniffer_id, position)| if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(sniffer_id as u8),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                        access_address : startps.access_address,
                        channel : *position,
                        master_phy : startps.master_phy,
                        slave_phy: startps.slave_phy,
                        listen_until : ListenUntil::Indefinitely
                    }))
                }).is_err() {panic!("master made bus overflow")});

                self.sniffer_orchestration = SnifferOrchestration::UsedAlwaysRestTimeOut(0, 0, current_channel_map);

                // Broadcast brute force parameters to slave
                if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Broadcast,
                    message : MasterMessageType::BruteForce(bfparams)
                }).is_err() {panic!("master made bus overflow")}

            },
            DeducerToMaster::ListenForUnsureChannels(mut conn_params, channels_todo) => {

                // Have to set todo's to used so we get unused reports for it
                conn_params.channel_map |= channels_todo;

                // Remember params
                #[cfg(target_arch="x86_64")]
                {self.connection_parameters = conn_params;}
                #[cfg(not(target_arch="x86_64"))]
                {self.connection_parameters = *conn_params;}

                // Make sure they are all silent so no doubles.
                let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
                if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}

                // Ask sniffer 0 to follow the connection
                if self.bus_tx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(0),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Follow(conn_params, Some(channels_todo)))
                }).is_err() {panic!("master made bus overflow")}

                self.sniffer_orchestration = SnifferOrchestration::Follow(Some(channels_todo))
            },
            DeducerToMaster::DeducedParameters(mut conn_params) => {

                let idle_mes = MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle};
                if self.bus_tx.enqueue(idle_mes).is_err() {panic!("master made bus overflow")}

                // Take our last known point, deducer one is not necessarily latest
                conn_params.last_counter = self.connection_parameters.last_counter;
                conn_params.last_time = self.connection_parameters.last_time;

                // Remember params
                #[cfg(target_arch="x86_64")]
                {self.connection_parameters = conn_params;}
                #[cfg(not(target_arch="x86_64"))]
                {self.connection_parameters = *conn_params;}

                // Ask sniffer 0 to follow the connection
                if self.bus_tx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(0),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Follow(conn_params, None))
                }).is_err() {panic!("master made bus overflow")}

                self.state = MasterState::Following;
                self.sniffer_orchestration = SnifferOrchestration::NotDeducing;
            },
        }
    }

    /// Should return whether you have sent something on the bus
    fn direct_slave_on_sample(&mut self, sniffer_id : u8, sample : &ConnectionSample) -> bool {
        match &mut self.sniffer_orchestration {
            SnifferOrchestration::SequentialTimeOut(_time_to_switch) => {
                // Sequential: just keep listening on sample
                false
            },
            SnifferOrchestration::UsedAlwaysRestTimeOut(time_to_switch, crc_init, used_channels_until_now) => {
                // conn interval and during brute force.
                // If not used, it is used now if the crc is ok
                if *used_channels_until_now & (1 << sample.channel) == 0 && sample.packet.reversed_crc_init == *crc_init {
                    let bustx = &mut self.bus_tx;
                    let startps = &self.start_parameters;
                    if bustx.enqueue(MasterMessage {
                        recipient: BusRecipient::Slave(sniffer_id as u8),
                        message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                            access_address : startps.access_address,
                            channel : self.sniffer_positions[sniffer_id as usize], // stay on same
                            master_phy : startps.master_phy,
                            slave_phy: startps.slave_phy,
                            listen_until : ListenUntil::Indefinitely
                        }))
                    }).is_err() {panic!("master made bus overflow")}
                    *used_channels_until_now |= 1 << sample.channel;
                    true
                }
                else { 
                    // Sniffer already listening indefinielty.
                    false
                }
            },
            SnifferOrchestration::TimeOutRemaining(time_to_listen_in_us, channels_todo, crc_init, known_used) => {
                // Add to known used and assign new todo. If no more to do and known unused, do nothing because danger of 2 on same channel.
                if sample.packet.reversed_crc_init == *crc_init {
                    *known_used |= 1 << sample.channel;

                    if let Some(next_channel) = (0..37u8).find(|c| *channels_todo & (1 << *c) != 0) {
                        // Assign to channel still to do
                        self.sniffer_positions[sniffer_id as usize] = next_channel;
    
                        let bustx = &mut self.bus_tx;
                        let startps = &self.start_parameters;
                        if bustx.enqueue(MasterMessage {
                            recipient: BusRecipient::Slave(sniffer_id as u8),
                            message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                                access_address : startps.access_address,
                                channel : next_channel, // go to next
                                master_phy : startps.master_phy,
                                slave_phy: startps.slave_phy,
                                listen_until : ListenUntil::PacketReception(*time_to_listen_in_us)
                            }))
                        }).is_err() {panic!("master made bus overflow")}
    
                        // Flag channel as not to do anymore, this sniffer will take care of it.
                        *channels_todo &= !(1 << next_channel);
                        true
                    } 
                    else {
                        // Not sending anything will make the sniffer idle.
                        self.sniffer_positions[sniffer_id as usize] = u8::MAX;
                        false
                    }   
                }   
                else {
                    // Crc was wrong, let it listen on the same channel for the remaining time
                    let bustx = &mut self.bus_tx;
                    let startps = &self.start_parameters;
                    if bustx.enqueue(MasterMessage {
                        recipient: BusRecipient::Slave(sniffer_id as u8),
                        message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                            access_address : startps.access_address,
                            channel : self.sniffer_positions[sniffer_id as usize], // go to next
                            master_phy : startps.master_phy,
                            slave_phy: startps.slave_phy,
                            listen_until : ListenUntil::PacketReception(*time_to_listen_in_us - sample.silence_time_on_channel)
                        }))
                    }).is_err() {panic!("master made bus overflow")}
                    true
                }  
                
            },
            SnifferOrchestration::NotDeducing => false, // nothing
            SnifferOrchestration::Follow(_) => false, // nothing, keep following
            
        }
    }

    /// Should return whether you have sent something on the bus
    fn direct_slave_on_unused(&mut self, sniffer_id : u8, unused_channel : &UnusedChannel) -> bool {
        // TODO bestuur zoals gezegt in snifferorchestration en thesis
        match &mut self.sniffer_orchestration {
            SnifferOrchestration::SequentialTimeOut(time_to_switch) => {
                // Tell the sniffer to move forward sequentially for same time, since unused flags that it timed out.
                // For a short time sniffers will listen on the same channel, until they all timed out. 
                // They should all time out around the same time.
                self.sniffer_positions[sniffer_id as usize] = (self.sniffer_positions[sniffer_id as usize] + self.nb_sniffers) % 37; 

                let bustx = &mut self.bus_tx;
                let startps = &self.start_parameters;
                if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(sniffer_id as u8),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                        access_address : startps.access_address,
                        channel : self.sniffer_positions[sniffer_id as usize],
                        master_phy : startps.master_phy,
                        slave_phy: startps.slave_phy,
                        listen_until : ListenUntil::TimeOut(*time_to_switch)
                    }))
                }).is_err() {panic!("master made bus overflow")}

                true
            },
            SnifferOrchestration::UsedAlwaysRestTimeOut(time_to_switch, crc_init, used_channels_until_now) => {
                // conn interval and during brute force.
                // Unused means it timed out -> reassign. This will never occur for brute force because
                // Just reassign to NOT used channels, only at start on on hearing a used channel you are allowed on one
                // For a short time sniffers will listen on the same channel, until they all timed out. 
                // They should all time out around the same time.
                let nb_used = used_channels_until_now.count_ones() as u8;
                let still_jumping = if self.nb_sniffers <= nb_used {panic!("this one should not time out then")} else {self.nb_sniffers - nb_used} as usize;

                let snifs = self.nb_sniffers;
                let pos = &mut self.sniffer_positions;
                let next_channel = (0..37u8).cycle().skip_while(|c| *c != unused_channel.channel)
                    .filter(|c| *used_channels_until_now & (1 << *c) == 0 && !pos[0..(snifs as usize)].contains(c))
                    .nth(still_jumping - 1).unwrap();

                self.sniffer_positions[sniffer_id as usize] = next_channel; 

                let bustx = &mut self.bus_tx;
                let startps = &self.start_parameters;
                if bustx.enqueue(MasterMessage {
                    recipient: BusRecipient::Slave(sniffer_id as u8),
                    message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                        access_address : startps.access_address,
                        channel : next_channel,
                        master_phy : startps.master_phy,
                        slave_phy: startps.slave_phy,
                        listen_until : ListenUntil::TimeOut(*time_to_switch)
                    }))
                }).is_err() {panic!("master made bus overflow")}

                true
            },
            SnifferOrchestration::TimeOutRemaining(time_to_listen_in_us, channels_todo, crc_init, known_used) => {
                // timed out, reassing to one still to do
                if let Some(next_channel) = (0..37u8).find(|c| *channels_todo & (1 << *c) != 0) {
                    // Assign to channel still to do
                    self.sniffer_positions[sniffer_id as usize] = next_channel;

                    let bustx = &mut self.bus_tx;
                    let startps = &self.start_parameters;
                    if bustx.enqueue(MasterMessage {
                        recipient: BusRecipient::Slave(sniffer_id as u8),
                        message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(HarvestParameters {
                            access_address : startps.access_address,
                            channel : next_channel, // go to next
                            master_phy : startps.master_phy,
                            slave_phy: startps.slave_phy,
                            listen_until : ListenUntil::PacketReception(*time_to_listen_in_us)
                        }))
                    }).is_err() {panic!("master made bus overflow")}

                    // Flag channel as not to do anymore, this sniffer will take care of it.
                    *channels_todo &= !(1 << next_channel);
                    true
                } 
                else {
                    // Not sending anything will make the sniffer idle.
                    self.sniffer_positions[sniffer_id as usize] = u8::MAX;
                    false
                }
            },
            SnifferOrchestration::NotDeducing => false, // not applicable
            SnifferOrchestration::Follow(_) => false, // only unsure event, never occurs
        }
    }


    pub fn following(&mut self) -> MasterLoopReturn {
        // todo empty the sniffer queue. Tell user when you received a whole bunch of missed packets = unsureChannelReports with unseen
        MasterLoopReturn {
            wake_deducer_task: false,
            wake_bus_transmitter: false,
            wake_master: false,
        }
    }

}

#[cfg(test)]
mod master_tests {
    use core::{ usize};

    #[cfg(not(target_arch="x86_64"))]
    use core::mem::MaybeUninit;
    #[cfg(not(target_arch="x86_64"))]
    use crate::jambler::deduction::control::{BruteForceParametersBox, DeducedParametersBox};
    #[cfg(not(target_arch="x86_64"))]
    use heapless::pool::{singleton::Pool, Node};

    use crate::{jambler::{BlePhy, deduction::{brute_force::{BruteForceParameters, BruteForceResult, clone_bf_param, convert_bf_param}, control::{DeduceConnectionParametersControl, DeducerToMaster, MasterToDeducer, convert_deduced_param}, deducer::{ConnectionSample, ConnectionSamplePacket, DeducedParameters, DeductionStartParameters, UnsureChannelEvent, UnusedChannel}}}, jambler_master::{BusRecipient,  JamblerCommand, ListenUntil, MasterLoopReturn, MasterMessageType, MasterState, RadioTask, SlaveMessageType, SnifferOrchestration}};

    use super::{JamblerMaster, MasterMessage, SlaveMessage};

    use rand::{prelude::SliceRandom, thread_rng};


    use heapless::{spsc::{Consumer, Producer}, spsc::Queue};
    use itertools::Itertools;

    struct DeductionQueues<'a> {
        sample_queue : Consumer<'a, ConnectionSample,16>,
        unused_queue : Consumer<'a, UnusedChannel,16>,
        command_queue : Consumer<'a, MasterToDeducer,16>,
        request_queue : Producer<'a, DeducerToMaster,16>,
        brute_force_result_queue : Consumer<'a, BruteForceResult,16>,
        unsure_channel_queue : Consumer<'a, UnsureChannelEvent,16>,
    }

    struct BusQueues<'a> {
        bus_master_messages : Consumer<'a, MasterMessage, 64>,
        bus_slave_messages : Producer<'a, SlaveMessage, 64>,
    }

    struct AllQueuesStore {
        sample_queue : Queue<ConnectionSample,16>,
        unused_queue : Queue<UnusedChannel,16>,
        command_queue : Queue<MasterToDeducer,16>,
        request_queue : Queue<DeducerToMaster,16>,
        brute_force_result_queue : Queue<BruteForceResult,16>,
        unsure_channel_queue : Queue<UnsureChannelEvent,16>,
        bus_master_messages : Queue<MasterMessage, 64>,
        bus_slave_messages : Queue<SlaveMessage, 64>,
    }
    impl AllQueuesStore {
        pub fn new() -> Self {
            AllQueuesStore {
                sample_queue : Queue::new(),
                unused_queue : Queue::new(),
                command_queue : Queue::new(),
                request_queue : Queue::new(),
                brute_force_result_queue : Queue::new(),
                unsure_channel_queue : Queue::new(),
                bus_master_messages : Queue::new(),
                bus_slave_messages : Queue::new(),
            }
        }
    }

    fn setup(store: &mut AllQueuesStore, nb_sniffers: u8) -> (JamblerMaster, BusQueues, DeductionQueues) {

        let (sqp, sqc) = store.sample_queue.split();
        let (uqp, uqc) = store.unused_queue.split();
        let (cqp, cqc) = store.command_queue.split();
        let (rqp, rqc) = store.request_queue.split();
        let (bfqp, bfqc) = store.brute_force_result_queue.split();
        let (unsqp, unsqc) = store.unsure_channel_queue.split();
        let (bmqp, bmqc) = store.bus_master_messages.split();
        let (bsqp, bsqc) = store.bus_slave_messages.split();


        let ded_ques = DeductionQueues {
            sample_queue: sqc,
            unused_queue: uqc,
            command_queue: cqc,
            request_queue: rqp,
            brute_force_result_queue: bfqc,
            unsure_channel_queue: unsqc,
        };
        let bus_q = BusQueues {
            bus_master_messages: bmqc,
            bus_slave_messages: bsqp,
        };

        let ded = DeduceConnectionParametersControl::new(sqp, uqp, cqp, rqc, bfqp, unsqp);

        let master = JamblerMaster::new(ded, nb_sniffers, bmqp, bsqc);
        (master, bus_q, ded_ques)
    }


    #[test]
    fn sequential_test() {
        let mut store = AllQueuesStore::new();
        const NB_SNIFFERS : u8 = 10;
        let mut sniffer_tasks : [Option<RadioTask>;NB_SNIFFERS as usize] = [None, None, None, None, None, None, None, None, None, None];

        let (mut master, mut bus, mut deducer_queues) = setup(&mut store, 10);

        //let mut start_params = DeductionStartParameters::default();
        //start_params.nb_sniffers = NB_SNIFFERS;

        let spars = DeductionStartParameters {
            nb_sniffers : NB_SNIFFERS,
            slave_phy: BlePhy::CodedS8,
            access_address : 1235234,
            ..Default::default()
        };

        // Also do init test

        let ret = master.execute_command(JamblerCommand::Follow(spars));

        assert_eq!(spars, master.start_parameters);
        assert_eq!(master.nb_sniffers, NB_SNIFFERS);
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: false,
            wake_deducer_task: true,
            wake_master: false
        });
        assert_eq!(master.state, MasterState::Deducing);
        

        if let Some(mm) = deducer_queues.command_queue.dequeue() {
            if let MasterToDeducer::Reset = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        if let Some(MasterToDeducer::Start(sent_to_ded)) = deducer_queues.command_queue.dequeue() {
            assert_eq!(spars, sent_to_ded);
        }
        else {
            panic!("")
        }
        assert!(deducer_queues.command_queue.dequeue().is_none());

        // Start sequential
        deducer_queues.request_queue.enqueue(DeducerToMaster::SearchPacketsForCrcInit(25)).unwrap();
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: false,
            wake_master: false
        });
        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::SequentialTimeOut(25));


        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}

        while let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                assert_eq!(harvest_params.access_address, spars.access_address);
                assert_eq!(harvest_params.master_phy, spars.master_phy);
                assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                assert_eq!(harvest_params.channel, sniffer_id);
                assert_eq!(harvest_params.listen_until, ListenUntil::TimeOut(25));
                sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
            }
            else {
                panic!("wrong harvest params")
            }
        }
        assert!(sniffer_tasks.iter().all(|t| t.is_some()));

        // Let all report unused channel to show they did timeout
        for t in 1..10 {
            let mut unused_channels_m = Vec::new();

            sniffer_tasks.iter().enumerate().for_each(|(id, s)| 
                {
                    let unuse = UnusedChannel {
                        channel : if let RadioTask::Harvest(h) = s.as_ref().unwrap() {h.channel} else {panic!("")},
                        sniffer_id : id as u8
                    };

                    unused_channels_m.push(unuse.clone());

                    if bus.bus_slave_messages.enqueue(SlaveMessage {
                        message : SlaveMessageType::UnusedChannelReport(unuse),
                        slave_id: id as u8,
                        relative_slave_drift: 10,
                        }).is_err() {
                        panic!("overf")
                    }
            });

            let ret = master.master_loop();
            assert_eq!(ret, MasterLoopReturn {
                wake_bus_transmitter: true,
                wake_deducer_task: false,
                wake_master: false
            });

            assert!(deducer_queues.unused_queue.dequeue().is_none());

            while let Some(mm) = bus.bus_master_messages.dequeue() {
                if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                    assert_eq!(harvest_params.access_address, spars.access_address);
                    assert_eq!(harvest_params.master_phy, spars.master_phy);
                    assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                    assert_eq!(harvest_params.channel, (sniffer_id + NB_SNIFFERS * t) % 37);
                    assert_eq!(harvest_params.listen_until, ListenUntil::TimeOut(25));
                    sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
                }
                else {
                    panic!("wrong harvest params")
                }
            }
            assert!(sniffer_tasks.iter().all(|t| t.is_some()));

        }

        // report sample and check if it propagates
        let mut sample = ConnectionSample {
            slave_id: 0,
            channel: 1,
            time: 300,
            silence_time_on_channel: 50,
            packet: ConnectionSamplePacket {
                first_header_byte: 9,
                reversed_crc_init: 123,
                phy: BlePhy::Uncoded1M,
                rssi: 0,
            },
            response: None,
        };

        if bus.bus_slave_messages.enqueue(SlaveMessage {
            message : SlaveMessageType::SampleReport(sample.clone()),
            slave_id: 0,
            relative_slave_drift: 10,
            }).is_err() {
            panic!("overf")
        }
        
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: false,
            wake_deducer_task: true,
            wake_master: false
        });

        // adjust drift
        sample.time += 10;
        let recs = deducer_queues.sample_queue.dequeue().unwrap();
        assert!(deducer_queues.sample_queue.dequeue().is_none());
        assert_eq!(sample, recs);
        assert!(bus.bus_master_messages.dequeue().is_none());
    }



    #[test]
    fn conn_int_test() {
        let mut store = AllQueuesStore::new();
        const NB_SNIFFERS : u8 = 10;
        let mut sniffer_tasks : [Option<RadioTask>;NB_SNIFFERS as usize] = [None, None, None, None, None, None, None, None, None, None];

        let (mut master, mut bus, mut deducer_queues) = setup(&mut store, 10);

        //let mut start_params = DeductionStartParameters::default();
        //start_params.nb_sniffers = NB_SNIFFERS;

        let spars = DeductionStartParameters {
            nb_sniffers : NB_SNIFFERS,
            slave_phy: BlePhy::CodedS8,
            access_address : 1235234,
            ..Default::default()
        };
        master.execute_command(JamblerCommand::Follow(spars));
        master.sniffer_orchestration = SnifferOrchestration::SequentialTimeOut(25);

        // Test going from crc init to conn int
        deducer_queues.request_queue.enqueue(DeducerToMaster::SearchPacketsForConnInterval(50, 1235234, (1 << 15) | (1 << 20))).unwrap();
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: false,
            wake_master: false
        });
        assert_eq!(spars, master.start_parameters);
        assert_eq!(master.nb_sniffers, NB_SNIFFERS);
        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::UsedAlwaysRestTimeOut(50, 1235234, (1 << 15) | (1 << 20)));


        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}

        while let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                assert_eq!(harvest_params.access_address, spars.access_address);
                assert_eq!(harvest_params.master_phy, spars.master_phy);
                assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                if sniffer_id == 0 {
                    assert_eq!(harvest_params.channel, 15);
                    assert_eq!(harvest_params.listen_until, ListenUntil::Indefinitely);
                }
                else if sniffer_id == 1{
                    assert_eq!(harvest_params.channel, 20);
                    assert_eq!(harvest_params.listen_until, ListenUntil::Indefinitely);
                }
                else {
                    assert_eq!(harvest_params.channel, sniffer_id - 2);
                    assert_eq!(harvest_params.listen_until, ListenUntil::TimeOut(50));
                }
                sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
            }
            else {
                panic!("wrong harvest params")
            }
        }
        assert!(sniffer_tasks.iter().all(|t| t.is_some()));

        // Send sample wit OK and with not OK crc init
        let mut sample_nok = ConnectionSample {
            slave_id: 3,
            channel: 0, // 3 is listening on channel 0
            time: 300,
            silence_time_on_channel: 14,
            packet: ConnectionSamplePacket {
                first_header_byte: 9,
                reversed_crc_init: 123, // <- wrong
                phy: BlePhy::Uncoded1M,
                rssi: 0,
            },
            response: None,
        };

        if bus.bus_slave_messages.enqueue(SlaveMessage {
            message : SlaveMessageType::SampleReport(sample_nok.clone()),
            slave_id: 3,
            relative_slave_drift: 10,
            }).is_err() {
            panic!("overf")
        }

        let mut sample = ConnectionSample {
            slave_id: 4,
            channel: 1,
            time: 300,
            silence_time_on_channel: 50,
            packet: ConnectionSamplePacket {
                first_header_byte: 9,
                reversed_crc_init: 1235234,
                phy: BlePhy::Uncoded1M,
                rssi: 0,
            },
            response: None,
        };

        if bus.bus_slave_messages.enqueue(SlaveMessage {
            message : SlaveMessageType::SampleReport(sample.clone()),
            slave_id: 4,
            relative_slave_drift: 10,
            }).is_err() {
            panic!("overf")
        }
        
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: true,
            wake_master: false
        });

        // adjust drift
        sample.time += 10;
        sample_nok.time += 10;
        // Get 3 nok packet out of queue. Have to send because deducers needs non crc oks as well sometimes
        assert_eq!(sample_nok, deducer_queues.sample_queue.dequeue().unwrap());
        assert_eq!(sample, deducer_queues.sample_queue.dequeue().unwrap());
        assert!(deducer_queues.sample_queue.dequeue().is_none());

        // This works with timeouts, so we do not want any message for 3, it just keeps on the same timeout until a correct crc is received
        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                assert_eq!(harvest_params.access_address, spars.access_address);
                assert_eq!(harvest_params.master_phy, spars.master_phy);
                assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                if sniffer_id == 4{
                    assert_eq!(harvest_params.channel, 2);
                    assert_eq!(harvest_params.listen_until, ListenUntil::Indefinitely);
                }
                else {
                    panic!("")
                }
                sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
            }
            else {
                panic!("wrong harvest params")
            }
        }
        assert!(bus.bus_master_messages.dequeue().is_none());

        

        // Send unusedes couple times and check they do not overlap
        for _ in 1..10 {
            let mut unused_channels_m = Vec::new();

            sniffer_tasks.iter().enumerate().filter(|(_,s)| 
                if let RadioTask::Harvest(h) = s.as_ref().unwrap() {h.listen_until != ListenUntil::Indefinitely} else {true})
            .for_each(|(id, s)| 
                {
                    let unuse = UnusedChannel {
                        channel : if let RadioTask::Harvest(h) = s.as_ref().unwrap() {h.channel} else {panic!("")},
                        sniffer_id : id as u8
                    };

                    unused_channels_m.push(unuse.clone());

                    if bus.bus_slave_messages.enqueue(SlaveMessage {
                        message : SlaveMessageType::UnusedChannelReport(unuse),
                        slave_id: id as u8,
                        relative_slave_drift: 10,
                        }).is_err() {
                        panic!("overf")
                    }
            });

            let ret = master.master_loop();
            assert_eq!(ret, MasterLoopReturn {
                wake_bus_transmitter: true,
                wake_deducer_task: false,
                wake_master: false
            });

            assert!(deducer_queues.unused_queue.dequeue().is_none());

            while let Some(mm) = bus.bus_master_messages.dequeue() {
                if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                    assert_eq!(harvest_params.access_address, spars.access_address);
                    assert_eq!(harvest_params.master_phy, spars.master_phy);
                    assert_eq!(harvest_params.slave_phy, spars.slave_phy);

                    let before = unused_channels_m.iter().find(|u| u.sniffer_id == sniffer_id).unwrap();

                    assert!(harvest_params.channel != before.channel);
                    assert_eq!(harvest_params.listen_until, ListenUntil::TimeOut(50));
                    sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
                }
                else {
                    panic!("wrong harvest params")
                }
            }
            assert!(sniffer_tasks.iter().all(|t| t.is_some()));

            assert!(sniffer_tasks.iter().enumerate().all(|(d,s)| 
                if let Some(RadioTask::Harvest(h)) = s.as_ref() {
                    if [0,1,4].contains(&(d as u8)) {
                        h.listen_until == ListenUntil::Indefinitely
                    }
                    else {
                        h.listen_until == ListenUntil::TimeOut(50)
                    }
                }
                else {
                    false
                }
            ));

            assert!(sniffer_tasks.iter().map(|s| 
                if let Some(RadioTask::Harvest(h)) = s.as_ref() {
                    h.channel
                }
                else {
                    panic!("")
                }
            ).unique().count() == NB_SNIFFERS as usize);

        }


    }



    #[test]
    fn channel_map_test() {
        let mut store = AllQueuesStore::new();
        const NB_SNIFFERS : u8 = 10;
        let mut sniffer_tasks : [Option<RadioTask>;NB_SNIFFERS as usize] = [None, None, None, None, None, None, None, None, None, None];

        let (mut master, mut bus, mut deducer_queues) = setup(&mut store, 10);

        //let mut start_params = DeductionStartParameters::default();
        //start_params.nb_sniffers = NB_SNIFFERS;

        let spars = DeductionStartParameters {
            nb_sniffers : NB_SNIFFERS,
            slave_phy: BlePhy::CodedS8,
            access_address : 1235234,
            ..Default::default()
        };
        master.execute_command(JamblerCommand::Follow(spars));
        master.sniffer_orchestration =  SnifferOrchestration::UsedAlwaysRestTimeOut(50, 1235234, (1 << 15) | (1 << 20));

        let mut cht = !((1 << 15) | (1 << 20)) & 0x1F_FF_FF_FF_FF;

        // Test going from conn int to channel map
        deducer_queues.request_queue.enqueue(DeducerToMaster::StartChannelMap(500, cht, 1235234)).unwrap();
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: false,
            wake_master: false
        });
        assert_eq!(spars, master.start_parameters);
        assert_eq!(master.nb_sniffers, NB_SNIFFERS);
        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::TimeOutRemaining(500, cht ^ 0b11_1111_1111,1235234,(1 << 15) | (1 << 20)));


        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}

        while let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                assert_eq!(harvest_params.access_address, spars.access_address);
                assert_eq!(harvest_params.master_phy, spars.master_phy);
                assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                assert_eq!(harvest_params.channel, sniffer_id );
                cht &= !(1 << harvest_params.channel) & 0x1F_FF_FF_FF_FF;
                assert_eq!(harvest_params.listen_until, ListenUntil::PacketReception(500));
                sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
            }
            else {
                panic!("wrong harvest params")
            }
        }
        assert!(sniffer_tasks.iter().all(|t| t.is_some()));

        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::TimeOutRemaining(500, cht,1235234,(1 << 15) | (1 << 20)));

        // Send sample with not OK crc init
        let mut sample_nok = ConnectionSample {
            slave_id: 0,
            channel: 0, // 3 is listening on channel 0
            time: 300,
            silence_time_on_channel: 14,
            packet: ConnectionSamplePacket {
                first_header_byte: 9,
                reversed_crc_init: 123, // <- wrong
                phy: BlePhy::Uncoded1M,
                rssi: 0,
            },
            response: None,
        };

        if bus.bus_slave_messages.enqueue(SlaveMessage {
            message : SlaveMessageType::SampleReport(sample_nok.clone()),
            slave_id: 0,
            relative_slave_drift: 10,
            }).is_err() {
            panic!("overf")
        }

        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: true,
            wake_master: false
        });

        // adjust drift
        sample_nok.time += 10;
        assert_eq!(sample_nok, deducer_queues.sample_queue.dequeue().unwrap());
        assert!(deducer_queues.sample_queue.dequeue().is_none());

        if let Some(MasterMessage { recipient : BusRecipient::Slave(0), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(h)) }) = bus.bus_master_messages.dequeue() {
            assert_eq!(h.channel, 0);
            assert_eq!(h.listen_until, ListenUntil::PacketReception(500 - 14)); // Should listen for remaining time
        }
        else {
            panic!("")
        }
        assert!(bus.bus_master_messages.dequeue().is_none());

        let mut rng = thread_rng();

        // TODO laat ze de channels reporten tot er geen meer zijn en check dan ook op brute force parameters door ze te zenden achteraf
        let mut channels_todo_vec = (0..37u8).filter(|c| cht & (1 << *c) != 0).collect::<Vec<_>>();
        let mut stop = false;
        while !stop {
            // let report 2 as used, 3 unused
            let mut candidates = sniffer_tasks.iter().enumerate().map(|(d,s)| 
                if let Some(RadioTask::Harvest(h)) = s {
                    (d as u8, h.channel)
                }
                else {
                    panic!("")
                }
            ).filter(|(s, c)| master.sniffer_positions[*s as usize] != u8::MAX)
            .inspect(|(s, c)|  assert_eq!(master.sniffer_positions[*s as usize], *c))
            .collect_vec();

            stop = candidates.is_empty();

            candidates.shuffle(&mut rng);
            let chantot = candidates.iter().take(4).cloned().collect_vec();
            let channels_to_see = chantot.iter().enumerate().filter_map(|(i, c)| if i % 2 == 0 {Some(*c)} else {None}).collect_vec();
            let channels_to_not_see = chantot.iter().enumerate().filter_map(|(i, c)| if i % 2 != 0 {Some(*c)} else {None}).collect_vec();

            let mut samples = vec![];
            let mut sniffers = chantot.iter().map(|c| c.0).collect_vec();
            
            

            for (sniffer_id, channel) in channels_to_see {

                let sample = ConnectionSample {
                    slave_id: sniffer_id,
                    channel,
                    time: 300,
                    silence_time_on_channel: 50,
                    packet: ConnectionSamplePacket {
                        first_header_byte: 9,
                        reversed_crc_init: 1235234,
                        phy: BlePhy::Uncoded1M,
                        rssi: 0,
                    },
                    response: None,
                };
    
                if bus.bus_slave_messages.enqueue(SlaveMessage {
                    message : SlaveMessageType::SampleReport(sample.clone()),
                    slave_id: sniffer_id,
                    relative_slave_drift: -10,
                    }).is_err() {
                    panic!("overf")
                }

                samples.push(sample)

            }

            let mut unuseds = vec![];
            
            for (sniffer_id, channel) in channels_to_not_see {
                let sample = UnusedChannel {
                    channel,
                    sniffer_id
                };
                if bus.bus_slave_messages.enqueue(SlaveMessage {
                    message : SlaveMessageType::UnusedChannelReport(sample.clone()),
                    slave_id: sniffer_id,
                    relative_slave_drift: -10,
                    }).is_err() {
                    panic!("overf")
                }
                unuseds.push(sample)
            }
            
            let ret = master.master_loop();
            assert_eq!(ret, MasterLoopReturn {
                wake_bus_transmitter: !channels_todo_vec.is_empty(),
                wake_deducer_task: !stop,
                wake_master: false
            });

            // Check if they were put through
            while let Some(mut s) = deducer_queues.sample_queue.dequeue() {
                s.time += 10;
                let i = samples.iter().position(|a| a == &s).unwrap();
                samples.remove(i);
            }
            assert!(samples.is_empty());

            while let Some( s) = deducer_queues.unused_queue.dequeue() {
                let i = unuseds.iter().position(|a| a == &s).unwrap();
                unuseds.remove(i);
            }
            assert!(unuseds.is_empty());

            // Check if they were reassigned
            while let Some(mm) = bus.bus_master_messages.dequeue() {
                if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                    assert_eq!(harvest_params.access_address, spars.access_address);
                    assert_eq!(harvest_params.master_phy, spars.master_phy);
                    assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                    assert!(sniffers.contains(&sniffer_id));
                    let r = sniffers.iter().position(|g| g == &sniffer_id).unwrap();
                    sniffers.remove(r);
                    let c = harvest_params.channel;
                    let r = channels_todo_vec.iter().position(|g| g == &c).unwrap();
                    channels_todo_vec.remove(r);
                    assert_eq!(harvest_params.listen_until, ListenUntil::PacketReception(500));
                    sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
                }
                else {
                    panic!("wrong harvest params")
                }
            }
            assert!(bus.bus_master_messages.dequeue().is_none());

            assert!(sniffers.is_empty() || channels_todo_vec.is_empty());

            if let SnifferOrchestration::TimeOutRemaining(500, 0,1235234,_) = master.sniffer_orchestration {
                assert!(channels_todo_vec.is_empty())
            }
        }


        if let SnifferOrchestration::TimeOutRemaining(500, 0,1235234,_) = master.sniffer_orchestration {
        } else {panic!("")}

        // see if it does not get more
        let sample = ConnectionSample {
            slave_id: 0,
            channel : 0,
            time: 300,
            silence_time_on_channel: 50,
            packet: ConnectionSamplePacket {
                first_header_byte: 9,
                reversed_crc_init: 1235234,
                phy: BlePhy::Uncoded1M,
                rssi: 0,
            },
            response: None,
        };

        if bus.bus_slave_messages.enqueue(SlaveMessage {
            message : SlaveMessageType::SampleReport(sample),
            slave_id: 0,
            relative_slave_drift: -10,
            }).is_err() {
            panic!("overf")
        }


        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: false,
            wake_deducer_task: true,
            wake_master: false
        });

        assert!(bus.bus_master_messages.dequeue().is_none());

        assert!(deducer_queues.sample_queue.dequeue().is_some());
        assert!(deducer_queues.sample_queue.dequeue().is_none());

        if let SnifferOrchestration::TimeOutRemaining(500, 0,1235234,_) = master.sniffer_orchestration {
        } else {panic!("")}

        // check brute force
        #[cfg(not(target_arch="x86_64"))]
        {static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;(NB_SNIFFERS + 1) as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};}

        let mut bf = convert_bf_param(&BruteForceParameters::default());

        bf.seen_channel_map =  !((1 << 5) | (1 << 20)) & 0x1F_FF_FF_FF_FF;

        // Test going from conn int to channel map
        deducer_queues.request_queue.enqueue(DeducerToMaster::DistributedBruteForce(clone_bf_param(&bf), bf.seen_channel_map)).unwrap();
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: false,
            wake_master: false
        });
        assert_eq!(spars, master.start_parameters);
        assert_eq!(master.nb_sniffers, NB_SNIFFERS);
        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::UsedAlwaysRestTimeOut(0,0, bf.seen_channel_map));


        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        
        let mut bf_seen = false;
        while let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(sniffer_id), message : MasterMessageType::RadioTaskRequest(RadioTask::Harvest(harvest_params)) } = mm {
                assert_eq!(harvest_params.access_address, spars.access_address);
                assert_eq!(harvest_params.master_phy, spars.master_phy);
                assert_eq!(harvest_params.slave_phy, spars.slave_phy);
                let c = sniffer_id + if sniffer_id >= 5 {1} else {0};
                assert_eq!(harvest_params.channel , c);
                assert_eq!(harvest_params.listen_until, ListenUntil::Indefinitely);
                sniffer_tasks[sniffer_id as usize] = Some(RadioTask::Harvest(harvest_params));
            }
            else if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::BruteForce(p) } = mm {
                assert_eq!(p, bf);
                assert!(!bf_seen);
                bf_seen = true;
            }
            else {
                panic!("wrong harvest params")
            }
        }
        assert!(bus.bus_master_messages.dequeue().is_none());
        assert!(bf_seen);


        if bus.bus_slave_messages.enqueue(SlaveMessage {
            message : SlaveMessageType::BruteForceResultReport(BruteForceResult {
                slave_id: 4,
                version: 1,
                result: crate::jambler::deduction::deducer::CounterInterval::NoSolutions,
            }),
            slave_id: 4,
            relative_slave_drift: -10,
            }).is_err() {
            panic!("overf")
        }

        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: false,
            wake_deducer_task: true,
            wake_master: false
        });

        if let Some(d) = deducer_queues.brute_force_result_queue.dequeue() {
            assert_eq!(d.slave_id, 4);
            assert_eq!(d.version, 1);
            assert_eq!(d.result, crate::jambler::deduction::deducer::CounterInterval::NoSolutions);
        }
        else {panic!()}
        assert!(deducer_queues.brute_force_result_queue.dequeue().is_none())
    }

    #[test]
    fn follow_unsure_test() {
        let mut store = AllQueuesStore::new();
        const NB_SNIFFERS : u8 = 10;

        let (mut master, mut bus, mut deducer_queues) = setup(&mut store, 10);

        //let mut start_params = DeductionStartParameters::default();
        //start_params.nb_sniffers = NB_SNIFFERS;

        let spars = DeductionStartParameters {
            nb_sniffers : NB_SNIFFERS,
            slave_phy: BlePhy::CodedS8,
            access_address : 1235234,
            ..Default::default()
        };
        master.execute_command(JamblerCommand::Follow(spars));
        master.sniffer_orchestration =  SnifferOrchestration::UsedAlwaysRestTimeOut(0,0, 1234);


        // check brute force
        #[cfg(not(target_arch="x86_64"))]
        {static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;(NB_SNIFFERS + 1) as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};}
        #[cfg(not(target_arch="x86_64"))]
        {static mut DP_HEAP : MaybeUninit<[Node<DeducedParameters>;10]> = MaybeUninit::uninit();
        unsafe{DeducedParametersBox::grow_exact(&mut DP_HEAP)};}


        let unsures = vec![2u8,3,4];
        let unsures_map = unsures.iter().fold(0u64, |b,c| b | (1 << *c));

        let dp = DeducedParameters {
            access_address : spars.access_address,
            slave_phy : spars.slave_phy,
            master_phy : spars.master_phy,
            channel_map : unsures_map,
            ..Default::default()
        };

        let dp = convert_deduced_param(&dp);


        let mut dp_cop = convert_deduced_param(&dp);

        // Test going from conn int to channel map
        deducer_queues.request_queue.enqueue(DeducerToMaster::ListenForUnsureChannels(dp, unsures_map)).unwrap();
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: false,
            wake_master: false
        });
        assert_eq!(spars, master.start_parameters);
        assert_eq!(master.nb_sniffers, NB_SNIFFERS);
        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::Follow(Some(unsures_map)));
        #[cfg(target_arch="x86_64")]
        assert_eq!(master.connection_parameters, dp_cop);
        #[cfg(not(target_arch="x86_64"))]
        assert_eq!(master.connection_parameters, *dp_cop);

        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}

        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(0), message : MasterMessageType::RadioTaskRequest(RadioTask::Follow(d, Some(ch))) } = mm {
                assert_eq!(dp_cop, d);
                assert_eq!(unsures_map, ch);
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        assert!(bus.bus_master_messages.dequeue().is_none());

        let mut event_counter = 4;
        for (time, channel) in (1000u64..100000).step_by(1000).zip((0..37u8).cycle()) {
            let mut event = UnsureChannelEvent {
                channel,
                time,
                event_counter,
                seen: event_counter % 2 == 0,
            };

            let mes = SlaveMessage {
                slave_id: 0,
                message: SlaveMessageType::UnsureChannelEventReport(event.clone()),
                relative_slave_drift: -10,
            };

            if bus.bus_slave_messages.enqueue(mes).is_err() {
                panic!("overf")
            }

            let should_report = unsures.contains(&channel);

            let ret = master.master_loop();
            assert_eq!(ret, MasterLoopReturn {
                wake_bus_transmitter: false,
                wake_deducer_task: should_report,
                wake_master: false
            });

            event.time -= 10;

            if should_report {
                assert_eq!(event, deducer_queues.unsure_channel_queue.dequeue().unwrap());
                assert!(deducer_queues.unsure_channel_queue.dequeue().is_none());
            }

            if event.seen {
                assert_eq!(master.connection_parameters.last_time, time - 10);
                assert_eq!(master.connection_parameters.last_counter, event_counter);
            }

            event_counter = event_counter.wrapping_add(1);
        }


        deducer_queues.request_queue.enqueue(DeducerToMaster::DeducedParameters(convert_deduced_param(&master.connection_parameters))).unwrap();
        let ret = master.master_loop();
        assert_eq!(ret, MasterLoopReturn {
            wake_bus_transmitter: true,
            wake_deducer_task: false,
            wake_master: false
        });
        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::NotDeducing);
        assert_eq!(master.state, MasterState::Following);

        dp_cop.last_time = master.connection_parameters.last_time;
        dp_cop.last_counter = master.connection_parameters.last_counter;

        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}

        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Slave(0), message : MasterMessageType::RadioTaskRequest(RadioTask::Follow(d, None)) } = mm {
                assert_eq!(dp_cop, d);
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        assert!(bus.bus_master_messages.dequeue().is_none());
    }


    #[test]
    fn reset_test() {
        let mut store = AllQueuesStore::new();
        const NB_SNIFFERS : u8 = 10;

        let (mut master, mut bus, mut deducer_queues) = setup(&mut store, 10);

        //let mut start_params = DeductionStartParameters::default();
        //start_params.nb_sniffers = NB_SNIFFERS;

        let spars = DeductionStartParameters {
            nb_sniffers : NB_SNIFFERS,
            slave_phy: BlePhy::CodedS8,
            access_address : 1235234,
            ..Default::default()
        };
        master.execute_command(JamblerCommand::Follow(spars));

        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        while bus.bus_master_messages.dequeue().is_some() {
            
        }
        assert!(bus.bus_master_messages.dequeue().is_none());

        if let Some(mm) = deducer_queues.command_queue.dequeue() {
            if let MasterToDeducer::Reset = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        assert!(deducer_queues.command_queue.dequeue().is_some());
        assert!(deducer_queues.command_queue.dequeue().is_none());

        master.reset();
        if let Some(mm) = bus.bus_master_messages.dequeue() {
            if let MasterMessage { recipient : BusRecipient::Broadcast, message : MasterMessageType::Idle} = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        assert!(bus.bus_master_messages.dequeue().is_none());


        assert_eq!(master.sniffer_orchestration, SnifferOrchestration::NotDeducing);
        assert_eq!(master.state, MasterState::Idle);

        if let Some(mm) = deducer_queues.command_queue.dequeue() {
            if let MasterToDeducer::Reset = mm {
            }
            else {
                panic!("wrong harvest params")
            }
        } else {panic!()}
        assert!(deducer_queues.command_queue.dequeue().is_none());

    }
}