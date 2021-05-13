
use super::BlePhy;
use super::PDU;
use heapless::pool::singleton::Box;

#[derive(Debug, Clone)]
pub enum JamblerHalError {
    SetAccessAddressError,
    InvalidChannel(u8),
}

/// The trait that a specific chip has to implement to be used by the jammer.
///
/// Reset can be called at any point.
///
/// ANY FUNCTION HERE SHOULD BE INLINED IN IMPLEMENTATION!
pub trait JamblerRadio {
    /// Start sending with the current configuration.
    /// Radio should be configure before this.
    /// Should be called shortly after config and fire up very fast, so any speedup achieved by making the radio more ready but consume more power should already running.
    fn send(&mut self);

    /// Start receiving with the current configuration.
    /// Radio should be configured before this.
    /// Should be called shortly after config and fire up very fast, so any speedup achieved by making the radio more ready but consume more power should already running.
    fn receive(&mut self);

    /// Should reset the radio to the same state as if at was on power on.
    /// Should be in some sort of idle or powered off state.
    /// Will often get called on initialising the radio for a new state.
    /// Should prevent any radio interrupts from happening past this point.
    fn reset(&mut self);

    /// Should prepare the radio for a configuration change.
    /// This might be a reset, but that may be too harsh.
    /// Any configurations between the previous reset and now should remain the exact same.
    /// It is more to safely change the access address for example and maybe the chip requires you should not be sending.
    fn prepare_for_config_change(&mut self);

    /// Should "pause" the radio, stopping any interrupt from being received.
    /// Should not change anything to the configuration and does not need to be a low power mode.
    fn idle(&mut self);

    /* // *** Discovering access addresses *** */

    /// Should get the radio ready for listening on the given phy and channel
    /// This config is special because many chips require hacks and cannot sniff every possible packet normally by listening.
    fn config_discover_access_addresses(
        &mut self,
        phy: BlePhy,
        channel: u8,
        minimum_rssi: Option<i8>,
    );

    /// Reads the access address from the receive buffer of you chip.
    /// Might be hacky for certain chips.
    fn read_discovered_access_address(&mut self, timer: &mut impl JamblerRestrictedTimer, aa_match_time: u64) -> Option<(u32, i8)>;

    /* // *** Harvesting packets *** */

    /// Should configure the radio to receive all packets sent by the given
    /// access address on the given phy and channel.
    /// Should enable crc checking (but not ignore failed checks) if the given crc_init is Some. Otherwise none.
    fn config_harvest_packets(
        &mut self,
        access_address: u32,
        phy: BlePhy,
        channel: u8,
        crc_init: Option<u32>,
    );

    /// Returns Some if a packet was received on the channel, phy and access address configured using the last config_harvest_packets.
    /// Regardless of whether the crc check failed/succeeded.
    ///
    /// In the Some case, Some contains a HalHarvestedPacket.
    /// See the comments for that to know what it contains.
    fn handle_harvest_packets_radio_interrupt(&mut self) -> Option<HalHarvestedPacket>;

    fn harvest_packets_quick_config(
        &mut self,
        access_address: u32,
        phy: BlePhy,
        channel: u8,
        crc_init: Option<u32>,
        master_pdu_buffer: &mut Box<PDU>,
    );

    /// Gets called after radio interrupt handler.
    /// If received a master packet, return some.
    /// If within busy wait time, second part will be some as well.
    /// These are supposed to be the crc's of the received packets.
    /// The slave packets has to be copied to the slave pdu buffer.
    fn harvest_packets_busy_wait_slave_response(
        &mut self,
        slave_phy: BlePhy,
        master_pdu_buffer: &mut Box<PDU>,
        slave_pdu_buffer: &mut Box<PDU>,
    ) -> PossiblePackets;
}

pub type PossiblePackets = Option<((u32, i8), Option<(u32, i8)>)>;

/// Return information when requested to harvest packets.
#[derive(Debug)]
pub struct HalHarvestedPacket {
    /// Some if crc has been enabled by providing a Some(crc_init) value in the latest config_harvest_packets. True if the crc check was successfull, false if it wasn't.
    pub crc_ok: bool,
    /// Some if instructed to reverse calculate the crc init and able to do so.
    /// Then it contains the reversed crc for this packet as it has been received (might have been received with errors).
    pub crc_init: u32,
    /// The rssi, why not
    pub rssi: i8,
    pub first_header_byte: u8,
    pub second_header_byte: u8,
}

/// A long term timer.
/// Should be accurate up until a microseconds and last for more than the lifetime of a human (= u64 wraparound counter).
/// TODO callback for correcting for a number of microseconds (BLE slave anchor point synchronisation, clock synchronisation over I2C).
pub trait JamblerTimer {
    /// Starts the timer
    fn start(&mut self);

    /// Gets the duration since the start of the count in micro seconds.
    /// Micro should be accurate enough for any BLE event.
    /// SHOULD ALWAYS BE INLINED
    fn get_time_micro_seconds(&self) -> u64;

    /// Called after 
    fn get_packet_received_time(&mut self) -> u64;

    /// Busy wait an amount of microseconds.
    /// Max 71 minutes because of u32
    fn busy_wait_us(&mut self, delay : u32);

    /// Resets the timer.
    fn reset(&mut self);

    /// Gets the drift of the timer in nanoseconds, rounded up.
    fn get_ppm(&self) -> u32;

    fn get_drift_percentage(&self) -> f64 {
        // ppm stands for parts per million, so divide by 1 million.
        self.get_ppm() as f64 / 1000000_f64
    }

    /// Gets the maximum amount of time before overflow in milliseconds, rounded down.
    fn get_max_time_us(&self) -> u64;

    /// Requests an interrupt at the given point in time.
    /// Returns Err if an interrupt is already pending.
    /// Only one interrupt at a time allowed.
    fn request_interrupt_at(&mut self, time : u64) -> Result<(), ()>;

    fn reset_interrupt_at(&mut self);

    /// Will be called when an interrupt for the timer occurs.
    /// Returns true if the interrupt was generated because it was requested by a state.
    fn interrupt_handler(&mut self) -> bool;
}

/// Restricted access to the timer for general time keeping.
pub trait JamblerRestrictedTimer {
    fn get_time_us(&mut self) -> u64;

    /// Busy wait an amount of microseconds.
    /// Max 71 minutes because of u32
    fn busy_wait_us(&mut self, delay : u32);

    fn get_ppm(&self) -> u32;
}

impl<T> JamblerRestrictedTimer for T where T: JamblerTimer {
    fn get_time_us(&mut self) -> u64 {
        self.get_time_micro_seconds()
    }

    fn busy_wait_us(&mut self, delay : u32) {
        self.busy_wait_us(delay)
    }

    fn get_ppm(&self) -> u32 {self.get_ppm()}
}

/// A timer which should generate an interrupt on its given interval.
/// ANY FUNCTION HERE SHOULD BE INLINED IN IMPLEMENTATION!
pub trait JamblerIntervalTimer {
    /// Sets the interval in microseconds and if the timer should function as a countdown or as a periodic timer.
    /// Returns false if the interval is too long for the timer.
    fn config(&mut self, interval: u32, periodic: bool) -> bool;

    /// Starts the timer
    ///
    fn start(&mut self);

    /// Resets the timer.
    fn reset(&mut self);

    /// Anything a timer needs to do to keep itself going on an interrupt.
    fn interrupt_handler(&mut self);
}
