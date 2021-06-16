
use super::{BlePhy};
#[cfg(not(target_arch="x86_64"))]
use heapless::pool::singleton::Box;
#[cfg(not(target_arch="x86_64"))]
use super::PDU;

#[derive(Clone, PartialEq, Eq)]
pub struct ListenParameters {
    pub access_address : u32,
    pub crc_init : Option<u32>,
    pub channel : u8,
    pub phy : BlePhy
}

/// The trait that a specific chip has to implement to be used by the jammer.
///
/// Reset can be called at any point.
///
/// ANY FUNCTION HERE SHOULD BE INLINED IN IMPLEMENTATION!
/// RI: Radio interrupt
/// TI: Timer interrupt
pub trait JamblerRadio {

    /// Should reset the radio to the same state as if at was on power on.
    fn reset(&mut self);

    fn listen_start(&mut self, params: &ListenParameters);

    fn listen_radio_interrupt(&mut self) -> Option<HalHarvestedPacket>;

}


// Necessary for mutlithreading on x86
#[cfg(target_arch="x86_64")]
use super::PDU_SIZE;
#[cfg(target_arch="x86_64")]
pub type HalPdu = [u8; PDU_SIZE];
#[cfg(not(target_arch="x86_64"))]
pub type HalPdu = Box<PDU>;

/// Return information when requested to harvest packets.
pub struct HalHarvestedPacket {
    pub crc : u32,
    pub rssi: i8,
    pub first_header_byte: u8,
    pub len: u8,
    pub pdu: HalPdu,
    pub phy: BlePhy,
    pub crc_status : CrcStatus
}



impl core::fmt::Display for HalHarvestedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let three_byte_header: bool = self.pdu[0] & 0b0010_0000 != 0;
        if three_byte_header {
            write!(
                f,
                "\n|         Header      | ... Payload ... |   CRC   |  RSSI   | PHY
                       \n|{:08b} {:3} {:08b}| ...{:3} bytes... | 0x{:06X}| {:>4}dBm | {:?}
                       ",
                self.pdu[0], self.pdu[1], self.pdu[2], self.pdu[1], self.crc, self.rssi, self.phy
            )
        } else {
            write!(
                f,
                "\n|   Header   | ... Payload ... |   CRC   |  RSSI   | PHY
                       \n|{:08b} {:3}| ...{:3} bytes... | 0x{:06X}| {:>4}dBm | {:?}
                       ",
                self.pdu[0], self.pdu[1], self.pdu[1], self.crc, self.rssi, self.phy
            )
        }
    }
}

impl core::fmt::Debug for HalHarvestedPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self)
    }
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

    /// Called after receiving a packet. Needs to be accurate to the microsecond.
    /// As backup, the get time function can be used to implement this but many devices provide something specialised for this.
    fn get_packet_received_start_time(&mut self) -> u64;


    /// Should capture when an interrupt was made. 
    /// For example, if it is supposed to wrap, this will just be the u64 << 32 part.
    /// If it was a radio interrupt, it should be the (wrapping) amount of ticks the timer moved on.
    fn get_interrupt_time(&mut self) -> u64;

    /// Gets the drift of the timer in nanoseconds, rounded up.
    fn get_ppm(&self) -> u32;

    /// Requests an interrupt at the given point in time.
    /// Returns true if the the has not passed yet, false if it has.
    fn request_interrupt_at(&mut self, time : u64) -> bool;

    /// Cancels any pending interrupt.
    fn cancel_interrupt(&mut self);

    /// Will be called when an interrupt for the timer occurs.
    /// Returns true if the interrupt was generated because it was requested by a state.
    fn interrupt_handler(&mut self) -> bool;
}

/// Restricted access to the timer for general time keeping.
pub trait RestrictedTimer {
    fn get_time_us(&mut self) -> u64;

    /// Busy wait an amount of microseconds.
    /// Max 71 minutes because of u32
    fn busy_wait_us(&mut self, delay : u32) {
        let end = self.get_time_us() + delay as u64;
        while self.get_time_us() < end  {}
    }

    fn get_ppm(&self) -> u32;
}

impl<T> RestrictedTimer for T where T: JamblerTimer {
    fn get_time_us(&mut self) -> u64 {
        self.get_time_micro_seconds()
    }

    fn get_ppm(&self) -> u32 {self.get_ppm()}
}


pub enum CrcStatus {
    Unknown,
    Passed,
    Failed
}


#[cfg(test)]
pub mod dummy_test_hals {

    use super::*;

    pub struct DummyRadio {
        pub has_been_reset: bool,
        pub params: ListenParameters,
        pub harvested_packet : Vec<Option<HalHarvestedPacket>>
    }
    impl JamblerRadio for DummyRadio {
        fn reset(&mut self) {
            self.has_been_reset = true
        }

        fn listen_start(&mut self, params: &ListenParameters) {
            self.params = params.clone();
            self.has_been_reset = false
        }

        fn listen_radio_interrupt(&mut self) -> Option<HalHarvestedPacket> {
            self.harvested_packet.pop().unwrap()
        }
    }

    pub struct DummyTimer {
        pub time : u64,
        pub packet_received_time : u64,
        pub interrupt_time : u64,
        pub pending_interrupt : Option<u64>,
    }
    impl JamblerTimer for DummyTimer {
        fn start(&mut self) {
        }

        fn get_time_micro_seconds(&self) -> u64 {
            self.time
        }

        fn get_packet_received_start_time(&mut self) -> u64 {
            self.packet_received_time
        }

        fn get_ppm(&self) -> u32 {
            20
        }

        fn request_interrupt_at(&mut self, time : u64) -> bool {
            let before = self.pending_interrupt.is_some();
            self.pending_interrupt = Some(time);
            before
        }

        fn cancel_interrupt(&mut self) {
            self.pending_interrupt = None
        }

        fn interrupt_handler(&mut self) -> bool {
            true
        }

        fn get_interrupt_time(&mut self) -> u64 {
            self.interrupt_time
        }
    }

}