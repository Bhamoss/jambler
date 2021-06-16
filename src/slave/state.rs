pub mod harvest;
pub mod idle;
pub mod follow;

/// Jammer states trait
/// This will handle the ugly truth of avoiding dynamic dispatch.
use crate::{master::RadioTask};

use super::{JamblerReturn, JamblerRadio, hardware_traits::JamblerTimer};



/// Struct for letting a state return something
///
/// Return string was completely removed, the state/master main should do user output
pub struct StateReturn {
    pub jambler_return: Option<JamblerReturn>
}

impl StateReturn {
    /// A convenience constructor.
    /// Everything None, change the fields manually to what is necessary.
    pub fn new() -> StateReturn {
        StateReturn {
            jambler_return: None
        }
    }

    /// Resets the struct so it can be reused.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.jambler_return = None
    }
}

/// Struct for passing parameters to a state.
/// Takes a mutable reference to a JamBLErHal which
/// must have a lifetime as long as the parameter lives
///
/// In all function where this is used it should be a mutable reference
/// that is passed to reduce stack size.
pub struct StateParameters {
    /// The time at which the call was made.
    /// Can be a special value for interrupts (binding timers to it etc..)
    /// For circumventing software delays
    pub current_time: u64,
}

impl StateParameters {
    pub fn new(instant_in_microseconds: u64) -> StateParameters {
        StateParameters {
            current_time: instant_in_microseconds,
        }
    }

    pub fn new_no_config(instant_in_microseconds: u64) -> StateParameters {
        StateParameters {
            current_time: instant_in_microseconds,
        }
    }

    /// Resets the parameters, making it ready for reuse.
    /// Does not reset the current_time, as this has to be overwritten.
    /// Does not reset the radio as this should be initialised once and remain.
    #[inline(always)]
    pub fn reset(&mut self) {
    }
}



pub trait JammerState<R: JamblerRadio,T: JamblerTimer> : core::default::Default {

    /// Returns an error if a required config parameter was missing.
    fn start(
        &mut self, 
        task : &RadioTask,
        radio: &mut R, 
        timer: &mut T,
        //parameters: &mut StateParameters
    );

    /// Handle a radio interrupt.
    /// ALWAYS INLINE IN IMPLEMENTATION!
    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        //parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    );

    /// Handle an interval timer interrupt.
    /// ALWAYS INLINE IN IMPLEMENTATION!
    fn handle_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        //parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    );
}

/// Will hold a struct of every possible state.
/// Necessary to avoid dynamic allocation but leverage polymorphism
/// and use the state GOF pattern.
/// It will have a function that will return a reference to the right jammerstate implementation given the corresponding JamBLErState enum.
pub struct StateStore {
    idle: idle::Idle,
    harvest: harvest::Harvest,
    follow: follow::Follow,
}


impl core::default::Default for StateStore {
    fn default() -> Self {
        StateStore {
            idle: idle::Idle::default(),
            harvest: harvest::Harvest::default(),
            follow: follow::Follow::default(),
        }
    }

}

impl StateStore {
    /// Transitions state in the proper way, only for valid state transitions.
    /// This also serves as a way for me to protect me from myself and easily catch things I did not intend to happen.
    ///
    /// Calibrate interval timer should always be last
    pub fn start<R: JamblerRadio, T: JamblerTimer> (
        &mut self,
        task: &RadioTask,
        radio: &mut R,
        timer: &mut T,
    ) {

        match task {
            RadioTask::Harvest(_) => self.harvest.start(task, radio, timer),
            RadioTask::Follow(_, _) => self.follow.start(task, radio, timer),
            RadioTask::Idle => self.idle.start(task, radio, timer),
        }

    }

    /// Will dispatch the radio interrupt to the right jammerstate for the current jamblerstate.
    #[inline]
    pub fn handle_radio_interrupt<R: JamblerRadio, T: JamblerTimer>(
        &mut self,
        task: &RadioTask,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        return_value: &mut StateReturn,
    ) {
        match task {
            RadioTask::Harvest(_) => self.harvest.handle_radio_interrupt(radio, timer, interrupt_time, return_value),
            RadioTask::Follow(_, _) => self.follow.handle_radio_interrupt(radio, timer, interrupt_time, return_value),
            RadioTask::Idle => self.idle.handle_radio_interrupt(radio, timer, interrupt_time, return_value),
        }
    }

    /// Will dispatch the interval timer interrupt to the right jammerstate for the current jamblerstate.
    #[inline]
    pub fn handle_interval_timer_interrupt<R: JamblerRadio, T: JamblerTimer>(
        &mut self,
        task: &RadioTask,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        return_value: &mut StateReturn,
    ) {
        match task {
            RadioTask::Harvest(_) => self.harvest.handle_timer_interrupt(radio, timer, interrupt_time, return_value),
            RadioTask::Follow(_, _) => self.follow.handle_timer_interrupt(radio, timer, interrupt_time, return_value),
            RadioTask::Idle => self.idle.handle_timer_interrupt(radio, timer, interrupt_time, return_value),
        }
    }
}
