use super::{super::JamblerRadio, JammerStateBasic};
use super::JammerState;
use super::StateMessage;
use super::StateParameters;
use super::StateReturn;
use crate::jambler::{hardware_traits::JamblerRestrictedTimer, state::IntervalTimerRequirements};
use crate::jambler::JamblerState;

#[derive(Clone)]
enum CalibrationSequence {
    StateChangeToPeriodic,
    PeriodicToPeriodic,
    PeriodicToCountdown,
}

/// A state used for calibrating the interval timer.
/// For calculating the delay between asking for an interval timer in the initialise state, changing the interval timer and the interrupt delay.
/// The long term timer is used for this. This one keeps on running so we can use it as a benchmark.
///
/// It goes state_change -> periodic interrupt 1 -> periodic interrupt 2 -> Countdown 1
/// with each phase requesting the other, except the 2 periodic ones.
///
/// The only unknown variable after this is that we do not know the (constant) delay between an interrupt firing and and the parameter.current time measurement.
/// We also do not know the influence of preemption, but this does not matter because the only really time critical state is the radio interrupt.
/// TODO maybe interval timer interrupt time critical as well?
pub struct CalibrateIntervalTimer {
    /// The time at the start of the state change that went Idle->Calibrate Interval Timer
    state_change_start_time: u64,
    /// The time point in time of the first periodic interrupt after the state change
    periodic_after_state_change_time: u64,
    /// The time of the periodic interrupt after the periodic interrupt without change.
    periodic_after_periodic_time: u64,
    /// The time of the countdown timer interrupt goes after requesting it in the second periodic interrupt.
    countdown_after_periodic: u64,
    /// To keep track were in the calibration sequence we are
    point_in_sequence: CalibrationSequence,
    /// For how long the timers will wait. Must be bigger than the time it takes to switch (although this is the time you are looking for).
    interval: u32,
}

impl core::default::Default for CalibrateIntervalTimer {
    fn default() -> Self {
        CalibrateIntervalTimer {
            state_change_start_time: 0,
            periodic_after_state_change_time: 0,
            periodic_after_periodic_time: 0,
            countdown_after_periodic: 0,
            point_in_sequence: CalibrationSequence::PeriodicToCountdown,
            interval: 0,
        }
    }
}

impl JammerStateBasic for CalibrateIntervalTimer {

    /// Can transition to Idle from any state
    fn is_valid_transition_from(&mut self, old_state: &JamblerState) {
        match old_state {
            JamblerState::Idle => {
                // Can come from idle
            }
            _ => panic!("Going to calibrate interval timer from a non-idle state."),
        }
    }

    /// Should only be ok for start states.
    fn is_valid_transition_to(&mut self, new_state: &JamblerState) {
        match new_state {
            JamblerState::Idle => {
                // Can go to idle
            }
            _ => panic!("Going from calibrate interval timer to a non-idle state."),
        }
    }
}

impl<R: JamblerRadio,T: JamblerRestrictedTimer> JammerState<R,T> for CalibrateIntervalTimer  {

    /// Set the interval
    fn config(&mut self, _radio: &mut R, 
        _timer: &mut T, parameters: &mut StateParameters) {
        self.interval = parameters
            .config
            .as_ref()
            .expect("Config not provided for calibrating interval timer.")
            .interval
            .expect("Interval not provided for calibrating interval timer.");
    }

    /// Ask for the periodic timer
    fn initialise(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Ask for a periodic timer on creation
        return_value.timing_requirements = Some(IntervalTimerRequirements::Periodic(self.interval));
    }

    /// Set state change time after launch (this will however be the same as config and initialise)
    fn launch(&mut self, radio: &mut R,
        timer: &mut T, parameters: &mut StateParameters) {
        self.state_change_start_time = parameters.current_time;
        self.point_in_sequence = CalibrationSequence::StateChangeToPeriodic;
    }

    fn update_state(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Should not be called
        panic!("Update state called on calibrate interval timer.")
    }

    fn stop(&mut self,
        radio: &mut R,
        timer: &mut T) {}

    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        panic!("Radio interrupt on calibrate interval timer.")
    }

    /// Remembers the times
    #[inline(always)]
    fn handle_interval_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        match self.point_in_sequence.clone() {
            CalibrationSequence::StateChangeToPeriodic => {
                // First periodic interrupt after state change
                self.periodic_after_state_change_time = parameters.current_time;
                self.point_in_sequence = CalibrationSequence::PeriodicToPeriodic;
            }
            CalibrationSequence::PeriodicToPeriodic => {
                // Periodic after periodic (without time change)
                self.periodic_after_periodic_time = parameters.current_time;
                self.point_in_sequence = CalibrationSequence::PeriodicToCountdown;

                // Ask for countdown
                return_value.timing_requirements =
                    Some(IntervalTimerRequirements::Countdown(self.interval));
            }
            CalibrationSequence::PeriodicToCountdown => {
                // Countdown after asking for it in periodic
                self.countdown_after_periodic = parameters.current_time;

                // Return the differences
                // Timing does not matter now anymore, we can do the calculation here

                // Calculate the times between each point
                let state_change_to_first_interrupt_time =
                    self.periodic_after_state_change_time - self.state_change_start_time;
                let periodic_no_change_time =
                    self.periodic_after_periodic_time - self.periodic_after_state_change_time;
                let interval_timer_change_time =
                    self.countdown_after_periodic - self.periodic_after_periodic_time;

                // Calculate how much longer they took compared to the actual given interval
                // Assume they all took longer than the actual interval
                let state_change_to_first_interrupt_delay: i32 =
                    (state_change_to_first_interrupt_time - self.interval as u64) as i32;
                let periodic_no_change_delay: i32 =
                    if periodic_no_change_time < self.interval as u64 {
                        -((self.interval as u64 - periodic_no_change_time) as i32)
                    } else {
                        (periodic_no_change_time - self.interval as u64) as i32
                    };
                let interval_timer_change_delay: i32 =
                    (interval_timer_change_time - self.interval as u64) as i32;

                // Put it in the return message
                return_value.state_message = Some(StateMessage::IntervalTimerDelays(
                    state_change_to_first_interrupt_delay,
                    periodic_no_change_delay,
                    interval_timer_change_delay,
                ));

                // Ask to go to the idle state
                // TODO if you want you can, depending on a counter, ask to enter this state again to see how reliable the delays are
                return_value.state_transition = Some((JamblerState::Idle, None));
            }
        }
    }

}
