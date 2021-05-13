use super::{super::JamblerRadio, JammerStateBasic};
use super::JammerState;
use super::StateParameters;
use super::StateReturn;
use crate::jambler::{JamblerState, hardware_traits::JamblerRestrictedTimer};

pub struct Idle {}

impl Default for Idle {
    fn default() -> Self {
        Idle {}
    }
}

impl JammerStateBasic for Idle {
    /// Can transition to Idle from any state
    fn is_valid_transition_from(&mut self, old_state: &JamblerState) {}

    /// Should only be ok for start states.
    #[allow(unreachable_patterns)]
    fn is_valid_transition_to(&mut self, new_state: &JamblerState) {
        match new_state {
            JamblerState::Idle
            | JamblerState::DiscoveringAAs
            | JamblerState::CalibrateIntervalTimer
            | JamblerState::HarvestingPackets => {}
            _ => panic!("Idle to a non-start state."),
        }
    }
}

impl <R: JamblerRadio,T: JamblerRestrictedTimer> JammerState<R,T>  for Idle {

    fn config(&mut self, 
        radio: &mut R,
        timer: &mut T, parameters: &mut StateParameters) {}

    fn initialise(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
    }

    fn launch(&mut self, 
        radio: &mut R,
        timer: &mut T, parameters: &mut StateParameters) {
        // TODO put radio to sleep? poweroff?
    }

    fn update_state(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Should not be called
        panic!("State update on Idle called")
    }

    fn stop(&mut self, 
        radio: &mut R,
        timer: &mut T,) {
        // TODO turn radio back on?
    }

    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Should never be reached
        panic!("Radio interrupt on idle")
    }

    fn handle_interval_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {
        // Should never be reached
        panic!("Interval timer interrupt on idle")
    }
}
