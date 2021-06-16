use super::{super::JamblerRadio};
use super::JammerState;
use super::StateReturn;
use crate::master::RadioTask;
use crate::slave::hardware_traits::JamblerTimer;

pub struct Idle {}

impl Default for Idle {
    fn default() -> Self {
        Idle {}
    }
}


impl <R: JamblerRadio,T: JamblerTimer> JammerState<R,T>  for Idle {

    fn start(
        &mut self, 
        task : &RadioTask,
        radio: &mut R, 
        timer: &mut T,
        //parameters: &mut StateParameters
    ) {}

    fn handle_radio_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        //parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ){}

    fn handle_timer_interrupt(
        &mut self,
        radio: &mut R,
        timer: &mut T,
        interrupt_time: u64,
        //parameters: &mut StateParameters,
        return_value: &mut StateReturn,
    ) {}
}
