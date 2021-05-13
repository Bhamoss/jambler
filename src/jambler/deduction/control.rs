use heapless::spsc::Producer;

use super::{ConnectionSample, UnusedChannel, processing::{DeductionCommand, DeductionStartParameters}};





/// A wrapper for all necessary control information for the task used for deducing connection parameters.
/// This is the message passing struct between the host and the task.
pub struct DeduceConnectionParametersControl<'a> {
    sample_queue : Producer<'a, ConnectionSample,16>,
    unused_queue : Producer<'a, UnusedChannel,16>,
    command_queue : Producer<'a, DeductionCommand,16>,
}

impl<'a> DeduceConnectionParametersControl<'a> {
    pub fn new(
        sample_queue : Producer<'a, ConnectionSample,16>,
        unused_queue : Producer<'a, UnusedChannel,16>,
        command_queue : Producer<'a, DeductionCommand,16>
    ) -> Self {
        DeduceConnectionParametersControl {
            sample_queue,
            unused_queue,
            command_queue
        }
    }

    /// Signals the task to reset
    pub fn reset(&mut self) {
        self.command_queue.enqueue(DeductionCommand::Reset).expect("Deduction command overflow, but should not happen. We cannot flush the queue with only the producer. Only last one matters");
    }

    pub fn start(&mut self, parameters: DeductionStartParameters) {
        self.command_queue.enqueue(DeductionCommand::Start(parameters)).expect("Deduction command overflow, but should not happen. We cannot flush the queue with only the producer. Only last one matters");
    }

    /// IMPORTANT SAMPLES MUST BE SENT IN REAL TIME ORDER
    /// todo See if you can make connection samples process agnostic to this.
    /// TODO It is the delta time that is bothering us. Since it is only calculated at brute force start, maybe keep it in a maxheap sorted on the captured time of the anchor points. Generate deltas when needed then.
    pub fn send_sample(&mut self, sample: ConnectionSample) {
        if self.sample_queue.enqueue(sample).is_err() {
            //println!("Sample queue overflow, dropping packet.")
        }
    }

    pub fn report_unused_channel(&mut self, channel: UnusedChannel) {
        if self.unused_queue.enqueue(channel).is_err() {
            //println!("Channel queue overflow, dropping packet.")
        }
    }
}
