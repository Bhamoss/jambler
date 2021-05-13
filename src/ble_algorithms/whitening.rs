


/// See figure 3.5 of specification page 2925.
/// The whitening and dewithening is the same, so just implement the figure.
pub fn dewithen_16_bit_pdu_header(first_byte: u8, second_byte: u8, channel: u8) -> (u8, u8) {
    // Initialise according to the spec sheet.
    // 6 rightmost (lsb) bits are set to the channel and 7th (right to left = second most significant) is one.
    // If the channel is valid it will fit in its 6 rightmost bits.
    // The leftmost bit (MSB) is never used
    let mut linear_feedback_shift_register: u8 = channel | 0b0100_0000;

    let mut bytes : [u8;2] = [first_byte, second_byte];

    for byte in bytes.iter_mut() {
        let mut mask = 0b1_u8;
        for _ in 0..8 {
            // Get data out from xor 6th = rightmost bit and data in
            let x7: bool = (linear_feedback_shift_register & 0b1) == 0b1;

            if x7 {
                // bit index has to be xored with 1
                // Do bitwise xor (0 in xor is stay the same for other side)
                *byte ^= mask;
            }

            // shift register next shift and operation
            linear_feedback_shift_register >>= 1;
            mask <<= 1;
            // If the bit that will be shifted out was one, the XOR and shift will matter
            if x7 {
                linear_feedback_shift_register ^= 0b0100_0100;
            }
        }
    }

    (bytes[0], bytes[1])
}









 #[cfg(test)]
 mod tests {

    use crate::ble_algorithms::util::reverse_bits;

    use super::*;


    /// See BLE specification Vol 6, part C, section 4.1. It contains the x7 xor sequence my algorithm should create.
    #[test]
    fn dewhitening() {
        let test_first = 0b1001_1101_u8;
        let test_second = 0b0010_0101_u8;

        // First 2 bytes on channel 3
        // 11011000 10100101 order generated over LSB -> reverse!
        // Whiten
        let rev_f = reverse_bits(0b1101_1000);
        let rev_s = reverse_bits(0b1010_0101);
        let xored_first = test_first ^ rev_f;
        let xored_second = test_second ^ rev_s;
        let (calced_f, calced_s) = dewithen_16_bit_pdu_header(test_first, test_second, 3);

        assert_eq!((xored_first, xored_second), (calced_f, calced_s), "Channel 3 whitening failed");
        // Dewhiten
        assert_eq!((test_first, test_second), dewithen_16_bit_pdu_header(xored_first, xored_second, 3), "Channel 3 dewhitening failed");


        let test_first = 0b1001_1101_u8;
        let test_second = 0b0_u8;

        // First 2 bytes on channel 24
        // 00011001 00010000  
        let rev_f = reverse_bits(0b00011001);
        let rev_s = reverse_bits(0b00010000);
        let xored_first = test_first ^ rev_f;
        let xored_second = test_second ^ rev_s;
        let (calced_f, calced_s) = dewithen_16_bit_pdu_header(test_first, test_second, 24);
        // Whiten
        assert_eq!((xored_first, xored_second), (calced_f, calced_s), "Channel 24 whitening failed");
        // Dewhiten
        assert_eq!((test_first, test_second), dewithen_16_bit_pdu_header(xored_first, xored_second, 24), "Channel 24 dewhitening failed");
    }
 }