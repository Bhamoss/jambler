


/// Shifts each byte to the left and have the MSb overflow bit of bytes[i] become
/// the LSb input bit of bytes[i+1]. 
/// The naming is right, because bytes are sent in reverse over the air and I want
/// to envision the on air bits.
/// Has been tested in testing crate.
/// ```
/// let bytes : [u8;3] = [0b1111_1111, 0b0000_0000, 0b1010_1010];
/// let goal : [u8;3] = [0b1111_1110, 0b0000_0001, 0b0101_0100];
/// let mut calculated = bytes;
/// bit_shift_slice_right(&mut calculated, 0);
/// assert_eq!(goal, calculated, "Bit shift right failed");
/// ```
#[inline]
pub fn bit_shift_slice_right(bytes: &mut [u8], input_bit: u8) {
    bytes.iter_mut().fold(input_bit, |input, byte|
        {
            let next_input = *byte >> 7; // get byte MSb and make it LSb
            *byte <<= 1;
            *byte |= input;
            next_input
        }
    );
}

/// Shifts each byte to the right and have the LSb overflow bit of bytes[i+1] become
/// the MSb input bit of bytes[i]. 
/// The naming is left, because bytes are sent in reverse over the air and I want
/// to envision the on air bits.
/// Has been tested in testing crate.
/// #Example
/// 
/// let bytes : [u8;3] = [0b1111_1111, 0b0000_0000, 0b1010_1010];
/// let goal : [u8;3] = [0b0111_1111, 0b0000_0000, 0b1101_0101];
/// let mut calculated = bytes;
/// bit_shift_slice_left(&mut calculated, 1);
/// 
#[inline]
pub fn bit_shift_slice_left(bytes: &mut [u8], mut input_bit: u8) {
    input_bit <<= 7;
    bytes.iter_mut().rev().fold(input_bit, |input, byte|
        {
            let next_input = *byte << 7; // get byte LSb and make it MSb
            *byte >>= 1;
            *byte |= input;
            next_input
        }
    );
}


/// TODO use the trick below
/// 
/// input = ((input & 0xaaaa) >> 1) | ((input & 0x5555) << 1);
/// input = ((input & 0xcccc) >> 2) | ((input & 0x3333) << 2);
/// input = ((input & 0xf0f0) >> 4) | ((input & 0x0f0f) << 4);
/// 
#[inline]
pub fn reverse_bits(byte: u8) -> u8 {
    let mut reversed_byte: u8 = 0;
    // Go right to left over original byte, building and shifting the reversed one in the process
    for bit_index in 0..8 {
        // Move to left to make room for new bit on the right (new LSB)
        reversed_byte <<= 1;
        // If byte is 1 in its indexed place, set 1 to right/LSB reversed
        if byte & (1 << bit_index) != 0 {
            reversed_byte |= 0b0000_0001;
        } else {
            reversed_byte |= 0b0000_0000;
        }
        //reversed_byte |= if byte & (1 << bit_index) != 0 {0b0000_0001} else {0b0000_0000};
    }
    reversed_byte
}

/// TODO use the trick below, but adapt. now it contains each byte reversed, so now reverse the bytes using 0xff00ff00 >> 8, 0x00ff00ff << 8 and 0xffff0000 >> 16, 0x0000ffff << 16
/// 
/// input = ((input & 0xaaaa) >> 1) | ((input & 0x5555) << 1);
/// input = ((input & 0xcccc) >> 2) | ((input & 0x3333) << 2);
/// input = ((input & 0xf0f0) >> 4) | ((input & 0x0f0f) << 4);
/// 
#[inline]
pub fn reverse_bits_u32(byte: u32) -> u32 {
    let mut reversed_byte: u32 = 0;
    // Go right to left over original byte, building and shifting the reversed one in the process
    for bit_index in 0..32 {
        // Move to left to make room for new bit on the right (new LSB)
        reversed_byte <<= 1;
        // If byte is 1 in its indexed place, set 1 to right/LSB reversed
        if byte & (1 << bit_index) != 0 {
            reversed_byte |= 0b0000_0001;
        } else {
            reversed_byte |= 0b0000_0000;
        }
        //reversed_byte |= if byte & (1 << bit_index) != 0 {0b0000_0001} else {0b0000_0000};
    }
    reversed_byte
}

#[inline]
pub fn reverse_bits_u64(byte: u64) -> u64 {
    let mut reversed_byte: u64 = 0;
    // Go right to left over original byte, building and shifting the reversed one in the process
    for bit_index in 0..64 {
        // Move to left to make room for new bit on the right (new LSB)
        reversed_byte <<= 1;
        // If byte is 1 in its indexed place, set 1 to right/LSB reversed
        if byte & (1 << bit_index) != 0 {
            reversed_byte |= 0b0000_0001;
        } else {
            reversed_byte |= 0b0000_0000;
        }
        //reversed_byte |= if byte & (1 << bit_index) != 0 {0b0000_0001} else {0b0000_0000};
    }
    reversed_byte
}


#[cfg(test)]
mod tests {


    use super::*;

    #[test]
    fn bit_shift_right() {
        let bytes : [u8;3] = [0b1111_1111, 0b0000_0000, 0b1010_1010];
        let goal : [u8;3] = [0b1111_1110, 0b0000_0001, 0b0101_0100];
        let mut calculated = bytes;
        bit_shift_slice_right(&mut calculated, 0);
        assert_eq!(goal, calculated, "Bit shift right failed");

    }


    #[test]
    fn bit_shift_left() {
        let bytes : [u8;3] = [0b1111_1111, 0b0000_0000, 0b1010_1010];
        let goal : [u8;3] = [0b0111_1111, 0b0000_0000, 0b1101_0101];
        let mut calculated = bytes;
        bit_shift_slice_left(&mut calculated, 1);
        assert_eq!(goal, calculated, "Bit shift right failed");

    }


}