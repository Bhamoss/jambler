use super::util::reverse_bits_u32;




pub fn calculate_crc(crc_init: u32, pdu: &[u8], pdu_length: u16) -> u32 {
    // put crc_init in state, MSB to LSB (MSB right)

    let mut state: u32 = 0;
    for i in 0..24 {
        state |= ((crc_init >> i) & 1) << (23 - i);
    }
    let lfsr_mask: u32 = 0b0101_1010_0110_0000_0000_0000;

    // loop over the pdu bits (as sent over the air)
    // The first processed bis it the 0bxxxx_xxx1 bit of the byte at index 0 of the given pdu
    (0..pdu_length).for_each(|byte_number| {
        let current_byte: u8 = pdu[byte_number as usize];
        (0..8).for_each(|bit_position| {
            // Pop position 23 x^24
            let old_position_23: u8 = (state & 1) as u8;
            // Shift the register to the right
            state >>= 1;
            // Get the data in bit
            let data_in = (current_byte >> bit_position) & 1;
            // calculate x^24 = new position 0 and put it in 24th bit
            let new_position_0 = (old_position_23 ^ data_in) as u32;
            state |= new_position_0 << 23;
            // if the new position is not 0, xor the register pointed to by a xor with 1
            if new_position_0 != 0 {
                state ^= lfsr_mask;
            }
        });
    });

    // Position 0 is the LSB of the init value, 23 the MSB (p2924 specifications)
    // So reverse it into a result u32
    //let mut ret : u32 = 0;
    // Go from CRC_init most significant to least = pos23->pos0
    //for i in 0..24 {
    //	ret |= ((state >> i) & 1) << (23 - i);
    //}

    reverse_bits_u32(state) >> 8
}

pub fn reverse_calculate_crc_init(received_crc_value: u32, pdu: &[u8], pdu_length: u16) -> u32 {
    let mut state: u32 = reverse_bits_u32(received_crc_value) >> 8;
    let lfsr_mask: u32 = 0xb4c000;

    // loop over the pdu bits (as sent over the air) in reverse
    // The first processed bit is the 0b1xxx_xxxx bit of the byte at index pdu_length of the given pdu
    for byte_number in (0..pdu_length).rev() {
        let current_byte: u8 = pdu[byte_number as usize];
        for bit_position in (0..8).rev() {
            // Pop position 0 = x^24
            let old_position_0: u8 = (state >> 23) as u8;
            // Shift the register to the left (reversed arrows) and mask the u32 to 24 bits
            state = (state << 1) & 0xffffff;
            // Get the data in bit
            let data_in = (current_byte >> bit_position) & 1;
            // xor x^24 with data in, giving us position 23
            // we shifted state to the left, so this will be 0, so or |= will set this to position 23 we want
            state |= (old_position_0 ^ data_in) as u32;
            // In the position followed by a XOR, there sits now the result value of that XOR with x^24 instead of what it is supposed to be.
            // Because XORing twice with the same gives the original, just XOR those position with x^24. So XOR with a mask of them if x^24 was 1 (XOR 0 does nothing)
            if old_position_0 != 0 {
                state ^= lfsr_mask;
            }
        }
    }

    // Position 0 is the LSB of the init value, 23 the MSB (p2924 specifications)
    // So reverse it into a result u32
    let mut ret: u32 = 0;
    // Go from CRC_init most significant to least = pos23->pos0
    for i in 0..24 {
        ret |= ((state >> i) & 1) << (23 - i);
    }

    ret
}






#[cfg(test)]
mod crc_tests {

    use crate::ble_algorithms::util::reverse_bits;

    use super::*;

    //use crc_any::CRCu32;

    #[test]
    fn reverse_crc() {
        // Test on the BLE p3089 LL data pdu example
        let pdu_length: u16 = 2 + (reverse_bits(0b1010_0000) as u16);
        assert_eq!(pdu_length, 7);

        // How the packet will be sent over the air
        // From the ble specification, this is also how the crc is calculated over it
        let mut pdu: Box<[u8]> = Box::new([
            0b01101000, // header first byte
            0b10100000, // header seconds byte (Length in bits)
            0b10000000, // The payload (1-5)
            0b01000000, 0b11000000, 0b00100000, 0b10100000,
        ]);

        // this is on air, reverse the bits
        for byte in pdu.iter_mut() {
            *byte = reverse_bits(*byte);
        }

        // is shown in msb msB so should be copy pasted
        // is 0xA20B4B
        let crc_value: u32 = 0b1010_0010_0000_1011_0100_1011;

        let crc_init: u32 = 0xC4C181;

        // check if the crc value of the spec sheet is this one
        assert_eq!(calculate_crc(crc_init, &pdu, pdu_length), crc_value);

        assert_eq!(
            reverse_calculate_crc_init(crc_value, &pdu, pdu_length),
            crc_init
        );

        // using crc any
        //let mut crc = CRCu32::create_crc(0x00065B, 24, initial, 0x000000, true);
        //let mut rev_crc = CRCu32::create_crc(0xDA6000, 24, initial, 0x000000, true);
    }

    /// Test on an actual packet I sniffed with the nrf sniffer
    #[test]
    fn own_captured_packet_crc() {
        let pdu_length: u16 = 2;

        // This is the packet as it sits in the buffer to be sent
        // It will be sent flipped
        let pdu: Box<[u8]> = Box::new([
            0b0000_0101, // header first byte
            0b0000_0000,
        ]);

        // is shown in msb msB so should be copy pasted
        // 0xA49FD1 in bit stream
        // 0x0025f98b as declared by the sniffer (in an actual information field)
        let crc_value: u32 = 0x0025f98b;

        // crc init sent in the connection request
        let crc_init: u32 = 0x00973198;

        // check if the crc value of the spec sheet is this one
        assert_eq!(calculate_crc(crc_init, &pdu, pdu_length), crc_value);

        assert_eq!(
            reverse_calculate_crc_init(crc_value, &pdu, pdu_length),
            crc_init
        );
    }

    #[test]
    fn reverse_bits_couple_of_tests() {
        let original = 0b1111_1011;
        let reversed = 0b1101_1111;
        assert_eq!(reverse_bits(original), reversed);
        assert_eq!(reverse_bits(reverse_bits(original)), original);

        let original = 0b1010_0000;
        let reversed = 0b0000_0101;
        assert_eq!(reverse_bits(original), reversed);
        assert_eq!(reverse_bits(reverse_bits(original)), original);

        let original = 0b1111_1111;
        let reversed = 0b1111_1111;
        assert_eq!(reverse_bits(original), reversed);
        assert_eq!(reverse_bits(reverse_bits(original)), original);

        let original = 0b0000_0000;
        let reversed = 0b0000_0000;
        assert_eq!(reverse_bits(original), reversed);
        assert_eq!(reverse_bits(reverse_bits(original)), original);
    }

    /// TAKE THIS AS A HOW TO ON HOW TO DO IT ON MY CHIP!!!!!!
    /// I EVEN FIGURED OUT HOW TO DO IT WITH A 16-BIT HEADER WHEN CONFIGURED FOR 24-BIT
    #[test]
    fn nrf_payload_calculate_and_reverse() {
        /* empty payload = empty packet */
        const EMPTY_CORRECT_CRC: u32 = 0xef83aa; // copy pasted from rxcrc
        const EMPTY_CORRECT_CRC_INIT: u32 = 0x555555;
        let empty_pdu_buf: [u8; 2] = [0b01110111, 0];

        /* Non-empty packet */

        const LEN: u16 = 89;
        // Buffer with S1 excluded
        let nrf_pdu_buf: [u8; (LEN + 2) as usize] = [
            119, 89, 84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 120, 116, 32, 112, 97,
            99, 107, 101, 116, 32, 115, 101, 110, 116, 32, 102, 114, 111, 109, 32, 116, 104, 101,
            32, 116, 104, 101, 115, 105, 115, 10, 32, 112, 114, 111, 106, 101, 99, 116, 32, 111,
            102, 32, 108, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 110, 103, 101, 114, 32,
            84, 104, 111, 109, 97, 115, 32, 66, 97, 109, 101, 108, 105, 115, 33, 0,
        ];

        // in rxcrc
        const CORRECT_CRC: u32 = 0xec6306; // reading in byte low to high (remember it is saved little endian in cpu but received big endian on air) 0000_0110        0110_0011        1110_1100
        const CORRECT_CRC_INIT: u32 = 0x555555;

        /* Turning the 3 extra bytes received by statlen = 3 into the crc in the RXCRC register which is the correct u32 representation of the crc */

        // statlen 3 extra buffer values after last 0: 55, 198, 96 = 0x37, 0xc6, 0x60 = 0011_0111, 1100_0110, 0110_0000,
        // Receiving it like this(as payload, which is received LS bit and byte) will have the bits and the bytes in the reverser order (because on air it is sent MS bit and byte). This corresponds to the chip specification on how it receives a packet
        let mut statlen_crc_bytes: [u8; 3] = [55, 198, 96];
        // reverse the bits
        for byte in statlen_crc_bytes.iter_mut() {
            *byte = reverse_bits(*byte)
        }
        // last byte most to the right
        let statlen_crc_bytes_reversed: u32 = (statlen_crc_bytes[0] as u32) << 16
            | (statlen_crc_bytes[1] as u32) << 8
            | statlen_crc_bytes[2] as u32;

        assert_eq!(statlen_crc_bytes_reversed, CORRECT_CRC);

        /* Getting the crc out of a 16-bit header pdu while reception was like 24 bit header pdu */

        // When putting s1 to 8 bits, but receiving a 16-bit header: new byte at end of payload (3 + len, 2+ len index) = 55 = 0x37 = 110111
        // Reading a u32 from the rxcrc register = 6489808 = 0000_0000 0110_0011 0000_0110 1101_0000 = 0x006306d0         (the bits are how you will receive them in the u32, but because of computer little endianness in memory they are reversed in memory bytes, but that is so for all of them)
        // The 1101_0000 = d0 is noise you receive because the radio listens too long
        let extra_s1_payload_end_byte: u8 = 0x37;
        let s1_malformed_rxcrc: u32 = 0x006306d0;

        let s1_constructed_crc: u32 =
            (reverse_bits(extra_s1_payload_end_byte) as u32) << 16 | (s1_malformed_rxcrc >> 8);

        assert_eq!(s1_constructed_crc, CORRECT_CRC);

        /* Calculate crc and crc_init for empty packet */

        // bytes 234 when receiving with statlen
        let empty_statlen_buf: [u8; 5] = [119, 0, 247, 193, 85];
        let empty_calculated_crc_init =
            reverse_calculate_crc_init(EMPTY_CORRECT_CRC, &empty_pdu_buf, 2);
        let empty_calculated_crc = calculate_crc(EMPTY_CORRECT_CRC_INIT, &empty_pdu_buf, 2);

        assert_eq!(empty_calculated_crc_init, EMPTY_CORRECT_CRC_INIT);
        assert_eq!(empty_calculated_crc, EMPTY_CORRECT_CRC);

        /* Calculating the crc from what I receive in the nrf buffer for the non-empty packet */

        const SHOULD_BE_ONE_FOR_24_BIT_HEADER: u8 = 0;

        let payload_offset: u8;
        if SHOULD_BE_ONE_FOR_24_BIT_HEADER == 1 {
            payload_offset = 3;
        } else {
            payload_offset = 2;
        }
        let calculated_crc =
            calculate_crc(CORRECT_CRC_INIT, &nrf_pdu_buf, payload_offset as u16 + LEN);
        let calculated_crc_init =
            reverse_calculate_crc_init(CORRECT_CRC, &nrf_pdu_buf, payload_offset as u16 + LEN);

        assert_eq!(calculated_crc_init, CORRECT_CRC_INIT);
        assert_eq!(calculated_crc, CORRECT_CRC);

        // So you actually do not have to change anything to the buffer. Just give it the rxcrc, the self.receive_buffer and the length and you will get your crc_init
        // Same for calculating the crc, but you just give it the actual init value, without any tampering (0x555555 for advertising for example)

    }
}
