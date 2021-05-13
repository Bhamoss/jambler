use crate::jambler::BlePhy;




 #[inline]
 fn is_valid_aa(mut aa: u32, phy: BlePhy) -> bool {
     let aa_copy = aa;
 
     let mut consecutive_6 = 0_u8;
     let mut bit;
     let mut byte = aa as u8;
     let mut eight_byte_jump = 17_u8;
     let mut all_equal = true;
     let mut prev_bit = aa as u8 & 0b1;
     let mut transitions_6_msbs = 0_u8;
     let mut ones_in_8_lsbs = 0_u8;
     let mut transitions_16_lsbs = 0_u8;
     for bit_index in 1..=32_u8 {
         bit = aa as u8 & 0b1;
 
         // It shall have no more than six consecutive zeros or ones.
         // So need to know last 7
         consecutive_6 <<= 1;
         consecutive_6 |= bit;
         consecutive_6 &= 0b0111_1111;
         if bit_index >= 7 && (consecutive_6 == 0b0 || consecutive_6 == 0b0111_1111) {
             return false;
         }
 
         // It shall not have all four octets equal.
         if eight_byte_jump == bit_index {
             let right_byte = aa as u8;
             if byte != right_byte {
                 all_equal = false
             }
             byte = right_byte;
             eight_byte_jump += 8;
         }
 
         // It shall have a minimum of two transitions in the most significant six bits.
         if bit_index > 27 && prev_bit != bit {
             transitions_6_msbs += 1;
         }
 
         // EXTRA FOR CODED PHY
         match phy {
             BlePhy::CodedS2 | BlePhy::CodedS8 => {
                 // It shall have at least three ones in the least significant 8 bits.
                 if bit_index <= 8 && bit == 0b1 {
                     ones_in_8_lsbs += 1;
                 }
                 // It shall have no more than eleven transitions in the least significant 16 bits.
                 if bit_index <= 16 && prev_bit != bit {
                     transitions_16_lsbs += 1;
                 }
             },
             _ => {},
         }
 
         aa >>= 1;
         prev_bit = bit;
     }
 
     if all_equal || transitions_6_msbs < 2 {
         return false
     }
 
     match phy {
         BlePhy::CodedS2 | BlePhy::CodedS8 => {
             if ones_in_8_lsbs < 3 || transitions_16_lsbs > 11 {
                 return false
             }
         },
         _ => {},
     }
 
     // The following are less likely to fail, so let's put them at the back
 
     // It shall not be the advertising physical channel packets’ Access Address.
     if aa_copy == 0x8E89BED6 {
         return false;
     }
     // It shall not be a sequence that differs from the advertising physical channel packets’ Access Address by only one bit.
     let mut mask = 1_u32;
     for _ in 0..32 {
         // flip each bit and check
         // xor bit with 1 is flip, with zero is stay the same.
         if (aa_copy ^ mask) == 0x8E89BED6 {
             return false;
         }
         mask <<= 1;
     }
 
     true
 }
 

 #[cfg(test)]
 mod tests {

    use super::*;

    #[test]
    fn valid_aas() {
        // It shall have no more than six consecutive zeros or ones.
        assert!(!is_valid_aa(0b11_1111_0111_1101_1110_1011_0100, BlePhy::CodedS8), "It shall have no more than six consecutive zeros or ones FAILED.");
        assert!(!is_valid_aa(0b00_0000_0111_1101_1110_1011_0100, BlePhy::CodedS8), "It shall have no more than six consecutive zeros or ones FAILED.");
        assert!(!is_valid_aa(0b11_1111, BlePhy::CodedS8), "It shall have no more than six consecutive zeros or ones FAILED.");

        // It shall not have all four octets equal.
        assert!(!is_valid_aa(0b1011_0100_1011_0100_1011_0100_1011_0100, BlePhy::CodedS8), "It shall not have all four octets equal FAILED.");

        // It shall have a minimum of two transitions in the most significant six bits.
        assert!(!is_valid_aa(0b1000_0010_1011_0100_1011_0100_1011_0100, BlePhy::CodedS8), "It shall have a minimum of two transitions in the most significant six bits FAILED.");

        // It shall have at least three ones in the least significant 8 bits.
        assert!(!is_valid_aa(0b1100_0010_1011_0100_1011_0101_0001_0100, BlePhy::CodedS8), "It shall have at least three ones in the least significant 8 bits FAILED.");

        // It shall have no more than eleven transitions in the least significant 16 bits.
        assert!(!is_valid_aa(0b1100_0010_1011_0100_1011_1101_0101_0101, BlePhy::CodedS8), "It shall have no more than eleven transitions in the least significant 16 bits FAILED.");

        // It shall not be the advertising physical channel packets’ Access Address.
        assert!(!is_valid_aa(0x8E89BED6, BlePhy::CodedS8), "It shall not be the advertising physical channel packets’ Access Address FAILED.");

        // It shall not be a sequence that differs from the advertising physical channel packets’ Access Address by only one bit.
        assert!(!is_valid_aa(0x8E89BED6 ^ (0b1_u32 << 24), BlePhy::CodedS8), "It shall not be a sequence that differs from the advertising physical channel packets’ Access Address by only one bit FAILED.");

        assert!(is_valid_aa(988865815, BlePhy::Uncoded2M), "conn_interval 30 example FAILED");
        assert!(is_valid_aa(317015871, BlePhy::Uncoded2M), "conn_interval 50 example FAILED");
        assert!(is_valid_aa(435611423, BlePhy::Uncoded2M), "conn_interval 400 example FAILED");
        assert!(is_valid_aa(2997936575, BlePhy::Uncoded2M), "conn_interval 1000 example FAILED");
    }

 }