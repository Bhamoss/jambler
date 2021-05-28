
use core::cmp::{max, min};


/// Calculates the channel identifier from the access address.
///
/// Only calculate on access address change.
pub fn calculate_channel_identifier(access_address: u32) -> u16 {
    (((access_address >> 16) as u16) ^ (access_address as u16)) as u16
}

/// Generates a bunch useful arrays out of a channel map delivered as a u64 bit mask.
/// Returns (channel_map_array, remapping_table, inverse_remapping_table, nb_used).
///
/// Only calculate on channel map change.
#[inline(always)]
pub fn generate_channel_map_arrays(channel_map: u64) -> ([bool; 37], [u8; 37], [u8; 37], u8) {
    let mut nb_used: u8 = 0;
    let mut channel_map_array = [false; 37];
    let mut remapping_table = [0xFF; 37];
    let mut inverse_remapping_table = [0xFF; 37]; // for subevents, when you need remapping index
    for channel_index in 0u8..37u8 {
        if channel_map & (1 << channel_index) != 0 {
            //
            channel_map_array[channel_index as usize] = true;
            // add to remapping table (in ascending order as specs say)
            remapping_table[nb_used as usize] = channel_index;
            // get this to to have O(1) remapping index
            inverse_remapping_table[channel_index as usize] = nb_used;
            // remember how many channels
            nb_used += 1;
        }
    }
    (
        channel_map_array,
        remapping_table,
        inverse_remapping_table,
        nb_used,
    )
}

/// Calculate the channel for the given counter, channel identifier and channel map.
/// Uses u32 internally because of overflow it will run into u32 multiple times and instead of casting thousands of time, just reuse the u32s.
pub fn csa2_no_subevent(
    counter: u32,
    channel_identifier: u32,
    channel_map: &[bool; 37],
    remapping_table: &[u8; 37],
    nb_used: u8,
) -> u8 {
    // calculate "pseudo random number e", figure 4.46
    let prn_e = prn_e(counter as u16, channel_identifier as u16);

    // figure 4.47
    let unmapped_channel: u8 = (prn_e % 37) as u8;

    // figure 4.48
    if channel_map[unmapped_channel as usize] {
        // used channel
        unmapped_channel
    } else {
        // remap
        let remapping_index = (((nb_used as u32) * (prn_e as u32)) >> 16) as usize;
        remapping_table[remapping_index]
    }
}

/// Operation block in the CSA#2 algorithm.
/// Switches the byte by first switching bits next to each other, pairs next to each other, then 4bits next to each other.
/// This results in each separate byte switched.
#[cfg(target_arch="arm")]
#[inline(always)]
pub fn perm(mut input: u16) -> u16 {
    unsafe {
        asm!("rbit {0}, {0}", "rev {0}, {0}", inout(reg) input);
    }
    input
}


#[cfg(not(target_arch="arm"))]
#[inline(always)]
pub fn perm(mut input: u16) -> u16 {
    input = ((input & 0xaaaa) >> 1) | ((input & 0x5555) << 1);
    input = ((input & 0xcccc) >> 2) | ((input & 0x3333) << 2);
    input = ((input & 0xf0f0) >> 4) | ((input & 0x0f0f) << 4);
    input
}

/// Operation block in the CSA#2 algorithm.
#[inline(always)]
pub fn mam(a: u16, b: u16) -> u16 {
    let mut ret: u32;
    //ret = a as u32 * 17; // cannot overflow! upgrade to u32
    // a * 17 = a * 2^4 + a
    //ret = (a << 4) + a;
    ret = a as u32 * 17;
    ret += b as u32;
    // mod 2^16
    ret as u16
}



/*********************************** WITH ALL SUBEVENTS */

/// Also return prn_s and remappingIndexOfLastUsedChannel
/// (first_channel, prn_s, remappingIndexOfLastUsedChannel)
pub fn csa2(
    counter: u32,
    channel_identifier: u32,
    channel_map: &[bool; 37],
    remapping_table: &[u8; 37],
    inverse_remapping_table: &[u8; 37],
    nb_used: u8,
) -> (u8, u16, u8) {
    // calculate "pseudo random number e", figure 4.46
    let (prn_e, prn_s) = prn_e_s(counter as u16, channel_identifier as u16);

    // figure 4.47
    let unmapped_channel: u8 = (prn_e % 37) as u8;

    // figure 4.48
    if channel_map[unmapped_channel as usize] {
        // used channel
        (
            unmapped_channel,
            prn_s,
            inverse_remapping_table[unmapped_channel as usize],
        )
    } else {
        // remap
        let remapping_index = (((nb_used as u32) * (prn_e as u32)) >> 16) as usize;
        (
            remapping_table[remapping_index],
            prn_s,
            remapping_index as u8,
        )
    }
}

#[inline(always)]
pub fn prn_e(counter: u16, channel_identifier: u16) -> u16 {
    let mut prn_e: u16;
    prn_e = counter ^ channel_identifier; // xor
    prn_e = perm(prn_e); // perm
    prn_e = mam(prn_e, channel_identifier); // mam
    prn_e = perm(prn_e); // perm
    prn_e = mam(prn_e, channel_identifier); // mam
    prn_e = perm(prn_e); // perm
    prn_e = mam(prn_e, channel_identifier); // mam
    prn_e ^= channel_identifier;
    prn_e
}

pub fn prn_e_s(counter: u16, channel_identifier: u16) -> (u16, u16) {
    let mut prn_e: u16;
    prn_e = counter ^ channel_identifier; // xor
    prn_e = perm(prn_e); // perm
    prn_e = mam(prn_e, channel_identifier); // mam
    prn_e = perm(prn_e); // perm
    prn_e = mam(prn_e, channel_identifier); // mam
    prn_e = perm(prn_e); // perm
    prn_e = mam(prn_e, channel_identifier); // mam
    let prn_s = prn_e;
    prn_e ^= channel_identifier;
    (prn_e, prn_s)
}

pub fn calculate_subevent_d(nb_used: u8) -> u8 {
    let nb_used: i8 = nb_used as i8;
    // for underflow
    /*
    let minus_5 : u8;
    if nb_used < (3 + 5) {
        minus_5 = nb_used -5;
    }
    else {
        minus_5 = 3;
    }
    let minus_10 : u8;
    // floor(23/2) = 11
    if nb_used < 23 {
        minus_10 = (nb_used - 10) >> 1;
    }
    else {
        minus_10 = 11;
    }
    let ret = max(1,max(minus_5,minus_10));
    */
    //assert_eq!(ret, reth);
    //ret
    max(1, max(min(3, nb_used - 5), min(11, (nb_used - 10) >> 1))) as u8
}

/// returns the (channel, prnSubEvent_lu, subEventIndex_se_n-1)
///
/// First run:
///     - calculate d with other function
///     - last_usedprn = prn_s (from csa2)
///     - index_of_last_used_channel = remappingIndexOfLastUsedChannel (from csa2)
/// Subsequent runs:
///     - same d
///     - last_usedprn = prnSubEvent_lu (from previous csa2_subevent run)
///     - index_of_last_used_channel = subEventIndex_se_n-1 (from previous csa2_subevent run)
pub fn csa2_subevent(
    last_usedprn: u32,
    index_of_last_used_channel: u32,
    channel_identifier: u32,
    channel_map: &[bool; 37],
    remapping_table: &[u8; 37],
    inverse_remapping_table: &[u8; 37],
    nb_used: u8,
    d: u8,
) -> (u8, u32, u32) {
    // figure 4.49
    let mut prn_sub_event_se: u32;
    prn_sub_event_se = perm(last_usedprn as u16) as u32;
    prn_sub_event_se = mam(prn_sub_event_se as u16, channel_identifier as u16) as u32;
    let prn_sub_event_lu: u32 = prn_sub_event_se;
    prn_sub_event_se ^= channel_identifier;

    // The most horrible line in human history
    let sub_event_index_se_n: u32 = (index_of_last_used_channel
        + d as u32
        + ((prn_sub_event_se * (nb_used - 2 * d + 1) as u32) >> 16))
        % nb_used as u32;

    let next_channel = remapping_table[sub_event_index_se_n as usize] as u8;
    (next_channel, prn_sub_event_lu, sub_event_index_se_n)
}





#[cfg(test)]
mod tests {
    use super::*;


    /// First run:
    ///     - calculate d with other function
    ///     - last_usedprn = prn_s (from csa2)
    ///     - index_of_last_used_channel = remappingIndexOfLastUsedChannel (from csa2)
    /// Subsequent runs:
    ///     - same d
    ///     - last_usedprn = prnSubEvent_lu (from previous csa2_subevent run)
    ///     - index_of_last_used_channel = subEventIndex_se_n-1 (from previous csa2_subevent run)
    fn csa2_all_subevents(
        access_address: u32,
        channel_map: u64,
        counter: u32,
        nb_subevents: u8,
    ) -> Vec<u8> {
        // part c, sec 3.2, Sample data 2 (9 used channels)

        //let access_address : u32 = 0x8E89BED6; // TODO
        //let channel_map : u64 = 0b11110_00000000_11100000_00000110_00000000; // TODO
        //let counter : u16 = 8; // TODO
        // Should be [34, 9, 33]

        let channel_identifier: u16 = calculate_channel_identifier(access_address);
        let channel_identifier: u32 = channel_identifier as u32;

        let mut ret = Vec::new();

        let (channel_map_array, remapping_table, inverse_remapping_table, nb_used) =
            generate_channel_map_arrays(channel_map);
        let (first_channel, prn_s, remapping_index_of_last_used_channel) = csa2(
            counter,
            channel_identifier,
            &channel_map_array,
            &remapping_table,
            &inverse_remapping_table,
            nb_used,
        );

        ret.push(first_channel);

        let d = calculate_subevent_d(nb_used);

        let mut last_usedprn = prn_s as u32;
        let mut index_of_last_used_channel = remapping_index_of_last_used_channel as u32;

        for _ in 1..nb_subevents {
            let (channel, prn_sub_event_lu, sub_event_index_se_n_1) = csa2_subevent(
                last_usedprn,
                index_of_last_used_channel,
                channel_identifier,
                &channel_map_array,
                &remapping_table,
                &inverse_remapping_table,
                nb_used,
                d,
            );

            ret.push(channel);

            last_usedprn = prn_sub_event_lu;
            index_of_last_used_channel = sub_event_index_se_n_1;
        }
        ret
    }

    #[test]
    fn test_channel_id() {
        // part c, sec 3, csa2 sample data
        assert_eq!(calculate_channel_identifier(0x8E89BED6), 0x305F_u16);
    }

    #[test]
    fn test_d() {
        // from ble examples
        assert_eq!(calculate_subevent_d(37), 11);
        assert_eq!(calculate_subevent_d(9), 3);
    }

    #[test]
    fn test_csa_full() {
        // TODO instead of writing tests for all seperate parts, put breakpoints during testing and compare to the values on pages 3085 and 3086

        // 3.2
        // d = 11? it says in docs... is it given then? I think not
        let access_address: u32 = 0x8E89BED6;
        let channel_map: u64 = 0b1_1111_1111_1111_1111_1111_1111_1111_1111_1111;
        let counter: u32 = 0;
        let channels = csa2_all_subevents(access_address, channel_map, counter, 4);
        assert_eq!(channels, vec![25, 1, 16, 36]);

        let counter: u32 = 3;
        let channels = csa2_all_subevents(access_address, channel_map, counter, 4);
        assert_eq!(channels, vec![21, 4, 22, 8]);

        // 3.2
        // d = 3?
        let access_address: u32 = 0x8E89BED6;
        let channel_map: u64 = 0b1_1110_0000_0000_1110_0000_0000_0110_0000_0000;
        let counter: u32 = 8;
        let channels = csa2_all_subevents(access_address, channel_map, counter, 4);
        assert_eq!(channels, vec![34, 9, 33, 10]);
    }

    #[test]
    fn test_csa_no_subevent() {
        // 3.1 NO REMAPPING
        let access_address: u32 = 0x8E89BED6;
        let channel_map: u64 = 0b1_1111_1111_1111_1111_1111_1111_1111_1111_1111;

        let channel_identifier: u16 = calculate_channel_identifier(access_address);
        let channel_identifier: u32 = channel_identifier as u32;

        let (channel_map_array, remapping_table, inverse_remapping_table, nb_used) =
        generate_channel_map_arrays(channel_map);

        let expected: Vec<u8> = vec![25, 20, 6, 21];

        for counter in 0..=3 {
            let channel = csa2_no_subevent(
                counter,
                channel_identifier,
                &channel_map_array,
                &remapping_table,
                nb_used,
            );
            assert_eq!(channel, *expected.get(counter as usize).unwrap());
        }

        // other examples with new channel map
        let channel_map: u64 = 0b1_1110_0000_0000_1110_0000_0000_0110_0000_0000;
        let (channel_map_array, remapping_table, inverse_remapping_table, nb_used) =
        generate_channel_map_arrays(channel_map);

        //3.2 REMAPPING
        let expected: Vec<u8> = vec![23, 9, 34];
        for counter in 6..=8 {
            let channel = csa2_no_subevent(
                counter,
                channel_identifier,
                &channel_map_array,
                &remapping_table,
                nb_used,
            );
            assert_eq!(channel, *expected.get((counter - 6) as usize).unwrap());
        }
    }

    #[test]
    fn test_perm() {
        let start: u16 = 0b0001_0011_0000_1111;
        let end: u16 = 0b1100_1000_1111_0000;
        assert_eq!(perm(start), end);

        let start: u16 = 0b0101_1011_0000_0010;
        let end: u16 = 0b1101_1010_0100_0000;
        assert_eq!(perm(start), end);
    }

    #[test]
    fn test_mam() {
        let a: u16 = 23457;
        let b: u16 = 4352;
        let result: u16 = 9905; // Python3: (((23457 * 17) + 4352) % (2**16))

        assert_eq!(mam(a, b), result);

        let a: u16 = 63928;
        let b: u16 = 59348;
        let result: u16 = 32012; // Python3: (((63928 * 17) + 59348) % (2**16))

        assert_eq!(mam(a, b), result);
    }

    #[test]
    fn test_generate() {
        // 37 bit map
        // Channel 1,3,5,10,23,26,36
        let channel_map_first_byte: u64 = 0b0010_1010;
        let channel_map_second_byte: u64 = 0b0000_0100;
        let channel_map_third_byte: u64 = 0b1000_0000;
        let channel_map_fourth_byte: u64 = 0b0000_0100;
        let channel_map_fifth_byte: u64 = 0b0001_0000;

        let channel_map: u64 = channel_map_first_byte
            | channel_map_second_byte << 8
            | channel_map_third_byte << 16
            | channel_map_fourth_byte << 24
            | channel_map_fifth_byte << 32;

        let mut channel_map_array: [bool; 37] = [false; 37];
        channel_map_array[1] = true;
        channel_map_array[3] = true;
        channel_map_array[5] = true;
        channel_map_array[10] = true;
        channel_map_array[23] = true;
        channel_map_array[26] = true;
        channel_map_array[36] = true;

        let remapping_table: [u8; 37] = [
            1, 3, 5, 10, 23, 26, 36, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255,
        ];
        let mut inverse_remapping_table: [u8; 37] = [0xFF; 37];
        inverse_remapping_table[1] = 0;
        inverse_remapping_table[3] = 1;
        inverse_remapping_table[5] = 2;
        inverse_remapping_table[10] = 3;
        inverse_remapping_table[23] = 4;
        inverse_remapping_table[26] = 5;
        inverse_remapping_table[36] = 6;

        let nb_used = 7;

        let calced =
        generate_channel_map_arrays(channel_map);
        assert_eq!(
            calced,
            (
                channel_map_array,
                remapping_table,
                inverse_remapping_table,
                nb_used
            )
        );
    }

    #[test]
    fn test_csa2_no_subevent() {
        // arguments taken from some packets sniffed with wireshark

        // TODO BLE spec has examples!
    }
}
