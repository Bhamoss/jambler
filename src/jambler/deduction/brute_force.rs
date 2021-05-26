

use heapless::{Vec, pool::Box};

use crate::ble_algorithms::csa2::{csa2_no_subevent, generate_channel_map_arrays};

use super::{deducer::CounterInterval, distributions::prob_of_seeing_if_used};



#[derive(Debug, Clone)]
/// Will be broadcast over i2c for distributed brute forcing.
pub struct BruteForceParameters {
    pub seen_channel_map: u64,
    pub channel_id: u16,
    /// The version to avoid confusion when start or reset inbetween.
    pub version: u8,
    pub nb_sniffers: u8,
    pub threshold: f32,
    pub nb_events: u16,
    pub packet_loss: f32,
    pub relative_counters_and_channels : Vec<(u16,u8),256>
}

impl Default for BruteForceParameters {
    fn default() -> Self {
        Self {
            seen_channel_map: u64::MAX,
            channel_id: u16::MAX,
            version: 0,
            nb_sniffers: 1,
            threshold: f32::MAX,
            nb_events: 0,
            packet_loss: f32::MAX,
            relative_counters_and_channels: Vec::new(),
        }
    }
}


pub struct BruteForceResult {
    pub slave_id: u8,
    pub version: u8,
    pub result: CounterInterval
}


pub fn brute_force(sniffer_id: u8, params: Box<BruteForceParameters>) -> BruteForceResult {

    // TODO for likely false negatives, take from 0..max because if your packet loss is less bad than expected
    // TODO this will result in no solution if your sniffer did capture all packets

    // remember version before consume
    let version = params.version;
    let seen_chm = params.seen_channel_map;
    // Calculate bounds
    let interval_size = u16::MAX / (params.nb_sniffers as u16);
    let start = sniffer_id as u16 * interval_size;
    let end = if sniffer_id == params.nb_sniffers - 1 {
        u16::MAX
    }
    else {
        (sniffer_id + 1) as u16 * interval_size - 1
    };

    // Get an iterator returning the false negatives above the threshold
    let nb_unused_seen = (0u8..37).filter(|channel| params.seen_channel_map & (1 << *channel) == 0).count() as u8;
    let likely_false_negatives = (0..=nb_unused_seen)
        .filter(|fns| prob_of_seeing_if_used(nb_unused_seen, *fns, params.nb_events, 1.0 - params.packet_loss) >= params.threshold);

    // Brute force for every nb of likely false negatives
    let result = likely_false_negatives.map(|nb_false_negs| {
        
        // Brute force for every channel map where ever possible combination of unused has been turned to used for nb_false_negs.
        ChmCombos::new(nb_unused_seen, nb_false_negs, seen_chm).into_iter().map( |chm|{
            let (channel_map_bool_array,remapping_table, _, nb_used) =  generate_channel_map_arrays(chm);

            // now we have concrete channel map as before

            let mut found_counter: Option<u32> = None;
            for potential_counter in start..=end {

                // If there is no inconsistency for this potential counter save it
                if params.relative_counters_and_channels.iter().all(|(relative_counter, channel)| *channel ==
                        csa2_no_subevent(
                            potential_counter.wrapping_add(*relative_counter) as u32,
                            params.channel_id as u32,
                            &channel_map_bool_array,
                            &remapping_table,
                            nb_used,
                        )
                    ) {
                    match found_counter {
                        None => {
                            // the first one without inconsistency, save it
                            found_counter = Some(potential_counter as u32);
                        }
                        Some(_) => {
                            // There was already another one without inconstistency, we have multiple solutions
                            return CounterInterval::MultipleSolutions;
                        }
                    }
                }
            }

            // The fact we get here, we did not find mutliple solutions, must be one or none.
            // Remember for exactly one you need to run through the whole range
            match found_counter {
                None => {
                    CounterInterval::NoSolutions
                }
                Some(counter) => 
                    CounterInterval::ExactlyOneSolution(counter as u16, chm, 0),
            }
        })
    })//.collect_vec();
    .flatten()
    //.inspect(|_| nb_bfs += 1) -> if you want to debug enable this. Or to log somewhere.
    .reduce(|a,b| { // IMPORTANT if 1 element this will give the 1 element => one solution stays one solution
        match a {
            CounterInterval::ExactlyOneSolution(ac, am, atodo) => {
                match b {
                    CounterInterval::ExactlyOneSolution(bc, bm, btodo) => {
                        // now require them to be exactly the same -> Wrong e.g. 0 fns wont have this
                        //assert!((*m).count_ones() <= tm.count_ones());
                        if ac == bc  {
                            // For same counters, or them = take union of used channels
                            // Later on we will require the union to be exactly the same for all numbers of false positives
                            // Remembers chm + the places where a 1 was turned into a 0
                            let more_todo_from_both = am ^ bm;

                            CounterInterval::ExactlyOneSolution(ac, am & bm,atodo | btodo | more_todo_from_both)
                        }
                        else {
                            CounterInterval::MultipleSolutions
                        }
                    }
                    CounterInterval::MultipleSolutions => {CounterInterval::MultipleSolutions}
                    CounterInterval::NoSolutions => {a}
                }
            }
            CounterInterval::MultipleSolutions => {CounterInterval::MultipleSolutions}
            CounterInterval::NoSolutions => {b}
        }
    })
    // If no nb of false negatives where possible (above our threshold) return no solutions.
    .unwrap_or(CounterInterval::NoSolutions);

    BruteForceResult {
        slave_id: sniffer_id,
        version,
        result,
    }
}

struct ChmCombos {
    nb_unused_seen: u8,
    nb_false_negatives: u8,
    seen_channel_map: u64,
    next_channel_map_combo: [u8;37]
}

impl ChmCombos {
    pub fn new(nb_unused_seen: u8, nb_false_negatives: u8, seen_channel_map: u64) -> Self {
        let mut ret = Self {
            nb_unused_seen,
            nb_false_negatives,
            seen_channel_map,
            next_channel_map_combo: [0u8;37],
        };
        (0..nb_false_negatives).for_each(|nf| ret.next_channel_map_combo[nf as usize] = nf);
        ret
    }
}

impl Iterator for ChmCombos {
    // A channel map with nb_false_negatives from seen_channel_map
    type Item = u64;
    
    /// We go RIGHT to LEFT over u64, thus stays the same!
    /// Position 0 is the lowest unused channel.
    fn next(&mut self) -> Option<Self::Item> {
        // Stop when rightmost would have to be one more than the number unused seen -> it would have to be bumped out -> stop
        if self.next_channel_map_combo[self.nb_false_negatives as usize - 1] >= self.nb_unused_seen {
            return None;
        }

        // Calculate this combo to remember it to return before we calculate next next
        let ret = self.next_channel_map_combo.iter().take(self.nb_false_negatives as usize)
            .fold(self.seen_channel_map, |running_chm, nth_unused_to_flip|
                // Flip the nth unused of the self.seen_channel_map by xorring the 1 bit mask for it with the running_chm
                {
                    let bit_to_flip = (0u8..37).filter(|i| self.seen_channel_map & (1 << *i) == 0).nth(*nth_unused_to_flip as usize).unwrap();
                    running_chm | (1 << bit_to_flip)
                }
            );

        // Calculate next combination
        // Find rightmost location that can be incremented
        // More to the right is higher array index.
        // It can move to the right if its current location is not equal to the highest position it could ever have,
        // Keeping in mind its highest location is the one were there are others (t) in front, and thus only t places to be filled in front of you.
        // Moving to the right any more would not leave room for one in front of you.
        let rightmost_ok = (1..self.nb_false_negatives).rev()
            .find(|t| 
                self.next_channel_map_combo[*t as usize] != self.nb_unused_seen - self.nb_false_negatives + *t
            ).unwrap_or(0);
        // Move it to the right
        self.next_channel_map_combo[rightmost_ok as usize] += 1;
        // All the one that are more to the right than this one, give them their starting position again, with the offset from the rightmost_ok
        ((rightmost_ok + 1)..self.nb_false_negatives).for_each(|i| 
            self.next_channel_map_combo[i as usize] = self.next_channel_map_combo[i as usize - 1] + 1);
        
        Some(ret)
    }
} 

#[cfg(test)]
mod chm_combo_tests {

    use crate::ble_algorithms::csa2::generate_channel_map_arrays;
    use std::vec::Vec;
    use std::iter::Iterator;
    use super::ChmCombos;
    use itertools::Itertools;
    use num::integer::binomial;

    #[test]
    fn correct_combos() {

        let nb_false_negs = 4u8;
        let chm = 0x10_FF_FF_F0_FFu64; // 8 unused seen
        let nb_unused_seen = (0u8..37).filter(|channel| chm & (1 << *channel) == 0).count() as u8;
        assert_eq!(nb_unused_seen, 8);

        let my_combo = ChmCombos::new(nb_unused_seen, nb_false_negs, chm);

        // Do like before
        let (channel_map_bool_array,_, _, _) = generate_channel_map_arrays(chm);
        let unused_channels = channel_map_bool_array.iter().enumerate().filter_map(|(channel, seen)| if !*seen {Some(channel as u8)} else {None}).collect_vec();

        let combinations: Vec<Vec<u8>> = unused_channels.clone().into_iter().combinations(nb_false_negs as usize).collect_vec();
        let mut chms = combinations.clone().into_iter().map(|to_flip| {
        unused_channels.iter().fold(0x1F_FF_FF_FF_FFu64, |chm, channel|{
                if !to_flip.contains(channel) {
                    // turn of if now flipped to used
                    chm & !(1 << *channel)
                }
                else {
                    chm
                }
            })
        }).collect_vec();
        let b = binomial(nb_unused_seen as u64, nb_false_negs as u64) as usize;
        if b != chms.len() {
            panic!("{} {:?}", b, combinations)
        }

        let mut rem = vec![];
        for my_chm in my_combo.into_iter() {
            assert!(chms.contains(&my_chm));
            assert!(chms.iter().filter(|f| **f == my_chm).count() == 1);
            let pos = chms.iter().position(|v| *v == my_chm).unwrap();
            chms.remove(pos);
            rem.push(my_chm)
        }

        assert!(chms.is_empty());
    }
}
