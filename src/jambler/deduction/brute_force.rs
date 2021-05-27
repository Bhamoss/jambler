

use heapless::{Vec, pool::singleton::Box};


use crate::ble_algorithms::csa2::{csa2_no_subevent, generate_channel_map_arrays};

use super::{deducer::CounterInterval, distributions::prob_of_seeing_if_used, control::BruteForceParametersBox};



#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub struct BruteForceResult {
    pub slave_id: u8,
    pub version: u8,
    pub result: CounterInterval
}


pub fn brute_force(sniffer_id: u8, params: Box<BruteForceParametersBox>) -> BruteForceResult {

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
        // 0 false negatives edge case
        if self.nb_false_negatives == 0 {
            if self.nb_unused_seen != u8::MAX {
                self.nb_unused_seen = u8::MAX;
                return Some(self.seen_channel_map);
            }
            else {
                return None
            }
        }


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


#[cfg(test)]
mod brute_force_tests {

    use core::mem::MaybeUninit;
    use std::vec::Vec;
    use std::iter::Iterator;
    use heapless::pool::Node;
    use heapless::pool::singleton::Pool;
    //use itertools::Itertools;
    use crate::jambler::deduction::brute_force::BruteForceParameters;
    use crate::jambler::deduction::brute_force::brute_force;
    use crate::jambler::deduction::deducer::CounterInterval::{self, *};
    use crate::jambler::deduction::control::BruteForceParametersBox;
    use rayon::prelude::*;


    #[test]
    fn bf_1() {
        let channel_id : u16 = 55578;
        let chm : u64 = 101668861912;
        let threshold : f32 = 0.1;
        let nb_events : u16 = 82;
        let packet_loss : f32 = 0.1;
        let nb_used : u8 = 32;
        let packets : Vec<(u16, u8)> = vec![(0, 31), (119, 21), (133, 32), (360, 34), (374, 8), (387, 6), (430, 4), (559, 10), (600, 22), (654, 25), (719, 15), (730, 29), (744, 13), (756, 12), (784, 36), (826, 16), (831, 23), (922, 18), (1102, 7), (1204, 24), (1382, 27), (1393, 9), (1405, 33), (1474, 17), (1486, 3), (1609, 19)];
        //let result : CounterInterval = ExactlyOneSolution(61381, 118648434557, 17716777090);
        let result : CounterInterval = ExactlyOneSolution(16570, 101668861912, 35501656103);

        const NB_SNIFFERS : u8 = 5;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);


    }


    #[test]
    fn bf_2() {
        let channel_id : u16 = 62589;
        let chm_seen : u64 = 51505052911;
        let threshold : f32 = 0.1;
        let nb_events : u16 = 148;
        let packet_loss : f32 = 0.5;
        let nb_used : u8 = 37;
        let packets : Vec<(u16, u8)> = vec![(0, 29), (2, 35), (166, 26), (321, 0), (361, 2), (447, 27), (725, 1), (926, 20), (930, 10), (1107, 22), (1153, 24), (1269, 12), (1362, 21), (1411, 31), (1464, 11), (1471, 13), (1513, 5), (2079, 15), (2399, 33), (2441, 6), (2514, 32), (2619, 30), (2800, 7), (2831, 23), (2851, 3), (2996, 28)];
        let result : CounterInterval = ExactlyOneSolution(31250, 51505052911, 85933900560);


        const NB_SNIFFERS : u8 = 10;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm_seen,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);


    }


    #[test]
    fn bf_3() {
        let channel_id : u16 = 48534;
        let chm_seen : u64 = 135288843775;
        let threshold : f32 = 0.1;
        let nb_events : u16 = 148;
        let packet_loss : f32 = 0.5;
        let nb_used : u8 = 36;
        let packets : Vec<(u16, u8)> = vec![(0, 18), (47, 24), (142, 30), (174, 0), (601, 20), (603, 7), (628, 32), (699, 25), (721, 34), (858, 27), (874, 17), (886, 33), (996, 8), (1185, 11), (1196, 28), (1233, 2), (1372, 15), (1404, 10), (1516, 6), (1568, 22), (1615, 35), (1684, 13), (1793, 3), (1810, 16), (1864, 5), (2027, 26), (2226, 1), (2263, 29), (2366, 36), (2461, 14), (2467, 4), (2485, 23)];
        let result : CounterInterval = ExactlyOneSolution(12093, 135288843775, 2150109696);


        const NB_SNIFFERS : u8 = 10;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm_seen,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);


    }


    #[test]
    fn bf_4() {
        let channel_id : u16 = 51945;
        let chm_seen : u64 = 134003151871;
        let threshold : f32 = 0.02;
        let nb_events : u16 = 103;
        let packet_loss : f32 = 0.3;
        let nb_used : u8 = 28;
        let packets : Vec<(u16, u8)> = vec![(0, 33), (313, 3), (315, 36), (325, 16), (423, 24), (441, 12), (480, 28), (509, 34), (683, 18), (684, 2), (835, 20), (841, 21), (886, 25), (910, 6), (914, 14), (940, 35), (1026, 29), (1111, 32), (1147, 0), (1268, 4), (1510, 7), (1548, 5), (1551, 15), (1565, 8), (1587, 9), (1601, 1)];
        let result : CounterInterval = ExactlyOneSolution(39654, 134003151871, 3368036352);


        const NB_SNIFFERS : u8 = 10;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm_seen,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);


    }


    #[test]
    fn bf_5() {
        let channel_id : u16 = 22210;
        let chm_seen : u64 = 65925207927;
        let threshold : f32 = 0.02;
        let nb_events : u16 = 103;
        let packet_loss : f32 = 0.3;
        let nb_used : u8 = 28;
        let packets : Vec<(u16, u8)> = vec![(0, 2), (27, 33), (51, 28), (52, 21), (106, 10), (118, 20), (125, 27), (207, 34), (376, 22), (408, 17), (616, 14), (721, 0), (756, 12), (820, 8), (863, 5), (888, 15), (1034, 24), (1191, 35), (1209, 4), (1216, 6), (1324, 32), (1579, 30), (1716, 1), (1727, 9)];
        let result : CounterInterval = ExactlyOneSolution(63549, 65925207927, 2249009280);


        const NB_SNIFFERS : u8 = 10;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm_seen,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);


    }


    #[test]
    fn bf_6() {
        let channel_id : u16 = 19584;
        let chm_seen : u64 = 91586754293;
        let threshold : f32 = 0.02;
        let nb_events : u16 = 103;
        let packet_loss : f32 = 0.3;
        let nb_used : u8 = 28;
        let packets : Vec<(u16, u8)> = vec![(0, 20), (138, 15), (320, 25), (353, 21), (356, 0), (433, 4), (716, 30), (717, 7), (736, 28), (739, 23), (748, 5), (750, 22), (1269, 36), (1279, 2), (1340, 34), (1502, 18), (1526, 9), (1538, 13), (1606, 32), (1632, 10), (1670, 17), (1885, 6), (1922, 12), (1933, 14), (1942, 19)];
        let result : CounterInterval = ExactlyOneSolution(43103, 91586754293, 37128046858);


        const NB_SNIFFERS : u8 = 10;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm_seen,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);


    }

    #[test]
    fn bf_7() {
        let channel_id : u16 = 55911;
        let chm_seen : u64 = 66027939687;
        let threshold : f32 = 0.02;
        let nb_events : u16 = 103;
        let packet_loss : f32 = 0.3;
        let nb_used : u8 = 28;
        let packets : Vec<(u16, u8)> = vec![(0, 0), (14, 1), (53, 23), (91, 5), (98, 27), (126, 32), (168, 17), (205, 33), (216, 2), (222, 24), (257, 35), (464, 20), (593, 8), (672, 26), (691, 30), (833, 9), (863, 13), (1075, 28), (1241, 25), (1559, 6), (1568, 10), (1757, 14), (1814, 34)];
        let result : CounterInterval = ExactlyOneSolution(25145, 66027939687, 2691008640);


        const NB_SNIFFERS : u8 = 10;
        let version = 0;

        let params = BruteForceParameters {
            seen_channel_map: chm_seen,
            channel_id,
            version,
            nb_sniffers: NB_SNIFFERS,
            threshold,
            nb_events,
            packet_loss,
            relative_counters_and_channels: packets.into_iter().collect(),
        };

        // Create heap for params
        static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;NB_SNIFFERS as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, BruteForceParametersBox::alloc().unwrap().init(params.clone())))
        .collect::<Vec<_>>();

        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));

        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);


        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);

        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();

        assert_eq!(bf_result.result, result);

    }
}