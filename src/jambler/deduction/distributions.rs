use num::integer::binomial;
#[allow(unused_imports)]
use num::traits::Float;

// USES f32 because of 32-bit floating point unit which only supports single precision

/// p: chance of success
/// wanted_probability: chance of success you want
/// return: necessary repetitions to get the wanted probability
pub fn geo_qdf(p: f32, wanted_probability : f32) -> u32 {
    let raw = (1f32 - wanted_probability).log(1.0 - p);
    //println!("{}", raw);
    raw.ceil() as u32 
}

pub fn geo_cdf(p: f32, occurences: u32) -> f32 {
    assert!(occurences > 0);
    1f32 - (1.0 - p).powi(occurences as i32)
}


pub fn prob_of_seeing_if_used(nb_unused_seen: u8, nb_false_negs: u8, nb_events: u16, physical_chance: f32) -> f32 {
    let nb_used = 37 - nb_unused_seen + nb_false_negs;
    if nb_used == 0 {return 0.0}
    let real_capture_chance = physical_chance * (1.0 / nb_used as f32);
    let chance_of_hearing_channel = geo_cdf(real_capture_chance, nb_events as u32); // cdf(e): chance of first occurring on or before e
    // the chance of seeing exactly that many true positives (and thus false negatives)
    binom_pmf(chance_of_hearing_channel, nb_used, nb_used - nb_false_negs)
}

pub fn binom_pmf(p: f32, n: u8, k: u8) -> f32 {
    let p_q = p.powi(k as i32) * (1.0 - p).powi((n-k) as i32);
    // Only use u64 when it would cause problems
    if n > 34 && k > 12 && k < 25 {
        binomial(n as u64, k as u64) as f32 * p_q
    } else {
        binomial(n as u32, k as u32) as f32 * p_q
    }
}



#[cfg(test)]
mod geo_test {
    use super::{geo_qdf, geo_cdf, binom_pmf, prob_of_seeing_if_used};
    use itertools::Itertools;
    use statrs::distribution::{Binomial, Discrete, Geometric};
    use statrs::distribution::Univariate;
    #[allow(unused_imports)]
    use num::traits::Float;

    #[test]
    fn geo() {
        let success_chance = 0.03f32;
        let target_chance = 0.141266f32;
        let required_repitions = 5;
        let dist = Geometric::new(success_chance as f64).unwrap();
        assert!((geo_cdf(success_chance, required_repitions) - target_chance).abs() < 0.0001, "{} was not {}", geo_cdf(success_chance, required_repitions), target_chance);
        assert!((dist.cdf(required_repitions as f64) - target_chance as f64).abs() < 0.00001);
        assert_eq!(geo_qdf(success_chance, target_chance - 0.01), required_repitions);
        let calced = geo_qdf(success_chance, target_chance - 0.001);
        assert_eq!(calced, required_repitions);
        let manual = geo_cdf(success_chance, calced);
        let dist_geo_cdf = dist.cdf(calced as f64);
        assert!((dist_geo_cdf - manual as f64).abs() < 0.0001, "{} {} {}", dist_geo_cdf, manual, calced);
        let my_geo_qdf = geo_qdf(success_chance, target_chance - 0.001);
        assert_eq!(my_geo_qdf, required_repitions);
        let my_geo_cdf = geo_cdf(success_chance, calced);
        assert!((my_geo_cdf - target_chance).abs() < 0.00001, "{} was not {}", my_geo_cdf, target_chance);
        assert!((geo_cdf(success_chance, my_geo_qdf) - target_chance).abs() < 0.0001);
        let should_be_x = dist.cdf(calced as f64 + 0.5);
        assert!((should_be_x - target_chance as f64).abs() < 0.01, "{} not {}", should_be_x, target_chance)
    }

    #[test]
    fn binom() {
        let p = 0.7f32;
        let n = 10u8;
        let k = 7u8;
        let solution = 0.266_827_94_f32;
        let dist = Binomial::new(p as f64, n as u64).unwrap();
        let statrs_sol = dist.pmf(k as u64) as f32;
        let diff = (solution - statrs_sol).abs();
        assert!(diff < 0.0001);
        let my_sol = binom_pmf(p, n, k);
        let my_diff = (solution - my_sol).abs();
        assert!(my_diff < 0.0001);

        (0u8..=37)
            .flat_map(|n| (0..=n).map(move |k| (n,k)))
            .cartesian_product((1u8..100).step_by(5).map(|t| 0.01f32 * t as f32))
            .for_each(|((n, k), p)| {
                let dist = Binomial::new(p as f64, n as u64).unwrap();
                let statrs_sol = dist.pmf(k as u64) as f32;
                let my_sol = binom_pmf(p, n, k);
                let my_diff = (statrs_sol - my_sol).abs();
                assert!(diff < 0.0001);
            });
    }


    fn chance_and_combo_reality_simulation_copy_paste(nb_unused_seen: u8, nb_false_negs: u8, nb_events: u8, physical_chance: f64) -> f64 {
        let nb_used = 37 - nb_unused_seen + nb_false_negs;
        let real_capture_chance = physical_chance * (1.0 / nb_used as f64);
        let dist = Geometric::new(real_capture_chance).unwrap(); 
        let chance_of_hearing_channel = dist.cdf(nb_events as f64); 
        let all_dist = Binomial::new(chance_of_hearing_channel, nb_used as u64).unwrap(); 
        all_dist.pmf((nb_used - nb_false_negs) as u64)
    }

    #[test]
    fn chm_bf_chance() {
        let nbu = 5u8;
        let nb_fn = 2u8;
        let nb_events = 120u16;
        let packet_loss = 0.1f32;

        let sim_sol = chance_and_combo_reality_simulation_copy_paste(nbu, nb_fn, nb_events as u8, 1.0 - packet_loss as f64);
        let my_sol = prob_of_seeing_if_used(nbu, nb_fn, nb_events, 1.0 - packet_loss);
        let diff = (sim_sol as f32 - my_sol).abs();
        assert!(diff < 0.0001);

        (0u8..=37)
            .flat_map(|nbu| (0..=nbu).map(move |nb_fn| (nbu,nb_fn)).filter(|(nbu,nb_fn)| 37 - *nbu + *nb_fn > 0))
            .cartesian_product((1u8..80).step_by(5).map(|t| 0.01f32 * t as f32))
            .cartesian_product(50u16..200).step_by(25)
            .for_each(|(((nbu, nb_fn), packet_loss), nb_events)| {
                let sim_sol = chance_and_combo_reality_simulation_copy_paste(nbu, nb_fn, nb_events as u8, 1.0 - packet_loss as f64);
                let my_sol = prob_of_seeing_if_used(nbu, nb_fn, nb_events, 1.0 - packet_loss);
                let diff = (sim_sol as f32 - my_sol).abs();
                assert!(diff < 0.0001);
            });
    }

}
