
#[cfg(not(target_arch="x86_64"))]
use core::mem::MaybeUninit;
#[cfg(not(target_arch="x86_64"))]
use heapless::pool::{Node, singleton::Pool};
#[cfg(not(target_arch="x86_64"))]
use jambler::deduction::control::BruteForceParametersBox;

use criterion::{ criterion_group, criterion_main, Criterion};
use jambler::{self, deduction::{brute_force::{BruteForceParameters, brute_force, clone_bf_param, convert_bf_param},  deducer::CounterInterval::{self, *}}};
use rayon::prelude::*;


fn criterion_benchmark(c: &mut Criterion) {

    let mut group = c.benchmark_group("bf");
    // Configure Criterion.rs to detect smaller differences and increase sample size to improve
    // precision and counteract the resulting noise.
    group.sample_size(10);

    group.bench_function("Brute force", |b| b.iter(|| {
        let channel_id : u16 = 55911;
        let chm_seen : u64 = 66027939687;
        let threshold : f32 = 0.02;
        let nb_events : u16 = 103;
        let packet_loss : f32 = 0.3;
        let _nb_used : u8 = 28;
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
        #[cfg(not(target_arch="x86_64"))]
        {static mut BFP_HEAP : MaybeUninit<[Node<BruteForceParameters>;(NB_SNIFFERS + 1) as usize]> = MaybeUninit::uninit();
        unsafe{BruteForceParametersBox::grow_exact(&mut BFP_HEAP)};}

        let params = convert_bf_param(&params);

        let results = (0..NB_SNIFFERS).into_par_iter()
        .map(|sniffer_id| brute_force(sniffer_id, clone_bf_param(&params)))
        .collect::<Vec<_>>();
        assert!(results.iter().all(|r| !matches!(r.result, MultipleSolutions)));
        let nb_exactly_one = results.iter().filter(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).count();
        assert_eq!(nb_exactly_one, 1);
        let nb_no_sol = results.iter().filter(|r| matches!(r.result, NoSolutions)).count();
        assert_eq!(nb_no_sol, NB_SNIFFERS as usize - 1);
        let bf_result = results.into_iter().find(|r| matches!(r.result, ExactlyOneSolution(_, _, _))).unwrap();
        assert_eq!(bf_result.result, result);
    }));

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);