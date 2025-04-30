// use criterion::{Criterion, criterion_group, criterion_main};
// use parasol_cpu::test_utils::make_computer_80;

// mod programs;

// use crate::programs::chi_squared::chi_squared_optimised_program;

// fn chi_squared(c: &mut Criterion) {
//     env_logger::init();

//     let (mut proc, enc) = make_computer_80();

//     let bit_width = 16;
//     let encrypted_computation = true;

//     let n_0 = 2u16;
//     let n_1 = 3u16;
//     let n_2 = 3u16;
//     let zero = 0u16;

//     let optimised_program = chi_squared_optimised_program(bit_width, encrypted_computation);

//     // let buffer_0 = buffer_from_value_80(n_0, &enc, encrypted_computation);
//     // let buffer_1 = buffer_from_value_80(n_1, &enc, encrypted_computation);
//     // let buffer_2 = buffer_from_value_80(n_2, &enc, encrypted_computation);

//     // let output_buffer_0 = buffer_from_value_80(zero, &enc, encrypted_computation);
//     // let output_buffer_1 = buffer_from_value_80(zero, &enc, encrypted_computation);
//     // let output_buffer_2 = buffer_from_value_80(zero, &enc, encrypted_computation);
//     // let output_buffer_3 = buffer_from_value_80(zero, &enc, encrypted_computation);

//     // let mut group = c.benchmark_group("chi_squared");
//     // group.sample_size(10);

//     // group.bench_function("chi squared optimised", |b| {
//     //     b.iter(|| {
//     //         proc.run_program(
//     //             &optimised_program.clone().into(),
//     //             &[
//     //                 buffer_0.clone(),
//     //                 buffer_1.clone(),
//     //                 buffer_2.clone(),
//     //                 output_buffer_0.clone(),
//     //                 output_buffer_1.clone(),
//     //                 output_buffer_2.clone(),
//     //                 output_buffer_3.clone(),
//     //             ],
//     //         )
//     //         .unwrap();
//     //     });
//     // });

//     // Seems to stall sometimes
//     // group.bench_function("chi squared naive", |b| {
//     //     b.iter(|| {
//     //         proc.run_program(
//     //             &naive_program,
//     //             vec![buffer_0.clone(), buffer_1.clone(), buffer_2.clone()],
//     //             vec![
//     //                 output_buffer_0.clone(),
//     //                 output_buffer_1.clone(),
//     //                 output_buffer_2.clone(),
//     //                 output_buffer_3.clone(),
//     //             ],
//     //         )
//     //         .unwrap();
//     //     });
//     // });
// }

// criterion_group!(benches, chi_squared);
// criterion_main!(benches);
fn main() {}
