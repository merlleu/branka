extern crate criterion;
extern crate getrandom;
extern crate branka;
extern crate branca;

use branca::Branca;
use branka::Branka;

use criterion::*;

use getrandom::getrandom;

static INPUT_SIZES: [usize; 5] = [128, 256, 512, 1024, 2 * 1024];

mod random_tokens {
    use super::*;

    pub fn bench_encode(c: &mut Criterion) {
        let mut group = c.benchmark_group("encode");
        let mut key = [0u8; 32];
        getrandom(&mut key).unwrap();


        for size in INPUT_SIZES.iter() {
            let mut input = vec![0u8; *size];
            getrandom(&mut input).unwrap();

            // group.throughput(Throughput::Bytes(*size as u64));
            group.throughput(Throughput::Elements(1));
            let branca = Branka::new(&key, 3000);
            group.bench_with_input(
                BenchmarkId::new("branka", *size),
                &input,
                |b, input_message| {
                    b.iter(|| {
                        let r = branca.encode(input_message);
                        black_box(r);
                    })
                },
            );

            let mut branca = Branca::new(&key).unwrap();
            group.bench_with_input(
                BenchmarkId::new("branca", *size),
                &input,
                |b, input_message| {
                    b.iter(|| {
                        let r = branca.encode(input_message).unwrap();
                        black_box(r)
                    })
                },
            );


        }
    }

    pub fn bench_decode(c: &mut Criterion) {
        let mut group = c.benchmark_group("decode");
        let mut key = [0u8; 32];
        getrandom(&mut key).unwrap();
        

        for size in INPUT_SIZES.iter() {
            let mut input = vec![0u8; *size];
            getrandom(&mut input).unwrap();
            let branca_ = Branka::new(&key, 3000);
            let token = branca_.encode(&input);
            let branca = Branka::new(&key, 3000);

            // group.throughput(Throughput::Bytes(*size as u64));
            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::new("branka", *size),
                &token,
                |b, input_message| {
                    b.iter(|| {
                        let r = branca.decode(&input_message).unwrap();
                        black_box(r);
                    })
                },
            );

            let branca = Branca::new(&key).unwrap();
            group.bench_with_input(
                BenchmarkId::new("branca", *size),
                &token,
                |b, input_message| {
                    b.iter(|| {
                        let r = branca.decode(input_message, 3000).unwrap();
                        black_box(r)
                    })
                },
            );


        }
    }

    criterion_group! {
        name = random_tokens;
        config = Criterion::default();
        targets =
        bench_encode,
        bench_decode,
    }
}

criterion_main!(
    random_tokens::random_tokens,
);
