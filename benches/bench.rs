extern crate branca;
extern crate branka;
extern crate criterion;
extern crate getrandom;

use branca::Branca;
use branka::Branka;

use criterion::*;
use flate2::Compression;
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use speedy::{Readable, Writable};

#[derive(Writable, Readable, Serialize, Deserialize)]
pub struct SvcTokenV1 {
    pub client_id: i64,
    pub flags: u32,

    pub user: Option<(i64, i32)>,

    #[speedy(length_type = u64_varint)]
    pub perms_i: Vec<u32>,
    #[speedy(length_type = u64_varint)]
    pub perms_s: Vec<PermissionStr>,
}

#[derive(Writable, Readable, Serialize, Deserialize)]
pub struct PermissionStr {
    #[speedy(length_type = u64_varint)]
    pub scope: String,
    pub crud: u8,
}

fn load(test_file: &str) -> SvcTokenV1 {
    let f = std::fs::File::open(test_file).unwrap();
    serde_json::from_reader(f).unwrap()
}

static TEST_FILES: [&str; 2] = ["test_1.json", "test_2.json"];

mod random_tokens {
    use super::*;

    pub fn bench_encode(c: &mut Criterion) {
        for fl in TEST_FILES {
            let mut group = c.benchmark_group(format!("encode-{}", fl));
            let mut key = [0u8; 32];
            getrandom(&mut key).unwrap();

            let input = load(fl);

            
            // group.throughput(Throughput::Bytes(*size as u64));
            group.throughput(Throughput::Elements(1));
            let branca = Branka::new(&key, 3000);
            let i = 6;
            let compression = Compression::new(i);
            group.bench_with_input(BenchmarkId::new("gz", i), &input, |b, input_message| {
                b.iter(|| {
                    let r = branca.encode_gz_struct(black_box(&input_message), compression);
                    black_box(r);
                })
            });

            group.bench_with_input(BenchmarkId::new("zlib", i), &input, |b, input_message| {
                b.iter(|| {
                    let r = branca.encode_zlib_struct(black_box(&input_message), compression);
                    black_box(r);
                })
            });

            // deflate
            group.bench_with_input(
                BenchmarkId::new("deflate", i),
                &input,
                |b, input_message| {
                    b.iter(|| {
                        let r = branca
                            .encode_deflate_struct(black_box(&input_message), compression);
                        black_box(r);
                    })
                },
            );
        }
    }

    pub fn bench_decode(c: &mut Criterion) {
        for fl in TEST_FILES {
            let mut group = c.benchmark_group(format!("decode-{}", fl));
            let mut key = [0u8; 32];
            getrandom(&mut key).unwrap();
            let input = load(fl);

            group.throughput(Throughput::Elements(1));
            let branca = Branka::new(&key, 3000);
            let i = 6;
            let compression = Compression::new(i);
            let token = branca.encode_gz_struct(&input, compression);
            group.bench_with_input(BenchmarkId::new("gz", i), &token, |b, input_message| {
                b.iter(|| {
                    let r: SvcTokenV1 =
                        branca.decode_gz_struct(black_box(&input_message)).unwrap();
                    black_box(r);
                })
            });

            // zlib
            let token = branca.encode_zlib_struct(&input, compression);
            group.bench_with_input(BenchmarkId::new("zlib", i), &token, |b, input_message| {
                b.iter(|| {
                    let r: SvcTokenV1 = branca
                        .decode_zlib_struct(black_box(&input_message))
                        .unwrap();
                    black_box(r);
                })
            });

            // deflate
            let token = branca.encode_deflate_struct(&input, compression);
            group.bench_with_input(
                BenchmarkId::new("deflate", i),
                &token,
                |b, input_message| {
                    b.iter(|| {
                        let r: SvcTokenV1 = branca
                            .decode_deflate_struct(black_box(&input_message))
                            .unwrap();
                        black_box(r);
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

criterion_main!(random_tokens::random_tokens,);
