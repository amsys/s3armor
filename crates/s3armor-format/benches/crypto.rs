//! Encrypt/decrypt throughput per algorithm and chunk size. Feeds
//! `s3armor bench`'s local tier (docs/ARCHITECTURE.md "Benchmarks (`s3armor bench`)").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "test code: a failed assumption should abort the test"
)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use s3armor_format::v1::{decrypt_all, encrypt_all, Alg};

const ALGS: [(&str, Alg); 2] = [
    ("aes256gcm", Alg::Aes256Gcm),
    ("xchacha20poly1305", Alg::XChaCha20Poly1305),
];
const CHUNK_SIZES: [(&str, usize); 3] = [
    ("64KiB", 64 * 1024),
    ("1MiB", 1024 * 1024),
    ("8MiB", 8 * 1024 * 1024),
];
const PAYLOAD_LEN: usize = 8 * 1024 * 1024;

#[expect(
    clippy::significant_drop_tightening,
    reason = "Criterion's BenchmarkGroup is held for the whole group by design; its Drop runs finish()"
)]
fn bench_crypto(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let payload = vec![0xABu8; PAYLOAD_LEN];

    let mut group = c.benchmark_group("encrypt");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    for (alg_name, alg) in ALGS {
        for (chunk_name, chunk_size) in CHUNK_SIZES {
            group.bench_with_input(
                BenchmarkId::new(alg_name, chunk_name),
                &chunk_size,
                |b, &chunk_size| b.iter(|| encrypt_all(alg, &key, 0, chunk_size, &payload)),
            );
        }
    }
    group.finish();

    let mut group = c.benchmark_group("decrypt");
    group.throughput(Throughput::Bytes(PAYLOAD_LEN as u64));
    for (alg_name, alg) in ALGS {
        for (chunk_name, chunk_size) in CHUNK_SIZES {
            let ciphertext = encrypt_all(alg, &key, 0, chunk_size, &payload);
            group.bench_with_input(
                BenchmarkId::new(alg_name, chunk_name),
                &chunk_size,
                |b, &chunk_size| {
                    b.iter(|| decrypt_all(alg, &key, 0, chunk_size, &ciphertext).unwrap());
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_crypto);
criterion_main!(benches);
