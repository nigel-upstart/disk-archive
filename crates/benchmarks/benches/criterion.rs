//! Criterion microbenchmarks: core, full native scanner and gzip/hash primitives.
//! These are not end-to-end pipeline measurements.
use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use disk_archive_benchmarks::{
    components::{BUFFER_BYTES, ScannerFixture, buffer, gzip_sha256},
    record, redact,
};

fn kernels(criterion: &mut Criterion) {
    let input = record(100 * 1024);
    assert!(input.is_ok(), "synthetic fixture must fit fixed budget");
    if let Ok(input) = input {
        let mut group = criterion.benchmark_group("production_redaction");
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_function("needle_build_and_line_rewrite", |bench| {
            bench.iter(|| {
                let result = redact(black_box(&input));
                assert!(matches!(result, Ok(stats) if stats.replacements == 1));
            });
        });
        group.finish();
    }
}

fn components(criterion: &mut Criterion) {
    let scanner = ScannerFixture::new();
    assert!(scanner.is_ok(), "the full native catalog must compile");
    if let Ok(scanner) = scanner {
        let mut group = criterion.benchmark_group("full_catalog_scanner");
        group.throughput(Throughput::Bytes(BUFFER_BYTES as u64));
        group.bench_function("fixed_buffer", |bench| {
            bench.iter(|| {
                assert!(black_box(&scanner).scan().is_ok());
            });
        });
        group.finish();
    }
    let input = buffer();
    let mut group = criterion.benchmark_group("gzip_sha256_primitives");
    group.throughput(Throughput::Bytes(input.len() as u64));
    group.bench_function("fixed_buffer", |bench| {
        bench.iter(|| {
            let result = gzip_sha256(black_box(&input));
            assert!(matches!(&result, Ok(stats) if !stats.gzip.is_empty()));
            black_box(result)
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    targets = kernels, components
}
criterion_main!(benches);
