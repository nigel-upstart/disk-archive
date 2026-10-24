//! Callgrind microbenchmarks: real core, full scanner, pinned gzip/hash primitives.
// LINT-JUSTIFICATION: Gungraun 0.20 emits undocumented public harness modules/constants/functions; this private benchmark-only wrapper is not a runtime API.
#[allow(missing_docs)]
mod generated {
    use std::hint::black_box;

    use disk_archive_benchmarks::{
        components::{ScannerFixture, buffer, gzip_sha256},
        record, redact,
    };
    use disk_archive_scanner::ScanError;
    use gungraun::{Callgrind, prelude::*};
    use zeroize::Zeroizing;

    fn setup() -> Zeroizing<Vec<u8>> {
        let input = record(100 * 1024);
        assert!(input.is_ok(), "synthetic fixture must fit fixed budget");
        input.unwrap_or_default()
    }

    #[library_benchmark]
    #[bench::practical_record(setup())]
    fn core_needle_build_and_rewrite(input: Zeroizing<Vec<u8>>) {
        let result = redact(black_box(&input));
        assert!(matches!(result, Ok(stats) if stats.replacements == 1));
    }

    #[library_benchmark]
    #[bench::fixed_buffer(ScannerFixture::new())]
    fn scanner_fixed_buffer(
        fixture: Result<ScannerFixture, ScanError>,
    ) -> Result<ScannerFixture, ScanError> {
        let result = fixture.as_ref().map(ScannerFixture::scan);
        assert!(matches!(result, Ok(Ok(summary)) if summary.findings > 0));
        // Return ownership so native catalog teardown is outside the scan region.
        fixture
    }

    #[library_benchmark]
    #[bench::fixed_buffer(buffer())]
    fn gzip_sha256_fixed_buffer(input: Zeroizing<Vec<u8>>) {
        let result = gzip_sha256(black_box(&input));
        assert!(matches!(&result, Ok(stats) if !stats.gzip.is_empty()));
        drop(black_box(result));
    }

    library_benchmark_group!(
        name = actual_components;
        benchmarks = core_needle_build_and_rewrite, scanner_fixed_buffer, gzip_sha256_fixed_buffer
    );

    main!(
        config = LibraryBenchmarkConfig::default()
            .tool(Callgrind::with_args([
                "--cache-sim=yes",
                "--I1=32768,8,64",
                "--D1=32768,8,64",
                "--LL=8388608,16,64",
                "--separate-threads=no",
            ]));
        library_benchmark_groups = actual_components
    );

    pub(super) fn run() {
        main();
    }
}

fn main() {
    generated::run();
}
