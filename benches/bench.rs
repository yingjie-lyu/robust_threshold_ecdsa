use criterion::{black_box, criterion_group, criterion_main, Criterion};
use robust_threshold_ecdsa::cdn;
use robust_threshold_ecdsa::wmc24;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Threshold ECDSA");
    group
        .sample_size(10)
        .sampling_mode(criterion::SamplingMode::Auto); // for slow benchmarks

    let rt = tokio::runtime::Runtime::new().unwrap();

    let n = 3;
    let t = 2;

    // group.bench_function("Benchmarking CDN", |b| {
    //     b.iter(|| {
    //         rt.block_on(async {
    //             cdn::simulate_cdn_signing(n, t).await;
    //         });
    //     })
    // });

    group.bench_function("Benchmarking WMC24", |b| {
        b.iter(|| {
            wmc24::WMC24::sign(n, t);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
