# IPA performance measurement

`ipa-multipoint/examples/performance.rs` measures owned, streaming and borrowed
APIs using deterministic query data. The harness reports cold CRS/table setup,
fixture setup, query conversion, proof creation, verification and end-to-end
operations separately.

## Running the harness

```sh
ipa_bench_target_dir="${CARGO_TARGET_DIR:-target}"
RUSTFLAGS='--cfg bench_streaming --cfg bench_borrowed' \
  RUSTC_WRAPPER='' RAYON_NUM_THREADS=1 cargo build --locked --release \
  --target-dir "$ipa_bench_target_dir" -p ipa-multipoint --example performance \
  --config profile.release.opt-level=3 \
  --config profile.release.debug=true \
  --config profile.release.debug-assertions=true \
  --config profile.release.incremental=false

RAYON_NUM_THREADS=1 "$ipa_bench_target_dir/release/examples/performance" 16000 dense owned
RAYON_NUM_THREADS=1 "$ipa_bench_target_dir/release/examples/performance" 16000 dense streaming
```

Use `cargo generate-lockfile` if the checkout has no lockfile. The arguments are
query count, shape (`repeat`, `dense`, `sparse`, `identity`, `synthetic90`) and API
(`owned`, `streaming`). Use `15474 synthetic90` for the synthetic 90-commitment
workload. Each process emits JSONL measurements. Synthetic inputs do not establish
application witness costs or chain throughput.

## Comparable measurements

Use identical harness code, dependency locks, release settings, query data and
thread counts for each implementation. The `bench_streaming` and `bench_borrowed`
configuration flags enable calls to those APIs; omit a flag when the compared
implementation lacks that API. Preserve the exact source, executable and
lockfile digests with the results.

Run balanced variant orders on a quiet host and record system load. Collect at
least ten observations per case. Compare interpolated p50/p95/p99 and paired
bootstrap intervals for median ratios. A regression bound of 5% is supported only
when the upper 95% interval is at most 1.05. Intervals spanning the bound are
inconclusive, and small samples provide weak tail estimates.

Cases should include small and large query counts, repeated and distinct pairs,
dense and sparse coefficients, and identity commitments. Cold and warm query
conversion are separate workloads. The [conversion harness](owned-conversion-control.rs)
measures 100 warm clone/drop operations after 100 warmup operations; divide its
`owned_conversion_warm100` totals by 100 for per-operation costs.

## Metric boundaries

Proof kernels exclude owned polynomial conversion. End-to-end operations include
conversion, proving and checking. Wall time, process CPU, calling-thread CPU,
allocation calls, requested bytes and additional peak live heap are distinct
measurements. The allocator uses atomics, so timings include instrumentation.

Capture maximum resident memory separately, for example with `/usr/bin/time -l`
on macOS. Process RSS combines all operations within that process and cannot be
assigned to one API. Default-feature results do not establish performance for a
different dependency lock, feature set, architecture or application workload.
