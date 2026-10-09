//! Matched deterministic benchmark. No application fixture or chain timing claim.
#![allow(unexpected_cfgs)]
use banderwagon::{trait_defs::*, Fr};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::{LagrangeBasis, PrecomputedWeights},
    multiproof::*,
    transcript::Transcript,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    time::Instant,
};
struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
fn account(n: usize) {
    COUNT.fetch_add(1, Relaxed);
    BYTES.fetch_add(n, Relaxed);
    let live = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(live, Relaxed);
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            account(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            account(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            LIVE.fetch_sub(l.size(), Relaxed);
            account(n);
        }
        q
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;
#[repr(C)]
struct Timespec {
    sec: i64,
    ns: i64,
}
extern "C" {
    fn clock_gettime(clock: i32, ts: *mut Timespec) -> i32;
}
fn cpu(thread: bool) -> u128 {
    #[cfg(target_os = "macos")]
    let id = if thread { 16 } else { 12 };
    #[cfg(not(target_os = "macos"))]
    let id = if thread { 3 } else { 2 };
    let mut ts = Timespec { sec: 0, ns: 0 };
    if unsafe { clock_gettime(id, &mut ts) } != 0 {
        return 0;
    }
    ts.sec as u128 * 1_000_000_000 + ts.ns as u128
}
fn measure<T>(case: &str, operation: &str, f: impl FnOnce() -> T) -> T {
    let count = COUNT.load(Relaxed);
    let bytes = BYTES.load(Relaxed);
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let pc = cpu(false);
    let tc = cpu(true);
    let start = Instant::now();
    let value = f();
    let wall = start.elapsed().as_nanos();
    let thread = cpu(true) - tc;
    let process = cpu(false) - pc;
    let allocations = COUNT.load(Relaxed) - count;
    let allocated = BYTES.load(Relaxed) - bytes;
    let peak = PEAK.load(Relaxed).saturating_sub(base);
    println!("{{\"case\":\"{case}\",\"operation\":\"{operation}\",\"wall_ns\":{wall},\"process_cpu_ns\":{process},\"thread_cpu_ns\":{thread},\"allocations\":{allocations},\"allocated_bytes\":{allocated},\"peak_extra_heap_bytes\":{peak}}}");
    value
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args[1].parse().unwrap();
    let shape = &args[2];
    let api = &args[3];
    let case = format!("{count}:{shape}:{api}");
    let n = 256;
    let (crs, weights) = measure(&case, "cold_setup", || {
        (
            CRS::new(n, b"matched-performance-v1"),
            PrecomputedWeights::new(n),
        )
    });
    // Keep this example compatible with Rust 1.70; usize::div_ceil needs 1.73.
    #[allow(clippy::manual_div_ceil)]
    let num_polys = match shape.as_str() {
        "repeat" | "identity" => 1,
        "synthetic90" => 90,
        _ => (count + n - 1) / n,
    };
    let (polys, comms) = measure(&case, "fixture_setup", || {
        let polys: Vec<_> = (0..num_polys)
            .map(|p| {
                LagrangeBasis::new(
                    (0..n)
                        .map(|i| {
                            if shape == "identity" || (shape == "sparse" && i != p % n) {
                                Fr::zero()
                            } else {
                                Fr::from(((p + 1) * 65537 + i + 1) as u128)
                            }
                        })
                        .collect(),
                )
            })
            .collect();
        let comms: Vec<_> = polys.iter().map(|p| crs.commit_lagrange_poly(p)).collect();
        (polys, comms)
    });
    let index = |i: usize| {
        if shape == "repeat" || shape == "identity" {
            (0, 0)
        } else if shape == "synthetic90" {
            (i % 90, (i / 90) % n)
        } else {
            (i / n, i % n)
        }
    };
    let owned = || {
        (0..count)
            .map(|i| {
                let (p, z) = index(i);
                ProverQuery {
                    commitment: comms[p],
                    poly: polys[p].clone(),
                    point: z,
                    result: polys[p].evaluate_in_domain(z),
                }
            })
            .collect::<Vec<_>>()
    };
    let verifier: Vec<_> = (0..count)
        .map(|i| {
            let (p, z) = index(i);
            VerifierQuery {
                commitment: comms[p],
                point: Fr::from(z as u128),
                result: polys[p].evaluate_in_domain(z),
            }
        })
        .collect();
    let proof = if api == "owned" {
        let queries = measure(&case, "owned_conversion", owned);
        measure(&case, "prove_kernel", || {
            MultiPoint::open(
                crs.clone(),
                &weights,
                &mut Transcript::new(b"matched-v1"),
                queries,
            )
        })
    } else {
        #[cfg(bench_streaming)]
        {
            let commitments: Vec<_> = comms.iter().map(|c| QueryCommitment::new(*c)).collect();
            measure(&case, "prove_kernel", || {
                MultiPoint::open_streaming(
                    crs.clone(),
                    &weights,
                    &mut Transcript::new(b"matched-v1"),
                    (0..count).map(|i| {
                        let (p, z) = index(i);
                        ProverQueryRef {
                            commitment: &commitments[p],
                            poly: &polys[p],
                            point: z,
                            result: polys[p].evaluate_in_domain(z),
                        }
                    }),
                )
                .unwrap()
            })
        }
        #[cfg(not(bench_streaming))]
        panic!("streaming unavailable")
    };
    let ok = measure(&case, "verify_kernel", || {
        #[cfg(bench_streaming)]
        if api != "owned" {
            return proof.check_grouped(
                &crs,
                &weights,
                &verifier,
                &mut Transcript::new(b"matched-v1"),
            );
        }
        proof.check(
            &crs,
            &weights,
            &verifier,
            &mut Transcript::new(b"matched-v1"),
        )
    });
    assert!(ok);
    #[cfg(bench_borrowed)]
    {
        let commitments: Vec<_> = comms.iter().map(|c| QueryCommitment::new(*c)).collect();
        let ok = measure(&case, "verify_borrowed_kernel", || {
            proof
                .check_grouped_streaming(
                    &crs,
                    &weights,
                    (0..count).map(|i| {
                        let (p, z) = index(i);
                        VerifierQueryRef {
                            commitment: &commitments[p],
                            point: Fr::from(z as u128),
                            result: polys[p].evaluate_in_domain(z),
                        }
                    }),
                    &mut Transcript::new(b"matched-v1"),
                )
                .unwrap()
        });
        assert!(ok);
    }
    let _ = measure(&case, "owned_witness_end_to_end", || {
        let queries = owned();
        let proof = MultiPoint::open(
            crs.clone(),
            &weights,
            &mut Transcript::new(b"matched-v1"),
            queries,
        );
        assert!(proof.check(
            &crs,
            &weights,
            &verifier,
            &mut Transcript::new(b"matched-v1")
        ));
        proof
    });
    #[cfg(bench_streaming)]
    if api != "owned" {
        let _ = measure(&case, "streaming_witness_end_to_end", || {
            let commitments: Vec<_> = comms.iter().map(|c| QueryCommitment::new(*c)).collect();
            let proof = MultiPoint::open_streaming(
                crs.clone(),
                &weights,
                &mut Transcript::new(b"matched-v1"),
                (0..count).map(|i| {
                    let (p, z) = index(i);
                    ProverQueryRef {
                        commitment: &commitments[p],
                        poly: &polys[p],
                        point: z,
                        result: polys[p].evaluate_in_domain(z),
                    }
                }),
            )
            .unwrap();
            assert!(proof.check_grouped(
                &crs,
                &weights,
                &verifier,
                &mut Transcript::new(b"matched-v1")
            ));
            proof
        });
    }
}
