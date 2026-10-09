//! Differential tests and a deterministic per-query coefficient-copy gate.
use ark_std::{rand::SeedableRng, UniformRand};
use banderwagon::{trait_defs::*, Element, Fr};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::{LagrangeBasis, PrecomputedWeights},
    multiproof::{
        MultiPoint, MultiPointProof, ProverQuery, ProverQueryRef, QueryCommitment, VerifierQuery,
    },
    transcript::{Transcript, TranscriptProtocol},
};
use rand_chacha::ChaCha20Rng;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

struct CountingAllocator;
thread_local! {
    static COUNT: Cell<bool> = const { Cell::new(false) };
    static POLY_ALLOCS: Cell<usize> = const { Cell::new(0) };
    static QUERY_SCALAR_ALLOCS: Cell<usize> = const { Cell::new(0) };
    static QUERY_POINT_ALLOCS: Cell<usize> = const { Cell::new(0) };
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNT.with(|active| {
            if active.get() && layout.size() == 8192 {
                POLY_ALLOCS.with(|n| n.set(n.get() + 1));
            }
        });
        COUNT.with(|active| {
            if active.get() && layout.size() == 1024 * std::mem::size_of::<Element>() {
                QUERY_POINT_ALLOCS.with(|n| n.set(n.get() + 1));
            }
        });
        COUNT.with(|active| {
            if active.get() && layout.size() == 1024 * std::mem::size_of::<Fr>() {
                QUERY_SCALAR_ALLOCS.with(|n| n.set(n.get() + 1));
            }
        });
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        COUNT.with(|active| {
            if active.get() && size == 8192 {
                POLY_ALLOCS.with(|n| n.set(n.get() + 1));
            }
        });
        COUNT.with(|active| {
            if active.get() && size == 1024 * std::mem::size_of::<Element>() {
                QUERY_POINT_ALLOCS.with(|n| n.set(n.get() + 1));
            }
        });
        COUNT.with(|active| {
            if active.get() && size == 1024 * std::mem::size_of::<Fr>() {
                QUERY_SCALAR_ALLOCS.with(|n| n.set(n.get() + 1));
            }
        });
        System.realloc(ptr, layout, size)
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn query_point_counter_counts_vec_reallocation() {
    let mut points = Vec::<Element>::with_capacity(512);
    let original_capacity = points.capacity();
    QUERY_POINT_ALLOCS.with(|n| n.set(0));
    COUNT.with(|active| active.set(true));
    // Vec grows an existing allocation to the forbidden query-sized buffer.
    points.reserve_exact(1024);
    COUNT.with(|active| active.set(false));
    assert_eq!(original_capacity, 512);
    assert_eq!(points.capacity(), 1024);
    let allocations = QUERY_POINT_ALLOCS.with(Cell::get);
    assert_eq!(
        allocations, 1,
        "query-sized Vec reallocation must be counted"
    );
    // Use the reserved buffer so the optimizer cannot remove its allocation.
    points.push(Element::zero());
    assert_eq!(points[0], Element::zero());
}

#[derive(Clone, Copy)]
struct BorrowedQuery<'a> {
    commitment: &'a QueryCommitment,
    poly: &'a LagrangeBasis,
    point: usize,
    result: Fr,
}
fn owned(q: BorrowedQuery<'_>) -> ProverQuery {
    ProverQuery {
        commitment: *q.commitment.element(),
        poly: q.poly.clone(),
        point: q.point,
        result: q.result,
    }
}
fn verifier(q: BorrowedQuery<'_>) -> VerifierQuery {
    VerifierQuery {
        commitment: *q.commitment.element(),
        point: Fr::from(q.point as u128),
        result: q.result,
    }
}
fn candidate_open(
    crs: CRS,
    weights: &PrecomputedWeights,
    transcript: &mut Transcript,
    queries: &[BorrowedQuery<'_>],
) -> MultiPointProof {
    MultiPoint::open_streaming(
        crs,
        weights,
        transcript,
        queries.iter().map(|q| ProverQueryRef {
            commitment: q.commitment,
            poly: q.poly,
            point: q.point,
            result: q.result,
        }),
    )
    .unwrap()
}
fn fixtures() -> (
    CRS,
    PrecomputedWeights,
    Vec<LagrangeBasis>,
    Vec<QueryCommitment>,
) {
    let crs = CRS::new(256, b"streaming differential fixtures");
    let weights = PrecomputedWeights::new(256);
    let mut rng = ChaCha20Rng::from_seed([29; 32]);
    let polynomials = vec![
        LagrangeBasis::new((0..256).map(|_| Fr::rand(&mut rng)).collect()),
        LagrangeBasis::new(
            (0..256)
                .map(|i| {
                    if i % 71 == 0 {
                        Fr::rand(&mut rng)
                    } else {
                        Fr::zero()
                    }
                })
                .collect(),
        ),
        LagrangeBasis::new(vec![Fr::zero(); 256]),
    ];
    let commitments = polynomials
        .iter()
        .map(|p| QueryCommitment::new(crs.commit_lagrange_poly(p)))
        .collect();
    (crs, weights, polynomials, commitments)
}
fn queries<'a>(
    commitments: &'a [QueryCommitment],
    polys: &'a [LagrangeBasis],
    layout: &[(usize, usize)],
) -> Vec<BorrowedQuery<'a>> {
    layout
        .iter()
        .map(|&(id, point)| BorrowedQuery {
            commitment: &commitments[id],
            poly: &polys[id],
            point,
            result: polys[id].evaluate_in_domain(point),
        })
        .collect()
}
#[test]
fn owned_streamed_bytes_transcript_and_cross_verification() {
    let (crs, weights, polys, commitments) = fixtures();
    let cases = vec![
        vec![(0, 0)],
        vec![(1, 71)],
        vec![(2, 4)],
        vec![(0, 9), (1, 71), (0, 9), (0, 11), (1, 71)],
        (0..256).map(|point| (point % 3, point)).collect(),
    ];
    for layout in cases {
        let qs = queries(&commitments, &polys, &layout);
        let mut reference_transcript = Transcript::new(b"streaming test");
        let reference = MultiPoint::open(
            crs.clone(),
            &weights,
            &mut reference_transcript,
            qs.iter().copied().map(owned).collect(),
        );
        let mut streamed_transcript = Transcript::new(b"streaming test");
        let streamed = candidate_open(crs.clone(), &weights, &mut streamed_transcript, &qs);
        assert_eq!(
            reference.to_bytes().unwrap(),
            streamed.to_bytes().unwrap(),
            "layout {layout:?}"
        );
        assert_eq!(
            reference.to_bytes_uncompressed().unwrap(),
            streamed.to_bytes_uncompressed().unwrap()
        );
        let reference_challenge = reference_transcript.challenge_scalar(b"after");
        assert_eq!(
            reference_challenge,
            streamed_transcript.challenge_scalar(b"after")
        );
        let vqs: Vec<_> = qs.iter().copied().map(verifier).collect();
        for proof in [&reference, &streamed] {
            let mut transcript = Transcript::new(b"streaming test");
            assert!(proof.check(&crs, &weights, &vqs, &mut transcript));
            assert_eq!(reference_challenge, transcript.challenge_scalar(b"after"));
            let mut transcript = Transcript::new(b"streaming test");
            assert!(candidate_check(
                proof,
                &crs,
                &weights,
                &vqs,
                &mut transcript
            ));
            assert_eq!(reference_challenge, transcript.challenge_scalar(b"after"));
        }
    }
}
#[test]
fn altered_statements_order_and_proof_are_rejected() {
    let (crs, weights, polys, commitments) = fixtures();
    let qs = queries(&commitments, &polys, &[(0, 8), (1, 71), (0, 19), (1, 142)]);
    let proof = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"streaming test"),
        &qs,
    );
    for alteration in 0..4 {
        let mut vqs: Vec<_> = qs.iter().copied().map(verifier).collect();
        match alteration {
            0 => vqs[0].result += Fr::one(),
            1 => vqs[0].commitment = *qs[1].commitment.element(),
            2 => vqs[0].point += Fr::one(),
            _ => vqs.swap(0, 1),
        }
        let mut reference = Transcript::new(b"streaming test");
        let mut grouped = Transcript::new(b"streaming test");
        let expected = proof.check(&crs, &weights, &vqs, &mut reference);
        assert!(!expected);
        assert_eq!(
            expected,
            candidate_check(&proof, &crs, &weights, &vqs, &mut grouped)
        );
        assert_eq!(
            reference.challenge_scalar(b"after"),
            grouped.challenge_scalar(b"after")
        );
    }
    let mut altered = proof.clone();
    altered.open_proof.a += Fr::one();
    let bytes = altered.to_bytes().unwrap();
    assert_ne!(bytes, proof.to_bytes().unwrap());
    let altered = MultiPointProof::from_bytes(&bytes, crs.n)
        .expect("altered canonical scalar must deserialize");
    let vqs: Vec<_> = qs.iter().copied().map(verifier).collect();
    let mut reference = Transcript::new(b"streaming test");
    let mut grouped = Transcript::new(b"streaming test");
    assert!(!altered.check(&crs, &weights, &vqs, &mut reference));
    assert!(!candidate_check(
        &altered,
        &crs,
        &weights,
        &vqs,
        &mut grouped
    ));
    assert_eq!(
        reference.challenge_scalar(b"after"),
        grouped.challenge_scalar(b"after")
    );
}
#[test]
fn repeated_queries_do_not_allocate_one_polynomial_each() {
    let (crs, weights, polys, commitments) = fixtures();
    let qs = queries(&commitments, &polys, &vec![(0, 7); 1024]);
    // Warm Rayon and all setup outside the measured calling-thread interval.
    let _ = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"warmup"),
        &qs[..1],
    );
    POLY_ALLOCS.with(|n| n.set(0));
    COUNT.with(|active| active.set(true));
    let proof = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"streaming test"),
        &qs,
    );
    COUNT.with(|active| active.set(false));
    let allocations = POLY_ALLOCS.with(Cell::get);
    eprintln!("measured coefficient-buffer allocations: {allocations}");
    assert!(allocations < 32, "one-point streaming should allocate fewer than 32 coefficient buffers, observed {allocations}");
    let vqs: Vec<_> = qs.iter().copied().map(verifier).collect();
    assert!(proof.check(
        &crs,
        &weights,
        &vqs,
        &mut Transcript::new(b"streaming test")
    ));
}

#[test]
fn checked_empty_queries_return_an_error() {
    let (crs, weights, _, _) = fixtures();
    assert_eq!(
        MultiPoint::open_streaming(
            crs,
            &weights,
            &mut Transcript::new(b"test"),
            std::iter::empty()
        ),
        Err(ipa_multipoint::ProofError::EmptyQueries)
    );
}

// The owned check remains the differential verifier oracle.
fn candidate_check(
    proof: &MultiPointProof,
    crs: &CRS,
    weights: &PrecomputedWeights,
    queries: &[VerifierQuery],
    transcript: &mut Transcript,
) -> bool {
    proof.check_grouped(crs, weights, queries, transcript)
}

#[test]
fn repeated_commitments_do_not_materialize_query_sized_msm_points() {
    let (crs, weights, polys, commitments) = fixtures();
    let qs = queries(&commitments, &polys, &vec![(0, 7); 1024]);
    let proof = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"streaming test"),
        &qs,
    );
    let vqs: Vec<_> = qs.iter().copied().map(verifier).collect();
    // IPA MSM grows a scratch allocation to the same byte size.
    // A one-query control with identical CRS/proof dimensions measures that
    // inherited cost, while extra query-sized point buffers must still fail.
    let control_proof = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"streaming test"),
        &qs[..1],
    );
    QUERY_POINT_ALLOCS.with(|n| n.set(0));
    COUNT.with(|active| active.set(true));
    let control_accepted = candidate_check(
        &control_proof,
        &crs,
        &weights,
        &vqs[..1],
        &mut Transcript::new(b"streaming test"),
    );
    COUNT.with(|active| active.set(false));
    assert!(control_accepted);
    let control_allocations = QUERY_POINT_ALLOCS.with(Cell::get);
    QUERY_POINT_ALLOCS.with(|n| n.set(0));
    COUNT.with(|active| active.set(true));
    let accepted = candidate_check(
        &proof,
        &crs,
        &weights,
        &vqs,
        &mut Transcript::new(b"streaming test"),
    );
    COUNT.with(|active| active.set(false));
    assert!(accepted);
    eprintln!(
        "measured query-sized commitment allocations: {}",
        QUERY_POINT_ALLOCS.with(Cell::get)
    );
    eprintln!("one-query IPA control allocations: {control_allocations}");
    assert_eq!(
        QUERY_POINT_ALLOCS.with(Cell::get),
        control_allocations,
        "grouped verifier must not add query-sized commitment buffers beyond the one-query IPA control"
    );
}

struct ChangedReplay<'a> {
    original: std::vec::IntoIter<ProverQueryRef<'a>>,
    cloned: Vec<ProverQueryRef<'a>>,
}
impl<'a> Clone for ChangedReplay<'a> {
    fn clone(&self) -> Self {
        Self {
            original: self.cloned.clone().into_iter(),
            cloned: self.cloned.clone(),
        }
    }
}
impl<'a> Iterator for ChangedReplay<'a> {
    type Item = ProverQueryRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.original.next()
    }
}
fn candidate_replay_open<'a>(
    crs: CRS,
    weights: &PrecomputedWeights,
    transcript: &mut Transcript,
    queries: ChangedReplay<'a>,
) -> Result<MultiPointProof, ipa_multipoint::multiproof::StreamingError> {
    MultiPoint::open_streaming(crs, weights, transcript, queries)
}
#[test]
fn changed_ordered_iterator_replay_is_rejected() {
    use ipa_multipoint::multiproof::StreamingError;
    let (crs, weights, polys, commitments) = fixtures();
    let qs = queries(&commitments, &polys, &[(0, 8), (1, 71), (0, 19)]);
    let refs: Vec<_> = qs
        .iter()
        .map(|q| ProverQueryRef {
            commitment: q.commitment,
            poly: q.poly,
            point: q.point,
            result: q.result,
        })
        .collect();
    for alteration in 0..6 {
        let mut changed = refs.clone();
        match alteration {
            0 => changed[0].result += Fr::one(),
            1 => changed[0].commitment = &commitments[1],
            2 => changed[0].point += 1,
            3 => changed.swap(0, 1),
            4 => {
                changed.pop();
            }
            _ => changed.push(refs[0]),
        }
        let replay = ChangedReplay {
            original: refs.clone().into_iter(),
            cloned: changed,
        };
        assert_eq!(
            candidate_replay_open(
                crs.clone(),
                &weights,
                &mut Transcript::new(b"streaming test"),
                replay
            ),
            Err(if alteration == 0 || alteration == 2 {
                StreamingError::InvalidQuery
            } else {
                StreamingError::ReplayMismatch
            }),
            "alteration {alteration}"
        );
    }
}

#[test]
fn invalid_streaming_domains_are_rejected() {
    use ipa_multipoint::multiproof::StreamingError;
    let (crs, weights, polys, commitments) = fixtures();
    let short = LagrangeBasis::new(vec![Fr::zero(); 255]);
    for (poly, point) in [(&polys[0], 256), (&short, 7)] {
        let query = ProverQueryRef {
            commitment: &commitments[0],
            poly,
            point,
            result: Fr::zero(),
        };
        assert_eq!(
            MultiPoint::open_streaming(
                crs.clone(),
                &weights,
                &mut Transcript::new(b"domain test"),
                std::iter::once(query)
            ),
            Err(StreamingError::InvalidDomain)
        );
    }
}

fn borrowed_verifier(q: BorrowedQuery<'_>) -> ipa_multipoint::multiproof::VerifierQueryRef<'_> {
    ipa_multipoint::multiproof::VerifierQueryRef {
        commitment: q.commitment,
        point: Fr::from(q.point as u128),
        result: q.result,
    }
}

#[test]
fn borrowed_grouped_verifier_matches_owned_for_valid_and_mutated_statements() {
    let (crs, weights, polys, commitments) = fixtures();
    for count in [1, 16, 256, 1024] {
        let layout: Vec<_> = (0..count).map(|i| (i % 3, i % 256)).collect();
        let qs = queries(&commitments, &polys, &layout);
        let mut pt = Transcript::new(b"borrowed");
        let proof = candidate_open(crs.clone(), &weights, &mut pt, &qs);
        for mutate in 0..4 {
            let mut vt = Transcript::new(b"borrowed");
            let mut ot = Transcript::new(b"borrowed");
            let mut owned: Vec<_> = qs.iter().copied().map(verifier).collect();
            let mut refs: Vec<_> = qs.iter().copied().map(borrowed_verifier).collect();
            match mutate {
                1 => {
                    owned[0].result += Fr::one();
                    refs[0].result += Fr::one();
                }
                2 => {
                    owned[0].commitment = *commitments[1].element();
                    refs[0].commitment = &commitments[1];
                }
                3 => {
                    owned[0].point = Fr::from(10001u64);
                    refs[0].point = Fr::from(10001u64);
                }
                _ => {}
            }
            let expected = proof.check(&crs, &weights, &owned, &mut ot);
            let actual = proof
                .check_grouped_streaming(&crs, &weights, refs.into_iter(), &mut vt)
                .unwrap();
            assert_eq!(expected, mutate == 0);
            assert_eq!(actual, expected);
            assert_eq!(ot.challenge_scalar(b"state"), vt.challenge_scalar(b"state"));
        }
    }
}

#[test]
fn all_proof_fields_are_bound_and_stale_commitments_fail() {
    let (crs, weights, polys, commitments) = fixtures();
    let qs = queries(&commitments, &polys, &[(0, 0), (1, 255), (2, 0)]);
    let proof = candidate_open(crs.clone(), &weights, &mut Transcript::new(b"fields"), &qs);
    let refs: Vec<_> = qs.iter().copied().map(borrowed_verifier).collect();
    for field in 0..18 {
        let mut bad = proof.clone();
        match field {
            0..=7 => bad.open_proof.L_vec[field] += crs.G[0],
            8..=15 => bad.open_proof.R_vec[field - 8] += crs.G[0],
            16 => bad.open_proof.a += Fr::one(),
            _ => bad.g_x_comm += crs.G[0],
        }
        assert_eq!(
            bad.check_grouped_streaming(
                &crs,
                &weights,
                refs.iter().copied(),
                &mut Transcript::new(b"fields")
            ),
            Ok(false)
        );
    }
    // An updated value and its freshly generated proof must fail against old C.
    let updated = LagrangeBasis::new(
        (0..256)
            .map(|i| polys[0].evaluate_in_domain(i) + Fr::one())
            .collect(),
    );
    let fresh = QueryCommitment::new(crs.commit_lagrange_poly(&updated));
    let changed = [BorrowedQuery {
        commitment: &fresh,
        poly: &updated,
        point: 0,
        result: updated.evaluate_in_domain(0),
    }];
    let proof = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"stale"),
        &changed,
    );
    let stale = [ipa_multipoint::multiproof::VerifierQueryRef {
        commitment: &commitments[0],
        point: Fr::zero(),
        result: updated.evaluate_in_domain(0),
    }];
    assert_eq!(
        proof.check_grouped_streaming(
            &crs,
            &weights,
            stale.into_iter(),
            &mut Transcript::new(b"stale")
        ),
        Ok(false)
    );
}

#[test]
fn prover_replay_binds_polynomial_identity_even_when_statement_matches() {
    let (crs, weights, polys, commitments) = fixtures();
    let mut replacement_values: Vec<_> = (0..256).map(|i| polys[0].evaluate_in_domain(i)).collect();
    replacement_values[1] += Fr::one();
    let replacement = LagrangeBasis::new(replacement_values);
    let q = ProverQueryRef {
        commitment: &commitments[0],
        poly: &polys[0],
        point: 0,
        result: polys[0].evaluate_in_domain(0),
    };
    let replay = ChangedReplay {
        original: vec![q].into_iter(),
        cloned: vec![ProverQueryRef {
            poly: &replacement,
            ..q
        }],
    };
    assert_eq!(
        MultiPoint::open_streaming(crs, &weights, &mut Transcript::new(b"identity"), replay),
        Err(ipa_multipoint::ProofError::ReplayMismatch)
    );
}

struct ChangedVerifierReplay<'a> {
    original: std::vec::IntoIter<ipa_multipoint::multiproof::VerifierQueryRef<'a>>,
    cloned: Vec<ipa_multipoint::multiproof::VerifierQueryRef<'a>>,
}
impl<'a> Clone for ChangedVerifierReplay<'a> {
    fn clone(&self) -> Self {
        Self {
            original: self.cloned.clone().into_iter(),
            cloned: self.cloned.clone(),
        }
    }
}
impl<'a> Iterator for ChangedVerifierReplay<'a> {
    type Item = ipa_multipoint::multiproof::VerifierQueryRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.original.next()
    }
}
#[test]
fn borrowed_verifier_checks_every_ordered_replay_field() {
    let (crs, weights, polys, commitments) = fixtures();
    let qs = queries(&commitments, &polys, &[(0, 0), (1, 255), (2, 1)]);
    let proof = candidate_open(crs.clone(), &weights, &mut Transcript::new(b"replay"), &qs);
    let refs: Vec<_> = qs.iter().copied().map(borrowed_verifier).collect();
    for alteration in 0..6 {
        let mut changed = refs.clone();
        match alteration {
            0 => changed[0].result += Fr::one(),
            1 => changed[0].commitment = &commitments[1],
            2 => changed[0].point += Fr::one(),
            3 => changed.swap(0, 1),
            4 => {
                changed.pop();
            }
            _ => changed.push(refs[0]),
        }
        let iter = ChangedVerifierReplay {
            original: refs.clone().into_iter(),
            cloned: changed,
        };
        assert_eq!(
            proof.check_grouped_streaming(&crs, &weights, iter, &mut Transcript::new(b"replay")),
            Err(ipa_multipoint::ProofError::ReplayMismatch)
        );
    }
}

#[test]
fn borrowed_verifier_allocations_do_not_grow_with_repeated_queries() {
    let (crs, weights, polys, commitments) = fixtures();
    let mut counts = Vec::new();
    for count in [1, 1024, 2048] {
        let qs = queries(&commitments, &polys, &vec![(0, 7); count]);
        let proof = candidate_open(crs.clone(), &weights, &mut Transcript::new(b"memory"), &qs);
        QUERY_SCALAR_ALLOCS.with(|n| n.set(0));
        QUERY_POINT_ALLOCS.with(|n| n.set(0));
        COUNT.with(|active| active.set(true));
        let result = proof.check_grouped_streaming(
            &crs,
            &weights,
            qs.iter().copied().map(borrowed_verifier),
            &mut Transcript::new(b"memory"),
        );
        COUNT.with(|active| active.set(false));
        assert_eq!(result, Ok(true));
        counts.push((
            QUERY_SCALAR_ALLOCS.with(Cell::get),
            QUERY_POINT_ALLOCS.with(Cell::get),
        ));
    }
    // Arkworks MSM has a fixed-size allocation that happens to match 1024 Fr
    // (32KiB). Comparing different Q separates that collision from Q-sized work.
    assert_eq!(counts[0], counts[1]);
    assert_eq!(counts[0], counts[2]);
    QUERY_SCALAR_ALLOCS.with(|n| n.set(0));
    COUNT.with(|active| active.set(true));
    let control = vec![Fr::zero(); 1024];
    std::hint::black_box(&control);
    COUNT.with(|active| active.set(false));
    assert_eq!(
        QUERY_SCALAR_ALLOCS.with(Cell::get),
        1,
        "negative control must detect a query-sized Fr buffer"
    );
}

#[test]
fn grouping_uses_the_entire_canonical_commitment_key() {
    // Find real valid points with a shared first byte, rather than forging a
    // QueryCommitment cache whose private invariant the public API enforces.
    let (crs, weights, _, _) = fixtures();
    let mut seen = std::collections::HashMap::new();
    let (a, b) = (1..=512u64)
        .find_map(|i| {
            let bytes = (crs.G[0] * Fr::from(i)).to_bytes();
            seen.insert(bytes[0], i).map(|j| (j, i))
        })
        .unwrap();
    let polys: Vec<_> = [a, b]
        .iter()
        .map(|i| {
            let mut values = vec![Fr::zero(); 256];
            values[0] = Fr::from(*i);
            LagrangeBasis::new(values)
        })
        .collect();
    let commitments: Vec<_> = polys
        .iter()
        .map(|p| QueryCommitment::new(crs.commit_lagrange_poly(p)))
        .collect();
    assert_eq!(
        commitments[0].element().to_bytes()[0],
        commitments[1].element().to_bytes()[0]
    );
    assert_ne!(
        commitments[0].element().to_bytes(),
        commitments[1].element().to_bytes()
    );
    let qs = queries(&commitments, &polys, &[(0, 0), (1, 0), (0, 255), (1, 255)]);
    let proof = candidate_open(
        crs.clone(),
        &weights,
        &mut Transcript::new(b"full-key"),
        &qs,
    );
    assert_eq!(
        proof.check_grouped_streaming(
            &crs,
            &weights,
            qs.iter().copied().map(borrowed_verifier),
            &mut Transcript::new(b"full-key")
        ),
        Ok(true)
    );
}
