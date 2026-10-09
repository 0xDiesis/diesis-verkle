//! Borrowed multiproof aggregation with the owned entry points kept as oracles.
#![allow(non_snake_case)]
use crate::{
    crs::CRS,
    ipa::slow_vartime_multiscalar_mul,
    lagrange_basis::{LagrangeBasis, PrecomputedWeights},
    multiproof::{MultiPoint, MultiPointProof, VerifierQuery},
    transcript::{Transcript, TranscriptProtocol},
};
use banderwagon::{trait_defs::*, Element, Fr};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// An immutable commitment and its canonical upstream transcript encoding.
/// Construct once per shared commitment, then borrow it for each opening.
#[derive(Clone, Debug)]
pub struct QueryCommitment {
    element: Element,
    bytes: [u8; 32],
}
impl QueryCommitment {
    pub fn new(element: Element) -> Self {
        let mut bytes = [0; 32];
        element.serialize_compressed(&mut bytes[..]).unwrap();
        Self { element, bytes }
    }
    /// Decode untrusted compressed input into a cache whose bytes cannot drift.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::ProofError> {
        Element::from_bytes(bytes)
            .map(Self::new)
            .ok_or(crate::ProofError::InvalidQuery)
    }
    pub fn element(&self) -> &Element {
        &self.element
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProverQueryRef<'a> {
    pub commitment: &'a QueryCommitment,
    pub poly: &'a LagrangeBasis,
    pub point: usize,
    pub result: Fr,
}

pub type StreamingError = crate::ProofError;

#[derive(Clone, Copy, Debug)]
pub struct VerifierQueryRef<'a> {
    pub commitment: &'a QueryCommitment,
    pub point: Fr,
    pub result: Fr,
}

fn statement_digest(digest: &mut Sha256, query: ProverQueryRef<'_>) {
    digest.update((query.poly as *const LagrangeBasis as usize).to_le_bytes());
    digest.update(query.commitment.bytes);
    let mut bytes = [0; 32];
    Fr::from(query.point as u128)
        .serialize_compressed(&mut bytes[..])
        .unwrap();
    digest.update(bytes);
    query.result.serialize_compressed(&mut bytes[..]).unwrap();
    digest.update(bytes);
}

impl MultiPoint {
    /// Absorb statements in caller order, then replay and aggregate by point.
    /// No owned query polynomials or query-sized challenge array are retained.
    /// The separate replay digest is never added to the proof transcript.
    ///
    /// The iterator must yield the same ordered statements on both traversals.
    /// The caller must supply the polynomial matching each commitment/result.
    /// On error the transcript must be discarded. Empty input is an error.
    /// CRS point validity must be established once with `CRS::validate` when
    /// loading untrusted parameters. The standard CRS is already trusted.
    pub fn open_streaming<'a, I>(
        crs: CRS,
        precomp: &PrecomputedWeights,
        transcript: &mut Transcript,
        queries: I,
    ) -> Result<MultiPointProof, StreamingError>
    where
        I: Iterator<Item = ProverQueryRef<'a>> + Clone,
    {
        if !crs.n.is_power_of_two() || crs.G.len() != crs.n || !precomp.matches_domain(crs.n) {
            return Err(StreamingError::InvalidDomain);
        }
        transcript.domain_sep(b"multiproof");
        let mut count = 0;
        let mut first = Sha256::new();
        for query in queries.clone() {
            if query.point >= crs.n || query.poly.values().len() != crs.n {
                return Err(StreamingError::InvalidDomain);
            }
            if query.result != query.poly.evaluate_in_domain(query.point) {
                return Err(StreamingError::InvalidQuery);
            }
            count += 1;
            transcript.append_point_bytes(b"C", &query.commitment.bytes);
            transcript.append_scalar(b"z", &Fr::from(query.point as u128));
            transcript.append_scalar(b"y", &query.result);
            statement_digest(&mut first, query);
        }
        if count == 0 {
            return Err(StreamingError::EmptyQueries);
        }
        let r = transcript.challenge_scalar(b"r");
        let mut r_i = Fr::one();
        let mut replay = Sha256::new();
        // Coalesce weights by immutable polynomial identity and point before
        // touching coefficients. A claimed commitment alone is not a safe key.
        let mut pairs: HashMap<(usize, usize), (&LagrangeBasis, Fr)> = HashMap::new();
        for query in queries {
            if query.point >= crs.n || query.poly.values().len() != crs.n {
                return Err(StreamingError::InvalidDomain);
            }
            if query.result != query.poly.evaluate_in_domain(query.point) {
                return Err(StreamingError::InvalidQuery);
            }
            statement_digest(&mut replay, query);
            let entry = pairs
                .entry((query.poly as *const LagrangeBasis as usize, query.point))
                .or_insert((query.poly, Fr::zero()));
            entry.1 += r_i;
            r_i *= r;
        }
        if first.finalize() != replay.finalize() {
            return Err(StreamingError::ReplayMismatch);
        }
        let mut buckets = BTreeMap::new();
        for ((_, point), (poly, weight)) in pairs {
            let polynomial = buckets
                .entry(point)
                .or_insert_with(|| vec![Fr::zero(); crs.n]);
            for (sum, value) in polynomial.iter_mut().zip(poly.values()) {
                *sum += *value * weight;
            }
        }
        let aggregated: Vec<_> = buckets
            .into_iter()
            .map(|(point, values)| (point, LagrangeBasis::new(values)))
            .collect();
        // Retain the reference division, commitment and IPA arithmetic.
        let g_x = aggregated
            .iter()
            .map(|(point, poly)| poly.divide_by_linear_vanishing(precomp, *point))
            .fold(LagrangeBasis::zero(), |sum, term| sum + term);
        let g_x_comm = crs.commit_lagrange_poly(&g_x);
        transcript.append_point(b"D", &g_x_comm);
        let t = transcript.challenge_scalar(b"t");
        if precomp.contains_point(t) {
            return Err(StreamingError::DegenerateChallenge);
        }
        let mut denominators: Vec<_> = aggregated
            .iter()
            .map(|(point, _)| t - Fr::from(*point as u128))
            .collect();
        batch_inversion(&mut denominators);
        let g1_x = aggregated
            .into_iter()
            .zip(denominators)
            .map(|((_, poly), inverse)| {
                LagrangeBasis::new(poly.values().iter().map(|value| inverse * value).collect())
            })
            .fold(LagrangeBasis::zero(), |sum, term| sum + term);
        let g1_comm = crs.commit_lagrange_poly(&g1_x);
        transcript.append_point(b"E", &g1_comm);
        let g3_x = &g1_x - &g_x;
        let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, crs.n, t);
        let open_proof = crate::ipa::try_create(
            transcript,
            crs,
            g3_x.values().to_vec(),
            g1_comm - g_x_comm,
            b,
            t,
        )?;
        Ok(MultiPointProof {
            open_proof,
            g_x_comm,
        })
    }
}

impl MultiPointProof {
    /// Verify with one MSM point per canonical commitment, preserving the
    /// ordered statement transcript and the reference g2 evaluation.
    pub fn check_grouped(
        &self,
        crs: &CRS,
        precomp: &PrecomputedWeights,
        queries: &[VerifierQuery],
        transcript: &mut Transcript,
    ) -> bool {
        if queries.is_empty()
            || !precomp.matches_domain(crs.n)
            || !self.open_proof.valid_shape(crs, crs.n)
        {
            return false;
        }
        transcript.domain_sep(b"multiproof");
        let (indices, commitments) = absorb_grouped_queries(queries, transcript);
        let r = transcript.challenge_scalar(b"r");
        transcript.append_point(b"D", &self.g_x_comm);
        let t = transcript.challenge_scalar(b"t");
        if precomp.contains_point(t) || queries.iter().any(|q| q.point == t) {
            return false;
        }
        let mut denominators: Vec<_> = queries.iter().map(|q| t - q.point).collect();
        batch_inversion(&mut denominators);
        let (g1_comm, g2_t) = grouped_evaluation(queries, denominators, indices, &commitments, r);
        transcript.append_point(b"E", &g1_comm);
        let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, crs.n, t);
        self.open_proof
            .verify_multiexp(transcript, crs, b, g1_comm - self.g_x_comm, t, g2_t)
    }
    /// Two ordered passes, one MSM point per full canonical commitment and
    /// one inversion per distinct evaluation point. Memory is O(U + V + n),
    /// where U and V count distinct commitments and points; V may equal Q
    /// for the generic Fr API. Errors consume transcript state.
    pub fn check_grouped_streaming<'a, I>(
        &self,
        crs: &CRS,
        precomp: &PrecomputedWeights,
        queries: I,
        transcript: &mut Transcript,
    ) -> Result<bool, StreamingError>
    where
        I: Iterator<Item = VerifierQueryRef<'a>> + Clone,
    {
        if !precomp.matches_domain(crs.n) || !self.open_proof.valid_shape(crs, crs.n) {
            return Err(StreamingError::InvalidDomain);
        }
        transcript.domain_sep(b"multiproof");
        let mut first = Sha256::new();
        let mut commitments = Vec::new();
        let mut commitment_index = HashMap::new();
        let mut point_index = HashMap::new();
        let mut points = Vec::new();
        let mut count = 0;
        for query in queries.clone() {
            count += 1;
            verifier_digest(&mut first, query);
            transcript.append_point_bytes(b"C", &query.commitment.bytes);
            transcript.append_scalar(b"z", &query.point);
            transcript.append_scalar(b"y", &query.result);
            commitment_index
                .entry(query.commitment.bytes)
                .or_insert_with(|| {
                    let index = commitments.len();
                    commitments.push(query.commitment.element);
                    index
                });
            let mut bytes = [0; 32];
            query.point.serialize_compressed(&mut bytes[..]).unwrap();
            point_index.entry(bytes).or_insert_with(|| {
                let index = points.len();
                points.push(query.point);
                index
            });
        }
        if count == 0 {
            return Err(StreamingError::EmptyQueries);
        }
        let r = transcript.challenge_scalar(b"r");
        transcript.append_point(b"D", &self.g_x_comm);
        let t = transcript.challenge_scalar(b"t");
        if precomp.contains_point(t) || points.contains(&t) {
            return Err(StreamingError::DegenerateChallenge);
        }
        let mut inverses: Vec<_> = points.into_iter().map(|z| t - z).collect();
        batch_inversion(&mut inverses);
        let mut scalars = vec![Fr::zero(); commitments.len()];
        let mut g2 = Fr::zero();
        let mut power = Fr::one();
        let mut replay = Sha256::new();
        for query in queries {
            verifier_digest(&mut replay, query);
            let mut bytes = [0; 32];
            query.point.serialize_compressed(&mut bytes[..]).unwrap();
            let index = point_index
                .get(&bytes)
                .ok_or(StreamingError::ReplayMismatch)?;
            let commitment = commitment_index
                .get(&query.commitment.bytes)
                .ok_or(StreamingError::ReplayMismatch)?;
            let helper = power * inverses[*index];
            scalars[*commitment] += helper;
            g2 += helper * query.result;
            power *= r;
        }
        if first.finalize() != replay.finalize() {
            return Err(StreamingError::ReplayMismatch);
        }
        let e = slow_vartime_multiscalar_mul(scalars.iter(), commitments.iter());
        transcript.append_point(b"E", &e);
        let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, crs.n, t);
        Ok(self
            .open_proof
            .verify_multiexp(transcript, crs, b, e - self.g_x_comm, t, g2))
    }
}

fn verifier_digest(digest: &mut Sha256, query: VerifierQueryRef<'_>) {
    digest.update(query.commitment.bytes);
    let mut bytes = [0; 32];
    query.point.serialize_compressed(&mut bytes[..]).unwrap();
    digest.update(bytes);
    query.result.serialize_compressed(&mut bytes[..]).unwrap();
    digest.update(bytes);
}

fn absorb_grouped_queries(
    queries: &[VerifierQuery],
    transcript: &mut Transcript,
) -> (Vec<usize>, Vec<Element>) {
    let mut indices = Vec::with_capacity(queries.len());
    let mut lookup = HashMap::new();
    let mut commitments = Vec::new();
    for query in queries {
        let commitment = QueryCommitment::new(query.commitment);
        transcript.append_point_bytes(b"C", &commitment.bytes);
        transcript.append_scalar(b"z", &query.point);
        transcript.append_scalar(b"y", &query.result);
        let next = commitments.len();
        let index = *lookup.entry(commitment.bytes).or_insert_with(|| {
            commitments.push(commitment.element);
            next
        });
        indices.push(index);
    }
    (indices, commitments)
}

fn grouped_evaluation(
    queries: &[VerifierQuery],
    denominators: Vec<Fr>,
    indices: Vec<usize>,
    commitments: &[Element],
    r: Fr,
) -> (Element, Fr) {
    let mut scalars = vec![Fr::zero(); commitments.len()];
    let mut r_i = Fr::one();
    let mut g2_t = Fr::zero();
    for ((query, inverse), index) in queries.iter().zip(denominators).zip(indices) {
        let helper = inverse * r_i;
        g2_t += helper * query.result;
        scalars[index] += helper;
        r_i *= r;
    }
    let g1_comm = slow_vartime_multiscalar_mul(scalars.iter(), commitments.iter());
    (g1_comm, g2_t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math_utils::powers_of;

    #[test]
    fn grouped_e_and_g2_match_reference_exactly() {
        let crs = CRS::new(256, b"grouped verifier E equivalence");
        for layout in [
            vec![],
            vec![0],
            vec![0, 1, 0, 2, 1],
            (0..1024).map(|i| i % 3).collect(),
        ] {
            let queries: Vec<_> = layout
                .iter()
                .enumerate()
                .map(|(i, id)| VerifierQuery {
                    commitment: if *id == 2 {
                        Element::zero()
                    } else {
                        crs.G[*id]
                    },
                    point: Fr::from((i % 256) as u128),
                    result: Fr::from((i + 7) as u128),
                })
                .collect();
            let mut owned = Transcript::new(b"grouped E test");
            let mut grouped = Transcript::new(b"grouped E test");
            for q in &queries {
                owned.append_point(b"C", &q.commitment);
                owned.append_scalar(b"z", &q.point);
                owned.append_scalar(b"y", &q.result);
            }
            let (indices, commitments) = absorb_grouped_queries(&queries, &mut grouped);
            let r = owned.challenge_scalar(b"r");
            assert_eq!(r, grouped.challenge_scalar(b"r"));
            let t = owned.challenge_scalar(b"t");
            assert_eq!(t, grouped.challenge_scalar(b"t"));
            let mut den: Vec<_> = queries.iter().map(|q| t - q.point).collect();
            batch_inversion(&mut den);
            let helpers: Vec<_> = powers_of(r, queries.len())
                .iter()
                .zip(&den)
                .map(|(r, d)| *r * d)
                .collect();
            let comms: Vec<_> = queries.iter().map(|q| q.commitment).collect();
            let reference_e = slow_vartime_multiscalar_mul(helpers.iter(), comms.iter());
            let reference_g2: Fr = helpers
                .iter()
                .zip(&queries)
                .map(|(h, q)| *h * q.result)
                .sum();
            let (e, g2) = grouped_evaluation(&queries, den, indices, &commitments, r);
            assert_eq!(e, reference_e);
            assert_eq!(e.to_bytes(), reference_e.to_bytes());
            assert_eq!(g2, reference_g2);
        }
    }
}

#[test]
fn degenerate_multiproof_challenges_and_r_edge_cases() {
    let crs = CRS::new(4, b"degenerate multiproof");
    let precomp = PrecomputedWeights::new(4);
    let poly = LagrangeBasis::new(vec![Fr::one(); 4]);
    let commitment = QueryCommitment::new(crs.commit_lagrange_poly(&poly));
    let queries = [ProverQueryRef {
        commitment: &commitment,
        poly: &poly,
        point: 0,
        result: Fr::one(),
    }];
    let refs = [VerifierQueryRef {
        commitment: &commitment,
        point: Fr::zero(),
        result: Fr::one(),
    }];
    let proof = MultiPoint::open_streaming(
        crs.clone(),
        &precomp,
        &mut Transcript::new(b"challenge"),
        queries.into_iter(),
    )
    .unwrap();
    for t in 0..4 {
        let mut tr = Transcript::new(b"challenge");
        tr.force_challenge(b"t", Fr::from(t as u64));
        assert_eq!(
            MultiPoint::open_streaming(crs.clone(), &precomp, &mut tr, queries.into_iter()),
            Err(StreamingError::DegenerateChallenge)
        );
        let mut tr = Transcript::new(b"challenge");
        tr.force_challenge(b"t", Fr::from(t as u64));
        assert_eq!(
            proof.check_grouped_streaming(&crs, &precomp, refs.into_iter(), &mut tr),
            Err(StreamingError::DegenerateChallenge)
        );
    }
    // A single query above covers domain errors; multi-query r-edge behavior
    // below exercises zero and combined weights across repeated/distinct pairs.
    for r in [Fr::zero(), Fr::one()] {
        let mut tr = Transcript::new(b"challenge");
        tr.force_challenge(b"r", r);
        let proof = MultiPoint::open_streaming(crs.clone(), &precomp, &mut tr, queries.into_iter())
            .unwrap();
        let mut verify = Transcript::new(b"challenge");
        verify.force_challenge(b"r", r);
        assert_eq!(
            proof.check_grouped_streaming(&crs, &precomp, refs.into_iter(), &mut verify),
            Ok(true)
        );
        assert_eq!(
            tr.challenge_scalar(b"after"),
            verify.challenge_scalar(b"after")
        );
    }
}

#[test]
fn multiquery_r_edge_weights_match_owned_reference() {
    use crate::multiproof::ProverQuery;
    let crs = CRS::new(4, b"r-edge-fixtures");
    let precomp = PrecomputedWeights::new(4);
    let polys = [
        LagrangeBasis::new(vec![Fr::from(3u64); 4]),
        LagrangeBasis::new((0..4).map(|i| Fr::from((i + 7) as u64)).collect()),
    ];
    let commitments: Vec<_> = polys
        .iter()
        .map(|p| QueryCommitment::new(crs.commit_lagrange_poly(p)))
        .collect();
    let layout = [(0, 0), (0, 0), (1, 3), (1, 2), (0, 3)];
    let owned: Vec<_> = layout
        .iter()
        .map(|&(p, z)| ProverQuery {
            commitment: commitments[p].element,
            poly: polys[p].clone(),
            point: z,
            result: polys[p].evaluate_in_domain(z),
        })
        .collect();
    let refs: Vec<_> = layout
        .iter()
        .map(|&(p, z)| ProverQueryRef {
            commitment: &commitments[p],
            poly: &polys[p],
            point: z,
            result: polys[p].evaluate_in_domain(z),
        })
        .collect();
    let verifier: Vec<_> = owned.iter().cloned().map(VerifierQuery::from).collect();
    let borrowed: Vec<_> = layout
        .iter()
        .map(|&(p, z)| VerifierQueryRef {
            commitment: &commitments[p],
            point: Fr::from(z as u64),
            result: polys[p].evaluate_in_domain(z),
        })
        .collect();
    for r in [Fr::zero(), Fr::one()] {
        let mut original = Transcript::new(b"r-edges");
        original.force_challenge(b"r", r);
        let expected = MultiPoint::open(crs.clone(), &precomp, &mut original, owned.clone());
        let mut streamed = Transcript::new(b"r-edges");
        streamed.force_challenge(b"r", r);
        let actual =
            MultiPoint::open_streaming(crs.clone(), &precomp, &mut streamed, refs.iter().copied())
                .unwrap();
        assert_eq!(expected.to_bytes().unwrap(), actual.to_bytes().unwrap());
        let after = original.challenge_scalar(b"after");
        assert_eq!(after, streamed.challenge_scalar(b"after"));
        for grouped in [false, true] {
            let mut tr = Transcript::new(b"r-edges");
            tr.force_challenge(b"r", r);
            assert!(if grouped {
                actual.check_grouped(&crs, &precomp, &verifier, &mut tr)
            } else {
                actual.check(&crs, &precomp, &verifier, &mut tr)
            });
            assert_eq!(after, tr.challenge_scalar(b"after"));
        }
        let mut tr = Transcript::new(b"r-edges");
        tr.force_challenge(b"r", r);
        assert_eq!(
            actual.check_grouped_streaming(&crs, &precomp, borrowed.iter().copied(), &mut tr),
            Ok(true)
        );
        assert_eq!(after, tr.challenge_scalar(b"after"));
    }
}
