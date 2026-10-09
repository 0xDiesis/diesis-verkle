#![allow(non_snake_case)]
use crate::crs::CRS;
use crate::math_utils::inner_product;
use crate::transcript::{Transcript, TranscriptProtocol};

use banderwagon::{multi_scalar_mul, trait_defs::*, Element, Fr};
#[cfg(test)]
use itertools::Itertools;

use crate::{IOError, IOErrorKind, IOResult};

use std::iter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPAProof {
    // Public proof fields support structured serialization and external verifiers.
    pub L_vec: Vec<Element>,
    pub R_vec: Vec<Element>,
    pub a: Fr,
}

impl IPAProof {
    pub(crate) fn serialized_size(&self) -> usize {
        (self.L_vec.len() * 2 + 1) * 32
    }
    pub(crate) fn uncompressed_size(&self) -> usize {
        (self.L_vec.len() * 2 * 64) + 32
    }
    pub fn from_bytes(bytes: &[u8], poly_degree: usize) -> IOResult<IPAProof> {
        // Given the polynomial degree, we will have log2 * 2 points
        let num_points = proof_rounds(bytes.len(), poly_degree, 32)?;
        let mut L_vec = Vec::with_capacity(num_points as usize);
        let mut R_vec = Vec::with_capacity(num_points as usize);

        // Chunk the byte slice into 32 bytes
        let mut chunks = bytes.chunks_exact(32);

        for _ in 0..num_points {
            let chunk = chunks.next().unwrap();
            let point: Element =
                Element::from_bytes(chunk).ok_or(IOError::from(IOErrorKind::InvalidData))?;
            L_vec.push(point)
        }

        for _ in 0..num_points {
            let chunk = chunks.next().unwrap();
            let point: Element =
                Element::from_bytes(chunk).ok_or(IOError::from(IOErrorKind::InvalidData))?;
            R_vec.push(point)
        }

        let last_32_bytes = chunks.next().unwrap();

        let a: Fr = CanonicalDeserialize::deserialize_compressed(last_32_bytes)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;

        Ok(IPAProof { L_vec, R_vec, a })
    }
    pub fn from_bytes_unchecked_uncompressed(
        bytes: &[u8],
        poly_degree: usize,
    ) -> IOResult<IPAProof> {
        // Given the polynomial degree, we will have log2 * 2 points
        let num_points = proof_rounds(bytes.len(), poly_degree, 64)?;
        let mut L_vec = Vec::with_capacity(num_points as usize);
        let mut R_vec = Vec::with_capacity(num_points as usize);

        let (points_bytes, a_bytes) = bytes.split_at(bytes.len() - 32);

        assert!(a_bytes.len() == 32);

        // Chunk the byte slice into 64 bytes
        let mut chunks = points_bytes.chunks_exact(64);

        for _ in 0..num_points {
            let chunk = chunks.next().unwrap();
            let L_bytes: [u8; 64] = chunk.try_into().unwrap();
            let point: Element = Element::from_bytes_unchecked_uncompressed(L_bytes);
            L_vec.push(point)
        }

        for _ in 0..num_points {
            let chunk = chunks.next().unwrap();
            let R_bytes: [u8; 64] = chunk.try_into().unwrap();
            let point: Element = Element::from_bytes_unchecked_uncompressed(R_bytes);
            R_vec.push(point)
        }

        let a: Fr = CanonicalDeserialize::deserialize_compressed(a_bytes)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;

        Ok(IPAProof { L_vec, R_vec, a })
    }
    pub fn from_bytes_uncompressed(bytes: &[u8], poly_degree: usize) -> IOResult<Self> {
        let rounds = proof_rounds(bytes.len(), poly_degree, 64)?;
        let mut points = bytes[..bytes.len() - 32].chunks_exact(64).map(|b| {
            Element::try_from_bytes_uncompressed(b.try_into().unwrap())
                .map_err(|_| IOError::from(IOErrorKind::InvalidData))
        });
        let L_vec = points
            .by_ref()
            .take(rounds as usize)
            .collect::<IOResult<_>>()?;
        let R_vec = points.collect::<IOResult<_>>()?;
        let a = Fr::deserialize_compressed(&bytes[bytes.len() - 32..])
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;
        Ok(Self { L_vec, R_vec, a })
    }
    pub(crate) fn valid_shape(&self, crs: &CRS, b_len: usize) -> bool {
        crs.n.is_power_of_two()
            && crs.G.len() == crs.n
            && b_len == crs.n
            && self.L_vec.len() == crs.n.trailing_zeros() as usize
            && self.R_vec.len() == self.L_vec.len()
    }
    pub fn to_bytes(&self) -> IOResult<Vec<u8>> {
        // We do not serialize the length. We assume that the deserializer knows this.
        let mut bytes = Vec::with_capacity(self.serialized_size());

        for L in &self.L_vec {
            bytes.extend(L.to_bytes());
        }

        for R in &self.R_vec {
            bytes.extend(R.to_bytes());
        }

        self.a
            .serialize_compressed(&mut bytes)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;
        Ok(bytes)
    }
    pub fn to_bytes_uncompressed(&self) -> IOResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.uncompressed_size());

        for L in &self.L_vec {
            bytes.extend(L.to_bytes_uncompressed());
        }

        for R in &self.R_vec {
            bytes.extend(R.to_bytes_uncompressed());
        }

        self.a
            .serialize_uncompressed(&mut bytes)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;
        Ok(bytes)
    }
}

fn proof_rounds(len: usize, degree: usize, point_size: usize) -> IOResult<u32> {
    if !degree.is_power_of_two() {
        return Err(IOError::from(IOErrorKind::InvalidData));
    }
    let rounds = degree.trailing_zeros();
    let expected = (rounds as usize * 2) * point_size + 32;
    if len != expected {
        return Err(IOError::from(IOErrorKind::InvalidData));
    }
    Ok(rounds)
}

/// Trusted compatibility wrapper; prefer `try_create` for fallible inputs.
pub fn create(
    transcript: &mut Transcript,
    crs: CRS,
    a_vec: Vec<Fr>,
    a_comm: Element,
    b_vec: Vec<Fr>,
    // This is the z in f(z)
    input_point: Fr,
) -> IPAProof {
    try_create(transcript, crs, a_vec, a_comm, b_vec, input_point)
        .expect("trusted IPA inputs must be coherent and challenges nonzero")
}

pub fn try_create(
    transcript: &mut Transcript,
    mut crs: CRS,
    mut a_vec: Vec<Fr>,
    a_comm: Element,
    mut b_vec: Vec<Fr>,
    // This is the z in f(z)
    input_point: Fr,
) -> Result<IPAProof, crate::ProofError> {
    if !crs.n.is_power_of_two()
        || crs.G.len() != crs.n
        || a_vec.len() != crs.n
        || b_vec.len() != crs.n
    {
        return Err(crate::ProofError::InvalidDomain);
    }
    transcript.domain_sep(b"ipa");

    let mut a = &mut a_vec[..];
    let mut b = &mut b_vec[..];
    let mut G = &mut crs.G[..];

    let n = G.len();

    // All of the input vectors must have the same length.
    assert_eq!(G.len(), n);
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    // All of the input vectors must have a length that is a power of two.
    assert!(n.is_power_of_two());

    // transcript.append_u64(b"n", n as u64);
    let output_point = inner_product(a, b);
    transcript.append_point(b"C", &a_comm);
    transcript.append_scalar(b"input point", &input_point);
    transcript.append_scalar(b"output point", &output_point);

    let w = transcript.challenge_scalar(b"w");
    if w.is_zero() {
        return Err(crate::ProofError::DegenerateChallenge);
    }
    let Q = crs.Q * w; // XXX: It would not hurt to add this augmented point into the transcript

    let num_rounds = log2(n);

    let mut L_vec: Vec<Element> = Vec::with_capacity(num_rounds as usize);
    let mut R_vec: Vec<Element> = Vec::with_capacity(num_rounds as usize);

    for _k in 0..num_rounds {
        let (a_L, a_R) = halve(a);
        let (b_L, b_R) = halve(b);
        let (G_L, G_R) = halve(G);

        let z_L = inner_product(a_R, b_L);
        let z_R = inner_product(a_L, b_R);

        let L = slow_vartime_multiscalar_mul(
            a_R.iter().chain(iter::once(&z_L)),
            G_L.iter().chain(iter::once(&Q)),
        );
        let R = slow_vartime_multiscalar_mul(
            a_L.iter().chain(iter::once(&z_R)),
            G_R.iter().chain(iter::once(&Q)),
        );

        L_vec.push(L);
        R_vec.push(R);

        transcript.append_point(b"L", &L);
        transcript.append_point(b"R", &R);

        let x = transcript.challenge_scalar(b"x");
        let x_inv = x.inverse().ok_or(crate::ProofError::DegenerateChallenge)?;
        for i in 0..a_L.len() {
            a_L[i] += x * a_R[i];
            b_L[i] += x_inv * b_R[i];
            G_L[i] += G_R[i] * x_inv;
        }

        a = a_L;
        b = b_L;
        G = G_L;
    }

    Ok(IPAProof {
        L_vec,
        R_vec,
        a: a[0],
    })
}
// Halves the slice that is passed in
// Assumes that the slice has an even length
fn halve<T>(scalars: &mut [T]) -> (&mut [T], &mut [T]) {
    let len = scalars.len();
    scalars.split_at_mut(len / 2)
}
fn log2(n: usize) -> u32 {
    n.trailing_zeros()
}

impl IPAProof {
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        mut crs: CRS,
        mut b: Vec<Fr>,
        a_comm: Element,
        input_point: Fr,
        output_point: Fr,
    ) -> bool {
        if !self.valid_shape(&crs, b.len()) {
            return false;
        }
        transcript.domain_sep(b"ipa");

        let mut G = &mut crs.G[..];
        let mut b = &mut b[..];

        let num_rounds = self.L_vec.len();

        // Check that the prover computed an inner proof
        // over a vector of size n

        // transcript.append_u64(b"n", n as u64);
        transcript.append_point(b"C", &a_comm);
        transcript.append_scalar(b"input point", &input_point);
        transcript.append_scalar(b"output point", &output_point);

        let w = transcript.challenge_scalar(b"w");
        if w.is_zero() {
            return false;
        }
        let Q = crs.Q * w;

        let mut a_comm = a_comm + (Q * output_point);

        let challenges = generate_challenges(self, transcript);
        if challenges.iter().any(Zero::is_zero) {
            return false;
        }
        let mut challenges_inv = challenges.clone();
        batch_inversion(&mut challenges_inv);

        // Compute the expected commitment
        for i in 0..num_rounds {
            let x = challenges[i];
            let x_inv = challenges_inv[i];
            let L = self.L_vec[i];
            let R = self.R_vec[i];

            a_comm = a_comm + (L * x) + (R * x_inv);
        }

        for x_inv in challenges_inv.iter() {
            let (G_L, G_R) = halve(G);
            let (b_L, b_R) = halve(b);

            for i in 0..G_L.len() {
                G_L[i] += G_R[i] * *x_inv;
                b_L[i] += b_R[i] * x_inv;
            }
            G = G_L;
            b = b_L;
        }
        assert_eq!(G.len(), 1);
        assert_eq!(b.len(), 1);

        let exp_P = (G[0] * self.a) + Q * (self.a * b[0]);

        exp_P == a_comm
    }
    pub fn verify_multiexp(
        &self,
        transcript: &mut Transcript,
        crs: &CRS,
        b_vec: Vec<Fr>,
        a_comm: Element,
        input_point: Fr,
        output_point: Fr,
    ) -> bool {
        if !self.valid_shape(crs, b_vec.len()) {
            return false;
        }
        transcript.domain_sep(b"ipa");

        // Check that the prover computed an inner proof
        // over a vector of size n

        // transcript.append_u64(b"n", n as u64);
        transcript.append_point(b"C", &a_comm);
        transcript.append_scalar(b"input point", &input_point);
        transcript.append_scalar(b"output point", &output_point);

        // Compute the scalar which will augment the point corresponding
        // to the inner product
        let w = transcript.challenge_scalar(b"w");
        if w.is_zero() {
            return false;
        }

        // Generate all of the necessary challenges and their inverses
        let challenges = generate_challenges(self, transcript);
        if challenges.iter().any(Zero::is_zero) {
            return false;
        }
        let mut challenges_inv = challenges.clone();
        batch_inversion(&mut challenges_inv);

        // Generate the coefficients for the `G` vector and the `b` vector
        // {-g_i}{-b_i}
        let b_i = folding_coefficients(&challenges_inv, -Fr::one());
        let g_i: Vec<_> = b_i.iter().map(|s| self.a * s).collect();

        let b_0 = inner_product(&b_vec, &b_i);
        let q_i = w * (output_point + self.a * b_0);

        slow_vartime_multiscalar_mul(
            challenges
                .iter()
                .chain(challenges_inv.iter())
                .chain(iter::once(&Fr::one()))
                .chain(iter::once(&q_i))
                .chain(g_i.iter()),
            self.L_vec
                .iter()
                .chain(self.R_vec.iter())
                .chain(iter::once(&a_comm))
                .chain(iter::once(&crs.Q))
                // The fixed CRS bases pair with the folded G coefficient vector.
                .chain(crs.G.iter()),
        )
        .is_zero()
    }
    // Equivalent partially unrolled verifier for reference comparisons.
    pub fn verify_semi_multiexp(
        &self,
        transcript: &mut Transcript,
        crs: &CRS,
        b_Vec: Vec<Fr>,
        a_comm: Element,
        input_point: Fr,
        output_point: Fr,
    ) -> bool {
        if !self.valid_shape(crs, b_Vec.len()) {
            return false;
        }
        transcript.domain_sep(b"ipa");

        // Check that the prover computed an inner proof
        // over a vector of size n

        // transcript.append_u64(b"n", n as u64);
        transcript.append_point(b"C", &a_comm);
        transcript.append_scalar(b"input point", &input_point);
        transcript.append_scalar(b"output point", &output_point);

        let w = transcript.challenge_scalar(b"w");
        if w.is_zero() {
            return false;
        }
        let Q = crs.Q * w;

        let a_comm = a_comm + (Q * output_point);

        let challenges = generate_challenges(self, transcript);
        if challenges.iter().any(Zero::is_zero) {
            return false;
        }
        let mut challenges_inv = challenges.clone();
        batch_inversion(&mut challenges_inv);

        let P = slow_vartime_multiscalar_mul(
            challenges
                .iter()
                .chain(challenges_inv.iter())
                .chain(iter::once(&Fr::one())),
            self.L_vec
                .iter()
                .chain(self.R_vec.iter())
                .chain(iter::once(&a_comm)),
        );

        // {g_i}
        let g_i = folding_coefficients(&challenges_inv, Fr::one());

        let b_0 = inner_product(&b_Vec, &g_i);
        let G_0 = slow_vartime_multiscalar_mul(g_i.iter(), crs.G.iter());

        let exp_P = (G_0 * self.a) + Q * (self.a * b_0);

        exp_P == P
    }
}

#[cfg(test)]
fn to_bits(n: usize, bits_needed: usize) -> impl Iterator<Item = u8> {
    (0..bits_needed).map(move |i| ((n >> i) & 1) as u8).rev()
}

pub fn slow_vartime_multiscalar_mul<'a>(
    scalars: impl Iterator<Item = &'a Fr>,
    points: impl Iterator<Item = &'a Element>,
) -> Element {
    let scalars: Vec<_> = scalars.into_iter().copied().collect();
    let points: Vec<_> = points.into_iter().copied().collect();
    multi_scalar_mul(&points, &scalars)
}

fn generate_challenges(proof: &IPAProof, transcript: &mut Transcript) -> Vec<Fr> {
    let mut challenges: Vec<Fr> = Vec::with_capacity(proof.L_vec.len());

    for (L, R) in proof.L_vec.iter().zip(proof.R_vec.iter()) {
        transcript.append_point(b"L", L);
        transcript.append_point(b"R", R);

        let x_i = transcript.challenge_scalar(b"x");
        challenges.push(x_i);
    }

    challenges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crs::CRS;
    use crate::math_utils::{inner_product, powers_of};

    use ark_std::{rand::SeedableRng, UniformRand};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_create_IPAProof_proof() {
        let n = 8;
        let crs = CRS::new(n, b"random seed");

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let input_point = Fr::rand(&mut rng);

        let b = powers_of(input_point, n);
        let output_point = inner_product(&a, &b);

        let mut prover_transcript = Transcript::new(b"ip_no_zk");

        let P = slow_vartime_multiscalar_mul(a.iter(), crs.G.iter());

        let proof = create(
            &mut prover_transcript,
            crs.clone(),
            a,
            P,
            b.clone(),
            input_point,
        );

        let mut verifier_transcript = Transcript::new(b"ip_no_zk");
        assert!(proof.verify(
            &mut verifier_transcript,
            crs,
            b,
            P,
            input_point,
            output_point
        ));
    }
}

// Fold G_L + x^-1 G_R. The reversed challenge order doubles adjacent
// coefficients; induction gives product x_j^-1 over the set bits of i.
fn folding_coefficients(inverses: &[Fr], initial: Fr) -> Vec<Fr> {
    let mut coefficients = Vec::with_capacity(1usize << inverses.len());
    coefficients.push(initial);
    for inverse in inverses.iter().rev() {
        let len = coefficients.len();
        for i in 0..len {
            coefficients.push(coefficients[i] * inverse);
        }
    }
    coefficients
}
#[test]
fn linear_coefficients_match_bit_oracle() {
    for rounds in 0..=8 {
        let inverses: Vec<_> = (0..rounds).map(|i| Fr::from((i + 2) as u64)).collect();
        for initial in [Fr::one(), -Fr::one()] {
            let slow: Vec<_> = (0..1usize << rounds)
                .map(|i| {
                    to_bits(i, rounds)
                        .zip_eq(&inverses)
                        .fold(initial, |v, (bit, x)| if bit == 1 { v * x } else { v })
                })
                .collect();
            assert_eq!(folding_coefficients(&inverses, initial), slow);
        }
    }
}

#[test]
fn degenerate_ipa_challenges_fail_closed() {
    for label in [b"w" as &'static [u8], b"x"] {
        let crs = CRS::new(4, b"challenge tests");
        let a = vec![Fr::one(); 4];
        let b = vec![Fr::one(); 4];
        let c = slow_vartime_multiscalar_mul(a.iter(), crs.G.iter());
        let proof = create(
            &mut Transcript::new(b"zero"),
            crs.clone(),
            a.clone(),
            c,
            b.clone(),
            Fr::from(9u64),
        );
        let mut tr = Transcript::new(b"zero");
        tr.force_challenge(label, Fr::zero());
        assert_eq!(
            try_create(&mut tr, crs.clone(), a, c, b.clone(), Fr::from(9u64)),
            Err(crate::ProofError::DegenerateChallenge)
        );
        for variant in 0..3 {
            let mut tr = Transcript::new(b"zero");
            tr.force_challenge(label, Fr::zero());
            let accepted = match variant {
                0 => proof.verify(
                    &mut tr,
                    crs.clone(),
                    b.clone(),
                    c,
                    Fr::from(9u64),
                    Fr::from(4u64),
                ),
                1 => proof.verify_multiexp(
                    &mut tr,
                    &crs,
                    b.clone(),
                    c,
                    Fr::from(9u64),
                    Fr::from(4u64),
                ),
                _ => proof.verify_semi_multiexp(
                    &mut tr,
                    &crs,
                    b.clone(),
                    c,
                    Fr::from(9u64),
                    Fr::from(4u64),
                ),
            };
            assert!(!accepted);
        }
    }
}
