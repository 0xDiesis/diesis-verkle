use banderwagon::{trait_defs::*, Element, Fr};
use ipa_multipoint::{
    crs::CRS,
    ipa::IPAProof,
    multiproof::MultiPointProof,
    transcript::{Transcript, TranscriptProtocol},
};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn overlong_element_is_rejected() {
    assert!(Element::from_bytes(&[0; 33]).is_none());
}

#[test]
fn proof_lengths_and_dimensions_return_errors() {
    for degree in [0, 3, 255, 256, usize::MAX] {
        for len in [0, 1, 31, 32, 543, 545, 575, 577] {
            let bytes = vec![0; len];
            let parsed = catch_unwind(|| IPAProof::from_bytes(&bytes, degree));
            assert!(
                parsed.is_ok(),
                "IPA decoder panicked: degree={degree}, len={len}"
            );
            assert!(parsed.unwrap().is_err());
            let parsed = catch_unwind(|| MultiPointProof::from_bytes(&bytes, degree));
            assert!(
                parsed.is_ok(),
                "multiproof decoder panicked: degree={degree}, len={len}"
            );
            assert!(parsed.unwrap().is_err());
        }
    }
}

fn zero_proof(rounds: usize) -> IPAProof {
    IPAProof {
        L_vec: vec![Element::zero(); rounds],
        R_vec: vec![Element::zero(); rounds],
        a: Fr::zero(),
    }
}

#[test]
fn malformed_verifier_shapes_fail_without_panics() {
    let crs = CRS::default();
    for (left, right, b_len, g_len, n) in [
        (72, 72, 256, 256, 256),
        (8, 7, 256, 256, 256),
        (8, 9, 256, 256, 256),
        (8, 8, 255, 256, 256),
        (8, 8, 256, 255, 256),
        (8, 8, 256, 256, 255),
        (0, 0, 0, 0, 0),
    ] {
        let mut proof = zero_proof(left);
        proof.R_vec.resize(right, Element::zero());
        let mut params = crs.clone();
        params.G.truncate(g_len);
        params.n = n;
        for variant in 0..3 {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut tr = Transcript::new(b"shape regression");
                let b = vec![Fr::zero(); b_len];
                match variant {
                    0 => proof.verify_multiexp(
                        &mut tr,
                        &params,
                        b,
                        Element::zero(),
                        Fr::zero(),
                        Fr::zero(),
                    ),
                    1 => proof.verify(
                        &mut tr,
                        params.clone(),
                        b,
                        Element::zero(),
                        Fr::zero(),
                        Fr::zero(),
                    ),
                    _ => proof.verify_semi_multiexp(
                        &mut tr,
                        &params,
                        b,
                        Element::zero(),
                        Fr::zero(),
                        Fr::zero(),
                    ),
                }
            }));
            assert!(
                result.is_ok(),
                "verifier {variant} panicked for L{left}/R{right}/b{b_len}/G{g_len}/n{n}"
            );
            assert!(!result.unwrap());
        }
    }
}

#[test]
fn checked_crs_loads_and_rejects_bad_parameters() {
    let crs = CRS::default();
    assert!(crs.validate().is_ok());
    assert_eq!(
        CRS::try_from_bytes(&crs.to_bytes()).unwrap().to_bytes(),
        crs.to_bytes()
    );
    assert!(CRS::try_from_bytes(&[]).is_err());
    assert!(CRS::try_from_hex(&["bad"]).is_err());
    let mut bad = crs.clone();
    bad.n -= 1;
    assert!(bad.validate().is_err());
    bad = crs.clone();
    bad.Q = bad.G[0];
    assert!(bad.validate().is_err());
    bad = crs.clone();
    bad.G[1] = bad.G[0];
    assert!(bad.validate().is_err());
    bad = crs.clone();
    bad.Q = Element::zero();
    assert!(bad.validate().is_err());
}

#[test]
fn checked_prover_boundaries_do_not_mutate_transcript_on_bad_dimensions() {
    use ipa_multipoint::{
        ipa::try_create, lagrange_basis::PrecomputedWeights, multiproof::MultiPoint, ProofError,
    };
    let crs = CRS::default();
    let mut tr = Transcript::new(b"test");
    assert_eq!(
        try_create(
            &mut tr,
            crs.clone(),
            vec![],
            Element::zero(),
            vec![],
            Fr::zero()
        ),
        Err(ProofError::InvalidDomain)
    );
    assert_eq!(
        tr.challenge_scalar(b"after"),
        Transcript::new(b"test").challenge_scalar(b"after")
    );
    assert_eq!(
        MultiPoint::open_streaming(
            crs,
            &PrecomputedWeights::new(128),
            &mut tr,
            std::iter::empty()
        ),
        Err(ProofError::InvalidDomain)
    );
}

#[test]
fn bounded_decoder_fuzz_smoke() {
    let mut state = 0x98127ab6_u64;
    for iteration in 0..2048 {
        let len = iteration % 1200;
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let degree = [0, 1, 2, 3, 128, 256, usize::MAX][iteration % 7];
        for uncompressed in [false, true] {
            let parsed = catch_unwind(AssertUnwindSafe(|| {
                if uncompressed {
                    MultiPointProof::from_bytes_uncompressed(&bytes, degree)
                } else {
                    MultiPointProof::from_bytes(&bytes, degree)
                }
            }));
            assert!(parsed.is_ok());
            if let Ok(proof) = parsed.unwrap() {
                let encoded = if uncompressed {
                    proof.to_bytes_uncompressed().unwrap()
                } else {
                    proof.to_bytes().unwrap()
                };
                assert_eq!(encoded, bytes);
            }
        }
        assert!(catch_unwind(|| Element::from_bytes(&bytes)).is_ok());
    }
}

#[test]
fn every_proof_truncation_and_suffix_is_rejected() {
    use ipa_multipoint::{
        lagrange_basis::{LagrangeBasis, PrecomputedWeights},
        multiproof::{MultiPoint, ProverQuery},
    };
    let crs = CRS::default();
    let poly = LagrangeBasis::new(vec![Fr::one(); 256]);
    let query = ProverQuery {
        commitment: crs.commit_lagrange_poly(&poly),
        poly,
        point: 255,
        result: Fr::one(),
    };
    let proof = MultiPoint::try_open(
        crs,
        &PrecomputedWeights::new(256),
        &mut Transcript::new(b"truncation"),
        &[query],
    )
    .unwrap();
    for uncompressed in [false, true] {
        let bytes = if uncompressed {
            proof.to_bytes_uncompressed().unwrap()
        } else {
            proof.to_bytes().unwrap()
        };
        let decode = |input: &[u8]| {
            if uncompressed {
                MultiPointProof::from_bytes_uncompressed(input, 256)
            } else {
                MultiPointProof::from_bytes(input, 256)
            }
        };
        assert_eq!(decode(&bytes).unwrap(), proof);
        for len in 0..bytes.len() {
            let parsed = catch_unwind(AssertUnwindSafe(|| decode(&bytes[..len])));
            assert!(parsed.is_ok());
            assert!(parsed.unwrap().is_err());
        }
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(decode(&suffix).is_err());
        suffix[bytes.len()] = 255;
        assert!(decode(&suffix).is_err());
    }
}
