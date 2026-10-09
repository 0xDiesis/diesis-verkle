use c_verkle::{context_free, context_new, verify_proof, verify_proof_uncompressed};
#[test]
fn bool_verifiers_reject_null_short_remainder_and_bad_encoding() {
    for verify in [verify_proof, verify_proof_uncompressed] {
        assert!(!verify(std::ptr::null_mut(), std::ptr::null(), 0));
        let ctx = context_new();
        assert!(!verify(ctx, std::ptr::null(), 1200));
        let input = vec![255; 1218];
        for len in [0, 1, 575, 576, 577, 641, 642, 1119, 1120, 1121, 1217, 1218] {
            assert!(!verify(ctx, input.as_ptr(), len));
        }
        context_free(ctx);
    }
}

#[test]
fn bool_verifiers_accept_valid_buffers_and_reject_each_encoding_boundary() {
    use banderwagon::{trait_defs::*, Fr};
    use ipa_multipoint::{
        crs::CRS,
        lagrange_basis::{LagrangeBasis, PrecomputedWeights},
        multiproof::{MultiPoint, ProverQuery},
        transcript::Transcript,
    };
    let crs = CRS::default();
    let weights = PrecomputedWeights::new(256);
    for value in [Fr::zero(), Fr::from(7u64)] {
        let poly = LagrangeBasis::new(vec![value; 256]);
        let c = crs.commit_lagrange_poly(&poly);
        let q = ProverQuery {
            commitment: c,
            poly,
            point: 255,
            result: value,
        };
        let proof =
            MultiPoint::try_open(crs.clone(), &weights, &mut Transcript::new(b"verkle"), &[q])
                .unwrap();
        for uncompressed in [false, true] {
            let verify = std::hint::black_box(if uncompressed {
                verify_proof_uncompressed
            } else {
                verify_proof
            });
            let size = if uncompressed { 64 } else { 32 };
            let proof_size = if uncompressed { 1120 } else { 576 };
            let mut input = if uncompressed {
                proof.to_bytes_uncompressed().unwrap()
            } else {
                proof.to_bytes().unwrap()
            };
            input.extend(if uncompressed {
                c.to_bytes_uncompressed().to_vec()
            } else {
                c.to_bytes().to_vec()
            });
            input.push(255);
            value.serialize_compressed(&mut input).unwrap();
            let ctx = context_new();
            assert!(verify(ctx, input.as_ptr(), input.len()));
            assert!(!verify(ctx, input.as_ptr(), usize::MAX));
            // Query remains valid while D, first L and first R are damaged.
            for point in [0, size, size * 9] {
                let mut bad = input.clone();
                bad[point..point + size].fill(255);
                assert!(!verify(ctx, bad.as_ptr(), bad.len()));
            }
            // Proof remains valid while query commitment/scalar are damaged.
            for range in [
                proof_size..proof_size + size,
                proof_size + size + 1..input.len(),
            ] {
                let mut bad = input.clone();
                bad[range].fill(255);
                assert!(!verify(ctx, bad.as_ptr(), bad.len()));
            }
            if uncompressed && value.is_zero() {
                // Both (0,1) and (0,-1) represent quotient identity. Base field
                // is the BLS12-381 scalar field; canonical p-1 is decoded here.
                let mut minus_one =
                    hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
                        .unwrap();
                minus_one.reverse();
                let mut equivalent = input.clone();
                equivalent[32..64].copy_from_slice(&minus_one);
                equivalent[proof_size + 32..proof_size + 64].copy_from_slice(&minus_one);
                assert!(verify(ctx, equivalent.as_ptr(), equivalent.len()));
            }
            context_free(ctx);
        }
    }
}
