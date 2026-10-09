// Application opening/update scenarios and incremental commitment checks.
use banderwagon::{trait_defs::*, Fr};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::{LagrangeBasis, PrecomputedWeights},
    multiproof::{MultiPoint, ProverQueryRef, QueryCommitment, VerifierQueryRef},
    transcript::{Transcript, TranscriptProtocol},
};
#[test]
fn application_openings_updates_and_incremental_commitments() {
    let crs = CRS::default();
    let weights = PrecomputedWeights::new(256);
    for positions in [
        vec![0],
        vec![5],
        vec![42],
        vec![100],
        vec![254],
        vec![255],
        (0..256).collect(),
    ] {
        let values: Vec<_> = (0..256).map(|i| Fr::from((i * i + 17) as u64)).collect();
        let poly = LagrangeBasis::new(values.clone());
        let commitment = QueryCommitment::new(crs.commit_lagrange_poly(&poly));
        let mut tr = Transcript::new(b"vt");
        let proof = MultiPoint::open_streaming(
            crs.clone(),
            &weights,
            &mut tr,
            positions.iter().map(|&point| ProverQueryRef {
                commitment: &commitment,
                poly: &poly,
                point,
                result: values[point],
            }),
        )
        .unwrap();
        let mut vt = Transcript::new(b"vt");
        assert_eq!(
            proof.check_grouped_streaming(
                &crs,
                &weights,
                positions.iter().map(|&point| VerifierQueryRef {
                    commitment: &commitment,
                    point: Fr::from(point as u64),
                    result: values[point]
                }),
                &mut vt
            ),
            Ok(true)
        );
        assert_eq!(tr.challenge_scalar(b"after"), vt.challenge_scalar(b"after"));
        // Every claimed evaluation is independently bound, including all256 openings.
        for bad_index in 0..positions.len() {
            assert_eq!(
                proof.check_grouped_streaming(
                    &crs,
                    &weights,
                    positions
                        .iter()
                        .enumerate()
                        .map(|(i, &point)| VerifierQueryRef {
                            commitment: &commitment,
                            point: Fr::from(point as u64),
                            result: values[point]
                                + if i == bad_index {
                                    Fr::one()
                                } else {
                                    Fr::zero()
                                }
                        }),
                    &mut Transcript::new(b"vt")
                ),
                Ok(false)
            );
        }
    }
    let mut values = vec![Fr::zero(); 256];
    let mut incremental = banderwagon::Element::zero();
    for i in [0, 4, 32, 64, 255] {
        let next = Fr::from((i + 3) as u64);
        incremental += crs.G[i] * (next - values[i]);
        values[i] = next;
        assert_eq!(
            incremental,
            crs.commit_lagrange_poly(&LagrangeBasis::new(values.clone()))
        );
    }
    for count in [64, 256] {
        for (i, value) in values.iter_mut().take(count).enumerate() {
            let next = Fr::from((i * i + 5) as u64);
            incremental += crs.G[i] * (next - *value);
            *value = next;
        }
        assert_eq!(
            incremental,
            crs.commit_lagrange_poly(&LagrangeBasis::new(values.clone()))
        );
    }
}
