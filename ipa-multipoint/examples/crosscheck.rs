//! Run once with Go JSONL as argv[1], then pass stdout back to the Go runner.
//! Deliberately uses the same documented integer input recipe, not shared fixtures.
use banderwagon::{trait_defs::*, Fr};
use ipa_multipoint::{
    crs::CRS,
    lagrange_basis::{LagrangeBasis, PrecomputedWeights},
    multiproof::{
        MultiPoint, MultiPointProof, ProverQuery, ProverQueryRef, QueryCommitment, VerifierQuery,
    },
    transcript::{Transcript, TranscriptProtocol},
};
use std::{collections::HashMap, fs};
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let prefix = format!("\"{key}\":\"");
    let rest = line.split_once(&prefix).expect("missing string field").1;
    rest.split('"').next().unwrap()
}
fn scalar(x: Fr) -> String {
    let mut b = [0; 32];
    x.serialize_compressed(&mut b[..]).unwrap();
    hex::encode(b)
}
fn main() {
    let peer = std::env::args().nth(1).expect("usage: crosscheck GO.jsonl");
    let input = fs::read_to_string(peer).unwrap();
    let peers: HashMap<_, _> = input
        .lines()
        .map(|line| {
            let n = line
                .split_once("\"n\":")
                .unwrap()
                .1
                .split(',')
                .next()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            ((n, field(line, "mode").to_owned()), line)
        })
        .collect();
    assert_eq!(peers.len(), 12);
    let crs = CRS::default();
    crs.validate().unwrap();
    let precomp = PrecomputedWeights::new(256);
    for n in [1, 16, 256, 1024] {
        for mode in ["distinct", "repeated", "identity"] {
            let polys: Vec<_> = (0..n)
                .map(|i| {
                    let id = match mode {
                        "repeated" => i % 4 + 1,
                        "identity" => 0,
                        _ => i + 1,
                    };
                    LagrangeBasis::new(
                        (0..256)
                            .map(|j| {
                                Fr::from(if id == 0 {
                                    0
                                } else {
                                    (id * 1009 + (j + 1) * (j + 3) + 17) as u128
                                })
                            })
                            .collect(),
                    )
                })
                .collect();
            let commitments: Vec<_> = polys
                .iter()
                .map(|p| QueryCommitment::new(crs.commit_lagrange_poly(p)))
                .collect();
            let positions: Vec<_> = (0..n)
                .map(|i| match i % 4 {
                    0 => 0,
                    1 => 255,
                    _ => (i * 73) % 256,
                })
                .collect();
            let queries: Vec<_> = (0..n)
                .map(|i| ProverQuery {
                    commitment: *commitments[i].element(),
                    poly: polys[i].clone(),
                    point: positions[i],
                    result: polys[i].evaluate_in_domain(positions[i]),
                })
                .collect();
            let verifier: Vec<_> = queries
                .iter()
                .map(|q| VerifierQuery {
                    commitment: q.commitment,
                    point: Fr::from(q.point as u128),
                    result: q.result,
                })
                .collect();
            let mut owned_tr = Transcript::new(b"diesis-crosscheck-v1");
            let owned = MultiPoint::open(crs.clone(), &precomp, &mut owned_tr, queries.clone());
            let mut tr = Transcript::new(b"diesis-crosscheck-v1");
            let proof = MultiPoint::open_streaming(
                crs.clone(),
                &precomp,
                &mut tr,
                (0..n).map(|i| ProverQueryRef {
                    commitment: &commitments[i],
                    poly: &polys[i],
                    point: positions[i],
                    result: queries[i].result,
                }),
            )
            .unwrap();
            let bytes = proof.to_bytes().unwrap();
            assert_eq!(owned.to_bytes().unwrap(), bytes);
            let challenge = scalar(tr.challenge_scalar(b"crosscheck-after"));
            assert_eq!(
                challenge,
                scalar(owned_tr.challenge_scalar(b"crosscheck-after"))
            );
            let peer = peers[&(n, mode.to_owned())];
            assert_eq!(
                hex::encode(&bytes),
                field(peer, "proof"),
                "proof n={n} mode={mode}"
            );
            let go = MultiPointProof::from_bytes(&hex::decode(field(peer, "proof")).unwrap(), 256)
                .unwrap();
            assert!(go.check(
                &crs,
                &precomp,
                &verifier,
                &mut Transcript::new(b"diesis-crosscheck-v1")
            ));
            let d = hex::encode(proof.g_x_comm.to_bytes());
            let comm: String = commitments
                .iter()
                .map(|c| hex::encode(c.element().to_bytes()))
                .collect();
            let mut audit = Transcript::new(b"diesis-crosscheck-v1");
            audit.domain_sep(b"multiproof");
            for q in &verifier {
                audit.append_point(b"C", &q.commitment);
                audit.append_scalar(b"z", &q.point);
                audit.append_scalar(b"y", &q.result);
            }
            let r = audit.challenge_scalar(b"r");
            audit.append_point(b"D", &proof.g_x_comm);
            let t = audit.challenge_scalar(b"t");
            let mut power = Fr::one();
            let mut h = vec![Fr::zero(); 256];
            for i in 0..n {
                let weight = power * (t - Fr::from(positions[i] as u128)).inverse().unwrap();
                for (j, x) in h.iter_mut().enumerate() {
                    *x += polys[i].evaluate_in_domain(j) * weight;
                }
                power *= r;
            }
            let e = hex::encode(crs.commit_lagrange_poly(&LagrangeBasis::new(h)).to_bytes());
            for (key, value) in [
                ("d", &d),
                ("e", &e),
                ("commitments", &comm),
                ("challenge", &challenge),
            ] {
                assert_eq!(value, field(peer, key), "{key} n={n} mode={mode}");
            }
            let mut tampered: Vec<_> = verifier
                .iter()
                .map(|q| VerifierQuery {
                    commitment: q.commitment,
                    point: q.point,
                    result: q.result,
                })
                .collect();
            tampered[0].result += Fr::one();
            assert!(!go.check(
                &crs,
                &precomp,
                &tampered,
                &mut Transcript::new(b"diesis-crosscheck-v1")
            ));
            tampered[0].result = verifier[0].result;
            tampered[0].commitment = crs.G[0];
            assert!(!go.check(
                &crs,
                &precomp,
                &tampered,
                &mut Transcript::new(b"diesis-crosscheck-v1")
            ));
            if mode != "identity" {
                tampered[0].commitment = verifier[0].commitment;
                tampered[0].point += Fr::one();
                assert!(!go.check(
                    &crs,
                    &precomp,
                    &tampered,
                    &mut Transcript::new(b"diesis-crosscheck-v1")
                ));
            }
            let mut bad = MultiPointProof::from_bytes(&bytes, 256).unwrap();
            bad.g_x_comm = crs.G[1];
            assert!(!bad.check(
                &crs,
                &precomp,
                &verifier,
                &mut Transcript::new(b"diesis-crosscheck-v1")
            ));
            println!("{{\"n\":{n},\"mode\":\"{mode}\",\"proof\":\"{}\",\"commitments\":\"{comm}\",\"d\":\"{d}\",\"e\":\"{e}\",\"challenge\":\"{challenge}\"}}",hex::encode(bytes));
            eprintln!("Rust owned/streaming and Go proof passed n={n} mode={mode}");
        }
    }
}
