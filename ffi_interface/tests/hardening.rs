use ffi_interface::{
    serialization::{try_deserialize_verifier_query, try_deserialize_verifier_query_uncompressed},
    verify_proof, Context,
};
#[test]
fn verifier_queries_reject_bad_lengths_and_encodings() {
    for len in [0, 1, 64, 66, 96, 98] {
        assert!(try_deserialize_verifier_query(&vec![0; len]).is_err());
        assert!(try_deserialize_verifier_query_uncompressed(&vec![0; len]).is_err());
    }
    assert!(try_deserialize_verifier_query(&[255; 65]).is_err());
    assert!(try_deserialize_verifier_query_uncompressed(&[255; 97]).is_err());
    let mut compressed = banderwagon::Element::zero().to_bytes().to_vec();
    compressed.push(0);
    compressed.extend_from_slice(&[0; 32]);
    assert!(try_deserialize_verifier_query(&compressed).is_ok());
    compressed[33..].fill(255);
    assert!(try_deserialize_verifier_query(&compressed).is_err());
    let mut uncompressed = banderwagon::Element::zero()
        .to_bytes_uncompressed()
        .to_vec();
    uncompressed.push(0);
    uncompressed.extend_from_slice(&[0; 32]);
    assert!(try_deserialize_verifier_query_uncompressed(&uncompressed).is_ok());
    uncompressed[65..].fill(255);
    assert!(try_deserialize_verifier_query_uncompressed(&uncompressed).is_err());
}
#[test]
fn verifier_rejects_malformed_input_without_panicking() {
    let context = Context::new();
    for len in [0, 1, 575, 576, 577, 640, 641, 642] {
        assert!(verify_proof(&context, vec![255; len]).is_err());
    }
}
#[test]
fn checked_arithmetic_rejects_malformed_commitments() {
    assert!(ffi_interface::try_add_commitment([255; 64], ffi_interface::ZERO_POINT).is_err());
    assert!(ffi_interface::try_hash_commitment([255; 64]).is_err());
    assert!(ffi_interface::serialization::try_serialize_commitment([255; 64]).is_err());
    assert_eq!(
        ffi_interface::try_add_commitment(ffi_interface::ZERO_POINT, ffi_interface::ZERO_POINT)
            .unwrap(),
        ffi_interface::ZERO_POINT
    );
}
