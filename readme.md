# Diesis Verkle

A Rust library for Verkle tries and degree-256 polynomial commitments over
Banderwagon, with IPA multiproofs and C, C# and Java bindings. Crate names follow
[psalz/rust-verkle](https://github.com/psalz/rust-verkle) for API compatibility.

This is an experimental cryptographic library. Production use requires an
independent cryptographic audit and validation in the consuming application.

## Proof APIs

Checked point, CRS and proof decoders reject malformed encodings and dimensions.
Checked proving APIs return `ProofError`; verification rejects malformed proof
shapes and challenges that would require division by zero.

`ProverQueryRef` and `MultiPoint::open_streaming` borrow polynomial data.
Repeated openings of the same immutable polynomial and position share aggregated
weights. Borrowed verification groups commitments by their full canonical
encoding and inverts one denominator per distinct evaluation point.

The transcript uses incremental SHA256. Verifier folding coefficients use a
linear recurrence, and scalar-window recoding serializes each nonzero scalar
once. The owned APIs support callers that need independently owned query data.

See [safety and compatibility](validation/IPA_SAFETY.md) for input contracts,
algebraic arguments and protocol limits, and [dependencies](validation/DEPENDENCIES.md)
for optional storage backends and native build requirements.

## Validation

```sh
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --lib -- -D warnings
python3 scripts/tests/test_compile_to_native.py
```

Tests cover malformed encodings, quotient representatives, degenerate challenges,
iterator replay, transcript continuation and owned/borrowed proof equivalence.
The [Go cross-check](validation/go-ipa/README.md) regenerates proofs and compares
arithmetic, encodings and challenges in both directions. The
[mutation runner](validation/mutation_checks.py) exercises deliberate faults in
input checks and arithmetic.

The [performance harness](validation/PERFORMANCE.md) reports setup, proving,
verification, conversion, allocation and memory costs separately. Library timings
must be measured on representative workloads before drawing application-level
conclusions.

## References

- [Verkle trie reference](https://github.com/ethereum/research/blob/master/verkle_trie_eip/verkle_trie.py)
- [Go Verkle implementation](https://github.com/gballet/go-verkle)

## License

MIT / Apache-2.0. See the license files for applicable terms.
