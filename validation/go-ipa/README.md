# Go and Rust runtime comparison

The Go dependency is pinned to upstream commit
`53bbb0ceb27adb011950fd0fce885ad6d4516f84`. Its `go.mod` and `go.sum` pin
the arithmetic dependencies. This runner uses Go APIs without copying
implementation code.

Run from the Rust repository root. The output directory stores generated
comparison records:

```sh
ipa_report_dir="${IPA_RESULTS_DIR:-$PWD/validation-results}"
mkdir -p "$ipa_report_dir"
(cd validation/go-ipa && go run .) > "$ipa_report_dir/go-crosscheck.jsonl" 2> "$ipa_report_dir/go-crosscheck.log"
cargo run -p ipa-multipoint --example crosscheck -- "$ipa_report_dir/go-crosscheck.jsonl" > "$ipa_report_dir/rust-crosscheck.jsonl" 2> "$ipa_report_dir/rust-crosscheck.log"
(cd validation/go-ipa && go run . "$ipa_report_dir/rust-crosscheck.jsonl") > "$ipa_report_dir/go-reciprocal.jsonl" 2> "$ipa_report_dir/go-reciprocal.log"
(cd validation/go-ipa && go run . --parameters ../../ipa-multipoint/src/default_crs.rs) > "$ipa_report_dir/go-crs-comparison.json"
python3 validation/go-ipa/check_scalars.py "$ipa_report_dir/go-crosscheck.jsonl" "$ipa_report_dir/rust-crosscheck.jsonl" > "$ipa_report_dir/scalar-encoding-comparison.json"
```

Both programs independently generate degree-256 evaluation vectors. For query
`i`, distinct polynomial ID is `i+1`; repeated ID is `i%4+1`; identity ID is
zero. Nonzero vector entry `j` is `ID*1009+(j+1)*(j+3)+17`, interpreted as
a scalar. Identity vectors contain zero. Positions are `i*73%256` except
`i%4==0` uses 0 and `i%4==1` uses 255. Query counts are 1, 16, 256, 1024.
The transcript starts with `diesis-crosscheck-v1`.

Each JSONL row carries proof bytes, ordered commitments, D, independently
reconstructed E, and a post-proof `crosscheck-after` challenge. The challenge
checks the transcript continuation, not a raw internal hash snapshot. Rust
checks the owned `MultiPoint::open` and borrowed streaming proof equivalence and verifies the Go
proof. The reciprocal Go run compares every row and verifies the Rust proof.

Each implementation checks changed evaluation results, stale commitments,
and a changed D. Position changes must fail for nonzero polynomials. The
all-zero polynomial has a valid opening at every position, so that negative
is deliberately omitted for identity cases. Serialized malformed encodings
are covered by the repository's hardening suite rather than this runner.

This is independent arithmetic and implementation evidence for the same
co-designed protocol. It is not an independent proof of protocol security.

The parameter check decodes every embedded Rust affine point with Go's decoder
and compares canonical compressed encodings of all 256 G points and Q with
freshly generated Go CRS points. It records their concatenated SHA256. The
scalar script compares 24 runtime canonical little-endian encodings, the
post-proof challenge and IPA final scalar from each of the 12 scenarios, and
records each sample and their concatenated SHA256.
