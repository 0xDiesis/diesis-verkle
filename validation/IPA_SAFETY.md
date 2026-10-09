# IPA safety and compatibility

The protocol uses the degree-256 Banderwagon CRS, generator Q, point and
scalar encodings, transcript labels and ordinary proof bytes. Checked APIs
reject malformed dimensions, encodings, empty multiproofs, incoherent weight
tables, changed iterator replays and degenerate inverted challenges.

## Trust boundaries

Use `CRS::try_from_bytes`/`try_from_hex` for external parameters, or call
`CRS::validate` once before reusing a CRS. That verifies dimensions, curve and
quotient membership, identity exclusion and duplicate G/Q encodings. It cannot
establish that discrete logarithm relationships are unknown: trust the pinned
standard CRS generation procedure. Checked proving APIs validate dimensions
and on-domain claimed values; they assume valid typed points and that a
commitment belongs to its supplied polynomial. Recomputing every commitment
would defeat shared-polynomial proving and is a caller responsibility.

`Element::try_from_bytes_uncompressed`, canonical validated deserialization,
checked IPA/multiproof parsers and verifier query decoders accept only canonical
fields and valid quotient points. Legacy explicitly unchecked loaders, owned
prover inputs and raw-return FFI arithmetic remain trusted-input interfaces;
fallible Rust alternatives accept untrusted encodings. C bool verifiers
check null/length/remainder conditions and encoding errors. The caller still
must supply valid, live pointers to allocations of the declared length.

Discard a transcript after any checked API error. No challenge is resampled.
`t` in the evaluation domain, `t=z`, `w=0` and `x=0` fail closed; `r=0` and `r=1`
retain existing semantics. Though hash-derived degeneracy is negligible in
practice, all consensus participants must enforce the same rejection rules.
Compatible encodings alone do not establish consensus compatibility.

## Algebraic arguments

1. **Repeated polynomial/point aggregation.** With identical immutable shared
   polynomial P and position z, sum_i r^i P = (sum_i r^i) P by distributivity
   in Fr. Sum weights before visiting coefficients, then combine by z. Keys
   use polynomial reference identity and z; a claimed C alone does not identify
   a polynomial. Both ordered passes bind C/z/y and polynomial identity in an
   auxiliary SHA256 digest. Pointer identities never enter the proof transcript.
   Distinct references to equal polynomials are correct but miss this optimization.
2. **Grouped verifier E.** For h_i = r^i/(t-z_i), E = sum_i h_i C_i =
   sum_C (sum_{i:C_i=C} h_i) C. Full canonical 32-byte encodings identify quotient
   elements. Values contribute independently to g2 = sum_i h_i y_i. Invert each
   distinct nonzero t-z once. Generic Fr points are supported; memory is
   O(distinct C + distinct z + n), which can be O(Q) on all-distinct input.
   Clone is not a replay guarantee: both passes compare ordered C/z/y digests.
3. **Linear folding coefficients.** The reference fold is G_L + x^-1 G_R.
   Starting from [1], process inverse challenges in reverse order and append
   each existing coefficient times the new inverse. Induction on rounds gives
   s_i = product_j x_j^-1 for each set bit j of i in the original folding order.
   The final verifier uses -a*s_i and b0 = dot(b,-s). The bitwise reference
   oracle checks every coefficient for rounds0 through8 and both signs.
4. **Incremental transcript.** SHA256 update partitions do not change the
   hash of concatenated bytes. At a challenge, append its label, finalize/reset,
   reduce the digest as a little-endian scalar, then append label and canonical
   scalar bytes to the fresh hash. This matches hashing the concatenated transcript buffer.
   Buffered reference tests and pinned Go compare multiple challenge boundaries.
5. **Quotient validation.** For extended projective (X,Y,T,Z), require Z!=0,
   T*Z=X*Y and (aX^2+Y^2)Z^2=Z^4+dX^2Y^2. The affine Banderwagon membership
   condition is that 1-a*x^2 is a nonzero quadratic residue. Multiplying by Z^2
   preserves residuosity for Z!=0, so test Z^2-aX^2 without inversion. This
   accepts equivalent (x,y)/(-x,-y) representatives and both identity
   representatives; a prime Edwards subgroup check would overreject them.

These are conditional algebraic arguments and executable properties, not
machine-checked end-to-end soundness or a cryptography audit. Banderwagon
operations and the Fiat-Shamir security assumptions remain dependencies.
Variable-time MSM/proving is intended for public Verkle state, not secret
witnesses requiring constant-time processing.

## Validation

Run `cargo test --workspace`, `cargo fmt --all -- --check` and Clippy. Targeted
regressions include every compressed/uncompressed proof truncation, suffixes,
canonicality, malformed L/R/CRS/b lengths, overflow-sized rounds, valid quotient
representatives and off-curve/wrong-coset points, forced w/x/t and r0/r1,
iterator substitution, each proof field and changed values/commitments.
`application_scenarios.rs` checks opening/update scenarios using independently
written tests. `validation/go-ipa` pins the independent Go arithmetic
implementation and compares fresh proofs, commitments, D/E and challenges in
both directions. It is the same co-designed protocol, not an independent
protocol-security proof.

`hardening::bounded_decoder_fuzz_smoke` runs 2048 deterministic generated
inputs and all truncation seeds in routine tests. `validation/mutation_checks.py` runs positive controls then deliberately removes
length/shape/quotient/replay checks, omits transcript absorption, removes Q/b0,
flips a folding sign, and truncates both commitment-map insert and lookup keys.
The full-key test uses real valid colliding-prefix commitments. A longer campaign can increase
that count or use the parser entry points as cargo-fuzz targets. Coverage and
negative-control/mutation results must be reported separately; percentage
coverage is not a correctness proof.

## API contracts and protocol limits

| Interface | Contract |
| --- | --- |
| Borrowed queries | `ProverQueryRef` and `open_streaming` borrow immutable polynomial data; owned inputs provide independent ownership. |
| Proof parsers | Exact lengths and dimensions are checked before allocation, slicing and shifts. Parser errors use `std::io`; checked proving errors use `ProofError`. |
| Point validation | `Valid` and checked uncompressed decoding enforce Edwards equations and quotient membership. |
| CRS validation | Checked loaders validate G and Q together. Validation cannot establish unknown discrete-log relationships. |
| Lagrange evaluation | Domain points produce the corresponding Kronecker vector. |
| Folding and MSM | Folding coefficients use a linear recurrence; signed-window recoding serializes each nonzero scalar once. |
| C verification | Encoding and length guards reject malformed inputs; callers remain responsible for valid pointers and lifetimes. |
| Proof sizes | `MultiPointProof` defines compressed and uncompressed degree-256 sizes. |
| Point encodings | Big-endian compressed encodings and valid uncompressed quotient representatives are accepted. Equality uses canonical compressed bytes. |

Changing Q generation, transcript domain separators or statement absorption
changes the protocol and requires coordinated interoperability checks. The
library does not provide proof aggregation. Fixed-base tables, MSM windows and
parallel thresholds must be selected using measured setup and memory costs.

Raw-return foreign APIs assume trusted inputs. Error-reporting ABI changes and
Java lifetime management require compatibility across language bindings.
Application integration must validate witness fixtures, state/admission rules
and runtime behavior against the exact consumer revision. Library tests do not
establish application correctness or deployment readiness.
