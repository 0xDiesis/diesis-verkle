# IPA multipoint

Polynomial commitments for opening multiple polynomials at different points
using the inner product argument. The group is
[Banderwagon](https://hackmd.io/@6iQDuIePQjyYBqDChYw_jg/BJ2-L6Nzc), constructed over
[Bandersnatch](https://eprint.iacr.org/2021/1152.pdf).

## Parameters and input contracts

The CRS generator hashes a seed and counter to point encodings and accepts valid
Banderwagon points. Q is the fixed prime-subgroup generator. Checked CRS loaders
validate dimensions, membership, identities and duplicate canonical encodings;
they cannot prove that discrete-log relationships are unknown.

Use checked parsers for external proofs and `CRS::validate` for external
parameters. Owned prover wrappers assume trusted inputs. Borrowed proving and
verification support replayable iterators, whose ordered contents must stay
identical across traversals. Polynomial/commitment correspondence is a caller
obligation. Discard transcripts after an error.

See [safety and compatibility](../validation/IPA_SAFETY.md) for protocol details,
conditional algebraic arguments and API limits. Production use requires an
independent cryptographic audit and application validation.

## Efficiency

Borrowed queries avoid polynomial copies. Repeated polynomial/position pairs
share aggregation work. Grouped verification uses one MSM point per distinct
canonical commitment and one inversion per distinct evaluation point.

MSM paths include Rayon parallelism. Workload size, setup cost, allocation and
memory must be considered when choosing an API. Use the
[performance harness](../validation/PERFORMANCE.md) for reproducible comparisons.
