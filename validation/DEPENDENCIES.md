# Dependency boundaries

`verkle-db` defaults to no disk backend. Its optional `rocks_db` feature selects
`rocksdb = "=0.19.0"`, which contains the upstream fix for
[RUSTSEC-2022-0046](https://rustsec.org/advisories/RUSTSEC-2022-0046.html).
The public `RocksDb` reexport includes multi-column-family TTL APIs. These require
one native TTL value per column family. The wrapper provides open, get and batch
operations.

RocksDB 0.19 uses the native RocksDB 7.4 engine. Existing databases require backup
and compatibility checks before opening them with a different engine version.
Native compilation requires a C++ toolchain and libclang.

## Storage tests

The optional-backend tests cover batch overwrite, persistence through reopen,
and multi-column-family TTL persistence, compaction and expiry:

```sh
cargo test -p verkle-db --features rocks_db --test rocksdb_hardening --jobs 2
```

## Dependency auditing

Audit the dependency resolution used by the consuming application:

```sh
cargo audit
```

The default IPA runtime dependency graph excludes RocksDB and atty. Other
dependency boundaries include:

- `atty` belongs to C header generation through cbindgen 0.26 and Clap 3.
  Its [unaligned-read advisory](https://rustsec.org/advisories/RUSTSEC-2021-0145.html)
  concerns Windows with custom global allocators.
- Arkworks 0.4 uses the `derivative` and `paste` procedural macros at compile time.
- The optional Sled backend uses `instant` and `fxhash`.

Review advisory and maintenance status against the exact downstream lockfile.
Dependency migrations must preserve arithmetic encodings, generated headers and
storage compatibility. A benchmark lockfile is not a deployment dependency policy.
