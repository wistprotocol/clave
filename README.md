# clave

WIST Protocol aggregator. Clave pulls signed deltas from publishers (via ping + the
publisher's `.well-known/wist` tree), verifies each one against its schema
and signature before admitting it, and seals them hourly into a public,
hash-chained, append-only log — the Certificate Transparency model applied
to a web index. It also serves the log, checkpoints, and periodic snapshots
over HTTP for consumers to sync against.

Subcommands: `init` (generate the log's genesis key and local store),
`serve` (HTTP ingest + read endpoints), `seal` (cut the next Block from
pending entries and chain it), `snapshot` (build a signed, verifiable
point-in-time index for cold-start sync).

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set. Building also
resolves `wist-core` from `../core` — both must be sibling checkouts.

## Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## Spec

Protocol definitions live in the sibling [spec repo](../spec) — WIST-3
(logbook & distribution: blocks, Merkle proofs, checkpoints, snapshots) is
what Clave implements, on top of the WIST-1 deltas it ingests.
