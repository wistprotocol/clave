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
point-in-time index for cold-start sync), `param-change` (queue a signed
`parameter_change` Registry Update, WIST-4 §9: bounds and combination
rules checked, `effective_at` held past the grace period, applied to the
live parameter set once its Block seals and the effective instant passes;
a change whose grace window lapses while queued is dropped from the Block
and reported by `seal`), `sanction` / `rule` / `lift` (WIST-4 §7 ladder:
a level 3/4 sanction seals its notice first; rulings and lifts close or
clear the process; in-force state honors the lapsed-deadline void rules),
`withdraw` (payload withdrawal: deletes the Payload, drops the record,
stops serving snapshots that still contain it), `poll-appeals` (fetches
every sanction notice's appeal path despite the 403, seals served appeals
or an unappealed ruling once the window closes; also run by `serve`'s
baseline pass), `mirror` (maintain the signed `/log/mirrors.json`).

`serve` additionally enforces the reputation-derived ping quota (429 +
Retry-After; only WIST2-E02/E04 pings count as noise), rejects quarantined
and delisted domains with 403, and runs a baseline pass every minute that
re-pulls stale or budget-suspended publishers without a Ping. Ingest
follows feed pages (WIST-2 §3.2) under the per-domain daily byte budget,
suspending and resuming across days.

Ingest re-fetches each known publisher's Declaration and validates the
chain (WIST-1 §5.2: `seq`/`prev_declaration` monotonicity, recovery-keys
protection, signer classification into ordinary rotation, recovery
rotation, or fresh identity — WIST1-E08 otherwise), and verifies every
delta against the full declared key set (`sig.key_id` membership and
`valid_from`; WIST1-E01/E02). A recovery rotation opens the WIST-1 §5.2
recovery window at its sealing Block (a `notice` with `details.kind`
`"recovery"` is sealed alongside, and the open window appears in snapshot
state): the domain's deltas queue instead of sealing, declarations signed
by superseded keys are rejected, and the first Block at or past the
window's end settles the queue — survivors seal in acceptance order,
failures surface as WIST1-E13 on the status endpoint. Snapshots carry tier0 SQLite and
tier1 Parquet (extracts + link graph), optionally sharded
(`snapshot_shard_count` in the local params table).

## Parameter schedules and Block sizes

Parameter admission checks the accepted schedule and queued amendments in
canonical Entry order. Sealing repeats validation at the actual Block
instant: delayed or conflicting amendments are dropped with WIST4-E03.
Every prospective map is checked, including grace changes and cadence
transitions that could outlive an older extension window.

Caps cover the largest complete JCS Block through each amendment's own
height. Pending reductions constrain packing immediately; deferred Entries
remain queued. SQLite stores actual Block sizes and canonical Entry
positions with the sealed changes. Restart replays the accepted schedule
using each historical size maximum, and rejects a history containing a
Block that exceeded its accepted schedule. Snapshot parameter tuples
include pending amendments and omit superseded equal-effective-time values.

Opening an older store reconstructs missing sizes and positions from its
Block files, checking the stored chain commitments and signatures. Verified
legacy files are re-encoded as canonical JCS without changing Block objects,
hashes or signatures. Missing or invalid history stops migration; restore
the original Blocks before reopening the store. Migration verifies
signatures against the stored Log Anchor's genesis public key; it requires
no private key.

Schedule validation uses the protocol's Registry defaults. Direct local
parameter overrides, including the accelerated `--cadence` setting, do not
amend that schedule and must not be used to assert protocol conformance.

## Authenticated history

`clave verify-history --data <directory>` authenticates stored Block files
from genesis through the database's current head. It needs the public
`anchor.json`, not the private signing key. The directory's Anchor and
database head are operator-trusted inputs; this command does not discover
newer Checkpoints or detect replacement of both trusted inputs.

The reader checks signatures, Merkle roots, Entry counts and canonical
positions, chain links, whole-second timestamps, the cadence grid, and
canonical JCS file bytes. It reconstructs accepted parameter schedules from
signed Envelopes, independently of the database's parameter summaries and
local overrides. Each Block's transport bound comes from the verified
prefix; current and pending caps constrain its actual size. Invalid
parameter candidates are reported by canonical Entry index and change no
schedule. Missing or corrupt history stops verification.

The `history::History` API exposes each authenticated Block's complete
Entries, original Envelopes, height, timestamp and canonical positions, plus
the accepted parameter schedule. It holds one Block at a time and retains
the accepted schedule; it currently reads each compressed file into memory.
Callers must finish iteration successfully before committing a reconstructed
state: the supplied head's hash binds the complete prefix only when its
Block is reached. A failed reader cannot resume, and Blocks sealed after
opening the reader are outside its pinned prefix.

Supported histories use object version `1.0.0` and the genesis signing key.
Log key transitions and successor Anchors stop the reader as unsupported.
Authentication establishes Block inclusion; it does not establish an
Entry's author, Audit Record eligibility, or correct derived reputation and
sanctions. Parameter Envelopes receive their own signature and admission
checks. Other Entry validation and service state reconstruction remain
separate from this command; successful history verification is not full
protocol conformance.

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set. Building also
resolves `wist-core` from `../core` — both must be sibling checkouts.

## Known deviations

The following settings support local integration tests:

- **Publisher identity carries a port.** WIST-1 §2's Canonical Host has
  no port, and this codebase treats a Publisher's identity as a bare
  `host[:port]` authority throughout, so several publishers can be
  served from loopback at once. On a public deployment every identity
  is portless and the two readings coincide.
- **Plain HTTP to loopback.** `--allow-http` lets pulls and pings use
  `http` when the host is a loopback address, which WIST-2 §8 forbids
  for any `wist` resource. Without the flag every fetch is HTTPS, and
  the flag never relaxes the scheme for a non-loopback host.

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
