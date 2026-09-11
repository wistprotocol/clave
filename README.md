# clave

The signed Delta format targets [WIST specification revision `8785c62e9e121037473d6144685fc547fa08a1b7`](https://github.com/wistprotocol/spec/tree/8785c62e9e121037473d6144685fc547fa08a1b7). Object version `1.0.0` alone does not identify a compatible draft.

Delta ingestion checks the signed canonical `publisher` against the logical Feed domain before source selection and duplicate suppression, including fetched predecessors. Chain tips use `(publisher, url)` and persist across reopen; the database upgrade preserves existing stored pairs but cannot reconstruct tips already overwritten by an older URL-only table. Sealing and recovery settlement reject mismatches between queue ownership and the signed author. Complete authenticated Delta history, recovery source selection and Audit Record eligibility remain separate validation requirements.

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

## Declaration key binding

Declaration admission rejects repeated key identifiers, including identical
entries, before resolving a signer. A replacement can reuse an old identifier
for a different public key: verification checks both the previous and incoming
bindings. Identity continuity follows the authenticated public key, so renaming
a signing key preserves ordinary rotation and renaming a recovery key preserves
its recovery authority. Recovery-set protection still applies. Public-key
aliases within one set remain permitted; signing/recovery overlap is rejected.

First-contact pulls apply the same checks before storing a Declaration. An
invalid first Declaration remains a WIST2-E04 pull rejection, with its specific
Declaration validation reason in the rejection detail.

Admission and Declaration history replay validate complete Envelope fields
before sequencing, conflicts, idempotence or signer resolution (WIST1-E14).
Checks include required and unknown members, optional nulls, safe integer
bounds, string lengths, release-version syntax, predecessor hashes, exact
Unicode 16 Canonical Host spelling, Publisher timestamps and canonical
unpadded base64url. Signed fields remain unchanged. All Declaration Entries
in a candidate Block receive these checks before any group installs; rejection
preserves the complete accepted state, including due recovery settlement.

Canonically encoded public bytes that do not decode to an eligible Ed25519
point are excluded from usable signing and recovery sets. Unused excluded keys
remain in the signed Envelope and do not prevent acceptance. Signer resolution
checks every usable named Declaration binding; no usable binding is WIST1-E02,
while usable bindings without a valid signature are WIST1-E01. Original entries
still determine identifier uniqueness, disjointness, hashes and recovery-set
protection. Shared Delta/Feed verification also rejects malformed key/signature
encoding and excludes unusable keys. Delta verification retains all supplied
named bindings, filters each by usability and its inclusive timestamp bound,
then accepts if any eligible binding verifies. No eligible binding is
WIST1-E02; eligible bindings with no valid signature are WIST1-E01. Reused
identifiers and public keys with different bounds cannot suppress a later
eligible binding, and signature success cannot borrow another key's bound.

Recovery queue admission retains complete pre-recovery and window-owner
Declarations, pairing each source's scope with its signing bindings. A Delta
must name that Publisher and verify under a usable, time-eligible binding in
a source that covers its URL host. Reused identifiers, shared public bytes and
differing timestamp bounds cannot transfer scope between sources. Later
followers change neither frozen admission source. Both Envelopes persist in
SQLite across restart; live Feed authentication still uses the current
Declaration's signing set.

`declaration::verify_delta_authority` checks already-selected, authenticated
Publisher sources. It derives time from signed `observed_at`, checks every
eligible binding before E01/E02, and returns E03 when no verifying source
covers the URL. URLs must already equal their protocol normalization; scope
compares canonical hostnames independently of a nondefault HTTPS port. Original
signed bytes remain unchanged. Admission, recovery settlement and sealing use
this check. Settlement maps binding/scope failure to E13; sealing preserves E03
for scope and E02 for stranded signing authority. Malformed checked fields
retain E14 in all three paths.

The signed `recovery-scope.json` probes derive sources from authenticated
Declaration histories, exercise exact timestamp bounds and reversed source
order, and compare reconstructed prefixes. Live tests cover crossed source
rejection, frozen sources through reopen, scope-only E13 settlement, survivor
publication, and ordinary scope revocation with an unchanged signing key.

Source selection and durable state integration remain incomplete. Sealing's
highest-sequence lookup still includes superseded competitors; recovery heads
advance on acceptance rather than only on sealing; admission does not yet
settle expired windows. Live predecessor evaluation must adopt both eligible
heads during an open window, then only the restored current head, while
preserving the accepted sequence floor. Dropped queue copies leave seen-ID
and chain-tip state that can obstruct permitted re-serving. Restoring a head
also enqueues a redundant Declaration re-serve; replay must retain idempotence
without a new installation, window or identity reset. These paths
require authenticated replay adoption and restart/retry tests before recovery
conformance can be claimed. Correct supplied-source checks do not establish
complete Delta chains, schema validation, Audit Record eligibility or sanctions.

Opening an older store restores missing owner Envelopes atomically. An opened
window requires complete authenticated Declaration history through the
operator-trusted database head, with a matching opening height and original
predecessor. A pending window requires exactly one distinct pending recovery
Declaration that authenticates against its stored predecessor. Missing,
ambiguous or invalid evidence stops opening; restore the original history or
pending entries before retrying. Migration never substitutes the evolving
chain head for the owner.

The signed `recovery-bindings.json` corpus exercises complete binding checks,
authenticated source reconstruction and owner migration. Live tests cover
followers, database reopen, admission diagnostics, settlement rejection and
actual survivor sealing. Full authenticated Delta chains, deadline-triggered
settlement during admission, signature-failure Declaration re-fetches, sealed
Feed key provenance and notice-era appeal authority remain incomplete.

Delta key-time checks compare `observed_at` and `valid_from` as instants,
including numeric UTC offsets and decimal fractions of arbitrary precision.
For example, `10:00:00.5Z` follows `10:00:00Z`; equal instants with different
fraction lengths or offsets satisfy the inclusive key bound. Ingest, sealing
and recovery settlement share this comparison. Timestamp strings remain
unchanged in signed Envelopes.

Publisher timestamps use the specified Gregorian clock: seconds 00–59, year
zero, arbitrary decimal fractions and numeric offsets, including arithmetic
beyond the written year range. Every leap-second label rejects with WIST1-E14;
validation needs no external leap table. Missing or malformed Delta
`observed_at` also rejects with WIST1-E14 before shared key verification.
Ingest compares each authenticated Delta with the validator clock plus the
`clock_skew_seconds` allowance in force at that instant (default 600 seconds).
The bound is inclusive, preserves every signed fractional digit, and supports
the Registry's signed integer range, including negative allowances. Rejection
is WIST1-E06 and leaves the Delta unseen, its chain tip unchanged, and its
Payload unstored; it enters neither pending sealing nor a recovery queue.
The same ID can succeed when retried after the clock advances, including
after reopening the database.

HTTP ingest and baseline polling sample the system clock separately for each
Delta, including fetched predecessors. `ingest::run_with_clock` accepts a clock
callback for controlled validation; its `now` argument remains a whole-second
Log timestamp for existing accounting and governance calls. `ingest::run`
uses that supplied instant as a fixed validation clock. Clock comparison uses
the full sampled precision; only parameter lookup floors to whole seconds,
because amendments take effect on that grid. Tests cover signed clock vectors,
zero and negative sealed amendments, exact activation, recovery queues and
restart/retry followed by sealing.

Full authenticated Delta chains and strict predecessor timestamp ordering
remain separate requirements. Log timestamps retain their distinct whole-second
profile. Binding and scope checks precede clock, chain and Payload checks;
WIST-1 §7 permits any established applicable semantic diagnostic after mandatory
field checks. Signed `publisher` determines attribution under WIST-1 §3.8.

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

Each file must contain exactly one standard Zstandard frame, with no
skippable frame or trailing data. Replay and legacy size restoration share
declared-size, frame-window and actual-size checks. Log timestamp parsing
rejects leap-second spellings without normalization and supports the complete
four-digit Gregorian range, from year zero through `9999-12-31T23:59:59Z`.
Conversion uses civil-calendar arithmetic; accepted parameter schedules still
determine which seconds are eligible sealing instants.

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

## Declaration history replay

`history::declarations::Declarations::reconstruct(directory, pinned_head)`
rebuilds Declaration sequence and author state from authenticated Block files.
It returns state only after reaching the trusted head successfully. Streaming
callers can instead pass each `History` result to `Declarations::apply`.

Replay preserves original Envelopes, publisher-object hashes, sealing times
and canonical Entry positions. Each domain’s equal-sequence groups apply in
ascending sequence after due settlement. Conflicting first installations or
failed Declaration acceptance reject the entire Block, preserving the previous
Declaration state and returning no effects. Idempotent current re-serves
install no signature and change no position. A streaming caller must stop and
discard its `History` reader after any Declaration-stage failure: that reader
has already advanced its separate Block/parameter state. Keep reconstructed
state and effects private until the complete pinned prefix validates.

Each domain retains its current Declaration, highest accepted sequence,
first-sealing position and latest fresh-identity reset position. An open
recovery window also retains its owner, original predecessor, current recovery
head and off-chain competitors. Its deadline uses the owner Block’s signed
parameter schedule and exact 128-bit arithmetic, surviving later amendments
and recovery followers. Settlement restores the recovery head without lowering
the sequence floor or resetting identity. Returned installation and settlement
effects identify resets, window openings and superseded competitors. They do
not apply database, queue or sanction changes.

`Domain::appeal_declaration()` selects the signing-key source after the current
Block’s Declaration stage. Callers must separately establish notice eligibility
and freeze that notice’s complete key bindings; this accessor does not validate
notices, appeals or appeal processes.

This API validates Declaration fields, sequencing and author authentication.
Deltas, Audit Records and non-parameter Registry Updates receive no eligibility checks here.
SQLite uses this state to restore missing owners of legacy opened recovery
windows. General live admission, sealing and database reconstruction still use
separate state; `verify-history` retains its Block/parameter verification scope. Snapshot
recovery state also requires the protocol’s unresolved Snapshot representation
rules. Successful reconstruction is not full protocol conformance.

Replay retains all domains’ current state and open-window competitors in memory;
atomic application stages a copy of the domain map while sharing immutable
Declaration Envelopes. It does not provide bounded-cache or Snapshot resume
behavior. Tests consume signed recovery ownership, predecessor, conflict,
identity, settlement and appeal-key histories, including corrupted or missing
history and signed recovery-parameter transitions.

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set. Building also
resolves `wist-core` from `../core` — both must be sibling checkouts.

## Known deviations

The following transport setting supports integration tests:

- **Plain HTTP to loopback.** `--allow-http` lets pulls and pings use
  `http` when the host is a loopback address, which WIST-2 §8 forbids
  for any `wist` resource. Without the flag every fetch is HTTPS, and
  the flag never relaxes the scheme for a non-loopback host.

Declaration identities are port-free Canonical Hosts. Integration fixtures
use signed `localhost` identities with an explicit DNS override to each
HTTP server's ephemeral socket. `fetch::Client::with_builder` and
`serve::run_with_client` allow transport configuration while retaining the
fetcher's timeout and redirect checks. A port-bearing signed Declaration
rejects with WIST1-E14 even when loopback HTTP is enabled.

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
