# clave

The signed Delta format targets [WIST specification revision `3dd2e8e97847e77d09de6d9b529d0c03d3766098`](https://github.com/wistprotocol/spec/tree/3dd2e8e97847e77d09de6d9b529d0c03d3766098). Object version `1.0.0` alone does not identify a compatible draft.

Delta ingestion checks the signed canonical `publisher` against the logical Feed domain before source selection and duplicate suppression, including fetched predecessors. Chain tips use `(publisher, url)` and persist across reopen; legacy index restoration is described under [Delta index reconciliation](#delta-index-reconciliation). Sealing and recovery settlement reject mismatches between queue ownership and the signed author. Complete authenticated Delta eligibility and Audit Record derivation remain separate validation requirements.

WIST Protocol aggregator. Clave pulls signed Deltas from Publishers through
ping + pull, validates them, and seals hourly hash-chained Blocks. It serves
the Log, Checkpoints and periodic Snapshots over HTTP for Consumer sync.

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
`"recovery"` is queued for inclusion, and the open window appears in snapshot
state): the domain's deltas queue instead of sealing, declarations signed
by superseded keys are rejected, and the first Block at or past the
window's end settles the queue — survivors become eligible for sealing,
failures surface as WIST1-E13 on the status endpoint. Snapshots carry tier0 SQLite and
tier1 Parquet (extracts + link graph), optionally sharded
(`snapshot_shard_count` in the local params table).

## Delta field validation

`declaration::delta::validate_fields` enforces WIST-1 §7's complete Delta
Envelope field checks before Feed association, authority or signature use.
`validate_version` applies those checks, then rejects unsupported majors with
WIST1-E15. It supports major `1`, preserves minor/patch components without
numeric conversion, and is used by Delta signature verification and
`validate_static`. The latter also checks content/predecessor presence and
URL/commitment caps. Its caller supplies valid stage-specific caps; the helper
does not authenticate parameter profiles. Live ingestion supplies effective
caps at its validation clock, including the derived commitment cap.

Typed ingestion reads a canonical temporary copy so integral decimal numbers
remain admissible; stored and verified signed objects retain their original
values. Rejected Deltas receive persistent typed status entries without
recording accepted IDs, changing URL tips or writing Payload files. Sealing
retains E15 for unsupported queued Deltas and releases their accepted indexes.

`delta-fields.json` exercises field/version boundaries and diagnostic
combinations. Live tests cover persistent rejection, active caps, decimal
byte counts, fetched unsupported predecessors and signed version preservation
across duplicate pulls, restart and sealing. These checks do not establish
complete authenticated Delta history or other objects' version support.
Live Declaration retries are described below.

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

Replacement admission retains the highest accepted sequence separately from
the current Declaration. Recovery restoration cannot lower that floor; a
well-formed re-serve of the current publisher object remains idempotent even
below it. Declaration, floor, pending Entry and recovery-head writes share a
SQLite transaction. Database upgrades reconstruct missing floors from the
authenticated pinned Block prefix and retained current/pending admission rows;
corrupt history rejects restoration before any floor is written. Retained
admission rows are local accepted state, not authenticated Log inclusion.

Only an accepted replacement or a valid unchanged re-serve renews the cached
Declaration's discovery timestamp. Rejected or unavailable responses preserve
that timestamp; after attempted discovery, an expired cache stops the pull
with WIST1-E02 before fetching the Feed. Restart preserves the same expiry
basis. Initial, periodic and failure-triggered Declaration requests are outside
the content byte budget under WIST-2 §5/ADR-0031; exhausted content fetching
still suspends the walk.

A failed live `feed.json` signature triggers one Declaration re-fetch under
WIST-2 §5. Replacement admission uses the same transaction, sequence floor and
recovery rules as periodic discovery. The same fetched Feed is checked
again against the resulting current keys; a remaining failure records one
WIST2-E04 pull rejection. This includes first-contact rotation races. An invalid
replacement cannot supply Feed authority or renew the cache.

A live Delta E01/E02 binding failure triggers one authenticated Declaration
retry per requested ID per pull, independently of Feed retries. Both authority
checks use post-settlement admission sources and the same attempt set;
predecessor retrieval and reinsertion cannot grant another attempt. The same
Delta Envelope is reverified, including scope. Invalid fields and foreign
Publisher association reject before binding checks. Invalid or unavailable
refreshes consume the attempt; a later pull can retry the ID again.

`declaration-refresh.json` supplies 30 signed transport cases consumed through
live HTTP, including ordinary rotation, reused identifiers, absent, excluded
and future bindings, separate Feed/Delta/predecessor attempts, unsuccessful
responses, sealed Page sources and content-budget boundaries. Additional tests
cover recovery, frozen sources, settlement during Payload fetching, cache expiry,
rollback and restart. Page authority is described under
[Page source verification](#page-source-verification); the content budget
does not bound Declaration traffic.

During recovery, a replacement may name either the current Declaration or
the accepted recovery-chain head. Its named predecessor determines signer
classification and recovery-key protection. Only an ordinary or recovery
rotation naming the recovery head advances that chain. Admission rebuilds
the head from authenticated sealed history and pending followers, preserving
unsealed continuations after partial packing and ignoring stale head summaries.
Pending recovery owners are verified against their retained predecessor.
This admission head does not replace the sealed authority used to settle
queued Deltas.

Before admission, `recovery::settle` authenticates the pinned Block prefix and
closes due windows. It restores the accepted recovery head, retains legitimate
pending followers and the sequence floor, and removes pending competitors and
their descendants. Queued Deltas are revalidated against the distinct sealed
head. Queue, rejection, seen-ID, Publisher-URL tip, current Declaration and
per-owner settlement-marker changes commit atomically. Markers survive reopen
and prevent later pulls or sealing from overwriting subsequent admissions.
Pulls that cross a deadline refresh authority before Declaration admission,
Delta verification and final queue insertion. The entry point replays the full
prefix on each pull; bounded replay state and crash recovery across database
and published files remain separate requirements.

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

Every seal reconstructs Declaration state from the complete authenticated Block
prefix pinned by the database head before using recovery sources. Settlement
uses the last recovery follower sealed inside the window, before the candidate
Block's Declarations. Delta sealing uses the Declaration state projected from
the Entries actually selected under the byte cap. A superseded competitor's
higher sequence cannot displace the restored recovery head; an unsealed
follower cannot change settlement authority. A deadline-Block replacement can
still invalidate a settlement survivor with sealing E02 or scope E03.

Declaration packing considers each domain's ascending sequences and defers a
successor when its pending predecessor does not fit. Selected Entries are then
stored in canonical type/leaf order and validated atomically. The final
Declaration projection is recomputed after Entry filtering. Recovery lengths
come from the authenticated schedule at the candidate instant, and existing
window ends remain frozen. Successful seals refresh stored recovery heads and
frozen sources from the projected state, without synthesizing a re-served
Declaration at settlement. A retained recovery-signed follower first sealed
after the deadline can own a new window; later Entries use that projection.
Sealing rejects a cadence slot before a completed admission settlement's
deadline, preserving closure until a valid deadline slot is available.

Database mutations for a seal share one transaction, including queue movement,
status rejections, stored recovery state and the committed Block head. A failed
Declaration candidate rolls those changes back. Missing or corrupt pinned
history stops sealing before settlement. Block/checkpoint file publication and
Snapshot generation do not share SQLite's transaction; crash recovery across
those stores remains a separate requirement. The history reader also rejects
prefixes produced off the signed cadence grid by local cadence overrides.

Admission's predecessor choices, accepted sequence floor and deadline
settlement are described at the start of
[Declaration key binding](#declaration-key-binding).

Pending and recovery copies share a persistent acceptance counter. Queue
transfers retain that order and clear pre-window inclusion turns; every pending
copy enters recovery when its window opens, including copies excluded by either
Block cap. Settlement survivors become eligible in acceptance order, with the
per-domain capacity determining their turns from the deadline onward. Rejected
copies release their seen IDs and rewind Publisher/URL tips to surviving
predecessors; accepted descendants of a rejected copy receive WIST1-E07. These
changes and status rejections commit together, allowing the same signed Deltas
to be re-served under later eligible authority after restart.

Legacy queue rowids cannot establish original acceptance order: earlier
transfers could insert copies in leaf order and propagate that order back to
pending entries. An upgrade with multiple outstanding Deltas for one domain
and missing acceptance positions stops without assigning positions or deleting
copies. Restore independently retained admission-order evidence before
reopening; do not infer positions from queue rowids, leaf hashes or observation
timestamps. Stores with at most one outstanding Delta per domain can upgrade
without deciding an unknown within-domain order. For already-discarded copies,
see [Delta index reconciliation](#delta-index-reconciliation).

Exact recovery ends outside the supported timestamp range stop sealing before
publication; full-range Snapshot representation requires specification resolution.
Correct sealing source selection does not establish complete recovery admission,
Delta chains, schema validation, Audit Record eligibility or sanctions.

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
actual survivor sealing. `recovery-admission.json` also exercises all eleven
signed pending-Declaration cases through SQLite reopen, exact deadline
settlement, repeated calls and candidate projection. Live tests cover new
post-deadline admissions, retained followers opening another window, injected
transaction failure and cadence rounding after admission closure.
Full authenticated Delta chains, signature-failure Declaration re-fetches, sealed
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

Log timestamps retain their distinct whole-second profile.
Binding and scope checks precede clock, chain and Payload checks;
WIST-1 §7 permits any established applicable semantic diagnostic after mandatory
field checks. Signed `publisher` determines attribution under WIST-1 §3.8.

## Page source verification

Sealed Page keys come from the complete authenticated Block prefix pinned by
the database head, using WIST-2 §3.2's current and first-next Declaration
cutoffs. Accepted unsealed Declarations supply no Page authority; first-contact
and rotation Pages can require another pull after their Declaration seals.
The `sealed_declarations` database summary supplies no verification evidence.

Declaration replay authenticates every source and excludes competitors when
recovery settles in that prefix; admission-time settlement alone changes no
Page source. Repeated idempotent Declaration
Entries retain their own Block times; the first-next search cannot skip them
to borrow a later rotation. Each selected source retains its complete signing
bindings, including reused identifiers. Missing or invalid pinned history
stops the pull before Page-derived Deltas enter admission. Trust inputs and
unsupported history transitions follow [Authenticated history](#authenticated-history).

Signed HTTP/restart tests cover unsealed-to-sealed authority, retired and reused
keys, alias renames, multiple Declarations in one Block, idempotent repetitions, recovery
supersession and forged or absent database summaries. Reconstruction runs once
when a pull first reaches a sealed Page and retains that prefix for the walk;
bounded replay/cache work remains unimplemented.

A failed Page signature uses WIST-2 §5's shared Feed/Page Declaration retry
if the live Feed has not consumed it. The original Page is rechecked against
the same authenticated prefix; an accepted unsealed replacement cannot
authorize it. Failure records WIST2-E04 even at the content-budget boundary.
Signed transport cases distinguish shared attempts, invalid/unavailable
responses, retired and first-next sources, unsealed and later-source
exclusion, and independent Delta retries. A restart regression preserves the
discovered rotation, renews the next pull's attempt and admits the unchanged
Page only after its authorizing Declaration seals.

Complete Feed fields/timestamps and durable selected-source provenance remain
incomplete. WIST-2 §3.2 named-entry fallback is covered by
all 16 signed `page-bindings.json` probes, including excluded entries and
rejection of aliases or public bytes available only from a later source.

## Delta predecessor admission

Ingest requires each Delta naming the accepted Publisher/URL tip to have a
strictly later signed `observed_at`, using the exact Publisher timestamp
comparison in WIST-1 §3.4. Equal instants, including equivalent offsets and
trailing fractional zeros, reject with WIST1-E07. Rejection leaves the ID
unseen, the tip unchanged and the Payload unstored; neither queue receives it.

An unseen predecessor is fetched into the same admission loop before its
links are followed. Each fetched Envelope receives its own validation and
rejection disposition, even when an older predecessor is unavailable or its
chain cannot join the requesting Delta's Publisher/URL tip. Valid predecessors
enter their own chains before descendants. An unavailable predecessor rejects
otherwise eligible fetched dependents with WIST1-E07; content-budget exhaustion
suspends the pull without concluding unavailability. Fetched Envelopes are reused within that
attempt; later pulls can retrieve rejected or suspended chains again.

The predecessor Envelope comes from retained pending/recovery admissions or
the complete authenticated Block prefix pinned to the database head. Lookup
checks its Delta ID; comparison also checks Publisher and URL ownership.
Materialized record timestamps supply no comparison authority. Unsealed
Envelopes remain trusted local admission state. Missing accepted evidence or
invalid Block history stops the pull; the sealed lookup validates the entire
pinned prefix before returning an Envelope. See
[Authenticated history](#authenticated-history) for its trust inputs and limits.

`declaration::verify_delta_predecessor` checks current Publisher/timestamp
fields, predecessor ID and ownership, and strict observation ordering. Callers
must separately establish both Envelopes' eligibility and predecessor
acceptance; this helper does not verify signatures, retrieve Deltas, establish
Log positions or select the canonical chain tip.

Signed `declaration-fields.json` relation cases and live tests cover exact
fractions, offset equality, both queues, restart, sealed evidence despite altered
materialized timestamps, fetched predecessors, missing older links, independent
URL chains, budget suspension/resumption and corrupt history. Lookup scans
retained domain admissions and, when needed, the full pinned Block prefix for
each predecessor; bounded lookup and complete authenticated Delta replay remain
separate requirements. Existing accepted or sealed chains receive no retroactive
timestamp revalidation from this admission check.

## Delta index reconciliation

Opening a store without a completed reconciliation marker rebuilds seen IDs
and Publisher/URL tips from its complete authenticated Block prefix and retained
pending/recovery admissions. This removes orphaned IDs left by discarded copies
and restores pairs overwritten by the former URL-only table. The Anchor and
database head are operator-trusted inputs, as in [Authenticated history](#authenticated-history).

Every retained Envelope passes the field and version checks in
[Delta field validation](#delta-field-validation). A `new` or `update`
without a `payload` commitment stops restoration with WIST1-E09;
an `update`, `delete` or `attest` without `prev` stops it with WIST1-E07.
Field/version checks run first. Sealed sources come from Declaration replay
at each Block. Restoration checks Delta signing bindings,
key-time bounds and scope, then follows predecessor
links within that Block. Retained unsealed copies follow persistent acceptance
positions across both queues; their Envelopes remain trusted local admission
state, without Log authentication or renewed authority, clock or Payload
checks. They must agree with their stored ownership, ID and URL and extend
their pair's tip.

Every successor, sealed or unsealed, must have a strictly later signed
`observed_at` than its predecessor under WIST-1 §3.4's exact comparison.
Equal instants and decreasing times stop restoration with WIST1-E07.
The predecessor time follows its Publisher/URL chain through Declaration
changes and identity resets; materialized record timestamps supply no authority.

Missing or corrupt history, unsupported versions/key transitions, invalid
sealed authority, duplicate IDs, forks, disconnected chains or invalid
acceptance positions stop restoration. Restore missing original Envelopes or
independently retained acceptance-order evidence and reconcile invalid retained
copies before retrying. No order is inferred from leaf hashes or timestamps.
Original Envelopes lacking the signed `publisher` cannot be translated during
restoration; their attribution requires separate resolution.

Index replacement and its completion marker commit under one SQLite write
transaction after the pinned prefix validates. Failure preserves both indexes;
retry repeats restoration. Subsequent opens skip this completed repair. Queues,
Payloads and rejection history are preserved. The repair retains all seen IDs
in memory plus each tip's signed observation time. It does not establish
complete Delta eligibility, governance replay, general legacy-state revalidation
or crash-safe publication. Historical size-cap selection awaits the temporal
anchor resolution in specification `CONFORMANCE.md`; no current/default cap
is substituted during restoration.

Signed restart tests cover chain and ownership restoration, preserved versioned
Envelopes across all three stores, field/version diagnostic precedence,
exact predecessor times, shared-URL identity resets, corrupt history, invalid
authority and atomic failure. Signed `delta-fields.json` missing-content and
missing-predecessor cases exercise all three stores, retry and Envelope
preservation; additional chains distinguish contentless successors from
invalid content-bearing entries. The signed `declaration-fields.json` predecessor
cases exercise same-Block chains, successive Blocks, sealed-to-queue transitions
and both queue orders.

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

`Declarations::project(sealed_at, recovery_window_days, entries)` evaluates
one proposed next Block without changing the accepted prefix. Pass its complete
Entries in canonical storage order after packing, and the recovery-window
parameter from the authenticated schedule in force at that proposed instant.
The method validates the parameter's value, timestamp profile and forward
ordering, Entry wrappers/order, and Declaration fields, authors and acceptance.
It does not authenticate the supplied parameter profile, check the cadence or
Block size, or validate other Entry bodies. A successful projection is therefore
conditional on those checks. Recompute it if the timestamp, profile or selected
Entries change.

The returned `Projection` exposes proposed domain state and effects, without
an accepted head or a way to install it as authenticated history. Its Declaration
positions, sealing times, identity resets and window openings are prospective.
Only `apply(VerifiedBlock)` advances replay, using the same transition logic.
Projection failure exposes no state or settlement effects. An unsealed follower
cannot change the accepted recovery head, sequence floor or future settlement.

`Domain::delta_admission_sources()` returns the frozen predecessor and owner
while that state's window is open, otherwise its current Declaration.
`delta_sealing_source()` returns no source during an open window, because its
Deltas must queue. At a deadline, `Projection::effects().settlements` retains
the sealed recovery head used to revalidate existing queued copies before any
candidate Declaration applies. The projected domain's sources reflect all
candidate replacements afterward. A deadline-Block replacement can therefore
change sealing authority without changing the queue's settlement authority.
These accessors describe the supplied prefix or projection; they do not refresh
live admission state, settle SQLite queues, or perform Delta eligibility checks.

Signed recovery probes exercise candidate rejection, retained sequence floors,
unsealed follower isolation, deadline boundaries, distinct settlement/sealing
scope and restart reconstruction. Live sealing consumes these projections
after packing and filtering. Live admission still requires integration with
durable queue, status and chain-tip updates, including preservation of
acceptance order across queues.

`Domain::appeal_declaration()` selects the signing-key source after the current
Block’s Declaration stage. Callers must separately establish notice eligibility
and freeze that notice’s complete key bindings; this accessor does not validate
notices, appeals or appeal processes.

This API validates Declaration fields, sequencing and author authentication.
Deltas, Audit Records and non-parameter Registry Updates receive no eligibility checks here.
SQLite uses this state to restore missing owners of legacy opened recovery
windows. Live sealing reconstructs and projects this state for source selection;
general admission and database reconstruction still use separate state.
`verify-history` retains its Block/parameter verification scope. Snapshot
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
