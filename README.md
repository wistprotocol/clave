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
does not authenticate parameter profiles. Profile selection follows
[Delta size-cap profiles](#delta-size-cap-profiles).

Typed ingestion and record materialization read canonical temporary copies so
integral decimal/exponent byte counts remain admissible through fetched chains,
restart and sealing; retained Envelopes and Payload files remain unchanged.
Rejected Deltas receive persistent typed status entries without
recording accepted IDs, changing URL tips or writing Payload files. Sealing
retains E15 for unsupported queued Deltas and releases their accepted indexes.

`delta-fields.json` exercises field/version boundaries and diagnostic
combinations. Live tests cover persistent rejection, active caps, decimal
byte counts, fetched unsupported predecessors and signed version preservation
across duplicate pulls, restart and sealing. These checks do not establish
complete authenticated Delta history or other objects' version support.
Live Declaration retries are described below.

## Delta size-cap profiles

WIST-1 §3.6 and ADR-0020 determine size-cap timing. Ingestion reconstructs the
pinned authenticated schedule when each fetched Delta begins validation and
retains its five caps through Declaration refresh, predecessor retrieval,
Payload validation and admission rechecks. Predecessors and attempts after
rejection or restart obtain fresh profiles. The same captured clock and
authenticated schedule supply [Delta clock eligibility](#delta-clock-eligibility).
Local parameter overrides and amendment summaries cannot replace either profile.

Sealing checks each candidate Delta and its stored Payload against the
candidate Block's authenticated profile. Pending amendments apply only from
their effective instant. Delta URL/declared-byte failures retain WIST1-E11/E04;
Payload cap failures use WIST2-E03 during pulls and WIST1-E04 at sealing.
Sealing removes rejected copies and dependent successors under
[Declaration key binding](#declaration-key-binding). Missing or
invalid stored Payloads follow [Retained Payload validation](#retained-payload-validation).

`VerifiedBlock::delta_size_caps` retains the committing Block's profile for
later Payload or reference validation. `SizeCaps::validate_payload_sizes`
measures original JSON values in JCS octets; callers must separately validate
Payload fields and integrity. Index restoration checks sealed Delta URL and
declared-byte caps against each Block's profile. It does not retrieve historical
Payloads or recalculate completed unsealed admissions' original profiles.

`delta-cap-time.json` exercises authenticated histories, stage boundaries,
reference profiles and invalid candidate Blocks. Live regressions cover
Payload/predecessor timing, repeated rejected IDs, restart, dependent rejection,
missing/corrupt Payload rollback and signed authority despite changed local
summaries. Full-prefix reconstruction per attempt remains unbounded.
[Historical Payload retrieval](#historical-payload-retrieval) preserves these
profiles; Audit Record integration remains required.

## Payload link admission

Ingestion enforces WIST-1 §3.6's WIST1-E12 checks before retaining a
Payload or accepting its Delta: URL uniqueness, byte-identical normalization,
external-host membership and `len(urls) <= total`. Externality uses the
Delta's authenticated signed Publisher, including for scoped subject URLs;
Declaration scope does not redefine internal links. A failed Payload rejects
the pull with WIST2-E03, leaving its ID retryable, its chain tip unchanged
and its content unstored. Fetched predecessors undergo the same checks.

`payload::validate_links` requires typed links and an already validated
Canonical Publisher host. It checks neither fields, commitments nor size
caps. It preserves URL order and accepts an incomplete prefix even when
more links could fit: only a page audit can verify the declared prefix.

`payload-links.json` supplies 31 signed commitment-valid probes. Live tests
cover their pull dispositions, restart, accepted-byte preservation through
sealing, scoped subjects and rejection of a retrieved predecessor.
Field/version admission and retained validation are described below;
historical validation remains outstanding.

## JSON input eligibility

Fetched protocol JSON and retained object reads reject duplicate decoded member
names before field, identity, signature or replay checks, including escaped
names and nested objects or arrays (WIST-1 §4, RFC 8785 §3.1). This covers
Declaration, Delta, Feed/Page, Payload, Log Anchor, Block, governance, Mirror
and Snapshot inputs. Fetches retain the role-specific WIST-2 rejection wrappers;
history readers stop on failure. Queue drains parse every selected Entry before
deleting any, preserving malformed bytes and other queued work on rejection.

Parsed-Value APIs require callers to validate raw JSON before constructing the
Value; discarded duplicate members cannot be recovered. These checks do not
establish complete object eligibility or revalidate all existing state at open.
`json_inputs` and `history` tests cover signed last-value duplicates, field and
signature precedence, retry/restart, retained queues and history authority.

## Payload field and version admission

Ingestion applies WIST-1 §§3.1/3.6/7 and ADR-0030/0034 before commitment,
link or size checks. `payload::validate_json` exposes the raw gate described in
[JSON input eligibility](#json-input-eligibility), rejecting malformed JSON,
invalid Unicode, nonfinite numbers and duplicate members with E05.
`payload::validate_fields` checks parsed JCS eligibility and complete fields;
`payload::validate_version` adds supported-major validation after E14 field
precedence. Callers separately check links, integrity and active caps. Pulls
retain the WIST2-E03 disposition in [Payload link admission](#payload-link-admission).

Canonical parsing during ingestion and record materialization accepts
integer-valued decimal/exponent forms without changing stored Payload bytes.
Same-major minor/patch components have no numeric bound and need not match
the Delta's version. Active octet caps govern extract and URL lengths;
summary scalar limits remain independent of its octet cap.

`payload-fields.json` supplies 128 signed candidates, consumed independently
of the Python reference. Live tests exercise 103 default-profile candidates,
restart, fetched predecessors, same-ID retry after version rejection,
record materialization and original-byte preservation through sealing.
Field vectors supply cap contexts; [Delta size-cap profiles](#delta-size-cap-profiles)
covers authenticated profile timing. Historical copies use
[Historical Payload retrieval](#historical-payload-retrieval); full Audit Record
eligibility remains incomplete.

## Retained Payload validation

Sealing validates each candidate's retained Payload fields, version, commitment,
exact content length, links and candidate-Block caps before publication. Missing,
unparseable or invalid retained content aborts the transaction, preserving
queued Envelopes, seen IDs, chain tips and rejection history for repair and
retry. Size-cap failures retain the exclusion and successor handling under
[Delta size-cap profiles](#delta-size-cap-profiles). A local Payload mismatch
does not reject its signed Delta (WIST-1 §7).

Record materialization repeats validation when reading content and aborts on
failure before publishing the Block or Checkpoint. Accepted Payload files and
signed Envelopes retain their original bytes; successful retry after repair
materializes the retained chains.
Crash-safe publication and concurrent filesystem mutation remain outside this
validation contract.

`payload::validate` applies the same complete checks during ingestion and
sealing and returns a typed Payload from a canonical temporary copy. Callers
supply an eligible Delta's commitment, authenticated Publisher and
stage-specific caps; the helper establishes neither Delta eligibility nor
parameter provenance. Raw-input requirements follow
[JSON input eligibility](#json-input-eligibility).

Signed field vectors exercise the helper's permitted diagnostics and retained
queue failures through restart. A same-length content substitution regression
checks atomic failure, preserved dependent and independent chains, and repair
before successful sealing. Previously sealed Payloads and recovery-held copies
that are not candidates receive no new validation from these checks.

## Delta clock eligibility

WIST-1 §3.4 and ADR-0020 govern clock selection. Ingestion captures one
validator clock and authenticated allowance when each fetched Delta begins
validation. Declaration retries, Payload retrieval and waiting for predecessors
retain that attempt; a predecessor starts its own. Rejection or restart permits
a new attempt. Mutable parameter summaries cannot replace the signed schedule.

Sealing repeats the check against the candidate Block's `sealed_at` and
allowance. WIST1-E06 rejections release the queued copy and dependent successors
through [Declaration key binding](#declaration-key-binding), allowing later
pulls to retry. Historical Delta replay and sealed index restoration use each
committing Block's time and allowance. `VerifiedBlock::clock_skew_seconds()`
and `DeltaSource::clock_skew_seconds()` expose the authenticated value; a
verified Block alone still establishes no Delta eligibility.

The exact inclusive comparison preserves arbitrary Publisher timestamp
fractions, signed allowances and bounds outside the written year range.
Later Blocks, parameter amendments or wall time cannot repair a clock-invalid
sealed Delta. Historical failure stops the complete pinned reconstruction
without a partial result, following [Historical Delta sources](#historical-delta-sources).
Completed index repairs still skip rebuilding; this is not general legacy-state
revalidation, Consumer ignored-Entry replay or proof of the Log clock's accuracy.

`delta-clock-time.json` supplies 96 signed clock probes, exercised with
authenticated parameter histories. Signed Delta histories cover committing
profiles, rejected amendments, later Blocks, restart and corrupt-file repair.
Live tests exercise fractional rejection across Declaration refresh, fresh
attempts after restart, predecessor waits and queued chains crossing a reduction.

## Historical Delta sources

`history::deltas::DeltaSource::reconstruct(directory, pinned_head, delta_id)`
returns one included Delta only after authenticating the entire pinned
Block/parameter and Declaration prefix and checking every included Delta's
fields, version, committing size caps, [clock eligibility](#delta-clock-eligibility),
historical authority and predecessor chain. Authority uses [Declaration history replay](#declaration-history-replay)
and [Declaration key binding](#declaration-key-binding); trust inputs and
unsupported transitions follow [Authenticated history](#authenticated-history).

Chains retain signed Publisher/URL ownership and exact predecessor observation
times across scope changes, rotation, recovery and identity resets. Within each
Block, predecessor links determine chain order independently of storage order.
Missing predecessors, forks, duplicate IDs, invalid authority or non-increasing
observations stop reconstruction, including failures after the requested Delta.
This is a strict integrity check of the Aggregator's retained history; it does
not implement Consumer ignored-Entry dispositions.

The source retains its Delta ID, original Envelope, canonical Entry position,
Block sealing time, authenticating Declaration, identity's first-installation
or latest reset position, committing
size caps, [audit extraction profile](#historical-audit-extraction-profiles)
and [verdict thresholds](#historical-verdict-thresholds).
Later history cannot change those bindings. Contentless `attest`
and `delete` Deltas are supported. Sealed-predecessor admission uses this source;
index reconciliation shares its sealed Delta checks. Their unsealed-state
policies remain under [Delta predecessor admission](#delta-predecessor-admission)
and [Delta index reconciliation](#delta-index-reconciliation).

Reconstruction changes no retained state and exposes no partial result. It scans
the full prefix, retaining Declaration state, every seen ID and each Publisher/URL
tip; bounded lookup remains required. It does not check Payload bodies,
sanctions, materialization or Audit Record eligibility, and does
not replace live admission or `verify-history`.

Signed tests cover exact predecessor vectors in same-Block and cross-Block chains,
invalid ancestors and later unrelated Deltas, independent Publishers sharing a
URL, identity resets, contentless successors, recreation after deletion, restart
and repair/retry.

## Historical audit extraction profiles

`DeltaSource::audit_profile()` exposes core's `ScoringProfile`, derived from the
accepted signed parameter schedule at that Delta's sealing Block under WIST-4
§§5/9. It retains `shingle_size`, `min_observed_words`, `similarity_consistent`
and `similarity_variance_floor`; `VerifiedBlock::audit_profile()` supplies the
same binding for streaming callers subject to [Authenticated history](#authenticated-history).

Use the audited Delta's source when producing or recomputing extract similarity
and hard hits. A reference Payload retains its own committing size caps under
[Historical Payload validation](#historical-payload-validation); its Delta's
extraction profile does not replace the audited Delta's. These APIs do not
establish reference selection, Record eligibility or complete verdicts.
Link thresholds follow [Historical verdict thresholds](#historical-verdict-thresholds).

Eight `canary.json` scoring-profile cases run through signed Block, amendment,
Declaration and Delta histories, reproducing extraction scores and hard-hit
outcomes before and at amendment effectiveness. Tests cover later reference
Payloads, subsequent parameter resets, reconstruction after restart, corrupt
later Blocks with repair/retry, and rejected signature, value and grace-period
amendments.

## Historical verdict thresholds

`DeltaSource::verdict_thresholds()` exposes core's `verdict::Thresholds` from
that Delta's accepted sealing-Block schedule under WIST-4 §§5/9. It combines
the [extraction profile](#historical-audit-extraction-profiles)'s similarity
thresholds and mass guard with `link_agreement_consistent` and
`link_variance_floor`. `VerifiedBlock::verdict_thresholds()` provides the same
binding for streaming callers under [Authenticated history](#authenticated-history).

Use `AuditChain::audited().verdict_thresholds()` for verdict derivation; a
resolved reference's thresholds cannot replace the audited Delta's. Core's
`verdict::resolve` separately takes the reference change type, availability
and observation; these APIs do not establish those inputs or Record eligibility.
Hard-hit scoring retains its extract-only rules.

Signed histories consume eight `link-agreement.json` amendment contexts with
increases, decreases, inclusive activation, link boundaries, all reference
change types and extract-band precedence. Later references, parameter resets,
reconstruction after restart and corrupt-prefix repair preserve the audited
profile. Rejected signatures, values and grace periods supply no thresholds;
`canary.json` histories also check shared extraction bindings. Full Record
replay, automatic source selection and availability/withdrawal enforcement
remain required.

## Historical sampling inputs

`DeltaSource::sampling_constants()` retains `sampling_floor`, `sampling_ceiling`
and `sampling_slope` from the accepted parameter schedule at the Delta's sealing
Block under WIST-4 §§4/9. Amendments apply at their exact effective instant;
later Blocks and audit references cannot replace that profile.
`VerifiedBlock::sampling_constants()` supplies the same values for streaming
callers under [Authenticated history](#authenticated-history).

`DeltaSource::block_hash()` retains the authenticated committing Block Hash.
Pass it to core's `sampling::alpha_from_block_hash` for the VRF input, then use
the full `DeltaSource::id()` for the draw. Reconstruction validates the complete
pinned prefix before returning either binding, including for Block 0.

These inputs do not establish Auditor standing or selection. Callers must
derive Publisher reputation and sanction/escalation state at the preceding
height, using the audited Block's applicable parameters, and enforce roster,
self-audit, selection-domain and extension rules before accepting a Record.
Those replay integrations remain unimplemented.

Signed-history tests cover increases and decreases of each constant before,
at and after effectiveness, negative slopes and zero, later references and resets,
reconstruction, VRF proof binding to the original Block, corrupt-prefix repair
and rejected signature/value/grace amendments. Default profiles reproduce
`sampling.json`'s rate cases, including sanction and escalation overrides.

## Historical Record inclusion and confirmation profiles

`history::records::IncludedRecord::reconstruct_all(directory, pinned_head)`
returns every `audit_record` Entry in canonical Log order after the complete
pinned Block prefix passes [Authenticated history](#authenticated-history).
Each result preserves the original Envelope, Entry position, Block Hash, Anchor
fingerprint and sealing time; reconstruction fails without returning a partial
set if any Block is missing or invalid. A fresh attempt rereads repaired files.

`confirmation_profile()` retains `confirm_auditors` and `confirm_window_hours`
from the accepted schedule at that Record's sealing instant, including amendments
effective exactly then. `VerifiedBlock::confirmation_profile()` exposes the same
binding. WIST-4 §§5/9 evaluate each candidate using its own profile and preserve
the earliest established confirmation; later profiles cannot re-evaluate earlier
candidates. These bindings are independent of database parameter summaries.

Inclusion establishes no Record authorship, field validity, standing, reference
eligibility or finding. Malformed and incorrectly signed Record Envelopes remain
in the returned sequence for subsequent eligibility classification. The API
does not derive identity-scoped confirming sets, reputation or sanctions, and
retains all included Record Envelopes in memory without a work/cache bound.

Tests embed the four `parameter-combinations.json` confirmation-clock cases in
signed histories with accepted prerequisite amendments. They cover quorum and
window changes, activation boundaries, preservation through later amendments
and restart, rejected signature/value/grace amendments, original Entries and
positions, pinned-prefix exclusion, corrupt-history failure and repair/retry.
The supplied candidate sets exercise profile timing without establishing Record
eligibility or complete finding replay.

## Included Record references

`IncludedRecord::resolve_reference(directory)` binds the Record's signed
`audited_delta`, `reference_delta` and `fetched_at` to
[Historical audit references](#historical-audit-references). Reconstruction pins
the prefix to the Record's own Block hash and sealing time and requires the
same authenticated Anchor fingerprint (WIST-3 §3.4). Equal Block hashes under
another Anchor cannot substitute a Log; identical authenticated files may be
read from another directory. Later Blocks neither supply references nor prevent
resolution of an already-included Record. Constructing that `IncludedRecord`
still requires its complete requested prefix to pass
[Historical Record inclusion and confirmation profiles](#historical-record-inclusion-and-confirmation-profiles).

Resolution rejects `fetched_at` after the Record's sealing instant with
WIST4-E02 and applies the named reference relation under WIST-4 §3. Fetch
timestamps use the strict whole-second Log profile. Missing/non-string inputs,
unavailable audited Deltas and history failures return errors without a partial
binding or state mutation; a new attempt rereads repaired files.

The returned `RecordReference` retains `record()`, `audited()`, `reference()`
and `payload_source()`, preserving the original Envelope, identity, confirmation
profile and each Delta's committing parameters. Retrieve or validate the Payload
through [Historical Payload retrieval](#historical-payload-retrieval).

This relation establishes no Record signature, complete field eligibility,
Auditor standing, verdict or finding. Extension standing must additionally
enforce the B₁ fetch lower bound; sanctions, withdrawal, availability and durable
source retention remain separate requirements. Work and memory bounds follow
[Historical audit references](#historical-audit-references).

Signed histories exercise all ten `superseded-audit.json` reference cases and
eight `link-agreement.json` amendment contexts. Regressions cover inclusive fetch
endpoints, same-Block references, contentless anchors, malformed fields/times,
forged Record signature preservation, identical hashes under different Anchors,
alternate directories, later invalid history, restart and file repair.

## Included Record verdict scores

`RecordReference::validate_verdict_scores()` applies WIST-4 §§3/5's
Log-decidable score/verdict checks through core's `verdict::record_scores_valid`.
The authenticated reference Delta supplies the change type; the audited Delta
supplies its sealing-Block thresholds. Later references, Record inclusion and
parameter resets cannot replace that profile.

Unknown verdicts, missing measured similarity, malformed or out-of-range scores,
explicit nulls, forbidden link readings and scores outside the claimed verdict's
bands return WIST4-E02. Deletion mirrors similarity using the reference change
type. Optional link omission preserves the extract verdict; link verdicts require
a score, and link scores are forbidden for deletion and unmeasured verdicts.

This check reads no Payloads or network state and writes nothing. Passing it
establishes neither measurement truth, complete field/signature eligibility,
Auditor standing, coverage nor a finding. Unmeasured verdicts with absent scores
pass this relation without proving their cause. The Record and its authenticated
bindings remain available after a score rejection for separate coverage handling
under WIST-4 §3. History prerequisites and resource limits follow
[Included Record references](#included-record-references).

Signed histories exercise link-band amendment vectors before and at activation,
later references and resets, all reference change types, score boundaries,
malformed JSON values, neutral dimensions and reconstruction after restart.
Forged Record signatures remain subject to the separate authorship check.

## Historical audit references

`history::references::AuditChain::reconstruct(directory, pinned_head, audited_id)`
authenticates the audited Delta and its complete Publisher/URL chain under
[Historical Delta sources](#historical-delta-sources). Predecessor links order
Deltas within each Block; rotations and identity resets preserve chain ownership.
The result retains each Delta's original authority, sealing time and parameter
profiles. Reconstruction exposes no state until the complete pinned prefix passes,
including unrelated or later Delta checks.

`newest_at(fetched_at)` selects WIST-4 §5's newest Delta sealed at or before that
instant, or returns none if no chain member qualifies. `resolve(reference_id,
fetched_at)` checks the named reference under §3: another chain, a predecessor of
the audited Delta or a Delta sealed after the fetch rejects with WIST4-E02.
An older eligible reference remains valid evidence under that relation. Both
methods require the strict whole-second Log timestamp profile. Callers must
separately establish the Record's fetch interval, standing, authorship and remaining
eligibility; these methods do not validate an Audit Record.

The resolved `Reference` exposes its named `delta()` and `payload_source()`:
the reference's own Payload for `new`/`update`, otherwise the last content-bearing
predecessor's. The Payload source validates supplied bytes with its original
commitment, Publisher and committing caps under
[Historical Payload validation](#historical-payload-validation). Extraction keeps
the audited Delta's [profile](#historical-audit-extraction-profiles), available
through `audited()`. [Historical Payload retrieval](#historical-payload-retrieval)
checks configured disk and HTTP candidates. Availability, withdrawal,
sanctions and verdict derivation remain separate requirements.

Reconstruction scans the pinned prefix twice and retains the selected chain's
Envelopes and bindings, in addition to the underlying replay state; bounded work
and caches remain unimplemented. Tests embed all ten `superseded-audit.json`
reference cases in signed histories and cover same-Block chain order, historical
caps and extraction profiles, shared-host Publishers, identity resets, malformed
fetch timestamps, invalid ancestors/later Entries, restart and repair/retry.

## Historical Payload validation

`history::payloads::PayloadSource::reconstruct(directory, pinned_head, delta_id)`
requires a [historical Delta source](#historical-delta-sources) with a Payload
commitment. `delta_source()` exposes its authenticated bindings.

`PayloadSource::validate(raw)` applies the complete
[Payload validator](#retained-payload-validation) to supplied bytes with the retained
commitment, signed Publisher and caps. Reconstructing after restart selects the
same profile; an Audit Record's or another Delta's profile cannot replace it.
Invalid bytes return a Payload error without mutating the source or stored state,
allowing another copy to be checked. Retrieval follows the contract below;
availability, withdrawal and Audit Record eligibility remain separate requirements.

Signed tests cover 103 default-profile Payload field cases, original-byte and
numeric-value preservation, historical cap references and invalid cap Blocks,
scope/key changes, recovery deadlines, missing/duplicate targets, full-prefix
failures, restart and repair/retry.

## Historical Payload retrieval

`PayloadSource::read(directory)` reads `payloads/<delta-id-hex>.json` beneath
the supplied directory. `fetch(client, url)` retrieves one explicitly selected
URL; WIST-3 §6.1 permits copies from any source because the commitment
authenticates the content. Both methods apply
[Historical Payload validation](#historical-payload-validation) before returning
a `RetrievedPayload`. Its `source()` retains the authenticated Delta bindings,
`location()` records the file path or requested URL, `raw()` exposes the original
file bytes, and `payload()` exposes the checked typed content.
Preserve `raw()` when storing a copy; serializing `payload()`
does not preserve the original representation.

Invalid bytes return `Error::Payload` with the WIST-1 diagnostic. Disk and
transport failures retain their respective errors; no failure establishes a
withdrawal, a serving fault or a `not_auditable` verdict. Reads and fetches
write no files or history state and retain no failure cache, so callers can
retry another copy. A resolved audit reference uses its `payload_source()`;
an `attest` or `delete` reference has no own Payload to retrieve.

`retrieve(client, candidates)` tries `PayloadLocation` file paths or URLs in
caller-supplied order, stopping at the first verified copy. `retained_location`
derives the local path; `distribution_location` appends the WIST-3 §6.1 path
to a configured HTTP(S) origin, preserving its port; `publisher_location`
derives the WIST-2 §3.1 path from the Delta's signed Publisher. Each uses the
Payload source's Delta ID, including when a contentless audit reference resolves
to an earlier anchor. Parsed distribution origins must be bare, without
credentials, query strings or fragments; the client enforces transport eligibility
when fetching.

Source order is caller policy under WIST-3 §6.1's permission to use any copy.
The successful result's `failed_attempts()` retains earlier locations and typed
errors; exhausted or empty candidates return `PayloadRetrievalError` with all attempts.
These diagnostics describe retrieval attempts, not protocol fault findings.
The selected location is an in-memory transport locator, not evidence of authorship
or the final redirect destination. Every copy retains the same authenticated
commitment and historical caps regardless of location.

HTTP retrieval uses the client's HTTPS guard, explicit loopback HTTP opt-in,
30-second request timeout and five-hop redirect limit within the same Canonical
Host. Response and file reads remain unbounded. Callers enforce withdrawal,
availability and Record eligibility before using or retaining content;
durable replication and those policy integrations remain unimplemented.

Tests exercise 103 signed Payload field cases through disk and HTTP, historical
cap amendments after reconstruction, named references including contentless
successors, malformed and substituted copies, missing files/HTTP responses,
retry, exact-byte preservation and unchanged authenticated history. Fallback tests
cover local and HTTP failures, Publisher attribution across scoped hosts, early
termination, preserved diagnostics, historical caps and reconstruction after restart.

## Historical Payload source discovery

`PayloadSource::discover(client, directory, independent_origins)` returns
`PayloadLocations` in this local policy order: retained file, independent origins
in supplied order, origins from `directory/log/mirrors.json` in listed order,
then the signed Publisher's well-known path. Pass `locations().iter().cloned()`
to `retrieve` under [Historical Payload retrieval](#historical-payload-retrieval).
Origins producing identical parsed URLs are tried once, preserving the first
position. Every path uses the authenticated Payload anchor, including references
through `attest` or `delete`.

The optional local Mirror list supplies untrusted location hints under WIST-3
§6.1's permission to obtain any copy. Discovery reads only its `mirror_urls`
string array; it neither verifies the Envelope nor asserts list authorship,
Log membership or administrative independence. Raw JSON eligibility still
applies. Missing lists are normal; unreadable/malformed lists and invalid origins
appear in `discovery_failures()` without suppressing other sources. A malformed
array contributes no entries; individually invalid origins leave valid siblings
available. Discovery errors name the list file or supplied origin and are
separate from retrieval failures.

`discover_with_remote_mirrors(client, directory, independent_origins,
mirror_list_origins)` adds remote hints after local hints and before the Publisher.
It fetches `/log/mirrors.json` from each distinct parsed origin in supplied order,
using the same origin restrictions and transport client as Payload retrieval.
Only explicitly supplied list origins are queried; independent origins and newly
listed Mirrors trigger no list requests. Remote lists use the same untrusted-hint
rules as local lists. HTTP failures, including absent lists, and malformed JSON
are recorded against the requested list URL; invalid list origins retain the
supplied origin. Each failure leaves subsequent lists and Payload candidates
available. List retrieval does not fetch Payloads.

`discover` performs no network requests. Neither method writes or caches state;
another call observes repairs or configuration changes. Remote list reads share
the [retrieval limits](#historical-payload-retrieval); neither signing-key time
authentication nor durable selected-source provenance is implemented. Service
and Audit Record integration remain unimplemented. Signed-history tests cover
independent/Mirror/Publisher fallback, malformed and duplicate-member lists,
origin and request deduplication, explicit-only discovery, corruption, repair,
restart, historical caps and contentless reference anchors.

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

Declaration sequence consumers use the validated numeric value under WIST-1
§§4/5.1. Integral decimal/exponent spellings and negative zero preserve
admission floors, pending recovery-head order, capped packing, sealed metadata
and Snapshot sealing-height lookup. Retained Envelopes remain unchanged;
Blocks and Snapshots use JCS serialization. Signed live/restart tests cover
mixed spellings, recovery competitors/followers and idempotent re-serves.
This does not reconstruct missing legacy metadata or establish Snapshot
recovery conformance; see [Declaration history replay](#declaration-history-replay).

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

## Feed field validation

Ingestion applies WIST-2 §5/ADR-0032's complete Feed Envelope field gate
before domain comparison, signature verification or Page source replay.
It checks required/unknown members, Canonical Host spelling, unbounded
release components, exact Gregorian Log timestamps, unique Delta IDs and
the 1000-entry cap, nullable `next` syntax and canonical signature fields.
Signed values remain unchanged. Field failures receive WIST2-E01 without
noise or a failure-triggered Declaration retry; field-valid foreign domains
receive WIST2-E04 without retry, even with a bad signature.

`feed-fields.json` supplies 134 signed probes; live HTTP tests exercise 133
through first contact and restart, checking persisted diagnostics, noise and
request counts. Page field regressions stop before Delta/Payload admission.
The schema gate does not establish complete `next` URL/authority validation,
exact Page cardinality, publication/history
partitioning, supported-major policy or durable selected-source provenance.

## Feed rollback protection

Ingestion implements WIST-2 §3.2/ADR-0033 using an atomic SQLite comparison
and update of each host's greatest authenticated live Feed timestamp.
WIST2-E05 stops Page and Delta work without noise. Field/domain/signature
failures retain their earlier diagnostics and cannot change that observation.
Equal timestamps pass; older sealed Pages do not enter this comparison.
The observation survives restart, subsequent retrieval failures, budget
suspension, empty Feeds and Declaration changes.

`feed-regression.json` supplies 21 signed observations, consumed over HTTP
with database reopen between observations. Additional tests cover dependent
Page/Delta/Payload failures, budget exhaustion, storage failure, older sealed
Pages, ordinary rotation, identity reset and concurrent per-host storage.
Recovery tests cover admission-time and sealing-time settlement with pending
or sealed competitors. A superseded identity's maximum timestamp survives
restoration of the lower-sequence recovery Declaration and restart; the
restored signer can publish and seal new Deltas using that same Feed timestamp.

Existing databases have no retained Feed observations to reconstruct; protection
starts at the first authenticated live Feed after upgrade. Backups must preserve
this table to preserve its observations. General crash recovery, backup restore
and concurrent pull serialization remain separate requirements.

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

Page cutoff comparison uses the strict Log timestamp parser, including year
zero and the final second of year 9999. Field checks and remaining Feed/Page
obligations are described under [Feed field validation](#feed-field-validation).
WIST-2 §3.2 named-entry fallback is covered by
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
the [historical Delta source](#historical-delta-sources) pinned to the database
head. Lookup checks its Delta ID; comparison also checks Publisher and URL ownership.
Materialized record timestamps supply no comparison authority. Unsealed
Envelopes remain trusted local admission state. Missing accepted evidence or
invalid retained history stops the pull before accepting the dependent Delta
or fetching its Payload. This storage failure does not reject the candidate;
repairing the history permits a later attempt. Historical source bindings
preserve the predecessor's authority across later Declaration changes.

`declaration::verify_delta_predecessor` checks current Publisher/timestamp
fields, predecessor ID and ownership, and strict observation ordering. Callers
must separately establish both Envelopes' eligibility and predecessor
acceptance; this helper does not verify signatures, retrieve Deltas, establish
Log positions or select the canonical chain tip.

Signed `declaration-fields.json` relation cases and live tests cover exact
fractions, offset equality, both queues, restart, sealed evidence despite altered
materialized timestamps, fetched predecessors, missing older links, independent
URL chains, budget suspension/resumption and corrupt history. Signed-Block
regressions cover invalid ancestor/target signatures, missing ancestors, later
unrelated Delta failures, restart, repair/retry and retired-key authority.
Lookup scans retained domain admissions and, when needed, the full pinned Block prefix for
each predecessor; bounded lookup and complete authenticated Delta replay remain
separate requirements.

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
at each Block. Sealed size and clock checks follow
[Delta size-cap profiles](#delta-size-cap-profiles) and
[Delta clock eligibility](#delta-clock-eligibility). Restoration checks Delta
signing bindings, key-time bounds and scope, then follows predecessor links
within that Block. Retained unsealed copies follow persistent acceptance
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
or crash-safe publication. Historical size-cap selection follows
[Delta size-cap profiles](#delta-size-cap-profiles).

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
