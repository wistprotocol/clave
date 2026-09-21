# clave

The signed Delta format targets [WIST specification revision `0127b0f2e5420e167a15d3f7afae6ed81030e158`](https://github.com/wistprotocol/spec/tree/0127b0f2e5420e167a15d3f7afae6ed81030e158). Object version `1.0.0` alone does not identify a compatible draft.

Delta ingestion checks the signed canonical `publisher` against the logical Feed domain before source selection and duplicate suppression, including fetched predecessors. Chain tips use `(publisher, url)` and persist across reopen; legacy index restoration is described under [Delta index reconciliation](#delta-index-reconciliation). Sealing and recovery settlement reject mismatches between queue ownership and the signed author. Complete authenticated Delta eligibility remains a separate validation requirement.

WIST Protocol aggregator. Clave pulls signed Deltas from Publishers through
ping + pull, validates them, and seals hourly Epochs into one growing
RFC 6962 Merkle tree. It serves that tree as C2SP tlog-tiles tiles and entry
bundles, its head and archived Checkpoints as signed notes, and periodic
Snapshots over HTTP for Consumer sync.

Subcommands: `init` (generate the log's genesis key and local store, and
print the signed-note verifier key a Witness is configured with),
`serve` (HTTP ingest + read endpoints; seals an Epoch at every cadence
grid instant unless `--no-seal`, under the store instance name
`--instance <name>` gives it), `seal` (append the next Epoch's
Entries to the tree and publish its Checkpoint at the wall clock floored
to the accepted cadence grid, or at `--at <whole-second UTC instant>` for
a test Log that advances Log time faster than the clock), `witness`
(maintain the Witnesses each sealed Checkpoint is submitted to),
`snapshot` (build a signed, verifiable
point-in-time index for cold-start sync), `param-change` (queue a signed
`parameter_change` Registry Update, WIST-4 §5: bounds and combination
rules checked, `effective_at` held past the grace period, applied to the
live parameter set once its Epoch seals and the effective instant passes;
a change whose grace window lapses while queued is dropped from the Epoch
and reported by `seal`), `withdraw` (queue a `payload_withdrawal`, WIST-4
§5.1 and WIST-3 §6.2: at sealing the act replays through core's
withdrawal engine under the Log key, seals only beside or above the
Delta it names, deletes the Payload, drops the record, stops serving
snapshots that still contain it and leaves a `withdrawal` tuple in every
later Snapshot state; a repeated withdrawal seals and changes nothing),
`suffix-list` (pin a Public Suffix List file, WIST-4 §3.1: the octets are
held in the store and served at `/log/suffix-lists/<hex>.dat` without
expiry, and the queued `suffix_list_update` seals in the next Epoch and
is in force from the Epoch after it; `init --suffix-list <file>` pins
one for Epoch 0, and without a pinned snapshot every Canonical Host is
its own accounting unit), `mirror` (maintain the signed
`/log/mirrors.json`), `log-key` (rotate the Log's own Aggregator keys, see
[Aggregator key rotation](#aggregator-key-rotation)).

Every Feed pull also pulls the domain's Label Feed where it serves one
(WIST-2 §3.3): `label-feed.json` and its Pages walk under the Feed's
rules and the ingest budget, each unseen Label or dispute is fetched
from `labels/<id>.json` and validated through core under the accepted
Declaration — fields, the registry name, self-labeling, the disputed
Label's sealing and authority, the signature — and queued as a `label`
or `dispute` Entry, sealed after the Deltas under the per-domain
capacity and the per-Labeler cap; a failure is `WIST2-E06` at the status
endpoint with the ID, pulled again on the next pull. The Snapshot state
carries the current Labels and disputes as `label` and `dispute`
tuples, and tier 1 carries `labels.parquet`, `disputes.parquet` and
`labelers.parquet` (WIST-3 §7).

`serve` additionally enforces the flat `quota_base` ping quota (429 +
Retry-After; only WIST2-E02/E04 pings count as noise), accounted per
Registrable Domain under the snapshot in force at the Ping and reported
as the shared remainder at every host's status endpoint, and re-pulls
every known publisher `baseline_poll_seconds` after its last pull
without a Ping, as [Concurrency](#concurrency) describes. Ingest
follows feed pages (WIST-2 §3.2) under the daily byte budget of the
host's Registrable Domain, suspending the walk when the budget or the
pull's own limits are spent and resuming it from the pages already
walked. The
seal's per-domain Epoch capacity counts Entries per Registrable Domain
under the snapshot in force at the Epoch, and the Snapshot state carries
the `suffix_list` tuple (WIST-3 §7). Ping admission and every fetch are
bounded as [Fetch bounds and destination policy](#fetch-bounds-and-destination-policy)
describes.

Ingest re-fetches each known publisher's Declaration and validates the
chain (WIST-1 §5.2: `seq`/`prev_declaration` monotonicity, recovery-keys
protection, signer classification into ordinary rotation, recovery
rotation, or fresh identity — WIST1-E08 otherwise), and verifies every
delta against the full declared key set (`sig.key_id` membership and
`valid_from`; WIST1-E01/E02). A recovery rotation opens the WIST-1 §5.2
recovery window at its sealing Epoch (the open window appears in snapshot
state): the domain's deltas queue instead of sealing, declarations signed
by superseded keys are rejected, and the first Epoch at or past the
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
candidate Epoch's authenticated profile. Pending amendments apply only from
their effective instant. Delta URL/declared-byte failures retain WIST1-E11/E04;
Payload cap failures use WIST2-E03 during pulls and WIST1-E04 at sealing.
Sealing removes rejected copies and dependent successors under
[Declaration key binding](#declaration-key-binding). Missing or
invalid stored Payloads follow [Retained Payload validation](#retained-payload-validation).

`VerifiedEpoch::delta_size_caps` retains the committing Epoch's profile for
later Payload or reference validation. `SizeCaps::validate_payload_sizes`
measures original JSON values in JCS octets; callers must separately validate
Payload fields and integrity. Index restoration checks sealed Delta URL and
declared-byte caps against each Epoch's profile. It does not retrieve historical
Payloads or recalculate completed unsealed admissions' original profiles.

`delta-cap-time.json` exercises authenticated histories, stage boundaries,
reference profiles and invalid candidate Epochs. Live regressions cover
Payload/predecessor timing, repeated rejected IDs, restart, dependent rejection,
missing/corrupt Payload rollback and signed authority despite changed local
summaries. Full-prefix reconstruction per attempt remains unbounded.
[Historical Payload retrieval](#historical-payload-retrieval) preserves these
profiles.

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
more links could fit: no party measures the page against the declared prefix.

`payload-links.json` supplies 31 signed commitment-valid probes. Live tests
cover their pull dispositions, restart, accepted-byte preservation through
sealing, scoped subjects and rejection of a retrieved predecessor.
Field/version admission and retained validation are described below;
historical validation remains outstanding.

## Fetch bounds and destination policy

Every fetch reads its response while it streams and refuses it at a bound
before buffering or parsing: a declared length above the bound is refused
before the body is read, and a body that crosses it is refused where it
crosses. A Declaration, Feed page or Mirror list is
bounded at 1 MiB; a Delta file at 16 KiB plus twice `url_cap_bytes`; a
Payload at `extract_cap_bytes + links_cap_bytes + summary_cap_bytes` plus
4 KiB, each read from the schedule in force at the pull. Content fetches
under WIST-2 §5's daily budget are further bounded by the budget's
remainder and by the pull's work limits (64 MiB and 4096 objects per
pull): an object that would cross the budget or the work limit is not
read past it, the bytes read are debited, and the walk suspends for a
later pull to resume from where it stopped, exactly as budget exhaustion
does; an object above its own cap is a failed fetch. The bound a request
is issued under is reserved against the budget before the request and
settled to the bytes actually read when the response is persisted, so
neither a pull that stops mid-request nor two hosts pulling one
Registrable Domain can read past a day's budget. Declaration requests
stay outside the budget and carry only their own cap.

A fetch connects only to a public unicast address. Loopback addresses are
allowed under `--allow-http`, the local-test exception; private,
link-local, shared (100.64/10), multicast, broadcast, documentation,
benchmarking, reserved and unspecified addresses, and IPv6 addresses that
map or embed them, are never fetch destinations. The policy applies to a
literal host, to every redirect hop and to what a name resolves to at
the moment the connection is made: name resolution runs through a
resolver that refuses the whole answer when any address fails the policy,
so a name that rebinds between two fetches is refused on the second. A
refused destination is a failed fetch with the address class named.
A redirect may leave the requested Canonical Host only for a host the
Publisher's Declaration lists in `subdomain_scope` at the moment the
request is issued (WIST-2 §8): a replacement Declaration admitted
earlier in the same pull governs the requests after it, a scope it
withdrew no longer authorizes a redirect, and before the first accepted
Declaration a redirect stays on the requested host.

`serve` bounds the work a Ping can start: at most 4 pulls run at once and
at most 64 accepted Pings wait for a slot. A Ping for a host with a pull
running or waiting is accepted (202) without new work; a Ping beyond the
waiting bound is refused with 503 and `Retry-After: 30`, is not queued,
and counts as neither noise nor a pull, so the Publisher retries later
under its own backoff. Quota (429) is answered before admission.

## The tree, its static layout and distribution

The Log is one growing RFC 6962 tree over SHA-256 (WIST-3 §4). The store
holds it durably: the leaf data of every Entry at its leaf index, and the
[tlog-tiles] tile hashes, so an Epoch is appended without rehashing
history. Epoch N's row records its number, the tree size and root its
Checkpoint states, its `sealed_at`, the octets its Entries occupy in
entry bundles, and the signed note itself with every signature line it
has obtained.

Sealing (WIST-3 §3.2) and distribution (WIST-3 §5, §6) are separate
stages. Sealing is one store transaction: it selects the eligible
Entries, holds out any whose JCS serialization exceeds 65 535 octets
(reported with the Epoch's drops), orders them canonically, bounds the
Epoch by `epoch_cap_bytes` counted as the sum over its
Entries of each JCS serialization plus two, appends their leaves at
`size(N-1)`, and signs Checkpoint N — origin, tree size, root,
`epoch_number` and `sealed_at` — under every held Aggregator key valid at
its height (WIST-3 §3.4, §5, see
[Aggregator key rotation](#aggregator-key-rotation)). An empty Epoch
restates the previous size and root.

`serve` seals at every instant of the cadence grid in force at the last
Epoch's `sealed_at` (at the current time before the first Epoch), an
empty Epoch when nothing is eligible. An instant is sealed within its
grace of `min(60, cadence / 2)` seconds after it, with `sealed_at` equal
to the instant however many attempts it took: while the instant is
unsealed and its grace lasts, a failed seal is retried every 5 seconds,
so a transient failure costs the Epoch nothing. An instant still unsealed
once its grace has passed is skipped and never sealed late. Every pass
first publishes each Epoch the store committed without publishing, under
the same sealer lease, so a seal interrupted between its commit and its
files serves that Checkpoint on the next pass rather than at the next
grid instant. Without the lease a pass neither seals nor publishes.
`serve --no-seal` leaves sealing to `seal`.

Distribution runs after the commit, is idempotent and restart-safe, and
writes each file through a sibling temporary file, syncing the file and
its directory. For every Epoch the store committed but has not marked
published, lowest first: the entry bundles and tiles the Epoch's leaves
reach, then `/log/checkpoints/<9-digit epoch number>`, then `/checkpoint`
last. No Checkpoint is therefore published before every Entry below its
tree size is durably stored and retrievable at its path. A full tile or
bundle is immutable once written, and the partial files at an index are
removed on the run that first writes the full one. `seal` and `serve`
start by running distribution, which finishes every interrupted
publication and restores any file of the head Epoch the disk has lost or
left torn; lower Epochs are checked by `verify-history` and reopening,
not at every start. Snapshot files follow the same seal outside that
record.

The served layout is:

```
/checkpoint                       (the head Checkpoint, a signed note)
/tile/<L>/<N>[.p/<W>]             (tree hashes, 256 per full tile)
/tile/entries/<N>[.p/<W>]         (entry bundles: the leaf data)
/log/checkpoints/<epoch_number>   (every Checkpoint published)
/log/anchor.json /log/mirrors.json /log/suffix-lists/<hex>.dat
/payloads/<delta-id-hex>.json
/snapshots/...
```

`serve` sends `/checkpoint` and the archive as
`text/plain; charset=utf-8` with `Cache-Control: no-store`, because both
are rewritten — the head at every Epoch and an archived note whenever a
Cosignature is added. Full tiles and entry bundles are
`application/octet-stream` with `public, max-age=604800, immutable`;
partial ones carry the same media type without caching, because they
stop being served once the full tile exists.

## Witness cosignatures

`clave witness --data <dir> --add <verifier key> --url <base>` records a
Witness; `--remove <name>` drops one and no argument lists them. The
verifier key is the signed-note string `<name>+<hex key ID>+<base64 key>`
of the Ed25519 cosignature/v1 type, and the store keeps the tree size each
Witness last cosigned. Default: no Witness, and a Log with none behaves
exactly as before.

After the archive write, each seal submits the head Checkpoint to every
configured Witness through [tlog-witness]'s `add-checkpoint`: the body is
`old <size>`, the Consistency Proof from that size one base64 hash per
line, a blank line, then the note. A 409 answer states the size the
Witness holds; the submission is retried once from it. Every returned
Cosignature is verified under the configured key over the note text
before it is accepted; it is then appended to the stored note, whose text
never changes, and the archive and `/checkpoint` are rewritten. A note
carries at most sixteen signature lines (WIST-3 §5): the Log's own lines
stay, and a Cosignature that does not fit is logged and dropped rather
than published, leaving the Witness's recorded size unchanged. A Witness
that refuses, answers with a Cosignature that does not verify, or cannot
be reached never blocks or fails the seal: the attempt is logged and made
again at the next distribution run.

## Aggregator key rotation

`init` writes the Log's genesis Aggregator key — the one the Anchor
declares — to `keys/seed` in the data directory, readable only by its
owner. Every later key is admitted in band (WIST-3 §3.4):

- `clave log-key add --data <dir>` generates an Ed25519 key, stores its
  seed as `keys/<key_id>.seed` under the same protection and format, and
  queues the `aggregator_key_add` that admits it. The `key_id` is `log<n>`
  for the least `n` above 1 no admitted key, queued addition or held seed
  uses; the genesis key's is `log1`. The seed reaches disk before the act
  is queued, so no sealed act names a key the Aggregator cannot sign with.
  The command prints the new key's note key ID and its signed-note
  verifier key, the form a Witness is configured with.
- `clave log-key remove --data <dir> --key-id <id>` queues the
  `aggregator_key_remove` that retires a key. Removal is permanent: the
  same `key_id` is never admitted again.
- `clave log-key list --data <dir>` prints each key's `key_id`, note key
  ID, the heights that admitted and retired it and whether the key store
  holds its private key. A key whose addition is queued and unsealed is
  listed with an `unsealed` height.

A key act sealed in Epoch N is signed under a key valid at height N−1,
every other Registry Update and Checkpoint N under a key valid at N. Both
commands therefore sign under a held key valid at the current head
height, and so do the Snapshot index, manifest and state file, the mirrors
list and the `parameter_change`, `payload_withdrawal` and
`suffix_list_update` acts. Where several held keys are valid, the one
admitted at the lowest height signs, and `key_id` breaks a tie.

Checkpoint N carries a signature line from every held key valid at N, in
that same order: the Epoch that seals an addition is signed by the
admitting key and the new one, and the Epoch that seals a removal is not
signed by the removed key. The state file carries an `aggregator_key`
tuple for every key the Log has admitted, removed keys included with their
removal height (WIST-3 §7), so a resuming Consumer judges every Checkpoint
at or below the Snapshot under the keys valid at its own height.

No key-act failure is ever sealed (WIST-3 §3.4). `log-key remove` refuses
at once when the `key_id` is not valid at the height the act authenticates
at, or when the key acts already queued would leave no key valid at the
next Epoch — which would leave that Epoch no valid Checkpoint. Sealing
checks every queued act again against the registry the replayed Log
establishes and drops what fails, reporting the rule: an addition naming
an admitted `key_id` or an admitted key's note key ID, and a removal of a
key not valid at the Epoch below, are `WIST4-E04`; an act no key valid at
that height signed is `WIST4-E11`. When an Epoch's accepted removals would
leave no key valid at its height, the removal at the highest canonical
Entry index is held back first, so the earliest ones still apply. The
`parameter_change`, `payload_withdrawal` and `suffix_list_update` acts are
authenticated under the keys valid at the sealing Epoch and dropped as
`WIST4-E11` otherwise.

## Concurrency

No pull holds a process-wide lock. Each pull, Ping check, status request
and dispatcher pass opens its own store connection (`Db::connect`), so a
slow origin delays only its own domain while other domains, status
answers and dispatching proceed; SQLite serializes the writes.

A pull runs in four stages: it is scheduled, it fetches, it verifies what
it fetched against the references it was issued with, and it admits the
result. Fetching and verification hold no store connection; every
admission is one write transaction. Every handoff between the stages is
persisted under a run of the domain (`pull_runs`, at most one open per
domain): each request enters `pull_objects` with the bytes it reserved
before it is issued, and the response, its verification and its admission
move that row forward; the domain's walk cursor (`pull_walk`) holds the
pages walked; `pull_attempts` holds the Declaration retry each Delta ID
spent and the predecessors it retrieved; and the run's phase, position,
chain position and remaining work advance in the same transaction as the
admission that moved them, its queue being written where a walk ends or a
retrieved predecessor is spliced into it rather than at each item.

Within one pull, a response the run already holds is read from the run
instead of requested again and an admission or rejection it already
recorded is not repeated, so a second delivery of either changes nothing.
A pull that stops before its run is closed — a crash, or a partition
taken over mid-pull — leaves the run behind, and the next pull of that
domain drops it with its objects and starts fresh, returning to the
budget what a request that never settled had reserved: resumption is a
later pull (WIST-2 §5), which takes its own clock and schedule (WIST-1
§3.4) and fetches `feed.json` again. Nothing is admitted twice across the
interruption, because an ID already accepted for sealing is seen (WIST-1
§3.5) and the walk cursor, which the run's deletion keeps, holds the
pages already walked. Closing a run rebuilds the pull's report from the
objects it admitted and rejected in the order it decided them, records
whether the walk suspended, and drops the run's state.

The pages a walk reads are the domain's walk cursor, which outlives the
pull that walked them. A pull whose walk suspended keeps them; the next
pull fetches the live `feed.json` again, since the Publisher rewrites it,
and wherever the chain it reads names a page the cursor already holds it
takes that page — a sealed Page is immutable — instead of fetching it,
then continues from where the cursor stopped. The cursor retains each
page's Envelope octets, and a page taken from it is admitted under every
check a freshly fetched sealed Page passes — fields, domain, signature
under §3.2's sealed sources at the height the pull pinned, and the target
rule on `next` — with the same dispositions, since the Declarations those
sources resolve may have changed since the page was walked: a recovery
settlement can exclude the Declaration that signed it. Only the request
and its debit against the budget are skipped. The walk stops, held page
or fetched, at the first page listing no unseen ID, and at a `next` that
is absent or fails the target rule.
The cursor is dropped once the Delta walk it fed completes, and the Label
Feed's once its Labels have been processed, so a page chain longer than
one pull's byte or object limit is walked across pulls instead of
restarted at the head each time.

`serve` schedules pulls durably in the store. `pull_schedule` holds at
most one due-time row per domain (`due_at` in Unix seconds, `reason`
`ping`, `baseline`, `resume` or `retry`, the count of consecutive failed
pulls, and `pinged_at`, the receipt instant of the earliest Ping the
pull serves); `pull_tasks` holds each pull in flight with the same
`pinged_at`, its owning instance, its lease and the partition token it
was claimed under.
Opening a store without the schedule gives every
known publisher a row: `resume` due at once for a suspended walk,
otherwise `baseline` due `baseline_poll_seconds` after its last pull,
or at once if it was never pulled. A publisher recorded later is due at
once unless its pull is in flight.

A Ping passes the host and quota checks, then one write transaction
schedules it, and 202 answers only after that commits:

- a domain that already has a row keeps it, its due time moved to the
  Ping's instant when that is earlier;
- a domain being pulled gets a `ping` row, which the next pull after the
  running one starts from;
- any other domain gets a `ping` row due at once, unless
  `max_pending_ingests` `ping` rows already wait, which answers 503 with
  a Retry-After of `OVERLOAD_RETRY_AFTER_SECS`.

The first two take no backlog slot. Rows combine as follows: the due
time is the earlier one; `retry` outranks every other reason and
`resume` outranks `ping` and `baseline`; between `ping` and `baseline`
the strictly earlier row's reason stays; the pull serves the earlier of
the two rows' Pings. A Ping arriving against a waiting `retry` row also
clears its failure count, so a fresh Ping cancels a pending backoff and
starts a new attempt (WIST-2 §7, `WIST2-E01`).

A pull's noise disposition (WIST-2 §4: `WIST2-E02` or `WIST2-E04`) is
charged only to the Ping the pull serves, against the Registrable
Domain and the UTC day in force at that Ping's receipt instant, not at
the pull's. A baseline poll, a resumption and a retry that no Ping asked
for cost the domain's quota nothing.

Every domain belongs to one of the store's `PARTITIONS` (16) pull
partitions: the first eight bytes of the SHA-256 of its canonical host,
read big-endian, modulo the partition count, which a store fixes when it
is created. Both schedule tables carry the partition. `pull_partitions`
holds each partition's lease: its owner, `lease_until` and a token that
every takeover increments.

A dispatcher runs at most `max_concurrent_ingests` pulls at once. It
wakes on every Ping, every finished pull and at least once a second, and
in one write transaction:

1. renews every partition lease it holds to `PARTITION_LEASE_SECONDS`
   (30) from now;
2. takes over unowned or lapsed partitions, lowest first, until it holds
   `max_partitions` (all by default), incrementing each one's token and
   returning every task claimed there under an older token to the
   schedule as `retry` due at once;
3. returns every task of a held partition whose lease lapsed to the
   schedule the same way, which recovers a pull that ended without
   completing, except for the domains whose pulls this dispatcher still
   has in flight: a lease left unrenewed by a slow pass names a pull
   that is still running here, and returning it would dispatch the
   domain a second time beside itself, both passing the partition's
   fence;
4. claims up to the free slots of due rows of the partitions it holds
   whose domain has neither a pull in flight nor one running here,
   leasing each for `LEASE_SECONDS` (600) under its instance name and
   recording the partition's token.

It renews its running pulls' leases while they run. Claims alternate
between the oldest due `ping` row and the oldest due row of any other
reason, and a class with nothing due yields its turn, so neither Pings
nor scheduled pulls wait behind the other's backlog. Claiming searches
each held partition's `due_at` indexes and never scans the publishers.
Two dispatchers on one store never hold the same partition and so never
claim the same domain.

A lease's owner is the instance name `serve --instance <name>` runs
under, `primary` by default, and the process holds an exclusive file
lock on `<data dir>/instance-<name>.lock` for its lifetime: a second
process under the same name refuses to start, naming the lock, and a
second process on one store takes another name. A process that starts
under the name it ran under before re-takes, in one transaction, every
partition lease and the sealer lease recorded under that name,
incrementing each token — which fences out anything the earlier
incarnation left running — and returns those partitions' pulls to the
schedule as `retry` due at once. A process killed without releasing its
leases is therefore succeeded at once by its restart rather than after
its own leases lapse. `clave seal` takes the sealer lease under an owner
unique to its process and its start.

A pull runs fenced by its partition and token. Every write transaction
it begins, including its completion, first checks under the write lock
that the partition's token is unchanged; once another dispatcher has
taken the partition over, the transaction writes nothing and fails with
`Error::Fenced`, and the pull is abandoned without a completion, since
the takeover already returned the domain to the schedule. What it
admitted before that stays, and the new holder pulls the domain fresh,
admitting nothing a second time. A Payload
file is written inside its Delta's admission transaction, after that
check, and is named by the Delta ID and holds the bytes the Delta
commits to, so a fenced-out pull writes none and a repeated admission
writes the same file.

A finished pull, in one write transaction, closes its run — which
rebuilds its report, records the walk's suspension and, for a completed
walk, the pull instant — drops its task and schedules the next pull,
combined with any Ping row that arrived meanwhile. A takeover between the
pull's last admission and that transaction writes none of it, so the
domain's next pull, held by the new dispatcher, schedules from its own
completion:

- after a completed walk, `baseline` due `baseline_poll_seconds` after
  the pull started;
- after a walk suspended at the pull's work limits, `resume` due at
  once, or at the next UTC day while the domain's daily ingest budget is
  spent;
- after a failed pull, `retry` due after `RETRY_BASE_SECONDS` (60)
  doubled for every earlier consecutive failure, at most
  `baseline_poll_seconds`; a successful pull resets the count.

A domain that is still no known publisher after its pull gets no next
pull. Running a returned pull again is safe because admission is
transactional and deduplicates by Delta ID. One pull runs per domain at
a time.
Fetching and state-independent verification happen outside any write
transaction. Each Delta attempt is issued, at its one clock sample, with
references to the state it is verified under: the hash of the domain's
accepted Declaration and of its recovery window's Declarations with the
window's opening Epoch, and the size caps and clock allowance of the
parameter schedule at the sampled clock with the height that schedule was
read at. Each Delta's persistence is one immediate write transaction that
first revalidates those references and the URL's chain tip, the caps only
when an Epoch was sealed since; on any change it writes nothing, and the
stored Delta and its verified Payload are verified again under fresh
references at the same clock, so a concurrent seal or admission cannot be
bypassed. A Label or dispute revalidates its Declaration the same way. Every
top-level write transaction begins immediately, taking the write lock
before its reads.

Sealing is exclusive to the holder of the Log's sealer lease
(`sealer_lease`: owner, `lease_until`, token). `serve`'s sealing
scheduler renews or takes the lease every `SEALER_LEASE_SECONDS` / 3
(10) seconds, holding it for `SEALER_LEASE_SECONDS` (30), and seals a
grid instant only while it holds the lease. While a seal runs, a
separate thread on its own connection renews the lease at the same
cadence and token, so a seal longer than the lease keeps it. A seal
runs fenced by the lease's token: its transaction begins by checking
the token under the write lock, and every file-writing stage after the
commit (distribution, Witness submission, withdrawal removal, the
Snapshot) checks it again, so a sealer whose lease was taken over
commits no Epoch, or publishes no further file after its commit.
`clave seal` takes the lease when it is unowned or lapsed, seals under
it with the same renewal and releases it; while another process holds
a live lease it fails, naming the holder and the lease's end. On Ctrl-C
or SIGTERM `serve` stops accepting requests, finishes those in flight,
stops its dispatcher and sealing passes and only then releases its
partition and sealer leases, so no pass takes a lease again after the
release and another process takes them over at once; a partition's next
holder still increments its token, fencing out any pull left running.
Recovering
the publication of Epochs already committed needs no lease, since it
rewrites byte-identical files. Durable publication remains a separate
requirement.

## JSON input eligibility

Fetched protocol JSON and retained object reads reject duplicate decoded member
names before field, identity, signature or replay checks, including escaped
names and nested objects or arrays (WIST-1 §4, RFC 8785 §3.1). This covers
Declaration, Delta, Feed/Page, Payload, Log Anchor, Epoch, governance, Mirror
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
[Historical Payload retrieval](#historical-payload-retrieval).

## Retained Payload validation

Sealing validates each candidate's retained Payload fields, version, commitment,
exact content length, links and candidate-Epoch caps before publication. Missing,
unparseable or invalid retained content aborts the transaction, preserving
queued Envelopes, seen IDs, chain tips and rejection history for repair and
retry. Size-cap failures retain the exclusion and successor handling under
[Delta size-cap profiles](#delta-size-cap-profiles). A local Payload mismatch
does not reject its signed Delta (WIST-1 §7).

Record materialization repeats validation when reading content and aborts on
failure before publishing the Epoch or Checkpoint. Accepted Payload files and
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

Sealing repeats the check against the candidate Epoch's `sealed_at` and
allowance. WIST1-E06 rejections release the queued copy and dependent successors
through [Declaration key binding](#declaration-key-binding), allowing later
pulls to retry. Historical Delta replay and sealed index restoration use each
committing Epoch's time and allowance. `VerifiedEpoch::clock_skew_seconds()`
and `DeltaSource::clock_skew_seconds()` expose the authenticated value; a
verified Epoch alone still establishes no Delta eligibility.

The exact inclusive comparison preserves arbitrary Publisher timestamp
fractions, signed allowances and bounds outside the written year range.
Later Epochs, parameter amendments or wall time cannot repair a clock-invalid
sealed Delta. Historical failure stops the complete pinned reconstruction
without a partial result, following [Historical Delta sources](#historical-delta-sources).
Completed index repairs still skip rebuilding; this is not general legacy-state
revalidation, Consumer ignored-Entry replay or proof of the Log clock's accuracy.

`delta-clock-time.json` supplies 96 signed clock probes, exercised with
authenticated parameter histories. Signed Delta histories cover committing
profiles, rejected amendments, later Epochs, restart and corrupt-file repair.
Live tests exercise fractional rejection across Declaration refresh, fresh
attempts after restart, predecessor waits and queued chains crossing a reduction.

## Historical Delta sources

`history::deltas::DeltaSource::reconstruct(directory, pinned_head, delta_id)`
returns one included Delta only after authenticating the entire pinned
Epoch/parameter and Declaration prefix and checking every included Delta's
fields, version, committing size caps, [clock eligibility](#delta-clock-eligibility),
historical authority and predecessor chain. Authority uses [Declaration history replay](#declaration-history-replay)
and [Declaration key binding](#declaration-key-binding); trust inputs and
unsupported transitions follow [Authenticated history](#authenticated-history).

Chains retain signed Publisher/URL ownership and exact predecessor observation
times across scope changes, rotation, recovery and identity resets. Within each
Epoch, predecessor links determine chain order independently of storage order.
Missing predecessors, forks, duplicate IDs, invalid authority or non-increasing
observations stop reconstruction, including failures after the requested Delta.
This is a strict integrity check of the Aggregator's retained history; it does
not implement Consumer ignored-Entry dispositions.

The source retains its Delta ID, original Envelope, canonical Entry position,
Epoch sealing time, authenticating Declaration, identity's first-installation
or latest reset position and committing size caps.
Later history cannot change those bindings. Contentless `attest`
and `delete` Deltas are supported. Sealed-predecessor admission uses this source;
index reconciliation shares its sealed Delta checks. Their unsealed-state
policies remain under [Delta predecessor admission](#delta-predecessor-admission)
and [Delta index reconciliation](#delta-index-reconciliation).

Reconstruction changes no retained state and exposes no partial result. It scans
the full prefix, retaining Declaration state, every seen ID and each Publisher/URL
tip; bounded lookup remains required. It does not check Payload bodies or
materialization, and does not replace live admission or `verify-history`.

Signed tests cover exact predecessor vectors in same-Epoch and cross-Epoch chains,
invalid ancestors and later unrelated Deltas, independent Publishers sharing a
URL, identity resets, contentless successors, recreation after deletion, restart
and repair/retry.

## Historical Payload validation

`history::payloads::PayloadSource::reconstruct(directory, pinned_head, delta_id)`
requires a [historical Delta source](#historical-delta-sources) with a Payload
commitment. `delta_source()` exposes its authenticated bindings.

`PayloadSource::validate(raw)` applies the complete
[Payload validator](#retained-payload-validation) to supplied bytes with the retained
commitment, signed Publisher and caps. Reconstructing after restart selects the
same profile; another Delta's profile cannot replace it.
Invalid bytes return a Payload error without mutating the source or stored state,
allowing another copy to be checked. Retrieval follows the contract below;
availability and withdrawal remain separate requirements.

Signed tests cover 103 default-profile Payload field cases, original-byte and
numeric-value preservation, historical cap references and invalid cap Epochs,
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
withdrawal or a serving fault. Reads and fetches
write no files or history state and retain no failure cache, so callers can
retry another copy. An `attest` or `delete` Delta has no own Payload to
retrieve.

`retrieve(client, candidates)` tries `PayloadLocation` file paths or URLs in
caller-supplied order, stopping at the first verified copy. `retained_location`
derives the local path; `distribution_location` appends the WIST-3 §6.1 path
to a configured HTTP(S) origin, preserving its port; `publisher_location`
derives the WIST-2 §3.1 path from the Delta's signed Publisher. Each uses the
Payload source's Delta ID. Parsed distribution origins must be bare, without
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
destination policy, 30-second request timeout and five-hop redirect limit
within the same Canonical Host, and reads a Payload only up to the cap its
content caps imply ([Fetch bounds and destination policy](#fetch-bounds-and-destination-policy));
file reads remain unbounded. Callers enforce withdrawal,
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
admission/replay integration remains unimplemented.
Signed-history tests cover
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
authenticated pinned Epoch prefix and retained current/pending admission rows;
corrupt history rejects restoration before any floor is written. Retained
admission rows are local accepted state, not authenticated Log inclusion.

Declaration sequence consumers use the validated numeric value under WIST-1
§§4/5.1. Integral decimal/exponent spellings and negative zero preserve
admission floors, pending recovery-head order, capped packing, sealed metadata
and Snapshot sealing-height lookup. Retained Envelopes remain unchanged;
Epochs and Snapshots use JCS serialization. Signed live/restart tests cover
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

Before admission, `recovery::settle` authenticates the pinned Epoch prefix and
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
in a candidate Epoch receive these checks before any group installs; rejection
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

Every seal reconstructs Declaration state from the complete authenticated Epoch
prefix pinned by the database head before using recovery sources. Settlement
uses the last recovery follower sealed inside the window, before the candidate
Epoch's Declarations. Delta sealing uses the Declaration state projected from
the Entries actually selected under the byte cap. A superseded competitor's
higher sequence cannot displace the restored recovery head; an unsealed
follower cannot change settlement authority. A deadline-Epoch replacement can
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
status rejections, stored recovery state and the committed Epoch head. A failed
Declaration candidate rolls those changes back. Missing or corrupt pinned
history stops sealing before settlement. Epoch/checkpoint file publication and
Snapshot generation do not share SQLite's transaction; crash recovery across
those stores remains a separate requirement. The history reader also rejects
prefixes produced off the signed cadence grid by local cadence overrides.

Admission's predecessor choices, accepted sequence floor and deadline
settlement are described at the start of
[Declaration key binding](#declaration-key-binding).

Pending and recovery copies share a persistent acceptance counter. Queue
transfers retain that order and clear pre-window inclusion turns; every pending
copy enters recovery when its window opens, including copies excluded by either
Epoch cap. Settlement survivors become eligible in acceptance order, with the
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

A recovery Declaration whose window would end after 9999-12-31T23:59:59Z
stops sealing before publication, and history replay rejects an Epoch sealing
one under WIST1-E08 (WIST-1 §5.2); window ends up to that instant are spelled
by `registry::instant`, which covers the whole four-digit-year range, so every
published window end is a Log timestamp.
Correct sealing source selection does not establish complete recovery admission,
Delta chains or schema validation.

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
Full authenticated Delta chains, signature-failure Declaration re-fetches and
sealed Feed key provenance remain incomplete.

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
The schema gate does not establish exact Page cardinality, publication/history
partitioning, supported-major policy or durable selected-source provenance;
target validation is described under [Feed next targets](#feed-next-targets).

## Feed next targets

The walk reads `next` only after the carrying Feed or Page passed the field,
domain, signature and live regression checks and lists an unseen Delta ID. A
read target is fetched only when it is byte-identical to its Normalized URL
and begins with `https://`, the requested Canonical Host and
`/.well-known/wist/` (WIST-2 §3.2, ADR-0038); no Declaration or
`subdomain_scope` host takes part, and the query is requested as written. A
loopback deployment under `--allow-http` rewrites only the scheme. A failing
target records WIST2-E01 without noise, is never requested, and stops the
walk while the Deltas of the objects already fetched proceed to admission.

`feed-next.json` drives the field and target dispositions of every case
through the same functions the walk uses; live HTTP tests show dot-segment,
encoded, port, scope-host and encoded-separator spellings stop the walk
without a Page request while the live Feed's Delta is admitted, a query
survives retrieval byte for byte, and an ingested or empty object never
reads its `next`.

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

Sealed Page keys come from the complete authenticated Epoch prefix pinned by
the database head, using WIST-2 §3.2's current and first-next Declaration
cutoffs. Accepted unsealed Declarations supply no Page authority; first-contact
and rotation Pages can require another pull after their Declaration seals.
The `sealed_declarations` database summary supplies no verification evidence.

Declaration replay authenticates every source and excludes competitors when
recovery settles in that prefix; admission-time settlement alone changes no
Page source. Repeated idempotent Declaration
Entries retain their own Epoch times; the first-next search cannot skip them
to borrow a later rotation. Each selected source retains its complete signing
bindings, including reused identifiers. Missing or invalid pinned history
stops the pull before Page-derived Deltas enter admission. Trust inputs and
unsupported history transitions follow [Authenticated history](#authenticated-history).

Signed HTTP/restart tests cover unsealed-to-sealed authority, retired and reused
keys, alias renames, multiple Declarations in one Epoch, idempotent repetitions, recovery
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
URL chains, budget suspension/resumption and corrupt history. Signed-Epoch
regressions cover invalid ancestor/target signatures, missing ancestors, later
unrelated Delta failures, restart, repair/retry and retired-key authority.
Lookup scans retained domain admissions and, when needed, the full pinned Epoch prefix for
each predecessor; bounded lookup and complete authenticated Delta replay remain
separate requirements.

## Delta index reconciliation

Opening a store without a completed reconciliation marker rebuilds seen IDs
and Publisher/URL tips from its complete authenticated Epoch prefix and retained
pending/recovery admissions. This removes orphaned IDs left by discarded copies
and restores pairs overwritten by the former URL-only table. The Anchor and
database head are operator-trusted inputs, as in [Authenticated history](#authenticated-history).

Every retained Envelope passes the field and version checks in
[Delta field validation](#delta-field-validation). A `new` or `update`
without a `payload` commitment stops restoration with WIST1-E09;
an `update`, `delete` or `attest` without `prev` stops it with WIST1-E07.
Field/version checks run first. Sealed sources come from Declaration replay
at each Epoch. Sealed size and clock checks follow
[Delta size-cap profiles](#delta-size-cap-profiles) and
[Delta clock eligibility](#delta-clock-eligibility). Restoration checks Delta
signing bindings, key-time bounds and scope, then follows predecessor links
within that Epoch. Retained unsealed copies follow persistent acceptance
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
cases exercise same-Epoch chains, successive Epochs, sealed-to-queue transitions
and both queue orders.

## Parameter schedules and Epoch sizes

Parameter admission checks the accepted schedule and queued amendments in
canonical Entry order. Sealing repeats validation at the actual Epoch
instant: delayed or conflicting amendments are dropped with WIST4-E03.
Every prospective map is checked, including grace changes and the
links, retention and Epoch-size combination rules. A
`recovery_window_days` amendment whose window from its own `effective_at`
would end after 9999-12-31T23:59:59Z is rejected at acceptance (WIST4-E03,
WIST-4 §5); the signed-history test replays the rejected amendment, the
largest representable window and an unsealable opening near the range end.

Caps cover the largest Epoch through each amendment's own height, counted
in entry-bundle octets. Pending reductions constrain packing immediately;
deferred Entries remain queued. SQLite stores actual Epoch sizes and
canonical Entry positions with the sealed changes. Restart replays the
accepted schedule using each historical size maximum, and rejects a
history containing an Epoch that exceeded its accepted schedule. Snapshot
parameter tuples include pending amendments and omit superseded
equal-effective-time values.

A store written before the Log became one tree keys its Blocks by a
per-Block hash and holds no leaf data; opening it fails with that reason
rather than half-migrating it. A store written before this rename still
names its table and columns after `block` and is refused the same way.
Start a new data directory.

Schedule validation uses the protocol's Registry defaults. Direct local
parameter overrides, including the accelerated `--cadence` setting, do not
amend that schedule and must not be used to assert protocol conformance.

## Authenticated history

`clave verify-history --data <directory>` authenticates the retained Log
from genesis through the database's current head and reports the tree size
and root it reaches. It needs the public `anchor.json`, not the private
signing key. The directory's Anchor and database head are operator-trusted
inputs; this command does not discover newer Checkpoints or detect
replacement of both trusted inputs.

The reader parses each Checkpoint as a signed note, checks that it states
the Epoch the store records, checks sequential `epoch_number`s,
non-shrinking tree sizes,
strictly increasing whole-second timestamps on the cadence grid, canonical
Entry order and each Entry's JCS leaf data, and recomputes the root the
Checkpoint states from the retained leaves and the stored tree hashes.

It then replays the Epoch's Aggregator key acts — authenticated under the
keys valid at the height below it — and verifies the Checkpoint's signature
under the keys valid at the Epoch itself (WIST-3 §3.4, §5). The signature
is checked in that order because the keys that can speak for Epoch N are
the ones the Log establishes at N. An Epoch whose Checkpoint verifies under
no such key stops the reader, and its key acts change nothing: an Epoch
whose accepted removals leave no valid key has no valid Checkpoint and is
never applied. The registry the reader reaches is available with the
`aggregator_key` tuples it produces, and `verify-history` prints the keys
valid at the head.

The reader reconstructs accepted parameter schedules from signed Envelopes,
independently of the database's parameter summaries and local overrides.
Each Epoch's transport bound comes from the verified prefix; current and
pending caps constrain its actual size. Invalid parameter candidates are
reported by canonical Entry index and change no schedule. Missing or
corrupt history stops verification.

Log timestamp parsing rejects leap-second spellings without normalization
and supports the complete four-digit Gregorian range, from year zero
through `9999-12-31T23:59:59Z`. Conversion uses civil-calendar arithmetic;
accepted parameter schedules still determine which seconds are eligible
sealing instants.

The `history::History` API exposes each authenticated Epoch's complete
Entries, original Envelopes, height, timestamp, tree size, root and
canonical positions, plus the accepted parameter schedule. It holds one
Epoch at a time and retains the accepted schedule. Callers must finish
iteration successfully before committing a reconstructed state: the
supplied head's root binds the complete prefix only when its Epoch is
reached. A failed reader cannot resume, and Epochs sealed after opening
the reader are outside its pinned prefix.

Supported histories use object version `1.0.0`. Successor Anchors stop the
reader as unsupported. A `parameter_change` counts toward the schedule only
when it authenticates under a key valid at its Epoch; an act no such key
signed is reported as an ignored candidate.
Authentication establishes Epoch inclusion; it does not establish an
Entry's author or eligibility. Parameter Envelopes receive their own signature and admission
checks. Other Entry validation and service state reconstruction remain
separate from this command; successful history verification is not full
protocol conformance.

## Declaration history replay

`history::declarations::Declarations::reconstruct(db, directory, pinned_head)`
rebuilds Declaration sequence and author state from the authenticated Log.
It returns state only after reaching the trusted head successfully. Streaming
callers can instead pass each `History` result to `Declarations::apply`.

Replay preserves original Envelopes, publisher-object hashes, sealing times
and canonical Entry positions. Each domain’s equal-sequence groups apply in
ascending sequence after due settlement. Conflicting first installations or
failed Declaration acceptance reject the entire Epoch, preserving the previous
Declaration state and returning no effects. Idempotent current re-serves
install no signature and change no position. A streaming caller must stop and
discard its `History` reader after any Declaration-stage failure: that reader
has already advanced its separate Epoch/parameter state. Keep reconstructed
state and effects private until the complete pinned prefix validates.

Each domain retains its current Declaration, highest accepted sequence,
first-sealing position and latest fresh-identity reset position. An open
recovery window also retains its owner, original predecessor, current recovery
head and off-chain competitors. Its deadline uses the owner Epoch’s signed
parameter schedule and exact 128-bit arithmetic, surviving later amendments
and recovery followers. Settlement restores the recovery head without lowering
the sequence floor or resetting identity. Returned installation and settlement
effects identify resets, window openings and superseded competitors. They do
not apply database or queue changes.

`Declarations::project(sealed_at, recovery_window_days, entries)` evaluates
one proposed next Epoch without changing the accepted prefix. Pass its complete
Entries in canonical storage order after packing, and the recovery-window
parameter from the authenticated schedule in force at that proposed instant.
The method validates the parameter's value, timestamp profile and forward
ordering, Entry wrappers/order, and Declaration fields, authors and acceptance.
It does not authenticate the supplied parameter profile, check the cadence or
Epoch size, or validate other Entry bodies. A successful projection is therefore
conditional on those checks. Recompute it if the timestamp, profile or selected
Entries change.

Snapshot `declaration` and `recovery_window` tuples are built from this
projection at each seal (WIST-3 §7, ADR-0040): the current Envelope, its
sealing height and the highest accepted `seq`; and, for an open window, the
owner height, the window end, the recovery-chain head Envelope and its
sealing height, so a resuming Consumer verifies followers against the head
and keeps the floor a restored lower-sequence head leaves above the current
`seq`. The live recovery test checks both tuples after a recovery rotation.

The returned `Projection` exposes proposed domain state and effects, without
an accepted head or a way to install it as authenticated history. Its Declaration
positions, sealing times, identity resets and window openings are prospective.
Only `apply(VerifiedEpoch)` advances replay, using the same transition logic.
Projection failure exposes no state or settlement effects. An unsealed follower
cannot change the accepted recovery head, sequence floor or future settlement.

`Domain::delta_admission_sources()` returns the frozen predecessor and owner
while that state's window is open, otherwise its current Declaration.
`delta_sealing_source()` returns no source during an open window, because its
Deltas must queue. At a deadline, `Projection::effects().settlements` retains
the sealed recovery head used to revalidate existing queued copies before any
candidate Declaration applies. The projected domain's sources reflect all
candidate replacements afterward. A deadline-Epoch replacement can therefore
change sealing authority without changing the queue's settlement authority.
These accessors describe the supplied prefix or projection; they do not refresh
live admission state, settle SQLite queues, or perform Delta eligibility checks.

Signed recovery probes exercise candidate rejection, retained sequence floors,
unsealed follower isolation, deadline boundaries, distinct settlement/sealing
scope and restart reconstruction. Live sealing consumes these projections
after packing and filtering. Live admission still requires integration with
durable queue, status and chain-tip updates, including preservation of
acceptance order across queues.

This API validates Declaration fields, sequencing and author authentication.
Deltas and non-parameter Registry Updates receive no eligibility checks here.
SQLite uses this state to restore missing owners of legacy opened recovery
windows. Live sealing reconstructs and projects this state for source selection;
general admission and database reconstruction still use separate state.
`verify-history` retains its Epoch/parameter verification scope. Snapshot
recovery state also requires the protocol’s unresolved Snapshot representation
rules. Successful reconstruction is not full protocol conformance.

Replay retains all domains’ current state and open-window competitors in memory;
atomic application stages a copy of the domain map while sharing immutable
Declaration Envelopes. It does not provide bounded-cache or Snapshot resume
behavior. Tests consume signed recovery ownership, predecessor, conflict,
identity and settlement histories, including corrupted or missing
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
  `http` when the host is a loopback address, `localhost` or a name under
  `.localhost` (RFC 6761), which WIST-2 §8 forbids for any `wist`
  resource. Without the flag every fetch is HTTPS, and the flag never
  relaxes the scheme for a non-loopback host. `seal --allow-http` applies
  the same exception to Witness submission.

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
(logbook & distribution: the tree, tiles, checkpoints, snapshots) is
what Clave implements, on top of the WIST-1 deltas it ingests.
