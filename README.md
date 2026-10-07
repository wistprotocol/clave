# clave

The publication format — Declarations, Collections, Catalogs, Items and Payloads — targets [WIST specification revision `f4acfefbe7d3cdb8e82ed34053377159d8782890`](https://github.com/wistprotocol/spec/tree/f4acfefbe7d3cdb8e82ed34053377159d8782890). Object version `1.0.0` alone does not identify a compatible draft.

WIST Protocol aggregator. Clave pulls each Publisher's Declaration, the
Catalogs of its Collections with their Items and Payloads, and its Label
Feed through ping + pull, judges them, and seals hourly Epochs into one
growing RFC 6962 Merkle tree. It serves that tree as C2SP tlog-tiles tiles
and entry bundles, its head and archived Checkpoints as signed notes, the
Payloads of sealed Items, and periodic Snapshots over HTTP for Consumer
sync.

Subcommands: `init` (generate the log's genesis key and local store, and
print the signed-note verifier key a Witness is configured with),
`serve` (HTTP ingest + read endpoints; seals an Epoch at every cadence
grid instant and produces Snapshots unless `--no-seal`, under the store
instance name `--instance <name>` gives it), `seal` (append the next
Epoch's Entries to the tree and publish its Checkpoint at the wall clock
floored to the accepted cadence grid, or at `--at <whole-second UTC
instant>` for a test Log that advances Log time faster than the clock,
then produce the Snapshot at the new head unless `--no-snapshot`;
it prints the seal's and the production's wall time), `witness`
(maintain the Witnesses each sealed Checkpoint is submitted to),
`snapshot` (produce the signed, verifiable point-in-time Snapshot at the
sealed head for cold-start sync, see [Snapshot production](#snapshot-production)),
`verify-history` (authenticate every stored Epoch and replay it),
`restore` (rebuild the tables derived from the Log, see
[Restoring the Log-derived tables](#restoring-the-log-derived-tables)),
`param-change` (queue a signed `parameter_change` Registry Update,
WIST-4 §5: bounds and combination rules checked, `effective_at` held past
the grace period, applied to the live parameter set once its Epoch seals
and the effective instant passes; a change whose grace window lapses
while queued is dropped from the Epoch and reported by `seal`),
`withdraw --domain <Publisher> --item-id <Item ID>` (queue a
`payload_withdrawal`, WIST-4 §5.1 and WIST-3 §6.2, naming a sealed Item:
at sealing the act replays through core's withdrawal engine under the Log
key and seals only beside or above an Item of the subject; its Epoch
destroys the held and served Payload, ends its Payload duty, removes
every served and staged Snapshot, rewrites the index without them and
leaves a `withdrawal` tuple in every later Snapshot state; the record
stays and is no longer materialized, and a later pull refuses the Item
with `WIST2-E03`), `suffix-list` (pin a Public Suffix List file, WIST-4
§3.1: the octets are held in the store and served at
`/log/suffix-lists/<hex>.dat` without expiry, and the queued
`suffix_list_update` seals in the next Epoch and is in force from the
Epoch after it; `init --suffix-list <file>` pins one for Epoch 0, and
without a pinned snapshot every Canonical Host is its own accounting
unit), `mirror` (maintain the signed `/log/mirrors.json`), `log-key`
(rotate the Log's own Aggregator keys, see
[Aggregator key rotation](#aggregator-key-rotation)).

`serve` additionally enforces the flat `quota_base` ping quota (429 +
Retry-After; only WIST2-E02/E04 pings count as noise), accounted per
Registrable Domain under the snapshot in force at the Ping and reported
as the shared remainder at every host's status endpoint, and re-pulls
every known publisher `baseline_poll_seconds` after its last pull
without a Ping, as [Concurrency](#concurrency) describes. The seal's
per-domain Epoch capacity counts Entries per Registrable Domain under
the snapshot in force at the Epoch, and the Snapshot state carries the
`suffix_list` tuple (WIST-3 §7).

## Pulling a Publisher

A pull (WIST-2 §5.1) fetches `/.well-known/wist/publisher.json` once,
outside the ingest budget, and judges it under the Collection limits of
the parameter map in force (WIST-1 §5). A first contact that fails is
`WIST2-E04` noise and stores nothing; a later Declaration that fails is
reported with its WIST-1 code and stops the pull at `WIST2-E01`. A
discovered Declaration that reduces authority is held for sealing with
the last height it may seal at (`record_seal_epochs`), and the Publisher's
Catalogs and Items wait behind it.

Each Collection the Declaration in force names — with the recovery
head's beside it during a recovery window — is then pulled in the
Declaration's order, every pull restarting from the first:

1. `collections/<name>/catalog.json` is fetched, read up to 16 385
   octets, with `If-None-Match` carrying the validator of the octets last
   read whole for that Collection. A Catalog not later than the last
   accepted one that is no idempotent re-serve is `WIST2-E05`; one that
   names another Publisher or Collection is `WIST2-E04`.
2. The list of an accepted Catalog is a held list of the Catalog's
   `size` and `root`; else, where a list of the Collection is held, the
   chain of `changes/<hex>.json` change lists applied oldest first,
   accepted only where the resulting count and root match; else the walk
   of its `tree/` files under `tree_file_cap_bytes` and `tree_depth_max`,
   reading held tree files first and holding every file read whole by its
   hash. A discarded chain is `WIST2-E08` with its condition, the
   fetched Catalog's ID and the change list where it was met; the walk
   that follows decides the Catalog. A walk meeting a condition of
   WIST-2 §5.3 is `WIST2-E07`, as is a list holding no Item for the URL of
   a record the Log holds for the Collection, unless the Catalog is a base
   against the floor; the report names those URLs.
3. Each Item of the list not yet judged is judged in list order: an Item
   whose Item ID a withdrawal names, or whose Payload
   (`payloads/<hex>.json`) is missing or fails WIST-1 §7, is `WIST2-E03`;
   the Payload of an admitted Item is held under `held/payloads/` until
   the Item is sealed.

The Label Feed (`label-feed.json` and its Pages) is pulled once every
Collection's pull has ended, under WIST-2 §3.2's rules; each unseen Label
or dispute is validated through core and waits for sealing, and a
failure is `WIST2-E06` with its ID.

Fetches are bounded while they stream: a Declaration, Label Feed page or
Mirror list at 1 MiB, a Label at 16 KiB plus twice `url_cap_bytes`, a
change list at the suite's change-list cap and a tree file at
`tree_file_cap_bytes`. Content fetches are further bounded by the daily
ingest budget of the host's Registrable Domain and by the pull's work
limits (64 MiB, 4096 objects and 300 seconds); a pull that reaches one
suspends, and the next pull resumes from the held files. Every fetch
connects only to a public unicast address (WIST-2 §8); a redirect stays on
the requested Canonical Host or a host the Declaration in force scopes.

## Recovery windows

From the discovery of a recovery rotation until its window settles
(WIST-1 §5.2), a pull judges Catalogs under the two frozen sources and
queues each one it accepts per Collection name and signing key. The
queue settles at the first pull or Epoch at or after the window's end:
every queued Catalog is judged again by C1 under the settlement source
with that event's instant, a failure being `WIST1-E13` and a Catalog not
later than the floor `WIST2-E05`, and the survivor of each name becomes
its last accepted Catalog. A seal whose cadence slot falls before the end
of a window whose queue a pull already settled is refused and sealed at
a later grid instant.

## Sealing

Each Epoch is planned from the stored waiting state: discovered
Declarations, Registry Updates, waiting Catalogs, Items with their
inclusion proofs against the latest Catalog, removal markers, Labels and
disputes, in place order under the per-domain capacity, the inclusion
ceiling and the deferrals of WIST-3 §3.3. An Entry over 65 535 octets is
never planned: an Item that large leaves with `WIST1-E04`, a Catalog
leaves as one failing C1 would and the seal reports it with `WIST3-E03`,
and a Declaration fails at sealing with `WIST1-E04`. The Epoch is fitted
to `epoch_cap_bytes` by leaving Entries unsealed, judged by core's
sealing replay resumed at the head, and committed only when every planned
Entry is valid. The commit writes the latest Catalogs, records, removals,
sealed Items, Payload duties and the deferrals and holds of the waiting
publications in the sealing transaction. The Payload of every sealed
page Item is served under `payloads/` before the Checkpoint is published
and for as long as its record holds or its `payload_window_days` window
runs.

The status endpoint (`/status/<domain>`, WIST-2 §7.1) lists one entry per
Collection that the Declaration in force or the recovery head names or
that the store holds, with its latest and last accepted Catalog IDs and
every Catalog and Item that waits or is queued, with the deferrals of the
last sealed Epoch and whether a Declaration that reduces authority held
it there; rejections carry their Catalog or Item ID, Collection, URLs and,
for `WIST2-E08`, the condition and change list.

## Restoring the Log-derived tables

`clave restore --data <dir>` replays the stored Log through core and
rewrites, in one transaction, every table the sealed Entries determine:
the latest Catalogs with their sealing height and base flag, the records
with the height that sealed each, the removals, the sealed Items, the
withdrawals and the Payload duties in force at the head. Pull state is
not in the Log and is not restored: held lists and tree files, list
admission, waiting places and eligibility, the recovery queue, discovered
Declarations not yet sealed, and the deferrals of the last seal. A
restored Aggregator recovers them by pulling: each Collection's next
pull walks or chains its list again and admits its Items, taking new
places.

## Store layout

The store carries a layout version. A store of an earlier layout is
refused at open with an instruction to start a new data directory; no
migration runs.

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
not at every start. Snapshots are produced separately, as described
under [Snapshot production](#snapshot-production).

The served layout is:

```
/checkpoint                       (the head Checkpoint, a signed note)
/tile/<L>/<N>[.p/<W>]             (tree hashes, 256 per full tile)
/tile/entries/<N>[.p/<W>]         (entry bundles: the leaf data)
/log/checkpoints/<epoch_number>   (every Checkpoint published)
/log/anchor.json /log/mirrors.json /log/suffix-lists/<hex>.dat
/payloads/<hex>.json             (the Payloads of sealed Items, under duty)
/snapshots/index.json /snapshots/<date>/<epoch_number>/...
```

`serve` sends `/checkpoint` and the archive as
`text/plain; charset=utf-8` with `Cache-Control: no-store`, because both
are rewritten — the head at every Epoch and an archived note whenever a
Cosignature is added. Full tiles and entry bundles are
`application/octet-stream` with `public, max-age=604800, immutable`;
partial ones carry the same media type without caching, because they
stop being served once the full tile exists.

## Restored stores and published heights

Two validly signed Checkpoints of one Log stating the same `epoch_number`
and a different tree size, root hash or `sealed_at` are Equivocation
(WIST-3 §5), and nothing withdraws a published Checkpoint. A store
restored from a backup taken before the last published Checkpoint would
seal that height again, so `clave` never signs or publishes a Checkpoint
while a different or higher Checkpoint of its Log is published.

Before every distribution pass — at `seal` and `serve` start, before and
after every seal, and before a Cosignature rewrites a Checkpoint file —
the store's head Epoch is compared with the data directory. The published
height is the higher of the `epoch_number` of `/checkpoint`, when it
parses as a Checkpoint, and the highest name in `/log/checkpoints/` made
of at least nine ASCII digits; other names are ignored. The pass is
refused, with nothing written, when that height is above the store's
head (a store with no Epoch is below a published Epoch 0), or when
`/checkpoint` or the archived file at the head's `epoch_number` parses
with signed note text — every line the signature covers, not the
signature lines, since Cosignatures differ — other than the store's. A
file named above the head refuses by its name alone. A file at or below
the head that is missing, torn or unparseable is repaired from the store,
as described above. Signatures are not checked: a restored store may
predate the key that signed a later Checkpoint. `serve` therefore does
not start, with or without `--no-seal`, while the refusal holds.

Before sealing, each listed Mirror's `<base URL>checkpoint` is fetched,
bounded at 65 536 octets. A `404` passes, as does a Checkpoint of this
Log at or below the store's head whose signed note text equals the
store's at equal height; a Checkpoint above the head or different at the
head refuses. Any other answer — a connection failure, timeout, other
status, an oversized or unparseable body, another Log's Checkpoint —
refuses as unconfirmed, because a seal cannot be undone and a refusal
costs one grid instant. `seal` consults every listed Mirror on every run.
Since the store commits before anything is published, a Mirror can only
be ahead after the store is replaced, which needs a restart; `serve`
therefore remembers, for the life of the process, each Mirror a
successful seal confirmed, and consults only listed Mirrors it has not
confirmed, so a Mirror listed later is consulted at the next seal. A
refused seal confirms no Mirror. No flag, environment variable or
setting overrides either refusal.

The refusal names the published height and the file or Mirror URL that
holds it. To recover:

1. Restore a backup whose head is at or above the published height.
2. When no such backup exists, end the Log and start a successor Log
   with a new `log_id` whose Anchor's `predecessor` names the final
   published Epoch and its root hash (WIST-3 §3.4). Never seal the old
   Log below its published height.
3. A Mirror that is permanently gone stops being consulted once it is
   removed from the signed Mirror list with `clave mirror --remove`.

The comparison protects against restoring an older store by accident,
not against an operator who deletes published files. The store and the
published files share the data directory, so a restore that replaces the
whole directory with an older copy removes the newer Checkpoints with the
store and leaves only a listed Mirror to reveal the published height:
keep the published files of the replaced directory and copy its
`/checkpoint` and `/log/checkpoints/` over the restored ones before
starting `clave`.

## Snapshot production

A seal publishes the Checkpoint only; the Snapshot at the sealed head is
produced afterwards by `seal` (unless `--no-snapshot`), by `clave snapshot
--data <dir>` (`--rebuild` rebuilds every shard instead of reusing
unchanged ones), or by `serve`'s producer task, which runs at start, after each
successful seal and every 60 seconds, and retries at once when a
withdrawal supersedes its build. `--no-seal` instances never produce. One
producer runs per data directory at a time, holding an exclusive lock on
`snapshot-build.lock`; a second one fails naming it. Production prints one
of `snapshot built at epoch N for <date> in M ms, K of S shards rebuilt`,
`snapshot current at
epoch N` (a Snapshot of the head Epoch is already served; with or
without `--rebuild`, nothing is built, and regenerating a served
Snapshot means sealing a new Epoch), `snapshot
superseded by a withdrawal at epoch H` or `snapshot not built: no Epoch
sealed`. A built Snapshot is followed by `snapshot bytes written N`
(bytes the build wrote into the staging directory: rebuilt tier files,
tier files copied because a hard link failed, `state.json` and
`manifest.json`), `snapshot bytes reused N` (tier files hard-linked from
the shard cache), `snapshot cache bytes written N` (bytes copied rather
than hard-linked into the shard cache), `snapshot payloads read N` and
`snapshot payload bytes read N` (Payload files read to build tier 1).

A producer reads the head Epoch and every input of the build (the latest
Catalogs, records, removals and withdrawals, parameters, suffix list,
Labels, Aggregator keys, the Declaration replay) in one SQLite read
transaction, so pulls and seals committing meanwhile are neither blocked
nor included. The state file carries one `collection`, `record`,
`removal` and `withdrawal` tuple per row of those tables, the tuples a
full replay of the Log gives. The materialized records are chosen by
WIST-3 §7's one-URL rule and ordered by Publisher, then URL, as UTF-8
octets; the link rows follow them, each record's by ascending
`position`. Tier 0's `records` table and `tier1/extracts.parquet` carry
the columns WIST-3 §7 names, then `collection`. A materialized record
whose Payload is missing, does not parse or does not reproduce its
Item's commitment fails the build with an error naming its Item ID
(WIST-3 §7). The files are written and synced into the staging directory
`snapshot-build/<epoch number>/`, outside `/snapshots` and never served,
then moved by one rename into `snapshots/<date>/<epoch>/`, the Epoch
zero-padded to nine digits (WIST-3 §6). That directory does not exist
before the rename, and a served directory is never rewritten: a later
Epoch sealed on the same date gets its own directory. The index is then
regenerated from the manifests on disk, newest date first and the
higher Epoch first within a date, and written through a synced
temporary file. The check for a withdrawal sealed above
the build's Epoch, the swap and the index write hold
`snapshot-swap.lock`, as does a withdrawal seal's removal; such a
withdrawal abandons the build instead of swapping it in.

A Snapshot superseded by a later one of the same date stays served and
listed for 24 hours (`SUPERSEDED_GRACE_SECONDS`), so a Consumer that
read the index before the newer Snapshot was swapped in finishes its
download. The index regeneration that first sees the older Snapshot
superseded records that instant in `snapshot-superseded/<date>/<epoch>`,
outside `/snapshots`; a reconciliation at or after 24 hours past it
rewrites the index without the entry, then removes the directory and the
marker. A missing or unreadable marker is rewritten with the current
time. Snapshots of earlier dates stay served until a withdrawal removes
them.

Tier files are reused per shard (unsharded: one shard). A shard whose
record projections (WIST-3 §7 `content_digest` over the shard), their
Collections, and Labels, disputes and labeler rows are unchanged since the last build
hard-links (else copies) its six tier files from
`snapshot-shards/<shard>/` instead of rebuilding them, reading no
Payloads; `content_digest`, `state.json` and the manifest are computed
in full every build. The cache lies outside `/snapshots` and is never
served. Each entry holds the tier files and `fingerprint.json` (shard
count, shard, Epoch, both digests, each file's `sha256` and `bytes`); an
entry is reused only when its fingerprint parses, matches and every file
has its listed length and `sha256`, so damage to the cache never reaches
a manifest. Entries of rebuilt shards are replaced under
`snapshot-swap.lock` after the withdrawal check and before the swap,
through `<shard>.new/` with the fingerprint written last; entries at or
above the shard count are removed. After `snapshot-shards/` is deleted,
the next build rebuilds every shard.

Every start of `seal` and `serve`, and every seal, reconciles the served
tree before re-signing it: an abandoned staging directory is removed
unless a producer holds its lock, `snapshots/index.json` is
regenerated when it is unparsable, missing while Snapshots are served, or
lists other entries than the manifests present (WIST-3 §6), and then an
entry under `snapshots/<date>/` that is not a directory holding a
readable manifest of that date and Epoch is removed, as is a superseded
Snapshot past its grace period. A withdrawal
seal's transaction drops the withdrawn record and records the removal
still owed; before any Checkpoint is published, the owed removal deletes
the Payload file, every served Snapshot, every grace-period marker, the staging area and the
`snapshot-shards/` entries of the withdrawn Items' Publisher shards,
writes an index listing none, then marks itself done and truncates the
store's write-ahead log. A removal interrupted before it was marked done
runs again at the next seal or start of `serve`, so no served Checkpoint
is at or above a withdrawal's height while its content is served; the
next production rebuilds those shards without the withdrawn content.
Reconciliation without a running producer also removes unfinished
`snapshot-shards/*.new/` entries.

## Witness cosignatures

`clave witness --data <dir> --add <verifier key> --url <base>` records a
Witness; `--remove <name>` drops one and no argument lists them. The
verifier key is the signed-note string `<name>+<hex key ID>+<base64 key>`
of the Ed25519 cosignature/v1 type, and the store keeps the tree size each
Witness last cosigned. Default: no Witness, and a seal then submits
nothing.

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

A pull runs under a run of the domain (`pull_runs`, at most one open per
domain): each request enters `pull_objects` with the bytes it reserved
before it is issued, and its response and admission move that row
forward. The Collection pull machine holds no store connection while it
fetches; each Collection's admission is one write transaction under the
pull's fence. A pull that loaded its state before a seal committed
reloads it and pulls that Collection again. A pull's position across
pulls is the held tree files, the held lists with each list Item's
admission state, and whether the Collection left its change-list chain;
no cursor is kept. The Label Feed's walk keeps its cursor (`pull_walk`)
of the pages walked, so a page chain longer than one pull's limits is
walked across pulls; the cursor of one domain holds at most 1024 pages
and 64 MiB of Envelope octets, and a `next` past either ends the walk as
an absent `next` does.

A pull that stops before its run is closed — a crash, or a partition
taken over mid-pull — leaves the run behind, and the next pull of that
domain drops it with its objects and starts fresh, returning what a
request that never settled had reserved to the budget row that request
was issued against. Nothing is admitted twice across the interruption:
an admitted list Item, an accepted Catalog and a seen Label ID stay as
they were.

`serve` schedules pulls durably in the store. `pull_schedule` holds at
most one due-time row per domain (`due_at` in Unix seconds, `reason`
`ping`, `baseline`, `resume` or `retry`, the count of consecutive pulls
that reached `WIST2-E01` or an internal failure, and `pinged_at`, the
receipt instant of the earliest Ping the
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
clears its retry count, so a fresh Ping cancels a pending backoff and
starts a new attempt at the first delay (WIST-2 §7, `WIST2-E01`).

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
second process on one store takes another name. The name is a single
path component of ASCII letters, digits, `-`, `_` and `.`. A process
that starts under the name it ran under before re-takes, in one
transaction, every partition lease and the sealer lease recorded under
that name, incrementing each token — which fences out anything the
earlier incarnation left running — and returns those partitions' pulls
to the schedule as `retry` due at once. A process killed without
releasing its leases is therefore succeeded at once by its restart
rather than after its own leases lapse. `clave seal` takes the sealer
lease under an owner unique to its process and its start.

A pull runs fenced by its partition and token. Every write transaction
it begins, including its completion, first checks under the write lock
that the partition's token is unchanged; once another dispatcher has
taken the partition over, the transaction writes nothing and fails with
`Error::Fenced`, and the pull is abandoned without a completion, since
the takeover already returned the domain to the schedule. What it
admitted before that stays, and the new holder pulls the domain fresh,
admitting nothing a second time. A Payload is held under
`held/payloads/<hex>.json`, named by its Item's Payload commitment
name, by the transaction that admits its Item, after that check, so a
fenced-out pull holds none and a repeated admission writes the same
file; it is served under `payloads/` only from the seal of its Item.

A finished pull, in one write transaction, closes its run — which
rebuilds its report, reports the code the pull or its Label Feed walk
ended at, records the walk's suspension and, for a completed walk, the pull
instant — drops its task and schedules the next pull,
combined with any Ping row that arrived meanwhile. A takeover between the
pull's last admission and that transaction writes none of it, so the
domain's next pull, held by the new dispatcher, schedules from its own
completion:

- after a completed walk, `baseline` due `baseline_poll_seconds` after
  the pull started, unless the walk stopped at a `next` failing the
  target rule or at a sealed Page it could not use;
- after a walk suspended at the pull's work limits, `resume` due at
  once, or at the next UTC day while the domain's daily ingest budget is
  spent, whatever the walk stopped at, and due at once again when a
  credit returns budget to that Registrable Domain's row for the day;
- after a pull that ended at `WIST2-E01` — a pull stopped at its
  Declaration outside first contact, or a `catalog.json` that cannot be
  fetched — or that ran to its end with its Label Feed walk stopped at a
  `next` failing the target rule or at a sealed Page it could not use, or
  at an internal failure, `retry` due
  `RETRY_BASE_SECONDS` (60) quadrupled for every earlier consecutive such
  pull after the instant the pull ended, so WIST-2 §7's retries fall at
  1, 4, 16 and 64 minutes; these delays are absolute, so a
  `baseline_poll_seconds` shorter than one of them does not shorten it.
  Once the fourth retry ends the same way the domain returns to the
  baseline schedule with the count reset, and a pull whose walk completed
  usably resets it too;
- after a pull that ended at `WIST2-E04`, `WIST2-E05` or `WIST1-E02`,
  `baseline` as after a completed walk: WIST-2 §7 backs off `WIST2-E01`
  alone.

A domain that is still no known publisher after its pull gets no next
pull. One pull runs per domain at a time. Every top-level write
transaction begins immediately, taking the write lock before its reads.

Sealing is exclusive to the holder of the Log's sealer lease
(`sealer_lease`: owner, `lease_until`, token). `serve`'s sealing
scheduler renews or takes the lease every `SEALER_LEASE_SECONDS` / 3
(10) seconds, holding it for `SEALER_LEASE_SECONDS` (30), and seals a
grid instant only while it holds the lease. While a seal runs, a
separate thread on its own connection renews the lease at the same
cadence and token, so a seal longer than the lease keeps it. A seal
runs fenced by the lease's token: its transaction begins by checking
the token under the write lock, and every file-writing stage after the
commit (withdrawal removal, distribution, Witness submission) checks it
again, so a sealer whose lease was taken over
commits no Epoch, or publishes no further file after its commit.
`clave seal` takes the lease when it is unowned or lapsed, seals under
it with the same renewal and releases it; while another process holds
a live lease it fails, naming the holder and the lease's end. On Ctrl-C
or SIGTERM `serve` stops accepting requests, finishes those in flight,
stops its dispatcher, sealing passes and Snapshot producer and only then releases its
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
Declaration, `catalog.json`, change list, tree file, Payload, Label Feed and
Page, Label, Log Anchor, Epoch, governance, Mirror and Snapshot inputs. Fetches retain the role-specific WIST-2 rejection wrappers;
history readers stop on failure. Queue drains parse every selected Entry before
deleting any, preserving malformed bytes and other queued work on rejection.

Parsed-Value APIs require callers to validate raw JSON before constructing the
Value; discarded duplicate members cannot be recovered. These checks do not
establish complete object eligibility or revalidate all existing state at open.
`json_inputs` and `history` tests cover signed last-value duplicates, field and
signature precedence, retry/restart, retained queues and history authority.

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

A store that keys its Blocks by a per-Block hash and holds no leaf data
fails to open with that reason rather than being half-migrated, as does
one that names its table and columns after `block`. Start a new data
directory.

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
strictly increasing whole-second timestamps on the cadence grid and each
Entry's JCS leaf data, and recomputes the root the Checkpoint states from
the retained leaves and the stored tree hashes. An Epoch core's sealing
replay rejects whole — Entries out of form or canonical order among its
conditions — or one over the smallest `epoch_cap_bytes` in force at its
`sealed_at` or at any accepted later `effective_at` (`WIST3-E03`) stays in
the Log and applies its key acts alone; `VerifiedEpoch::rejected` carries
its codes and the reader continues (WIST-3 §3.3).

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
head and off-chain competitors. Snapshot `declaration` and `recovery_window`
tuples are built from this state (WIST-3 §7).

History verification runs core's sealing replay over every Epoch beside the
Epoch checks, with the Label-sealed-once check before each Epoch, so the
latest Catalogs, records, removals, withdrawals and Payload duties of a
verified prefix are the replay's.

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set. Building also
resolves `wist-core` from `../core` — both must be sibling checkouts.

The ingestion fault cases — a worker lost with its pull leased, a
partition taken over while its pull runs, and a Ping, a seal or a
recovery settlement landing while a Collection is pulled — are
`crates/clave/tests/ingestion_faults.rs`, a test binary of its own:
Cargo runs test binaries one at a time, so their load never runs beside
the timing-sensitive dispatch tests in `tests/serve.rs`.

## Releases

A release is a Git tag `v<version>` equal to the crate version in
`crates/clave/Cargo.toml`. Pushing the tag runs
`.github/workflows/release.yml`: it builds `x86_64-unknown-linux-musl`
against the current `wistprotocol/core` default branch, checks that the
binary's `clave --version` reports the tag's version, and attaches
`clave-<tag>-x86_64-unknown-linux-musl.tar.gz` (the `clave` binary at the
archive root) and `SHA256SUMS` (`<sha256>  <asset>` lines) to a GitHub
release named after the tag, whose notes name the core commit built. A
tag with a `-` suffix publishes a pre-release.

To cut a release: set the version in `crates/clave/Cargo.toml`, run
`cargo build` so `Cargo.lock` records it, commit, tag `v<version>` and
push the commit and the tag.

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
what Clave implements, on top of the WIST-1 Declarations, Catalogs and Items
and the WIST-2 publication it pulls.
