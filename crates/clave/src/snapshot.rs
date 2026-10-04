use crate::db::{Db, EpochRow};
use crate::error::{Error, Result};
use crate::history::declarations::{Declarations, DeclarationsReplay};
use crate::WIST_VERSION;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::label::{self, LabelerRow, SealedLabelCount};
use wist_core::materialization::{self, ContentTuple, LinkRow};
use wist_core::objects::{
    AggregatorKeyEntry, DeclarationEntry, DisputeEntry, LabelEntry, ParameterEntry, Payload,
    PendingDeclarationEntry, RecoveryWindowEntry, RegistryUpdateEntry, SnapshotFile, SnapshotIndex,
    SnapshotIndexEntry, SnapshotManifest, SnapshotState, SnapshotStateFile, StateEntry,
    SuffixListEntry,
};
use wist_core::sealing::Records;
use wist_core::snapshot::{content_digest, shard_of, shard_path, state_digest, TIER_FILES};
use wist_core::withdrawal::WithdrawalReplay;

pub const SHARD_CACHE_DIRECTORY: &str = "snapshot-shards";
const FINGERPRINT: &str = "fingerprint.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedFile {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fingerprint {
    shard_count: u64,
    shard: u64,
    epoch_number: u64,
    record_digest: String,
    tier_digest: String,
    label_digest: String,
    files: Vec<CachedFile>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Incremental,
    Full,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn shard_count_of(count: u64) -> NonZeroU64 {
    NonZeroU64::new(count).unwrap_or(NonZeroU64::MIN)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Materialized {
    pub tuple: ContentTuple,
    pub collection: String,
    pub item: Value,
}

#[derive(Debug, Clone)]
pub struct TierRecord {
    pub tuple: ContentTuple,
    pub collection: String,
    pub lang: Option<String>,
    pub payload: Payload,
}

/// WIST-3 §7, Materialization rule.
pub fn materialize(
    entries: &[StateEntry],
    self_declared: impl Fn(&str) -> bool,
) -> Result<Vec<Materialized>> {
    let records = Records::from_state(entries)?;
    let withdrawals = WithdrawalReplay::from_state(entries)?;
    let tuples = materialization::materialized(records.records(), self_declared, |item_id| {
        withdrawals.is_withdrawn(item_id)
    })?;
    tuples
        .into_iter()
        .map(|tuple| {
            let record = records
                .record(&tuple.publisher, &tuple.url)
                .ok_or_else(|| Error::Snapshot(format!("{} has no record", tuple.url)))?;
            Ok(Materialized {
                collection: record.collection.clone(),
                item: record.item.clone(),
                tuple,
            })
        })
        .collect()
}

/// WIST-3 §7: no content whose commitment the build did not verify.
pub fn tier_record(record: &Materialized, octets: &[u8]) -> Result<TierRecord> {
    let unverified = |why: &str| {
        Error::Snapshot(format!(
            "the Payload of live record {} {why}",
            record.tuple.item_id
        ))
    };
    let value: Value = crate::json::parse(octets).map_err(|_| unverified("does not parse"))?;
    let payload: Payload =
        serde_json::from_value(value.clone()).map_err(|_| unverified("is not a Payload"))?;
    let content_octets = wist_core::jcs::canonicalize(&value["content"])?.len() as u64;
    let commitment = wist_core::item::commitment(&payload.salt, &value["content"])?;
    if record.item["payload"]["bytes"].as_u64() != Some(content_octets)
        || record.item["payload"]["commitment"] != commitment.as_str()
    {
        return Err(unverified("does not reproduce its Item's commitment"));
    }
    Ok(TierRecord {
        tuple: record.tuple.clone(),
        collection: record.collection.clone(),
        lang: record.item["meta"]["lang"].as_str().map(str::to_owned),
        payload,
    })
}

/// WIST-3 §7, Materialization rule.
pub fn link_rows(records: &[&TierRecord]) -> Vec<LinkRow> {
    records
        .iter()
        .flat_map(|record| materialization::links(&record.tuple.url, &record.payload))
        .collect()
}

/// WIST-3 §7: a party missing a Payload that was never withdrawn reports
/// that rather than emit a Snapshot silently missing a record.
fn load_tier_records(
    data_dir: &Path,
    records: &[&Materialized],
    cost: &mut Cost,
) -> Result<Vec<TierRecord>> {
    let mut loaded = Vec::with_capacity(records.len());
    for record in records {
        let item_id = &record.tuple.item_id;
        let served = crate::db::served_payload_path(data_dir, item_id)?;
        let octets = match std::fs::read(&served) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::read(crate::db::held_payload_path(data_dir, item_id)?)
            }
            read => read,
        }
        .map_err(|error| {
            Error::Snapshot(format!(
                "the Payload of live record {item_id} cannot be read: {error}"
            ))
        })?;
        cost.payloads_read += 1;
        cost.payload_bytes_read += octets.len() as u64;
        loaded.push(tier_record(record, &octets)?);
    }
    Ok(loaded)
}

enum Column {
    Text(Vec<Vec<u8>>),
    OptionalText(Vec<Option<Vec<u8>>>),
    Int(Vec<i64>),
    OptionalInt(Vec<Option<i64>>),
}

fn write_parquet_table(path: &Path, schema: &str, columns: &[Column]) -> Result<Vec<u8>> {
    use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;
    let schema = std::sync::Arc::new(
        parse_message_type(schema).map_err(|e| Error::Snapshot(format!("parquet schema: {e}")))?,
    );
    let props = std::sync::Arc::new(WriterProperties::builder().build());
    let file = std::fs::File::create(path)?;
    let mut writer = SerializedFileWriter::new(file, schema, props)
        .map_err(|e| Error::Snapshot(format!("parquet writer: {e}")))?;
    let mut rg = writer
        .next_row_group()
        .map_err(|e| Error::Snapshot(format!("parquet row group: {e}")))?;
    for column in columns {
        let mut col = rg
            .next_column()
            .map_err(|e| Error::Snapshot(format!("parquet column: {e}")))?
            .ok_or_else(|| Error::Snapshot("parquet schema/column mismatch".into()))?;
        let written = match column {
            Column::Text(values) => {
                let values: Vec<ByteArray> = values
                    .iter()
                    .map(|v| ByteArray::from(v.as_slice()))
                    .collect();
                col.typed::<ByteArrayType>()
                    .write_batch(&values, None, None)
            }
            Column::OptionalText(values) => {
                let levels: Vec<i16> = values.iter().map(|v| i16::from(v.is_some())).collect();
                let present: Vec<ByteArray> = values
                    .iter()
                    .flatten()
                    .map(|v| ByteArray::from(v.as_slice()))
                    .collect();
                col.typed::<ByteArrayType>()
                    .write_batch(&present, Some(&levels), None)
            }
            Column::Int(values) => col.typed::<Int64Type>().write_batch(values, None, None),
            Column::OptionalInt(values) => {
                let levels: Vec<i16> = values.iter().map(|v| i16::from(v.is_some())).collect();
                let present: Vec<i64> = values.iter().flatten().copied().collect();
                col.typed::<Int64Type>()
                    .write_batch(&present, Some(&levels), None)
            }
        };
        written.map_err(|e| Error::Snapshot(format!("parquet write: {e}")))?;
        col.close()
            .map_err(|e| Error::Snapshot(format!("parquet close: {e}")))?;
    }
    rg.close()
        .map_err(|e| Error::Snapshot(format!("parquet close: {e}")))?;
    writer
        .close()
        .map_err(|e| Error::Snapshot(format!("parquet close: {e}")))?;
    Ok(std::fs::read(path)?)
}

fn text(values: impl Iterator<Item = String>) -> Column {
    Column::Text(values.map(String::into_bytes).collect())
}

fn optional_text(values: impl Iterator<Item = Option<String>>) -> Column {
    Column::OptionalText(values.map(|v| v.map(String::into_bytes)).collect())
}

struct LabelTables {
    labels: Vec<u8>,
    disputes: Vec<u8>,
    labelers: Vec<u8>,
}

fn build_label_tables(
    dir: &Path,
    labels: &[LabelEntry],
    disputes: &[DisputeEntry],
    labelers: &[LabelerRow],
) -> Result<LabelTables> {
    std::fs::create_dir_all(dir)?;
    let labels_bytes = write_parquet_table(
        &dir.join("labels.parquet"),
        "message labels { required binary labeler (UTF8); required binary subject (UTF8); required binary name (UTF8); optional int64 value; required binary asserted_at (UTF8); optional binary expires_at (UTF8); optional binary delta (UTF8); }",
        &[
            text(labels.iter().map(|l| l.labeler.clone())),
            text(labels.iter().map(|l| l.subject.clone())),
            text(labels.iter().map(|l| l.name.clone())),
            Column::OptionalInt(labels.iter().map(|l| l.value.map(|v| v as i64)).collect()),
            text(labels.iter().map(|l| l.asserted_at.clone())),
            optional_text(labels.iter().map(|l| l.expires_at.clone())),
            optional_text(labels.iter().map(|l| l.delta.clone())),
        ],
    )?;
    let disputes_bytes = write_parquet_table(
        &dir.join("disputes.parquet"),
        "message disputes { required binary label_id (UTF8); required binary disputant (UTF8); optional binary reason (UTF8); required binary asserted_at (UTF8); }",
        &[
            text(disputes.iter().map(|d| d.label_id.clone())),
            text(disputes.iter().map(|d| d.disputant.clone())),
            optional_text(disputes.iter().map(|d| d.reason.clone())),
            text(disputes.iter().map(|d| d.asserted_at.clone())),
        ],
    )?;
    let labelers_bytes = write_parquet_table(
        &dir.join("labelers.parquet"),
        "message labelers { required binary labeler (UTF8); required int64 label_count; required int64 retraction_count; required int64 distinct_subjects; required int64 first_seen_height; }",
        &[
            text(labelers.iter().map(|r| r.labeler.clone())),
            Column::Int(labelers.iter().map(|r| r.label_count as i64).collect()),
            Column::Int(labelers.iter().map(|r| r.retraction_count as i64).collect()),
            Column::Int(labelers.iter().map(|r| r.distinct_subjects as i64).collect()),
            Column::Int(labelers.iter().map(|r| r.first_seen_height as i64).collect()),
        ],
    )?;
    Ok(LabelTables {
        labels: labels_bytes,
        disputes: disputes_bytes,
        labelers: labelers_bytes,
    })
}

/// WIST-2 §3.3, WIST-3 §7: the Labels and disputes current at
/// `head_sealed_at`, and labeler statistics over every sealed Label.
fn label_state(
    db: &Db,
    head_sealed_at: &str,
) -> Result<(Vec<LabelEntry>, Vec<DisputeEntry>, Vec<LabelerRow>)> {
    let sealed = db.sealed_labels()?;
    let mut by_triple: BTreeMap<(String, String, String), Vec<&label::SealedLabel>> =
        BTreeMap::new();
    for entry in &sealed {
        by_triple
            .entry((
                entry.label.labeler.clone(),
                entry.label.subject.clone(),
                entry.label.name.clone(),
            ))
            .or_default()
            .push(entry);
    }
    let labels: Vec<LabelEntry> = by_triple
        .values()
        .filter_map(|group| label::current_label(group.iter().copied()))
        .filter_map(|current| label::label_tuple(current, head_sealed_at))
        .collect();
    let disputes_sealed = db.sealed_disputes()?;
    let mut by_pair: BTreeMap<(String, String), Vec<&label::SealedDispute>> = BTreeMap::new();
    for entry in &disputes_sealed {
        by_pair
            .entry((entry.dispute.label.clone(), entry.dispute.disputant.clone()))
            .or_default()
            .push(entry);
    }
    let disputes: Vec<DisputeEntry> = by_pair
        .values()
        .filter_map(|group| label::current_dispute(group.iter().copied()))
        .map(label::dispute_tuple)
        .collect();
    let labelers = label::labeler_rows(sealed.iter().map(|entry| SealedLabelCount {
        height: entry.height,
        labeler: &entry.label.labeler,
        subject: &entry.label.subject,
        retracted: entry.label.retracted == Some(true),
    }));
    Ok((labels, disputes, labelers))
}

/// WIST-3 §7, Tier layout.
fn build_tier1(dir: &Path, records: &[&TierRecord]) -> Result<(Vec<u8>, Vec<u8>)> {
    std::fs::create_dir_all(dir)?;
    let extracts_bytes = write_parquet_table(
        &dir.join("extracts.parquet"),
        "message extracts { required binary url (UTF8); required binary publisher (UTF8); required binary item_id (UTF8); required binary extract (UTF8); required binary collection (UTF8); }",
        &[
            text(records.iter().map(|r| r.tuple.url.clone())),
            text(records.iter().map(|r| r.tuple.publisher.clone())),
            text(records.iter().map(|r| r.tuple.item_id.clone())),
            text(records.iter().map(|r| r.payload.content.extract.clone())),
            text(records.iter().map(|r| r.collection.clone())),
        ],
    )?;
    let links = link_rows(records);
    let links_bytes = write_parquet_table(
        &dir.join("links.parquet"),
        "message links { required binary source_url (UTF8); required binary target_url (UTF8); required int64 position; }",
        &[
            text(links.iter().map(|row| row.source_url.clone())),
            text(links.iter().map(|row| row.target_url.clone())),
            Column::Int(links.iter().map(|row| row.position as i64).collect()),
        ],
    )?;
    Ok((extracts_bytes, links_bytes))
}

/// WIST-3 §7, Tier layout.
fn build_tier0(dir: &Path, records: &[&TierRecord]) -> Result<Vec<u8>> {
    std::fs::create_dir_all(dir)?;
    let sqlite_path = dir.join("index.sqlite");
    if sqlite_path.exists() {
        std::fs::remove_file(&sqlite_path)?;
    }
    let conn = Connection::open(&sqlite_path)?;
    conn.execute_batch(
        "CREATE TABLE records(url TEXT, publisher TEXT, item_id TEXT, observed_at TEXT, attested_at TEXT, title TEXT, abstract TEXT, lang TEXT, collection TEXT);
         CREATE VIRTUAL TABLE records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
    )?;
    for r in records {
        let summary = &r.payload.content.summary;
        conn.execute(
            "INSERT INTO records(url, publisher, item_id, observed_at, attested_at, title, abstract, lang, collection) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                r.tuple.url,
                r.tuple.publisher,
                r.tuple.item_id,
                r.tuple.observed_at,
                r.tuple.attested_at,
                summary.title,
                summary.r#abstract,
                r.lang,
                r.collection,
            ],
        )?;
    }
    conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    drop(conn);
    Ok(std::fs::read(&sqlite_path)?)
}

pub fn write_tier_files(
    base: &Path,
    records: &[&TierRecord],
    labels: &[LabelEntry],
    disputes: &[DisputeEntry],
    labelers: &[LabelerRow],
) -> Result<Vec<Vec<u8>>> {
    let sqlite_bytes = build_tier0(&base.join("tier0"), records)?;
    let (extracts_bytes, links_bytes) = build_tier1(&base.join("tier1"), records)?;
    let tables = build_label_tables(&base.join("tier1"), labels, disputes, labelers)?;
    Ok(vec![
        sqlite_bytes,
        extracts_bytes,
        links_bytes,
        tables.labels,
        tables.disputes,
        tables.labelers,
    ])
}

/// WIST-3 §7, Sharding.
pub fn file_layout(count: u64) -> Vec<(String, u8, Option<u64>)> {
    let sharded = count > 1;
    (0..count.max(1))
        .flat_map(|shard| {
            TIER_FILES.iter().map(move |(path, tier)| {
                if sharded {
                    (shard_path(shard, path), *tier, Some(shard))
                } else {
                    ((*path).to_owned(), *tier, None)
                }
            })
        })
        .collect()
}

struct ReadState {
    head: EpochRow,
    signer: (String, SigningKey),
    log_entries: Vec<StateEntry>,
    records: Vec<Materialized>,
    parameters: Vec<(String, i64, String)>,
    suffix_list: Option<(String, u64)>,
    registry_updates: Vec<RegistryUpdateEntry>,
    labels: Vec<LabelEntry>,
    disputes: Vec<DisputeEntry>,
    labelers: Vec<LabelerRow>,
    key_entries: Vec<AggregatorKeyEntry>,
    shard_count: u64,
    declarations: Declarations,
}

fn read_state(db: &Db, data_dir: &Path, head: EpochRow) -> Result<ReadState> {
    let (labels, disputes, labelers) = label_state(db, &head.sealed_at)?;
    let mut key_entries = db.aggregator_key_entries()?;
    if key_entries.is_empty() {
        let anchor = crate::history::anchor(data_dir)?;
        key_entries.push(AggregatorKeyEntry {
            key_id: anchor.key_id,
            public_key: anchor.key.to_b64u(),
            added_height: 0,
            removed_height: None,
            adding_act: None,
            removing_act: None,
        });
    }
    let mut history = crate::history::History::open(db, data_dir, Some(head.clone()))?;
    let mut declarations = Declarations::default();
    while let Some(epoch) = history.next_epoch()? {
        declarations.apply(&epoch)?;
    }
    let registry_updates = history.replay().registry_updates().entries();
    let log_entries = db.log_state_entries()?;
    let domains = declarations.domains();
    let records = materialize(&log_entries, |host| domains.contains_key(host))?;
    Ok(ReadState {
        signer: crate::keys::head_signer(data_dir, db)?,
        log_entries,
        records,
        parameters: db.parameter_state(&head.sealed_at)?,
        suffix_list: db.suffix_list_at_epoch(head.epoch_number)?,
        registry_updates,
        labels,
        disputes,
        labelers,
        key_entries,
        shard_count: db.param("snapshot_shard_count").unwrap_or(1).max(1) as u64,
        declarations,
        head,
    })
}

fn build_state(read: &ReadState) -> Result<(SnapshotState, String)> {
    let domains = read.declarations.domains();
    let mut entries = Vec::with_capacity(2 + domains.len() + read.log_entries.len());
    // WIST-3 §7: one `aggregator_key` tuple per admitted key, removed keys
    // included, so a resuming Consumer judges a Checkpoint at or below the
    // Snapshot under the keys valid at its height (§3.4).
    entries.extend(
        read.key_entries
            .iter()
            .cloned()
            .map(StateEntry::AggregatorKey),
    );
    for (name, value, effective_at) in &read.parameters {
        entries.push(StateEntry::Parameter(ParameterEntry {
            name: name.clone(),
            effective_at: effective_at.clone(),
            value: *value,
        }));
    }
    if let Some((identifier, sealing_height)) = &read.suffix_list {
        entries.push(StateEntry::SuffixList(SuffixListEntry {
            identifier: identifier.clone(),
            sealing_height: *sealing_height,
        }));
    }
    entries.extend(
        read.registry_updates
            .iter()
            .cloned()
            .map(StateEntry::RegistryUpdate),
    );
    entries.extend(read.labels.iter().cloned().map(StateEntry::Label));
    entries.extend(read.disputes.iter().cloned().map(StateEntry::Dispute));
    for (domain, state) in domains {
        let current = state.current();
        entries.push(StateEntry::Declaration(DeclarationEntry {
            domain: domain.clone(),
            declaration: current.envelope().clone(),
            sealing_height: current.position().epoch_number,
            highest_accepted_seq: state.highest_accepted_seq(),
        }));
    }
    for (domain, state) in domains {
        let Some(pending) = state.pending() else {
            continue;
        };
        entries.push(StateEntry::PendingDeclaration(PendingDeclarationEntry {
            domain: domain.clone(),
            head: pending.head().envelope().clone(),
            sealing_height: pending.head().position().epoch_number,
            activation_height: pending.activation_height(),
        }));
    }
    for (domain, state) in domains {
        let Some(window) = state.window() else {
            continue;
        };
        let end = i64::try_from(window.end_s())
            .ok()
            .and_then(|end| crate::registry::instant(end).ok())
            .ok_or_else(|| Error::Snapshot("recovery window end is not a Log timestamp".into()))?;
        entries.push(StateEntry::RecoveryWindow(RecoveryWindowEntry {
            domain: domain.clone(),
            declaration_height: window.owner().position().epoch_number,
            window_end: end,
            head: window.head().envelope().clone(),
            head_height: window.head().position().epoch_number,
        }));
    }
    entries.extend(read.log_entries.iter().cloned());

    let entry_values = entries
        .iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<Vec<Value>>>()?;
    let digest = state_digest(&entry_values)?;

    Ok((
        SnapshotState {
            wist_version: WIST_VERSION.to_string(),
            tree_size: read.head.tree_size,
            entries,
        },
        digest,
    ))
}

pub const SUPERSEDED_DIRECTORY: &str = "snapshot-superseded";
pub const SUPERSEDED_GRACE_SECONDS: i64 = 24 * 60 * 60;

pub fn epoch_directory(epoch_number: u64) -> String {
    format!("{epoch_number:09}")
}

fn snapshot_date_of(head: &EpochRow) -> String {
    head.sealed_at
        .get(..10)
        .unwrap_or(&head.sealed_at)
        .to_string()
}

fn served_directory(data_dir: &Path, snapshot_date: &str, epoch_number: u64) -> PathBuf {
    data_dir
        .join("snapshots")
        .join(snapshot_date)
        .join(epoch_directory(epoch_number))
}

fn superseded_marker(data_dir: &Path, snapshot_date: &str, epoch_number: u64) -> PathBuf {
    data_dir
        .join(SUPERSEDED_DIRECTORY)
        .join(snapshot_date)
        .join(epoch_directory(epoch_number))
}

fn served_manifest(directory: &Path) -> Option<SnapshotManifest> {
    let bytes = std::fs::read(directory.join("manifest.json")).ok()?;
    let document: Value = crate::json::parse(&bytes).ok()?;
    let manifest: SnapshotManifest =
        serde_json::from_value(document.get("manifest")?.clone()).ok()?;
    let epoch = directory.file_name().and_then(|name| name.to_str());
    let date = directory
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str());
    (date == Some(manifest.snapshot_date.as_str())
        && epoch == Some(epoch_directory(manifest.epoch_number).as_str()))
    .then_some(manifest)
}

fn superseded_expired(superseded_at: jiff::Timestamp, now: jiff::Timestamp) -> bool {
    now.as_second() - superseded_at.as_second() >= SUPERSEDED_GRACE_SECONDS
}

fn superseded_at(data_dir: &Path, manifest: &SnapshotManifest) -> Option<jiff::Timestamp> {
    let marker = superseded_marker(data_dir, &manifest.snapshot_date, manifest.epoch_number);
    std::fs::read_to_string(marker).ok()?.trim().parse().ok()
}

struct ServedPlan {
    entries: Vec<SnapshotIndexEntry>,
    removals: Vec<PathBuf>,
}

fn plan_served(data_dir: &Path, now: jiff::Timestamp) -> Result<ServedPlan> {
    let mut served: Vec<SnapshotManifest> = Vec::new();
    let mut removals = Vec::new();
    for directory in snapshot_date_children(data_dir)? {
        match directory
            .is_dir()
            .then(|| served_manifest(&directory))
            .flatten()
        {
            Some(manifest) => served.push(manifest),
            None => removals.push(directory),
        }
    }
    let mut newest: BTreeMap<String, u64> = BTreeMap::new();
    for manifest in &served {
        let epoch = newest.entry(manifest.snapshot_date.clone()).or_default();
        *epoch = (*epoch).max(manifest.epoch_number);
    }
    let mut kept = Vec::new();
    for manifest in served {
        let marker = superseded_marker(data_dir, &manifest.snapshot_date, manifest.epoch_number);
        if newest.get(&manifest.snapshot_date) == Some(&manifest.epoch_number) {
            remove_path(&marker)?;
            kept.push(manifest);
            continue;
        }
        match superseded_at(data_dir, &manifest) {
            Some(at) if superseded_expired(at, now) => {
                removals.push(served_directory(
                    data_dir,
                    &manifest.snapshot_date,
                    manifest.epoch_number,
                ));
                continue;
            }
            Some(_) => {}
            None => crate::publication::write_durable(&marker, now.to_string().as_bytes())?,
        }
        kept.push(manifest);
    }
    Ok(ServedPlan {
        entries: index_entries(kept),
        removals,
    })
}

/// WIST-3 §6.
pub fn index_entries(mut manifests: Vec<SnapshotManifest>) -> Vec<SnapshotIndexEntry> {
    manifests.sort_by(|a, b| {
        b.snapshot_date
            .cmp(&a.snapshot_date)
            .then(b.epoch_number.cmp(&a.epoch_number))
    });
    manifests
        .into_iter()
        .map(|manifest| SnapshotIndexEntry {
            manifest_url: format!(
                "/snapshots/{}/{}/manifest.json",
                manifest.snapshot_date,
                epoch_directory(manifest.epoch_number)
            ),
            snapshot_date: manifest.snapshot_date,
            tree_size: manifest.tree_size,
            content_digest: manifest.content_digest,
        })
        .collect()
}

fn remove_unlisted(data_dir: &Path, removals: &[PathBuf]) -> Result<()> {
    for path in removals {
        remove_path(path)?;
    }
    remove_empty_children(&data_dir.join("snapshots"))?;
    for (date, date_path) in children(&data_dir.join(SUPERSEDED_DIRECTORY))? {
        for (name, marker) in children(&date_path)? {
            if !data_dir.join("snapshots").join(&date).join(&name).is_dir() {
                remove_path(&marker)?;
            }
        }
    }
    remove_empty_children(&data_dir.join(SUPERSEDED_DIRECTORY))
}

fn children(path: &Path) -> Result<Vec<(String, PathBuf)>> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut listed = Vec::new();
    for entry in entries {
        let entry = entry?;
        listed.push((
            entry.file_name().to_string_lossy().into_owned(),
            entry.path(),
        ));
    }
    listed.sort();
    Ok(listed)
}

fn remove_empty_children(path: &Path) -> Result<()> {
    for (_, child) in children(path)? {
        if child.is_dir() && std::fs::read_dir(&child)?.next().is_none() {
            remove_tree(&child)?;
        }
    }
    Ok(())
}

fn index_path(data_dir: &Path) -> PathBuf {
    data_dir.join("snapshots/index.json")
}

fn listed_entries(data_dir: &Path) -> Option<Vec<SnapshotIndexEntry>> {
    let document = served_document(&index_path(data_dir)).ok()??;
    let index: SnapshotIndex = serde_json::from_value(document.get("index")?.clone()).ok()?;
    Some(index.snapshots)
}

fn same_entries(listed: &[SnapshotIndexEntry], served: &[SnapshotIndexEntry]) -> bool {
    let values = |entries: &[SnapshotIndexEntry]| -> Vec<Option<Value>> {
        entries
            .iter()
            .map(|entry| serde_json::to_value(entry).ok())
            .collect()
    };
    values(listed) == values(served)
}

fn regenerate_index(db: &Db, data_dir: &Path, always: bool) -> Result<()> {
    regenerate_index_at(db, data_dir, always, jiff::Timestamp::now())
}

fn regenerate_index_at(db: &Db, data_dir: &Path, always: bool, now: jiff::Timestamp) -> Result<()> {
    let ServedPlan {
        entries: snapshots,
        removals,
    } = plan_served(data_dir, now)?;
    let unchanged = !always
        && match listed_entries(data_dir) {
            Some(listed) => same_entries(&listed, &snapshots),
            None => snapshots.is_empty() && !index_path(data_dir).exists(),
        };
    if !unchanged {
        let updated_at = jiff::Timestamp::from_second(now.as_second())
            .map_err(|_| Error::Snapshot("current time out of range".into()))?
            .to_string();
        let index = SnapshotIndex {
            wist_version: WIST_VERSION.to_string(),
            updated_at,
            snapshots,
        };
        let (key_id, sk) = crate::keys::head_signer(data_dir, db)?;
        let envelope = sign_envelope(&serde_json::to_value(&index)?, "index", &key_id, &sk)?;
        crate::publication::write_durable(&index_path(data_dir), &serde_json::to_vec(&envelope)?)?;
    }
    // WIST-3 §6: an index entry is removed before its Snapshot's files.
    remove_unlisted(data_dir, &removals)
}

fn snapshot_date_children(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut listed = Vec::new();
    for (_, date) in children(&data_dir.join("snapshots"))? {
        if date.is_dir() {
            listed.extend(children(&date)?.into_iter().map(|(_, path)| path));
        }
    }
    Ok(listed)
}

fn snapshot_directories(data_dir: &Path) -> Vec<PathBuf> {
    snapshot_date_children(data_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path.is_dir())
        .collect()
}

fn served_document(path: &Path) -> Result<Option<Value>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(crate::json::parse(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn signed_off_the_head(document: &Value, valid: &[String]) -> bool {
    match document.pointer("/sig/key_id").and_then(Value::as_str) {
        Some(key_id) => !valid.iter().any(|valid| valid == key_id),
        None => true,
    }
}

fn signer_at_head<'a>(
    db: &Db,
    data_dir: &Path,
    held: &'a mut Option<(String, SigningKey)>,
) -> Result<&'a (String, SigningKey)> {
    if held.is_none() {
        *held = Some(crate::keys::head_signer(data_dir, db)?);
    }
    Ok(held.as_ref().expect("the head signer is loaded"))
}

fn resigned(document: &Value, inner_key: &str, key_id: &str, sk: &SigningKey) -> Result<Vec<u8>> {
    let inner = document
        .get(inner_key)
        .cloned()
        .ok_or_else(|| Error::Snapshot(format!("a served document carries no {inner_key:?}")))?;
    Ok(serde_json::to_vec(&sign_envelope(
        &inner, inner_key, key_id, sk,
    )?)?)
}

fn served_name(data_dir: &Path, path: &Path) -> String {
    path.strip_prefix(data_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// WIST-3 §3.4: an unsealed Aggregator-signed document verifies under the
/// keys valid at the Checkpoint a Consumer adopts, so a removed key's
/// signature is re-made under a key valid at the head. Every state file
/// comes first, then the manifest that carries its `sha256` and `bytes`,
/// then the index and the Mirror list; each document is judged alone, so
/// an interrupted pass is finished by the next one.
pub fn resign_unsealed(db: &Db, data_dir: &Path) -> Result<Vec<String>> {
    let head = crate::keys::head_height(db)?;
    let registry = db.aggregator_key_entries()?;
    if registry.is_empty() {
        return Ok(Vec::new());
    }
    let valid: Vec<String> = registry
        .iter()
        .filter(|entry| {
            entry.added_height <= head && entry.removed_height.is_none_or(|removed| removed > head)
        })
        .map(|entry| entry.key_id.clone())
        .collect();

    let mut signer: Option<(String, SigningKey)> = None;
    let mut rewritten = Vec::new();
    for directory in snapshot_directories(data_dir) {
        let state_path = directory.join("state.json");
        if let Some(state) = served_document(&state_path)? {
            if signed_off_the_head(&state, &valid) {
                let (key_id, sk) = signer_at_head(db, data_dir, &mut signer)?;
                let bytes = resigned(&state, "state", key_id, sk)?;
                crate::publication::write_durable(&state_path, &bytes)?;
                rewritten.push(served_name(data_dir, &state_path));
            }
        }
        let manifest_path = directory.join("manifest.json");
        let Some(mut manifest) = served_document(&manifest_path)? else {
            continue;
        };
        let described = std::fs::read(&state_path)
            .ok()
            .map(|bytes| (sha256_hex(&bytes), bytes.len() as u64));
        let restates = described.as_ref().is_some_and(|(sha256, bytes)| {
            manifest["manifest"]["state"]["sha256"] != *sha256.as_str()
                || manifest["manifest"]["state"]["bytes"] != *bytes
        });
        if !restates && !signed_off_the_head(&manifest, &valid) {
            continue;
        }
        if let Some((sha256, bytes)) = described {
            manifest["manifest"]["state"]["sha256"] = Value::from(sha256);
            manifest["manifest"]["state"]["bytes"] = Value::from(bytes);
        }
        let (key_id, sk) = signer_at_head(db, data_dir, &mut signer)?;
        let bytes = resigned(&manifest, "manifest", key_id, sk)?;
        crate::publication::write_durable(&manifest_path, &bytes)?;
        rewritten.push(served_name(data_dir, &manifest_path));
    }
    for (path, inner_key) in [
        (data_dir.join("snapshots/index.json"), "index"),
        (data_dir.join("log/mirrors.json"), "mirrors"),
    ] {
        let Some(document) = served_document(&path)? else {
            continue;
        };
        if !signed_off_the_head(&document, &valid) {
            continue;
        }
        let (key_id, sk) = signer_at_head(db, data_dir, &mut signer)?;
        let bytes = resigned(&document, inner_key, key_id, sk)?;
        crate::publication::write_durable(&path, &bytes)?;
        rewritten.push(served_name(data_dir, &path));
    }
    Ok(rewritten)
}

fn tier_digest(records: &[&Materialized]) -> Result<String> {
    let rows: Vec<Value> = records
        .iter()
        .map(|record| serde_json::json!([record.tuple, record.collection]))
        .collect();
    Ok(sha256_hex(&wist_core::jcs::canonicalize(&Value::Array(
        rows,
    ))?))
}

fn label_digest(
    labels: &[LabelEntry],
    disputes: &[DisputeEntry],
    labelers: &[LabelerRow],
) -> Result<String> {
    let labels = labels
        .iter()
        .cloned()
        .map(|entry| serde_json::to_value(StateEntry::Label(entry)))
        .collect::<serde_json::Result<Vec<Value>>>()?;
    let disputes = disputes
        .iter()
        .cloned()
        .map(|entry| serde_json::to_value(StateEntry::Dispute(entry)))
        .collect::<serde_json::Result<Vec<Value>>>()?;
    let labelers: Vec<Value> = labelers
        .iter()
        .map(|row| {
            serde_json::json!({
                "labeler": row.labeler,
                "label_count": row.label_count,
                "retraction_count": row.retraction_count,
                "distinct_subjects": row.distinct_subjects,
                "first_seen_height": row.first_seen_height,
            })
        })
        .collect();
    let canonical = wist_core::jcs::canonicalize(&serde_json::json!({
        "labels": labels,
        "disputes": disputes,
        "labelers": labelers,
    }))?;
    Ok(sha256_hex(&canonical))
}

fn shard_cache(data_dir: &Path) -> PathBuf {
    data_dir.join(SHARD_CACHE_DIRECTORY)
}

fn read_fingerprint(entry: &Path) -> Option<Fingerprint> {
    let bytes = std::fs::read(entry.join(FINGERPRINT)).ok()?;
    let fingerprint: Fingerprint = serde_json::from_slice(&bytes).ok()?;
    (fingerprint.shard_count > 0).then_some(fingerprint)
}

fn reusable(entry: &Path, wanted: &Fingerprint) -> Option<Vec<CachedFile>> {
    let cached = read_fingerprint(entry)?;
    let matches = cached.shard_count == wanted.shard_count
        && cached.shard == wanted.shard
        && cached.record_digest == wanted.record_digest
        && cached.tier_digest == wanted.tier_digest
        && cached.label_digest == wanted.label_digest
        && cached.files.len() == TIER_FILES.len()
        && cached
            .files
            .iter()
            .zip(TIER_FILES)
            .all(|(file, (path, _))| {
                file.path == path
                    && std::fs::metadata(entry.join(path))
                        .is_ok_and(|meta| meta.is_file() && meta.len() == file.bytes)
                    && file_sha256_hex(&entry.join(path)).is_ok_and(|hash| hash == file.sha256)
            });
    matches.then_some(cached.files)
}

fn file_sha256_hex(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
    Ok(hex_encode(&hasher.finalize()))
}

#[derive(Debug, Default)]
struct Cost {
    bytes_written: u64,
    bytes_reused: u64,
    cache_bytes_written: u64,
    payloads_read: u64,
    payload_bytes_read: u64,
}

enum Placed {
    Linked(u64),
    Copied(u64),
}

fn link_or_copy(source: &Path, target: &Path) -> Result<Placed> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::hard_link(source, target).is_err() {
        return Ok(Placed::Copied(std::fs::copy(source, target)?));
    }
    Ok(Placed::Linked(std::fs::metadata(target)?.len()))
}

fn shard_base(staged: &Path, shard_count: u64, shard: u64) -> PathBuf {
    if shard_count > 1 {
        staged.join(format!("shard-{shard}"))
    } else {
        staged.to_path_buf()
    }
}

fn build_staged(
    read: &ReadState,
    data_dir: &Path,
    staged: &Path,
    snapshot_date: &str,
    mode: Mode,
    observe: &mut dyn FnMut(Phase) -> Result<()>,
    cost: &mut Cost,
) -> Result<Vec<Fingerprint>> {
    let (key_id, sk) = (&read.signer.0, &read.signer.1);
    let shard_count = read.shard_count;
    let sharded = shard_count > 1;
    let count = shard_count_of(shard_count);
    let mut partitions: Vec<Vec<&Materialized>> = (0..shard_count).map(|_| Vec::new()).collect();
    let mut whole_projection = Vec::with_capacity(read.records.len());
    for record in &read.records {
        whole_projection.push(record.tuple.clone());
        partitions[shard_of(&record.tuple.publisher, count) as usize].push(record);
    }
    let content_digest_value = content_digest(&whole_projection)?;

    let mut files = Vec::new();
    let mut shard_digests = Vec::new();
    let mut rebuilt = Vec::new();
    for (i, shard_records) in partitions.into_iter().enumerate() {
        let shard = i as u64;
        let (prefix, shard_field) = if sharded {
            (format!("shard-{i}/"), Some(shard))
        } else {
            (String::new(), None)
        };
        let shard_base = shard_base(staged, shard_count, shard);
        let in_shard = |domain: &str| !sharded || shard_of(domain, count) == shard;
        let shard_labels: Vec<LabelEntry> = read
            .labels
            .iter()
            .filter(|l| in_shard(&l.labeler))
            .cloned()
            .collect();
        let shard_disputes: Vec<DisputeEntry> = read
            .disputes
            .iter()
            .filter(|d| in_shard(&d.disputant))
            .cloned()
            .collect();
        let shard_labelers: Vec<LabelerRow> = read
            .labelers
            .iter()
            .filter(|r| in_shard(&r.labeler))
            .cloned()
            .collect();
        let projection: Vec<ContentTuple> = shard_records.iter().map(|r| r.tuple.clone()).collect();
        let mut fingerprint = Fingerprint {
            shard_count,
            shard,
            epoch_number: read.head.epoch_number,
            record_digest: content_digest(&projection)?,
            tier_digest: tier_digest(&shard_records)?,
            label_digest: label_digest(&shard_labels, &shard_disputes, &shard_labelers)?,
            files: Vec::new(),
        };
        let entry = shard_cache(data_dir).join(shard.to_string());
        // A withdrawal purges cache entries under the swap lock, so the
        // fingerprint check and the links it authorizes stay under it too.
        let cached = match mode {
            Mode::Incremental => {
                let _swap = swap_lock(data_dir)?;
                let cached = reusable(&entry, &fingerprint);
                if cached.is_some() {
                    for (path, _) in TIER_FILES {
                        match link_or_copy(&entry.join(path), &shard_base.join(path))? {
                            Placed::Linked(bytes) => cost.bytes_reused += bytes,
                            Placed::Copied(bytes) => cost.bytes_written += bytes,
                        }
                    }
                }
                cached
            }
            Mode::Full => None,
        };
        if let Some(cached) = cached {
            fingerprint.files = cached;
        } else {
            let loaded = load_tier_records(data_dir, &shard_records, cost)?;
            let written = write_tier_files(
                &shard_base,
                &loaded.iter().collect::<Vec<_>>(),
                &shard_labels,
                &shard_disputes,
                &shard_labelers,
            )?;
            fingerprint.files = TIER_FILES
                .iter()
                .zip(&written)
                .map(|((path, _), bytes)| CachedFile {
                    path: (*path).to_string(),
                    sha256: sha256_hex(bytes),
                    bytes: bytes.len() as u64,
                })
                .collect();
            cost.bytes_written += fingerprint.files.iter().map(|f| f.bytes).sum::<u64>();
            rebuilt.push(fingerprint.clone());
        }
        for (file, (_, tier)) in fingerprint.files.iter().zip(TIER_FILES) {
            files.push(SnapshotFile {
                path: format!("{prefix}{}", file.path),
                sha256: file.sha256.clone(),
                bytes: file.bytes,
                tier,
                shard: shard_field,
            });
        }
        if sharded {
            shard_digests.push(fingerprint.record_digest);
        }
        observe(Phase::ShardWritten(shard))?;
    }

    let (state, state_digest_value) = build_state(read)?;
    let state_value = serde_json::to_value(&state)?;
    let state_envelope = sign_envelope(&state_value, "state", key_id, sk)?;
    let state_bytes = serde_json::to_vec(&state_envelope)?;
    std::fs::write(staged.join("state.json"), &state_bytes)?;
    cost.bytes_written += state_bytes.len() as u64;

    let manifest = SnapshotManifest {
        wist_version: WIST_VERSION.to_string(),
        snapshot_date: snapshot_date.to_string(),
        epoch_number: read.head.epoch_number,
        tree_size: read.head.tree_size,
        root_hash: read.head.root.clone(),
        content_digest: content_digest_value,
        state: SnapshotStateFile {
            path: "state.json".to_string(),
            sha256: sha256_hex(&state_bytes),
            bytes: state_bytes.len() as u64,
            state_digest: state_digest_value,
        },
        shards: sharded.then_some(wist_core::objects::SnapshotShards {
            count: shard_count,
            digests: shard_digests,
        }),
        files,
    };
    let manifest_value = serde_json::to_value(&manifest)?;
    let manifest_envelope = sign_envelope(&manifest_value, "manifest", key_id, sk)?;
    let manifest_bytes = serde_json::to_vec(&manifest_envelope)?;
    std::fs::write(staged.join("manifest.json"), &manifest_bytes)?;
    cost.bytes_written += manifest_bytes.len() as u64;
    sync_tree(staged)?;
    Ok(rebuilt)
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_tree(path: &Path) -> Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            std::fs::File::open(entry.path())?.sync_all()?;
        }
    }
    sync_directory(path)
}

fn remove_tree(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

fn remove_path(path: &Path) -> Result<()> {
    if path.is_dir() {
        return remove_tree(path);
    }
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

fn cache_entries(data_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let entries = match std::fs::read_dir(shard_cache(data_dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut listed = Vec::new();
    for entry in entries {
        let entry = entry?;
        listed.push((
            entry.file_name().to_string_lossy().into_owned(),
            entry.path(),
        ));
    }
    Ok(listed)
}

fn update_cache(
    data_dir: &Path,
    staged: &Path,
    shard_count: u64,
    rebuilt: &[Fingerprint],
) -> Result<u64> {
    let mut copied = 0;
    let cache = shard_cache(data_dir);
    std::fs::create_dir_all(&cache)?;
    for fingerprint in rebuilt {
        let entry = cache.join(fingerprint.shard.to_string());
        let fresh = cache.join(format!("{}.new", fingerprint.shard));
        remove_path(&fresh)?;
        let source = shard_base(staged, shard_count, fingerprint.shard);
        for (path, _) in TIER_FILES {
            if let Placed::Copied(bytes) = link_or_copy(&source.join(path), &fresh.join(path))? {
                copied += bytes;
            }
            std::fs::File::open(fresh.join(path))?.sync_all()?;
        }
        sync_directory(&fresh.join("tier0"))?;
        sync_directory(&fresh.join("tier1"))?;
        sync_directory(&fresh)?;
        // The fingerprint is written last: an entry without one is never reused.
        crate::publication::write_durable(
            &fresh.join(FINGERPRINT),
            &serde_json::to_vec(fingerprint)?,
        )?;
        remove_path(&entry)?;
        std::fs::rename(&fresh, &entry)?;
    }
    for (name, path) in cache_entries(data_dir)? {
        if name.parse::<u64>().is_ok_and(|shard| shard >= shard_count) {
            remove_path(&path)?;
        }
    }
    sync_directory(&cache)?;
    Ok(copied)
}

fn clear_directory(path: &Path) -> Result<()> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_tree(&entry.path())?;
        } else {
            match std::fs::remove_file(entry.path()) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.into())
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub const STAGING_DIRECTORY: &str = "snapshot-build";
const PRODUCER_LOCK: &str = "snapshot-build.lock";
const SWAP_LOCK: &str = "snapshot-swap.lock";

fn staging(data_dir: &Path) -> PathBuf {
    data_dir.join(STAGING_DIRECTORY)
}

fn lock(path: &Path, wait: bool) -> Result<Option<std::fs::File>> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    let operation = if wait {
        rustix::fs::FlockOperation::LockExclusive
    } else {
        rustix::fs::FlockOperation::NonBlockingLockExclusive
    };
    match rustix::fs::flock(&file, operation) {
        Ok(()) => Ok(Some(file)),
        Err(errno) if !wait && errno == rustix::io::Errno::WOULDBLOCK => Ok(None),
        Err(errno) => Err(std::io::Error::from(errno).into()),
    }
}

fn swap_lock(data_dir: &Path) -> Result<std::fs::File> {
    lock(&data_dir.join(SWAP_LOCK), true)?
        .ok_or_else(|| Error::Snapshot("the Snapshot swap lock was not taken".into()))
}

fn reconcile_locked(db: &Db, data_dir: &Path, clear_staging: bool) -> Result<()> {
    if clear_staging {
        clear_directory(&staging(data_dir))?;
        for (name, path) in cache_entries(data_dir)? {
            if name.ends_with(".new") {
                remove_path(&path)?;
            }
        }
    }
    let _swap = swap_lock(data_dir)?;
    regenerate_index(db, data_dir, false)
}

/// Staging is left alone while a producer holds its lock: the producer
/// owns it and finishes or abandons its build itself.
pub fn reconcile(db: &Db, data_dir: &Path) -> Result<()> {
    let producer = lock(&data_dir.join(PRODUCER_LOCK), false)?;
    reconcile_locked(db, data_dir, producer.is_some())
}

pub(crate) fn apply_pending_removals(db: &Db, data_dir: &Path) -> Result<bool> {
    let pending = db.pending_removals()?;
    if pending.is_empty() {
        return Ok(false);
    }
    db.check_fence()?;
    for (item_id, _) in &pending {
        let hex = item_id.strip_prefix("sha256:").unwrap_or(item_id);
        remove_path(&data_dir.join("payloads").join(format!("{hex}.json")))?;
        remove_path(&data_dir.join("held/payloads").join(format!("{hex}.json")))?;
    }
    let publishers: Vec<&str> = pending.iter().map(|(_, domain)| domain.as_str()).collect();
    withdraw_served(db, data_dir, &publishers)?;
    let item_ids: Vec<String> = pending.into_iter().map(|(item_id, _)| item_id).collect();
    db.clear_pending_removals(&item_ids)?;
    if !db.truncate_wal()? {
        tracing::warn!("a reader kept the write-ahead log from being truncated after a withdrawal");
    }
    Ok(true)
}

/// WIST-3 §6.2, §7: every served Snapshot and every staged build may carry
/// the withdrawn content, so all are removed and the index lists none. A
/// build under a live producer is left to it: below the withdrawal's height
/// it is abandoned under the swap lock, at or above it the content is gone.
fn withdraw_served(db: &Db, data_dir: &Path, publishers: &[&str]) -> Result<()> {
    if let Some(_producer) = lock(&data_dir.join(PRODUCER_LOCK), false)? {
        clear_directory(&staging(data_dir))?;
    }
    let _swap = swap_lock(data_dir)?;
    clear_directory(&data_dir.join("snapshots"))?;
    clear_directory(&data_dir.join(SUPERSEDED_DIRECTORY))?;
    for (_, path) in cache_entries(data_dir)? {
        let affected = read_fingerprint(&path).is_none_or(|fingerprint| {
            publishers.iter().any(|publisher| {
                shard_of(publisher, shard_count_of(fingerprint.shard_count)) == fingerprint.shard
            })
        });
        if affected {
            remove_path(&path)?;
        }
    }
    regenerate_index(db, data_dir, true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Built {
        epoch_number: u64,
        tree_size: u64,
        snapshot_date: String,
        shards_rebuilt: u64,
        shard_count: u64,
        bytes_written: u64,
        bytes_reused: u64,
        cache_bytes_written: u64,
        payloads_read: u64,
        payload_bytes_read: u64,
    },
    Current {
        epoch_number: u64,
    },
    Superseded {
        built: u64,
        withdrawal_height: u64,
    },
    Unsealed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Reading,
    Read,
    ShardWritten(u64),
    FilesWritten,
    Swapped,
    Indexed,
}

pub fn produce(db_path: &Path, data_dir: &Path) -> Result<Outcome> {
    produce_with(db_path, data_dir, Mode::Incremental, &mut |_| Ok(()))
}

fn superseding(db: &Db, built: u64) -> Result<Option<u64>> {
    Ok(db
        .withdrawal_state()?
        .into_iter()
        .map(|(_, _, sealing_height)| sealing_height)
        .filter(|sealing_height| *sealing_height > built)
        .max())
}

pub fn produce_with(
    db_path: &Path,
    data_dir: &Path,
    mode: Mode,
    observe: &mut dyn FnMut(Phase) -> Result<()>,
) -> Result<Outcome> {
    let producer_lock = data_dir.join(PRODUCER_LOCK);
    let Some(_producer) = lock(&producer_lock, false)? else {
        return Err(Error::Snapshot(format!(
            "another Snapshot producer holds {}; wait for it to finish",
            producer_lock.display()
        )));
    };
    let db = Db::connect(db_path)?;
    reconcile_locked(&db, data_dir, true)?;

    let Some(head) = db.last_epoch()? else {
        return Ok(Outcome::Unsealed);
    };
    let served = served_directory(data_dir, &snapshot_date_of(&head), head.epoch_number);
    if served_manifest(&served).is_some() {
        return Ok(Outcome::Current {
            epoch_number: head.epoch_number,
        });
    }

    let read = db.consistent_read(|db| {
        let head = db
            .last_epoch()?
            .ok_or_else(|| Error::Snapshot("the sealed head is absent".into()))?;
        observe(Phase::Reading)?;
        read_state(db, data_dir, head)
    })?;
    observe(Phase::Read)?;

    let built = read.head.epoch_number;
    let snapshot_date = snapshot_date_of(&read.head);
    let staged = staging(data_dir).join(built.to_string());
    remove_tree(&staged)?;
    std::fs::create_dir_all(&staged)?;
    let mut cost = Cost::default();
    let rebuilt = match build_staged(
        &read,
        data_dir,
        &staged,
        &snapshot_date,
        mode,
        observe,
        &mut cost,
    ) {
        Ok(rebuilt) => rebuilt,
        Err(error) => {
            if let Some(withdrawal_height) = superseding(&db, built)? {
                remove_tree(&staged)?;
                return Ok(Outcome::Superseded {
                    built,
                    withdrawal_height,
                });
            }
            return Err(error);
        }
    };
    sync_directory(&staging(data_dir))?;
    observe(Phase::FilesWritten)?;

    let _swap = swap_lock(data_dir)?;
    if let Some(withdrawal_height) = superseding(&db, built)? {
        remove_tree(&staged)?;
        return Ok(Outcome::Superseded {
            built,
            withdrawal_height,
        });
    }
    if !staged.is_dir() {
        let withdrawal_height = db
            .withdrawal_state()?
            .into_iter()
            .map(|(_, _, sealing_height)| sealing_height)
            .max()
            .unwrap_or(built);
        return Ok(Outcome::Superseded {
            built,
            withdrawal_height,
        });
    }
    let target = served_directory(data_dir, &snapshot_date, built);
    if target.exists() {
        remove_tree(&staged)?;
        return Ok(Outcome::Current {
            epoch_number: built,
        });
    }
    // Under the swap lock and after the superseding check: a withdrawal seal
    // either abandons this build or runs after it and removes its shard.
    cost.cache_bytes_written = update_cache(data_dir, &staged, read.shard_count, &rebuilt)?;
    let served_root = data_dir.join("snapshots");
    let date_root = served_root.join(&snapshot_date);
    std::fs::create_dir_all(&date_root)?;
    std::fs::rename(&staged, &target)?;
    sync_directory(&date_root)?;
    sync_directory(&served_root)?;
    sync_directory(&staging(data_dir))?;
    observe(Phase::Swapped)?;

    regenerate_index(&db, data_dir, true)?;
    observe(Phase::Indexed)?;
    Ok(Outcome::Built {
        epoch_number: built,
        tree_size: read.head.tree_size,
        snapshot_date,
        shards_rebuilt: rebuilt.len() as u64,
        shard_count: read.shard_count,
        bytes_written: cost.bytes_written,
        bytes_reused: cost.bytes_reused,
        cache_bytes_written: cost.cache_bytes_written,
        payloads_read: cost.payloads_read,
        payload_bytes_read: cost.payload_bytes_read,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;

    fn ts(unix: i64) -> String {
        jiff::Timestamp::from_second(unix).unwrap().to_string()
    }

    #[test]
    fn a_superseded_snapshot_expires_when_the_grace_period_has_fully_elapsed() {
        let at = jiff::Timestamp::from_second(T0).unwrap();
        let after = |seconds: i64| jiff::Timestamp::from_second(T0 + seconds).unwrap();
        assert!(!superseded_expired(at, at));
        assert!(!superseded_expired(at, after(SUPERSEDED_GRACE_SECONDS - 1)));
        assert!(superseded_expired(at, after(SUPERSEDED_GRACE_SECONDS)));
    }

    #[test]
    fn an_epoch_directory_is_the_epoch_zero_padded_to_nine_digits() {
        assert_eq!(epoch_directory(0), "000000000");
        assert_eq!(epoch_directory(24), "000000024");
        assert_eq!(epoch_directory(1_234_567_890), "1234567890");
    }

    #[test]
    fn one_url_one_publisher_prefers_self_then_nearest_ancestor_then_octet_order() {
        let rows: [(&str, &str, bool); 11] = [
            ("https://a.example.com/x", "example.com", false),
            ("https://a.example.com/x", "a.example.com", true),
            ("https://d.example.com/x", "example.com", true),
            ("https://a.b.example.com/x", "example.com", false),
            ("https://a.b.example.com/x", "b.example.com", false),
            ("https://c.example.com/x", "zeta.example", false),
            ("https://c.example.com/x", "example.com", false),
            ("https://e.example.com/x", "zeta.example", false),
            ("https://e.example.com/x", "alpha.example", false),
            ("https://a.notexample.com/x", "example.com", false),
            ("https://a.notexample.com/x", "beta.example", false),
        ];
        let declared: Vec<String> = rows
            .iter()
            .filter(|(_, _, declares)| *declares)
            .map(|(url, _, _)| crate::declaration::url_host(url).to_owned())
            .collect();
        let entries: Vec<StateEntry> = rows
            .iter()
            .map(|(url, publisher, _)| {
                StateEntry::Record(wist_core::objects::RecordEntry {
                    publisher: (*publisher).to_owned(),
                    url: (*url).to_owned(),
                    item: serde_json::json!({
                        "publisher": publisher, "url": url, "observed_at": ts(T0),
                        "payload": {"commitment": format!("hmac-sha256:{}", "0".repeat(64)), "alg": "HMAC-SHA256", "bytes": 1},
                        "meta": {"lang": "en"}
                    }),
                    collection: "default".into(),
                    catalog_id: format!("sha256:{}", "1".repeat(64)),
                    generated_at: ts(T0),
                })
            })
            .collect();
        let kept = materialize(&entries, |host| declared.iter().any(|d| d == host)).unwrap();
        let mut pairs: Vec<(&str, &str)> = kept
            .iter()
            .map(|r| (r.tuple.url.as_str(), r.tuple.publisher.as_str()))
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            [
                ("https://a.b.example.com/x", "b.example.com"),
                ("https://a.example.com/x", "a.example.com"),
                ("https://a.notexample.com/x", "beta.example"),
                ("https://c.example.com/x", "example.com"),
                ("https://e.example.com/x", "alpha.example"),
            ]
        );
    }
}
