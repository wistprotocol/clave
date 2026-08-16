use crate::db::{Db, RecordRow};
use crate::error::{Error, Result};
use crate::keys;
use crate::WIST_VERSION;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{
    AggregatorKeyEntry, DeclarationEntry, ParameterEntry, RecordEntry, RecoveryWindowEntry,
    SnapshotFile, SnapshotIndex, SnapshotIndexEntry, SnapshotManifest, SnapshotState,
    SnapshotStateFile, StateEntry,
};
use wist_core::snapshot::{content_digest, state_digest};

const AGGREGATOR_KEY_ID: &str = "log1";

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

/// WIST-3 §7: shard assignment is the first 8 octets of SHA-256 of the
/// UTF-8 Publisher domain, read big-endian, mod count.
pub fn shard_index(domain: &str, count: u64) -> u64 {
    let digest = Sha256::digest(domain.as_bytes());
    let prefix: [u8; 8] = digest[..8].try_into().expect("SHA-256 has 32 octets");
    u64::from_be_bytes(prefix) % count
}

struct Tier1Row {
    url: String,
    publisher: String,
    delta_id: String,
    extract: String,
    links: Vec<String>,
}

fn load_tier1_rows(data_dir: &Path, records: &[RecordRow]) -> Vec<Tier1Row> {
    let mut rows = Vec::with_capacity(records.len());
    for r in records {
        let hex = r.delta_id.strip_prefix("sha256:").unwrap_or(&r.delta_id);
        let Ok(bytes) = std::fs::read(data_dir.join("payloads").join(format!("{hex}.json"))) else {
            continue;
        };
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let extract = payload["content"]["extract"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let links = payload["content"]["links"]["urls"]
            .as_array()
            .map(|urls| {
                urls.iter()
                    .filter_map(|u| u.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        rows.push(Tier1Row {
            url: r.url.clone(),
            publisher: r.publisher.clone(),
            delta_id: r.delta_id.clone(),
            extract,
            links,
        });
    }
    rows
}

fn write_parquet_strings(
    path: &Path,
    message_type: &str,
    columns: &[Vec<Vec<u8>>],
    int_column: Option<&[i64]>,
) -> Result<Vec<u8>> {
    use parquet::data_type::{ByteArray, ByteArrayType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;
    use std::sync::Arc;

    let schema = Arc::new(
        parse_message_type(message_type)
            .map_err(|e| Error::Snapshot(format!("parquet schema: {e}")))?,
    );
    let file = std::fs::File::create(path)?;
    let mut writer =
        SerializedFileWriter::new(file, schema, Arc::new(WriterProperties::builder().build()))
            .map_err(|e| Error::Snapshot(format!("parquet writer: {e}")))?;
    let mut rg = writer
        .next_row_group()
        .map_err(|e| Error::Snapshot(format!("parquet row group: {e}")))?;
    for column in columns {
        let mut col = rg
            .next_column()
            .map_err(|e| Error::Snapshot(format!("parquet column: {e}")))?
            .ok_or_else(|| Error::Snapshot("parquet schema/column mismatch".into()))?;
        let values: Vec<ByteArray> = column
            .iter()
            .map(|v| ByteArray::from(v.as_slice()))
            .collect();
        col.typed::<ByteArrayType>()
            .write_batch(&values, None, None)
            .map_err(|e| Error::Snapshot(format!("parquet write: {e}")))?;
        col.close()
            .map_err(|e| Error::Snapshot(format!("parquet close: {e}")))?;
    }
    if let Some(ints) = int_column {
        let mut col = rg
            .next_column()
            .map_err(|e| Error::Snapshot(format!("parquet column: {e}")))?
            .ok_or_else(|| Error::Snapshot("parquet schema/column mismatch".into()))?;
        col.typed::<Int64Type>()
            .write_batch(ints, None, None)
            .map_err(|e| Error::Snapshot(format!("parquet write: {e}")))?;
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

fn build_tier1(dir: &Path, rows: &[Tier1Row]) -> Result<(Vec<u8>, Vec<u8>)> {
    std::fs::create_dir_all(dir)?;
    let extracts_bytes = write_parquet_strings(
        &dir.join("extracts.parquet"),
        "message extracts { required binary url (UTF8); required binary publisher (UTF8); required binary delta_id (UTF8); required binary extract (UTF8); }",
        &[
            rows.iter().map(|r| r.url.clone().into_bytes()).collect(),
            rows.iter()
                .map(|r| r.publisher.clone().into_bytes())
                .collect(),
            rows.iter()
                .map(|r| r.delta_id.clone().into_bytes())
                .collect(),
            rows.iter()
                .map(|r| r.extract.clone().into_bytes())
                .collect(),
        ],
        None,
    )?;

    let mut sources = Vec::new();
    let mut targets = Vec::new();
    let mut positions = Vec::new();
    for r in rows {
        for (i, target) in r.links.iter().enumerate() {
            sources.push(r.url.clone().into_bytes());
            targets.push(target.clone().into_bytes());
            positions.push(i as i64);
        }
    }
    let links_bytes = write_parquet_strings(
        &dir.join("links.parquet"),
        "message links { required binary source_url (UTF8); required binary target_url (UTF8); required int64 position; }",
        &[sources, targets],
        Some(&positions),
    )?;
    Ok((extracts_bytes, links_bytes))
}

fn record_projection(r: &RecordRow) -> Value {
    serde_json::json!({
        "url": r.url,
        "publisher": r.publisher,
        "delta_id": r.delta_id,
        "observed_at": r.observed_at,
        "weight": r.weight,
    })
}

fn build_tier0(dir: &Path, records: &[RecordRow]) -> Result<Vec<u8>> {
    std::fs::create_dir_all(dir)?;
    let sqlite_path = dir.join("index.sqlite");
    if sqlite_path.exists() {
        std::fs::remove_file(&sqlite_path)?;
    }
    let conn = Connection::open(&sqlite_path)?;
    conn.execute_batch(
        "CREATE TABLE records(url TEXT, publisher TEXT, delta_id TEXT, observed_at TEXT, weight TEXT, title TEXT, abstract TEXT, lang TEXT);
         CREATE VIRTUAL TABLE records_fts USING fts5(title, abstract, content=records, content_rowid=rowid);",
    )?;
    for r in records {
        conn.execute(
            "INSERT INTO records(url, publisher, delta_id, observed_at, weight, title, abstract, lang) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (&r.url, &r.publisher, &r.delta_id, &r.observed_at, &r.weight, &r.title, &r.abstract_text, &r.lang),
        )?;
    }
    conn.execute("INSERT INTO records_fts(records_fts) VALUES('rebuild')", [])?;
    drop(conn);
    Ok(std::fs::read(&sqlite_path)?)
}

fn build_state(
    db: &Db,
    data_dir: &Path,
    log_position: u64,
    records: &[RecordRow],
) -> Result<(SnapshotState, String)> {
    let seed_bytes = std::fs::read(data_dir.join("keys/seed"))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| Error::Key("seed file must be exactly 32 bytes".into()))?;
    let aggregator_public_key = keys::public_b64u(&seed);
    let cadence = db.param("block_cadence_seconds")?;
    let publishers = db.list_publishers()?;

    let mut entries = Vec::with_capacity(2 + publishers.len() + records.len());
    entries.push(StateEntry::AggregatorKey(AggregatorKeyEntry {
        key_id: AGGREGATOR_KEY_ID.to_string(),
        public_key: aggregator_public_key,
        added_height: 0,
        removed_height: None,
    }));
    entries.push(StateEntry::Parameter(ParameterEntry {
        name: "block_cadence_seconds".to_string(),
        value: cadence,
        effective_height: 0,
    }));
    for p in &publishers {
        let declaration: Value = serde_json::from_slice(&p.declaration_json)?;
        entries.push(StateEntry::Declaration(DeclarationEntry {
            domain: p.domain.clone(),
            declaration,
            sealing_height: 0,
        }));
    }
    for (domain, opened_block, window_end) in db.list_open_recovery_windows()? {
        entries.push(StateEntry::RecoveryWindow(RecoveryWindowEntry {
            domain,
            declaration_height: opened_block as u64,
            window_end,
        }));
    }
    for r in records {
        entries.push(StateEntry::Record(RecordEntry {
            publisher: r.publisher.clone(),
            url: r.url.clone(),
            delta_id: r.delta_id.clone(),
        }));
    }

    let entry_values = entries
        .iter()
        .map(serde_json::to_value)
        .collect::<serde_json::Result<Vec<Value>>>()?;
    let digest = state_digest(&entry_values)?;

    Ok((
        SnapshotState {
            wist_version: WIST_VERSION.to_string(),
            log_position,
            entries,
        },
        digest,
    ))
}

fn update_index(
    data_dir: &Path,
    snapshot_date: &str,
    log_position: u64,
    content_digest_value: &str,
    sk: &SigningKey,
) -> Result<()> {
    let index_path = data_dir.join("snapshots/index.json");
    let mut snapshots = if index_path.exists() {
        let bytes = std::fs::read(&index_path)?;
        let doc: Value = serde_json::from_slice(&bytes)?;
        let inner = doc
            .get("index")
            .cloned()
            .ok_or_else(|| Error::Snapshot("existing index.json missing 'index'".into()))?;
        let index: SnapshotIndex = serde_json::from_value(inner)?;
        index.snapshots
    } else {
        Vec::new()
    };
    snapshots.retain(|e| e.snapshot_date != snapshot_date);
    snapshots.push(SnapshotIndexEntry {
        snapshot_date: snapshot_date.to_string(),
        log_position,
        manifest_url: format!("/snapshots/{snapshot_date}/manifest.json"),
        content_digest: content_digest_value.to_string(),
    });
    snapshots.sort_by_key(|e| std::cmp::Reverse(e.log_position));

    let updated_at = jiff::Timestamp::from_second(jiff::Timestamp::now().as_second())
        .map_err(|_| Error::Snapshot("current time out of range".into()))?
        .to_string();

    let index = SnapshotIndex {
        wist_version: WIST_VERSION.to_string(),
        updated_at,
        snapshots,
    };
    let index_value = serde_json::to_value(&index)?;
    let envelope = sign_envelope(&index_value, "index", AGGREGATOR_KEY_ID, sk)?;
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&index_path, serde_json::to_vec(&envelope)?)?;
    Ok(())
}

fn apply_sanctions(db: &Db, records: Vec<RecordRow>, at: &str) -> Result<Vec<RecordRow>> {
    let mut levels: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    let mut kept = Vec::with_capacity(records.len());
    for mut r in records {
        let level = match levels.get(&r.publisher) {
            Some(l) => *l,
            None => {
                let l = crate::sanctions::sanction_level(db, &r.publisher, at)?;
                levels.insert(r.publisher.clone(), l);
                l
            }
        };
        match level {
            4 => continue,
            2 => r.weight = "reduced".to_string(),
            _ => {}
        }
        kept.push(r);
    }
    Ok(kept)
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    log_position: u64,
    anchor_block_hash: &str,
    snapshot_date: &str,
    sealed_at: &str,
) -> Result<()> {
    let records = apply_sanctions(db, db.list_records()?, sealed_at)?;
    let snapshot_dir = data_dir.join("snapshots").join(snapshot_date);

    let shard_count = db.param("snapshot_shard_count").unwrap_or(1).max(1) as u64;
    let sharded = shard_count > 1;
    let mut partitions: Vec<Vec<RecordRow>> = (0..shard_count).map(|_| Vec::new()).collect();
    let mut whole_projection = Vec::with_capacity(records.len());
    for r in records {
        whole_projection.push(record_projection(&r));
        partitions[shard_index(&r.publisher, shard_count) as usize].push(r);
    }
    let content_digest_value = content_digest(&whole_projection)?;

    let mut files = Vec::new();
    let mut shard_digests = Vec::new();
    let mut all_records = Vec::new();
    for (i, shard_records) in partitions.into_iter().enumerate() {
        let (prefix, shard_field) = if sharded {
            (format!("shard-{i}/"), Some(i as u64))
        } else {
            (String::new(), None)
        };
        let shard_base = snapshot_dir.join(prefix.trim_end_matches('/'));
        let sqlite_bytes = build_tier0(&shard_base.join("tier0"), &shard_records)?;
        let tier1_rows = load_tier1_rows(data_dir, &shard_records);
        let (extracts_bytes, links_bytes) = build_tier1(&shard_base.join("tier1"), &tier1_rows)?;
        for (rel, bytes, tier) in [
            ("tier0/index.sqlite", &sqlite_bytes, 0u8),
            ("tier1/extracts.parquet", &extracts_bytes, 1),
            ("tier1/links.parquet", &links_bytes, 1),
        ] {
            files.push(SnapshotFile {
                path: format!("{prefix}{rel}"),
                sha256: sha256_hex(bytes),
                bytes: bytes.len() as u64,
                tier,
                shard: shard_field,
            });
        }
        if sharded {
            let projection: Vec<Value> = shard_records.iter().map(record_projection).collect();
            shard_digests.push(content_digest(&projection)?);
        }
        all_records.extend(shard_records);
    }
    let records = all_records;

    let (state, state_digest_value) = build_state(db, data_dir, log_position, &records)?;
    let state_value = serde_json::to_value(&state)?;
    let state_envelope = sign_envelope(&state_value, "state", AGGREGATOR_KEY_ID, sk)?;
    let state_bytes = serde_json::to_vec(&state_envelope)?;
    std::fs::write(snapshot_dir.join("state.json"), &state_bytes)?;

    let manifest = SnapshotManifest {
        wist_version: WIST_VERSION.to_string(),
        snapshot_date: snapshot_date.to_string(),
        log_position,
        anchor_block_hash: anchor_block_hash.to_string(),
        content_digest: content_digest_value.clone(),
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
    let manifest_envelope = sign_envelope(&manifest_value, "manifest", AGGREGATOR_KEY_ID, sk)?;
    std::fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_vec(&manifest_envelope)?,
    )?;

    update_index(
        data_dir,
        snapshot_date,
        log_position,
        &content_digest_value,
        sk,
    )
}
