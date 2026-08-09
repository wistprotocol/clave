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
    AggregatorKeyEntry, DeclarationEntry, ParameterEntry, RecordEntry, SnapshotFile, SnapshotIndex,
    SnapshotIndexEntry, SnapshotManifest, SnapshotState, SnapshotStateFile, StateEntry,
};
use wist_core::snapshot::{content_digest, state_digest};

const AGGREGATOR_KEY_ID: &str = "log1";

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
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

fn build_state(db: &Db, data_dir: &Path, log_position: u64) -> Result<(SnapshotState, String)> {
    let seed_bytes = std::fs::read(data_dir.join("keys/seed"))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| Error::Key("seed file must be exactly 32 bytes".into()))?;
    let aggregator_public_key = keys::public_b64u(&seed);
    let cadence = db.param("block_cadence_seconds")?;
    let publishers = db.list_publishers()?;
    let records = db.list_records()?;

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
    for r in &records {
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

pub fn build(
    db: &Db,
    data_dir: &Path,
    sk: &SigningKey,
    log_position: u64,
    anchor_block_hash: &str,
    snapshot_date: &str,
) -> Result<()> {
    let records = db.list_records()?;
    let snapshot_dir = data_dir.join("snapshots").join(snapshot_date);

    let sqlite_bytes = build_tier0(&snapshot_dir.join("tier0"), &records)?;

    let record_values: Vec<Value> = records.iter().map(record_projection).collect();
    let content_digest_value = content_digest(&record_values)?;

    let (state, state_digest_value) = build_state(db, data_dir, log_position)?;
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
        shards: None,
        files: vec![SnapshotFile {
            path: "tier0/index.sqlite".to_string(),
            sha256: sha256_hex(&sqlite_bytes),
            bytes: sqlite_bytes.len() as u64,
            tier: 0,
            shard: None,
        }],
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
