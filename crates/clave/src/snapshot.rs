use crate::db::{Db, RecordRow};
use crate::error::{Error, Result};
use crate::history::declarations::Domain;
use crate::keys;
use crate::WIST_VERSION;
use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use wist_core::crypto::{hex_encode, SigningKey};
use wist_core::envelope::sign_envelope;
use wist_core::objects::{
    AggregatorKeyEntry, AuditorEntry, DeclarationEntry, ParameterEntry, RecordEntry,
    RecoveryWindowEntry, SanctionStateEntry, SnapshotFile, SnapshotIndex, SnapshotIndexEntry,
    SnapshotManifest, SnapshotState, SnapshotStateFile, StateEntry,
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
        let Ok(payload) = crate::json::parse(&bytes) else {
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
    domains: &BTreeMap<String, Domain>,
) -> Result<(SnapshotState, String)> {
    let seed_bytes = std::fs::read(data_dir.join("keys/seed"))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| Error::Key("seed file must be exactly 32 bytes".into()))?;
    let aggregator_public_key = keys::public_b64u(&seed);
    let head_sealed_at = db
        .last_block()?
        .map(|b| b.sealed_at)
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());

    let mut entries = Vec::with_capacity(2 + domains.len() + records.len());
    entries.push(StateEntry::AggregatorKey(AggregatorKeyEntry {
        key_id: AGGREGATOR_KEY_ID.to_string(),
        public_key: aggregator_public_key,
        added_height: 0,
        removed_height: None,
    }));
    for (name, value, effective_at) in db.parameter_state(&head_sealed_at)? {
        entries.push(StateEntry::Parameter(ParameterEntry {
            name,
            effective_at,
            value,
        }));
    }
    for (domain, state) in domains {
        let current = state.current();
        entries.push(StateEntry::Declaration(DeclarationEntry {
            domain: domain.clone(),
            declaration: current.envelope().clone(),
            sealing_height: current.position().block_number,
            highest_accepted_seq: state.highest_accepted_seq(),
        }));
    }
    for (auditor_id, key_id, public_key, admitted_height, removed_height) in db.roster_state()? {
        entries.push(StateEntry::Auditor(AuditorEntry {
            auditor_id,
            key_id,
            public_key,
            admitted_height,
            removed_height,
        }));
    }
    for domain in db.derived_sanctioned_domains(&head_sealed_at)? {
        let state = crate::sanctions::sanction_state(db, &domain, &head_sealed_at)?;
        if state.derived_level == 0 {
            continue;
        }
        entries.push(StateEntry::SanctionState(SanctionStateEntry {
            domain,
            level: state.derived_level as u64,
            evidence: state.evidence,
            deadlines: state.deadlines,
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
            declaration_height: window.owner().position().block_number,
            window_end: end,
            head: window.head().envelope().clone(),
            head_height: window.head().position().block_number,
        }));
    }
    // WIST-3 §7: a `record` tuple exists for every key the chain-tip
    // table holds, a deleted URL included — a chain never restarts, so a
    // resuming Consumer needs the tip to reject a fork of it.
    for (publisher, url, tip) in db.list_url_tips()? {
        entries.push(StateEntry::Record(RecordEntry {
            publisher,
            url,
            delta_id: tip,
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
        let doc: Value = crate::json::parse(&bytes)?;
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

/// WIST-3 §7: level 2 marks the domain's records reduced-weight, level 3
/// stops its later Deltas from being materialized at all from the height
/// it takes effect, and level 4 removes its records entirely.
fn apply_sanctions(db: &Db, records: Vec<RecordRow>, at: &str) -> Result<Vec<RecordRow>> {
    let mut states: std::collections::HashMap<String, (u8, Option<String>)> =
        std::collections::HashMap::new();
    let mut kept = Vec::with_capacity(records.len());
    for mut r in records {
        let state = match states.get(&r.publisher) {
            Some(state) => state.clone(),
            None => {
                let s = crate::sanctions::sanction_state(db, &r.publisher, at)?;
                let state = (s.level, s.effective_at);
                states.insert(r.publisher.clone(), state.clone());
                state
            }
        };
        match state {
            (4, _) => continue,
            (3, Some(effective_at)) if r.sealed_at >= effective_at => continue,
            (2, _) => r.weight = "reduced".to_string(),
            _ => {}
        }
        kept.push(r);
    }
    Ok(kept)
}

/// WIST-3 §7, one URL, one Publisher: a self-declared host's own record,
/// else the nearest ancestor Publisher's, else the least non-ancestor
/// domain in ascending octet order; the other records are excluded.
fn prefer_one_publisher(db: &Db, records: Vec<RecordRow>) -> Result<Vec<RecordRow>> {
    let mut by_url: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for (index, record) in records.iter().enumerate() {
        by_url.entry(record.url.as_str()).or_default().push(index);
    }
    let mut declared: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut keep = vec![true; records.len()];
    for (url, indices) in by_url {
        let host = crate::declaration::url_host(url);
        let own = indices
            .iter()
            .copied()
            .find(|index| records[*index].publisher == host);
        if own.is_none()
            && indices
                .iter()
                .all(|index| records[*index].publisher == host)
        {
            continue;
        }
        let self_declared = own.is_some()
            || match declared.get(host) {
                Some(known) => *known,
                None => {
                    let sealed = !db.sealed_declarations(host)?.is_empty();
                    declared.insert(host.to_owned(), sealed);
                    sealed
                }
            };
        let preferred = if self_declared {
            own
        } else {
            let ancestor = |index: &usize| {
                host.strip_suffix(records[*index].publisher.as_str())
                    .is_some_and(|prefix| prefix.ends_with('.'))
            };
            indices
                .iter()
                .copied()
                .filter(ancestor)
                .max_by_key(|index| records[*index].publisher.len())
                .or_else(|| {
                    indices.iter().copied().min_by(|a, b| {
                        records[*a]
                            .publisher
                            .as_bytes()
                            .cmp(records[*b].publisher.as_bytes())
                    })
                })
        };
        for index in indices {
            keep[index] = preferred == Some(index);
        }
    }
    Ok(records
        .into_iter()
        .zip(keep)
        .filter_map(|(record, kept)| kept.then_some(record))
        .collect())
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
    domains: &BTreeMap<String, Domain>,
) -> Result<()> {
    let records = prefer_one_publisher(db, apply_sanctions(db, db.list_records()?, sealed_at)?)?;
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

    let (state, state_digest_value) = build_state(db, data_dir, log_position, &records, domains)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::RecordUpsert;

    const DAY: i64 = 86400;
    const T0: i64 = 1_800_000_000;

    fn ts(epoch: i64) -> String {
        jiff::Timestamp::from_second(epoch).unwrap().to_string()
    }

    fn seal_record(db: &Db, block: u64, sealed_epoch: i64, url: &str) {
        seal_record_as(db, block, sealed_epoch, url, "example.com", &[]);
    }

    fn seal_record_as(
        db: &Db,
        block: u64,
        sealed_epoch: i64,
        url: &str,
        publisher: &str,
        declared: &[&str],
    ) {
        let declarations: Vec<crate::db::SealedDeclarationRow<'_>> = declared
            .iter()
            .map(|domain| crate::db::SealedDeclarationRow {
                domain,
                seq: 0,
                declaration_json: b"{}",
            })
            .collect();
        db.commit_seal(
            &[],
            block,
            &format!("sha256:h{block}"),
            &ts(sealed_epoch),
            &[RecordUpsert {
                url,
                publisher,
                delta_id: &format!("sha256:{:064x}", block),
                observed_at: &ts(sealed_epoch),
                weight: "full",
                title: "t",
                abstract_text: None,
                lang: "en",
            }],
            &[],
            &[],
            &declarations,
            0,
        )
        .unwrap();
    }

    #[test]
    fn one_url_one_publisher_prefers_self_then_nearest_ancestor_then_octet_order() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        let rows: [(&str, &str, &[&str]); 11] = [
            ("https://a.example.com/x", "example.com", &[]),
            (
                "https://a.example.com/x",
                "a.example.com",
                &["a.example.com"],
            ),
            ("https://d.example.com/x", "example.com", &["d.example.com"]),
            ("https://a.b.example.com/x", "example.com", &[]),
            ("https://a.b.example.com/x", "b.example.com", &[]),
            ("https://c.example.com/x", "zeta.example", &[]),
            ("https://c.example.com/x", "example.com", &[]),
            ("https://e.example.com/x", "zeta.example", &[]),
            ("https://e.example.com/x", "alpha.example", &[]),
            ("https://a.notexample.com/x", "example.com", &[]),
            ("https://a.notexample.com/x", "beta.example", &[]),
        ];
        for (block, (url, publisher, declared)) in rows.iter().enumerate() {
            seal_record_as(
                &db,
                block as u64,
                T0 + block as i64,
                url,
                publisher,
                declared,
            );
        }
        let kept = prefer_one_publisher(&db, db.list_records().unwrap()).unwrap();
        let mut pairs: Vec<(&str, &str)> = kept
            .iter()
            .map(|r| (r.url.as_str(), r.publisher.as_str()))
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

    #[test]
    fn level_three_stops_materialization_from_its_effective_height() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("clave.sqlite")).unwrap();
        seal_record(&db, 0, T0, "https://example.com/before");
        seal_record(&db, 1, T0 + DAY, "https://example.com/at");
        db.record_derived_state(
            1,
            &ts(T0 + DAY),
            &[crate::db::DerivedPublisherRow {
                domain: "example.com",
                reputation_u: 100_000,
                level: 3,
                enforceable_level: 3,
                fallback_level: 1,
                level_since: &ts(T0 + DAY),
                evidence: &[],
                deadlines: &[],
            }],
            &[],
        )
        .unwrap();
        seal_record(&db, 2, T0 + 2 * DAY, "https://example.com/after");

        let kept = apply_sanctions(&db, db.list_records().unwrap(), &ts(T0 + 3 * DAY)).unwrap();
        let urls: Vec<&str> = kept.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(urls, ["https://example.com/before"]);
    }
}
