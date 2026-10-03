mod common;

use clave::snapshot::{
    file_layout, index_entries, link_rows, materialize, tier_record, TierRecord,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use wist_core::materialization::{ContentTuple, LinkRow};
use wist_core::objects::{RecordEntry, SnapshotManifest, StateEntry, WithdrawalEntry};
use wist_core::sealing::{Record, Records, Removal};
use wist_core::snapshot::{content_digest, shard_of};

fn vector(name: &str) -> Value {
    let path = common::spec_dir().join("vectors/wist3").join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn payload_octets(payloads: &Value, item_id: &str) -> Vec<u8> {
    wist_core::jcs::canonicalize(&payloads[item_id]).unwrap()
}

fn tier_records(
    entries: &[StateEntry],
    self_declared: impl Fn(&str) -> bool,
    payloads: &Value,
) -> Vec<TierRecord> {
    materialize(entries, self_declared)
        .unwrap()
        .iter()
        .map(|record| {
            tier_record(record, &payload_octets(payloads, &record.tuple.item_id)).unwrap()
        })
        .collect()
}

fn tuples_of(records: &[TierRecord]) -> Vec<ContentTuple> {
    records.iter().map(|record| record.tuple.clone()).collect()
}

fn links_of(value: &Value) -> Vec<LinkRow> {
    serde_json::from_value(value.clone()).unwrap()
}

fn parquet_rows(path: &std::path::Path) -> Vec<Vec<String>> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let reader = SerializedFileReader::new(std::fs::File::open(path).unwrap()).unwrap();
    reader
        .get_row_iter(None)
        .unwrap()
        .map(|row| {
            row.unwrap()
                .get_column_iter()
                .map(|(_, value)| format!("{value}").trim_matches('"').to_owned())
                .collect()
        })
        .collect()
}

fn sqlite_rows(path: &std::path::Path) -> Vec<Vec<Option<String>>> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = conn
        .prepare("SELECT url, publisher, item_id, observed_at, attested_at, title, abstract, lang, collection FROM records ORDER BY rowid")
        .unwrap();
    statement
        .query_map([], |row| {
            (0..9)
                .map(|column| row.get::<_, Option<String>>(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn snapshot_records_vector_materializes_content_tuples_tier_rows_and_link_rows() {
    let vector = vector("snapshot-records.json");
    let entries: Vec<StateEntry> = serde_json::from_value(vector["tuples"].clone()).unwrap();
    let records = tier_records(&entries, |_| false, &vector["payloads"]);
    let expected: Vec<ContentTuple> = serde_json::from_value(vector["records"].clone()).unwrap();
    let mut sorted_expected = expected.clone();
    sorted_expected.sort_by(|a, b| (&a.publisher, &a.url).cmp(&(&b.publisher, &b.url)));
    assert_eq!(tuples_of(&records), sorted_expected);
    assert_eq!(
        content_digest(&tuples_of(&records)).unwrap(),
        vector["content_digest"]
    );
    let refs: Vec<&TierRecord> = records.iter().collect();
    assert_eq!(link_rows(&refs), links_of(&vector["links"]));

    let dir = tempfile::tempdir().unwrap();
    clave::snapshot::write_tier_files(dir.path(), &refs, &[], &[], &[]).unwrap();
    let links: Vec<Vec<String>> = links_of(&vector["links"])
        .into_iter()
        .map(|row| vec![row.source_url, row.target_url, row.position.to_string()])
        .collect();
    assert_eq!(parquet_rows(&dir.path().join("tier1/links.parquet")), links);
    let extracts = parquet_rows(&dir.path().join("tier1/extracts.parquet"));
    let rows = sqlite_rows(&dir.path().join("tier0/index.sqlite"));
    for ((record, extract), row) in records.iter().zip(&extracts).zip(&rows) {
        let summary = &record.payload.content.summary;
        assert_eq!(
            *extract,
            vec![
                record.tuple.url.clone(),
                record.tuple.publisher.clone(),
                record.tuple.item_id.clone(),
                record.payload.content.extract.clone(),
                "default".to_owned(),
            ]
        );
        assert_eq!(
            *row,
            vec![
                Some(record.tuple.url.clone()),
                Some(record.tuple.publisher.clone()),
                Some(record.tuple.item_id.clone()),
                Some(record.tuple.observed_at.clone()),
                Some(record.tuple.attested_at.clone()),
                Some(summary.title.clone()),
                summary.r#abstract.clone(),
                Some("en".to_owned()),
                Some("default".to_owned()),
            ]
        );
    }
    assert_eq!((extracts.len(), rows.len()), (records.len(), records.len()));
}

#[test]
fn snapshot_records_vector_shards_rows_and_files_by_the_domain_rule() {
    let vector = vector("snapshot-records.json");
    let sharded = &vector["sharded"];
    let count = sharded["count"].as_u64().unwrap();
    let nonzero = NonZeroU64::new(count).unwrap();
    for (domain, shard) in sharded["shard_of"].as_object().unwrap() {
        assert_eq!(
            shard_of(domain, nonzero),
            shard.as_u64().unwrap(),
            "{domain}"
        );
    }
    let entries: Vec<StateEntry> = serde_json::from_value(vector["tuples"].clone()).unwrap();
    let records = tier_records(&entries, |_| false, &vector["payloads"]);
    for (shard, digest) in sharded["digests"].as_array().unwrap().iter().enumerate() {
        let held: Vec<ContentTuple> = records
            .iter()
            .filter(|record| shard_of(&record.tuple.publisher, nonzero) == shard as u64)
            .map(|record| record.tuple.clone())
            .collect();
        assert_eq!(content_digest(&held).unwrap(), *digest, "shard {shard}");
    }
    let files: Vec<(String, u8, Option<u64>)> = sharded["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            (
                file["path"].as_str().unwrap().to_owned(),
                file["tier"].as_u64().unwrap() as u8,
                file["shard"].as_u64(),
            )
        })
        .collect();
    assert_eq!(file_layout(count), files);
    for (rows, member) in [
        (&sharded["label_rows"], "labeler"),
        (&sharded["labeler_rows"], "labeler"),
        (&sharded["dispute_rows"], "disputant"),
    ] {
        for row in rows.as_array().unwrap() {
            assert_eq!(
                shard_of(row[member].as_str().unwrap(), nonzero),
                row["shard"].as_u64().unwrap()
            );
        }
    }
}

struct Replayed {
    records: Records,
    withdrawn: BTreeSet<String>,
    declared: BTreeSet<String>,
}

impl Replayed {
    fn apply(&mut self, event: &Value) {
        let text = |name: &str| event[name].as_str().unwrap().to_owned();
        match event["event"].as_str().unwrap() {
            "declaration" => {
                self.declared.insert(text("domain"));
            }
            "withdrawal" => {
                self.withdrawn.insert(text("item"));
            }
            "narrowing" => {
                for url in event["urls"].as_array().unwrap() {
                    self.records
                        .remove(&text("publisher"), url.as_str().unwrap());
                }
            }
            "base" => {
                self.records
                    .remove_collection(&text("publisher"), &text("collection"));
            }
            "record" => {
                let item = event["item"].clone();
                let url = item["url"].as_str().unwrap().to_owned();
                self.records.insert(
                    &text("publisher"),
                    &url,
                    Record {
                        item_id: wist_core::item::item_id(&item).unwrap(),
                        item,
                        collection: text("collection"),
                        catalog: text("catalog"),
                        generated_at: text("generated_at"),
                    },
                );
            }
            "removal" => {
                self.records.remove_with(
                    &text("publisher"),
                    &text("url"),
                    Removal {
                        item_id: text("item"),
                        catalog: text("catalog"),
                        generated_at: text("generated_at"),
                    },
                );
            }
            other => panic!("unknown event {other}"),
        }
    }

    fn entries(&self) -> Vec<StateEntry> {
        let mut entries = self.records.state_entries();
        entries.extend(self.withdrawn.iter().map(|item_id| {
            StateEntry::Withdrawal(WithdrawalEntry {
                item_id: item_id.clone(),
                publisher: String::new(),
                sealing_height: 0,
            })
        }));
        entries
    }
}

fn check_height(
    expected: &Value,
    entries: &[StateEntry],
    declared: &BTreeSet<String>,
    payloads: &Value,
    case: &str,
) {
    let records = tier_records(entries, |host| declared.contains(host), payloads);
    let materialized: Vec<ContentTuple> =
        serde_json::from_value(expected["materialized"].clone()).unwrap();
    assert_eq!(tuples_of(&records), materialized, "{case}");
    let refs: Vec<&TierRecord> = records.iter().collect();
    assert_eq!(link_rows(&refs), links_of(&expected["links"]), "{case}");
    assert_eq!(
        content_digest(&tuples_of(&records)).unwrap(),
        expected["content_digest"],
        "{case}"
    );
}

#[test]
fn record_materialization_vector_replays_through_the_producer_at_every_height() {
    let vector = vector("record-materialization.json");
    let mut heights = 0;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut replayed = Replayed {
            records: Records::default(),
            withdrawn: BTreeSet::new(),
            declared: BTreeSet::new(),
        };
        let expected: BTreeMap<u64, &Value> = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|expected| (expected["height"].as_u64().unwrap(), expected))
            .collect();
        for epoch in case["epochs"].as_array().unwrap() {
            for event in epoch["events"].as_array().unwrap() {
                replayed.apply(event);
            }
            let height = epoch["height"].as_u64().unwrap();
            check_height(
                expected[&height],
                &replayed.entries(),
                &replayed.declared,
                &vector["payloads"],
                &format!("{name} at {height}"),
            );
            heights += 1;
        }
        let snapshot = &case["snapshot"];
        let tuples: Vec<StateEntry> = serde_json::from_value(snapshot["tuples"].clone()).unwrap();
        let declared: BTreeSet<String> = tuples
            .iter()
            .filter_map(|tuple| match tuple {
                StateEntry::Declaration(entry) => Some(entry.domain.clone()),
                _ => None,
            })
            .collect();
        let height = snapshot["height"].as_u64().unwrap();
        check_height(
            expected[&height],
            &tuples,
            &declared,
            &vector["payloads"],
            &format!("{name} resumed at {height}"),
        );
    }
    assert_eq!(heights, 16);
}

#[test]
fn materialization_preference_vector_selects_one_publisher_per_url() {
    let vector = vector("materialization-preference.json");
    for case in vector["cases"].as_array().unwrap() {
        let host = case["host"].as_str().unwrap();
        let url = format!("https://{host}/page");
        let mut entries = Vec::new();
        for (index, record) in case["records"].as_array().unwrap().iter().enumerate() {
            let publisher = record["publisher"].as_str().unwrap();
            let item = json!({
                "publisher": publisher, "url": url, "observed_at": "2026-10-01T00:00:00Z",
                "payload": {"commitment": format!("hmac-sha256:{index:064x}"), "alg": "HMAC-SHA256", "bytes": 1},
                "meta": {"lang": "en"}
            });
            if record["withdrawn"] == true {
                entries.push(StateEntry::Withdrawal(WithdrawalEntry {
                    item_id: wist_core::item::item_id(&item).unwrap(),
                    publisher: publisher.to_owned(),
                    sealing_height: 0,
                }));
            }
            entries.push(StateEntry::Record(RecordEntry {
                publisher: publisher.to_owned(),
                url: url.clone(),
                item,
                collection: "default".into(),
                catalog_id: format!("sha256:{}", "a".repeat(64)),
                generated_at: "2026-10-01T00:00:00Z".into(),
            }));
        }
        let self_declared = case["self_declared"] == true;
        let materialized =
            materialize(&entries, |candidate| self_declared && candidate == host).unwrap();
        let chosen: Vec<&str> = materialized
            .iter()
            .map(|record| record.tuple.publisher.as_str())
            .collect();
        let expected: Vec<&str> = case["materialized"].as_str().into_iter().collect();
        assert_eq!(chosen, expected, "{}", case["label"]);
    }
}

#[test]
fn snapshot_index_vector_lists_newest_date_then_higher_epoch_first() {
    let vector = vector("snapshot-index.json");
    for case in vector["cases"].as_array().unwrap() {
        let manifests: Vec<SnapshotManifest> = case["manifests"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(|envelope| serde_json::from_value(envelope["manifest"].clone()).ok())
            .collect();
        if manifests.len() != case["manifests"].as_object().unwrap().len() {
            continue;
        }
        let listed: Vec<&str> = case["index"]["index"]["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["manifest_url"].as_str().unwrap())
            .collect();
        let produced: Vec<String> = index_entries(manifests)
            .into_iter()
            .map(|entry| entry.manifest_url)
            .collect();
        assert_eq!(
            listed == produced,
            case["index_ordered"] == true,
            "{}",
            case["name"]
        );
    }
}
