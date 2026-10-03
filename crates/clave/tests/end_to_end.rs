mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use wist_core::objects::StateEntry;
use wist_core::sealing::{Epoch, Judgment, Outcome, Parameters, Replay};

fn leaf(entry: &Value) -> [u8; 32] {
    wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap())
}

fn replay_published(data_dir: &Path) -> Replay {
    let head = head_checkpoint(data_dir);
    let anchor = clave::history::anchor(data_dir).unwrap();
    let (key, key_id) = (anchor.key.clone(), anchor.key_id.clone());
    let log_key = move |kid: &str| (kid == key_id).then(|| key.clone());
    let parameters = Parameters::suite();
    let mut replay = Replay::new();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for height in 0..=head.epoch_number() {
        let note =
            std::fs::read_to_string(clave::publication::archive_path(data_dir, height)).unwrap();
        let checkpoint = wist_core::checkpoint::Checkpoint::parse(&note).unwrap();
        let previous = leaves.len() as u64;
        let entries = served_entries(data_dir, previous, checkpoint.tree_size());
        wist_core::epoch::verify_epoch(
            previous,
            &checkpoint,
            &entries,
            &wist_core::merkle::LeafHashes(&leaves),
            u64::MAX,
        )
        .unwrap();
        leaves.extend(entries.iter().map(leaf));
        let outcome = replay
            .epoch(&Epoch {
                height,
                root: &checkpoint.root_token(),
                sealed_at: checkpoint.sealed_at(),
                parameters: &parameters,
                suffix_list: None,
                log_key: &log_key,
                entries: &entries,
            })
            .unwrap();
        let Outcome::Accepted {
            entries: judged, ..
        } = outcome
        else {
            panic!("Epoch {height} is rejected: {outcome:?}");
        };
        for (index, judgment) in judged.iter().enumerate() {
            assert!(
                matches!(judgment, None | Some(Judgment::Valid)),
                "Entry {index} of Epoch {height}: {judgment:?}"
            );
        }
    }
    replay
}

fn page(r: &Rig, path: &str, links: &[&str]) -> (Value, Option<Value>) {
    let (item, payload) = page_item_with_links(&r.p, &r.url(path), path, links);
    (item, Some(payload))
}

fn publish(
    r: &Rig,
    collection: &str,
    items: &[(Value, Option<Value>)],
    at: &str,
    previous: Option<&Published>,
) -> Published {
    publish_collection(&r.p, collection, items, at, previous)
}

fn status(r: &Rig) -> Value {
    let status = clave::serve::load_status(&r.db, &r.host).unwrap().unwrap();
    let value = serde_json::to_value(&status).unwrap();
    assert_valid("status.schema.json", &value);
    value
}

fn sealed_heights(r: &Rig, kind: &str) -> Vec<u64> {
    let head = r.db.last_epoch().unwrap().unwrap().epoch_number;
    (0..=head)
        .filter(|height| r.entries(*height).iter().any(|entry| entry["type"] == kind))
        .collect()
}

struct Built {
    r: Rig,
    shop_v2: Published,
    narrowed_at: u64,
}

fn built_log() -> Built {
    let r = Rig::new();
    r.db.set_param("snapshot_shard_count", 1).unwrap();
    let mut declaration = current_declaration(&r.p)["publisher"].clone();
    declaration["collections"] = json!([
        {"name": "journal", "scope": [{"url": r.url("journal/"), "match": "prefix"}]},
        {"name": "shop", "scope": [{"url": r.url("shop/"), "match": "prefix"}]},
    ]);
    write_declaration(&r.p, &declaration, &K1_SEED);

    let keep_a = page(
        &r,
        "journal/keep/a",
        &["https://other.example/1", "https://other.example/2"],
    );
    let b = page(&r, "journal/b", &[]);
    let c = page(&r, "journal/c", &[]);
    let x = page(&r, "shop/x", &["https://other.example/x"]);
    let y = page(&r, "shop/y", &[]);
    let journal_v1 = publish(
        &r,
        "journal",
        &[keep_a.clone(), b.clone(), c.clone()],
        "2026-08-09T12:00:00Z",
        None,
    );
    let shop_v1 = publish(
        &r,
        "shop",
        &[x.clone(), y.clone()],
        "2026-08-09T12:00:00Z",
        None,
    );
    r.pull("2026-08-09T12:00:05Z");
    let opening = status(&r);
    let names: Vec<&str> = opening["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|collection| collection["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"journal") && names.contains(&"shop"),
        "{opening}"
    );
    let journal = opening["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|collection| collection["name"] == "journal")
        .unwrap();
    assert_eq!(journal["latest"], Value::Null);
    assert_eq!(journal["accepted"], journal_v1.catalog_id.as_str());
    assert_eq!(journal["waiting"][0]["id"], journal_v1.catalog_id.as_str());
    assert_eq!(journal["waiting"].as_array().unwrap().len(), 4);
    r.seal("2026-08-09T13:00:00Z");
    let sealed = status(&r);
    assert!(sealed["collections"]
        .as_array()
        .unwrap()
        .iter()
        .all(|collection| collection["latest"] == collection["accepted"]
            && collection["waiting"].as_array().unwrap().is_empty()));

    let keep_d = page(&r, "journal/keep/d", &["https://other.example/d"]);
    let journal_v2 = publish(
        &r,
        "journal",
        &[
            keep_a.clone(),
            b.clone(),
            (removed_item(&r.p, &r.url("journal/c")), None),
            keep_d.clone(),
        ],
        "2026-08-09T13:30:00Z",
        Some(&journal_v1),
    );
    assert!(journal_v2.change_list.is_some());
    clave::governance::withdraw(
        &r.db,
        &r.sk,
        &r.host,
        &item_id(&b.0),
        "court order",
        "DE",
        wist_core::timestamp::log_seconds("2026-08-09T13:30:00Z").unwrap(),
    )
    .unwrap();
    let z = page(&r, "shop/z", &[]);
    let shop_v2 = publish(
        &r,
        "shop",
        &[x.clone(), y.clone(), z.clone()],
        "2026-08-09T13:30:00Z",
        Some(&shop_v1),
    );
    let broken = collection_dir(&r.p, "shop").join(format!(
        "changes/{}.json",
        shop_v2.change_list.as_ref().unwrap()
    ));
    std::fs::write(broken, b"{not json").unwrap();
    r.pull("2026-08-09T13:30:05Z");
    let discarded = status(&r);
    let chain = discarded["rejections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rejection| rejection["code"] == "WIST2-E08")
        .unwrap_or_else(|| panic!("{discarded}"));
    assert_eq!(chain["collection"], "shop");
    assert_eq!(chain["id"], shop_v2.catalog_id.as_str());
    assert!(chain["change_list"].is_string() && chain["condition"].is_string());
    r.seal("2026-08-09T14:00:00Z");
    r.seal("2026-08-09T15:00:00Z");

    let initial = current_declaration(&r.p);
    let mut narrowed = initial["publisher"].clone();
    narrowed["seq"] = 1.into();
    narrowed["prev_declaration"] = declaration_hash(&initial).into();
    narrowed["collections"][0]["scope"] =
        json!([{"url": r.url("journal/keep/"), "match": "prefix"}]);
    write_declaration(&r.p, &narrowed, &K1_SEED);
    let keep_e = page(&r, "journal/keep/e", &[]);
    publish(
        &r,
        "journal",
        &[keep_a.clone(), keep_d.clone(), keep_e.clone()],
        "2026-08-09T15:30:00Z",
        Some(&journal_v2),
    );
    r.pull("2026-08-09T15:30:05Z");
    let narrowed_at = r.db.last_epoch().unwrap().unwrap().epoch_number + 1;
    r.seal("2026-08-09T16:00:00Z");
    r.seal("2026-08-09T17:00:00Z");
    r.seal("2026-08-09T18:00:00Z");

    let w = page(&r, "shop/w", &[]);
    publish(
        &r,
        "shop",
        std::slice::from_ref(&w),
        "2027-02-10T00:00:00Z",
        Some(&shop_v2),
    );
    r.pull("2027-02-10T00:00:05Z");
    r.seal("2027-02-10T01:00:00Z");
    r.seal("2027-02-10T02:00:00Z");
    Built {
        r,
        shop_v2,
        narrowed_at,
    }
}

fn state_kinds(entries: &[StateEntry]) -> Vec<Value> {
    let mut values: Vec<Value> = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry,
                StateEntry::Collection(_)
                    | StateEntry::Record(_)
                    | StateEntry::Removal(_)
                    | StateEntry::Withdrawal(_)
            )
        })
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect();
    values.sort_by_key(|value| value.to_string());
    values
}

fn sqlite_rows(path: &Path) -> Vec<Vec<Option<String>>> {
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

fn parquet_rows(path: &Path) -> Vec<Vec<String>> {
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

#[test]
fn two_collections_pulled_and_sealed_replay_through_core_and_snapshot_and_status_agree() {
    let Built {
        r,
        shop_v2,
        narrowed_at,
    } = built_log();
    let replay = replay_published(r.data.path());

    let declarations = sealed_heights(&r, "publisher_declaration");
    assert!(declarations.contains(&narrowed_at), "{declarations:?}");
    let catalogs = sealed_heights(&r, "publisher_catalog");
    assert!(catalogs.iter().any(|height| *height >= narrowed_at));
    let journal_after = r
        .entries(narrowed_at)
        .iter()
        .chain(r.entries(narrowed_at + 1).iter())
        .any(|entry| {
            entry["type"] == "publisher_item"
                && entry["body"]["item"]["url"] == r.url("journal/keep/e").as_str()
        });
    assert!(
        journal_after,
        "the narrowed Collection's Item seals once the Declaration is sealed"
    );

    let records: Vec<&str> = replay.records().records().map(|(_, url, _)| url).collect();
    assert_eq!(
        records,
        [
            r.url("journal/keep/a"),
            r.url("journal/keep/d"),
            r.url("journal/keep/e"),
            r.url("shop/w"),
        ]
    );
    let removals: Vec<&str> = replay.records().removals().map(|(_, url, _)| url).collect();
    assert_eq!(removals, [r.url("journal/c")]);
    let shop_latest = replay.latest(&r.host, "shop").unwrap();
    assert_ne!(shop_latest.catalog_id, shop_v2.catalog_id);
    assert_eq!(shop_latest.base, Some(true));

    let outcome =
        clave::snapshot::produce(&r.data.path().join("clave.sqlite"), r.data.path()).unwrap();
    assert!(
        matches!(outcome, clave::snapshot::Outcome::Built { .. }),
        "{outcome:?}"
    );
    let directory = newest_served_snapshot(r.data.path());
    let state: Value =
        serde_json::from_slice(&std::fs::read(directory.join("state.json")).unwrap()).unwrap();
    let produced: Vec<StateEntry> =
        serde_json::from_value(state["state"]["entries"].clone()).unwrap();
    assert_eq!(state_kinds(&produced), state_kinds(&replay.state_entries()));

    let materialized = replay.materialized().unwrap();
    let rows = sqlite_rows(&directory.join("tier0/index.sqlite"));
    let expected_rows: Vec<Vec<Option<String>>> = materialized
        .iter()
        .map(|tuple| {
            let record = replay
                .records()
                .record(&tuple.publisher, &tuple.url)
                .unwrap();
            vec![
                Some(tuple.url.clone()),
                Some(tuple.publisher.clone()),
                Some(tuple.item_id.clone()),
                Some(tuple.observed_at.clone()),
                Some(tuple.attested_at.clone()),
                Some(tuple.url.clone()),
                None,
                Some("en".into()),
                Some(record.collection.clone()),
            ]
        })
        .collect();
    assert_eq!(rows, expected_rows);
    let links = parquet_rows(&directory.join("tier1/links.parquet"));
    assert_eq!(
        links,
        [
            [
                r.url("journal/keep/a"),
                "https://other.example/1".into(),
                "0".into()
            ],
            [
                r.url("journal/keep/a"),
                "https://other.example/2".into(),
                "1".into()
            ],
            [
                r.url("journal/keep/d"),
                "https://other.example/d".into(),
                "0".into()
            ],
        ]
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["manifest"]["content_digest"],
        wist_core::snapshot::content_digest(&materialized).unwrap()
    );

    let status = status(&r);
    let collections: Vec<(&str, &Value)> = status["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|collection| (collection["name"].as_str().unwrap(), &collection["latest"]))
        .collect();
    assert_eq!(
        collections,
        [
            (
                "journal",
                &json!(replay.latest(&r.host, "journal").unwrap().catalog_id)
            ),
            ("shop", &json!(shop_latest.catalog_id)),
        ]
    );
}

fn derived_tables(path: &Path) -> Vec<Vec<Vec<Option<String>>>> {
    let conn = rusqlite::Connection::open(path).unwrap();
    [
        "SELECT publisher, name, latest_envelope, latest_id, latest_height, latest_base FROM collections WHERE latest_id IS NOT NULL ORDER BY publisher, name",
        "SELECT publisher, url, item, item_id, collection, catalog_id, generated_at, sealing_height FROM records ORDER BY publisher, url",
        "SELECT publisher, url, item_id, catalog_id, generated_at FROM removals ORDER BY publisher, url",
        "SELECT item_id, publisher, kind, first_height FROM sealed_items ORDER BY item_id, publisher, kind",
        "SELECT item_id, domain, update_id, epoch_number, sealed_at FROM withdrawals ORDER BY item_id",
        "SELECT item_id, publisher, url, until, served FROM payload_duties ORDER BY item_id",
    ]
    .iter()
    .map(|sql| {
        let mut statement = conn.prepare(sql).unwrap();
        let width = statement.column_count();
        statement
            .query_map([], |row| {
                (0..width)
                    .map(|column| {
                        let value: rusqlite::types::Value = row.get(column)?;
                        Ok(match value {
                            rusqlite::types::Value::Null => None,
                            rusqlite::types::Value::Integer(n) => Some(n.to_string()),
                            rusqlite::types::Value::Real(n) => Some(n.to_string()),
                            rusqlite::types::Value::Text(text) => Some(text),
                            rusqlite::types::Value::Blob(octets) => {
                                Some(String::from_utf8_lossy(&octets).into_owned())
                            }
                        })
                    })
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    })
    .collect()
}

#[test]
fn a_store_restored_from_its_log_equals_the_store_that_sealed_it_in_every_log_derived_table() {
    let Built { r, .. } = built_log();
    let original = r.data.path().join("clave.sqlite");
    let archive = r.data.path().join("archive.sqlite");
    rusqlite::Connection::open(&original)
        .unwrap()
        .execute("VACUUM INTO ?1", [archive.to_str().unwrap()])
        .unwrap();
    let produced = derived_tables(&original);
    assert!(produced.iter().all(|rows| !rows.is_empty()), "{produced:?}");
    rusqlite::Connection::open(&archive)
        .unwrap()
        .execute_batch(
            "DELETE FROM collections; DELETE FROM records; DELETE FROM removals; DELETE FROM sealed_items; DELETE FROM withdrawals; DELETE FROM payload_duties;",
        )
        .unwrap();
    let restored = clave::db::Db::open(&archive).unwrap();
    let counts = restored.restore_from_log(r.data.path()).unwrap();
    assert_eq!(counts.records, produced[1].len());
    drop(restored);
    assert_eq!(derived_tables(&archive), produced);
    let again = clave::db::Db::open(&archive).unwrap();
    again.restore_from_log(r.data.path()).unwrap();
    drop(again);
    assert_eq!(
        derived_tables(&archive),
        produced,
        "a restore is idempotent"
    );
}

#[test]
fn a_store_restored_from_its_log_destroys_both_copies_of_a_withdrawn_payload() {
    let Built { r, .. } = built_log();
    let withdrawn: Vec<String> = rusqlite::Connection::open(r.data.path().join("clave.sqlite"))
        .unwrap()
        .prepare("SELECT item_id FROM withdrawals")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!withdrawn.is_empty());
    let copies = |item: &str| {
        [
            clave::db::served_payload_path(r.data.path(), item).unwrap(),
            clave::db::held_payload_path(r.data.path(), item).unwrap(),
        ]
    };
    for item in &withdrawn {
        for path in copies(item) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"{}").unwrap();
        }
    }
    r.db.restore_from_log(r.data.path()).unwrap();
    for item in &withdrawn {
        for path in copies(item) {
            assert!(!path.exists(), "{} survived the restore", path.display());
        }
    }
}
