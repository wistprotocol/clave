mod common;

use clave::snapshot::{Outcome, Phase};
use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SEAL_START: i64 = 1_786_276_800;
const DAY: i64 = 86_400;
const DATE: &str = "2026-08-09";

struct Log {
    publisher: common::TestPub,
    host: String,
    client: clave::fetch::Client,
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: wist_core::crypto::SigningKey,
    ids: Vec<String>,
}

impl Log {
    fn new(urls: &[&str]) -> Log {
        let (listener, host, client) = reserve_addr();
        let publisher = make_publisher_with_scope(&host, &["example.com"]);
        let ids: Vec<String> = urls
            .iter()
            .map(|url| add_delta(&publisher, url, &format!("body of {url}"), None))
            .collect();
        write_feed(&publisher, &host, &ids, "2026-08-09T12:00:00Z");
        serve_static(listener, publisher.dir.path().to_path_buf());
        let data = tempfile::tempdir().unwrap();
        clave::init::run(&host, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        db.set_param("epoch_cadence_seconds", 1).unwrap();
        clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
        let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
        Log {
            publisher,
            host,
            client,
            data,
            db,
            sk,
            ids,
        }
    }

    fn path(&self) -> &Path {
        self.data.path()
    }

    fn db_path(&self) -> PathBuf {
        self.path().join("clave.sqlite")
    }

    fn seal_on(&self, db: &clave::db::Db, at: i64) -> u64 {
        clave::seal::run(db, self.path(), &self.sk, at)
            .unwrap()
            .epoch_number
    }

    fn seal(&self, at: i64) -> u64 {
        self.seal_on(&self.db, at)
    }

    fn produce(&self) -> clave::error::Result<Outcome> {
        clave::snapshot::produce(&self.db_path(), self.path())
    }

    fn produce_with(
        &self,
        observe: &mut dyn FnMut(Phase) -> clave::error::Result<()>,
    ) -> clave::error::Result<Outcome> {
        clave::snapshot::produce_with(&self.db_path(), self.path(), observe)
    }

    fn publish(&mut self, url: &str, generated_at: &str) -> String {
        let id = add_delta(&self.publisher, url, &format!("body of {url}"), None);
        self.ids.push(id.clone());
        write_feed(&self.publisher, &self.host, &self.ids, generated_at);
        id
    }

    fn pull(&self, db: &clave::db::Db, at: &str) -> clave::ingest::IngestReport {
        clave::ingest::run(db, &self.client, self.path(), &self.host, at).unwrap()
    }

    fn connection(&self) -> clave::db::Db {
        clave::db::Db::connect(&self.db_path()).unwrap()
    }

    fn manifest(&self, date: &str) -> Value {
        read(&self.path().join(format!("snapshots/{date}/manifest.json")))
    }

    fn listed(&self) -> Vec<Value> {
        read(&self.path().join("snapshots/index.json"))["index"]["snapshots"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn records_digest(&self) -> String {
        let projection: Vec<Value> = self
            .db
            .list_records()
            .unwrap()
            .iter()
            .map(|r| {
                serde_json::json!({
                    "url": r.url,
                    "publisher": r.publisher,
                    "delta_id": r.delta_id,
                    "observed_at": r.observed_at,
                })
            })
            .collect();
        wist_core::snapshot::content_digest(&projection).unwrap()
    }

    fn staged(&self) -> Vec<String> {
        entries(&self.path().join(clave::snapshot::STAGING_DIRECTORY))
    }

    fn served_directories(&self) -> Vec<String> {
        let snapshots = self.path().join("snapshots");
        entries(&snapshots)
            .into_iter()
            .filter(|name| snapshots.join(name).is_dir())
            .collect()
    }
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn entries(directory: &Path) -> Vec<String> {
    let Ok(listing) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut names: Vec<String> = listing
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn file_bytes(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(file_bytes(&path));
        } else {
            files.insert(path.clone(), std::fs::read(&path).unwrap());
        }
    }
    files
}

fn crash_at(at: Phase) -> impl FnMut(Phase) -> clave::error::Result<()> {
    move |phase| {
        if phase == at {
            Err(clave::Error::Snapshot(format!("crashed at {phase:?}")))
        } else {
            Ok(())
        }
    }
}

fn tier0_urls(path: &Path) -> Vec<String> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = conn
        .prepare("SELECT url FROM records ORDER BY url")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<String>>>()
        .unwrap()
}

#[test]
fn production_reports_an_unsealed_log_and_a_current_snapshot() {
    let log = Log::new(&["https://example.com/a"]);
    assert_eq!(log.produce().unwrap(), Outcome::Unsealed);
    assert!(log.served_directories().is_empty());
    log.seal(SEAL_START);
    assert!(matches!(
        log.produce().unwrap(),
        Outcome::Built {
            epoch_number: 0,
            ..
        }
    ));
    assert_eq!(log.produce().unwrap(), Outcome::Current { epoch_number: 0 });
}

#[test]
fn a_seal_committed_while_files_are_written_leaves_the_manifest_at_the_read_height() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    let read_digest = log.records_digest();
    let read_head = log.db.epoch_at(0).unwrap().unwrap();

    let outcome = log
        .produce_with(&mut |phase| {
            if phase == Phase::FilesWritten {
                let db = log.connection();
                let id = add_delta(&log.publisher, "https://example.com/b", "b body", None);
                write_feed(
                    &log.publisher,
                    &log.host,
                    &[log.ids[0].clone(), id],
                    "2026-08-09T12:00:10Z",
                );
                assert_eq!(log.pull(&db, "2026-08-09T12:00:10Z").accepted.len(), 1);
                assert_eq!(log.seal_on(&db, SEAL_START + 3600), 1);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        outcome,
        Outcome::Built {
            epoch_number: 0,
            tree_size: read_head.tree_size,
            snapshot_date: DATE.to_string(),
        }
    );
    let manifest = log.manifest(DATE);
    assert_eq!(manifest["manifest"]["epoch_number"], 0);
    assert_eq!(manifest["manifest"]["tree_size"], read_head.tree_size);
    assert_eq!(manifest["manifest"]["root_hash"], read_head.root);
    assert_eq!(manifest["manifest"]["content_digest"], read_digest);
    assert_ne!(log.records_digest(), read_digest);
    let listed = log.listed();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["tree_size"], read_head.tree_size);

    let head = log.db.last_epoch().unwrap().unwrap();
    assert_eq!(
        log.produce().unwrap(),
        Outcome::Built {
            epoch_number: 1,
            tree_size: head.tree_size,
            snapshot_date: DATE.to_string(),
        }
    );
    assert_eq!(
        log.manifest(DATE)["manifest"]["content_digest"],
        log.records_digest()
    );
}

#[test]
fn a_withdrawal_sealed_while_files_are_written_supersedes_the_build() {
    let log = Log::new(&["https://example.com/a", "https://example.com/b"]);
    log.seal(SEAL_START);
    let doomed = log.ids[1].clone();

    let outcome = log
        .produce_with(&mut |phase| {
            if phase == Phase::FilesWritten {
                let db = log.connection();
                clave::governance::withdraw(
                    &db,
                    &log.sk,
                    &log.host,
                    &doomed,
                    "court order",
                    "DE",
                    SEAL_START + 1,
                )
                .unwrap();
                assert_eq!(log.seal_on(&db, SEAL_START + 3600), 1);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        outcome,
        Outcome::Superseded {
            built: 0,
            withdrawal_height: 1,
        }
    );
    assert!(log.staged().is_empty(), "{:?}", log.staged());
    assert!(log.served_directories().is_empty());
    assert!(log.listed().is_empty());

    assert!(matches!(
        log.produce().unwrap(),
        Outcome::Built {
            epoch_number: 1,
            ..
        }
    ));
    let manifest = log.manifest(DATE);
    assert_eq!(manifest["manifest"]["content_digest"], log.records_digest());
    assert_eq!(
        tier0_urls(
            &log.path()
                .join(format!("snapshots/{DATE}/tier0/index.sqlite"))
        ),
        vec!["https://example.com/a".to_string()]
    );
}

#[test]
fn a_crash_after_the_swap_leaves_the_old_index_entry_until_reconciled() {
    let mut log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    let old = log.listed()[0].clone();

    log.publish("https://example.com/b", "2026-08-09T12:00:10Z");
    log.pull(&log.db, "2026-08-09T12:00:10Z");
    log.seal(SEAL_START + 3600);
    let crashed = log.produce_with(&mut crash_at(Phase::Swapped));
    assert!(crashed.is_err());
    let manifest = log.manifest(DATE);
    assert_eq!(manifest["manifest"]["epoch_number"], 1);
    assert_eq!(log.listed(), vec![old.clone()]);
    assert_ne!(old["tree_size"], manifest["manifest"]["tree_size"]);

    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    let listed = log.listed();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["tree_size"], manifest["manifest"]["tree_size"]);
    assert_eq!(
        listed[0]["content_digest"],
        manifest["manifest"]["content_digest"]
    );
    assert_eq!(
        listed[0]["manifest_url"],
        format!("/snapshots/{DATE}/manifest.json")
    );
    assert_eq!(log.produce().unwrap(), Outcome::Current { epoch_number: 1 });
}

#[test]
fn a_crash_after_files_are_written_leaves_the_served_snapshot_unchanged() {
    let mut log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    let served = file_bytes(&log.path().join("snapshots"));

    log.publish("https://example.com/b", "2026-08-09T12:00:10Z");
    log.pull(&log.db, "2026-08-09T12:00:10Z");
    log.seal(SEAL_START + 3600);
    assert!(log
        .produce_with(&mut crash_at(Phase::FilesWritten))
        .is_err());
    assert_eq!(log.staged(), vec!["1".to_string()]);
    assert_eq!(file_bytes(&log.path().join("snapshots")), served);

    log.seal(SEAL_START + 7200);
    assert!(matches!(
        log.produce().unwrap(),
        Outcome::Built {
            epoch_number: 2,
            ..
        }
    ));
    assert!(log.staged().is_empty(), "{:?}", log.staged());
}

#[test]
fn the_staging_area_lies_outside_the_served_snapshot_tree() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    assert!(log
        .produce_with(&mut crash_at(Phase::FilesWritten))
        .is_err());
    let staged = log
        .path()
        .join(clave::snapshot::STAGING_DIRECTORY)
        .join("0");
    assert!(staged.join("manifest.json").exists());
    assert!(!staged.starts_with(log.path().join("snapshots")));
    assert!(log.served_directories().is_empty());
}

#[test]
fn a_pull_committing_during_the_read_succeeds_and_the_build_keeps_the_read_head() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    let read_digest = log.records_digest();
    let mut accepted = Vec::new();

    let outcome = log
        .produce_with(&mut |phase| {
            if phase == Phase::Reading {
                let db = log.connection();
                let id = add_delta(&log.publisher, "https://example.com/b", "b body", None);
                write_feed(
                    &log.publisher,
                    &log.host,
                    &[log.ids[0].clone(), id],
                    "2026-08-09T12:00:10Z",
                );
                accepted = log.pull(&db, "2026-08-09T12:00:10Z").accepted;
                log.seal_on(&db, SEAL_START + 3600);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(accepted.len(), 1);
    assert!(matches!(
        outcome,
        Outcome::Built {
            epoch_number: 0,
            ..
        }
    ));
    assert_eq!(log.manifest(DATE)["manifest"]["epoch_number"], 0);
    assert_eq!(
        log.manifest(DATE)["manifest"]["content_digest"],
        read_digest
    );
}

#[test]
fn a_withdrawal_seal_removes_every_wiped_date_from_the_index() {
    let log = Log::new(&["https://example.com/a", "https://example.com/b"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    log.seal(SEAL_START + DAY);
    log.produce().unwrap();
    let dates: Vec<Value> = log
        .listed()
        .iter()
        .map(|entry| entry["snapshot_date"].clone())
        .collect();
    assert_eq!(dates, vec!["2026-08-10", DATE]);

    clave::governance::withdraw(
        &log.db,
        &log.sk,
        &log.host,
        &log.ids[1],
        "court order",
        "DE",
        SEAL_START + DAY + 1,
    )
    .unwrap();
    log.seal(SEAL_START + DAY + 3600);
    assert!(log.listed().is_empty());
    assert!(log.served_directories().is_empty());
    wist_core::envelope::verify_envelope(
        &read(&log.path().join("snapshots/index.json")),
        "index",
        &log.sk.public(),
    )
    .unwrap();
}

#[test]
fn a_live_record_without_its_payload_fails_the_build_naming_the_delta() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    let id = &log.ids[0];
    std::fs::remove_file(
        log.path()
            .join("payloads")
            .join(format!("{}.json", id.strip_prefix("sha256:").unwrap())),
    )
    .unwrap();
    let error = log.produce().unwrap_err().to_string();
    assert!(error.contains(id), "{error}");
    assert!(log.served_directories().is_empty());
    assert!(!log.path().join("snapshots/index.json").exists());
}

#[test]
fn a_second_producer_is_refused_while_the_first_holds_the_lock() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    let mut refusal = None;
    log.produce_with(&mut |phase| {
        if phase == Phase::Read {
            refusal = Some(log.produce());
        }
        Ok(())
    })
    .unwrap();
    let Some(Err(error)) = refusal else {
        panic!("a second producer ran beside the first");
    };
    assert!(
        error
            .to_string()
            .contains("another Snapshot producer holds"),
        "{error}"
    );
}
