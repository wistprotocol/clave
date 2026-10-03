mod common;

use clave::snapshot::{Outcome, Phase};
use common::{add_label, make_publisher_with_scope, reserve_addr, serve_static, write_label_feed};
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
            .map(|url| {
                add_label(
                    &publisher,
                    &url.replace("example.com", "other.example"),
                    "2026-08-09T11:00:00Z",
                )
            })
            .collect();
        write_label_feed(&publisher, &host, &ids, "2026-08-09T12:00:00Z");
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
        clave::snapshot::produce_with(
            &self.db_path(),
            self.path(),
            clave::snapshot::Mode::Incremental,
            observe,
        )
    }

    fn publish(&mut self, url: &str, generated_at: &str) -> String {
        let id = add_label(
            &self.publisher,
            &url.replace("example.com", "other.example"),
            "2026-08-09T11:00:00Z",
        );
        self.ids.push(id.clone());
        write_label_feed(&self.publisher, &self.host, &self.ids, generated_at);
        id
    }

    fn pull(&self, db: &clave::db::Db, at: &str) -> clave::ingest::IngestReport {
        clave::ingest::run(db, &self.client, self.path(), &self.host, at).unwrap()
    }

    fn listed(&self) -> Vec<Value> {
        read(&self.path().join("snapshots/index.json"))["index"]["snapshots"]
            .as_array()
            .unwrap()
            .clone()
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
    let manifest = read(
        &log.path()
            .join(format!("snapshots/{DATE}/000000001/manifest.json")),
    );
    assert_eq!(manifest["manifest"]["epoch_number"], 1);
    assert_eq!(log.listed(), vec![old.clone()]);
    assert_ne!(old["tree_size"], manifest["manifest"]["tree_size"]);

    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    let listed = log.listed();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["tree_size"], manifest["manifest"]["tree_size"]);
    assert_eq!(
        listed[0]["content_digest"],
        manifest["manifest"]["content_digest"]
    );
    assert_eq!(
        listed[0]["manifest_url"],
        format!("/snapshots/{DATE}/000000001/manifest.json")
    );
    assert_eq!(listed[1], old);
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

fn listed_urls(log: &Log) -> Vec<String> {
    log.listed()
        .iter()
        .map(|entry| entry["manifest_url"].as_str().unwrap().to_string())
        .collect()
}

fn superseded_marker(log: &Log, date: &str, epoch: &str) -> PathBuf {
    log.path()
        .join(clave::snapshot::SUPERSEDED_DIRECTORY)
        .join(date)
        .join(epoch)
}

fn backdate_marker(log: &Log, date: &str, epoch: &str, seconds: i64) {
    let marker = superseded_marker(log, date, epoch);
    let at: jiff::Timestamp = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let earlier = jiff::Timestamp::from_second(at.as_second() - seconds).unwrap();
    std::fs::write(&marker, earlier.to_string()).unwrap();
}

#[test]
fn a_same_date_seal_serves_a_second_directory_and_keeps_the_first_byte_identical() {
    let mut log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    let first = log.path().join(format!("snapshots/{DATE}/000000000"));
    let first_files = common::tree_bytes(&first);

    log.publish("https://example.com/b", "2026-08-09T12:00:10Z");
    log.pull(&log.db, "2026-08-09T12:00:10Z");
    log.seal(SEAL_START + 3600);
    assert!(matches!(
        log.produce().unwrap(),
        Outcome::Built {
            epoch_number: 1,
            ..
        }
    ));
    assert_eq!(common::tree_bytes(&first), first_files);
    assert!(log
        .path()
        .join(format!("snapshots/{DATE}/000000001/manifest.json"))
        .exists());
    assert_eq!(
        listed_urls(&log),
        vec![
            format!("/snapshots/{DATE}/000000001/manifest.json"),
            format!("/snapshots/{DATE}/000000000/manifest.json"),
        ]
    );
}

#[test]
fn a_superseded_same_date_snapshot_is_unlisted_then_removed_after_the_grace_period() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    log.seal(SEAL_START + 3600);
    log.produce().unwrap();
    let old = log.path().join(format!("snapshots/{DATE}/000000000"));
    assert!(superseded_marker(&log, DATE, "000000000").exists());
    assert!(!superseded_marker(&log, DATE, "000000001").exists());

    backdate_marker(
        &log,
        DATE,
        "000000000",
        clave::snapshot::SUPERSEDED_GRACE_SECONDS - 3600,
    );
    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    assert_eq!(listed_urls(&log).len(), 2);
    assert!(old.exists());

    backdate_marker(&log, DATE, "000000000", 3600);
    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    assert_eq!(
        listed_urls(&log),
        vec![format!("/snapshots/{DATE}/000000001/manifest.json")]
    );
    assert!(!old.exists());
    assert!(!superseded_marker(&log, DATE, "000000000").exists());
    assert_eq!(log.produce().unwrap(), Outcome::Current { epoch_number: 1 });
}

#[test]
fn only_a_same_date_successor_starts_a_grace_period_and_the_index_is_newest_first() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    log.seal(SEAL_START + 3600);
    log.produce().unwrap();
    log.seal(SEAL_START + DAY);
    log.produce().unwrap();
    assert_eq!(
        listed_urls(&log),
        vec![
            "/snapshots/2026-08-10/000000002/manifest.json".to_string(),
            format!("/snapshots/{DATE}/000000001/manifest.json"),
            format!("/snapshots/{DATE}/000000000/manifest.json"),
        ]
    );
    assert!(!superseded_marker(&log, DATE, "000000001").exists());
    assert!(!superseded_marker(&log, "2026-08-10", "000000002").exists());

    backdate_marker(
        &log,
        DATE,
        "000000000",
        clave::snapshot::SUPERSEDED_GRACE_SECONDS,
    );
    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    assert_eq!(
        listed_urls(&log),
        vec![
            "/snapshots/2026-08-10/000000002/manifest.json".to_string(),
            format!("/snapshots/{DATE}/000000001/manifest.json"),
        ]
    );
}

#[test]
fn reconciliation_removes_a_directory_whose_name_does_not_match_its_manifest() {
    let log = Log::new(&["https://example.com/a"]);
    log.seal(SEAL_START);
    log.produce().unwrap();
    let served = log.path().join(format!("snapshots/{DATE}/000000000"));
    let misnamed_epoch = log.path().join(format!("snapshots/{DATE}/000000007"));
    let misnamed_date = log.path().join("snapshots/2026-08-10/000000000");
    for copy in [&misnamed_epoch, &misnamed_date] {
        std::fs::create_dir_all(copy).unwrap();
        for file in ["manifest.json", "state.json"] {
            std::fs::copy(served.join(file), copy.join(file)).unwrap();
        }
    }
    let unpadded = log.path().join(format!("snapshots/{DATE}/0"));
    std::fs::create_dir_all(&unpadded).unwrap();
    std::fs::copy(served.join("manifest.json"), unpadded.join("manifest.json")).unwrap();

    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    assert!(!misnamed_epoch.exists());
    assert!(!misnamed_date.exists());
    assert!(!log.path().join("snapshots/2026-08-10").exists());
    assert!(!unpadded.exists());
    assert!(served.join("manifest.json").exists());
    assert_eq!(
        listed_urls(&log),
        vec![format!("/snapshots/{DATE}/000000000/manifest.json")]
    );
}
