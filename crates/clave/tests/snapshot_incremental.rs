mod common;

use clave::snapshot::{Mode, Outcome, Phase, SHARD_CACHE_DIRECTORY};

fn shard_index(domain: &str, count: u64) -> u64 {
    wist_core::snapshot::shard_of(domain, std::num::NonZeroU64::new(count).unwrap())
}
use common::{add_label, make_publisher_with_scope, serve_static, write_label_feed, TestPub};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const SEAL_START: i64 = 1_786_276_800;
const DATE: &str = "2026-08-09";
const PRIMARY: &str = "localhost";
const TIER_FILES: [&str; 6] = [
    "tier0/index.sqlite",
    "tier1/extracts.parquet",
    "tier1/links.parquet",
    "tier1/labels.parquet",
    "tier1/disputes.parquet",
    "tier1/labelers.parquet",
];

struct Site {
    publisher: TestPub,
    scope: &'static str,
    ids: Vec<String>,
}

struct Log {
    primary: Site,
    other: Site,
    client: clave::fetch::Client,
    data: tempfile::TempDir,
    db: clave::db::Db,
    shard_count: u64,
    height: i64,
}

fn instant(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

fn other_domain(shard_count: u64) -> String {
    let primary = shard_index(PRIMARY, shard_count.max(2));
    (0..)
        .map(|n| format!("p{n}.localhost"))
        .find(|domain| shard_index(domain, shard_count.max(2)) != primary)
        .unwrap()
}

fn listener() -> std::net::TcpListener {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

impl Log {
    fn new(shard_count: u64) -> Log {
        let other = other_domain(shard_count);
        let (primary_listener, other_listener) = (listener(), listener());
        let client = clave::fetch::Client::with_builder(
            true,
            reqwest::blocking::Client::builder()
                .no_proxy()
                .resolve(PRIMARY, primary_listener.local_addr().unwrap())
                .resolve(&other, other_listener.local_addr().unwrap()),
        );
        let mut sites = Vec::new();
        for (domain, scope) in [(PRIMARY, "example.com"), (other.as_str(), "example.org")] {
            let publisher = make_publisher_with_scope(domain, &[scope]);
            let url = format!("https://subject.example/{scope}/a");
            let ids = vec![add_label(&publisher, &url, "2026-08-09T11:00:00Z")];
            write_label_feed(&publisher, domain, &ids, "2026-08-09T12:00:00Z");
            sites.push(Site {
                publisher,
                scope,
                ids,
            });
        }
        let other_site = sites.pop().unwrap();
        let primary_site = sites.pop().unwrap();
        serve_static(
            primary_listener,
            primary_site.publisher.dir.path().to_path_buf(),
        );
        serve_static(
            other_listener,
            other_site.publisher.dir.path().to_path_buf(),
        );
        let data = tempfile::tempdir().unwrap();
        clave::init::run(PRIMARY, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        db.set_param("epoch_cadence_seconds", 1).unwrap();
        db.set_param("snapshot_shard_count", shard_count as i64)
            .unwrap();
        let log = Log {
            primary: primary_site,
            other: other_site,
            client,
            data,
            db,
            shard_count,
            height: 0,
        };
        log.ingest(PRIMARY);
        log.ingest(&log.other.publisher.domain);
        log
    }

    fn path(&self) -> &Path {
        self.data.path()
    }

    fn other_domain(&self) -> String {
        self.other.publisher.domain.clone()
    }

    fn now(&self) -> String {
        if self.height == 0 {
            "2026-08-09T12:00:00Z".to_string()
        } else {
            instant(SEAL_START + (self.height - 1) * 3600 + 60)
        }
    }

    fn ingest(&self, domain: &str) -> clave::ingest::IngestReport {
        clave::ingest::run(&self.db, &self.client, self.path(), domain, &self.now()).unwrap()
    }

    fn seal(&mut self) -> clave::seal::SealReport {
        let (_, signer) = clave::keys::head_signer(self.path(), &self.db).unwrap();
        let report = clave::seal::run(
            &self.db,
            self.path(),
            &signer,
            SEAL_START + self.height * 3600,
        )
        .unwrap();
        self.height += 1;
        report
    }

    fn site(&mut self, primary: bool) -> &mut Site {
        if primary {
            &mut self.primary
        } else {
            &mut self.other
        }
    }

    fn publish(&mut self, primary: bool, path: &str) -> String {
        let now = self.now();
        let site = self.site(primary);
        let url = format!("https://subject.example/{}/{path}", site.scope);
        let id = add_label(&site.publisher, &url, "2026-08-09T11:00:00Z");
        site.ids.push(id.clone());
        write_label_feed(&site.publisher, &site.publisher.domain, &site.ids, &now);
        let domain = site.publisher.domain.clone();
        assert_eq!(self.ingest(&domain).labels, vec![id.clone()]);
        id
    }

    fn produce(&self, mode: Mode) -> Outcome {
        clave::snapshot::produce_with(
            &self.path().join("clave.sqlite"),
            self.path(),
            mode,
            &mut |_| Ok(()),
        )
        .unwrap()
    }

    fn produce_built(&self, mode: Mode) -> u64 {
        match self.produce(mode) {
            Outcome::Built {
                shards_rebuilt,
                shard_count,
                ..
            } => {
                assert_eq!(shard_count, self.shard_count);
                shards_rebuilt
            }
            other => panic!("no Snapshot built: {other:?}"),
        }
    }

    fn produce_cost(&self, mode: Mode) -> Cost {
        match self.produce(mode) {
            Outcome::Built {
                bytes_written,
                bytes_reused,
                cache_bytes_written,
                payloads_read,
                payload_bytes_read,
                ..
            } => Cost {
                bytes_written,
                bytes_reused,
                cache_bytes_written,
                payloads_read,
                payload_bytes_read,
            },
            other => panic!("no Snapshot built: {other:?}"),
        }
    }

    fn served_shard_bytes(&self, shard: u64) -> u64 {
        TIER_FILES
            .iter()
            .map(|file| file_size(&self.served_file(shard, file)))
            .sum()
    }

    fn served_top_level_bytes(&self) -> u64 {
        ["state.json", "manifest.json"]
            .iter()
            .map(|file| file_size(&self.served_dir().join(file)))
            .sum()
    }

    fn shard_of(&self, domain: &str) -> u64 {
        shard_index(domain, self.shard_count)
    }

    fn cache_entry(&self, shard: u64) -> PathBuf {
        self.path()
            .join(SHARD_CACHE_DIRECTORY)
            .join(shard.to_string())
    }

    fn served_dir(&self) -> PathBuf {
        common::served_snapshot(self.path(), DATE)
    }

    fn served_file(&self, shard: u64, file: &str) -> PathBuf {
        if self.shard_count > 1 {
            self.served_dir().join(format!("shard-{shard}")).join(file)
        } else {
            self.served_dir().join(file)
        }
    }

    fn entry_inodes(&self, shard: u64) -> Vec<u64> {
        TIER_FILES
            .iter()
            .map(|file| inode(&self.cache_entry(shard).join(file)))
            .collect()
    }

    fn served_inodes(&self, shard: u64) -> Vec<u64> {
        TIER_FILES
            .iter()
            .map(|file| inode(&self.served_file(shard, file)))
            .collect()
    }

    fn capture(&self) -> Captured {
        let directory = self.served_dir();
        let manifest = read(&directory.join("manifest.json"));
        let state = read(&directory.join("state.json"));
        let mut files = BTreeMap::new();
        let mut rows = BTreeMap::new();
        for file in manifest["manifest"]["files"].as_array().unwrap() {
            let path = file["path"].as_str().unwrap().to_string();
            let on_disk = directory.join(&path);
            files.insert(path.clone(), std::fs::read(&on_disk).unwrap());
            rows.insert(path.clone(), table_rows(&on_disk));
        }
        Captured {
            manifest,
            state,
            files,
            rows,
        }
    }

    fn full_rebuild(&self) -> Captured {
        std::fs::remove_dir_all(self.path().join("snapshots")).unwrap();
        let _ = std::fs::remove_file(self.path().join("snapshots/index.json"));
        let _ = std::fs::remove_dir_all(self.path().join(SHARD_CACHE_DIRECTORY));
        assert_eq!(self.produce_built(Mode::Full), self.shard_count);
        self.capture()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Cost {
    bytes_written: u64,
    bytes_reused: u64,
    cache_bytes_written: u64,
    payloads_read: u64,
    payload_bytes_read: u64,
}

fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

struct Captured {
    manifest: Value,
    state: Value,
    files: BTreeMap<String, Vec<u8>>,
    rows: BTreeMap<String, Vec<Vec<String>>>,
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn inode(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().ino()
}

fn table_rows(path: &Path) -> Vec<Vec<String>> {
    if path
        .extension()
        .is_some_and(|extension| extension == "sqlite")
    {
        let conn =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let mut statement = conn
            .prepare("SELECT url, publisher, item_id, observed_at, attested_at, title, abstract, lang, collection FROM records ORDER BY rowid")
            .unwrap();
        return statement
            .query_map([], |row| {
                (0..9)
                    .map(|column| {
                        row.get::<_, Option<String>>(column)
                            .map(|value| value.unwrap_or_else(|| "NULL".into()))
                    })
                    .collect::<rusqlite::Result<Vec<String>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<Vec<String>>>>()
            .unwrap();
    }
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let reader = SerializedFileReader::new(std::fs::File::open(path).unwrap()).unwrap();
    reader
        .get_row_iter(None)
        .unwrap()
        .map(|row| {
            row.unwrap()
                .get_column_iter()
                .map(|(_, value)| format!("{value}"))
                .collect()
        })
        .collect()
}

fn assert_same_snapshot(a: &Captured, b: &Captured) {
    let signed_over = |captured: &Captured| {
        let mut manifest = captured.manifest["manifest"].clone();
        let state = manifest["state"].as_object_mut().unwrap();
        state.remove("sha256");
        state.remove("bytes");
        manifest
    };
    assert_eq!(signed_over(a), signed_over(b));
    assert_eq!(
        a.manifest["manifest"]["state"]["state_digest"],
        b.manifest["manifest"]["state"]["state_digest"]
    );
    assert_eq!(a.state["state"]["tree_size"], b.state["state"]["tree_size"]);
    assert_eq!(a.rows, b.rows);
    assert_eq!(a.files, b.files);
}

fn walk(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, found);
        } else {
            found.push(path);
        }
    }
}

fn cache_bytes(log: &Log) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = Vec::new();
    walk(&log.path().join(SHARD_CACHE_DIRECTORY), &mut found);
    found
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

fn built_log(shard_count: u64) -> Log {
    let mut log = Log::new(shard_count);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), shard_count);
    log
}

#[test]
fn an_empty_epoch_reuses_every_shard_and_matches_a_full_rebuild() {
    let mut log = built_log(2);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 0);
    for shard in 0..2 {
        assert_eq!(log.served_inodes(shard), log.entry_inodes(shard));
    }
    let incremental = log.capture();
    assert_eq!(incremental.manifest["manifest"]["epoch_number"], 1);
    assert_same_snapshot(&incremental, &log.full_rebuild());
}

fn publish_label(site: &Site, subject: &str, at: &str) -> String {
    let domain = &site.publisher.domain;
    let inner = json!({"wist_version": "1.0.0", "labeler": domain, "subject": subject,
        "name": "wist:spam", "value": 500_000, "asserted_at": at});
    let id = wist_core::label::label_id(&inner).unwrap();
    let envelope = wist_core::envelope::sign_envelope(
        &inner,
        "label",
        &site.publisher.kid,
        &site.publisher.sk,
    )
    .unwrap();
    let directory = site.publisher.dir.path().join(".well-known/wist/labels");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join(format!("{}.json", &id[7..])),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    let feed = json!({"wist_version": "1.0.0", "domain": domain, "generated_at": at,
        "deltas": [id], "next": null});
    let feed =
        wist_core::envelope::sign_envelope(&feed, "feed", &site.publisher.kid, &site.publisher.sk)
            .unwrap();
    std::fs::write(
        site.publisher
            .dir
            .path()
            .join(".well-known/wist/label-feed.json"),
        serde_json::to_vec(&feed).unwrap(),
    )
    .unwrap();
    id
}

#[test]
fn a_sealed_label_rebuilds_only_its_labelers_shard() {
    let mut log = built_log(2);
    let changed = log.shard_of(&log.other_domain());
    let kept = log.shard_of(PRIMARY);
    let kept_before = log.entry_inodes(kept);
    let id = publish_label(&log.other, "https://reduced.example.org/notice", &log.now());
    assert_eq!(log.ingest(&log.other_domain()).labels, vec![id]);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 1);
    assert_eq!(log.served_inodes(kept), kept_before);
    let incremental = log.capture();
    assert_eq!(
        incremental.rows[&format!("shard-{changed}/tier1/labels.parquet")].len(),
        2
    );
    assert_eq!(
        incremental.rows[&format!("shard-{changed}/tier1/labelers.parquet")].len(),
        1
    );
    assert_same_snapshot(&incremental, &log.full_rebuild());
}

#[test]
fn an_aggregator_key_addition_reuses_every_shard_and_changes_only_the_state() {
    let mut log = built_log(2);
    let before = log.capture();
    let inodes: Vec<Vec<u64>> = (0..2).map(|shard| log.entry_inodes(shard)).collect();
    clave::log_key::add(&log.db, log.path(), SEAL_START + 60).unwrap();
    assert_eq!(log.seal().entry_count, 1);
    assert_eq!(log.produce_built(Mode::Incremental), 0);
    for (shard, inodes) in inodes.iter().enumerate() {
        assert_eq!(&log.served_inodes(shard as u64), inodes);
    }
    let incremental = log.capture();
    assert_ne!(
        incremental.manifest["manifest"]["state"]["state_digest"],
        before.manifest["manifest"]["state"]["state_digest"]
    );
    assert_eq!(incremental.files, before.files);
    assert_same_snapshot(&incremental, &log.full_rebuild());
}

#[test]
fn a_build_interrupted_between_shards_leaves_the_cache_unchanged() {
    let mut log = built_log(2);
    let cached = cache_bytes(&log);
    log.publish(true, "b");
    log.publish(false, "b");
    log.seal();
    let crashed = clave::snapshot::produce_with(
        &log.path().join("clave.sqlite"),
        log.path(),
        Mode::Incremental,
        &mut |phase| {
            if phase == Phase::ShardWritten(0) {
                Err(clave::Error::Snapshot("crashed between shards".into()))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
    assert_eq!(cache_bytes(&log), cached);

    assert_eq!(log.produce_built(Mode::Incremental), 2);
    let incremental = log.capture();
    assert_same_snapshot(&incremental, &log.full_rebuild());
}

#[test]
fn a_cache_entry_with_a_truncated_or_missing_file_is_not_reused() {
    let mut log = built_log(2);
    let truncated = std::fs::OpenOptions::new()
        .write(true)
        .open(log.cache_entry(0).join("tier1/extracts.parquet"))
        .unwrap();
    truncated.set_len(4).unwrap();
    drop(truncated);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 1);
    assert_same_snapshot(&log.capture(), &log.full_rebuild());

    std::fs::remove_file(log.cache_entry(1).join("tier0/index.sqlite")).unwrap();
    let reused = log.entry_inodes(0);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 1);
    assert_eq!(log.served_inodes(0), reused);
    assert_same_snapshot(&log.capture(), &log.full_rebuild());
}

#[test]
fn a_cache_entry_with_a_same_length_corrupted_file_is_not_reused() {
    let mut log = built_log(2);
    let damaged = log.cache_entry(0).join("tier1/links.parquet");
    let mut bytes = std::fs::read(&damaged).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&damaged, &bytes).unwrap();
    let reused = log.entry_inodes(1);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 1);
    assert_eq!(log.served_inodes(1), reused);
    let captured = log.capture();
    for file in captured.manifest["manifest"]["files"].as_array().unwrap() {
        let path = file["path"].as_str().unwrap();
        let digest = wist_core::crypto::hex_encode(&sha2::Sha256::digest(&captured.files[path]));
        assert_eq!(file["sha256"].as_str().unwrap(), digest, "{path}");
    }
    assert_same_snapshot(&captured, &log.full_rebuild());
}

#[test]
fn a_full_rebuild_at_a_served_head_builds_nothing() {
    let log = built_log(2);
    let served = common::tree_bytes(&log.path().join("snapshots"));
    let entries: Vec<Vec<u64>> = (0..2).map(|shard| log.entry_inodes(shard)).collect();
    let head = log.db.last_epoch().unwrap().unwrap().epoch_number;
    assert_eq!(
        log.produce(Mode::Full),
        Outcome::Current { epoch_number: head }
    );
    for (shard, before) in entries.iter().enumerate() {
        assert_eq!(&log.entry_inodes(shard as u64), before);
    }
    assert_eq!(common::tree_bytes(&log.path().join("snapshots")), served);
}

#[test]
fn a_full_rebuild_of_a_new_empty_epoch_rebuilds_every_shard_and_matches() {
    let mut log = built_log(2);
    log.seal();
    let entries: Vec<Vec<u64>> = (0..2).map(|shard| log.entry_inodes(shard)).collect();
    assert_eq!(log.produce_built(Mode::Full), 2);
    for (shard, before) in entries.iter().enumerate() {
        assert_ne!(&log.entry_inodes(shard as u64), before);
    }
    let full = log.capture();
    assert_same_snapshot(&full, &log.full_rebuild());
}

#[test]
fn an_unsharded_empty_epoch_reuses_the_single_shard() {
    let mut log = built_log(1);
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 0);
    assert_eq!(log.served_inodes(0), log.entry_inodes(0));
    assert!(log.served_dir().join("tier0/index.sqlite").exists());
    let incremental = log.capture();
    assert_same_snapshot(&incremental, &log.full_rebuild());
}

#[test]
fn a_changed_shard_count_rebuilds_every_shard_and_drops_surplus_entries() {
    let mut log = built_log(2);
    log.db.set_param("snapshot_shard_count", 1).unwrap();
    log.shard_count = 1;
    log.seal();
    assert_eq!(log.produce_built(Mode::Incremental), 1);
    assert!(log.cache_entry(0).exists());
    assert!(!log.cache_entry(1).exists());
    assert_same_snapshot(&log.capture(), &log.full_rebuild());
}

#[test]
fn reconciliation_removes_unfinished_cache_entries_and_keeps_complete_ones() {
    let log = built_log(2);
    let unfinished = log.path().join(SHARD_CACHE_DIRECTORY).join("0.new");
    std::fs::create_dir_all(unfinished.join("tier0")).unwrap();
    std::fs::write(unfinished.join("tier0/index.sqlite"), b"partial").unwrap();
    let complete = cache_bytes(&log)
        .into_iter()
        .filter(|(path, _)| !path.starts_with(&unfinished))
        .collect::<BTreeMap<_, _>>();
    clave::snapshot::reconcile(&log.db, log.path()).unwrap();
    assert!(!unfinished.exists());
    assert_eq!(cache_bytes(&log), complete);
}

#[test]
fn an_empty_epoch_build_reads_no_payloads_and_writes_only_state_and_manifest() {
    let mut log = built_log(2);
    log.seal();
    let cost = log.produce_cost(Mode::Incremental);
    assert_eq!(
        cost,
        Cost {
            bytes_written: log.served_top_level_bytes(),
            bytes_reused: log.served_shard_bytes(0) + log.served_shard_bytes(1),
            cache_bytes_written: 0,
            payloads_read: 0,
            payload_bytes_read: 0,
        }
    );
}
