mod common;

use common::{list_signed_mirrors, loopback_client, serve_not_found, serve_recording, tree_bytes};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wist_core::checkpoint::Checkpoint;
use wist_core::crypto::SigningKey;

const SEAL_START: i64 = 1_786_276_800;
const LOG_ID: &str = "log.example.test";

struct Log {
    data: tempfile::TempDir,
    db: Option<clave::db::Db>,
    client: clave::fetch::Client,
}

impl Log {
    fn new() -> Self {
        let data = tempfile::tempdir().unwrap();
        clave::init::run(LOG_ID, data.path()).unwrap();
        let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
        db.set_param("epoch_cadence_seconds", 3600).unwrap();
        let client = loopback_client();
        Log {
            data,
            db: Some(db),
            client,
        }
    }

    fn path(&self) -> &Path {
        self.data.path()
    }

    fn db(&self) -> &clave::db::Db {
        self.db.as_ref().unwrap()
    }

    fn try_seal(&self, height: i64) -> clave::error::Result<clave::seal::SealReport> {
        let (_, signer) = clave::keys::head_signer(self.path(), self.db()).unwrap();
        clave::seal::run_with_client(
            self.db(),
            self.path(),
            &signer,
            &self.client,
            SEAL_START + height * 3600,
        )
    }

    fn seal(&self, height: i64) -> clave::seal::SealReport {
        self.try_seal(height).unwrap()
    }

    fn store_path(&self) -> PathBuf {
        self.path().join("clave.sqlite")
    }

    fn back_up(&self) -> tempfile::NamedTempFile {
        let backup = tempfile::NamedTempFile::new().unwrap();
        std::fs::remove_file(backup.path()).unwrap();
        rusqlite::Connection::open(self.store_path())
            .unwrap()
            .execute("VACUUM INTO ?1", [backup.path().to_str().unwrap()])
            .unwrap();
        backup
    }

    fn restore(&mut self, backup: &tempfile::NamedTempFile) {
        self.db = None;
        let store = self.store_path();
        for side in ["-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{side}", store.display()));
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
        std::fs::copy(backup.path(), &store).unwrap();
        self.db = Some(clave::db::Db::open(&store).unwrap());
    }

    fn head_epoch(&self) -> Option<u64> {
        self.db()
            .last_epoch()
            .unwrap()
            .map(|epoch| epoch.epoch_number)
    }

    fn published(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = tree_bytes(&self.path().join("log"));
        if self.path().join("tile").exists() {
            files.extend(
                tree_bytes(&self.path().join("tile"))
                    .into_iter()
                    .map(|(path, bytes)| (Path::new("tile").join(path), bytes)),
            );
        }
        files.insert(
            PathBuf::from("checkpoint"),
            std::fs::read(self.path().join("checkpoint")).unwrap_or_default(),
        );
        files
    }

    fn archive(&self, epoch_number: u64) -> PathBuf {
        clave::publication::archive_path(self.path(), epoch_number)
    }

    fn signer(&self) -> SigningKey {
        clave::keys::load(&self.path().join("keys/seed")).unwrap()
    }

    fn list_mirrors(&self, urls: &[String]) {
        let (key_id, signer) = clave::keys::head_signer(self.path(), self.db()).unwrap();
        list_signed_mirrors(self.path(), &key_id, &signer, urls, SEAL_START);
    }
}

fn forged(origin: &str, epoch_number: u64, root: [u8; 32], key: &SigningKey) -> String {
    let mut checkpoint =
        Checkpoint::new(origin, 1, root, epoch_number, "2026-08-09T12:00:00Z").unwrap();
    checkpoint.sign(key);
    checkpoint.encode()
}

fn refused_as_ahead(
    result: clave::error::Result<impl Sized>,
) -> (String, u64, Option<u64>, String) {
    match result {
        Err(error @ clave::error::Error::PublishedAhead { .. }) => {
            let message = error.to_string();
            let clave::error::Error::PublishedAhead {
                holder,
                published,
                store_head,
            } = error
            else {
                unreachable!()
            };
            (holder, published, store_head, message)
        }
        Err(error) => panic!("refused for another reason: {error}"),
        Ok(_) => panic!("not refused"),
    }
}

fn mirror() -> (String, PathBuf, tempfile::TempDir) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    serve_recording(listener, directory.path().to_path_buf());
    (url, directory.path().to_path_buf(), directory)
}

#[test]
fn a_store_restored_one_epoch_behind_its_published_directory_is_refused_and_changes_nothing() {
    let mut log = Log::new();
    log.seal(0);
    let backup = log.back_up();
    log.seal(1);
    log.restore(&backup);
    let before = log.published();

    let (holder, published, store_head, message) = refused_as_ahead(log.try_seal(2));

    assert_eq!((published, store_head), (1, Some(0)));
    assert_eq!(holder, log.archive(1).display().to_string());
    assert!(message.contains("Epoch 1"), "{message}");
    assert!(message.contains(&holder), "{message}");
    assert_eq!(log.published(), before);
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn a_store_restored_at_its_published_height_seals() {
    let mut log = Log::new();
    log.seal(0);
    let backup = log.back_up();
    log.restore(&backup);

    assert_eq!(log.seal(1).epoch_number, 1);
    assert_eq!(common::head_checkpoint(log.path()).epoch_number(), 1);
}

#[test]
fn a_published_directory_one_epoch_behind_the_store_is_repaired() {
    let log = Log::new();
    log.seal(0);
    let previous = std::fs::read(log.path().join("checkpoint")).unwrap();
    log.seal(1);
    let expected = log.published();
    std::fs::write(log.path().join("checkpoint"), &previous).unwrap();
    std::fs::remove_file(log.archive(1)).unwrap();

    assert_eq!(
        clave::publication::recover(log.db(), log.path()).unwrap(),
        vec![1]
    );
    assert_eq!(log.published(), expected);
    assert_eq!(log.seal(2).epoch_number, 2);
}

#[test]
fn a_store_without_an_epoch_beside_a_published_epoch_zero_is_refused() {
    let mut log = Log::new();
    let backup = log.back_up();
    log.seal(0);
    log.restore(&backup);
    let before = log.published();

    let (_, published, store_head, message) = refused_as_ahead(log.try_seal(1));

    assert_eq!((published, store_head), (0, None));
    assert!(message.contains("no Epoch"), "{message}");
    assert_eq!(log.published(), before);
    assert_eq!(log.head_epoch(), None);
}

#[test]
fn a_published_checkpoint_at_the_store_head_stating_a_different_tree_is_refused() {
    for published_as in ["checkpoint", "archive"] {
        let log = Log::new();
        log.seal(0);
        let path = match published_as {
            "checkpoint" => clave::publication::head_path(log.path()),
            _ => log.archive(0),
        };
        std::fs::write(&path, forged(LOG_ID, 0, [7u8; 32], &log.signer())).unwrap();
        let before = log.published();

        let (holder, published, store_head, _) = refused_as_ahead(log.try_seal(1));

        assert_eq!(holder, path.display().to_string(), "{published_as}");
        assert_eq!((published, store_head), (0, Some(0)), "{published_as}");
        assert_eq!(log.published(), before, "{published_as}");
        assert_eq!(log.head_epoch(), Some(0), "{published_as}");
    }
}

#[test]
fn a_published_checkpoint_above_the_store_head_is_refused_under_a_key_the_store_does_not_hold() {
    let log = Log::new();
    log.seal(0);
    let unknown = SigningKey::from_seed(&[42u8; 32]);
    std::fs::write(
        clave::publication::head_path(log.path()),
        forged(LOG_ID, 1, [7u8; 32], &unknown),
    )
    .unwrap();

    let (holder, published, store_head, _) = refused_as_ahead(log.try_seal(1));

    assert_eq!(
        holder,
        clave::publication::head_path(log.path())
            .display()
            .to_string()
    );
    assert_eq!((published, store_head), (1, Some(0)));
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn an_archive_file_named_above_the_store_head_refuses_without_parsing() {
    let log = Log::new();
    log.seal(0);
    std::fs::write(log.path().join("log/checkpoints/0000000005"), b"torn").unwrap();
    std::fs::write(log.path().join("log/checkpoints/.000000009.tmp"), b"x").unwrap();
    std::fs::write(log.path().join("log/checkpoints/00000009"), b"x").unwrap();

    let (holder, published, store_head, _) = refused_as_ahead(log.try_seal(1));

    assert_eq!(
        holder,
        log.path()
            .join("log/checkpoints/0000000005")
            .display()
            .to_string()
    );
    assert_eq!((published, store_head), (5, Some(0)));
}

#[test]
fn a_torn_archive_file_at_the_store_head_is_repaired_not_refused() {
    let log = Log::new();
    log.seal(0);
    let note = std::fs::read(log.archive(0)).unwrap();
    std::fs::write(log.archive(0), &note[..note.len() / 2]).unwrap();

    assert_eq!(
        clave::publication::recover(log.db(), log.path()).unwrap(),
        vec![0]
    );
    assert_eq!(std::fs::read(log.archive(0)).unwrap(), note);
}

#[test]
fn every_publication_pass_is_refused_before_writing_while_the_store_is_behind() {
    let mut log = Log::new();
    log.seal(0);
    let backup = log.back_up();
    log.seal(1);
    log.restore(&backup);
    std::fs::remove_dir_all(log.path().join("tile")).unwrap();
    let before = log.published();

    let (_, published, _, _) = refused_as_ahead(clave::publication::recover(log.db(), log.path()));
    assert_eq!(published, 1);
    refused_as_ahead(clave::publication::finish_committed(log.db(), log.path()));
    let (_, note) = log.db().head_publication().unwrap().unwrap();
    refused_as_ahead(clave::publication::republish_checkpoint(
        log.db(),
        log.path(),
        0,
        &note,
    ));

    assert_eq!(log.published(), before);
    assert!(!log.path().join("tile").exists());
}

#[test]
fn a_mirror_above_the_store_head_refuses_the_seal() {
    let log = Log::new();
    log.seal(0);
    let (url, directory, _held) = mirror();
    std::fs::write(
        directory.join("checkpoint"),
        forged(LOG_ID, 1, [7u8; 32], &log.signer()),
    )
    .unwrap();
    log.list_mirrors(std::slice::from_ref(&url));
    let before = log.published();

    let (holder, published, store_head, message) = refused_as_ahead(log.try_seal(1));

    assert_eq!(holder, format!("{url}checkpoint"));
    assert_eq!((published, store_head), (1, Some(0)));
    assert!(message.contains(&holder), "{message}");
    assert_eq!(log.published(), before);
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn a_mirror_at_the_store_head_stating_a_different_tree_refuses_the_seal() {
    let log = Log::new();
    log.seal(0);
    let (url, directory, _held) = mirror();
    std::fs::write(
        directory.join("checkpoint"),
        forged(LOG_ID, 0, [7u8; 32], &log.signer()),
    )
    .unwrap();
    log.list_mirrors(std::slice::from_ref(&url));

    let (_, published, store_head, _) = refused_as_ahead(log.try_seal(1));

    assert_eq!((published, store_head), (0, Some(0)));
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn a_mirror_serving_the_store_head_checkpoint_lets_the_seal_proceed() {
    let log = Log::new();
    log.seal(0);
    let (url, directory, _held) = mirror();
    std::fs::copy(log.path().join("checkpoint"), directory.join("checkpoint")).unwrap();
    log.list_mirrors(std::slice::from_ref(&url));

    assert_eq!(log.seal(1).epoch_number, 1);
}

#[test]
fn a_mirror_answering_not_found_lets_the_seal_proceed() {
    let log = Log::new();
    log.list_mirrors(&[serve_not_found()]);

    assert_eq!(log.seal(0).epoch_number, 0);
    assert_eq!(log.seal(1).epoch_number, 1);
}

#[test]
fn an_unreachable_mirror_refuses_the_seal() {
    let log = Log::new();
    log.seal(0);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", closed.local_addr().unwrap());
    drop(closed);
    log.list_mirrors(std::slice::from_ref(&url));

    match log.try_seal(1) {
        Err(clave::error::Error::MirrorUnconfirmed { url: named, reason }) => {
            assert_eq!(named, format!("{url}checkpoint"));
            assert!(!reason.is_empty());
        }
        Err(error) => panic!("refused for another reason: {error}"),
        Ok(_) => panic!("sealed without confirming the Mirror"),
    }
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn a_mirror_serving_another_logs_checkpoint_refuses_the_seal() {
    let log = Log::new();
    log.seal(0);
    let (url, directory, _held) = mirror();
    std::fs::write(
        directory.join("checkpoint"),
        forged("other.example.test", 0, [7u8; 32], &log.signer()),
    )
    .unwrap();
    log.list_mirrors(std::slice::from_ref(&url));

    let error = log.try_seal(1).err().expect("the seal is refused");
    assert!(
        matches!(error, clave::error::Error::MirrorUnconfirmed { .. }),
        "{error}"
    );
    assert!(error.to_string().contains("other.example.test"), "{error}");
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn a_mirror_answering_with_an_unparseable_note_refuses_the_seal() {
    let log = Log::new();
    log.seal(0);
    let (url, directory, _held) = mirror();
    std::fs::write(directory.join("checkpoint"), b"not a note").unwrap();
    log.list_mirrors(std::slice::from_ref(&url));

    assert!(matches!(
        log.try_seal(1),
        Err(clave::error::Error::MirrorUnconfirmed { .. })
    ));
    assert_eq!(log.head_epoch(), Some(0));
}

#[test]
fn a_mirror_answering_above_the_head_bound_refuses_the_seal() {
    let log = Log::new();
    log.seal(0);
    let (url, directory, _held) = mirror();
    std::fs::write(
        directory.join("checkpoint"),
        vec![b'a'; clave::publication::MIRROR_HEAD_CAP_BYTES as usize + 1],
    )
    .unwrap();
    log.list_mirrors(std::slice::from_ref(&url));

    match log.try_seal(1) {
        Err(clave::error::Error::MirrorUnconfirmed { reason, .. }) => {
            assert!(reason.contains("65536-byte bound"), "{reason}")
        }
        Err(error) => panic!("refused for another reason: {error}"),
        Ok(_) => panic!("sealed without confirming the Mirror"),
    }
}

#[test]
fn every_seal_command_consults_every_listed_mirror() {
    let log = Log::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let requests = serve_recording(listener, directory.path().to_path_buf());
    log.list_mirrors(std::slice::from_ref(&url));

    log.seal(0);
    log.seal(1);

    assert_eq!(
        *requests.lock().unwrap(),
        vec!["/checkpoint".to_string(), "/checkpoint".to_string()]
    );
}

#[test]
fn archive_names_stating_one_epoch_name_the_lexicographically_smallest() {
    let log = Log::new();
    log.seal(0);
    for name in ["000000005", "00000000005", "0000000005"] {
        std::fs::write(log.path().join("log/checkpoints").join(name), b"x").unwrap();
    }

    let (holder, published, _, _) = refused_as_ahead(log.try_seal(1));

    assert_eq!(published, 5);
    assert_eq!(
        holder,
        log.path()
            .join("log/checkpoints/00000000005")
            .display()
            .to_string()
    );
}
