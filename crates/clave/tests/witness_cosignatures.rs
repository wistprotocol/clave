mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};
use std::path::Path;
use std::sync::{Arc, Mutex};
use wist_core::checkpoint::{self, Checkpoint, SignatureLine, WitnessKey};
use wist_core::crypto::SigningKey;

const SEAL_START: i64 = 1_786_276_800;
const WITNESS_NAME: &str = "witness.example";

/// How a fake Witness answers `add-checkpoint`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    /// 200 with a Cosignature over the note text.
    Cosign,
    /// 409 with the size it claims to hold, then 200.
    ConflictThenCosign(u64),
    /// 200 with a Cosignature under another key.
    WrongKey,
    /// The connection is refused: nothing listens.
    Down,
}

struct Calls {
    bodies: Arc<Mutex<Vec<String>>>,
}

impl Calls {
    fn old_sizes(&self) -> Vec<u64> {
        self.bodies
            .lock()
            .unwrap()
            .iter()
            .map(|body| {
                body.lines().next().unwrap()["old ".len()..]
                    .parse::<u64>()
                    .unwrap()
            })
            .collect()
    }
}

fn witness_key() -> SigningKey {
    SigningKey::from_seed(&[77u8; 32])
}

fn spawn_witness(behavior: Behavior) -> (String, Calls) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    if behavior == Behavior::Down {
        drop(listener);
        return (base, Calls { bodies });
    }
    let recorded = bodies.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let served = Arc::new(Mutex::new(0usize));
            let app = axum::Router::new().route(
                "/add-checkpoint",
                axum::routing::post(move |body: String| {
                    let recorded = recorded.clone();
                    let served = served.clone();
                    async move {
                        recorded.lock().unwrap().push(body.clone());
                        let attempt = {
                            let mut served = served.lock().unwrap();
                            *served += 1;
                            *served
                        };
                        let note = body.split_once("\n\n").map(|(_, note)| note).unwrap_or("");
                        let checkpoint = Checkpoint::parse(note).unwrap();
                        if let Behavior::ConflictThenCosign(size) = behavior {
                            if attempt == 1 {
                                return (
                                    axum::http::StatusCode::CONFLICT,
                                    [(axum::http::header::CONTENT_TYPE, "text/x.tlog.size")],
                                    format!("{size}\n"),
                                );
                            }
                        }
                        let signer = if behavior == Behavior::WrongKey {
                            SigningKey::from_seed(&[13u8; 32])
                        } else {
                            witness_key()
                        };
                        let line = checkpoint::cosignature_line(
                            WITNESS_NAME,
                            &signer,
                            &checkpoint.note_text(),
                            1_786_276_800,
                        );
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "text/plain")],
                            format!("{}\n", line.encode()),
                        )
                    }
                }),
            );
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .await
                .unwrap();
        });
    });
    (base, Calls { bodies })
}

struct Log {
    data: tempfile::TempDir,
    db: clave::db::Db,
    sk: SigningKey,
    host: String,
    client: clave::fetch::Client,
}

fn sealed_log() -> Log {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("block_cadence_seconds", 1).unwrap();
    clave::ingest::run(&db, &client, data.path(), &host, "2026-08-09T12:00:00Z").unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Log {
        data,
        db,
        sk,
        host,
        client,
    }
}

fn configure(log: &Log, base_url: &str) {
    let key = clave::witness::verifier_key(WITNESS_NAME, &witness_key().public());
    let (name, _) = clave::witness::parse_verifier_key(&key).unwrap();
    assert_eq!(name, WITNESS_NAME);
    log.db.add_witness(&name, &key, base_url).unwrap();
}

fn head_note(data: &Path) -> String {
    std::fs::read_to_string(data.join("checkpoint")).unwrap()
}

fn cosigners(note: &str, key_id: &str, aggregator: &SigningKey) -> Vec<String> {
    let checkpoint = Checkpoint::parse(note).unwrap();
    let verification = checkpoint::verify(
        &checkpoint,
        key_id,
        &[checkpoint::AggregatorKey {
            key_id: "log1".into(),
            public_key: aggregator.public(),
        }],
        &[WitnessKey {
            name: WITNESS_NAME.into(),
            public_key: witness_key().public(),
        }],
    )
    .unwrap();
    verification.cosigners.into_iter().collect()
}

#[test]
fn a_cosigned_checkpoint_is_republished_with_the_witness_signature_line() {
    let log = sealed_log();
    let (base, calls) = spawn_witness(Behavior::Cosign);
    configure(&log, &base);

    clave::seal::run_with_client(&log.db, log.data.path(), &log.sk, &log.client, SEAL_START)
        .unwrap();

    let note = head_note(log.data.path());
    assert_eq!(cosigners(&note, &log.host, &log.sk), [WITNESS_NAME]);
    assert_eq!(
        std::fs::read_to_string(log.data.path().join("log/checkpoints/000000000")).unwrap(),
        note,
        "the archive carries the Cosignature too"
    );
    let head = Checkpoint::parse(&note).unwrap();
    let before = Checkpoint::parse(&log.db.checkpoint_note(0).unwrap().unwrap()).unwrap();
    assert_eq!(before.note_text(), head.note_text());
    assert_eq!(calls.old_sizes(), [0]);
    assert_eq!(log.db.witnesses().unwrap()[0].last_size, head.tree_size());

    clave::seal::run_with_client(
        &log.db,
        log.data.path(),
        &log.sk,
        &log.client,
        SEAL_START + 3600,
    )
    .unwrap();
    assert_eq!(
        calls.old_sizes(),
        [0, head.tree_size()],
        "the next proof runs from the size the Witness last cosigned"
    );
}

#[test]
fn a_witness_that_states_another_size_is_retried_once_from_that_size() {
    let log = sealed_log();
    let (base, calls) = spawn_witness(Behavior::ConflictThenCosign(0));
    configure(&log, &base);
    log.db.set_witness_size(WITNESS_NAME, 1).unwrap();

    clave::seal::run_with_client(&log.db, log.data.path(), &log.sk, &log.client, SEAL_START)
        .unwrap();

    assert_eq!(calls.old_sizes(), [1, 0]);
    let note = head_note(log.data.path());
    assert_eq!(cosigners(&note, &log.host, &log.sk), [WITNESS_NAME]);
}

#[test]
fn a_cosignature_that_does_not_verify_is_not_published() {
    let log = sealed_log();
    let (base, _calls) = spawn_witness(Behavior::WrongKey);
    configure(&log, &base);

    clave::seal::run_with_client(&log.db, log.data.path(), &log.sk, &log.client, SEAL_START)
        .unwrap();

    let note = head_note(log.data.path());
    assert!(cosigners(&note, &log.host, &log.sk).is_empty());
    assert_eq!(Checkpoint::parse(&note).unwrap().signatures().len(), 1);
    assert_eq!(log.db.witnesses().unwrap()[0].last_size, 0);
}

#[test]
fn a_witness_that_cannot_be_reached_does_not_fail_the_seal() {
    let log = sealed_log();
    let (base, _calls) = spawn_witness(Behavior::Down);
    configure(&log, &base);

    let report =
        clave::seal::run_with_client(&log.db, log.data.path(), &log.sk, &log.client, SEAL_START)
            .unwrap();
    assert_eq!(report.block_number, 0);

    let note = head_note(log.data.path());
    assert!(cosigners(&note, &log.host, &log.sk).is_empty());
    assert_eq!(log.db.witnesses().unwrap()[0].last_size, 0);

    let signatures: Vec<SignatureLine> = Checkpoint::parse(&note).unwrap().signatures().to_vec();
    assert_eq!(signatures.len(), 1, "only the Aggregator's own signature");
}

#[test]
fn a_verifier_key_string_round_trips_and_rejects_a_mismatched_key_id() {
    let key = witness_key().public();
    let encoded = clave::witness::verifier_key(WITNESS_NAME, &key);
    let (name, parsed) = clave::witness::parse_verifier_key(&encoded).unwrap();
    assert_eq!(name, WITNESS_NAME);
    assert_eq!(parsed.to_bytes(), key.to_bytes());
    let mut parts: Vec<&str> = encoded.splitn(3, '+').collect();
    parts[1] = "00000000";
    assert!(clave::witness::parse_verifier_key(&parts.join("+")).is_err());
    assert!(clave::witness::parse_verifier_key("only+two").is_err());
}
