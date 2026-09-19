use clave::db::{Db, Fence, SEALER_LEASE_SECONDS};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Configures a Witness that answers every submission with 500 after
/// `delay`, which holds a seal open that long after its commit.
fn slow_witness(db: &Db, sk: &wist_core::crypto::SigningKey, delay: Duration) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let app = axum::Router::new().fallback(move || async move {
                tokio::time::sleep(delay).await;
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            });
            axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                .await
                .unwrap();
        });
    });
    let key = clave::witness::verifier_key("slow.example/witness", &sk.public());
    db.add_witness("slow.example/witness", &key, &base).unwrap();
}

fn snapshot_index(data: &Path) -> bool {
    data.join("snapshots/index.json").exists()
}

fn log(data: &Path) -> (Db, wist_core::crypto::SigningKey) {
    clave::init::run("127.0.0.1:0", data).unwrap();
    let db = Db::open(&data.join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.join("keys/seed")).unwrap();
    (db, sk)
}

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[test]
fn only_the_sealer_lease_holder_seals_and_a_one_shot_seal_releases_it() {
    let data = tempfile::tempdir().unwrap();
    let (db, sk) = log(data.path());
    let path = data.path().join("clave.sqlite");
    let client = clave::fetch::Client::new(false);
    assert_eq!(db.hold_sealer_lease("serving", now()).unwrap(), Some(1));

    let Err(refused) = clave::seal::run_leased(&path, data.path(), &sk, &client, now(), "one-shot")
    else {
        panic!("sealed without the sealer lease");
    };
    assert!(
        matches!(&refused, clave::Error::Seal(message) if message.contains("held by serving")),
        "{refused}"
    );
    assert!(db.last_epoch().unwrap().is_none());
    assert!(!clave::publication::head_path(data.path()).exists());
    assert_eq!(db.sealer_lease().unwrap().owner.as_deref(), Some("serving"));

    db.release_sealer_lease("serving").unwrap();
    let report =
        clave::seal::run_leased(&path, data.path(), &sk, &client, now(), "one-shot").unwrap();
    assert_eq!(report.epoch_number, 0);
    assert!(clave::publication::head_path(data.path()).exists());
    let lease = db.sealer_lease().unwrap();
    assert_eq!((lease.owner, lease.token), (None, 2));
}

#[test]
fn a_sealer_whose_lease_was_taken_over_has_its_commit_refused_with_no_epoch_or_file() {
    let data = tempfile::tempdir().unwrap();
    let (db, sk) = log(data.path());
    let path = data.path().join("clave.sqlite");
    let now = now();
    let stale = db
        .hold_sealer_lease("stale", now - SEALER_LEASE_SECONDS)
        .unwrap()
        .unwrap();
    assert_eq!(db.hold_sealer_lease("current", now - 1).unwrap(), None);
    let current = db.hold_sealer_lease("current", now).unwrap().unwrap();
    assert_eq!(current, stale + 1);
    assert_eq!(db.hold_sealer_lease("stale", now).unwrap(), None);

    let stale_db = Db::connect(&path)
        .unwrap()
        .fenced(Fence::Sealer { token: stale });
    assert!(matches!(
        clave::seal::run(&stale_db, data.path(), &sk, now),
        Err(clave::Error::Fenced)
    ));
    assert!(db.last_epoch().unwrap().is_none());
    assert!(!clave::publication::head_path(data.path()).exists());
    assert!(!clave::publication::archive_path(data.path(), 0).exists());

    let current_db = Db::connect(&path)
        .unwrap()
        .fenced(Fence::Sealer { token: current });
    let report = clave::seal::run(&current_db, data.path(), &sk, now).unwrap();
    assert_eq!(report.epoch_number, 0);
    assert!(clave::publication::archive_path(data.path(), 0).exists());
}

#[test]
fn a_seal_longer_than_its_lease_keeps_the_lease_by_renewal_and_completes() {
    let data = tempfile::tempdir().unwrap();
    let (db, sk) = log(data.path());
    let path = data.path().join("clave.sqlite");
    slow_witness(&db, &sk, Duration::from_secs(4));
    let terms = clave::seal::LeaseTerms {
        lease_seconds: 2,
        renewal: Duration::from_millis(250),
    };
    let sealing = Arc::new(AtomicBool::new(true));
    let rival = {
        let (path, sealing) = (path.clone(), sealing.clone());
        std::thread::spawn(move || {
            let db = Db::connect(&path).unwrap();
            while sealing.load(Ordering::SeqCst)
                && db.sealer_lease().unwrap().owner.as_deref() != Some("sealer")
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut takeovers = 0;
            while sealing.load(Ordering::SeqCst) {
                if db
                    .hold_sealer_lease_for("rival", now(), terms.lease_seconds)
                    .unwrap()
                    .is_some()
                {
                    takeovers += 1;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            takeovers
        })
    };
    let started = std::time::Instant::now();
    let report = clave::seal::run_leased_with(
        &path,
        data.path(),
        &sk,
        &clave::fetch::Client::new(true),
        now(),
        "sealer",
        terms,
    );
    sealing.store(false, Ordering::SeqCst);
    assert!(started.elapsed() > Duration::from_secs(3));
    assert_eq!(report.unwrap().epoch_number, 0);
    assert_eq!(
        rival.join().unwrap(),
        0,
        "the rival took the lease mid-seal"
    );
    assert!(snapshot_index(data.path()));
    assert_eq!(db.sealer_lease().unwrap().token, 1);
}

#[test]
fn a_sealer_that_loses_its_lease_after_committing_publishes_no_further_files() {
    let data = tempfile::tempdir().unwrap();
    let (db, sk) = log(data.path());
    let path = data.path().join("clave.sqlite");
    slow_witness(&db, &sk, Duration::from_secs(3));
    let token = db
        .hold_sealer_lease_for("unrenewed", now(), 1)
        .unwrap()
        .unwrap();
    let sealer = {
        let (path, data) = (path.clone(), data.path().to_path_buf());
        std::thread::spawn(move || {
            let sk = clave::keys::load(&data.join("keys/seed")).unwrap();
            let db = Db::connect(&path).unwrap().fenced(Fence::Sealer { token });
            clave::seal::run_with_client(&db, &data, &sk, &clave::fetch::Client::new(true), now())
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while db.hold_sealer_lease("rival", now()).unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "the lease never lapsed"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(matches!(sealer.join().unwrap(), Err(clave::Error::Fenced)));
    assert_eq!(db.last_epoch().unwrap().unwrap().epoch_number, 0);
    assert!(!snapshot_index(data.path()));
}
