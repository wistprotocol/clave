use wist_core::envelope::sign_envelope;

const SEAL_START: i64 = 1_786_276_800;
const FIRST: &str = "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n";
const SECOND: &str = "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\nhosts.sample.net\n// ===END PRIVATE DOMAINS===\n";

fn instant(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

fn state_entries(data: &std::path::Path) -> Vec<serde_json::Value> {
    let read = |path: &std::path::Path| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    };
    let index = read(&data.join("snapshots/index.json"));
    let manifest_url = index["index"]["snapshots"][0]["manifest_url"]
        .as_str()
        .unwrap()
        .trim_start_matches('/')
        .to_string();
    let manifest_path = data.join(&manifest_url);
    let manifest = read(&manifest_path);
    let state_path = manifest_path
        .parent()
        .unwrap()
        .join(manifest["manifest"]["state"]["path"].as_str().unwrap());
    read(&state_path)["state"]["entries"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn a_pinned_snapshot_governs_from_the_epoch_after_its_seal() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.example", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let file = data.path().join("first.dat");
    std::fs::write(&file, FIRST).unwrap();
    let first = clave::suffix_list::pin(&db, data.path(), &sk, &file, SEAL_START - 10).unwrap();
    assert_eq!(
        first.identifier,
        wist_core::suffix_list::identifier(FIRST.as_bytes())
    );
    assert_eq!(first.bytes, FIRST.len() as u64);
    let served = clave::suffix_list::file_path(data.path(), &first.identifier);
    assert!(served.starts_with(data.path().join("log/suffix-lists")));
    assert_eq!(std::fs::read(&served).unwrap(), FIRST.as_bytes());
    let before = instant(SEAL_START - 1);
    assert_eq!(
        clave::suffix_list::unit_at(&db, "a.example.com", &before).unwrap(),
        "a.example.com"
    );

    let r0 = clave::seal::run(&db, data.path(), &sk, SEAL_START).unwrap();
    assert_eq!((r0.epoch_number, r0.entry_count), (0, 1));
    assert!(r0.dropped.is_empty(), "{:?}", r0.dropped);
    assert_eq!(
        db.suffix_list_acts().unwrap(),
        vec![(0, first.identifier.clone())]
    );
    assert_eq!(db.suffix_list_in_force_at_epoch(0).unwrap(), None);
    assert_eq!(
        db.suffix_list_in_force_at_epoch(1).unwrap(),
        Some((first.identifier.clone(), 0))
    );
    assert_eq!(
        clave::suffix_list::unit_at(&db, "a.example.com", &before).unwrap(),
        "a.example.com"
    );
    let after = instant(SEAL_START + 1);
    let unit = |host: &str| clave::suffix_list::unit_at(&db, host, &after).unwrap();
    assert_eq!(unit("a.example.com"), "example.com");
    assert_eq!(unit("b.example.com"), "example.com");
    assert_eq!(unit("alice.github.io"), "alice.github.io");
    assert_eq!(unit("a.hosts.sample.net"), "sample.net");
    assert_eq!(unit("localhost"), "localhost");
    assert!(state_entries(data.path()).contains(&serde_json::json!([
        "suffix_list",
        first.identifier,
        0
    ])));

    db.set_param("quota_base", 2).unwrap();
    db.bump_noise_ping("example.com", &after[..10]).unwrap();
    let remaining = |host: &str| clave::quota::quota_remaining(&db, host, &after).unwrap();
    assert_eq!(remaining("a.example.com"), 1);
    assert_eq!(remaining("b.example.com"), 1);
    assert_eq!(remaining("alice.github.io"), 2);

    let file = data.path().join("second.dat");
    std::fs::write(&file, SECOND).unwrap();
    let second = clave::suffix_list::pin(&db, data.path(), &sk, &file, SEAL_START).unwrap();
    let r1 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 7200).unwrap();
    assert_eq!((r1.epoch_number, r1.entry_count), (1, 1));
    assert_eq!(
        db.suffix_list_in_force_at_epoch(1).unwrap(),
        Some((first.identifier.clone(), 0))
    );
    assert_eq!(
        db.suffix_list_in_force_at_epoch(2).unwrap(),
        Some((second.identifier.clone(), 1))
    );
    let later = instant(SEAL_START + 10800);
    assert_eq!(
        clave::suffix_list::unit_at(&db, "a.hosts.sample.net", &later).unwrap(),
        "a.hosts.sample.net"
    );
    assert_eq!(
        clave::suffix_list::unit_at(&db, "a.hosts.sample.net", &after).unwrap(),
        "sample.net"
    );
    assert!(state_entries(data.path()).contains(&serde_json::json!([
        "suffix_list",
        second.identifier,
        1
    ])));

    clave::suffix_list::pin(&db, data.path(), &sk, &file, SEAL_START + 10800).unwrap();
    let r2 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 14400).unwrap();
    assert_eq!((r2.epoch_number, r2.entry_count), (2, 1));
    assert!(r2.dropped.is_empty(), "{:?}", r2.dropped);
    assert_eq!(db.suffix_list_acts().unwrap().len(), 2);
    assert_eq!(
        db.suffix_list_in_force_at_epoch(3).unwrap(),
        Some((second.identifier.clone(), 1))
    );

    let forged = serde_json::json!({
        "wist_version": "1.0.0",
        "action": "suffix_list_update",
        "subject": first.identifier,
        "details": {"sha256": first.identifier, "bytes": first.bytes + 1},
        "effective_at": instant(SEAL_START + 18000),
    });
    let envelope = sign_envelope(&forged, "update", "log1", &sk).unwrap();
    db.insert_pending_entry("registry_update", "", &envelope, 0)
        .unwrap();
    let r3 = clave::seal::run(&db, data.path(), &sk, SEAL_START + 18000).unwrap();
    assert_eq!((r3.epoch_number, r3.entry_count), (3, 0));
    assert!(
        r3.dropped.iter().any(|d| d.starts_with("WIST4-E04")),
        "{:?}",
        r3.dropped
    );
    assert_eq!(db.suffix_list_acts().unwrap().len(), 2);
}
