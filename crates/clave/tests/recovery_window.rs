mod common;

use clave::history::declarations::DeclarationsReplay;
use common::*;

const DAY: i64 = 86400;

struct Rig {
    host: String,
    p: TestPub,
    data: tempfile::TempDir,
    db: clave::db::Db,
    client: clave::fetch::Client,
    sk: wist_core::crypto::SigningKey,
}

fn rig(p_for: fn(&str) -> TestPub) -> Rig {
    let (listener, host, client) = reserve_addr();
    let p = p_for(&host);
    serve_static(listener, p.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run(&host, data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    Rig {
        host,
        p,
        data,
        db,
        client,
        sk,
    }
}

fn ingest(r: &Rig, now: &str) -> clave::ingest::IngestReport {
    clave::ingest::run(&r.db, &r.client, r.data.path(), &r.host, now).unwrap()
}

fn rejection_codes(r: &Rig) -> Vec<String> {
    r.db.list_rejections(&r.host)
        .unwrap()
        .into_iter()
        .map(|x| x.code)
        .collect()
}

#[test]
fn pending_owner_migration_rejects_missing_ambiguous_and_invalid_sources_atomically() {
    for mutation in ["missing", "ambiguous", "invalid", "duplicate"] {
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("clave.sqlite");
        let db = clave::db::Db::open(&path).unwrap();
        for domain in ["a.example.com", "b.example.com"] {
            let p = make_publisher_with_recovery(domain);
            let prior = current_declaration(&p);
            let mut owner = prior["publisher"].clone();
            owner["seq"] = 1.into();
            owner["prev_declaration"] = declaration_hash(&prior).into();
            owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
            write_declaration(&p, &owner, &R1_SEED);
            let owner = current_declaration(&p);
            db.open_recovery_window(
                domain,
                &serde_json::to_vec(&owner).unwrap(),
                &serde_json::to_vec(&prior).unwrap(),
            )
            .unwrap();
            if domain == "a.example.com" || mutation != "missing" {
                let mut candidate = owner.clone();
                if domain == "b.example.com" && mutation == "invalid" {
                    candidate["publisher"]["contact"] = "altered@example.com".into();
                }
                db.hold_discovered_declaration(domain, &candidate).unwrap();
            }
            if domain == "b.example.com" && matches!(mutation, "ambiguous" | "duplicate") {
                let mut competitor = owner["publisher"].clone();
                if mutation == "ambiguous" {
                    competitor["seq"] = 2.into();
                }
                write_declaration(&p, &competitor, &R1_SEED);
                db.hold_discovered_declaration(domain, &current_declaration(&p))
                    .unwrap();
            }
        }
        drop(db);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "ALTER TABLE recovery_windows DROP COLUMN owner_declaration_json",
                [],
            )
            .unwrap();
        drop(connection);
        let restored = clave::db::Db::open(&path);
        assert_eq!(restored.is_ok(), mutation == "duplicate", "{mutation}");
        drop(restored);
        let connection = rusqlite::Connection::open(&path).unwrap();
        let missing: u64 = connection
            .query_row(
                "SELECT count(*) FROM recovery_windows WHERE owner_declaration_json IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            missing,
            if mutation == "duplicate" { 0 } else { 2 },
            "{mutation}"
        );
    }
}

fn sealed_recovery() -> (Rig, i64, serde_json::Value) {
    let r = rig(make_publisher_with_recovery);
    let start = "2026-08-09T12:00:00Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .as_second();
    ingest(&r, "2026-08-09T12:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &owner, &R1_SEED);
    ingest(&r, "2026-08-09T13:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
    (r, start, owner)
}

fn stored_entries(r: &Rig, height: u64) -> Vec<serde_json::Value> {
    r.db.epoch_entries(height).unwrap()
}

#[test]
fn admission_uses_both_heads_without_joining_a_competing_branch() {
    let (mut r, start, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut competitor = owner.clone();
    competitor["seq"] = 4.into();
    competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
    competitor["keys"] = serde_json::json!([
        key_entry(&X1_SEED, "2026-08-09T13:00:00Z"),
        key_entry(&K2_SEED, "2026-08-09T13:00:00Z")
    ]);
    write_declaration(&r.p, &competitor, &X1_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    let mut branch = competitor.clone();
    branch["seq"] = 6.into();
    branch["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    write_declaration(&r.p, &branch, &K2_SEED);
    let branch_envelope = current_declaration(&r.p);
    ingest(&r, "2026-08-09T14:00:00Z");
    let recovery = r.db.get_recovery_window(&r.host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&recovery.declaration_json).unwrap(),
        owner_envelope
    );
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(6)
    );
    r.db.update_recovery_chain_head(&r.host, &serde_json::to_vec(&branch_envelope).unwrap())
        .unwrap();
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();

    let mut follower = owner.clone();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    for seq in [5, 6] {
        follower["seq"] = seq.into();
        write_declaration(&r.p, &follower, &K2_SEED);
        ingest(&r, "2026-08-09T14:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(6)
        );
        assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 2);
    }
    assert_eq!(
        rejection_codes(&r)
            .iter()
            .filter(|code| *code == "WIST1-E08")
            .count(),
        2
    );
    write_declaration(&r.p, &owner, &R1_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    assert_eq!(
        rejection_codes(&r)
            .iter()
            .filter(|code| *code == "WIST1-E08")
            .count(),
        3
    );
    let mut malformed = branch_envelope.clone();
    malformed["sig"]["value"] = "=".into();
    std::fs::write(
        r.p.dir.path().join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&malformed).unwrap(),
    )
    .unwrap();
    ingest(&r, "2026-08-09T14:00:00Z");
    assert!(rejection_codes(&r).contains(&"WIST1-E14".into()));
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(6)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &r.db.get_publisher_declaration(&r.host).unwrap().unwrap()
        )
        .unwrap(),
        branch_envelope
    );
    follower["seq"] = 7.into();
    write_declaration(&r.p, &follower, &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(7)
    );
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 3);
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
    let history = clave::history::declarations::Declarations::reconstruct(
        &r.db,
        r.data.path(),
        r.db.last_epoch().unwrap(),
    )
    .unwrap();
    assert_eq!(
        history.domains()[&r.host]
            .window()
            .unwrap()
            .head()
            .envelope(),
        &current_declaration(&r.p)
    );
}

#[test]
fn settled_admission_retains_the_floor_and_current_idempotence_after_migration() {
    for migrate in [false, true] {
        let (mut r, start, owner) = sealed_recovery();
        let owner_envelope = current_declaration(&r.p);
        let mut competitor = owner.clone();
        competitor["seq"] = 9.into();
        competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
        competitor["keys"] = serde_json::json!([key_entry(&X1_SEED, "2026-08-09T13:00:00Z")]);
        write_declaration(&r.p, &competitor, &X1_SEED);
        ingest(&r, "2026-08-09T14:00:00Z");
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
        let path = r.data.path().join("clave.sqlite");
        if migrate {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute("DROP TABLE declaration_floors", []).unwrap();
            conn.execute(
                "UPDATE sealed_declarations SET seq = seq + 100, declaration_json = x'7b7d'",
                [],
            )
            .unwrap();
        }
        r.db = clave::db::Db::open(&path).unwrap();
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(9)
        );
        write_declaration(&r.p, &owner, &R1_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 0);
        assert!(!rejection_codes(&r).contains(&"WIST1-E08".into()));
        let mut follower = owner.clone();
        follower["seq"] = 8.into();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        write_declaration(&r.p, &follower, &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert!(rejection_codes(&r).contains(&"WIST1-E08".into()));
        assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 0);
        follower["seq"] = 10.into();
        write_declaration(&r.p, &follower, &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(10)
        );
        assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 1);
    }
}

#[test]
fn capped_recovery_siblings_preserve_sequences_and_progress_after_restart() {
    for oversized_lower in [false, true] {
        let (mut r, start, owner) = sealed_recovery();
        let owner_envelope = current_declaration(&r.p);
        let mut competitor = owner.clone();
        competitor["seq"] = 2.into();
        competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
        competitor["keys"] = serde_json::json!([key_entry(&X1_SEED, "2026-08-09T13:00:00Z")]);
        write_declaration(&r.p, &competitor, &X1_SEED);
        ingest(&r, "2026-08-09T14:00:00Z");
        clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();

        competitor["seq"] = 3.into();
        competitor["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
        competitor["subdomain_scope"] = serde_json::json!((0..70)
            .map(|i| format!("explicit-host-{i}.example.com"))
            .collect::<Vec<_>>());
        write_declaration(&r.p, &competitor, &X1_SEED);
        let lower = current_declaration(&r.p);
        ingest(&r, "2026-08-09T14:00:00Z");
        let mut follower = owner;
        follower["seq"] = 4.into();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        write_declaration(&r.p, &follower, &K2_SEED);
        let higher = current_declaration(&r.p);
        ingest(&r, "2026-08-09T15:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(4)
        );
        let retained = r.db.discovered_declarations(&r.host).unwrap();
        assert_eq!(retained.len(), 2);

        let size_of = |declaration: &serde_json::Value| {
            wist_core::epoch::epoch_octets(&[serde_json::json!({
                "type": "publisher_declaration", "body": declaration
            })])
            .unwrap() as i64
        };
        let lower_cap = size_of(&lower);
        let higher_cap = size_of(&higher);
        assert!(lower_cap > higher_cap);
        r.db.set_param(
            "epoch_cap_bytes",
            if oversized_lower {
                higher_cap
            } else {
                lower_cap
            },
        )
        .unwrap();
        let database = r.data.path().join("clave.sqlite");
        let first_height = if oversized_lower {
            let mut independent = lower["publisher"].clone();
            independent["domain"] = "zz-independent.example".into();
            independent["seq"] = 0.into();
            for field in ["prev_declaration", "subdomain_scope", "recovery_keys"] {
                independent.as_object_mut().unwrap().remove(field);
            }
            let independent = wist_core::envelope::sign_envelope(
                &independent,
                "publisher",
                &kid(&X1_SEED),
                &wist_core::crypto::SigningKey::from_seed(&X1_SEED),
            )
            .unwrap();
            assert!(size_of(&independent) <= higher_cap);
            r.db.record_publisher_declaration(
                "zz-independent.example",
                &serde_json::to_vec(&independent).unwrap(),
                &kid(&X1_SEED),
                independent["publisher"]["keys"][0]["x"].as_str().unwrap(),
                &independent,
            )
            .unwrap();
            for height in [3, 4] {
                r.db = clave::db::Db::open(&database).unwrap();
                let report =
                    clave::seal::run(&r.db, r.data.path(), &r.sk, start + height * 3600).unwrap();
                assert_eq!(report.entry_count, u64::from(height == 3));
                assert!(report.dropped.is_empty());
                if height == 3 {
                    assert_eq!(
                        stored_entries(&r, 3),
                        vec![serde_json::json!({
                            "type": "publisher_declaration", "body": independent
                        })]
                    );
                }
                assert_eq!(r.db.discovered_declarations(&r.host).unwrap(), retained);
                assert_eq!(
                    r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
                    Some(4)
                );
                let state = clave::history::declarations::Declarations::reconstruct(
                    &r.db,
                    r.data.path(),
                    r.db.last_epoch().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    state.domains()[&r.host].current().envelope()["publisher"]["seq"],
                    2
                );
                assert_eq!(
                    state.domains()[&r.host].window().unwrap().head().envelope(),
                    &owner_envelope
                );
            }
            r.db.set_param("epoch_cap_bytes", lower_cap).unwrap();
            5
        } else {
            3
        };
        for (height, expected) in [(first_height, &lower), (first_height + 1, &higher)] {
            r.db = clave::db::Db::open(&database).unwrap();
            let report =
                clave::seal::run(&r.db, r.data.path(), &r.sk, start + height * 3600).unwrap();
            assert_eq!(report.entry_count, 1);
            assert!(report.dropped.is_empty());
            let epoch = stored_entries(&r, height as u64);
            assert_eq!(
                epoch,
                vec![serde_json::json!({"type": "publisher_declaration", "body": expected})]
            );
            assert!(wist_core::epoch::epoch_octets(&epoch).unwrap() as i64 <= lower_cap);
            let state = clave::history::declarations::Declarations::reconstruct(
                &r.db,
                r.data.path(),
                r.db.last_epoch().unwrap(),
            )
            .unwrap();
            assert_eq!(state.domains()[&r.host].current().envelope(), expected);
            assert_eq!(
                state.domains()[&r.host].window().unwrap().head().envelope(),
                if height == first_height {
                    &owner_envelope
                } else {
                    &higher
                }
            );
            assert_eq!(
                r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
                Some(4)
            );
            assert_eq!(
                r.db.count_discovered_declarations(&r.host).unwrap() as usize,
                (first_height + 1 - height) as usize
            );
        }
        r.db = clave::db::Db::open(&database).unwrap();
        assert_eq!(
            clave::seal::run(
                &r.db,
                r.data.path(),
                &r.sk,
                start + (first_height + 2) * 3600
            )
            .unwrap()
            .entry_count,
            0
        );
        clave::history::declarations::Declarations::reconstruct(
            &r.db,
            r.data.path(),
            r.db.last_epoch().unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn pending_recovery_followers_remain_eligible_after_partial_sealing() {
    let (mut r, start, owner) = sealed_recovery();
    let mut follower = owner.clone();
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    write_declaration(&r.p, &follower, &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    follower["seq"] = 3.into();
    follower["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
    follower["subdomain_scope"] = serde_json::json!((0..70)
        .map(|i| format!("long-explicit-host-{i}.example.com"))
        .collect::<Vec<_>>());
    write_declaration(&r.p, &follower, &K2_SEED);
    let pending_follower = current_declaration(&r.p);
    ingest(&r, "2026-08-09T14:00:00Z");
    r.db.set_param("epoch_cap_bytes", 1800).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 1);
    let window = r.db.get_recovery_window(&r.host).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&window.declaration_json).unwrap()["publisher"]
            ["seq"],
        2
    );
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    let mut competitor = follower.clone();
    competitor["seq"] = 4.into();
    competitor["prev_declaration"] = declaration_hash(&pending_follower).into();
    competitor["keys"] = serde_json::json!([key_entry(&X1_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &competitor, &X1_SEED);
    ingest(&r, "2026-08-09T15:00:00Z");
    follower["seq"] = 5.into();
    follower["prev_declaration"] = declaration_hash(&pending_follower).into();
    write_declaration(&r.p, &follower, &K2_SEED);
    ingest(&r, "2026-08-09T15:00:00Z");
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(5)
    );
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 3);
    assert!(!rejection_codes(&r).contains(&"WIST1-E08".into()));
    r.db.set_param("epoch_cap_bytes", 16_777_216).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 10800).unwrap();
    let state = clave::history::declarations::Declarations::reconstruct(
        &r.db,
        r.data.path(),
        r.db.last_epoch().unwrap(),
    )
    .unwrap();
    assert_eq!(
        state.domains()[&r.host].window().unwrap().head().envelope()["publisher"]["seq"],
        5
    );
}

#[test]
fn floor_migration_authenticates_the_pinned_prefix_before_writing() {
    let (mut r, _, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut follower = owner.clone();
    follower["seq"] = 12.into();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    write_declaration(&r.p, &follower, &K2_SEED);
    ingest(&r, "2026-08-09T14:00:00Z");
    let database = r.data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&database).unwrap();
    conn.execute(
        "UPDATE publishers SET declaration_json = ?1",
        [serde_json::to_vec(&owner_envelope).unwrap()],
    )
    .unwrap();
    conn.execute("DROP TABLE declaration_floors", []).unwrap();
    let corrupted: Vec<u8> = conn
        .query_row(
            "SELECT entry_json FROM log_entries WHERE leaf_index = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
        [br#"{"type":"label","body":{}}"#.as_slice()],
    )
    .unwrap();
    assert!(clave::db::Db::open(&database).is_err());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM declaration_floors", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 1);
    conn.execute(
        "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
        [corrupted],
    )
    .unwrap();
    r.db = clave::db::Db::open(&database).unwrap();
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(12)
    );
}

#[test]
fn failed_recovery_head_write_rolls_back_declaration_floor_and_pending_entry() {
    let (mut r, _, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut follower = owner.clone();
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    write_declaration(&r.p, &follower, &K2_SEED);
    let path = r.data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER fail_changed_recovery_head AFTER UPDATE OF declaration_json ON recovery_windows WHEN NEW.declaration_json != OLD.declaration_json BEGIN SELECT RAISE(ABORT, 'injected head write failure'); END;").unwrap();
    let error = clave::ingest::run(
        &r.db,
        &r.client,
        r.data.path(),
        &r.host,
        "2026-08-09T14:00:00Z",
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected head write failure"));
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(1)
    );
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 0);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &r.db.get_publisher_declaration(&r.host).unwrap().unwrap()
        )
        .unwrap(),
        owner_envelope
    );
    assert!(r.db.list_rejections(&r.host).unwrap().is_empty());
    conn.execute("DROP TRIGGER fail_changed_recovery_head", [])
        .unwrap();
    r.db = clave::db::Db::open(&path).unwrap();
    ingest(&r, "2026-08-09T14:00:00Z");
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(2)
    );
    assert_eq!(r.db.count_discovered_declarations(&r.host).unwrap(), 1);
}

fn queued_catalog(r: &Rig, at: &str) -> (Published, (serde_json::Value, serde_json::Value)) {
    let item = page_item(&r.p, &format!("https://{}/queued", r.host), "queued");
    let catalog = publish_collection_signed(
        &r.p,
        "default",
        &[(item.0.clone(), Some(item.1.clone()))],
        at,
        None,
        &K2_SEED,
    );
    (catalog, item)
}

#[test]
fn recovery_flow_queues_settles_and_seals_the_survivor() {
    let (r, start, _) = sealed_recovery();
    let (catalog, item) = queued_catalog(&r, "2026-08-09T14:00:00Z");
    let report = ingest(&r, "2026-08-09T14:00:05Z");
    assert_eq!(report.queued, [format!("default/{}", catalog.catalog_id)]);
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3 * 3600).unwrap();
    assert_eq!(
        report.entry_count, 0,
        "a queued Catalog is held through the window"
    );
    let status =
        serde_json::to_value(clave::serve::load_status(&r.db, &r.host).unwrap().unwrap()).unwrap();
    assert_valid("status.schema.json", &status);
    let queued = status["collections"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|collection| collection["waiting"].as_array().unwrap())
        .find(|entry| entry["id"] == catalog.catalog_id.as_str())
        .unwrap_or_else(|| panic!("{status}"));
    assert_eq!(queued["deferrals"], serde_json::json!(["recovery_window"]));
    assert_eq!(queued["held"], false);
    let window_end = start + 3600 + 7 * DAY;
    clave::seal::run(&r.db, r.data.path(), &r.sk, window_end - 3600).unwrap();
    assert!(stored_entries(&r, 3).is_empty());
    clave::seal::run(&r.db, r.data.path(), &r.sk, window_end).unwrap();
    clave::seal::run(&r.db, r.data.path(), &r.sk, window_end + 3600).unwrap();
    let sealed: Vec<serde_json::Value> = (4..=5)
        .flat_map(|height| stored_entries(&r, height))
        .collect();
    assert!(sealed
        .iter()
        .any(|entry| entry["type"] == "publisher_catalog" && entry["body"] == catalog.envelope));
    assert_eq!(sealed_item_ids(&sealed), [item_id(&item.0)]);
    let scope = std::collections::BTreeSet::from([r.host.clone()]);
    let state =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    assert!(state.queues.is_empty());
    assert!(state
        .record(&r.host, &format!("https://{}/queued", r.host))
        .is_some());
}

#[test]
fn corrupt_pinned_history_cannot_settle_a_queue() {
    let (r, start, _) = sealed_recovery();
    let (catalog, _) = queued_catalog(&r, "2026-08-09T14:00:00Z");
    ingest(&r, "2026-08-09T14:00:05Z");
    let connection = rusqlite::Connection::open(r.data.path().join("clave.sqlite")).unwrap();
    let original: Vec<u8> = connection
        .query_row(
            "SELECT entry_json FROM log_entries WHERE leaf_index = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
            [br#"{"type":"label","body":{}}"#.as_slice()],
        )
        .unwrap();
    let deadline = start + 3600 + 7 * DAY;
    let at = wist_core::timestamp::instant(deadline + 60).unwrap();
    assert!(clave::ingest::run(&r.db, &r.client, r.data.path(), &r.host, &at).is_err());
    assert!(clave::seal::run(&r.db, r.data.path(), &r.sk, deadline).is_err());
    connection
        .execute(
            "UPDATE log_entries SET entry_json = ?1 WHERE leaf_index = 0",
            [original],
        )
        .unwrap();
    let scope = std::collections::BTreeSet::from([r.host.clone()]);
    let state =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    let queue = &state.queues[&r.host];
    assert!(queue
        .queued
        .values()
        .any(|queued| queued.catalog_id == catalog.catalog_id));
}

#[test]
fn a_rejected_candidate_rolls_back_a_due_settlement() {
    let (r, start, _) = sealed_recovery();
    let (catalog, _) = queued_catalog(&r, "2026-08-09T14:00:00Z");
    ingest(&r, "2026-08-09T14:00:05Z");
    let fresh = |contact: &str| {
        let signer = wist_core::crypto::SigningKey::from_seed(&X1_SEED);
        wist_core::envelope::sign_envelope(
            &serde_json::json!({"wist_version": "1.0.0", "domain": "fresh.example",
                "contact": contact, "keys": [key_entry(&X1_SEED, "2026-08-09T00:00:00Z")],
                "seq": 0}),
            "publisher",
            &kid(&X1_SEED),
            &signer,
        )
        .unwrap()
    };
    for contact in ["mailto:a@fresh.example", "mailto:b@fresh.example"] {
        r.db.hold_discovered_declaration("fresh.example", &fresh(contact))
            .unwrap();
    }
    let deadline = start + 3600 + 7 * DAY;
    assert!(clave::seal::run(&r.db, r.data.path(), &r.sk, deadline).is_err());
    let scope = std::collections::BTreeSet::from([r.host.clone()]);
    let state =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    assert!(state.queues[&r.host]
        .queued
        .values()
        .any(|queued| queued.catalog_id == catalog.catalog_id));
    assert!(r
        .db
        .list_rejections(&r.host)
        .unwrap()
        .iter()
        .all(|rejection| rejection.at.as_str() < "2026-08-16"));
}

#[test]
fn cadence_rounding_cannot_reopen_a_settled_admission_window() {
    const T0: i64 = 1_786_276_800;
    let r = rig(make_publisher_with_recovery);
    let at = |seconds| jiff::Timestamp::from_second(seconds).unwrap().to_string();
    r.db.set_param("epoch_cadence_seconds", 3600).unwrap();
    ingest(&r, &at(T0));
    let effective = T0 + 30 * DAY;
    let update = wist_core::envelope::sign_envelope(&serde_json::json!({
        "wist_version": "1.0.0", "action": "parameter_change", "subject": "epoch_cadence_seconds",
        "details": {"parameter": "epoch_cadence_seconds", "value": 3599}, "effective_at": at(effective)
    }), "update", "log1", &r.sk).unwrap();
    r.db.insert_pending_entry("registry_update", "", &update, 0)
        .unwrap();
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, T0).unwrap();
    assert!(report.dropped.is_empty(), "{:?}", report.dropped);
    clave::seal::run(&r.db, r.data.path(), &r.sk, effective).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &owner, &R1_SEED);
    let opened = (effective.div_euclid(3599) + 1) * 3599;
    ingest(&r, &at(opened));
    clave::seal::run(&r.db, r.data.path(), &r.sk, opened).unwrap();
    let (catalog, item) = queued_catalog(&r, &at(opened));
    let report = ingest(&r, &at(opened + 5));
    assert_eq!(report.queued, [format!("default/{}", catalog.catalog_id)]);
    let deadline = opened + 7 * DAY;
    ingest(&r, &at(deadline));
    let scope = std::collections::BTreeSet::from([r.host.clone()]);
    let settled =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    assert!(
        settled.queues.is_empty(),
        "the pull at the deadline settles"
    );
    let error = clave::seal::run(&r.db, r.data.path(), &r.sk, deadline)
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("predates completed recovery settlement"),
        "{error}"
    );
    let unchanged =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    assert!(unchanged.queues.is_empty());
    let next = (deadline.div_euclid(3599) + 1) * 3599;
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, next).unwrap();
    let sealed = stored_entries(&r, report.epoch_number);
    assert!(sealed
        .iter()
        .any(|entry| entry["type"] == "publisher_catalog" && entry["body"] == catalog.envelope));
    assert_eq!(sealed_item_ids(&sealed), [item_id(&item.0)]);
    clave::history::declarations::Declarations::reconstruct(
        &r.db,
        r.data.path(),
        r.db.last_epoch().unwrap(),
    )
    .unwrap();
}

fn queued_catalog_signed(
    r: &Rig,
    url: &str,
    at: &str,
    signer: &[u8; 32],
) -> (Published, (serde_json::Value, serde_json::Value)) {
    let item = page_item(&r.p, url, "queued");
    let catalog = publish_collection_signed(
        &r.p,
        "default",
        &[(item.0.clone(), Some(item.1.clone()))],
        at,
        None,
        signer,
    );
    (catalog, item)
}

#[test]
fn authenticated_sealing_separates_settlement_from_packed_authority() {
    for case in [
        "competitor",
        "deferred_follower",
        "deadline_key",
        "deadline_scope",
    ] {
        let (mut r, start, owner) = sealed_recovery();
        let (rejected, _) = queued_catalog_signed(
            &r,
            "https://example.com/rejected",
            "2026-08-09T14:00:00Z",
            &K1_SEED,
        );
        assert_eq!(
            ingest(&r, "2026-08-09T14:00:05Z").queued,
            [format!("default/{}", rejected.catalog_id)],
            "{case}"
        );
        let (survivor, item) = queued_catalog_signed(
            &r,
            "https://example.com/survivor",
            "2026-08-09T15:00:00Z",
            &K2_SEED,
        );
        assert_eq!(
            ingest(&r, "2026-08-09T15:00:05Z").queued,
            [format!("default/{}", survivor.catalog_id)],
            "{case}"
        );
        let mut replacement = owner.clone();
        replacement["seq"] = 2.into();
        replacement["prev_declaration"] = declaration_hash(&current_declaration(&r.p)).into();
        let seed = if case == "competitor" {
            &X1_SEED
        } else {
            &K2_SEED
        };
        match case {
            "competitor" => {
                replacement["keys"] =
                    serde_json::json!([key_entry(&X1_SEED, "2026-08-09T13:00:00Z")]);
            }
            "deadline_scope" => replacement["subdomain_scope"] = serde_json::json!([]),
            "deadline_key" => replacement["keys"][0]["nbf"] = nbf("2026-08-10T00:00:00Z").into(),
            _ => {}
        }
        if case == "deferred_follower" {
            replacement["subdomain_scope"] =
                serde_json::json!(std::iter::once("example.com".to_string())
                    .chain((0..70).map(|i| format!("explicit-host-{i}.example.com")))
                    .collect::<Vec<_>>());
        }
        write_declaration(&r.p, &replacement, seed);
        ingest(&r, "2026-08-09T16:00:00Z");
        assert_eq!(
            r.db.count_discovered_declarations(&r.host).unwrap(),
            1,
            "{case}"
        );
        if case == "deferred_follower" {
            r.db.set_param("epoch_cap_bytes", 1800).unwrap();
        } else {
            clave::seal::run(&r.db, r.data.path(), &r.sk, start + 7200).unwrap();
        }
        r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
        let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
        let entries = stored_entries(&r, report.epoch_number);
        assert_eq!(entries.len() as u64, report.entry_count, "{case}");
        let state = clave::history::declarations::Declarations::reconstruct(
            &r.db,
            r.data.path(),
            r.db.last_epoch().unwrap(),
        )
        .unwrap();
        let current = &state.domains()[&r.host];
        assert!(current.window().is_none(), "{case}");
        let survivor_sealed = entries.iter().any(|entry| {
            entry["type"] == "publisher_catalog" && entry["body"] == survivor.envelope
        });
        assert_eq!(survivor_sealed, case != "deadline_key", "{case}");
        let recorded = sealed_item_ids(&entries).contains(&item_id(&item.0));
        assert_eq!(
            recorded,
            matches!(case, "competitor" | "deferred_follower"),
            "{case}"
        );
        assert_eq!(
            current.current().envelope()["publisher"]["seq"],
            if matches!(case, "competitor" | "deferred_follower") {
                1
            } else {
                2
            },
            "{case}"
        );
        let rejections = r.db.list_rejections(&r.host).unwrap();
        assert!(
            rejections.iter().any(|rejection| rejection.id.as_deref()
                == Some(rejected.catalog_id.as_str())
                && rejection.code == "WIST1-E13"),
            "{case}: {rejections:?}"
        );
        let survivor_rejected = rejections.iter().any(|rejection| {
            rejection.id.as_deref() == Some(survivor.catalog_id.as_str())
                && rejection.code == "WIST1-E13"
        });
        assert_eq!(
            survivor_rejected,
            case == "deadline_key",
            "{case}: {rejections:?}"
        );
        assert_eq!(
            r.db.count_discovered_declarations(&r.host).unwrap(),
            i64::from(case == "deferred_follower"),
            "{case}"
        );
    }
}

#[test]
fn failed_admission_settlement_rolls_back_every_database_effect() {
    let (mut r, _, _) = sealed_recovery();
    let (rejected, _) = queued_catalog_signed(
        &r,
        "https://example.com/old",
        "2026-08-09T14:00:00Z",
        &K1_SEED,
    );
    ingest(&r, "2026-08-09T14:00:05Z");
    let before = r.db.list_rejections(&r.host).unwrap().len();
    let path = r.data.path().join("clave.sqlite");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_settlement BEFORE DELETE ON catalog_queues BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert!(clave::ingest::run(
        &r.db,
        &r.client,
        r.data.path(),
        &r.host,
        "2026-08-16T13:00:00Z"
    )
    .is_err());
    r.db = clave::db::Db::open(&path).unwrap();
    let scope = std::collections::BTreeSet::from([r.host.clone()]);
    let state =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    assert!(state.queues[&r.host]
        .queued
        .values()
        .any(|queued| queued.catalog_id == rejected.catalog_id));
    assert_eq!(r.db.list_rejections(&r.host).unwrap().len(), before);
    conn.execute_batch("DROP TRIGGER refuse_settlement;")
        .unwrap();
    ingest(&r, "2026-08-16T13:00:00Z");
    let state =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    assert!(state.queues.is_empty());
    assert!(r
        .db
        .list_rejections(&r.host)
        .unwrap()
        .iter()
        .any(|rejection| rejection.code == "WIST1-E13"
            && rejection.id.as_deref() == Some(rejected.catalog_id.as_str())));
}

#[test]
fn a_pull_started_before_the_deadline_reads_the_window_at_its_own_instant_however_the_clock_crosses(
) {
    for crossing_call in [0, 1, 2, 3, 5] {
        let (r, _, _) = sealed_recovery();
        let (catalog, _) = queued_catalog_signed(
            &r,
            "https://example.com/crossing",
            "2026-08-16T12:59:59Z",
            &K1_SEED,
        );
        let calls = std::cell::Cell::new(0);
        let report = clave::ingest::run_with_clock(
            &r.db,
            &r.client,
            r.data.path(),
            &r.host,
            "2026-08-16T12:59:59Z",
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call < crossing_call {
                    "2026-08-16T12:59:59Z"
                } else {
                    "2026-08-16T13:00:00Z"
                }
                .parse()
                .unwrap()
            },
        )
        .unwrap();
        assert_eq!(
            report.queued,
            [format!("default/{}", catalog.catalog_id)],
            "{crossing_call}"
        );
        ingest(&r, "2026-08-16T13:00:00Z");
        let scope = std::collections::BTreeSet::from([r.host.clone()]);
        let state =
            r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
                .unwrap();
        assert!(state.queues.is_empty(), "{crossing_call}");
        assert!(r
            .db
            .list_rejections(&r.host)
            .unwrap()
            .iter()
            .any(|rejection| rejection.code == "WIST1-E13"
                && rejection.id.as_deref() == Some(catalog.catalog_id.as_str())));
    }
}

#[test]
fn a_queued_catalog_rejected_at_settlement_is_judged_again_when_served_again() {
    let (r, start, _) = sealed_recovery();
    let (queued, item) = queued_catalog_signed(
        &r,
        "https://example.com/retry",
        "2026-08-09T14:00:00Z",
        &K1_SEED,
    );
    ingest(&r, "2026-08-09T14:00:05Z");
    let deadline = "2026-08-16T13:00:00Z";
    ingest(&r, deadline);
    assert!(r
        .db
        .list_rejections(&r.host)
        .unwrap()
        .iter()
        .any(|rejection| rejection.code == "WIST1-E13"
            && rejection.id.as_deref() == Some(queued.catalog_id.as_str())));
    let resigned = wist_core::envelope::sign_envelope(
        &queued.envelope["catalog"],
        "catalog",
        &kid(&K2_SEED),
        &wist_core::crypto::SigningKey::from_seed(&K2_SEED),
    )
    .unwrap();
    std::fs::write(
        collection_dir(&r.p, "default").join("catalog.json"),
        wist_core::jcs::canonicalize(&resigned).unwrap(),
    )
    .unwrap();
    let report = ingest(&r, "2026-08-16T13:00:05Z");
    assert!(report.queued.is_empty(), "{report:?}");
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
    let entries = stored_entries(&r, report.epoch_number);
    assert!(entries
        .iter()
        .any(|entry| entry["type"] == "publisher_catalog" && entry["body"] == resigned));
    assert_eq!(sealed_item_ids(&entries), [item_id(&item.0)]);
}

#[test]
fn admission_deadline_preserves_pending_followers_and_later_replacements() {
    let (mut r, start, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let (rejected, _) = queued_catalog_signed(
        &r,
        "https://example.com/old",
        "2026-08-09T14:00:00Z",
        &K1_SEED,
    );
    ingest(&r, "2026-08-09T14:00:05Z");
    let mut competitor = owner.clone();
    competitor["seq"] = 2.into();
    competitor["prev_declaration"] = declaration_hash(&owner_envelope).into();
    competitor["keys"] = serde_json::json!([key_entry(&X1_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &competitor, &X1_SEED);
    ingest(&r, "2026-08-09T15:00:00Z");
    let mut follower = owner;
    follower["seq"] = 3.into();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    follower["keys"] = serde_json::json!([key_entry(&K1_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &follower, &K2_SEED);
    let follower_envelope = current_declaration(&r.p);
    ingest(&r, "2026-08-09T16:00:00Z");
    let deadline = "2026-08-16T13:00:00Z";
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    ingest(&r, deadline);
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(3)
    );
    assert!(r
        .db
        .list_rejections(&r.host)
        .unwrap()
        .iter()
        .any(
            |rejection| rejection.id.as_deref() == Some(rejected.catalog_id.as_str())
                && rejection.code == "WIST1-E13"
        ));
    competitor["seq"] = 4.into();
    competitor["prev_declaration"] = declaration_hash(&follower_envelope).into();
    write_declaration(&r.p, &competitor, &K1_SEED);
    let replacement = current_declaration(&r.p);
    let (after, item) = queued_catalog_signed(&r, "https://example.com/after", deadline, &X1_SEED);
    let report = ingest(&r, "2026-08-16T13:00:05Z");
    assert_eq!(
        report.accepted,
        [format!("default/{}", after.catalog_id)],
        "{report:?}"
    );
    r.db = clave::db::Db::open(&r.data.path().join("clave.sqlite")).unwrap();
    ingest(&r, "2026-08-16T13:00:05Z");
    let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600 + 7 * DAY).unwrap();
    let state = clave::history::declarations::Declarations::reconstruct(
        &r.db,
        r.data.path(),
        r.db.last_epoch().unwrap(),
    )
    .unwrap();
    assert_eq!(state.domains()[&r.host].current().envelope(), &replacement);
    assert_eq!(
        r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
        Some(4)
    );
    let sealed = sealed_item_ids(&stored_entries(&r, report.epoch_number));
    assert!(sealed.contains(&item_id(&item.0)));
    assert!(state.domains()[&r.host].window().is_none());
}

fn held_deferrals(r: &Rig, url: &str) -> serde_json::Value {
    let status =
        serde_json::to_value(clave::serve::load_status(&r.db, &r.host).unwrap().unwrap()).unwrap();
    assert_valid("status.schema.json", &status);
    status["collections"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|collection| collection["waiting"].as_array().unwrap())
        .find(|entry| entry["url"] == url)
        .unwrap_or_else(|| panic!("{status}"))["deferrals"]
        .clone()
}

#[test]
fn a_window_opened_over_a_waiting_catalog_defers_its_held_items_at_every_epoch_inside_it() {
    use clave::collection::plan::{self, Deferral, EpochInput, Inclusion, Publication};
    let r = rig(make_publisher_with_recovery);
    let start = wist_core::timestamp::log_seconds("2026-08-09T12:00:00Z").unwrap();
    ingest(&r, "2026-08-09T12:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
    let url = format!("https://{}/held", r.host);
    let (waiting, _) = queued_catalog_signed(&r, &url, "2026-08-09T12:30:00Z", &K1_SEED);
    let report = ingest(&r, "2026-08-09T12:30:05Z");
    assert_eq!(report.accepted, [format!("default/{}", waiting.catalog_id)]);
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &owner, &R1_SEED);
    ingest(&r, "2026-08-09T12:45:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();

    let scope = std::collections::BTreeSet::from([r.host.clone()]);
    let mut state =
        r.db.load_state(r.db.sealed_state(r.data.path()).unwrap(), &scope)
            .unwrap();
    let held = clave::db::StoreHeld::new(&r.db, r.data.path(), "2026-08-09T13:00:00Z");
    let parameters = clave::collection::Parameters::new(Default::default());
    let inclusion = Inclusion::constant(24);
    let unsealed = std::collections::BTreeSet::new();
    for (height, sealed_at) in [(2, "2026-08-09T14:00:00Z"), (3, "2026-08-09T15:00:00Z")] {
        let planned = plan::plan(
            &state,
            &held,
            &EpochInput {
                height,
                sealed_at,
                parameters: &parameters,
                inclusion: &inclusion,
                suffix_list: None,
                declarations: &[],
                updates: &[],
                unsealed: &unsealed,
                log_key: &|_| None,
            },
        )
        .unwrap_or_else(|error| panic!("in memory at {height}: {error}"));
        assert!(planned.entries.is_empty());
        let deferred = planned
            .deferred
            .iter()
            .find(|deferred| {
                matches!(&deferred.publication, Publication::Item { url: held, .. } if *held == url)
            })
            .unwrap_or_else(|| panic!("in memory at {height}: {:?}", planned.deferred));
        assert_eq!(deferred.reasons, [Deferral::RecoveryWindow]);
        state = planned.state;
        state.declarations.seed_head(
            height,
            "root",
            Some(wist_core::timestamp::log_seconds(sealed_at).unwrap()),
        );
    }

    for hour in 2..=3 {
        let report = clave::seal::run(&r.db, r.data.path(), &r.sk, start + hour * 3600)
            .unwrap_or_else(|error| panic!("through the store at {hour}: {error}"));
        assert_eq!(report.entry_count, 0);
        assert_eq!(
            held_deferrals(&r, &url),
            serde_json::json!(["recovery_window"])
        );
    }
}

#[test]
fn a_seal_inside_a_window_that_a_pull_settled_is_refused_while_a_follower_queue_is_held() {
    let (r, start, owner) = sealed_recovery();
    let owner_envelope = current_declaration(&r.p);
    let mut follower = owner;
    follower["seq"] = 2.into();
    follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
    follower["keys"] = serde_json::json!([key_entry(&K1_SEED, "2026-08-09T13:00:00Z")]);
    write_declaration(&r.p, &follower, &R1_SEED);
    let url = format!("https://{}/later", r.host);
    let (later, _) = queued_catalog_signed(&r, &url, "2026-08-09T15:30:00Z", &K1_SEED);
    let report = ingest(&r, "2026-08-09T16:00:00Z");
    assert_eq!(report.queued, [format!("default/{}", later.catalog_id)]);
    let settled = |r: &Rig| {
        r.db.list_rejections(&r.host)
            .unwrap()
            .into_iter()
            .filter(|rejection| {
                rejection.code == "WIST1-E13"
                    && rejection.id.as_deref() == Some(later.catalog_id.as_str())
            })
            .count()
    };
    let window_end = start + 3600 + 7 * DAY;
    ingest(&r, "2026-08-16T13:00:00Z");
    assert_eq!(settled(&r), 1);
    assert!(r.db.count_discovered_declarations(&r.host).unwrap() > 0);
    let inside = clave::seal::run(&r.db, r.data.path(), &r.sk, window_end - 3600);
    assert!(
        inside.is_err(),
        "a slot below the end sealed after a pull settled the window"
    );
    clave::seal::run(&r.db, r.data.path(), &r.sk, window_end).unwrap();
    assert_eq!(settled(&r), 1, "the queue is settled once");
}

#[test]
fn a_status_inside_a_window_names_the_collections_of_both_frozen_sources() {
    let r = rig(make_publisher_with_recovery);
    let url = |path: &str| format!("https://{}/{path}", r.host);
    let mut first = current_declaration(&r.p)["publisher"].clone();
    first["collections"] = serde_json::json!([
        {"name": "journal", "scope": [{"url": url("journal/"), "match": "prefix"}]},
        {"name": "archive", "scope": [{"url": url("archive/"), "match": "prefix"}]},
    ]);
    write_declaration(&r.p, &first, &K1_SEED);
    let start = wist_core::timestamp::log_seconds("2026-08-09T12:00:00Z").unwrap();
    ingest(&r, "2026-08-09T12:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start).unwrap();
    let prior = current_declaration(&r.p);
    let mut owner = prior["publisher"].clone();
    owner["seq"] = 1.into();
    owner["prev_declaration"] = declaration_hash(&prior).into();
    owner["keys"] = serde_json::json!([key_entry(&K2_SEED, "2026-08-09T13:00:00Z")]);
    owner["collections"] = serde_json::json!([
        {"name": "journal", "scope": [{"url": url("journal/"), "match": "prefix"}]},
    ]);
    write_declaration(&r.p, &owner, &R1_SEED);
    ingest(&r, "2026-08-09T13:00:00Z");
    clave::seal::run(&r.db, r.data.path(), &r.sk, start + 3600).unwrap();
    ingest(&r, "2026-08-09T14:00:00Z");
    let status =
        serde_json::to_value(clave::serve::load_status(&r.db, &r.host).unwrap().unwrap()).unwrap();
    assert_valid("status.schema.json", &status);
    let names: Vec<&str> = status["collections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|collection| collection["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["archive", "journal"], "{status}");
}
