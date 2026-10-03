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
                db.insert_pending_entry("publisher_declaration", domain, &candidate, 0)
                    .unwrap();
            }
            if domain == "b.example.com" && matches!(mutation, "ambiguous" | "duplicate") {
                let mut competitor = owner["publisher"].clone();
                if mutation == "ambiguous" {
                    competitor["seq"] = 2.into();
                }
                write_declaration(&p, &competitor, &R1_SEED);
                db.insert_pending_entry(
                    "publisher_declaration",
                    domain,
                    &current_declaration(&p),
                    0,
                )
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
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            2
        );
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
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        3
    );
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
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            0
        );
        assert!(!rejection_codes(&r).contains(&"WIST1-E08".into()));
        let mut follower = owner.clone();
        follower["seq"] = 8.into();
        follower["prev_declaration"] = declaration_hash(&owner_envelope).into();
        write_declaration(&r.p, &follower, &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert!(rejection_codes(&r).contains(&"WIST1-E08".into()));
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            0
        );
        follower["seq"] = 10.into();
        write_declaration(&r.p, &follower, &K2_SEED);
        ingest(&r, "2026-08-16T14:00:00Z");
        assert_eq!(
            r.db.highest_accepted_declaration_seq(&r.host).unwrap(),
            Some(10)
        );
        assert_eq!(
            r.db.count_pending_entries("publisher_declaration").unwrap(),
            1
        );
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
        let pending = r.db.peek_pending_entries().unwrap().0;
        assert_eq!(pending.len(), 2);
        let retained: Vec<_> = pending
            .iter()
            .map(|p| (p.rowid, p.entry_json.clone()))
            .collect();

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
                assert_eq!(
                    r.db.peek_pending_entries()
                        .unwrap()
                        .0
                        .iter()
                        .map(|p| (p.rowid, p.entry_json.clone()))
                        .collect::<Vec<_>>(),
                    retained
                );
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
                r.db.peek_pending_entries().unwrap().0.len(),
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
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
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
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        3
    );
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
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
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
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        0
    );
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
    assert_eq!(
        r.db.count_pending_entries("publisher_declaration").unwrap(),
        1
    );
}
