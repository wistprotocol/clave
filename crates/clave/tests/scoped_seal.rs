mod common;

use common::{
    add_label, current_declaration, declaration_hash, make_publisher_with_scope, serve_static,
    write_declaration, write_label_feed, K1_SEED,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use wist_core::sealing::Judgment;

const SUBJECT: &str = "https://reduced.example.org/notice";

struct Built {
    log: common::Rig,
    _site: common::TestPub,
    label_id: String,
    dispute_id: String,
    disputant: String,
    withdrawn: String,
    disputed: clave::seal::SealReport,
    waiting_at_dispute: BTreeSet<String>,
    waiting_at_withdrawal: BTreeSet<String>,
    narrowed_url: String,
    narrowed: clave::seal::SealReport,
    foreign_item: String,
    refused: clave::seal::SealReport,
}

fn sign_dispute(p: &common::TestPub, inner: Value) -> (String, Value) {
    let id = wist_core::label::label_id(&inner).unwrap();
    let envelope = wist_core::envelope::sign_envelope(&inner, "dispute", &p.kid, &p.sk).unwrap();
    (id, envelope)
}

fn serve_dispute(
    disputant: &str,
    label_id: &str,
) -> (clave::fetch::Client, String, common::TestPub) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve(disputant, listener.local_addr().unwrap()),
    );
    let d = make_publisher_with_scope(disputant, &["reduced.example.org"]);
    let (dispute_id, envelope) = sign_dispute(
        &d,
        json!({"wist_version": "1.0.0", "disputant": disputant, "label": label_id, "log": "log.example", "height": 0, "asserted_at": "2026-08-09T13:00:00Z"}),
    );
    let dir = d.dir.path().join(".well-known/wist/labels");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{}.json", &dispute_id[7..])),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    write_label_feed(
        &d,
        disputant,
        std::slice::from_ref(&dispute_id),
        "2026-08-09T13:00:00Z",
    );
    serve_static(listener, d.dir.path().to_path_buf());
    (client, dispute_id, d)
}

fn built() -> Built {
    let log = common::Rig::new();
    let (a, a_payload) = log.page("a", "withdrawable body");
    let (b, b_payload) = log.page("b", "kept body");
    let first = log.publish(
        &[(a.clone(), Some(a_payload)), (b.clone(), Some(b_payload))],
        "2026-08-09T12:00:00Z",
        None,
    );
    let label_id = add_label(&log.p, SUBJECT, "2026-08-09T12:00:00Z");
    write_label_feed(
        &log.p,
        &log.host,
        std::slice::from_ref(&label_id),
        "2026-08-09T12:00:00Z",
    );
    log.pull("2026-08-09T12:00:05Z");
    log.seal("2026-08-09T13:00:00Z");
    assert_eq!(log.db.sealed_labels().unwrap().len(), 1);

    let disputant = "disputant.localhost".to_owned();
    let (client, dispute_id, site) = serve_dispute(&disputant, &label_id);
    let pulled = clave::ingest::run(
        &log.db,
        &client,
        log.data.path(),
        &disputant,
        "2026-08-09T13:10:00Z",
    )
    .unwrap();
    assert_eq!(pulled.labels, vec![dispute_id.clone()]);
    let waiting_at_dispute = log.db.waiting_publishers().unwrap();
    let disputed = log.seal("2026-08-09T14:00:00Z");

    let withdrawn = common::item_id(&a);
    clave::governance::withdraw(
        &log.db,
        &log.sk,
        &log.host,
        &withdrawn,
        "court order",
        "DE",
        wist_core::timestamp::log_seconds("2026-08-09T14:30:00Z").unwrap(),
    )
    .unwrap();
    let waiting_at_withdrawal = log.db.waiting_publishers().unwrap();
    assert_eq!(log.seal("2026-08-09T15:00:00Z").entry_count, 1);

    let initial = current_declaration(&log.p);
    let mut successor = initial["publisher"].clone();
    successor["seq"] = 1.into();
    successor["prev_declaration"] = declaration_hash(&initial).into();
    successor["collections"] = json!([{"name": "default", "scope": [
        {"url": log.url("a"), "match": "exact"},
        {"url": log.url("c"), "match": "exact"},
    ]}]);
    write_declaration(&log.p, &successor, &K1_SEED);
    log.pull("2026-08-09T15:30:05Z");
    let conn = rusqlite::Connection::open(log.data.path().join("clave.sqlite")).unwrap();
    let narrowed_url = log.url("b");
    assert!(record_urls(&conn).contains(&narrowed_url));
    let narrowed = log.seal("2026-08-09T16:00:00Z");
    assert!(!record_urls(&conn).contains(&narrowed_url));

    let (c, c_payload) = log.page("c", "later body");
    log.publish(
        &[(a, None), (c, Some(c_payload))],
        "2026-08-09T16:30:00Z",
        Some(&first),
    );
    write_label_feed(
        &log.p,
        &log.host,
        std::slice::from_ref(&label_id),
        "2026-08-09T16:30:00Z",
    );
    let relisted = log.pull("2026-08-09T16:30:05Z");
    assert!(
        !relisted.labels.contains(&label_id),
        "{:?}",
        relisted.labels
    );
    let foreign_item = common::item_id(&b);
    queue_foreign_withdrawal(&log, &disputant, &foreign_item);
    let refused = log.seal("2026-08-09T17:00:00Z");
    log.seal("2026-08-09T18:00:00Z");
    Built {
        log,
        _site: site,
        label_id,
        dispute_id,
        disputant,
        withdrawn,
        disputed,
        waiting_at_dispute,
        waiting_at_withdrawal,
        narrowed_url,
        narrowed,
        foreign_item,
        refused,
    }
}

fn queue_foreign_withdrawal(log: &common::Rig, subject: &str, item_id: &str) {
    let update = json!({
        "wist_version": "1.0.0", "action": "payload_withdrawal", "subject": subject,
        "details": {"delta_id": item_id, "legal_basis": "court order", "jurisdiction": "DE"},
        "effective_at": "2026-08-09T16:40:00Z",
    });
    let kid = log.db.signing_key_id(&log.sk.public()).unwrap();
    let envelope = wist_core::envelope::sign_envelope(&update, "update", &kid, &log.sk).unwrap();
    log.db
        .insert_pending_entry("registry_update", "", &envelope, 0)
        .unwrap();
}

fn record_urls(conn: &rusqlite::Connection) -> BTreeSet<String> {
    conn.prepare("SELECT url FROM records")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn judgment_at(log: &common::Rig, height: u64, entry_type: &str) -> Option<Judgment> {
    let head = log.db.last_epoch().unwrap();
    let mut history = clave::history::History::open(&log.db, log.data.path(), head).unwrap();
    while let Some(verified) = history.next_epoch().unwrap() {
        if verified.epoch_number() != height {
            continue;
        }
        let index = verified
            .entries()
            .iter()
            .position(|entry| entry["type"] == entry_type)
            .unwrap_or_else(|| panic!("no {entry_type} Entry at height {height}"));
        return verified.judgments()[index].clone();
    }
    panic!("no Epoch at height {height}");
}

#[test]
fn a_dispute_naming_a_label_whose_labeler_has_no_waiting_work_is_judged_valid() {
    let built = built();
    assert!(!built.waiting_at_dispute.contains(&built.log.host));
    assert!(built.waiting_at_dispute.contains(&built.disputant));
    assert!(
        built.disputed.dropped.is_empty(),
        "{:?}",
        built.disputed.dropped
    );
    let disputes = built.log.db.sealed_disputes().unwrap();
    assert_eq!(disputes.len(), 1);
    assert_eq!(disputes[0].dispute.label, built.label_id);
    assert!(built
        .log
        .entries(1)
        .iter()
        .any(|entry| entry["type"] == "dispute"
            && wist_core::label::dispute_id(&entry["body"]["dispute"]).unwrap()
                == built.dispute_id));
    assert_eq!(judgment_at(&built.log, 1, "dispute"), Some(Judgment::Valid));
}

#[test]
fn a_withdrawal_whose_subject_has_no_waiting_work_is_judged_against_its_sealed_item() {
    let built = built();
    assert!(!built.waiting_at_withdrawal.contains(&built.log.host));
    assert!(built
        .log
        .entries(2)
        .iter()
        .any(|entry| entry["type"] == "registry_update"
            && entry["body"]["update"]["details"]["delta_id"] == built.withdrawn.as_str()));
    assert!(built.log.db.withdrawal_state().unwrap().contains(&(
        built.withdrawn.clone(),
        built.log.host.clone(),
        2
    )));
    assert_eq!(
        judgment_at(&built.log, 2, "registry_update"),
        Some(Judgment::Valid)
    );
}

fn page_source_rows(conn: &rusqlite::Connection) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let rows = |sql: &str| -> Vec<Vec<String>> {
        let mut statement = conn.prepare(sql).unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| {
                        Ok(match row.get_ref(index)? {
                            rusqlite::types::ValueRef::Blob(octets) => {
                                String::from_utf8_lossy(octets).into_owned()
                            }
                            other => format!("{other:?}"),
                        })
                    })
                    .collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    };
    (
        rows("SELECT domain, hash, epoch_number, ordinal, sealed_at_s, seq, keys_json FROM sealed_page_sources ORDER BY domain, hash, epoch_number"),
        rows("SELECT domain, hash, epoch_number FROM sealed_page_exclusions ORDER BY domain, hash"),
    )
}

#[test]
fn scoped_seals_persist_the_derived_state_a_full_replay_derives() {
    let built = built();
    let log = &built.log;
    let head = log.db.last_epoch().unwrap().unwrap();
    assert!(log
        .entries(3)
        .iter()
        .chain(log.entries(4).iter())
        .any(|entry| entry["type"] == "publisher_declaration"
            && entry["body"]["publisher"]["seq"] == 1));
    let declarations = log.db.derived_declarations(&head).unwrap().unwrap();
    let accepted = log.db.accepted_updates().unwrap();
    assert!(!accepted.is_empty());
    let conn = rusqlite::Connection::open(log.data.path().join("clave.sqlite")).unwrap();
    let sources = page_source_rows(&conn);
    assert!(!sources.0.is_empty());
    conn.execute_batch(
        "DELETE FROM sealed_page_sources; DELETE FROM sealed_page_exclusions; DELETE FROM sealed_page_sources_recorded;",
    )
    .unwrap();

    let rejected = rejected_flags(&conn);
    let records = stored_records(&conn);
    let removals = stored_removals(&conn);
    let sealed_items = stored_sealed_items(&conn);
    assert!(!records.is_empty());
    assert!(sealed_items.iter().any(|(_, _, _, height)| *height > 0));

    let mut full = clave::history::History::open(&log.db, log.data.path(), Some(head)).unwrap();
    let mut judged = Vec::new();
    while let Some(verified) = full.next_epoch().unwrap() {
        judged.push((verified.epoch_number(), verified.rejected().is_some()));
    }
    assert_eq!(rejected, judged);
    assert_eq!(rejected_flags(&conn), rejected);
    assert_eq!(
        serde_json::to_value(&declarations).unwrap(),
        serde_json::to_value(full.replay().declarations()).unwrap()
    );
    assert_eq!(accepted, full.replay().registry_updates().entries());
    assert_eq!(page_source_rows(&conn), sources);
    let replayed = full.replay().records();
    assert_eq!(
        records,
        replayed
            .records()
            .map(|(publisher, url, record)| (
                publisher.to_owned(),
                url.to_owned(),
                record.item.clone(),
                record.item_id.clone(),
                record.collection.clone(),
                record.catalog.clone(),
                record.generated_at.clone(),
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        removals,
        replayed
            .removals()
            .map(|(publisher, url, removal)| (
                publisher.to_owned(),
                url.to_owned(),
                removal.item_id.clone(),
                removal.catalog.clone(),
                removal.generated_at.clone(),
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        sealed_items,
        full.replay()
            .sealed_items()
            .sealed()
            .map(|sealed| (
                sealed.item_id.to_owned(),
                sealed.publisher.to_owned(),
                match sealed.kind {
                    wist_core::item::Kind::Page => "page".to_owned(),
                    wist_core::item::Kind::Removed => "removed".to_owned(),
                },
                sealed.height,
            ))
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn the_scenario_narrows_a_record_away_and_refuses_a_foreign_withdrawal_and_a_label_sealed_before() {
    let built = built();
    let log = &built.log;
    assert!(log
        .entries(built.narrowed.epoch_number)
        .iter()
        .any(|entry| entry["type"] == "publisher_declaration"
            && entry["body"]["publisher"]["seq"] == 1));
    assert!(
        !built
            .log
            .state()
            .records
            .contains_key(&(log.host.clone(), built.narrowed_url.clone())),
        "{:?}",
        built.narrowed.dropped
    );
    assert_eq!(
        built.refused.dropped,
        [format!(
            "WIST4-E04 payload_withdrawal {} is not sealed",
            built.foreign_item
        )]
    );
    let entries = log.entries(built.refused.epoch_number);
    assert!(!entries
        .iter()
        .any(|entry| entry["type"] == "registry_update"
            && entry["body"]["update"]["subject"] == built.disputant.as_str()));
    assert!(!entries.iter().any(|entry| entry["type"] == "label"));
    assert_eq!(log.db.sealed_labels().unwrap().len(), 1);
    assert_eq!(log.db.count_pending_entries("label").unwrap(), 0);
}

fn rejected_flags(conn: &rusqlite::Connection) -> Vec<(u64, bool)> {
    conn.prepare("SELECT epoch_number, rejected FROM epochs ORDER BY epoch_number")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

type StoredRecord = (String, String, Value, String, String, String, String);

fn stored_records(conn: &rusqlite::Connection) -> Vec<StoredRecord> {
    conn.prepare("SELECT publisher, url, item, item_id, collection, catalog_id, generated_at FROM records ORDER BY publisher, url")
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                serde_json::from_slice(&row.get::<_, Vec<u8>>(2)?).unwrap(),
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn stored_removals(conn: &rusqlite::Connection) -> Vec<(String, String, String, String, String)> {
    conn.prepare("SELECT publisher, url, item_id, catalog_id, generated_at FROM removals ORDER BY publisher, url")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn stored_sealed_items(conn: &rusqlite::Connection) -> BTreeSet<(String, String, String, u64)> {
    conn.prepare("SELECT item_id, publisher, kind, first_height FROM sealed_items")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn a_scoped_replay_carries_the_accepted_registry_updates_of_its_state() {
    let mut state = clave::collection::State {
        height: Some(3),
        ..Default::default()
    };
    state.declarations.seed_head(3, "root", Some(1_786_276_800));
    state.withdrawals.adopt("sha256:withdrawn", "p.example", 2);
    state.withdrawals.accept_update("sha256:update", 2);
    let replay = clave::collection::plan::scoped_replay(&state, &BTreeSet::new()).unwrap();
    assert_eq!(replay.next_height(), 4);
    assert_eq!(
        replay.registry_updates().entries(),
        state.withdrawals.accepted_updates().entries()
    );
    assert_eq!(
        replay.registry_updates().accepted_height("sha256:update"),
        Some(2)
    );
    assert!(replay.withdrawals().is_withdrawn("sha256:withdrawn"));
}

#[test]
fn a_history_resumed_without_records_judges_only_under_an_adopted_replay_at_its_height() {
    let log = common::Rig::new();
    log.pull("2026-08-09T12:00:05Z");
    log.seal("2026-08-09T13:00:00Z");
    let mut light =
        clave::history::History::resume_without_records(&log.db, log.data.path()).unwrap();
    assert!(light.next_epoch().is_err());

    let mut light =
        clave::history::History::resume_without_records(&log.db, log.data.path()).unwrap();
    assert!(light
        .adopt_replay(wist_core::sealing::Replay::new())
        .is_err());
    let state = log.state();
    light
        .adopt_replay(clave::collection::plan::scoped_replay(&state, &BTreeSet::new()).unwrap())
        .unwrap();
    assert!(light.next_epoch().unwrap().is_none());
}

#[test]
fn a_seal_persists_derived_declarations_headed_at_its_real_root() {
    let log = common::Rig::new();
    log.pull("2026-08-09T12:00:05Z");
    log.seal("2026-08-09T13:00:00Z");
    log.seal("2026-08-09T14:00:00Z");
    let head = log.db.last_epoch().unwrap().unwrap();
    assert!(head.epoch_number > 0);
    let declarations = log.db.derived_declarations(&head).unwrap().unwrap();
    assert_eq!(
        declarations.head(),
        Some((head.epoch_number, head.root.as_str()))
    );
    assert_ne!(head.root, "candidate");
}
