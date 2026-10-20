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
        &[(a.clone(), Some(a_payload)), (b, Some(b_payload))],
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
    write_declaration(&log.p, &successor, &K1_SEED);
    let (c, c_payload) = log.page("c", "later body");
    log.publish(
        &[(a, None), (c, Some(c_payload))],
        "2026-08-09T15:30:00Z",
        Some(&first),
    );
    log.pull("2026-08-09T15:30:05Z");
    for at in [
        "2026-08-09T16:00:00Z",
        "2026-08-09T17:00:00Z",
        "2026-08-09T18:00:00Z",
    ] {
        log.seal(at);
    }
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
    }
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

    let mut full = clave::history::History::open(&log.db, log.data.path(), Some(head)).unwrap();
    while full.next_epoch().unwrap().is_some() {}
    assert_eq!(
        serde_json::to_value(&declarations).unwrap(),
        serde_json::to_value(full.replay().declarations()).unwrap()
    );
    assert_eq!(accepted, full.replay().registry_updates().entries());
    assert_eq!(page_source_rows(&conn), sources);
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
