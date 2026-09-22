mod common;

use clave::db::Db;
use common::{
    add_delta_signed, make_publisher, reserve_addr, serve_recording, write_feed, K1_SEED,
};
use std::path::Path;

const DAY: i64 = 86_400;
/// An instant on the Epoch cadence grid every seal in this file sits on.
const SEAL_START: i64 = 1_786_276_800;
const CADENCE: i64 = 3_600;

fn instant(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).unwrap().to_string()
}

fn file_len(p: &common::TestPub, rel: &str) -> i64 {
    std::fs::metadata(p.dir.path().join(".well-known/wist").join(rel))
        .unwrap()
        .len() as i64
}

/// The octets one Delta costs the budget: its file and its Payload.
fn item_len(p: &common::TestPub, id: &str) -> i64 {
    file_len(p, &format!("deltas/{}.json", &id[7..]))
        + file_len(p, &format!("payloads/{}.json", &id[7..]))
}

/// Pulls `host` with a clock standing at `before` until `first` is
/// accepted and at `after` from then on, so every request after it is
/// issued on the far side of the crossing.
fn pull_across(
    db: &Db,
    client: &clave::fetch::Client,
    data: &Path,
    host: &str,
    first: &str,
    before: &str,
    after: &str,
) -> clave::ingest::IngestReport {
    clave::ingest::run_with_clock(db, client, data, host, before, || {
        if db.is_delta_seen_for(first, host).unwrap() {
            after
        } else {
            before
        }
        .parse()
        .unwrap()
    })
    .unwrap()
}

fn open_log(host: &str, data: &Path) -> Db {
    clave::init::run(host, data).unwrap();
    Db::open(&data.join("clave.sqlite")).unwrap()
}

#[test]
fn a_fetch_after_midnight_utc_is_metered_on_the_new_day() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let before = "2026-08-09T23:59:59Z";
    let after = "2026-08-10T00:00:00Z";
    let first = add_delta_signed(&p, "https://localhost/a", "first", None, before, &K1_SEED);
    let second = add_delta_signed(&p, "https://localhost/b", "second", None, before, &K1_SEED);
    write_feed(&p, &host, &[first.clone(), second.clone()], before);
    serve_recording(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    let db = open_log(&host, data.path());
    let spent_before = file_len(&p, "feed.json") + item_len(&p, &first);
    db.set_param("ingest_budget_bytes_day", spent_before)
        .unwrap();

    let report = pull_across(&db, &client, data.path(), &host, &first, before, after);
    assert_eq!(report.accepted, [first, second.clone()], "{report:?}");
    assert!(
        !report.suspended,
        "a budget the day before spent does not suspend a request issued on the next day"
    );
    assert_eq!(
        db.ingest_bytes(&host, &before[..10]).unwrap(),
        spent_before,
        "the requests issued before midnight stay debited to that day"
    );
    assert_eq!(
        db.ingest_bytes(&host, &after[..10]).unwrap(),
        item_len(&p, &second),
        "the requests issued after midnight are debited to the new day"
    );
}

#[test]
fn a_fetch_after_a_budget_change_is_metered_under_the_budget_in_force_at_it() {
    let sealed_at = SEAL_START;
    let after = instant(sealed_at + 8 * DAY);
    let before = instant(sealed_at + 8 * DAY - 1);
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add_delta_signed(&p, "https://localhost/a", "first", None, &before, &K1_SEED);
    let second = add_delta_signed(&p, "https://localhost/b", "second", None, &before, &K1_SEED);
    write_feed(&p, &host, &[first.clone(), second.clone()], &before);
    serve_recording(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    let db = open_log(&host, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let spent_before = file_len(&p, "feed.json") + item_len(&p, &first);
    db.set_param("ingest_budget_bytes_day", spent_before)
        .unwrap();
    clave::param_change::run(
        &db,
        &sk,
        "ingest_budget_bytes_day",
        1 << 30,
        Some(&after),
        sealed_at,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, sealed_at).unwrap();

    let report = pull_across(&db, &client, data.path(), &host, &first, &before, &after);
    assert_eq!(report.accepted, [first, second.clone()], "{report:?}");
    assert!(
        !report.suspended,
        "a request issued after the raise is metered under the raised budget"
    );
    assert_eq!(
        db.ingest_bytes(&host, &before[..10]).unwrap(),
        spent_before + item_len(&p, &second)
    );
}

#[test]
fn a_fetch_after_a_response_bound_change_is_read_to_the_bound_in_force_at_it() {
    let sealed_at = SEAL_START;
    let after = instant(sealed_at + 8 * DAY);
    let before = instant(sealed_at + 8 * DAY - 1);
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let first = add_delta_signed(&p, "https://localhost/a", "first", None, &before, &K1_SEED);
    let large = add_delta_signed(
        &p,
        "https://localhost/b",
        &"x".repeat(60_000),
        None,
        &before,
        &K1_SEED,
    );
    write_feed(&p, &host, &[first.clone(), large.clone()], &before);
    serve_recording(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    let db = open_log(&host, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    clave::param_change::run(
        &db,
        &sk,
        "extract_cap_bytes",
        131_072,
        Some(&after),
        sealed_at,
    )
    .unwrap();
    clave::seal::run(&db, data.path(), &sk, sealed_at).unwrap();
    assert!(
        file_len(&p, &format!("payloads/{}.json", &large[7..]))
            > clave::payload::cap_bytes(&clave::declaration::delta::SizeCaps::from_schedule(
                &db.parameter_schedule(sealed_at).unwrap(),
                before.parse::<jiff::Timestamp>().unwrap().as_second(),
            )) as i64,
        "the Payload is above the bound in force before the change and below the one after it"
    );

    let report = pull_across(&db, &client, data.path(), &host, &first, &before, &after);
    assert_eq!(
        report.accepted,
        [first.clone(), large.clone()],
        "{report:?}"
    );
    assert!(report.rejected.is_empty(), "{report:?}");
    assert_eq!(
        db.ingest_bytes(&host, &before[..10]).unwrap(),
        file_len(&p, "feed.json") + item_len(&p, &first) + item_len(&p, &large),
        "the Payload read to the raised bound is debited whole"
    );
}

const WITHOUT_SUBDOMAIN: &str = "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n";
const WITH_SUBDOMAIN: &str = "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\nsub.localhost\n// ===END PRIVATE DOMAINS===\n";

#[test]
fn a_fetch_after_a_suffix_list_update_is_debited_to_the_unit_in_force_at_it() {
    let before = instant(SEAL_START + CADENCE - 1);
    let after = instant(SEAL_START + CADENCE);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve("a.sub.localhost", addr),
    );
    let host = "a.sub.localhost";
    let p = make_publisher(host);
    let first = add_delta_signed(
        &p,
        "https://a.sub.localhost/a",
        "first",
        None,
        &before,
        &K1_SEED,
    );
    let second = add_delta_signed(
        &p,
        "https://a.sub.localhost/b",
        "second",
        None,
        &before,
        &K1_SEED,
    );
    write_feed(&p, host, &[first.clone(), second.clone()], &before);
    serve_recording(listener, p.dir.path().into());
    let data = tempfile::tempdir().unwrap();
    let db = open_log("log.example", data.path());
    db.set_param("epoch_cadence_seconds", 1).unwrap();
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    for (octets, seal) in [
        (WITHOUT_SUBDOMAIN, SEAL_START),
        (WITH_SUBDOMAIN, SEAL_START + CADENCE),
    ] {
        let file = data.path().join(format!("{seal}.dat"));
        std::fs::write(&file, octets).unwrap();
        clave::suffix_list::pin(&db, data.path(), &sk, &file, seal - 1).unwrap();
        clave::seal::run(&db, data.path(), &sk, seal).unwrap();
    }
    assert_eq!(
        clave::suffix_list::unit_at(&db, host, &before).unwrap(),
        "sub.localhost"
    );
    assert_eq!(
        clave::suffix_list::unit_at(&db, host, &after).unwrap(),
        "a.sub.localhost"
    );

    let report = pull_across(&db, &client, data.path(), host, &first, &before, &after);
    assert_eq!(
        report.accepted,
        [first.clone(), second.clone()],
        "{report:?}"
    );
    assert_eq!(
        db.ingest_bytes("sub.localhost", &before[..10]).unwrap(),
        file_len(&p, "feed.json") + item_len(&p, &first),
        "the requests issued under the earlier snapshot stay debited to the unit it named"
    );
    assert_eq!(
        db.ingest_bytes("a.sub.localhost", &after[..10]).unwrap(),
        item_len(&p, &second),
        "the requests issued under the accepted snapshot are debited to the unit it names"
    );
}
