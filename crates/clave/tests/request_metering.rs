mod common;

use clave::db::Db;
use common::{make_publisher, page_item, publish_collection, reserve_addr, serve_recording};
use std::path::Path;
use std::sync::{Arc, Mutex};

const DAY: i64 = 86_400;
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

struct Site {
    first: String,
    second: String,
    walked: i64,
    requests: Arc<Mutex<Vec<String>>>,
}

fn payload_file(item: &serde_json::Value) -> String {
    format!(
        "collections/default/payloads/{}.json",
        wist_core::item::payload_name(item).unwrap()
    )
}

fn site(p: &common::TestPub, listener: std::net::TcpListener, at: &str) -> Site {
    let host = p.domain.clone();
    let items: Vec<_> = ["a", "b"]
        .iter()
        .map(|name| page_item(p, &format!("https://{host}/{name}"), name))
        .collect();
    let published = publish_collection(
        p,
        "default",
        &items
            .iter()
            .map(|(item, payload)| (item.clone(), Some(payload.clone())))
            .collect::<Vec<_>>(),
        at,
        None,
    );
    let mut order: Vec<&serde_json::Value> = items.iter().map(|(item, _)| item).collect();
    order.sort_by_key(|item| wist_core::item::key(item["url"].as_str().unwrap()));
    let walked = file_len(p, "collections/default/catalog.json")
        + published
            .tree
            .keys()
            .map(|hex| file_len(p, &format!("collections/default/tree/{hex}")))
            .sum::<i64>();
    let requests = serve_recording(listener, p.dir.path().into());
    Site {
        first: payload_file(order[0]),
        second: payload_file(order[1]),
        walked,
        requests,
    }
}

fn pull_across(
    db: &Db,
    client: &clave::fetch::Client,
    data: &Path,
    host: &str,
    site: &Site,
    before: &str,
    after: &str,
) -> clave::ingest::IngestReport {
    let first = format!("/.well-known/wist/{}", site.first);
    clave::ingest::run_with_clock(db, client, data, host, before, || {
        if site.requests.lock().unwrap().contains(&first) {
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
    let site = site(&p, listener, "2026-08-09T12:00:00Z");
    let data = tempfile::tempdir().unwrap();
    let db = open_log(&host, data.path());
    let spent_before = site.walked + file_len(&p, &site.first);
    db.set_param("ingest_budget_bytes_day", spent_before)
        .unwrap();

    let report = pull_across(&db, &client, data.path(), &host, &site, before, after);
    assert_eq!(report.items.len(), 2, "{report:?}");
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
        file_len(&p, &site.second),
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
    let site = site(&p, listener, "2026-08-09T12:00:00Z");
    let data = tempfile::tempdir().unwrap();
    let db = open_log(&host, data.path());
    let sk = clave::keys::load(&data.path().join("keys/seed")).unwrap();
    let spent_before = site.walked + file_len(&p, &site.first);
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

    let report = pull_across(&db, &client, data.path(), &host, &site, &before, &after);
    assert_eq!(report.items.len(), 2, "{report:?}");
    assert!(
        !report.suspended,
        "a request issued after the raise is metered under the raised budget"
    );
    assert_eq!(
        db.ingest_bytes(&host, &before[..10]).unwrap(),
        spent_before + file_len(&p, &site.second)
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
    let site = site(&p, listener, "2026-08-09T12:00:00Z");
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

    let report = pull_across(&db, &client, data.path(), host, &site, &before, &after);
    assert_eq!(report.items.len(), 2, "{report:?}");
    assert_eq!(
        db.ingest_bytes("sub.localhost", &before[..10]).unwrap(),
        site.walked + file_len(&p, &site.first),
        "the requests issued under the earlier snapshot stay debited to the unit it named"
    );
    assert_eq!(
        db.ingest_bytes("a.sub.localhost", &after[..10]).unwrap(),
        file_len(&p, &site.second),
        "the requests issued under the accepted snapshot are debited to the unit it names"
    );
}
