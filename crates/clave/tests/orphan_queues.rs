mod common;

use std::collections::BTreeSet;

use clave::collection::state::{Discovered, Place, QueuedCatalog, RecoveryQueue};
use clave::collection::State;
use common::{make_publisher, serve_static, TestPub};
use serde_json::json;

const AT: &str = "2026-08-09T12:00:00Z";
const NOW: &str = "2026-08-09T13:00:00Z";
const QUEUED: &str = "sha256:queued";

fn queue(owner: &str, end_s: Option<i128>) -> RecoveryQueue {
    let mut queue = RecoveryQueue {
        owner: owner.into(),
        end_s,
        ..RecoveryQueue::default()
    };
    queue.queued.insert(
        ("default".into(), "key".into()),
        QueuedCatalog {
            envelope: json!({"catalog": {"generated_at": AT}}),
            catalog_id: QUEUED.into(),
            place: Place::catalog(0, 0),
            sources: Vec::new(),
        },
    );
    queue.first.insert("default".into(), Place::catalog(0, 0));
    queue
}

fn discovered(hash: &str) -> Discovered {
    Discovered {
        envelope: json!({}),
        hash: hash.into(),
        event: 0,
        last_sealed_at_discovery: None,
        reduces_authority: false,
        last_seal_height: None,
        competitor: false,
        competes_with: None,
    }
}

fn store(db: &clave::db::Db, after: &State) {
    let publishers: BTreeSet<String> = after.queues.keys().cloned().collect();
    db.store_state(&State::default(), after, &publishers, AT)
        .unwrap();
}

#[test]
fn the_pull_scope_holds_the_host_and_only_the_publishers_whose_queue_is_an_orphan() {
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.localhost", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let mut state = State::default();
    state
        .queues
        .insert("opened.localhost".into(), queue("sha256:opened", Some(1)));
    state
        .queues
        .insert("found.localhost".into(), queue("sha256:found", None));
    state.discovered.insert(
        "found.localhost".into(),
        vec![discovered("sha256:other"), discovered("sha256:found")],
    );
    state
        .queues
        .insert("orphan.localhost".into(), queue("sha256:gone", None));
    state
        .discovered
        .insert("orphan.localhost".into(), vec![discovered("sha256:other")]);
    store(&db, &state);
    assert_eq!(
        db.pull_scope("host.localhost").unwrap(),
        BTreeSet::from(["host.localhost".to_owned(), "orphan.localhost".to_owned()])
    );
    assert_eq!(
        db.pull_scope("orphan.localhost").unwrap(),
        BTreeSet::from(["orphan.localhost".to_owned()])
    );
}

struct Sites {
    _a: TestPub,
    _b: TestPub,
    client: clave::fetch::Client,
    data: tempfile::TempDir,
    db: clave::db::Db,
}

const A: &str = "a.localhost";
const B: &str = "b.localhost";

fn sites_with_an_orphan_of_a() -> Sites {
    let a_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let b_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = clave::fetch::Client::with_builder(
        true,
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve(A, a_listener.local_addr().unwrap())
            .resolve(B, b_listener.local_addr().unwrap()),
    );
    let a = make_publisher(A);
    let b = make_publisher(B);
    serve_static(a_listener, a.dir.path().to_path_buf());
    serve_static(b_listener, b.dir.path().to_path_buf());
    let data = tempfile::tempdir().unwrap();
    clave::init::run("log.localhost", data.path()).unwrap();
    let db = clave::db::Db::open(&data.path().join("clave.sqlite")).unwrap();
    let mut state = State::default();
    state.queues.insert(A.into(), queue("sha256:gone", None));
    store(&db, &state);
    Sites {
        _a: a,
        _b: b,
        client,
        data,
        db,
    }
}

fn settlement_of_a(sites: &Sites) -> Vec<Vec<String>> {
    let conn = rusqlite::Connection::open(sites.data.path().join("clave.sqlite")).unwrap();
    [
        "SELECT * FROM catalog_queues WHERE publisher = ?1",
        "SELECT * FROM catalog_queue WHERE publisher = ?1",
        "SELECT * FROM catalog_queue_first WHERE publisher = ?1",
        "SELECT code, at, id, detail, collection, urls_json, condition, change_list FROM rejections WHERE domain = ?1 AND id = ?2",
    ]
    .iter()
    .flat_map(|sql| {
        let mut statement = conn.prepare(sql).unwrap();
        let columns = statement.column_count();
        let parameters: &[&dyn rusqlite::ToSql] = if sql.contains("?2") {
            &[&A, &QUEUED]
        } else {
            &[&A]
        };
        statement
            .query_map(parameters, |row| {
                (0..columns)
                    .map(|index| Ok(format!("{:?}", row.get::<_, rusqlite::types::Value>(index)?)))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

#[test]
fn a_pull_of_another_host_settles_an_orphan_queue_as_a_pull_of_its_owner_would() {
    let by_b = sites_with_an_orphan_of_a();
    common::pull_at(&by_b.db, &by_b.client, by_b.data.path(), B, NOW);
    let by_a = sites_with_an_orphan_of_a();
    common::pull_at(&by_a.db, &by_a.client, by_a.data.path(), A, NOW);
    let settled = settlement_of_a(&by_b);
    let text = |value: &str| format!("{:?}", rusqlite::types::Value::Text(value.into()));
    assert_eq!(settled.len(), 1);
    assert_eq!(settled[0][0], text(clave::collection::queue::REJECTED));
    assert_eq!(settled[0][2], text(QUEUED));
    assert_eq!(settled, settlement_of_a(&by_a));
}
