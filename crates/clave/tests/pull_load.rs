mod common;

use common::{add_delta, make_publisher_with_scope, reserve_addr, serve_static, write_feed};

const MIB: f64 = 1_048_576.0;

fn pull(
    db: &clave::db::Db,
    client: &clave::fetch::Client,
    data_dir: &std::path::Path,
    host: &str,
    started_at: i64,
    ended_at: i64,
) -> clave::ingest::IngestReport {
    db.schedule_ping(host, started_at, 4).unwrap();
    let task = db
        .claim_pulls(
            started_at,
            1,
            "me",
            clave::db::PARTITIONS as usize,
            &[],
            &mut true,
            true,
        )
        .unwrap()
        .remove(0);
    let run = clave::ingest::open_pull(
        db,
        client,
        data_dir,
        host,
        &clave::registry::instant(started_at).unwrap(),
        jiff::Timestamp::now,
        clave::ingest::PullLimits::default(),
    )
    .unwrap();
    clave::ingest::finish_pull(db, &task, "me", started_at, run, ended_at).unwrap()
}

#[test]
fn a_pulls_cost_is_its_wall_seconds_plus_its_fetched_mebibytes() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    let id = add_delta(&p, "https://example.com/a", "alpha body", None);
    write_feed(&p, &host, std::slice::from_ref(&id), "2026-08-09T12:00:00Z");
    serve_static(listener, p.dir.path().to_path_buf());
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let started_at = jiff::Timestamp::now().as_second();
    let day = &clave::registry::instant(started_at).unwrap()[..10];

    let first = pull(&db, &client, tmp.path(), &host, started_at, started_at);
    assert_eq!(first.accepted, vec![id]);
    let metered = db.ingest_bytes(&host, day).unwrap();
    assert!(metered > 0);
    assert_eq!(first.fetched_bytes, metered as u64);
    let score = first.fetched_bytes as f64 / MIB;
    assert_eq!(db.pull_load_score(&host).unwrap(), Some(score));

    let second = pull(&db, &client, tmp.path(), &host, started_at, started_at + 10);
    assert_eq!(
        second.fetched_bytes,
        (db.ingest_bytes(&host, day).unwrap() - metered) as u64
    );
    let cost = 10.0 + second.fetched_bytes as f64 / MIB;
    assert_eq!(
        db.pull_load_score(&host).unwrap(),
        Some((score + cost) / 2.0)
    );
}
