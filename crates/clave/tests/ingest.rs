mod common;

use common::{make_publisher, make_publisher_with_scope, reserve_addr, serve_static};

#[test]
fn ingest_onboard_failure_is_e04_noise() {
    let (listener, host, client) = reserve_addr();
    let empty = tempfile::tempdir().unwrap();
    serve_static(listener, empty.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();

    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:05Z").unwrap();
    assert_eq!(report.noise, Some("WIST2-E04"));
}

#[test]
fn a_redirect_chain_that_revisits_a_url_stops_at_the_repeat() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);

    let server = std::thread::spawn(move || {
        listener
            .set_nonblocking(false)
            .expect("blocking accept loop");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            let body = format!("HTTP/1.1 302 Found\r\nLocation: http://{addr}/loop.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });

    let client = clave::fetch::Client::new(true);
    let err = client
        .get_json(&format!("http://{addr}/loop.json"))
        .unwrap_err();
    assert!(
        err.to_string().contains("already fetched"),
        "unexpected error {err}"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the chain must stop at the repeat, not run to the hop bound"
    );
    drop(server);
}

/// WIST-2 §4: only a Ping's own pull can cost its Registrable Domain
/// noise, counted under the unit and UTC day in force at the Ping.
#[test]
fn only_a_pulls_own_ping_is_charged_noise_and_at_the_instant_it_was_received() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher_with_scope(&host, &["example.com"]);
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let all = clave::db::PARTITIONS as usize;
    let now = jiff::Timestamp::now().as_second();
    let day = |unix: i64| jiff::Timestamp::from_second(unix).unwrap().to_string()[..10].to_string();

    let onboarded = jiff::Timestamp::from_second(now - 2 * 86_400)
        .unwrap()
        .to_string();
    clave::ingest::run(&db, &client, tmp.path(), &host, &onboarded).unwrap();
    let pinged_at = now - 86_400;
    db.schedule_ping(&host, pinged_at, 4).unwrap();
    let task = db
        .claim_pulls(now, 1, "me", all, &[], &mut true, true)
        .unwrap()
        .remove(0);
    assert_eq!(task.pinged_at, Some(pinged_at));
    let pull = |task: &clave::db::PullTask, at: i64| {
        let now = jiff::Timestamp::from_second(at).unwrap().to_string();
        let run = clave::ingest::open_pull(
            &db,
            &client,
            tmp.path(),
            &host,
            &now,
            jiff::Timestamp::now,
            clave::ingest::PullLimits::default(),
        )
        .unwrap();
        clave::ingest::finish_pull(&db, task, "me", at, run, at).unwrap()
    };

    let report = pull(&task, now);
    assert_eq!(report.noise, Some("WIST2-E02"));
    assert_eq!(
        db.noise_ping_count(&host, &day(pinged_at)).unwrap(),
        1,
        "the noise is counted on the day of the Ping it answered"
    );
    assert_eq!(db.noise_ping_count(&host, &day(now)).unwrap(), 0);

    let baseline = db.scheduled_pull(&host).unwrap().unwrap();
    assert_eq!(baseline.reason, clave::db::Reason::Baseline);
    assert_eq!(baseline.pinged_at, None);
    let later = baseline.due_at;
    let task = db
        .claim_pulls(later, 1, "me", all, &[], &mut false, true)
        .unwrap()
        .remove(0);
    assert_eq!(task.pinged_at, None);
    assert_eq!(pull(&task, later).noise, Some("WIST2-E02"));
    for at in [pinged_at, now, later] {
        assert_eq!(
            db.noise_ping_count(&host, &day(at)).unwrap(),
            i64::from(at == pinged_at),
            "a baseline poll no Ping asked for counts against no quota"
        );
    }
}

#[test]
fn a_label_feed_regressed_at_wist2_e05_keeps_the_baseline_schedule() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let started_at = jiff::Timestamp::now().as_second();
    let at = |unix: i64| jiff::Timestamp::from_second(unix).unwrap().to_string();
    serve_static(listener, p.dir.path().to_path_buf());

    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    let all = clave::db::PARTITIONS as usize;
    let baseline = 3600;
    db.set_param("baseline_poll_seconds", baseline).unwrap();
    let pull = |started_at: i64| {
        db.schedule_ping(&host, started_at, 4).unwrap();
        let task = db
            .claim_pulls(started_at, 1, "me", all, &[], &mut true, true)
            .unwrap()
            .remove(0);
        let run = clave::ingest::open_pull(
            &db,
            &client,
            tmp.path(),
            &host,
            &at(started_at),
            jiff::Timestamp::now,
            clave::ingest::PullLimits::default(),
        )
        .unwrap();
        clave::ingest::finish_pull(&db, &task, "me", started_at, run, started_at + 5).unwrap()
    };
    common::write_label_feed(&p, &host, &[], &at(started_at - 60));
    assert_eq!(pull(started_at).ended, None);

    common::write_label_feed(&p, &host, &[], &at(started_at - 600));
    let regressed_at = started_at + baseline;
    assert_eq!(pull(regressed_at).ended, None);
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E05");
    let next = db.scheduled_pull(&host).unwrap().unwrap();
    assert_eq!(next.reason, clave::db::Reason::Baseline);
    assert_eq!(next.attempts, 0);
    assert_eq!(next.due_at, regressed_at + baseline);
}

#[test]
fn a_declaration_fetch_that_fails_after_first_contact_stops_the_pull_at_wist2_e01() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    common::write_label_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    std::fs::remove_file(p.dir.path().join(".well-known/wist/publisher.json")).unwrap();
    requests.lock().unwrap().clear();
    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:10:00Z").unwrap();
    assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
    assert_eq!(report.noise, None);
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        ["/.well-known/wist/publisher.json"],
        "no Label Feed is read in a pull stopped at its Declaration"
    );
    assert_eq!(db.list_rejections(&host).unwrap()[0].code, "WIST2-E01");
}

#[test]
fn a_refused_declaration_stops_the_pull_at_wist2_e01_after_recording_its_code() {
    let (listener, host, client) = reserve_addr();
    let p = make_publisher(&host);
    let requests = common::serve_recording(listener, p.dir.path().to_path_buf());
    common::write_label_feed(&p, &host, &[], "2026-08-09T12:00:00Z");
    let tmp = tempfile::tempdir().unwrap();
    clave::init::run(&host, tmp.path()).unwrap();
    let db = clave::db::Db::open(&tmp.path().join("clave.sqlite")).unwrap();
    clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:00:00Z").unwrap();

    let mut same_seq = common::current_declaration(&p)["publisher"].clone();
    same_seq["contact"] = "mailto:other@example.com".into();
    common::write_declaration(&p, &same_seq, &common::K1_SEED);
    requests.lock().unwrap().clear();
    let report =
        clave::ingest::run(&db, &client, tmp.path(), &host, "2026-08-09T12:10:00Z").unwrap();
    assert_eq!(report.ended.as_deref(), Some("WIST2-E01"));
    let codes: Vec<String> = db
        .list_rejections(&host)
        .unwrap()
        .into_iter()
        .map(|rejection| rejection.code)
        .collect();
    assert_eq!(codes, ["WIST2-E01", "WIST1-E08"]);
    assert_eq!(
        requests.lock().unwrap().as_slice(),
        ["/.well-known/wist/publisher.json"]
    );
}
