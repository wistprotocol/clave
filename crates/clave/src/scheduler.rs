use crate::db::{Db, Fence, SEALER_LEASE_SECONDS};
use crate::error::{Error, Result};
use crate::fetch::Client;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_GRACE_SECONDS: i64 = 60;
const RETRY_AFTER_READ_FAILURE: Duration = Duration::from_secs(1);
const LEASE_RENEWAL_SECONDS: i64 = SEALER_LEASE_SECONDS / 3;
const RETRY_INTERVAL_SECONDS: i64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Attempt {
    instant: i64,
    at: i64,
}

/// Instants are Unix seconds on the cadence grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    SealNow(i64),
    SleepUntil(i64),
}

pub fn grace(cadence: i64) -> i64 {
    (cadence / 2).min(MAX_GRACE_SECONDS)
}

/// WIST-3 §3.2: a missed instant is skipped, never sealed late.
pub fn next_seal(last_sealed_unix: Option<i64>, cadence: i64, now_unix: i64) -> Decision {
    let instant = now_unix.div_euclid(cadence) * cadence;
    if last_sealed_unix.is_none_or(|last| instant > last) && now_unix - instant <= grace(cadence) {
        return Decision::SealNow(instant);
    }
    let floor = last_sealed_unix.map_or(instant, |last| last.max(instant));
    Decision::SleepUntil((floor.div_euclid(cadence) + 1) * cadence)
}

fn grid(db: &Db, now_unix: i64) -> Result<(Option<i64>, i64)> {
    let last = db
        .last_epoch()?
        .map(|epoch| crate::registry::unix(&epoch.sealed_at))
        .transpose()?;
    let at = crate::registry::instant(last.unwrap_or(now_unix))?;
    let cadence = crate::registry::effective(db, "epoch_cadence_seconds", &at)?;
    if cadence <= 0 {
        return Err(Error::Seal("epoch_cadence_seconds must be positive".into()));
    }
    Ok((last, cadence))
}

fn seal_at(
    db_path: &Path,
    data_dir: &Path,
    client: &Client,
    instant: i64,
    owner: &str,
    token: i64,
    confirmed: &mut HashSet<String>,
) -> Result<()> {
    let db = Db::connect(db_path)?.fenced(Fence::Sealer { token });
    let (_, sk) = crate::keys::head_signer(data_dir, &db)?;
    let report = crate::seal::under_renewed_lease(
        db_path,
        owner,
        token,
        crate::seal::LeaseTerms::default(),
        || crate::seal::run_confirming(&db, data_dir, &sk, client, instant, confirmed),
    )?;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "sealed epoch {} with {} entries at {}",
        report.epoch_number,
        report.entry_count,
        crate::registry::instant(instant)?
    );
    for reason in &report.dropped {
        let _ = writeln!(out, "dropped: {reason}");
    }
    for late in &report.late {
        let _ = writeln!(out, "late inclusion: {late}");
    }
    let _ = out.flush();
    Ok(())
}

fn report_failure(what: &str, err: impl std::fmt::Display) {
    let _ = writeln!(std::io::stderr(), "{what}: {err}");
}

fn finish_publications(db_path: &Path, data_dir: &Path, owner: &str, token: i64) -> Result<()> {
    let db = Db::connect(db_path)?.fenced(Fence::Sealer { token });
    if db.unpublished_publications()?.is_empty() && db.pending_removals()?.is_empty() {
        return Ok(());
    }
    crate::seal::under_renewed_lease(
        db_path,
        owner,
        token,
        crate::seal::LeaseTerms::default(),
        || crate::publication::finish_committed(&db, data_dir),
    )?;
    Ok(())
}

fn pass(
    db_path: &Path,
    data_dir: &Path,
    owner: &str,
    now_unix: i64,
    attempt: Option<Attempt>,
    seal: impl FnOnce(i64, i64) -> Result<()>,
) -> Result<(i64, Option<Attempt>)> {
    let db = Db::connect(db_path)?;
    let Some(token) = db.hold_sealer_lease(owner, now_unix)? else {
        return Ok((now_unix + LEASE_RENEWAL_SECONDS, attempt));
    };
    finish_publications(db_path, data_dir, owner, token)?;
    let (last, cadence) = grid(&db, now_unix)?;
    match next_seal(last, cadence, now_unix) {
        Decision::SleepUntil(instant) => {
            Ok((instant.min(now_unix + LEASE_RENEWAL_SECONDS), attempt))
        }
        Decision::SealNow(instant) => {
            if let Some(previous) = attempt.filter(|previous| previous.instant == instant) {
                let due = previous.at + RETRY_INTERVAL_SECONDS;
                if now_unix < due {
                    return Ok((due, attempt));
                }
            }
            if let Err(err) = seal(instant, token) {
                report_failure(&format!("seal at Unix second {instant}"), err);
            }
            Ok((
                now_unix,
                Some(Attempt {
                    instant,
                    at: now_unix,
                }),
            ))
        }
    }
}

async fn sleep_until(instant: i64) {
    let wait = instant
        .saturating_mul(1000)
        .saturating_sub(jiff::Timestamp::now().as_millisecond());
    if let Ok(wait) = u64::try_from(wait) {
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
}

/// WIST-3 §3.2: a failed seal is retried while its instant's grace lasts
/// and never sealed late.
pub async fn run(
    db_path: PathBuf,
    data_dir: PathBuf,
    client: Arc<Client>,
    owner: Arc<str>,
    sealed: Arc<tokio::sync::Notify>,
) {
    let mut attempt: Option<Attempt> = None;
    let confirmed = Arc::new(Mutex::new(HashSet::new()));
    loop {
        let (store, data, client, holder, sealed, confirmed) = (
            db_path.clone(),
            data_dir.clone(),
            client.clone(),
            owner.clone(),
            sealed.clone(),
            confirmed.clone(),
        );
        let passed = tokio::task::spawn_blocking(move || {
            let now_unix = jiff::Timestamp::now().as_second();
            pass(
                &store,
                &data,
                &holder,
                now_unix,
                attempt,
                |instant, token| {
                    let mut confirmed = confirmed.lock().unwrap_or_else(|poisoned| {
                        let mut forgotten = poisoned.into_inner();
                        forgotten.clear();
                        forgotten
                    });
                    seal_at(
                        &store,
                        &data,
                        &client,
                        instant,
                        &holder,
                        token,
                        &mut confirmed,
                    )?;
                    sealed.notify_one();
                    Ok(())
                },
            )
        })
        .await;
        match passed {
            Ok(Ok((due, made))) => {
                attempt = made;
                sleep_until(due).await;
            }
            Ok(Err(err)) => {
                report_failure("sealing schedule", err);
                tokio::time::sleep(RETRY_AFTER_READ_FAILURE).await;
            }
            Err(err) => {
                report_failure("sealing schedule", err);
                tokio::time::sleep(RETRY_AFTER_READ_FAILURE).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    const T: i64 = 1_786_276_800;
    const OWNER: &str = "sealing";

    fn log(data: &Path) -> (PathBuf, Db) {
        crate::init::run("127.0.0.1:0", data).unwrap();
        let db_path = data.join("clave.sqlite");
        let db = Db::open(&db_path).unwrap();
        db.set_param("epoch_cadence_seconds", HOUR).unwrap();
        (db_path, db)
    }

    fn transient(_instant: i64, _token: i64) -> Result<()> {
        Err(Error::Seal("transient failure".into()))
    }

    #[test]
    fn a_transient_seal_failure_is_retried_five_seconds_later_within_grace() {
        let data = tempfile::tempdir().unwrap();
        let (db_path, db) = log(data.path());
        let (due, attempt) = pass(&db_path, data.path(), OWNER, T, None, transient).unwrap();
        assert_eq!(due, T);
        assert!(db.last_epoch().unwrap().is_none());

        let mut attempts = 0;
        let (due, attempt) = pass(&db_path, data.path(), OWNER, T + 4, attempt, |_, _| {
            attempts += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((due, attempts), (T + RETRY_INTERVAL_SECONDS, 0));

        let client = Client::new(false);
        pass(
            &db_path,
            data.path(),
            OWNER,
            T + 5,
            attempt,
            |instant, token| {
                seal_at(
                    &db_path,
                    data.path(),
                    &client,
                    instant,
                    OWNER,
                    token,
                    &mut HashSet::new(),
                )
            },
        )
        .unwrap();
        let epoch = db.last_epoch().unwrap().unwrap();
        assert_eq!(
            (epoch.epoch_number, epoch.sealed_at),
            (0, crate::registry::instant(T).unwrap())
        );
        assert!(crate::publication::head_path(data.path()).exists());
    }

    #[test]
    fn an_epoch_committed_without_publication_is_published_on_the_next_pass() {
        let data = tempfile::tempdir().unwrap();
        let (db_path, db) = log(data.path());
        let (_, attempt) = pass(&db_path, data.path(), OWNER, T, None, |instant, _| {
            crate::db::tests::seal_epoch(&db, 0, &crate::registry::instant(instant)?, &[]);
            Err(Error::Seal("interrupted before publication".into()))
        })
        .unwrap();
        assert_eq!(db.last_epoch().unwrap().unwrap().epoch_number, 0);
        assert!(!crate::publication::head_path(data.path()).exists());

        let mut attempts = 0;
        let (due, _) = pass(&db_path, data.path(), OWNER, T + 1, attempt, |_, _| {
            attempts += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(attempts, 0);
        assert!(due < T + HOUR);
        assert!(crate::publication::head_path(data.path()).exists());
        assert!(crate::publication::archive_path(data.path(), 0).exists());
        assert!(db.unpublished_publications().unwrap().is_empty());
    }

    #[test]
    fn an_unsealed_instant_is_retried_through_the_last_second_of_its_grace_and_no_later() {
        let data = tempfile::tempdir().unwrap();
        let (db_path, db) = log(data.path());
        let (_, attempt) = pass(&db_path, data.path(), OWNER, T, None, transient).unwrap();

        let mut attempts = 0;
        let (_, attempt) = pass(
            &db_path,
            data.path(),
            OWNER,
            T + grace(HOUR),
            attempt,
            |instant, token| {
                attempts += 1;
                transient(instant, token)
            },
        )
        .unwrap();
        assert_eq!(attempts, 1);

        let (due, _) = pass(
            &db_path,
            data.path(),
            OWNER,
            T + grace(HOUR) + 1,
            attempt,
            |_, _| {
                attempts += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            (attempts, due),
            (1, T + grace(HOUR) + 1 + LEASE_RENEWAL_SECONDS)
        );
        assert!(db.last_epoch().unwrap().is_none());
    }

    #[test]
    fn a_pass_without_the_sealer_lease_neither_retries_nor_publishes() {
        let data = tempfile::tempdir().unwrap();
        let (db_path, db) = log(data.path());
        crate::db::tests::seal_epoch(&db, 0, &crate::registry::instant(T - HOUR).unwrap(), &[]);
        assert!(db
            .hold_sealer_lease("another instance", T)
            .unwrap()
            .is_some());
        let waiting = Attempt {
            instant: T,
            at: T - RETRY_INTERVAL_SECONDS,
        };

        let mut attempts = 0;
        let (due, attempt) = pass(&db_path, data.path(), OWNER, T, Some(waiting), |_, _| {
            attempts += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!((attempts, due), (0, T + LEASE_RENEWAL_SECONDS));
        assert_eq!(attempt, Some(waiting));
        assert_eq!(db.last_epoch().unwrap().unwrap().epoch_number, 0);
        assert!(!crate::publication::head_path(data.path()).exists());
        assert_eq!(db.unpublished_publications().unwrap().len(), 1);
    }

    fn not_found_mirror() -> (String, Arc<Mutex<Vec<String>>>) {
        use std::io::{BufRead, BufReader};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut line = String::new();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut header = String::new();
                while reader.read_line(&mut header).is_ok_and(|read| read > 2) {
                    header.clear();
                }
                recorded.lock().unwrap().push(line.trim_end().to_owned());
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            }
        });
        (url, requests)
    }

    fn list_mirrors(data: &Path, urls: &[&str]) {
        std::fs::write(
            data.join("log/mirrors.json"),
            serde_json::to_vec(&serde_json::json!({"mirrors": {"mirror_urls": urls}})).unwrap(),
        )
        .unwrap();
    }

    fn scheduled_seal(
        db_path: &Path,
        data: &Path,
        instant: i64,
        confirmed: &mut HashSet<String>,
    ) -> Result<()> {
        let client = Client::with_builder(true, reqwest::blocking::Client::builder().no_proxy());
        let db = Db::connect(db_path)?;
        let token = db.hold_sealer_lease(OWNER, instant)?.unwrap();
        seal_at(db_path, data, &client, instant, OWNER, token, confirmed)
    }

    #[test]
    fn the_scheduler_consults_a_confirmed_mirror_once_and_a_mirror_listed_later_at_the_next_seal() {
        let data = tempfile::tempdir().unwrap();
        let (db_path, db) = log(data.path());
        let (first, first_requests) = not_found_mirror();
        let (second, second_requests) = not_found_mirror();
        list_mirrors(data.path(), &[&first]);
        let mut confirmed = HashSet::new();

        scheduled_seal(&db_path, data.path(), T, &mut confirmed).unwrap();
        scheduled_seal(&db_path, data.path(), T + HOUR, &mut confirmed).unwrap();
        assert_eq!(first_requests.lock().unwrap().len(), 1);

        list_mirrors(data.path(), &[&first, &second]);
        scheduled_seal(&db_path, data.path(), T + 2 * HOUR, &mut confirmed).unwrap();
        scheduled_seal(&db_path, data.path(), T + 3 * HOUR, &mut confirmed).unwrap();

        assert_eq!(
            *first_requests.lock().unwrap(),
            ["GET /checkpoint HTTP/1.1"]
        );
        assert_eq!(
            *second_requests.lock().unwrap(),
            ["GET /checkpoint HTTP/1.1"]
        );
        assert_eq!(db.last_epoch().unwrap().unwrap().epoch_number, 3);
        assert_eq!(confirmed, HashSet::from([first, second]));
    }

    #[test]
    fn a_refused_mirror_check_confirms_no_mirror() {
        let data = tempfile::tempdir().unwrap();
        let (db_path, db) = log(data.path());
        let (answering, requests) = not_found_mirror();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unreachable = format!("http://{}/", closed.local_addr().unwrap());
        drop(closed);
        list_mirrors(data.path(), &[&answering, &unreachable]);
        let mut confirmed = HashSet::new();

        let refused = scheduled_seal(&db_path, data.path(), T, &mut confirmed);

        assert!(
            matches!(refused, Err(Error::MirrorUnconfirmed { .. })),
            "{refused:?}"
        );
        assert!(confirmed.is_empty());
        assert!(db.last_epoch().unwrap().is_none());
        list_mirrors(data.path(), &[&answering]);
        scheduled_seal(&db_path, data.path(), T + HOUR, &mut confirmed).unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn grace_is_half_the_cadence_capped_at_sixty_seconds() {
        assert_eq!(grace(1), 0);
        assert_eq!(grace(2), 1);
        assert_eq!(grace(90), 45);
        assert_eq!(grace(120), 60);
        assert_eq!(grace(HOUR), 60);
    }

    #[test]
    fn first_epoch_seals_at_the_current_instant_within_grace() {
        assert_eq!(next_seal(None, HOUR, T + 30), Decision::SealNow(T));
    }

    #[test]
    fn first_epoch_past_grace_waits_for_the_next_instant() {
        assert_eq!(
            next_seal(None, HOUR, T + 61),
            Decision::SleepUntil(T + HOUR)
        );
    }

    #[test]
    fn an_instant_reached_exactly_seals_at_it() {
        assert_eq!(next_seal(Some(T - HOUR), HOUR, T), Decision::SealNow(T));
    }

    #[test]
    fn the_last_second_of_grace_still_seals() {
        assert_eq!(
            next_seal(Some(T - HOUR), HOUR, T + 60),
            Decision::SealNow(T)
        );
        assert_eq!(next_seal(Some(T - 10), 10, T + 5), Decision::SealNow(T));
    }

    #[test]
    fn an_instant_past_grace_is_skipped_for_the_next_one() {
        assert_eq!(
            next_seal(Some(T - HOUR), HOUR, T + 61),
            Decision::SleepUntil(T + HOUR)
        );
        assert_eq!(
            next_seal(Some(T - 10), 10, T + 6),
            Decision::SleepUntil(T + 10)
        );
    }

    #[test]
    fn an_instant_already_sealed_waits_for_the_next_one() {
        assert_eq!(next_seal(Some(T), HOUR, T), Decision::SleepUntil(T + HOUR));
        assert_eq!(
            next_seal(Some(T), HOUR, T + 30),
            Decision::SleepUntil(T + HOUR)
        );
    }

    #[test]
    fn a_clock_behind_the_last_sealed_instant_waits_past_it() {
        assert_eq!(
            next_seal(Some(T + HOUR), HOUR, T + 10),
            Decision::SleepUntil(T + 2 * HOUR)
        );
    }

    #[test]
    fn a_shorter_cadence_seals_on_its_own_grid_after_the_last_instant() {
        assert_eq!(next_seal(Some(T), 60, T + 60), Decision::SealNow(T + 60));
        assert_eq!(next_seal(Some(T), 60, T + 20), Decision::SleepUntil(T + 60));
    }

    #[test]
    fn a_longer_cadence_waits_for_its_next_multiple_after_the_last_instant() {
        let day = 86_400;
        let last = T - T.rem_euclid(day) + HOUR;
        assert_eq!(
            next_seal(Some(last), day, last + 10),
            Decision::SleepUntil(last - HOUR + day)
        );
        assert_eq!(
            next_seal(Some(last), day, last - HOUR + day + 5),
            Decision::SealNow(last - HOUR + day)
        );
    }

    #[test]
    fn a_short_cadence_without_grace_seals_every_second() {
        assert_eq!(next_seal(Some(T), 1, T + 1), Decision::SealNow(T + 1));
    }
}
