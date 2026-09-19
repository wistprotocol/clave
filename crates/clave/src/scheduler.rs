use crate::db::{Db, Fence, SEALER_LEASE_SECONDS};
use crate::error::{Error, Result};
use crate::fetch::Client;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const MAX_GRACE_SECONDS: i64 = 60;
const RETRY_AFTER_READ_FAILURE: Duration = Duration::from_secs(1);
/// How often the sealer lease's holder renews it and another process
/// looks whether it has lapsed.
const LEASE_RENEWAL_SECONDS: i64 = SEALER_LEASE_SECONDS / 3;

/// What the sealing scheduler does next, as a Unix second on the cadence
/// grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    SealNow(i64),
    SleepUntil(i64),
}

/// How long after a grid instant its Epoch may still be sealed at it:
/// half the cadence, at most 60 seconds.
pub fn grace(cadence: i64) -> i64 {
    (cadence / 2).min(MAX_GRACE_SECONDS)
}

/// Seals the grid instant `now_unix` falls in when it is after the last
/// sealed instant and its grace has not passed; otherwise waits for the
/// next grid instant after both. A missed instant is skipped, never
/// sealed late (WIST-3 §3.2).
pub fn next_seal(last_sealed_unix: Option<i64>, cadence: i64, now_unix: i64) -> Decision {
    let instant = now_unix.div_euclid(cadence) * cadence;
    if last_sealed_unix.is_none_or(|last| instant > last) && now_unix - instant <= grace(cadence) {
        return Decision::SealNow(instant);
    }
    let floor = last_sealed_unix.map_or(instant, |last| last.max(instant));
    Decision::SleepUntil((floor.div_euclid(cadence) + 1) * cadence)
}

/// The last Epoch's `sealed_at` and the `epoch_cadence_seconds` in force
/// there, or at `now_unix` before the first Epoch.
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
) -> Result<()> {
    let db = Db::connect(db_path)?.fenced(Fence::Sealer { token });
    let (_, sk) = crate::keys::head_signer(data_dir, &db)?;
    let report = crate::seal::under_renewed_lease(
        db_path,
        owner,
        token,
        crate::seal::LeaseTerms::default(),
        || crate::seal::run_with_client(&db, data_dir, &sk, client, instant),
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

async fn sleep_until(instant: i64) {
    let wait = instant
        .saturating_mul(1000)
        .saturating_sub(jiff::Timestamp::now().as_millisecond());
    if let Ok(wait) = u64::try_from(wait) {
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
}

/// Seals an Epoch at every grid instant reached while serving and holding
/// the Log's sealer lease as `owner`, re-reading the lease, the last Epoch
/// and the cadence before each decision and at least every
/// `LEASE_RENEWAL_SECONDS`. Each seal is fenced by the lease's token, so a
/// seal begun after another process took the lease over commits nothing.
/// An instant is attempted once: a failed seal is reported and the next
/// instant awaited.
pub async fn run(db_path: PathBuf, data_dir: PathBuf, client: Arc<Client>, owner: Arc<str>) {
    let mut attempted: Option<i64> = None;
    loop {
        let read_path = db_path.clone();
        let holder = owner.clone();
        let read = tokio::task::spawn_blocking(move || {
            let now_unix = jiff::Timestamp::now().as_second();
            let db = Db::connect(&read_path)?;
            let Some(token) = db.hold_sealer_lease(&holder, now_unix)? else {
                return Ok(None);
            };
            grid(&db, now_unix).map(|(last, cadence)| Some((token, last, cadence, now_unix)))
        })
        .await;
        let (token, last, cadence, now_unix) = match read {
            Ok(Ok(Some(state))) => state,
            Ok(Ok(None)) => {
                tokio::time::sleep(Duration::from_secs(LEASE_RENEWAL_SECONDS as u64)).await;
                continue;
            }
            Ok(Err(err)) => {
                report_failure("sealing schedule", err);
                tokio::time::sleep(RETRY_AFTER_READ_FAILURE).await;
                continue;
            }
            Err(err) => {
                report_failure("sealing schedule", err);
                tokio::time::sleep(RETRY_AFTER_READ_FAILURE).await;
                continue;
            }
        };
        match next_seal(last.max(attempted), cadence, now_unix) {
            Decision::SleepUntil(instant) => {
                sleep_until(instant.min(now_unix + LEASE_RENEWAL_SECONDS)).await
            }
            Decision::SealNow(instant) => {
                attempted = Some(instant);
                let (db_path, data_dir, client, holder) = (
                    db_path.clone(),
                    data_dir.clone(),
                    client.clone(),
                    owner.clone(),
                );
                let sealed = tokio::task::spawn_blocking(move || {
                    seal_at(&db_path, &data_dir, &client, instant, &holder, token)
                })
                .await;
                let what = format!("seal at Unix second {instant}");
                match sealed {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => report_failure(&what, err),
                    Err(err) => report_failure(&what, err),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    const T: i64 = 1_786_276_800;

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
