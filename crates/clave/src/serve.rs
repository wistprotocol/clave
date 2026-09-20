use crate::db::{Db, PingAdmission, PullOutcome, PullTask};
use crate::error::{Error, Result};
use crate::fetch::Client;
use crate::ingest::{self, canonical_authority};
use crate::WIST_VERSION;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use tower_http::services::{ServeDir, ServeFile};
use wist_core::objects::Status;

pub const MAX_CONCURRENT_INGESTS: usize = 4;
pub const MAX_PENDING_INGESTS: usize = 64;
pub const OVERLOAD_RETRY_AFTER_SECS: u64 = 30;
/// The instance name a `serve` without `--instance` runs under.
pub const DEFAULT_INSTANCE: &str = "primary";

/// The bounds `serve` applies to pulls and Pings: at most
/// `max_concurrent_ingests` pulls run at once and at most
/// `max_pending_ingests` Pings wait in the pull schedule; a Ping for a
/// domain neither waiting nor being pulled beyond that bound is refused
/// with 503 and a Retry-After, never queued. The dispatcher holds at most
/// `max_partitions` pull partitions and pulls only their domains. With
/// `seal` set, an Epoch is sealed at every grid instant reached while
/// serving and holding the Log's sealer lease. `instance` names this
/// process's place in the store: it owns the leases recorded under that
/// name and holds an exclusive file lock on it for its lifetime, so a
/// restart resumes its predecessor's place instead of waiting for the
/// leases to lapse, and two processes on one store take distinct names.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub instance: String,
    pub max_concurrent_ingests: usize,
    pub max_pending_ingests: usize,
    pub max_partitions: usize,
    pub seal: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions {
            instance: DEFAULT_INSTANCE.to_string(),
            max_concurrent_ingests: MAX_CONCURRENT_INGESTS,
            max_pending_ingests: MAX_PENDING_INGESTS,
            max_partitions: crate::db::PARTITIONS as usize,
            seal: true,
        }
    }
}

/// One `serve` process's exclusive hold on its instance name, an OS file
/// lock on `<data_dir>/instance-<name>.lock` released when the process
/// ends however it ends.
struct InstanceLock(#[allow(dead_code)] std::fs::File);

/// Takes `instance`'s file lock under `data_dir`, failing at once while
/// another process holds it. The name is restricted to a single path
/// component of ASCII letters, digits, `-`, `_` and `.` so it names one
/// file inside the data directory.
fn lock_instance(data_dir: &std::path::Path, instance: &str) -> Result<InstanceLock> {
    let named = !instance.is_empty()
        && instance != "."
        && instance != ".."
        && instance
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !named {
        return Err(Error::Instance(format!(
            "{instance:?} is no instance name: use ASCII letters, digits, '-', '_' or '.'"
        )));
    }
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join(format!("instance-{instance}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| {
        Error::Instance(format!(
            "another process is already serving this store as instance {instance} ({} is locked); pass --instance <name> to serve it under another name",
            path.display()
        ))
    })?;
    Ok(InstanceLock(file))
}

/// The longest the dispatcher sleeps before it looks for due pulls again
/// when nothing wakes it.
const DISPATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
    client: Arc<Client>,
    data_dir: PathBuf,
    max_pending: usize,
    wake: Arc<tokio::sync::Notify>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestRequest {
    host: String,
}

/// WIST-3 §6 and [tlog-tiles]: the head Checkpoint and the archive are
/// text served without caching, since both are rewritten — the head at
/// every Epoch, an archived note whenever a Cosignature is added.
const NOTE_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const NO_CACHE: &str = "no-store";
/// A full tile or entry bundle never changes once written, so it is
/// cached as the immutable file it is.
const TILE_CONTENT_TYPE: &str = "application/octet-stream";
const IMMUTABLE_CACHE: &str = "public, max-age=604800, immutable";

/// Resolves a served path under `root`, refusing any component that is
/// not an ordinary name so no request reaches outside the directory.
fn under(root: &std::path::Path, relative: &str) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for component in std::path::Path::new(relative).components() {
        match component {
            std::path::Component::Normal(name) => path.push(name),
            _ => return None,
        }
    }
    Some(path)
}

async fn serve_file(
    path: Option<PathBuf>,
    content_type: &'static str,
    cache_control: &'static str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [
                (axum::http::header::CONTENT_TYPE, content_type),
                (axum::http::header::CACHE_CONTROL, cache_control),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn checkpoint_handler(State(state): State<AppState>) -> axum::response::Response {
    serve_file(
        Some(crate::publication::head_path(&state.data_dir)),
        NOTE_CONTENT_TYPE,
        NO_CACHE,
    )
    .await
}

/// Serves `/tile/<L>/<N>` and `/tile/entries/<N>`, full ones as the
/// immutable files they are and partial ones — the `.p/<W>` paths a head
/// size requires — without caching, because they stop being served once
/// the full tile exists.
async fn tile_handler(
    State(state): State<AppState>,
    Path(rest): Path<String>,
) -> axum::response::Response {
    let partial = rest.contains(".p/");
    serve_file(
        under(&state.data_dir.join("tile"), &rest),
        TILE_CONTENT_TYPE,
        if partial { NO_CACHE } else { IMMUTABLE_CACHE },
    )
    .await
}

async fn log_handler(
    State(state): State<AppState>,
    Path(rest): Path<String>,
) -> axum::response::Response {
    let path = under(&state.data_dir.join("log"), &rest);
    if rest.starts_with("checkpoints/") {
        return serve_file(path, NOTE_CONTENT_TYPE, NO_CACHE).await;
    }
    let content_type = if rest.ends_with(".json") {
        "application/json"
    } else {
        TILE_CONTENT_TYPE
    };
    serve_file(path, content_type, IMMUTABLE_CACHE).await
}

fn utc(second: i64) -> String {
    jiff::Timestamp::from_second(second)
        .expect("current Unix second is in range")
        .to_string()
}

fn now_utc() -> String {
    utc(jiff::Timestamp::now().as_second())
}

fn load_status(db: &Db, domain: &str) -> Result<Option<Status>> {
    let Some(row) = db.get_publisher_status(domain)? else {
        return Ok(None);
    };
    let rejections = db.list_rejections(domain)?;
    let now = now_utc();
    let quota_remaining = crate::quota::quota_remaining(db, domain, &now)?.max(0) as u64;
    Ok(Some(Status {
        wist_version: WIST_VERSION.to_string(),
        domain: domain.to_string(),
        last_pull_at: row.last_pull_at,
        quota_remaining,
        state: row.state,
        rejections,
    }))
}

fn seconds_to_next_utc_day(now: &str) -> i64 {
    now.parse::<jiff::Timestamp>()
        .map(|ts| 86400 - ts.as_second().rem_euclid(86400))
        .unwrap_or(86400)
}

async fn ingest_handler(State(state): State<AppState>, body: Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    let payload: IngestRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(host) = canonical_authority(&payload.host) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let now_unix = jiff::Timestamp::now().as_second();
    let now = utc(now_unix);

    let quota = {
        let db_path = state.db_path.clone();
        let host = host.clone();
        let at = now.clone();
        tokio::task::spawn_blocking(move || {
            let db = Db::connect(&db_path)?;
            crate::quota::quota_remaining(&db, &host, &at)
        })
        .await
    };
    match quota {
        Ok(Ok(remaining)) if remaining <= 0 => {
            let retry_after = seconds_to_next_utc_day(&now);
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("Retry-After", retry_after.to_string())],
            )
                .into_response();
        }
        Ok(Ok(_)) => {}
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    let admission = {
        let db_path = state.db_path.clone();
        let max_pending = state.max_pending;
        tokio::task::spawn_blocking(move || {
            Db::connect(&db_path)?.schedule_ping(&host, now_unix, max_pending)
        })
        .await
    };
    match admission {
        Ok(Ok(PingAdmission::Overloaded)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("Retry-After", OVERLOAD_RETRY_AFTER_SECS.to_string())],
        )
            .into_response(),
        Ok(Ok(_)) => {
            state.wake.notify_one();
            StatusCode::ACCEPTED.into_response()
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Runs `task` to completion and schedules the domain's next pull, every
/// write fenced by the partition token the task was claimed under: once
/// another dispatcher has taken the partition over, the pull writes
/// nothing more and leaves the domain, and whatever its run committed, to
/// the new holder.
fn pull(state: &AppState, owner: &str, task: &PullTask) {
    let Ok(db) = Db::connect(&state.db_path) else {
        return;
    };
    let db = db.fenced(task.fence());
    let started_at = jiff::Timestamp::now().as_second();
    let now = utc(started_at);
    let run = ingest::open_pull(
        &db,
        &state.client,
        &state.data_dir,
        &task.domain,
        &now,
        jiff::Timestamp::now,
        ingest::PullLimits::default(),
    );
    match run {
        Ok(run) => {
            let _ = ingest::finish_pull(
                &db,
                task,
                owner,
                started_at,
                run,
                jiff::Timestamp::now().as_second(),
            );
        }
        Err(Error::Fenced) => {}
        Err(_) => {
            let _ = db.complete_pull(
                task,
                owner,
                started_at,
                PullOutcome::Failed,
                jiff::Timestamp::now().as_second(),
            );
        }
    }
}

/// Claims due pulls whenever a worker slot is free, woken by each Ping,
/// each finished pull and at least every `DISPATCH_INTERVAL`; renews its
/// partition leases and the leases of the pulls it runs, takes over
/// lapsed partitions up to `max_partitions` and returns lapsed pulls to
/// the schedule.
async fn dispatch(state: AppState, owner: Arc<str>, slots: usize, max_partitions: usize) {
    let running = Arc::new(Mutex::new(HashSet::<String>::new()));
    let mut ping_next = true;
    loop {
        let held: Vec<String> = running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        let free = slots.saturating_sub(held.len());
        let pass = {
            let db_path = state.db_path.clone();
            let owner = owner.clone();
            let mut next = ping_next;
            tokio::task::spawn_blocking(move || {
                let db = Db::connect(&db_path)?;
                let now = jiff::Timestamp::now().as_second();
                if !held.is_empty() {
                    db.renew_pull_leases(&held, &owner, now)?;
                }
                let tasks = db.claim_pulls(now, free, &owner, max_partitions, &mut next)?;
                Ok::<_, Error>((tasks, next))
            })
            .await
        };
        if let Ok(Ok((tasks, next))) = pass {
            ping_next = next;
            for task in tasks {
                running
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(task.domain.clone());
                let state = state.clone();
                let owner = owner.clone();
                let running = running.clone();
                tokio::spawn(async move {
                    let worker = state.clone();
                    let domain = task.domain.clone();
                    let _ = tokio::task::spawn_blocking(move || pull(&worker, &owner, &task)).await;
                    running
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&domain);
                    state.wake.notify_one();
                });
            }
        }
        tokio::select! {
            _ = state.wake.notified() => {}
            _ = tokio::time::sleep(DISPATCH_INTERVAL) => {}
        }
    }
}

async fn status_handler(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> std::result::Result<Json<Status>, StatusCode> {
    let db_path = state.db_path.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let db = Db::connect(&db_path)?;
        load_status(&db, &domain)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    outcome.map(Json).ok_or(StatusCode::NOT_FOUND)
}

pub fn run(
    data_dir: PathBuf,
    db_path: PathBuf,
    bind: SocketAddr,
    allow_http: bool,
    seal: bool,
    instance: String,
) -> Result<()> {
    run_with_options(
        data_dir,
        db_path,
        bind,
        Client::new(allow_http),
        ServeOptions {
            instance,
            seal,
            ..ServeOptions::default()
        },
    )
}

pub fn run_with_client(
    data_dir: PathBuf,
    db_path: PathBuf,
    bind: SocketAddr,
    client: Client,
) -> Result<()> {
    run_with_options(data_dir, db_path, bind, client, ServeOptions::default())
}

pub fn run_with_options(
    data_dir: PathBuf,
    db_path: PathBuf,
    bind: SocketAddr,
    client: Client,
    options: ServeOptions,
) -> Result<()> {
    let _instance = lock_instance(&data_dir, &options.instance)?;
    let owner: Arc<str> = options.instance.as_str().into();
    let db = Db::open(&db_path)?;
    db.reclaim_instance_leases(&owner, jiff::Timestamp::now().as_second())?;
    crate::publication::recover(&db, &data_dir)?;
    drop(db);
    let state = AppState {
        db_path,
        client: Arc::new(client),
        data_dir: data_dir.clone(),
        max_pending: options.max_pending_ingests,
        wake: Arc::new(tokio::sync::Notify::new()),
    };
    let bg_state = state.clone();
    let app = Router::new()
        .route("/ingest", post(ingest_handler))
        .route("/status/:domain", get(status_handler))
        .route("/checkpoint", get(checkpoint_handler))
        .route("/tile/*path", get(tile_handler))
        .route("/log/*path", get(log_handler))
        .nest_service("/payloads", ServeDir::new(data_dir.join("payloads")))
        .nest_service("/snapshots", ServeDir::new(data_dir.join("snapshots")))
        .route_service(
            "/log/anchor.json",
            ServeFile::new(data_dir.join("anchor.json")),
        )
        .with_state(state);

    let bg_data = data_dir.clone();
    let release_path = bg_state.db_path.clone();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        if options.seal {
            tokio::spawn(crate::scheduler::run(
                bg_state.db_path.clone(),
                bg_data.clone(),
                bg_state.client.clone(),
                owner.clone(),
            ));
        }
        tokio::spawn(dispatch(
            bg_state,
            owner.clone(),
            options.max_concurrent_ingests,
            options.max_partitions,
        ));
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        println!("listening on http://{local_addr}");
        std::io::stdout().flush().ok();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        tokio::task::spawn_blocking(move || {
            let db = Db::connect(&release_path)?;
            db.release_partitions(&owner)?;
            db.release_sealer_lease(&owner)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        Ok::<(), Error>(())
    })
}

/// Resolves on Ctrl-C and, on Unix, on SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
