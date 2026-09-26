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
pub const BACKLOG_EPOCHS: u32 = 2;
pub const BACKLOG_ENTRIES: u64 = 1 << 20;
pub const PREFETCH_OBJECTS: u32 = 4;
pub const DEFAULT_INSTANCE: &str = "primary";

#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub instance: String,
    pub max_concurrent_ingests: usize,
    pub max_pending_ingests: usize,
    pub max_partitions: usize,
    pub seal: bool,
    pub backlog_epochs: u32,
    pub backlog_entries: u64,
    pub pull_limits: ingest::PullLimits,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions {
            instance: DEFAULT_INSTANCE.to_string(),
            max_concurrent_ingests: MAX_CONCURRENT_INGESTS,
            max_pending_ingests: MAX_PENDING_INGESTS,
            max_partitions: crate::db::PARTITIONS as usize,
            seal: true,
            backlog_epochs: BACKLOG_EPOCHS,
            backlog_entries: BACKLOG_ENTRIES,
            pull_limits: ingest::PullLimits {
                prefetch_objects: PREFETCH_OBJECTS,
                ..ingest::PullLimits::default()
            },
        }
    }
}

struct InstanceLock(#[allow(dead_code)] std::fs::File);

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

const DISPATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
    client: Arc<Client>,
    data_dir: PathBuf,
    max_pending: usize,
    wake: Arc<tokio::sync::Notify>,
    pull_limits: ingest::PullLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestRequest {
    host: String,
}

/// WIST-3 §6, [tlog-tiles]: served without caching, since the head and the
/// archive are rewritten.
const NOTE_CONTENT_TYPE: &str = "text/plain; charset=utf-8";
const NO_CACHE: &str = "no-store";
const TILE_CONTENT_TYPE: &str = "application/octet-stream";
const IMMUTABLE_CACHE: &str = "public, max-age=604800, immutable";

/// Refuses any component that is not an ordinary name, so no request
/// reaches outside `root`.
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

fn ping_host_admitted(host: &str, allow_http: bool) -> bool {
    // WIST-2 §4 rejects a non-canonical host rather than canonicalizing it.
    // The ported authority below is the --allow-http loopback extension, which
    // `scheme_for_host` bounds to the hosts that opt-in reaches over http.
    if wist_core::host::canonical_host(host).ok().as_deref() == Some(host) {
        return true;
    }
    allow_http
        && canonical_authority(host).as_deref() == Some(host)
        && crate::fetch::scheme_for_host(host, true) == "http"
}

async fn ingest_handler(State(state): State<AppState>, body: Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    let payload: IngestRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let host = payload.host;
    if !ping_host_admitted(&host, state.client.allow_http()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
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
        state.pull_limits,
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
        Err(err) => {
            eprintln!("pull of {} failed: {err}", task.domain);
            let now = jiff::Timestamp::now().as_second();
            let _ = db.complete_pull(
                task,
                owner,
                started_at,
                PullOutcome::Failed,
                now.saturating_sub(started_at).max(0) as f64,
                now,
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DispatchBounds {
    slots: usize,
    max_partitions: usize,
    backlog_epochs: u32,
    backlog_entries: u64,
}

impl DispatchBounds {
    fn under_pressure(&self, db: &Db, now: i64) -> Result<bool> {
        let (entries, bytes) = db.sealing_backlog()?;
        let cap =
            crate::registry::effective(db, "epoch_cap_bytes", &crate::registry::instant(now)?)?;
        let limit = (cap.max(0) as u64).saturating_mul(u64::from(self.backlog_epochs));
        Ok(bytes >= limit || entries >= self.backlog_entries)
    }
}

async fn dispatch(state: AppState, owner: Arc<str>, bounds: DispatchBounds) {
    let running = Arc::new(Mutex::new(HashSet::<String>::new()));
    let mut ping_next = true;
    loop {
        let held: Vec<String> = running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        let free = bounds.slots.saturating_sub(held.len());
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
                let demand = !bounds.under_pressure(&db, now)?;
                let tasks = db.claim_pulls(
                    now,
                    free,
                    &owner,
                    bounds.max_partitions,
                    &held,
                    &mut next,
                    demand,
                )?;
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
        pull_limits: options.pull_limits,
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
        let sealed = Arc::new(tokio::sync::Notify::new());
        let sealing = options.seal.then(|| {
            [
                tokio::spawn(crate::scheduler::run(
                    bg_state.db_path.clone(),
                    bg_data.clone(),
                    bg_state.client.clone(),
                    owner.clone(),
                    sealed.clone(),
                )),
                tokio::spawn(produce_snapshots(
                    bg_state.db_path.clone(),
                    bg_data.clone(),
                    sealed,
                )),
            ]
        });
        let dispatching = tokio::spawn(dispatch(
            bg_state,
            owner.clone(),
            DispatchBounds {
                slots: options.max_concurrent_ingests,
                max_partitions: options.max_partitions,
                backlog_epochs: options.backlog_epochs,
                backlog_entries: options.backlog_entries,
            },
        ));
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        println!("listening on http://{local_addr}");
        std::io::stdout().flush().ok();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        // The leases are released only once no pass can take them again.
        for task in sealing.into_iter().flatten().chain([dispatching]) {
            task.abort();
            let _ = task.await;
        }
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

const SNAPSHOT_FALLBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

async fn produce_snapshots(db_path: PathBuf, data_dir: PathBuf, sealed: Arc<tokio::sync::Notify>) {
    loop {
        let (store, data) = (db_path.clone(), data_dir.clone());
        let produced =
            tokio::task::spawn_blocking(move || crate::snapshot::produce(&store, &data)).await;
        match produced {
            Ok(Ok(crate::snapshot::Outcome::Superseded { .. })) => continue,
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(%error, "Snapshot production failed"),
            Err(error) => tracing::warn!(%error, "Snapshot production failed"),
        }
        tokio::select! {
            _ = sealed.notified() => {}
            _ = tokio::time::sleep(SNAPSHOT_FALLBACK_INTERVAL) => {}
        }
    }
}

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
