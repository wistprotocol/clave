use crate::db::Db;
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
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use tower_http::services::{ServeDir, ServeFile};
use wist_core::objects::Status;

pub const MAX_CONCURRENT_INGESTS: usize = 4;
pub const MAX_PENDING_INGESTS: usize = 64;
pub const OVERLOAD_RETRY_AFTER_SECS: u64 = 30;

/// The admission bounds `serve` applies to Pings: at most
/// `max_concurrent_ingests` pulls run at once and at most
/// `max_pending_ingests` accepted Pings wait for a slot; a Ping beyond
/// both is refused with 503 and a Retry-After, never queued.
#[derive(Debug, Clone, Copy)]
pub struct ServeOptions {
    pub max_concurrent_ingests: usize,
    pub max_pending_ingests: usize,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions {
            max_concurrent_ingests: MAX_CONCURRENT_INGESTS,
            max_pending_ingests: MAX_PENDING_INGESTS,
        }
    }
}

pub struct IngestGate {
    inflight: Mutex<std::collections::HashSet<String>>,
    pending: Mutex<usize>,
    max_pending: usize,
    pub semaphore: Arc<tokio::sync::Semaphore>,
}

/// What a Ping's host was admitted to.
pub enum Admission {
    /// The host has no pull in flight or waiting; the caller owns the
    /// pending slot until it starts the pull.
    Queued(InflightGuard),
    /// A pull for the host is already running or waiting.
    Duplicate,
    /// Every pending slot is taken.
    Overloaded,
}

pub struct InflightGuard {
    gate: Arc<IngestGate>,
    host: String,
    pending: bool,
}

impl IngestGate {
    pub fn new(max_concurrent: usize) -> Arc<IngestGate> {
        Self::with_pending(max_concurrent, MAX_PENDING_INGESTS)
    }

    pub fn with_pending(max_concurrent: usize, max_pending: usize) -> Arc<IngestGate> {
        Arc::new(IngestGate {
            inflight: Mutex::new(std::collections::HashSet::new()),
            pending: Mutex::new(0),
            max_pending,
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        })
    }

    pub fn begin(self: &Arc<Self>, host: &str) -> Admission {
        let mut set = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if set.contains(host) {
            return Admission::Duplicate;
        }
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if *pending >= self.max_pending {
            return Admission::Overloaded;
        }
        *pending += 1;
        set.insert(host.to_string());
        Admission::Queued(InflightGuard {
            gate: self.clone(),
            host: host.to_string(),
            pending: true,
        })
    }

    pub fn pending(&self) -> usize {
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn release_pending(&self) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        *pending = pending.saturating_sub(1);
    }
}

impl IngestGate {
    /// Admits a background pull for `host` unless a pull for it is
    /// already running or waiting; background work takes no pending slot.
    pub fn begin_background(self: &Arc<Self>, host: &str) -> Option<InflightGuard> {
        let mut set = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if !set.insert(host.to_string()) {
            return None;
        }
        Some(InflightGuard {
            gate: self.clone(),
            host: host.to_string(),
            pending: false,
        })
    }
}

impl InflightGuard {
    /// Marks the pull as running: its pending slot frees for another Ping
    /// while the host stays in flight until the guard drops.
    pub fn started(&mut self) {
        if std::mem::take(&mut self.pending) {
            self.gate.release_pending();
        }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if self.pending {
            self.gate.release_pending();
        }
        self.gate
            .inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.host);
    }
}

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
    client: Arc<Client>,
    data_dir: PathBuf,
    gate: Arc<IngestGate>,
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

fn now_utc() -> String {
    jiff::Timestamp::from_second(jiff::Timestamp::now().as_second())
        .expect("current Unix second is in range")
        .to_string()
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
    let payload = IngestRequest { host };
    let now = now_utc();

    let quota = {
        let db_path = state.db_path.clone();
        let host = payload.host.clone();
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

    let mut guard = match state.gate.begin(&payload.host) {
        Admission::Queued(guard) => guard,
        Admission::Duplicate => return StatusCode::ACCEPTED.into_response(),
        Admission::Overloaded => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("Retry-After", OVERLOAD_RETRY_AFTER_SECS.to_string())],
            )
                .into_response()
        }
    };
    let semaphore = state.gate.semaphore.clone();
    let db_path = state.db_path.clone();
    let client = state.client.clone();
    let data_dir = state.data_dir.clone();
    tokio::spawn(async move {
        let Ok(_permit) = semaphore.acquire_owned().await else {
            return;
        };
        guard.started();
        let _guard = guard;
        let _ = tokio::task::spawn_blocking(move || {
            let Ok(db) = Db::connect(&db_path) else {
                return;
            };
            let report = ingest::run_with_clock(
                &db,
                &client,
                &data_dir,
                &payload.host,
                &now,
                jiff::Timestamp::now,
            );
            if let Ok(report) = report {
                if report.noise.is_some() {
                    let day = now.get(..10).unwrap_or(&now);
                    if let Ok(unit) = crate::suffix_list::unit_at(&db, &payload.host, &now) {
                        let _ = db.bump_noise_ping(&unit, day);
                    }
                }
            }
        })
        .await;
    });
    StatusCode::ACCEPTED.into_response()
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

pub fn run(data_dir: PathBuf, db_path: PathBuf, bind: SocketAddr, allow_http: bool) -> Result<()> {
    run_with_client(data_dir, db_path, bind, Client::new(allow_http))
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
    crate::publication::recover(&Db::open(&db_path)?, &data_dir)?;
    let state = AppState {
        db_path,
        client: Arc::new(client),
        data_dir: data_dir.clone(),
        gate: IngestGate::with_pending(options.max_concurrent_ingests, options.max_pending_ingests),
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

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                ticker.tick().await;
                let db_path = bg_state.db_path.clone();
                let client = bg_state.client.clone();
                let data = bg_data.clone();
                let gate = bg_state.gate.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let Ok(db) = Db::connect(&db_path) else {
                        return;
                    };
                    let now_unix = jiff::Timestamp::now().as_second();
                    let _ = crate::baseline::run_pass_gated(&db, &client, &data, now_unix, &gate);
                })
                .await;
            }
        });
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        println!("listening on http://{local_addr}");
        std::io::stdout().flush().ok();
        axum::serve(listener, app).await?;
        Ok::<(), Error>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(admission: Admission) -> Option<InflightGuard> {
        match admission {
            Admission::Queued(guard) => Some(guard),
            _ => None,
        }
    }

    #[test]
    fn gate_dedups_inflight_hosts_and_releases_on_drop() {
        let gate = IngestGate::new(4);
        let guard = queued(gate.begin("example.com")).unwrap();
        assert!(matches!(gate.begin("example.com"), Admission::Duplicate));
        assert!(queued(gate.begin("other.example")).is_some());
        drop(guard);
        assert!(queued(gate.begin("example.com")).is_some());
    }

    #[test]
    fn gate_refuses_pings_beyond_the_pending_bound_until_a_pull_starts_or_ends() {
        let gate = IngestGate::with_pending(1, 2);
        let mut first = queued(gate.begin("a.example")).unwrap();
        let second = queued(gate.begin("b.example")).unwrap();
        assert!(matches!(gate.begin("c.example"), Admission::Overloaded));
        assert!(matches!(gate.begin("a.example"), Admission::Duplicate));
        assert_eq!(gate.pending(), 2);
        first.started();
        assert_eq!(gate.pending(), 1);
        let third = queued(gate.begin("c.example")).unwrap();
        assert!(matches!(gate.begin("d.example"), Admission::Overloaded));
        drop(second);
        let fourth = queued(gate.begin("d.example")).unwrap();
        assert_eq!(gate.pending(), 2);
        drop(first);
        assert_eq!(gate.pending(), 2);
        drop(third);
        drop(fourth);
        assert_eq!(gate.pending(), 0);
    }

    #[test]
    fn gate_semaphore_caps_concurrency() {
        let gate = IngestGate::new(2);
        let p1 = gate.semaphore.clone().try_acquire_owned().unwrap();
        let _p2 = gate.semaphore.clone().try_acquire_owned().unwrap();
        assert!(gate.semaphore.clone().try_acquire_owned().is_err());
        drop(p1);
        assert!(gate.semaphore.clone().try_acquire_owned().is_ok());
    }
}
