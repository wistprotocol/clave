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

pub struct IngestGate {
    inflight: Mutex<std::collections::HashSet<String>>,
    pub semaphore: Arc<tokio::sync::Semaphore>,
}

pub struct InflightGuard {
    gate: Arc<IngestGate>,
    host: String,
}

impl IngestGate {
    pub fn new(max_concurrent: usize) -> Arc<IngestGate> {
        Arc::new(IngestGate {
            inflight: Mutex::new(std::collections::HashSet::new()),
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        })
    }

    pub fn begin(self: &Arc<Self>, host: &str) -> Option<InflightGuard> {
        let mut set = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if !set.insert(host.to_string()) {
            return None;
        }
        Some(InflightGuard {
            gate: self.clone(),
            host: host.to_string(),
        })
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.gate
            .inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.host);
    }
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Db>>,
    client: Arc<Client>,
    data_dir: PathBuf,
    gate: Arc<IngestGate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestRequest {
    host: String,
}

fn now_utc() -> String {
    jiff::Timestamp::from_second(jiff::Timestamp::now().as_second())
        .expect("current epoch second is in range")
        .to_string()
}

fn load_status(db: &Db, domain: &str) -> Result<Option<Status>> {
    let Some(row) = db.get_publisher_status(domain)? else {
        return Ok(None);
    };
    let rejections = db.list_rejections(domain)?;
    let now = now_utc();
    let quota_remaining = crate::quota::quota_remaining(db, domain, &now)?.max(0) as u64;
    let state = match crate::sanctions::sanction_level(db, domain, &now)? {
        4 => wist_core::objects::PublisherState::Delisted,
        3 => wist_core::objects::PublisherState::SanctionedQuarantine,
        _ => row.state,
    };
    Ok(Some(Status {
        wist_version: WIST_VERSION.to_string(),
        domain: domain.to_string(),
        last_pull_at: row.last_pull_at,
        quota_remaining,
        state,
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
        let db = state.db.clone();
        let host = payload.host.clone();
        let at = now.clone();
        tokio::task::spawn_blocking(move || {
            let db = db.lock().unwrap_or_else(PoisonError::into_inner);
            let level = crate::sanctions::sanction_level(&db, &host, &at)?;
            crate::quota::quota_remaining(&db, &host, &at).map(|q| (level, q))
        })
        .await
    };
    match quota {
        Ok(Ok((level, _))) if level >= 3 => {
            return StatusCode::FORBIDDEN.into_response();
        }
        Ok(Ok((_, remaining))) if remaining <= 0 => {
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

    let Some(guard) = state.gate.begin(&payload.host) else {
        return StatusCode::ACCEPTED.into_response();
    };
    let semaphore = state.gate.semaphore.clone();
    let db = state.db.clone();
    let client = state.client.clone();
    let data_dir = state.data_dir.clone();
    tokio::spawn(async move {
        let Ok(_permit) = semaphore.acquire_owned().await else {
            return;
        };
        let _guard = guard;
        let _ = tokio::task::spawn_blocking(move || {
            let db = db.lock().unwrap_or_else(PoisonError::into_inner);
            let report = ingest::run(&db, &client, &data_dir, &payload.host, &now);
            if let Ok(report) = report {
                if report.noise.is_some() {
                    let day = now.get(..10).unwrap_or(&now);
                    let _ = db.bump_noise_ping(&payload.host, day);
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
    let db = state.db.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let db = db.lock().unwrap_or_else(PoisonError::into_inner);
        load_status(&db, &domain)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    outcome.map(Json).ok_or(StatusCode::NOT_FOUND)
}

pub fn run(data_dir: PathBuf, db_path: PathBuf, bind: SocketAddr, allow_http: bool) -> Result<()> {
    let db = Db::open(&db_path)?;
    let state = AppState {
        db: Arc::new(Mutex::new(db)),
        client: Arc::new(Client::new(allow_http)),
        data_dir: data_dir.clone(),
        gate: IngestGate::new(MAX_CONCURRENT_INGESTS),
    };
    let bg_state = state.clone();
    let app = Router::new()
        .route("/ingest", post(ingest_handler))
        .route("/status/:domain", get(status_handler))
        .nest_service("/log", ServeDir::new(data_dir.join("log")))
        .nest_service("/payloads", ServeDir::new(data_dir.join("payloads")))
        .nest_service("/snapshots", ServeDir::new(data_dir.join("snapshots")))
        .route_service("/anchor.json", ServeFile::new(data_dir.join("anchor.json")))
        .with_state(state);

    let baseline_sk = crate::keys::load(&data_dir.join("keys/seed"))
        .ok()
        .map(Arc::new);
    let bg_data = data_dir.clone();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        if let Some(sk) = baseline_sk {
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    ticker.tick().await;
                    let db = bg_state.db.clone();
                    let client = bg_state.client.clone();
                    let data = bg_data.clone();
                    let sk = sk.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let db = db.lock().unwrap_or_else(PoisonError::into_inner);
                        let now_epoch = jiff::Timestamp::now().as_second();
                        let _ = crate::baseline::run_pass(&db, &client, &sk, &data, now_epoch);
                    })
                    .await;
                }
            });
        }
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

    #[test]
    fn gate_dedups_inflight_hosts_and_releases_on_drop() {
        let gate = IngestGate::new(4);
        let guard = gate.begin("example.com").unwrap();
        assert!(gate.begin("example.com").is_none());
        assert!(gate.begin("other.example").is_some());
        drop(guard);
        assert!(gate.begin("example.com").is_some());
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
