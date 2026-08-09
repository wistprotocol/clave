use crate::db::Db;
use crate::error::{Error, Result};
use crate::fetch::Client;
use crate::ingest;
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
use tower_http::services::ServeDir;
use wist_core::objects::Status;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Db>>,
    client: Arc<Client>,
    data_dir: PathBuf,
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
    Ok(Some(Status {
        wist_version: WIST_VERSION.to_string(),
        domain: domain.to_string(),
        last_pull_at: row.last_pull_at,
        quota_remaining: 1100,
        state: row.state,
        rejections,
    }))
}

async fn ingest_handler(State(state): State<AppState>, body: Bytes) -> StatusCode {
    let payload: IngestRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let now = now_utc();
    let db = state.db.clone();
    let client = state.client.clone();
    let data_dir = state.data_dir.clone();
    tokio::task::spawn_blocking(move || {
        let db = db.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = ingest::run(&db, &client, &data_dir, &payload.host, &now);
    });
    StatusCode::ACCEPTED
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
    };
    let app = Router::new()
        .route("/ingest", post(ingest_handler))
        .route("/status/:domain", get(status_handler))
        .fallback_service(ServeDir::new(data_dir))
        .with_state(state);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        println!("listening on http://{local_addr}");
        std::io::stdout().flush().ok();
        axum::serve(listener, app).await?;
        Ok::<(), Error>(())
    })
}
