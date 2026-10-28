use std::{
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use crate::{error::AppError, state::AppState};

#[derive(Serialize)]
pub struct LiveResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub database: &'static str,
}

#[derive(Serialize)]
pub struct DatabaseHealth {
    pub status: &'static str,
    pub latency_ms: u128,
    pub pool_size: u32,
    pub pool_idle: usize,
}

#[derive(Serialize)]
pub struct DeepHealthResponse {
    pub status: &'static str,
    pub timestamp: u64,
    pub uptime_seconds: u64,
    pub database: DatabaseHealth,
    pub active_sse_connections: i64,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(deep_health))
        .route("/live", get(live))
        .route("/ready", get(ready))
}

pub async fn live() -> Json<LiveResponse> {
    Json(LiveResponse { status: "live" })
}

pub async fn ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, AppError> {
    sqlx::query("SELECT 1").execute(&state.database).await?;
    Ok(Json(ReadyResponse {
        status: "ready",
        database: "connected",
    }))
}

pub async fn deep_health(
    State(state): State<AppState>,
) -> Result<Json<DeepHealthResponse>, (StatusCode, Json<serde_json::Value>)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let uptime = state.metrics.start_time.elapsed().as_secs();
    let active_sse = state.metrics.active_sse_connections.load(Ordering::Relaxed);

    let db_start = Instant::now();
    match sqlx::query("SELECT 1").execute(&state.database).await {
        Ok(_) => {
            let latency_ms = db_start.elapsed().as_millis();
            let db_health = DatabaseHealth {
                status: "connected",
                latency_ms,
                pool_size: state.database.size(),
                pool_idle: state.database.num_idle(),
            };
            Ok(Json(DeepHealthResponse {
                status: "healthy",
                timestamp: now,
                uptime_seconds: uptime,
                database: db_health,
                active_sse_connections: active_sse,
            }))
        }
        Err(e) => {
            tracing::error!("Deep health check database error: {e}");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "degraded",
                    "error": "database_unavailable",
                    "timestamp": now,
                    "uptime_seconds": uptime,
                })),
            ))
        }
    }
}

pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.metrics.start_time.elapsed().as_secs();
    let total = state.metrics.total_requests.load(Ordering::Relaxed);
    let errors = state.metrics.error_requests.load(Ordering::Relaxed);
    let active_sse = state.metrics.active_sse_connections.load(Ordering::Relaxed);
    let db_size = state.database.size();
    let db_idle = state.database.num_idle();

    let body = format!(
        "# HELP nexxpass_sync_uptime_seconds Total seconds server has been running\n\
         # TYPE nexxpass_sync_uptime_seconds counter\n\
         nexxpass_sync_uptime_seconds {}\n\n\
         # HELP nexxpass_sync_http_requests_total Total number of HTTP requests processed\n\
         # TYPE nexxpass_sync_http_requests_total counter\n\
         nexxpass_sync_http_requests_total {}\n\n\
         # HELP nexxpass_sync_http_errors_total Total number of HTTP client/server errors returned\n\
         # TYPE nexxpass_sync_http_errors_total counter\n\
         nexxpass_sync_http_errors_total {}\n\n\
         # HELP nexxpass_sync_active_sse_connections Current active SSE streaming connections\n\
         # TYPE nexxpass_sync_active_sse_connections gauge\n\
         nexxpass_sync_active_sse_connections {}\n\n\
         # HELP nexxpass_sync_db_pool_connections Total database pool connections\n\
         # TYPE nexxpass_sync_db_pool_connections gauge\n\
         nexxpass_sync_db_pool_connections{{state=\"total\"}} {}\n\
         nexxpass_sync_db_pool_connections{{state=\"idle\"}} {}\n",
        uptime, total, errors, active_sse, db_size, db_idle
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}
