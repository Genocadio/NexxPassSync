use axum::{extract::State, routing::get, Json, Router};
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

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
}

async fn live() -> Json<LiveResponse> {
    Json(LiveResponse { status: "live" })
}

async fn ready(State(state): State<AppState>) -> Result<Json<ReadyResponse>, AppError> {
    sqlx::query("SELECT 1").execute(&state.database).await?;
    Ok(Json(ReadyResponse {
        status: "ready",
        database: "connected",
    }))
}
