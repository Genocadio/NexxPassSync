use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::{error::AppError, state::AppState};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    sqlx::query("SELECT 1").execute(&state.database).await?;
    Ok(Json(HealthResponse { status: "ready" }))
}
