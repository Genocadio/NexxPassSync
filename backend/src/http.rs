use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{error::AppError, health, state::AppState};

pub fn router(state: AppState) -> Router {
    let device_routes = Router::new()
        .route(
            "/accounts/me",
            axum::routing::get(crate::account::get_account_me),
        )
        .route(
            "/pairings/{pairing_id}/approve",
            post(crate::pairing::approve_pairing),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::authenticate_device,
        ));
    let api_v1 = Router::new()
        .route("/accounts", post(crate::registration::register_account))
        .route("/pairings", post(crate::pairing::create_pairing_challenge))
        .merge(device_routes);
    Router::new()
        .nest("/health", health::routes())
        .nest("/v1", api_v1)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(RequestBodyLimitLayer::new(128 * 1024))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        // Avoid TraceLayer's default header/body recording. Keep request logs
        // metadata-only; signed bytes and secrets must never be emitted.
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(map_payload_limit_error))
        .with_state(state)
}

async fn map_payload_limit_error(request: Request<Body>, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::RequestTooLarge.into_response()
    } else {
        response
    }
}
