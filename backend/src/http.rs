use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    http::{
        header::{HeaderName, HeaderValue},
        Request, StatusCode,
    },
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
    let authenticated_routes = Router::new()
        .route(
            "/accounts/me",
            axum::routing::get(crate::account::get_account_me),
        )
        .route(
            "/accounts/recovery",
            axum::routing::get(crate::device::get_recovery_wraps),
        )
        .route("/accounts/lock", post(crate::device::lock_account))
        .route("/accounts/migrate", post(crate::device::migrate_identity))
        .route("/accounts/disable-sync", post(crate::device::disable_sync))
        .route(
            "/accounts",
            axum::routing::delete(crate::device::delete_account),
        )
        .route(
            "/accounts/deletion/cancel",
            post(crate::device::cancel_deletion),
        )
        .route(
            "/devices",
            axum::routing::get(crate::device::list_devices)
                .post(crate::device::register_device_recovery),
        )
        .route(
            "/devices/{device_id}",
            axum::routing::delete(crate::device::revoke_device),
        )
        .route(
            "/pairings/{pairing_id}/approve",
            post(crate::pairing::approve_pairing),
        )
        .route(
            "/pairings/relay",
            post(crate::pairing::submit_pairing_relay),
        )
        .route("/sync/batch", post(crate::sync::handle_sync_batch))
        .route(
            "/sync/attachments/{record_id}/{attachment_id}",
            axum::routing::get(crate::attachment::get_attachment)
                .put(crate::attachment::put_attachment),
        )
        .route(
            "/sync/attachments/{record_id}/reconcile",
            post(crate::attachment::reconcile_attachments),
        )
        .route(
            "/sync/events",
            axum::routing::get(crate::sync::handle_sync_events),
        )
        .route("/sync/pull", post(crate::pull::handle_sync_pull))
        .route("/sync/ack", post(crate::pull::handle_sync_ack))
        .route("/rotation/start", post(crate::rotation::start_rotation))
        .route(
            "/rotation/heartbeat",
            post(crate::rotation::heartbeat_rotation),
        )
        .route("/rotation/resume", post(crate::rotation::resume_rotation))
        .route("/rotation/ack", post(crate::rotation::ack_rotation))
        .route(
            "/rotation/complete",
            post(crate::rotation::complete_rotation),
        )
        .route("/rotation/abort", post(crate::rotation::abort_rotation))
        .route("/rotation/rewrite", post(crate::rotation::rewrite_rotation))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::authenticate_device,
        ))
        .layer(DefaultBodyLimit::max(
            crate::attachment::MAX_ATTACHMENT_REQUEST_BYTES,
        ))
        .layer(RequestBodyLimitLayer::new(
            crate::attachment::MAX_ATTACHMENT_REQUEST_BYTES,
        ));
    let public_routes = Router::new()
        .route("/accounts", post(crate::registration::register_account))
        .route("/pairings", post(crate::pairing::create_pairing_challenge))
        .route(
            "/pairings/relay/{device_id}",
            axum::routing::get(crate::pairing::get_pairing_relay),
        )
        .layer(RequestBodyLimitLayer::new(1024 * 1024));
    let api_v1 = Router::new()
        .merge(public_routes)
        .merge(authenticated_routes);
    Router::new()
        .nest("/health", health::routes())
        .route("/health", axum::routing::get(health::deep_health))
        .route("/metrics", axum::routing::get(health::metrics))
        .nest("/v1", api_v1)
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        // Avoid TraceLayer's default header/body recording. Keep request logs
        // metadata-only; signed bytes and secrets must never be emitted.
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(map_payload_limit_error))
        .layer(middleware::from_fn(set_security_headers))
        .layer(middleware::from_fn_with_state(state.clone(), track_metrics))
        .with_state(state)
}

async fn track_metrics(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    state
        .metrics
        .total_requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        state
            .metrics
            .error_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    response
}

async fn set_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
    response
}

async fn map_payload_limit_error(request: Request<Body>, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::RequestTooLarge.into_response()
    } else {
        response
    }
}
