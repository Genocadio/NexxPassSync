use axum::{
    http::{header::HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("malformed request")]
    MalformedRequest,
    #[error("unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("device revoked")]
    DeviceRevoked,
    #[error("identity locked")]
    IdentityLocked,
    #[error("account suspended")]
    AccountSuspended,
    #[error("account deletion pending")]
    AccountDeletionPending,
    #[error("timestamp out of range")]
    TimestampOutOfRange,
    #[error("replayed request")]
    ReplayDetected,
    #[error("invalid input")]
    InvalidInput,
    #[error("request too large")]
    RequestTooLarge,
    #[error("account id has been retired")]
    AccountIdRetired,
    #[error("pairing challenge is invalid")]
    PairingChallengeInvalid,
    #[error("account key rotation is in progress")]
    RotationInProgress,
    #[error("operation id reused with different hash")]
    OperationIdReused,
    #[error("conflict")]
    Conflict,
    #[error("service unavailable")]
    Unavailable,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_s: Option<u32>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, retry_after_s) = match self {
            Self::MalformedRequest => (
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "Malformed request.",
                None,
            ),
            Self::UnsupportedProtocolVersion => (
                StatusCode::BAD_REQUEST,
                "unsupported_protocol_version",
                "Unsupported protocol version.",
                None,
            ),
            Self::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                "Authentication failed.",
                None,
            ),
            Self::DeviceRevoked => (
                StatusCode::FORBIDDEN,
                "device_revoked",
                "This device has been revoked.",
                None,
            ),
            Self::IdentityLocked => (
                StatusCode::FORBIDDEN,
                "identity_locked",
                "Account identity is locked.",
                None,
            ),
            Self::AccountSuspended => (
                StatusCode::FORBIDDEN,
                "account_suspended",
                "Account is temporarily unavailable.",
                None,
            ),
            Self::AccountDeletionPending => (
                StatusCode::FORBIDDEN,
                "account_deletion_pending",
                "Account deletion is pending.",
                None,
            ),
            Self::TimestampOutOfRange => (
                StatusCode::UNAUTHORIZED,
                "timestamp_out_of_range",
                "Request timestamp is outside the allowed window.",
                None,
            ),
            Self::ReplayDetected => (
                StatusCode::UNAUTHORIZED,
                "replay_detected",
                "Request has already been used.",
                None,
            ),
            Self::InvalidInput => (
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Request values are invalid.",
                None,
            ),
            Self::RequestTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "Request exceeds the allowed size.",
                None,
            ),
            Self::AccountIdRetired => (
                StatusCode::CONFLICT,
                "account_id_retired",
                "This account ID cannot be registered.",
                None,
            ),
            Self::PairingChallengeInvalid => (
                StatusCode::CONFLICT,
                "pairing_challenge_invalid",
                "Pairing challenge is invalid or expired.",
                None,
            ),
            Self::RotationInProgress => (
                StatusCode::CONFLICT,
                "rotation_in_progress",
                "Pairing or mutation is unavailable during this key rotation.",
                None,
            ),
            Self::OperationIdReused => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "operation_id_reused",
                "Operation ID was previously used with a different hash.",
                None,
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "The request conflicts with existing account state.",
                None,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "Service temporarily unavailable.",
                Some(5),
            ),
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code,
                    message,
                    request_id: request_id.clone(),
                    retry_after_s,
                },
            }),
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        if let Some(seconds) = retry_after_s {
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static("retry-after"), value);
            }
        }
        response
    }
}

impl From<sqlx::Error> for AppError {
    fn from(_: sqlx::Error) -> Self {
        // Database error text may expose schema/query details; keep it out of logs.
        tracing::error!("database operation failed");
        Self::Unavailable
    }
}
