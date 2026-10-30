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
    #[error("client update required for signed deletion support")]
    DeleteProofRequired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("device revoked")]
    DeviceRevoked,
    #[error("device revoked")]
    DeviceRevokedWithDetails {
        reason: Option<String>,
        revocation_proof: Option<String>,
    },
    #[error("sync disabled")]
    SyncDisabled,
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
    #[error("resync required")]
    ResyncRequired,
    #[error("conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited { retry_after_s: u32 },
    #[error("quota exceeded")]
    QuotaExceeded,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    wipe_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    re_enable_requires_new_account: Option<bool>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut wipe_required = None;
        let mut revoked_reason = None;
        let mut revocation_proof = None;
        let mut re_enable_requires_new_account = None;

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
            Self::DeleteProofRequired => (
                StatusCode::UPGRADE_REQUIRED,
                "delete_proof_required",
                "Update the client to a version that supports signed deletions.",
                None,
            ),
            Self::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                "invalid_signature",
                "Authentication failed.",
                None,
            ),
            Self::DeviceRevoked => {
                wipe_required = Some(true);
                (
                    StatusCode::FORBIDDEN,
                    "device_revoked",
                    "This device has been revoked. Erase local vault data and reset to start page.",
                    None,
                )
            }
            Self::DeviceRevokedWithDetails {
                reason,
                revocation_proof: proof,
            } => {
                wipe_required = Some(true);
                revoked_reason = reason;
                revocation_proof = proof;
                (
                    StatusCode::FORBIDDEN,
                    "device_revoked",
                    "This device has been revoked. Erase local vault data and reset to start page.",
                    None,
                )
            }
            Self::SyncDisabled => {
                re_enable_requires_new_account = Some(true);
                (
                    StatusCode::FORBIDDEN,
                    "sync_disabled",
                    "Sync has been disabled for this account. Register a new account to resume syncing.",
                    None,
                )
            }
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
            Self::ResyncRequired => (
                StatusCode::GONE,
                "resync_required",
                "Checkpoint is below the retained history floor.",
                None,
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                "conflict",
                "The request conflicts with existing account state.",
                None,
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "Resource not found.",
                None,
            ),
            Self::RateLimited { retry_after_s } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests.",
                Some(retry_after_s),
            ),
            Self::QuotaExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "quota_exceeded",
                "Account storage or device quota exceeded.",
                Some(60),
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "Service temporarily unavailable.",
                Some(5),
            ),
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let proof_header = revocation_proof.clone();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code,
                    message,
                    request_id: request_id.clone(),
                    retry_after_s,
                    wipe_required,
                    revoked_reason,
                    revocation_proof,
                    re_enable_requires_new_account,
                },
            }),
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        if wipe_required == Some(true) {
            response.headers_mut().insert(
                HeaderName::from_static("x-nexxpass-wipe-vault"),
                HeaderValue::from_static("true"),
            );
        }
        if let Some(proof) = proof_header {
            if let Ok(value) = HeaderValue::from_str(&proof) {
                response.headers_mut().insert(
                    HeaderName::from_static("x-nexxpass-revocation-proof"),
                    value,
                );
            }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn missing_delete_proof_returns_an_explicit_client_upgrade_error() {
        let response = AppError::DeleteProofRequired.into_response();
        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);

        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["error"]["code"], "delete_proof_required");
    }
}
