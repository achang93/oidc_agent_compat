//! Authentication middleware for the central proxy.
//!
//! The central proxy authenticates each request by verifying the opaque
//! bearer token from the `Authorization: Bearer <token>` header against the
//! central token store (zero-trust). The token store performs a DB lookup
//! with constant-time hash comparison and returns the verified identity
//! from the token record. Relay-forwarded `X-OAC-*` identity headers are
//! **ignored** for identity — the identity comes solely from the token
//! store.
//!
//! The `X-OAC-Request-Id` header is still read (it is per-request
//! correlation, not identity).
//!
//! # Security
//!
//! - Requires a valid `Authorization: Bearer <token>` header on all
//!   non-healthz routes.
//! - Rejects requests with a missing or unverifiable token with
//!   `401 Unauthorized`.
//! - Attaches the verified identity (from the token record) to the
//!   request extensions for downstream audit logging and authorization.
//! - Authentication remains mandatory in `dev_mode`; that flag relaxes
//!   transport and rate-limiting behavior, not the identity trust boundary.

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use oidc_agent_common::identity;
use oidc_agent_common::keys::extract_bearer;

use super::AppState;

/// The verified user identity attached to a central-proxy request after
/// auth.
///
/// All identity fields (`subject`, `email`, `groups`, `identity_id`) come
/// from the central token record — never from relay-forwarded headers.
/// `request_id` is per-request and still read from the `X-OAC-Request-Id`
/// header. `token_id` and `created_at` support the admin token-TTL
/// backstop check in the permissions middleware.
#[derive(Debug, Clone)]
pub struct VerifiedRelayIdentity {
    /// The user subject (from the IdP, stored in the token record).
    pub subject: String,
    /// The user email, if provided.
    pub email: Option<String>,
    /// The relay-side identity database ID, if known.
    pub identity_id: Option<String>,
    /// The group/role memberships (JSON array string), if provided.
    pub groups: Option<String>,
    /// The request ID for end-to-end correlation, if provided.
    pub request_id: Option<String>,
    /// The central token row id (for backstop enforcement).
    pub token_id: Option<String>,
    /// When the token was minted (for the admin TTL backstop check).
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// The authentication middleware for the central proxy.
///
/// Extracts the bearer token from the `Authorization` header, verifies it
/// via `state.token_store.verify_token`, and attaches the verified
/// identity (from the token record) to the request extensions. Returns
/// `401 Unauthorized` if the token is missing or unverifiable in every mode.
///
/// The `X-OAC-Request-Id` header is still read (per-request correlation).
/// All other `X-OAC-*` identity headers are ignored — the identity comes
/// from the token store, not from relay-forwarded headers.
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health check.
    if request.uri().path() == "/healthz" {
        return Ok(next.run(request).await);
    }

    // Extract the bearer token from the Authorization header.
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(extract_bearer);

    // The request ID is per-request, not per-token — still read it from
    // the X-OAC-Request-Id header for end-to-end correlation.
    let request_id = request
        .headers()
        .get(identity::HEADER_REQUEST_ID)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let bearer = match bearer {
        Some(b) => b.to_string(),
        None => {
            tracing::warn!("rejected central request without Authorization bearer token");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Verify the bearer token against the central token store.
    let verification = match state.token_store.verify_token(&bearer).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            tracing::warn!("rejected central request: token verification failed");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            tracing::error!(error = %e, "token store verification error");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let identity = verification.identity;

    // Device binding enforcement: if the token has a stored device
    // fingerprint, the request must carry a matching X-OAC-Device-Fingerprint
    // header. A mismatch (or missing header) means the token is being used
    // from a different relay than the one that minted it → 401.
    // If the token has no stored fingerprint (None, dev mode), skip the check.
    if let Some(ref stored_fp) = identity.device_fingerprint {
        let header_fp = request
            .headers()
            .get(identity::HEADER_DEVICE_FINGERPRINT)
            .and_then(|h| h.to_str().ok());
        match header_fp {
            Some(fp) if fp == stored_fp => { /* match — allowed */ }
            Some(_) => {
                tracing::warn!("device fingerprint mismatch — token bound to a different relay");
                return Err(StatusCode::UNAUTHORIZED);
            }
            None => {
                tracing::warn!(
                    "device fingerprint header missing but token has a stored fingerprint"
                );
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    // Attach the verified identity to the request extensions. All
    // identity fields come from the token record — X-OAC-* identity
    // headers are intentionally ignored.
    request.extensions_mut().insert(VerifiedRelayIdentity {
        subject: identity.subject,
        email: identity.email,
        identity_id: identity.identity_id,
        groups: identity.groups,
        request_id,
        token_id: Some(identity.token_id),
        created_at: Some(identity.created_at),
    });

    Ok(next.run(request).await)
}
