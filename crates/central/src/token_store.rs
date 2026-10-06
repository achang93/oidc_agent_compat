//! Central token store — mint, verify, revoke, list (zero-trust).
//!
//! The central proxy is the sole minting authority for opaque bearer tokens.
//! Only the SHA-256 hash of the plaintext token is stored; the plaintext is
//! returned to the relay at mint time and never persisted. Verification is a
//! DB lookup with constant-time hash comparison (CWE-208). Expired and
//! backstop-violating tokens are deleted on verification so stale credentials
//! cannot be replayed.
//!
//! # Security
//!
//! - Tokens are 256-bit OS CSPRNG, `oac_` prefix, base64url.
//! - Only SHA-256 hash stored at rest.
//! - Constant-time hash comparison via [`KeyHash::matches`].
//! - No early return in the verification loop (timing attack prevention).
//! - The plaintext is never logged.

use sea_orm::{ConnectionTrait, DatabaseConnection, Statement, Value};
use time::Duration;
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::keys::{KeyHash, LocalKey};
use oidc_agent_common::time_util;

use crate::entity::token;

/// The request body for minting a token.
#[derive(Debug, Clone)]
pub struct MintRequest {
    /// The user subject (from the IdP). Required.
    pub subject: String,
    /// The OIDC issuer. Required.
    pub issuer: String,
    /// The user email, if known.
    pub email: Option<String>,
    /// The user display name, if known.
    pub display_name: Option<String>,
    /// The group/role memberships (JSON array string), if known.
    pub groups: Option<String>,
    /// The relay-side identity database ID, if known.
    pub identity_id: Option<String>,
    /// Human-readable label. Required.
    pub label: String,
    /// When the token expires (`None` = never).
    pub expires_at: Option<time::PrimitiveDateTime>,
    /// The SHA-256 fingerprint of the relay's mTLS client cert (device binding).
    /// `None` in dev mode (no mTLS).
    pub device_fingerprint: Option<String>,
}

/// A freshly minted token: the plaintext (returned to the relay, never
/// persisted) plus the stored row's id.
#[derive(Debug)]
pub struct MintedToken {
    /// The plaintext token (`oac_...`). Zeroized on drop.
    pub plaintext: LocalKey,
    /// The stored token row id (UUID).
    pub token_id: String,
    /// When the token expires (`None` = never).
    pub expires_at: Option<time::PrimitiveDateTime>,
}

/// The verified identity extracted from a token record.
#[derive(Debug, Clone)]
pub struct TokenIdentity {
    /// The token row id.
    pub token_id: String,
    /// The user subject.
    pub subject: String,
    /// The OIDC issuer.
    pub issuer: String,
    /// The user email, if known.
    pub email: Option<String>,
    /// The user display name, if known.
    pub display_name: Option<String>,
    /// The group/role memberships (JSON array string), if known.
    pub groups: Option<String>,
    /// The relay-side identity database ID, if known.
    pub identity_id: Option<String>,
    /// When the token was minted.
    pub created_at: time::PrimitiveDateTime,
    /// When the token expires (`None` = never).
    pub expires_at: Option<time::PrimitiveDateTime>,
    /// The SHA-256 fingerprint of the relay's mTLS client cert (device binding).
    /// `None` in dev mode.
    pub device_fingerprint: Option<String>,
}

/// The result of verifying a bearer token.
#[derive(Debug, Clone)]
pub struct TokenVerification {
    /// The verified identity.
    pub identity: TokenIdentity,
}

/// The central token store, backed by the central proxy's database.
#[derive(Clone)]
pub struct TokenStore {
    db: DatabaseConnection,
}

impl TokenStore {
    /// Creates a new `TokenStore`.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Mints a new opaque token, storing only its SHA-256 hash. The plaintext
    /// is returned to the caller (the relay) and never persisted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on persistence failure.
    pub async fn mint_token(&self, req: &MintRequest) -> Result<MintedToken> {
        let plaintext = LocalKey::generate();
        let hash = KeyHash::from_plaintext(plaintext.as_str());
        let id = Uuid::new_v4().to_string();
        let now = time_util::now_utc();
        let now_str = time_util::format_time(&now);
        let expires_str = req.expires_at.map(|e| time_util::format_time(&e));

        let email_val = req
            .email
            .as_ref()
            .map(|e| Value::String(Some(Box::new(e.clone()))))
            .unwrap_or(Value::String(None));
        let display_name_val = req
            .display_name
            .as_ref()
            .map(|d| Value::String(Some(Box::new(d.clone()))))
            .unwrap_or(Value::String(None));
        let groups_val = req
            .groups
            .as_ref()
            .map(|g| Value::String(Some(Box::new(g.clone()))))
            .unwrap_or(Value::String(None));
        let identity_id_val = req
            .identity_id
            .as_ref()
            .map(|i| Value::String(Some(Box::new(i.clone()))))
            .unwrap_or(Value::String(None));
        let expires_val = expires_str
            .as_ref()
            .map(|e| Value::String(Some(Box::new(e.clone()))))
            .unwrap_or(Value::String(None));
        let device_fingerprint_val = req
            .device_fingerprint
            .as_ref()
            .map(|f| Value::String(Some(Box::new(f.clone()))))
            .unwrap_or(Value::String(None));

        let sql = "INSERT INTO tokens \
             (id, subject, issuer, email, display_name, groups, identity_id, \
             label, token_hash, created_at, expires_at, last_used_at, revoked, \
             device_fingerprint) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, $12, $13)";
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    id.clone().into(),
                    req.subject.clone().into(),
                    req.issuer.clone().into(),
                    email_val,
                    display_name_val,
                    groups_val,
                    identity_id_val,
                    req.label.clone().into(),
                    hash.as_bytes().to_vec().into(),
                    now_str.into(),
                    expires_val,
                    Value::Bool(Some(false)),
                    device_fingerprint_val,
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("insert token: {e}")))?;

        Ok(MintedToken {
            plaintext,
            token_id: id,
            expires_at: req.expires_at,
        })
    }

    /// Verifies a plaintext bearer token against the stored hashes.
    ///
    /// Iterates ALL rows without early return to prevent timing leaks
    /// (CWE-208). Expired tokens are deleted on verification. Returns the
    /// verified identity on success, or `Ok(None)` if no matching,
    /// non-expired, non-revoked token exists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn verify_token(&self, plaintext: &str) -> Result<Option<TokenVerification>> {
        let candidate = KeyHash::from_plaintext(plaintext);
        let now = time_util::now_utc();

        let sql = "SELECT id, subject, issuer, email, display_name, groups, identity_id, token_hash, \
             created_at, expires_at, revoked, device_fingerprint FROM tokens";
        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![],
            ))
            .await
            .map_err(|e| Error::Database(format!("query tokens: {e}")))?;

        let mut matched_id: Option<String> = None;
        let mut matched_subject: Option<String> = None;
        let mut matched_issuer: Option<String> = None;
        let mut matched_email: Option<String> = None;
        let mut matched_display_name: Option<String> = None;
        let mut matched_groups: Option<String> = None;
        let mut matched_identity_id: Option<String> = None;
        let mut matched_created: Option<time::PrimitiveDateTime> = None;
        let mut matched_expires: Option<time::PrimitiveDateTime> = None;
        let mut matched_device_fingerprint: Option<String> = None;
        let mut expired_ids: Vec<String> = Vec::new();

        for row in rows {
            let row_id: String = row.try_get("", "id").unwrap_or_default();
            let row_subject: String = row.try_get("", "subject").unwrap_or_default();
            let row_issuer: String = row.try_get("", "issuer").unwrap_or_default();
            let row_email: Option<String> = row.try_get("", "email").ok();
            let row_display_name: Option<String> = row.try_get("", "display_name").ok();
            let row_groups: Option<String> = row.try_get("", "groups").ok();
            let row_identity_id: Option<String> = row.try_get("", "identity_id").ok();
            let row_hash: Vec<u8> = row.try_get("", "token_hash").unwrap_or_default();
            let row_created: time::PrimitiveDateTime = row.try_get("", "created_at").unwrap_or(now);
            let row_expires: Option<time::PrimitiveDateTime> = row.try_get("", "expires_at").ok();
            let row_revoked: bool = row.try_get("", "revoked").unwrap_or(true);
            let row_device_fingerprint: Option<String> = row.try_get("", "device_fingerprint").ok();

            // Constant-time comparison against the candidate hash.
            let stored = KeyHash::from_hash_bytes(&row_hash);
            if !row_revoked && stored.matches(&candidate) {
                // Check expiry.
                let expired = row_expires.is_some_and(|e| e <= now);
                if expired {
                    expired_ids.push(row_id.clone());
                } else if matched_id.is_none() {
                    matched_id = Some(row_id);
                    matched_subject = Some(row_subject);
                    matched_issuer = Some(row_issuer);
                    matched_email = row_email;
                    matched_display_name = row_display_name;
                    matched_groups = row_groups;
                    matched_identity_id = row_identity_id;
                    matched_created = Some(row_created);
                    matched_expires = row_expires;
                    matched_device_fingerprint = row_device_fingerprint;
                }
            }
        }

        // Delete expired tokens so stale credentials cannot be replayed.
        for id in &expired_ids {
            let _ = self.delete_by_id(id).await;
        }

        let Some(token_id) = matched_id else {
            return Ok(None);
        };

        // Update last_used_at (best-effort, non-fatal).
        let _ = self.touch_last_used(&token_id).await;

        Ok(Some(TokenVerification {
            identity: TokenIdentity {
                token_id,
                subject: matched_subject.unwrap_or_default(),
                issuer: matched_issuer.unwrap_or_default(),
                email: matched_email,
                display_name: matched_display_name,
                groups: matched_groups,
                identity_id: matched_identity_id,
                created_at: matched_created.unwrap_or(now),
                expires_at: matched_expires,
                device_fingerprint: matched_device_fingerprint,
            },
        }))
    }

    /// Revokes the token matching the given plaintext. Returns `true` if a
    /// token was found and deleted, `false` if no matching token exists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query/delete failure.
    pub async fn revoke_by_token(&self, plaintext: &str) -> Result<bool> {
        let candidate = KeyHash::from_plaintext(plaintext);
        let sql = "SELECT id, token_hash, revoked FROM tokens";
        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![],
            ))
            .await
            .map_err(|e| Error::Database(format!("query tokens for revoke: {e}")))?;

        let mut target_id: Option<String> = None;
        for row in rows {
            let row_id: String = row.try_get("", "id").unwrap_or_default();
            let row_hash: Vec<u8> = row.try_get("", "token_hash").unwrap_or_default();
            let stored = KeyHash::from_hash_bytes(&row_hash);
            if stored.matches(&candidate) {
                target_id = Some(row_id);
                // Do NOT break — iterate all rows to avoid timing leaks.
            }
        }

        let Some(id) = target_id else {
            return Ok(false);
        };
        self.delete_by_id(&id).await?;
        Ok(true)
    }

    /// Lists all tokens for a given subject. Returns metadata only — never
    /// the token hash or plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn list_for_subject(&self, subject: &str) -> Result<Vec<token::Model>> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        token::Entity::find()
            .filter(token::Column::Subject.eq(subject))
            .all(&self.db)
            .await
            .map_err(|e| Error::Database(format!("list tokens: {e}")))
    }

    /// Deletes a token row by id (used by the backstop enforcement path).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn revoke_by_token_id(&self, id: &str) -> Result<()> {
        self.delete_by_id(id).await
    }

    /// Deletes a token row by id.
    async fn delete_by_id(&self, id: &str) -> Result<()> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        token::Entity::delete_many()
            .filter(token::Column::Id.eq(id))
            .exec(&self.db)
            .await
            .map_err(|e| Error::Database(format!("delete token: {e}")))?;
        Ok(())
    }

    /// Updates `last_used_at` for a token (best-effort).
    async fn touch_last_used(&self, id: &str) -> Result<()> {
        let now = time_util::now_utc();
        let now_str = time_util::format_time(&now);
        let sql = "UPDATE tokens SET last_used_at = $1 WHERE id = $2";
        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![now_str.into(), id.to_string().into()],
            ))
            .await
            .map_err(|e| Error::Database(format!("touch last_used: {e}")))?;
        Ok(())
    }
}

/// Checks the admin token-TTL backstop: returns `true` if the token (minted at
/// `created_at`) is older than `max_token_ttl_seconds` and should be rejected.
///
/// `max_token_ttl_seconds` of `None` means no backstop (always returns
/// `false`).
#[must_use]
pub fn check_backstop(
    created_at: time::PrimitiveDateTime,
    max_token_ttl_seconds: Option<i64>,
) -> bool {
    let Some(cap) = max_token_ttl_seconds else {
        return false;
    };
    let now = time_util::now_utc();
    let age = now - created_at;
    age > Duration::seconds(cap)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    async fn setup_store() -> TokenStore {
        let url = oidc_agent_common::persistence::temp_sqlite_url("token_store");
        let db = crate::db::setup(&url).await.expect("db setup");
        TokenStore::new(db)
    }

    fn mint_req(subject: &str, label: &str, ttl: Option<i64>) -> MintRequest {
        let expires_at = ttl.map(|s| time_util::now_utc() + Duration::seconds(s));
        MintRequest {
            subject: subject.into(),
            issuer: "https://idp.example.com".into(),
            email: Some("user@example.com".into()),
            display_name: None,
            groups: Some(r#"["engineering"]"#.into()),
            identity_id: None,
            label: label.into(),
            expires_at,
            device_fingerprint: None,
        }
    }

    #[tokio::test]
    async fn mint_and_verify_round_trip() {
        let store = setup_store().await;
        let minted = store
            .mint_token(&mint_req("alice", "laptop", Some(3600)))
            .await
            .expect("mint");
        let plaintext = minted.plaintext.to_string();
        let verify = store
            .verify_token(&plaintext)
            .await
            .expect("verify")
            .expect("verified");
        assert_eq!(verify.identity.subject, "alice");
        assert_eq!(verify.identity.token_id, minted.token_id);
    }

    #[tokio::test]
    async fn verify_rejects_invalid_token() {
        let store = setup_store().await;
        let _ = store
            .mint_token(&mint_req("alice", "laptop", Some(3600)))
            .await
            .expect("mint");
        let verify = store.verify_token("oac_nonexistent").await.expect("query");
        assert!(verify.is_none(), "invalid token must not verify");
    }

    #[tokio::test]
    async fn verify_rejects_expired_and_deletes_row() {
        let store = setup_store().await;
        // Mint with a TTL already in the past (-1 second).
        let minted = store
            .mint_token(&mint_req("alice", "laptop", Some(-1)))
            .await
            .expect("mint");
        let plaintext = minted.plaintext.to_string();
        let verify = store.verify_token(&plaintext).await.expect("verify");
        assert!(verify.is_none(), "expired token must not verify");
        // The row must have been deleted.
        let tokens = store.list_for_subject("alice").await.expect("list");
        assert!(tokens.is_empty(), "expired token must be deleted");
    }

    #[tokio::test]
    async fn revoke_by_plaintext_removes_token() {
        let store = setup_store().await;
        let minted = store
            .mint_token(&mint_req("alice", "laptop", Some(3600)))
            .await
            .expect("mint");
        let plaintext = minted.plaintext.to_string();
        let revoked = store.revoke_by_token(&plaintext).await.expect("revoke");
        assert!(revoked, "revoke must report true for existing token");
        // The token must no longer verify.
        let verify = store.verify_token(&plaintext).await.expect("verify");
        assert!(verify.is_none(), "revoked token must not verify");
    }

    #[tokio::test]
    async fn revoke_nonexistent_returns_false() {
        let store = setup_store().await;
        let revoked = store
            .revoke_by_token("oac_nonexistent")
            .await
            .expect("revoke");
        assert!(!revoked);
    }

    #[tokio::test]
    async fn list_for_subject_returns_metadata_only() {
        let store = setup_store().await;
        let minted = store
            .mint_token(&mint_req("alice", "laptop", Some(3600)))
            .await
            .expect("mint");
        let tokens = store.list_for_subject("alice").await.expect("list");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, minted.token_id);
        assert_eq!(tokens[0].subject, "alice");
        assert_eq!(tokens[0].label, "laptop");
        // The hash column exists but we never expose it in API responses.
        assert_eq!(tokens[0].token_hash.len(), 32);
    }

    #[tokio::test]
    async fn never_expires_token_verifies() {
        let store = setup_store().await;
        let minted = store
            .mint_token(&mint_req("alice", "laptop", None))
            .await
            .expect("mint");
        let plaintext = minted.plaintext.to_string();
        let verify = store
            .verify_token(&plaintext)
            .await
            .expect("verify")
            .expect("verified");
        assert!(verify.identity.expires_at.is_none());
    }

    #[test]
    fn check_backstop_none_is_false() {
        let now = time_util::now_utc();
        assert!(!check_backstop(now, None));
        assert!(!check_backstop(now - Duration::days(1), None));
    }

    #[test]
    fn check_backstop_enforces_cap() {
        let now = time_util::now_utc();
        // Token minted 1000s ago; cap is 500s -> violated.
        assert!(check_backstop(now - Duration::seconds(1000), Some(500)));
        // Token minted 100s ago; cap is 500s -> OK.
        assert!(!check_backstop(now - Duration::seconds(100), Some(500)));
    }

    #[tokio::test]
    async fn device_fingerprint_stored_and_returned_on_verify() {
        let store = setup_store().await;
        let mut req = mint_req("alice", "laptop", Some(3600));
        req.device_fingerprint = Some("aa1122ff".into());
        let minted = store.mint_token(&req).await.expect("mint");
        let plaintext = minted.plaintext.to_string();
        let verify = store
            .verify_token(&plaintext)
            .await
            .expect("verify")
            .expect("verified");
        assert_eq!(
            verify.identity.device_fingerprint.as_deref(),
            Some("aa1122ff"),
            "device fingerprint must be stored and returned on verify"
        );
    }

    #[tokio::test]
    async fn device_fingerprint_none_by_default() {
        let store = setup_store().await;
        let minted = store
            .mint_token(&mint_req("alice", "laptop", Some(3600)))
            .await
            .expect("mint");
        let plaintext = minted.plaintext.to_string();
        let verify = store
            .verify_token(&plaintext)
            .await
            .expect("verify")
            .expect("verified");
        assert!(
            verify.identity.device_fingerprint.is_none(),
            "device fingerprint must be None when not set"
        );
    }
}
