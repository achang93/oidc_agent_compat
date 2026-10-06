//! Central-side OIDC authorization-code exchange for token bootstrap.
//!
//! The relay is a native application and therefore cannot keep an OIDC
//! client secret. It starts the authorization-code + PKCE flow, then sends
//! the one-time code, PKCE verifier, redirect URI, and nonce to central over
//! mTLS. Central performs the token exchange and validates the resulting ID
//! token before any identity or group data can reach the token store.

use async_trait::async_trait;
use oidc_agent_common::config::OidcConfig;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::oidc::{
    CustomClient, CustomIdTokenClaims, CustomProviderMetadata, CustomUserInfoClaims,
    groups_to_json_string, union_groups_roles,
};
use openidconnect::core::CoreJwsSigningAlgorithm;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeVerifier, RedirectUrl, SubjectIdentifier,
};

/// A one-time OIDC authorization-code grant received from a relay.
///
/// This type intentionally does not implement `Debug`: the authorization
/// code and PKCE verifier are short-lived secrets and must not reach logs.
pub struct BootstrapGrant {
    /// The authorization code returned to the relay's loopback callback.
    pub authorization_code: String,
    /// The PKCE verifier paired with the authorization request's S256 challenge.
    pub pkce_verifier: String,
    /// The exact loopback redirect URI used for the authorization request.
    pub redirect_uri: String,
    /// The nonce generated for the authorization request.
    pub nonce: String,
}

/// Identity data obtained from a central-validated OIDC response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapIdentity {
    /// The OIDC issuer.
    pub issuer: String,
    /// The issuer-scoped subject identifier.
    pub subject: String,
    /// The user's email address, if supplied by the IdP.
    pub email: Option<String>,
    /// The user's display name, if supplied by the IdP.
    pub display_name: Option<String>,
    /// Deduplicated group and role claims encoded as a JSON array string.
    pub groups: Option<String>,
}

/// Exchanges bootstrap grants and returns only centrally verified identities.
#[async_trait]
pub trait BootstrapIdentityVerifier: Send + Sync {
    /// Exchanges and validates a one-time OIDC authorization-code grant.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Oidc`] when the code exchange, ID-token validation,
    /// nonce check, algorithm pin, or access-token hash check fails.
    async fn exchange_and_verify(&self, grant: &BootstrapGrant) -> Result<BootstrapIdentity>;
}

/// Production OIDC bootstrap verifier backed by discovered provider metadata.
pub struct OidcBootstrapVerifier {
    client: CustomClient,
    http_client: reqwest::Client,
}

impl OidcBootstrapVerifier {
    /// Discovers provider metadata and builds the confidential central client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Oidc`] if the configured secret is unavailable, the
    /// issuer URL is invalid, discovery fails, or the hardened HTTP client
    /// cannot be built.
    pub async fn discover(config: &OidcConfig) -> Result<Self> {
        let client_secret = oidc_agent_common::oidc::resolve_client_secret(config)?;
        let http_client = oidc_agent_common::oidc::build_http_client()?;
        let issuer_url = IssuerUrl::new(config.issuer.clone())
            .map_err(|e| Error::oidc(format!("invalid issuer URL: {e}")))?;
        let provider_metadata = CustomProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .map_err(|e| Error::oidc(format!("OIDC discovery failed: {e}")))?;
        let client = CustomClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(client_secret)),
        );
        Ok(Self {
            client,
            http_client,
        })
    }
}

#[async_trait]
impl BootstrapIdentityVerifier for OidcBootstrapVerifier {
    async fn exchange_and_verify(&self, grant: &BootstrapGrant) -> Result<BootstrapIdentity> {
        oidc_agent_common::oidc::validate_loopback_redirect(&grant.redirect_uri)?;
        let redirect_uri = RedirectUrl::new(grant.redirect_uri.clone())
            .map_err(|e| Error::oidc(format!("invalid bootstrap redirect URI: {e}")))?;
        let client = self.client.clone().set_redirect_uri(redirect_uri);

        let token_response = client
            .exchange_code(AuthorizationCode::new(grant.authorization_code.clone()))
            .map_err(|e| Error::oidc(format!("prepare token exchange: {e}")))?
            .set_pkce_verifier(PkceCodeVerifier::new(grant.pkce_verifier.clone()))
            .request_async(&self.http_client)
            .await
            .map_err(|e| Error::oidc(format!("token exchange failed: {e}")))?;

        let id_token = token_response
            .extra_fields()
            .id_token()
            .ok_or_else(|| Error::oidc("IdP did not return an ID token"))?;
        let signing_alg = id_token
            .signing_alg()
            .map_err(|e| Error::oidc(format!("ID token has no signing algorithm: {e}")))?;
        if !is_allowed_alg(signing_alg) {
            return Err(Error::oidc(
                "ID token signed with disallowed algorithm; only RS256/ES256 are accepted",
            ));
        }

        let nonce = Nonce::new(grant.nonce.clone());
        let id_token_claims: &CustomIdTokenClaims = id_token
            .claims(&client.id_token_verifier(), &nonce)
            .map_err(|e| Error::oidc(format!("ID token validation failed: {e}")))?;

        if let Some(expected_at_hash) = id_token_claims.access_token_hash() {
            let id_token_verifier = client.id_token_verifier();
            let signing_key = id_token
                .signing_key(&id_token_verifier)
                .map_err(|e| Error::oidc(format!("ID token signing key lookup failed: {e}")))?;
            let actual_at_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                signing_alg,
                signing_key,
            )
            .map_err(|e| Error::oidc(format!("at_hash computation failed: {e}")))?;
            if actual_at_hash != *expected_at_hash {
                return Err(Error::oidc(
                    "at_hash mismatch — access token may have been substituted",
                ));
            }
        }

        let identity = claims_from_id_token(id_token_claims);
        let expected_subject = SubjectIdentifier::new(identity.subject.clone());
        match client.user_info(
            token_response.access_token().clone(),
            Some(expected_subject),
        ) {
            Ok(request) => match request.request_async(&self.http_client).await {
                Ok(userinfo) => {
                    let userinfo: CustomUserInfoClaims = userinfo;
                    Ok(identity_from_userinfo(
                        id_token_claims.issuer().to_string(),
                        &userinfo,
                    ))
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "userinfo request failed, using validated ID-token claims"
                    );
                    Ok(identity)
                }
            },
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "userinfo endpoint unavailable, using validated ID-token claims"
                );
                Ok(identity)
            }
        }
    }
}

/// A fail-closed verifier for tests and callers that do not exercise login.
pub struct UnavailableBootstrapVerifier;

#[async_trait]
impl BootstrapIdentityVerifier for UnavailableBootstrapVerifier {
    async fn exchange_and_verify(&self, _grant: &BootstrapGrant) -> Result<BootstrapIdentity> {
        Err(Error::oidc("OIDC bootstrap verifier is unavailable"))
    }
}

fn is_allowed_alg(alg: &CoreJwsSigningAlgorithm) -> bool {
    matches!(
        alg,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256 | CoreJwsSigningAlgorithm::EcdsaP256Sha256
    )
}

fn claims_from_id_token(claims: &CustomIdTokenClaims) -> BootstrapIdentity {
    let display_name = claims
        .name()
        .and_then(|name| name.get(None))
        .map(|name| name.as_str().to_string())
        .or_else(|| {
            claims
                .preferred_username()
                .map(|username| username.as_str().to_string())
        });
    let groups = groups_to_json_string(&union_groups_roles(claims.additional_claims()));
    BootstrapIdentity {
        issuer: claims.issuer().to_string(),
        subject: claims.subject().to_string(),
        email: claims.email().map(|email| email.as_str().to_string()),
        display_name,
        groups,
    }
}

fn identity_from_userinfo(issuer: String, claims: &CustomUserInfoClaims) -> BootstrapIdentity {
    let display_name = claims
        .name()
        .and_then(|name| name.get(None))
        .map(|name| name.as_str().to_string())
        .or_else(|| {
            claims
                .preferred_username()
                .map(|username| username.as_str().to_string())
        });
    let groups = groups_to_json_string(&union_groups_roles(claims.additional_claims()));
    BootstrapIdentity {
        issuer,
        subject: claims.subject().to_string(),
        email: claims.email().map(|email| email.as_str().to_string()),
        display_name,
        groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_pin_accepts_only_rs256_and_es256() {
        assert!(is_allowed_alg(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
        ));
        assert!(is_allowed_alg(&CoreJwsSigningAlgorithm::EcdsaP256Sha256));
        assert!(!is_allowed_alg(&CoreJwsSigningAlgorithm::None));
        assert!(!is_allowed_alg(&CoreJwsSigningAlgorithm::HmacSha256));
        assert!(!is_allowed_alg(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384
        ));
    }

    #[test]
    fn id_token_claims_supply_authorization_identity() {
        let claims: CustomIdTokenClaims = serde_json::from_str(
            r#"{
                "iss":"https://idp.example.com",
                "sub":"alice",
                "aud":"test",
                "exp":9999999999,
                "iat":1000000000,
                "email":"alice@example.com",
                "name":"Alice Doe",
                "groups":["engineering","ai-users"],
                "roles":["admin","ai-users"]
            }"#,
        )
        .expect("claims");
        let identity = claims_from_id_token(&claims);
        assert_eq!(identity.issuer, "https://idp.example.com");
        assert_eq!(identity.subject, "alice");
        assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
        assert_eq!(identity.display_name.as_deref(), Some("Alice Doe"));
        assert_eq!(
            identity.groups.as_deref(),
            Some(r#"["admin","ai-users","engineering"]"#)
        );
    }

    #[test]
    fn id_token_claims_fall_back_to_preferred_username() {
        let claims: CustomIdTokenClaims = serde_json::from_str(
            r#"{
                "iss":"https://idp.example.com",
                "sub":"alice",
                "aud":"test",
                "exp":9999999999,
                "iat":1000000000,
                "preferred_username":"alice-user"
            }"#,
        )
        .expect("claims");
        let identity = claims_from_id_token(&claims);
        assert_eq!(identity.display_name.as_deref(), Some("alice-user"));
        assert!(identity.groups.is_none());
    }

    #[tokio::test]
    async fn unavailable_verifier_fails_closed() {
        let grant = BootstrapGrant {
            authorization_code: "code".into(),
            pkce_verifier: "verifier".into(),
            redirect_uri: "http://127.0.0.1:1234/callback".into(),
            nonce: "nonce".into(),
        };
        let result = UnavailableBootstrapVerifier
            .exchange_and_verify(&grant)
            .await;
        assert!(result.is_err());
    }
}
