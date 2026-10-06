//! The central proxy binary entrypoint.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use oac_central::audit::AuditLogger;
use oac_central::db;
use oac_central::provider::ProviderStore;
use oac_central::proxy;
use oidc_agent_common::config::CentralConfig;
use oidc_agent_common::error::Result;

/// The central proxy for the OIDC agent compatibility server.
#[derive(Parser, Debug)]
#[command(name = "oac-central", version, about)]
struct Cli {
    /// Path to the config file.
    #[arg(short, long, env = "OAC_CENTRAL_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// The subcommand to run.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Start the central proxy server (default).
    Serve,
    /// Admin API operations (manage policies, devices, audit logs).
    Admin(AdminCli),
    /// Mint an initial token directly from the database in dev mode only.
    #[command(hide = true)]
    DevToken {
        /// Subject stored on the development token.
        #[arg(long, default_value = "dev-user")]
        subject: String,
        /// Comma-separated development groups.
        #[arg(long)]
        groups: Option<String>,
        /// Human-readable token label.
        #[arg(long, default_value = "dev-bootstrap")]
        label: String,
    },
}

/// Admin CLI subcommands.
#[derive(Parser, Debug)]
struct AdminCli {
    /// The relay URL to send admin requests through (the relay authenticates
    /// the user via OIDC and forwards to central). Defaults to
    /// http://127.0.0.1:8787.
    #[arg(long, env = "OAC_ADMIN_URL")]
    url: Option<String>,

    /// The local API key (obtained via `oac-relay login`). The relay
    /// authenticates the user via OIDC and forwards the request to central
    /// with the verified identity headers. The user must belong to the
    /// configured admin group.
    #[arg(long, env = "OAC_API_KEY")]
    key: String,

    /// The subcommand to run.
    #[command(subcommand)]
    subcommand: AdminSubcommand,
}

/// Admin subcommands.
#[derive(Subcommand, Debug)]
enum AdminSubcommand {
    /// List all configured providers.
    ProviderList,
    /// Create or update a provider.
    ProviderSet {
        /// Stable provider identifier.
        id: String,
        /// Human-readable provider name.
        #[arg(long)]
        name: String,
        /// OpenAI-compatible backend base URL.
        #[arg(long)]
        base_url: String,
        /// Comma-separated exact model names; omit for all models.
        #[arg(long)]
        models: Option<String>,
        /// Mark the provider as the default fallback.
        #[arg(long)]
        default: bool,
        /// Disable the provider.
        #[arg(long)]
        disabled: bool,
    },
    /// Delete a provider and all of its keys.
    ProviderDelete { id: String },
    /// Set the default fallback provider.
    ProviderDefault { id: String },
    /// List metadata for a provider's keys.
    ProviderKeyList { provider_id: String },
    /// Add a provider key, reading its secret without echo.
    ProviderKeyAdd {
        /// Provider identifier.
        provider_id: String,
        /// Human-readable key label.
        #[arg(long)]
        label: String,
        /// Selection priority; lower values are preferred.
        #[arg(long, default_value = "0")]
        priority: i32,
        /// Comma-separated groups allowed to use this key.
        #[arg(long)]
        groups: Option<String>,
    },
    /// Delete a provider key.
    ProviderKeyDelete { provider_id: String, key_id: String },
    /// List all group policies.
    PolicyList,
    /// Get a single group policy.
    PolicyGet { name: String },
    /// Set (upsert) a group policy.
    PolicySet {
        name: String,
        /// Comma-separated list of allowed models (omit for all).
        #[arg(long)]
        models: Option<String>,
        /// Comma-separated list of allowed endpoints (omit for all).
        #[arg(long)]
        endpoints: Option<String>,
        /// Daily token quota.
        #[arg(long)]
        token_quota: Option<i64>,
        /// Daily request quota.
        #[arg(long)]
        request_quota: Option<i64>,
    },
    /// Delete a group policy.
    PolicyDelete { name: String },
    /// List all devices.
    DeviceList,
    /// Revoke a device.
    DeviceRevoke { fingerprint: String },
    /// Reinstate a revoked device.
    DeviceReinstate { fingerprint: String },
    /// Query the audit log.
    AuditQuery {
        /// Filter by user subject.
        #[arg(long)]
        subject: Option<String>,
        /// Maximum number of entries.
        #[arg(long, default_value = "100")]
        limit: u32,
        /// Number of newest entries to skip.
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Query usage (per-user request/token/cost totals).
    UsageQuery {
        /// Filter by user subject. If omitted, returns all users.
        #[arg(long)]
        subject: Option<String>,
    },
    /// Get quota status for a user.
    QuotaGet {
        /// The user subject.
        subject: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    let _ = oidc_agent_common::logging::init();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| oidc_agent_common::error::Error::Internal(format!("tokio runtime: {e}")))?;
    rt.block_on(async {
        match cli.command.unwrap_or(Command::Serve) {
            Command::Serve => serve(config).await,
            Command::Admin(admin_cli) => admin(admin_cli).await,
            Command::DevToken {
                subject,
                groups,
                label,
            } => mint_dev_token(&config, subject, groups, label).await,
        }
    })
}

/// Mints an initial development token through direct database access.
async fn mint_dev_token(
    config: &CentralConfig,
    subject: String,
    groups: Option<String>,
    label: String,
) -> Result<()> {
    if !config.dev_mode {
        return Err(oidc_agent_common::error::Error::Config(
            "dev-token is disabled unless dev_mode = true".into(),
        ));
    }
    if subject.trim().is_empty() {
        return Err(oidc_agent_common::error::Error::Config(
            "dev-token subject must not be empty".into(),
        ));
    }
    if label.trim().is_empty() {
        return Err(oidc_agent_common::error::Error::Config(
            "dev-token label must not be empty".into(),
        ));
    }
    let groups = groups
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|group| !group.is_empty())
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .filter(|groups| !groups.is_empty())
        .map(|groups| serde_json::to_string(&groups))
        .transpose()
        .map_err(|error| oidc_agent_common::error::Error::Internal(error.to_string()))?;
    let db = db::setup(&config.database_url).await?;
    let minted = oac_central::token_store::TokenStore::new(db)
        .mint_token(&oac_central::token_store::MintRequest {
            subject,
            issuer: config.oidc.issuer.clone(),
            email: None,
            display_name: None,
            groups,
            identity_id: None,
            label,
            expires_at: None,
            device_fingerprint: None,
        })
        .await?;
    println!("{}", minted.plaintext.as_str());
    Ok(())
}

/// Loads the central config from the given path.
fn load_config(path: &std::path::Path) -> Result<CentralConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        oidc_agent_common::error::Error::Config(format!("read {}: {e}", path.display()))
    })?;
    CentralConfig::from_toml(&contents)
}

/// Starts the central proxy server.
async fn serve(config: CentralConfig) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    let audit = AuditLogger::new(db);

    let encryption_key = load_provider_encryption_key()?;
    let encryption_key = ProviderStore::encryption_key_from_hex(&encryption_key)?;

    proxy::serve(config, encryption_key, audit).await
}

/// Loads the provider-key encryption key from the environment or the
/// conventional Docker secret path.
fn load_provider_encryption_key() -> Result<String> {
    if let Ok(value) = std::env::var("OAC_PROVIDER_ENCRYPTION_KEY") {
        return Ok(value);
    }
    std::fs::read_to_string("/run/secrets/provider-encryption-key").map_err(|_| {
        oidc_agent_common::error::Error::Config(
            "set OAC_PROVIDER_ENCRYPTION_KEY or mount /run/secrets/provider-encryption-key".into(),
        )
    })
}

/// Runs an admin CLI command through the relay (which authenticates the user
/// via OIDC and forwards to central). The user must belong to the configured
/// admin group.
async fn admin(cli: AdminCli) -> Result<()> {
    // Resolve the relay URL. The admin sends requests through the relay,
    // which authenticates the user via their local API key (obtained via
    // `oac-relay login`) and forwards to central with the verified identity
    // headers. The user must belong to the configured admin group.
    let url = cli
        .url
        .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());

    let key = cli.key;
    let client = reqwest::Client::new();
    let base_url = url.trim_end_matches('/');

    match cli.subcommand {
        AdminSubcommand::ProviderList => {
            let resp = admin_get(&client, base_url, &key, "/admin/v1/providers").await?;
            println!("{resp}");
        }
        AdminSubcommand::ProviderSet {
            id,
            name,
            base_url: provider_base_url,
            models,
            default,
            disabled,
        } => {
            let body = serde_json::json!({
                "id": id,
                "name": name,
                "base_url": provider_base_url,
                "enabled": !disabled,
                "is_default": default,
                "models": models.map(|m| m.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect::<Vec<_>>()),
            });
            let resp =
                admin_post_json(&client, base_url, &key, "/admin/v1/providers", &body).await?;
            println!("{resp}");
        }
        AdminSubcommand::ProviderDelete { id } => {
            admin_delete(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/providers/{id}"),
            )
            .await?;
            println!("provider '{id}' deleted");
        }
        AdminSubcommand::ProviderDefault { id } => {
            admin_post(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/providers/{id}/default"),
            )
            .await?;
            println!("provider '{id}' is now the default");
        }
        AdminSubcommand::ProviderKeyList { provider_id } => {
            let resp = admin_get(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/providers/{provider_id}/keys"),
            )
            .await?;
            println!("{resp}");
        }
        AdminSubcommand::ProviderKeyAdd {
            provider_id,
            label,
            priority,
            groups,
        } => {
            let secret = rpassword::prompt_password("Provider API key: ").map_err(|e| {
                oidc_agent_common::error::Error::Internal(format!("read provider key: {e}"))
            })?;
            let body = serde_json::json!({
                "key": secret,
                "label": label,
                "priority": priority,
                "allowed_groups": groups.map(|g| g.split(',').map(|v| v.trim().to_string()).filter(|v| !v.is_empty()).collect::<Vec<_>>()).unwrap_or_default(),
            });
            let resp = admin_post_json(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/providers/{provider_id}/keys"),
                &body,
            )
            .await?;
            println!("{resp}");
        }
        AdminSubcommand::ProviderKeyDelete {
            provider_id,
            key_id,
        } => {
            admin_delete(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/providers/{provider_id}/keys/{key_id}"),
            )
            .await?;
            println!("provider key '{key_id}' deleted");
        }
        AdminSubcommand::PolicyList => {
            let resp = admin_get(&client, base_url, &key, "/admin/v1/group-policies").await?;
            println!("{resp}");
        }
        AdminSubcommand::PolicyGet { name } => {
            let resp = admin_get(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/group-policies/{name}"),
            )
            .await?;
            println!("{resp}");
        }
        AdminSubcommand::PolicySet {
            name,
            models,
            endpoints,
            token_quota,
            request_quota,
        } => {
            let body = serde_json::json!({
                "allowed_models": models.map(|m| m.split(',').map(String::from).collect::<Vec<_>>()),
                "allowed_endpoints": endpoints.map(|e| e.split(',').map(String::from).collect::<Vec<_>>()),
                "daily_token_quota": token_quota,
                "daily_request_quota": request_quota,
            });
            let resp = admin_put(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/group-policies/{name}"),
                &body,
            )
            .await?;
            println!("{resp}");
        }
        AdminSubcommand::PolicyDelete { name } => {
            admin_delete(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/group-policies/{name}"),
            )
            .await?;
            println!("policy '{name}' deleted");
        }
        AdminSubcommand::DeviceList => {
            let resp = admin_get(&client, base_url, &key, "/admin/v1/devices").await?;
            println!("{resp}");
        }
        AdminSubcommand::DeviceRevoke { fingerprint } => {
            admin_post(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/devices/{fingerprint}/revoke"),
            )
            .await?;
            println!("device '{fingerprint}' revoked");
        }
        AdminSubcommand::DeviceReinstate { fingerprint } => {
            admin_post(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/devices/{fingerprint}/reinstate"),
            )
            .await?;
            println!("device '{fingerprint}' reinstated");
        }
        AdminSubcommand::AuditQuery {
            subject,
            limit,
            offset,
        } => {
            let mut path = format!("/admin/v1/audit?limit={limit}&offset={offset}");
            if let Some(s) = subject {
                path.push_str(&format!("&subject={s}"));
            }
            let resp = admin_get(&client, base_url, &key, &path).await?;
            println!("{resp}");
        }
        AdminSubcommand::UsageQuery { subject } => {
            let mut path = "/admin/v1/usage".to_string();
            if let Some(s) = subject {
                path.push_str(&format!("?subject={s}"));
            }
            let resp = admin_get(&client, base_url, &key, &path).await?;
            println!("{resp}");
        }
        AdminSubcommand::QuotaGet { subject } => {
            let resp = admin_get(
                &client,
                base_url,
                &key,
                &format!("/admin/v1/quotas/{subject}"),
            )
            .await?;
            println!("{resp}");
        }
    }

    Ok(())
}

/// Sends an authenticated GET to the admin API.
async fn admin_get(
    client: &reqwest::Client,
    base_url: &str,
    key: &str,
    path: &str,
) -> Result<String> {
    let resp = client
        .get(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("admin request: {e}")))?;
    admin_response(resp).await
}

/// Sends an authenticated PUT with a JSON body to the admin API.
async fn admin_put(
    client: &reqwest::Client,
    base_url: &str,
    key: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<String> {
    let resp = client
        .put(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("admin request: {e}")))?;
    admin_response(resp).await
}

/// Sends an authenticated POST with a JSON body to the admin API.
async fn admin_post_json(
    client: &reqwest::Client,
    base_url: &str,
    key: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<String> {
    let resp = client
        .post(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("admin request: {e}")))?;
    admin_response(resp).await
}

/// Sends an authenticated POST to the admin API.
async fn admin_post(client: &reqwest::Client, base_url: &str, key: &str, path: &str) -> Result<()> {
    let resp = client
        .post(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("admin request: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(oidc_agent_common::error::Error::Http(format!(
            "admin request failed: {status} {body}"
        )));
    }
    Ok(())
}

/// Sends an authenticated DELETE to the admin API.
async fn admin_delete(
    client: &reqwest::Client,
    base_url: &str,
    key: &str,
    path: &str,
) -> Result<()> {
    let resp = client
        .delete(format!("{base_url}{path}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("admin request: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(oidc_agent_common::error::Error::Http(format!(
            "admin request failed: {status} {body}"
        )));
    }
    Ok(())
}

/// Extracts the response body, returning an error on non-2xx.
async fn admin_response(resp: reqwest::Response) -> Result<String> {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("read response: {e}")))?;
    if !status.is_success() {
        return Err(oidc_agent_common::error::Error::Http(format!(
            "admin request failed: {status} {body}"
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn test_config(dev_mode: bool) -> CentralConfig {
        CentralConfig {
            listen_addr: "127.0.0.1:8443".parse().expect("address"),
            database_url: "sqlite://unused.db".into(),
            oidc: oidc_agent_common::config::OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "test".into(),
                client_secret_env: "TEST_SECRET".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            mtls: oidc_agent_common::config::MtlsServerConfig {
                ca_cert_path: "/ca.pem".into(),
                server_cert_path: "/server.pem".into(),
                server_key_path: "/server.key".into(),
            },
            admin: None,
            pricing: None,
            dev_mode,
            rate_limit_requests: 60,
            rate_limit_window_secs: 60,
        }
    }

    #[tokio::test]
    async fn dev_token_is_disabled_in_production_mode() {
        let result = mint_dev_token(&test_config(false), "alice".into(), None, "test".into()).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("production must reject dev token minting")
                .to_string()
                .contains("dev_mode")
        );
    }

    #[tokio::test]
    async fn dev_token_rejects_empty_identity_before_database_access() {
        let result = mint_dev_token(&test_config(true), "  ".into(), None, "test".into()).await;
        assert!(result.is_err());
        assert!(
            result
                .expect_err("empty subject must be rejected")
                .to_string()
                .contains("subject")
        );
    }
}
