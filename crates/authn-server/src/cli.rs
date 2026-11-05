//! Command line interface (OPS-01).

use std::path::PathBuf;

use std::sync::Arc;

use authn_admin::{AdminSettings, Justification, OfflineOperator, OfflineTarget};
use authn_core::config::AppConfig;
use authn_core::error::AuthError;
use authn_core::ports::{AuditSink, Clock, SystemClock};
use authn_crypto::CryptoServices;
use clap::{Parser, Subcommand};
use secrecy::zeroize::Zeroizing;

use crate::error::ServerError;
use crate::operations;

/// rust-authentication: authentication server for web, B2B SaaS and mobile.
#[derive(Debug, Parser)]
#[command(name = "rust-authentication", version, about)]
pub struct Cli {
    /// TOML configuration file; `AUTHN__*` environment variables override it.
    #[arg(long, short = 'c', env = "AUTHN_CONFIG", global = true)]
    pub config: Option<PathBuf>,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Run the HTTP server.
    Serve,
    /// Apply pending database migrations.
    Migrate,
    /// Load and validate the configuration, then exit.
    CheckConfig,
    /// Create a break-glass platform admin (ADM-05): prints a one-time
    /// initial password (changed at first login, expires after 24 hours if
    /// unused, K-110), or with `--passkey-link` a single-use passkey
    /// enrollment link (K-11). Shown once, never logged.
    CreateAdmin {
        /// E-mail address of the admin account.
        #[arg(long)]
        email: String,
        /// Create the account without a password and print a one-time
        /// passkey enrollment link instead.
        #[arg(long)]
        passkey_link: bool,
        /// Lifetime of the enrollment link (e.g. `30m`, at most `24h`).
        /// Default `30m`.
        #[arg(long, requires = "passkey_link", value_parser = parse_ttl)]
        ttl: Option<std::time::Duration>,
    },
    /// New passkey enrollment link for an existing break-glass admin
    /// (K-07 recovery): removes the account's password, passkeys, MFA
    /// factors and sessions in the same transaction.
    AdminEnrollmentLink {
        /// Target, justification and operator.
        #[command(flatten)]
        offline: OfflineArgs,
        /// Lifetime of the link (e.g. `30m`, at most `24h`). Default `30m`.
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<std::time::Duration>,
    },
    /// Suspend a platform admin offline (K-07): sessions, trusted devices
    /// and the impersonations it started end too.
    SuspendAdmin {
        /// Target, justification and operator.
        #[command(flatten)]
        offline: OfflineArgs,
    },
    /// Lift the suspension of a platform admin offline (K-07).
    UnsuspendAdmin {
        /// Target, justification and operator.
        #[command(flatten)]
        offline: OfflineArgs,
    },
    /// Revoke every session of a platform admin offline (K-07).
    RevokeAdminSessions {
        /// Target, justification and operator.
        #[command(flatten)]
        offline: OfflineArgs,
    },
    /// Grant regular platform-admin rights to an existing active account
    /// offline (K-76): its sessions end; the API never grants admin rights.
    GrantAdmin {
        /// Target, justification and operator.
        #[command(flatten)]
        offline: OfflineArgs,
    },
    /// Revoke the platform-admin rights of an account offline (K-76):
    /// sessions, trusted devices, impersonations and enrollment links end;
    /// refused for the last active admin.
    RevokeAdmin {
        /// Target, justification and operator.
        #[command(flatten)]
        offline: OfflineArgs,
    },
    /// Seal a Sign in with Apple private key for
    /// `oidc_client.apple.private_key_ciphertext` (SOC-07, K-34). Reads the
    /// PKCS#8 PEM from a file or stdin (`-`); the key is never printed.
    SealAppleKey {
        /// PEM file, or `-` for stdin.
        #[arg(long)]
        pem_file: PathBuf,
    },
    /// Generate a new JWT signing key and schedule rotation (CRY-10).
    RotateSigningKey {
        /// Revoke the active key immediately (key compromise).
        #[arg(long)]
        emergency: bool,
    },
    /// Re-wrap data-encryption keys with the current KEK (CRY-08).
    #[command(alias = "reencrypt")]
    RotateKek,
    /// Verify the audit log hash chain (AUD-02, K-77: keyed with the chain
    /// key derived from `crypto.hmac_root_key`).
    VerifyAuditChain {
        /// Start after an externally kept checkpoint `<seq>:<hash hex>`
        /// (e.g. from the WORM copy of the logs) instead of the retention
        /// start.
        #[arg(long, value_parser = parse_anchor)]
        anchor: Option<authn_audit::ChainAnchor>,
        /// Refuse unkeyed (legacy SHA-256) events after this sequence number
        /// (overrides `audit.chain.legacy_until_seq`).
        #[arg(long)]
        legacy_until_seq: Option<i64>,
    },
    /// Switch the audit chain to `audit.chain.key_version` now (K-77): the
    /// first keyed event after an upgrade, or a key rotation. Prints the
    /// `chain_key_switch` checkpoint to keep outside the database. The
    /// server does the same at start-up.
    RotateAuditChainKey,
    /// Wrap legacy password hashes in bulk (CRY-04).
    MigrateLegacyHashes {
        /// Input file with `user_id,algorithm,hash` lines.
        #[arg(long)]
        input: PathBuf,
    },
    /// Record a checkpoint of the audit chain head now and print it as
    /// `<seq>:<hash hex>` (the `verify-audit-chain --anchor` format) to keep
    /// outside the database (K-107). Uses `database.maintenance_url` when
    /// set (the application role cannot write checkpoints).
    AuditCheckpoint,
    /// Write the erasure ledger as JSON lines (K-108) for storage outside
    /// the database; re-apply it with `reapply-erasures` after a restore.
    ExportErasures {
        /// Only erasures at or after this RFC 3339 time (overlap freely:
        /// the ledger is keyed by account). Default: everything.
        #[arg(long, value_parser = parse_rfc3339)]
        since: Option<time::OffsetDateTime>,
        /// File to write (created or replaced); `-` for stdout (log lines
        /// share stdout: prefer a file).
        #[arg(long)]
        output: PathBuf,
    },
    /// Erase again every account of an exported erasure ledger that a
    /// restored backup brought back (K-108; KVKK md. 7, GDPR art. 17).
    /// Idempotent. Run it before `serve` after every restore.
    ReapplyErasures {
        /// JSON-lines ledger from `export-erasures`, or `-` for stdin.
        #[arg(long)]
        from: PathBuf,
    },
}

impl Command {
    /// Stable command name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Serve => "serve",
            Self::Migrate => "migrate",
            Self::CheckConfig => "check-config",
            Self::CreateAdmin { .. } => "create-admin",
            Self::AdminEnrollmentLink { .. } => "admin-enrollment-link",
            Self::SuspendAdmin { .. } => "suspend-admin",
            Self::UnsuspendAdmin { .. } => "unsuspend-admin",
            Self::RevokeAdminSessions { .. } => "revoke-admin-sessions",
            Self::GrantAdmin { .. } => "grant-admin",
            Self::RevokeAdmin { .. } => "revoke-admin",
            Self::SealAppleKey { .. } => "seal-apple-key",
            Self::RotateSigningKey { .. } => "rotate-signing-key",
            Self::RotateKek => "rotate-kek",
            Self::VerifyAuditChain { .. } => "verify-audit-chain",
            Self::RotateAuditChainKey => "rotate-audit-chain-key",
            Self::MigrateLegacyHashes { .. } => "migrate-legacy-hashes",
            Self::AuditCheckpoint => "audit-checkpoint",
            Self::ExportErasures { .. } => "export-erasures",
            Self::ReapplyErasures { .. } => "reapply-erasures",
        }
    }
}

/// Arguments of the offline admin commands (K-07).
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct OfflineArgs {
    /// The account (a platform admin, except for `grant-admin`): e-mail
    /// address or user id.
    #[arg(long)]
    pub target: String,
    /// Justification (1–1000 printable characters), audited.
    #[arg(long)]
    pub reason: String,
    /// Who runs the command (1–64 of `[A-Za-z0-9._@-]`), audited.
    #[arg(long)]
    pub operator: String,
}

/// `<seq>:<64 hex digits>`.
fn parse_anchor(value: &str) -> Result<authn_audit::ChainAnchor, String> {
    const FORMAT: &str = "expected <seq>:<64 hex digits>";
    let (seq, hex) = value.split_once(':').ok_or(FORMAT)?;
    let seq: i64 = seq.trim().parse().map_err(|_| FORMAT)?;
    let hex = hex.trim().as_bytes();
    if seq < 0 || hex.len() != 64 {
        return Err(FORMAT.to_owned());
    }
    let mut hash = [0_u8; 32];
    for (byte, pair) in hash.iter_mut().zip(hex.chunks_exact(2)) {
        let text = std::str::from_utf8(pair).map_err(|_| FORMAT)?;
        *byte = u8::from_str_radix(text, 16).map_err(|_| FORMAT)?;
    }
    Ok(authn_audit::ChainAnchor { seq, hash })
}

fn parse_rfc3339(value: &str) -> Result<time::OffsetDateTime, String> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| "expected an RFC 3339 time, e.g. 2026-11-05T00:00:00Z".to_owned())
}

/// Ledger entries exported per query (K-108).
const LEDGER_PAGE: i64 = 1000;

/// Parses an exported erasure ledger (JSON lines; blank lines and `#`
/// comments skipped). Every line is checked — format and MAC under `key`
/// (`KeyPurpose::ErasureLedger`, K-108) — before anything is erased; an
/// invalid or forged line is an input error naming its number, never its
/// content.
pub fn parse_erasure_ledger(
    text: &str,
    key: &authn_crypto::kdf::HmacKey,
) -> Result<Vec<authn_account::ErasureRecord>, ServerError> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = authn_account::parse_ledger_line(line, key).ok_or_else(|| {
            ServerError::Input(format!(
                "line {} of the erasure ledger is not an authentic ledger entry \
                 (written by export-erasures with this crypto.hmac_root_key)",
                index + 1
            ))
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

/// The erasure ledger MAC key of the configuration (K-108).
fn ledger_key(config: &AppConfig) -> Result<authn_crypto::kdf::HmacKey, ServerError> {
    authn_crypto::kdf::KeyRing::from_config(&config.crypto)
        .and_then(|ring| {
            ring.key(authn_crypto::kdf::KeyPurpose::ErasureLedger)
                .cloned()
        })
        .map_err(|e| ServerError::Startup(AuthError::from(e)))
}

/// The audit chain keys of the configuration (K-77).
fn chain_keys(
    config: &AppConfig,
    crypto: &CryptoServices,
) -> Result<authn_audit::ChainKeys, ServerError> {
    authn_audit::ChainKeys::from_config(&crypto.keys, &config.audit.chain)
        .map_err(ServerError::Startup)
}

fn parse_ttl(value: &str) -> Result<std::time::Duration, String> {
    authn_core::config::duration::parse(value).map_err(str::to_owned)
}

/// The break-glass enrollment link: the token travels in the URL
/// **fragment**, which browsers never send to a server, so it cannot end up
/// in access logs.
#[must_use]
pub fn enrollment_url(public_base_url: &url::Url, token: &str) -> String {
    format!(
        "{}/admin/enroll#{token}",
        public_base_url.as_str().trim_end_matches('/')
    )
}

/// Outcome of a successful command, printed by `main`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to print.
    Done,
    /// A message for stdout.
    Message(String),
}

/// Loads the configuration, starts telemetry and connects (commands that
/// work on the database).
async fn connect(cli: &Cli) -> Result<(AppConfig, sqlx::PgPool), ServerError> {
    let config = AppConfig::load(cli.config.as_deref())?;
    crate::telemetry::init(&config.server)?;
    let pool = authn_store::connect(&config.database).await?;
    crate::serve::ensure_compatible_schema(&pool).await?;
    Ok((config, pool))
}

/// Every service, for the commands that act through a module service
/// (offline admin commands). Notifications are queued in the outbox and
/// delivered by the running server.
async fn services(
    cli: &Cli,
    clock: Arc<dyn Clock>,
) -> Result<(Arc<AppConfig>, crate::services::Services), ServerError> {
    let (config, pool) = connect(cli).await?;
    let config = Arc::new(config);
    let ports =
        crate::services::Ports::from_config(&config, clock).map_err(ServerError::Startup)?;
    let services = crate::services::Services::build(config.clone(), pool, ports)
        .await
        .map_err(ServerError::Startup)?;
    Ok((config, services))
}

impl OfflineArgs {
    /// Validates the arguments **before** anything touches the database;
    /// a bad value is an input error (exit code 65) naming the flag, never
    /// echoing the value.
    fn parse(&self) -> Result<(OfflineOperator, OfflineTarget, Justification), ServerError> {
        let operator = OfflineOperator::parse(&self.operator).map_err(|_| {
            ServerError::Input("--operator must be 1-64 of [A-Za-z0-9._@-]".to_owned())
        })?;
        let reason = Justification::parse(Some(&self.reason)).map_err(|_| {
            ServerError::Input("--reason must be 1-1000 printable characters".to_owned())
        })?;
        Ok((operator, OfflineTarget::parse(&self.target), reason))
    }
}

fn describe(outcome: &authn_admin::ActionOutcome) -> String {
    serde_json::to_string(outcome).unwrap_or_else(|_| "done".to_owned())
}

/// Largest accepted Apple key PEM.
const MAX_PEM_BYTES: usize = 16 * 1024;

/// Reads the Apple key PEM (`-` = stdin), bounded; never echoed. The
/// buffer is allocated once (no re-allocation leaves copies behind) and
/// zeroed on drop; larger input is refused, never silently truncated.
fn read_pem(path: &std::path::Path) -> Result<Zeroizing<String>, ServerError> {
    use std::io::Read as _;
    let limit = u64::try_from(MAX_PEM_BYTES + 1).unwrap_or(u64::MAX);
    let mut text = Zeroizing::new(String::with_capacity(MAX_PEM_BYTES + 1));
    let read = if path.as_os_str() == "-" {
        std::io::stdin().take(limit).read_to_string(&mut text)
    } else {
        std::fs::File::open(path)?
            .take(limit)
            .read_to_string(&mut text)
    };
    read.map_err(|_| ServerError::Input("the PEM input is not readable UTF-8 text".to_owned()))?;
    if text.len() > MAX_PEM_BYTES {
        return Err(ServerError::Input(format!(
            "the PEM input exceeds {MAX_PEM_BYTES} bytes"
        )));
    }
    Ok(text)
}

/// The settings `serve` validates only while building the router and the
/// services (fail fast, ARC-07), checked without a database so that
/// `check-config` never calls a configuration valid that `serve` refuses:
/// web protection (host, security headers, CORS, admin console CORS), the
/// key material (KEKs, peppers, HMAC root) and the social-login providers
/// (the envelope-encrypted Apple key must open with the configured KEKs,
/// `oidc_client.error_redirect` must be an allowed redirect target, K-73).
async fn check_startup_settings(config: &AppConfig) -> Result<(), ServerError> {
    let protect = &config.protect;
    authn_protect::web::HostValidation::from_config(protect, &config.server.public_base_url)
        .map_err(ServerError::Startup)?;
    authn_protect::web::SecurityHeaders::from_config(&protect.security_headers)
        .map_err(ServerError::Startup)?;
    authn_protect::web::CorsPolicy::from_config(&protect.cors).map_err(ServerError::Startup)?;
    crate::cors::AdminConsoleCors::from_config(config).map_err(ServerError::Startup)?;
    let crypto = crypto(config).await?;
    let mut settings = authn_oidc_client::OidcClientSettings::from_app_config(config);
    // K-73: the web flow's error page must be an allowed redirect target
    // (`serve` refuses it while building the social-login service).
    authn_oidc_client::validate_error_redirect(&settings).map_err(ServerError::Startup)?;
    if let Some(apple) = settings.config.apple.as_mut() {
        authn_oidc_client::apple::resolve_private_key(apple, &crypto.envelopes)
            .await
            .map_err(ServerError::Startup)?;
    }
    authn_oidc_client::ProviderRegistry::from_settings(&settings).map_err(ServerError::Startup)?;
    Ok(())
}

async fn crypto(config: &AppConfig) -> Result<CryptoServices, ServerError> {
    CryptoServices::from_config(&config.crypto)
        .await
        .map_err(|e| ServerError::Startup(AuthError::from(e)))
}

/// Runs a command.
pub async fn run(cli: Cli) -> Result<Outcome, ServerError> {
    authn_core::tls::install_crypto_provider();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    match &cli.command {
        Command::CheckConfig => {
            let config = AppConfig::load(cli.config.as_deref())?;
            authn_notify::TemplateRenderer::from_config(&config).map_err(|e| {
                ServerError::InvalidSettings(
                    AuthError::internal("notification templates are invalid").with_source(e),
                )
            })?;
            // A refused setting is an invalid configuration (exit code 78,
            // as `AppConfig::load` refusals), not a service failure.
            check_startup_settings(&config)
                .await
                .map_err(|err| match err {
                    ServerError::Startup(err) => ServerError::InvalidSettings(err),
                    other => other,
                })?;
            Ok(Outcome::Message("configuration is valid".to_owned()))
        }
        Command::Migrate => {
            let config = AppConfig::load(cli.config.as_deref())?;
            crate::telemetry::init(&config.server)?;
            let pool = authn_store::connect(&config.database).await?;
            authn_store::run_migrations(&pool).await?;
            let status = authn_store::migration_status(&pool).await?;
            Ok(Outcome::Message(
                if status.is_ahead() && status.is_compatible() {
                    format!(
                        "migrations applied; schema is ahead of this binary (newer migrations {:?}); compatible: true",
                        status.unknown_applied
                    )
                } else {
                    format!(
                        "migrations applied; schema up to date: {}",
                        status.is_up_to_date()
                    )
                },
            ))
        }
        Command::Serve => {
            let config = AppConfig::load(cli.config.as_deref())?;
            crate::telemetry::init(&config.server)?;
            crate::serve::serve(config).await?;
            Ok(Outcome::Done)
        }
        Command::CreateAdmin {
            email,
            passkey_link,
            ttl,
        } => {
            let (config, pool) = connect(&cli).await?;
            let keys = chain_keys(&config, &crypto(&config).await?)?;
            let audit: Arc<dyn AuditSink> = Arc::new(authn_audit::PgAuditSink::keyed(
                pool.clone(),
                clock.clone(),
                keys,
            ));
            if *passkey_link {
                let ttl =
                    ttl.unwrap_or(AdminSettings::from_app_config(&config).enrollment_link_ttl);
                let link = authn_admin::create_break_glass_admin_with_passkey_link(
                    &pool,
                    clock.as_ref(),
                    &audit,
                    email,
                    ttl,
                )
                .await
                .map_err(ServerError::Startup)?;
                return Ok(Outcome::Message(format!(
                    "break-glass admin {} created without a password.\nOne-time passkey enrollment link (valid until {}; deliver it over a secure channel, it is not shown again):\n{}",
                    link.user_id,
                    link.expires_at,
                    enrollment_url(&config.server.public_base_url, link.token.expose())
                )));
            }
            let crypto = crypto(&config).await?;
            let admin = authn_admin::create_break_glass_admin(
                &pool,
                &crypto.passwords,
                clock.as_ref(),
                &audit,
                email,
            )
            .await
            .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "break-glass admin {} created.\nOne-time password (store it offline now, it is not shown again; the first login requires a code e-mailed to the account, a passkey enrollment and a new password; unused, it stops working at {}):\n{}",
                admin.user_id,
                admin.password_expires_at,
                admin.password.expose()
            )))
        }
        Command::AdminEnrollmentLink { offline, ttl } => {
            let (operator, target, reason) = offline.parse()?;
            let (config, services) = services(&cli, clock).await?;
            let ttl = ttl.unwrap_or(AdminSettings::from_app_config(&config).enrollment_link_ttl);
            let link = services
                .admin
                .issue_break_glass_enrollment_link_offline(&operator, &target, &reason, ttl)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "every credential and session of {} was removed.\nOne-time passkey enrollment link (valid until {}; deliver it over a secure channel, it is not shown again):\n{}",
                link.user_id,
                link.expires_at,
                enrollment_url(&config.server.public_base_url, link.token.expose())
            )))
        }
        Command::SuspendAdmin { offline } => {
            let (operator, target, reason) = offline.parse()?;
            let (_config, services) = services(&cli, clock).await?;
            let outcome = services
                .admin
                .suspend_admin_offline(&operator, &target, &reason)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "suspend-admin: {}",
                describe(&outcome)
            )))
        }
        Command::UnsuspendAdmin { offline } => {
            let (operator, target, reason) = offline.parse()?;
            let (_config, services) = services(&cli, clock).await?;
            let outcome = services
                .admin
                .unsuspend_admin_offline(&operator, &target, &reason)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "unsuspend-admin: {}",
                describe(&outcome)
            )))
        }
        Command::RevokeAdminSessions { offline } => {
            let (operator, target, reason) = offline.parse()?;
            let (_config, services) = services(&cli, clock).await?;
            let outcome = services
                .admin
                .revoke_admin_sessions_offline(&operator, &target, &reason)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "revoke-admin-sessions: {}",
                describe(&outcome)
            )))
        }
        Command::GrantAdmin { offline } => {
            let (operator, target, reason) = offline.parse()?;
            let (_config, services) = services(&cli, clock).await?;
            let outcome = services
                .admin
                .grant_admin_offline(&operator, &target, &reason)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "grant-admin: {}",
                describe(&outcome)
            )))
        }
        Command::RevokeAdmin { offline } => {
            let (operator, target, reason) = offline.parse()?;
            let (_config, services) = services(&cli, clock).await?;
            let outcome = services
                .admin
                .revoke_admin_offline(&operator, &target, &reason)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "revoke-admin: {}",
                describe(&outcome)
            )))
        }
        Command::SealAppleKey { pem_file } => {
            let pem = read_pem(pem_file)?;
            let config = AppConfig::load(cli.config.as_deref())?;
            let crypto = crypto(&config).await?;
            let sealed = operations::seal_apple_key(&crypto.envelopes, &pem)
                .await
                .map_err(|err| {
                    if err.status().is_server_error()
                        && err.context() == Some(operations::NOT_AN_APPLE_KEY)
                    {
                        ServerError::Input(
                            "the input is not a PKCS#8 P-256 private key (PEM)".to_owned(),
                        )
                    } else {
                        ServerError::Startup(err)
                    }
                })?;
            Ok(Outcome::Message(format!(
                "set oidc_client.apple.private_key_ciphertext to (and remove private_key_pem / private_key_file):\n{sealed}"
            )))
        }
        Command::RotateSigningKey { emergency } => {
            let (config, pool) = connect(&cli).await?;
            let crypto = crypto(&config).await?;
            let kid = operations::rotate_signing_key(
                &pool,
                &crypto,
                clock.as_ref(),
                &config.crypto.signing_keys,
                *emergency,
            )
            .await
            .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(if *emergency {
                format!(
                    "emergency rotation done; active key {kid}; serving instances drop the revoked key at once (signing-key listener, K-58), at the latest after session.signing_key_cache_ttl"
                )
            } else {
                format!(
                    "pending key {kid} created; it activates after crypto.signing_keys.pending_period"
                )
            }))
        }
        Command::RotateKek => {
            let (config, pool) = connect(&cli).await?;
            let crypto = crypto(&config).await?;
            let report = operations::rotate_kek(&pool, &crypto.envelopes)
                .await
                .map_err(ServerError::Startup)?;
            let apple = match operations::rewrap_apple_key(&config, &crypto.envelopes)
                .await
                .map_err(ServerError::Startup)?
            {
                operations::AppleKeyRewrap::NotConfigured => String::new(),
                operations::AppleKeyRewrap::Current => {
                    "\noidc_client.apple.private_key_ciphertext already uses the current KEK"
                        .to_owned()
                }
                operations::AppleKeyRewrap::Rewrapped(value) => format!(
                    "\nreplace oidc_client.apple.private_key_ciphertext with (before removing the old KEK):\n{value}"
                ),
            };
            Ok(Outcome::Message(format!(
                "re-wrapped: {} signing keys, {} webhook secrets, {} other values{apple}",
                report.signing_keys, report.webhook_secrets, report.other
            )))
        }
        Command::VerifyAuditChain {
            anchor,
            legacy_until_seq,
        } => {
            let (config, pool) = connect(&cli).await?;
            let mut keys = chain_keys(&config, &crypto(&config).await?)?;
            if legacy_until_seq.is_some() {
                keys = keys.with_legacy_until_seq(*legacy_until_seq);
            }
            let report = match anchor {
                Some(anchor) => authn_audit::verify_chain_from(&pool, &keys, *anchor).await,
                None => authn_audit::verify_chain(&pool, &keys).await,
            }
            .map_err(ServerError::Startup)?;
            if report.is_intact() {
                let legacy = if report.legacy_events == 0 {
                    String::new()
                } else if keys.legacy_until_seq().is_some() {
                    format!(
                        "; {} unkeyed (legacy) events, all within the pinned prefix",
                        report.legacy_events
                    )
                } else {
                    format!(
                        "; WARNING: {} unkeyed (legacy) events accepted, first keyed event {}: pin audit.chain.legacy_until_seq",
                        report.legacy_events,
                        report
                            .keyed_from_seq
                            .map_or_else(|| "none".to_owned(), |seq| seq.to_string())
                    )
                };
                Ok(Outcome::Message(format!(
                    "audit chain intact; {} events verified; head {}:{} (key version {}){legacy}",
                    report.events_verified,
                    report.head.seq,
                    report.head.hash_hex(),
                    report
                        .head_key_version
                        .map_or_else(|| "none".to_owned(), |v| v.to_string()),
                )))
            } else {
                Err(ServerError::Integrity(format!(
                    "audit chain broken after {} verified events: {:?}",
                    report.events_verified, report.broken
                )))
            }
        }
        Command::RotateAuditChainKey => {
            let (config, pool) = connect(&cli).await?;
            let keys = chain_keys(&config, &crypto(&config).await?)?;
            let activation = authn_audit::PgAuditSink::keyed(pool, clock.clone(), keys)
                .activate_chain_key()
                .await
                .map_err(ServerError::Startup)?;
            let from = activation
                .from_version
                .map_or_else(|| "unkeyed".to_owned(), |v| format!("version {v}"));
            Ok(Outcome::Message(match activation.switch {
                None => format!(
                    "audit chain already uses key version {} (configured {})",
                    activation.to_version, config.audit.chain.key_version
                ),
                Some(switch) => format!(
                    "audit chain switched from {from} to key version {}; keep this checkpoint outside the database: {}:{}",
                    activation.to_version,
                    switch.seq,
                    switch.hash_hex()
                ),
            }))
        }
        Command::AuditCheckpoint => {
            let (config, pool) = connect(&cli).await?;
            let pool = match config.database.maintenance() {
                Some(maintenance) => authn_store::connect(&maintenance).await?,
                None => pool,
            };
            let anchor = authn_audit::create_checkpoint(&pool, clock.as_ref())
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "{}:{}",
                anchor.seq,
                anchor.hash_hex()
            )))
        }
        Command::ExportErasures { since, output } => {
            let (config, services) = services(&cli, clock).await?;
            let key = ledger_key(&config)?;
            let since = since.unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
            let mut lines = Vec::new();
            let mut after: Option<authn_account::ErasureRecord> = None;
            loop {
                let page = services
                    .accounts
                    .export_erasures(since, after.as_ref(), LEDGER_PAGE)
                    .await
                    .map_err(ServerError::Startup)?;
                for entry in &page {
                    lines.push(authn_account::ledger_line(entry, &key));
                }
                if page.len() < usize::try_from(LEDGER_PAGE).unwrap_or(usize::MAX) {
                    break;
                }
                after = page.last().cloned();
            }
            let count = lines.len();
            let mut text = lines.join("\n");
            if !text.is_empty() {
                text.push('\n');
            }
            if output.as_os_str() == "-" {
                return Ok(Outcome::Message(text.trim_end().to_owned()));
            }
            std::fs::write(output, text)?;
            Ok(Outcome::Message(format!(
                "{count} erasure ledger entries written"
            )))
        }
        Command::ReapplyErasures { from } => {
            let text = if from.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(from)?
            };
            let key = ledger_key(&AppConfig::load(cli.config.as_deref())?)?;
            let entries = parse_erasure_ledger(&text, &key)?;
            let (_config, services) = services(&cli, clock).await?;
            let (mut erased, mut gone) = (0_u64, 0_u64);
            let mut blocked = Vec::new();
            for entry in &entries {
                match services
                    .accounts
                    .reapply_erasure(entry)
                    .await
                    .map_err(ServerError::Startup)?
                {
                    authn_account::ReapplyOutcome::Erased => erased += 1,
                    authn_account::ReapplyOutcome::AlreadyErased => gone += 1,
                    authn_account::ReapplyOutcome::BlockedLastOwner => {
                        blocked.push(entry.user_id.to_string());
                    }
                }
            }
            let summary = format!(
                "{} ledger entries: {erased} accounts erased again, {gone} already erased, {} blocked",
                entries.len(),
                blocked.len()
            );
            if blocked.is_empty() {
                Ok(Outcome::Message(summary))
            } else {
                Err(ServerError::Integrity(format!(
                    "{summary}; last owner of an organization (transfer or delete the organization, then rerun): {}",
                    blocked.join(", ")
                )))
            }
        }
        Command::MigrateLegacyHashes { input } => {
            let text = std::fs::read_to_string(input)?;
            let lines = operations::parse_legacy_lines(&text).map_err(ServerError::Input)?;
            let (config, pool) = connect(&cli).await?;
            let crypto = crypto(&config).await?;
            let updated = operations::migrate_legacy_hashes(&pool, &crypto, clock.as_ref(), &lines)
                .await
                .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "{updated} of {} accounts migrated",
                lines.len()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn ops_01_cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn ops_01_all_subcommands_parse() {
        let offline = [
            "--target",
            "root@example.com",
            "--reason",
            "incident 42",
            "--operator",
            "oncall",
        ];
        for (command, name) in [
            ("suspend-admin", "suspend-admin"),
            ("unsuspend-admin", "unsuspend-admin"),
            ("revoke-admin-sessions", "revoke-admin-sessions"),
            ("admin-enrollment-link", "admin-enrollment-link"),
        ] {
            let cli =
                Cli::try_parse_from(["rust-authentication", command].into_iter().chain(offline))
                    .unwrap_or_else(|e| panic!("{command}: {e}"));
            assert_eq!(cli.command.name(), name);
            // --reason and --operator are mandatory (K-07).
            for missing in ["--reason", "--operator"] {
                let mut args = vec!["rust-authentication", command];
                let mut skip = false;
                for a in offline {
                    if skip {
                        skip = false;
                        continue;
                    }
                    if a == missing {
                        skip = true;
                        continue;
                    }
                    args.push(a);
                }
                assert!(
                    Cli::try_parse_from(args).is_err(),
                    "{command} without {missing}"
                );
            }
        }
        let cli = Cli::try_parse_from([
            "rust-authentication",
            "create-admin",
            "--email",
            "a@example.com",
            "--passkey-link",
            "--ttl",
            "45m",
        ])
        .unwrap();
        assert_eq!(
            cli.command,
            Command::CreateAdmin {
                email: "a@example.com".into(),
                passkey_link: true,
                ttl: Some(std::time::Duration::from_secs(45 * 60)),
            }
        );
        // --ttl only with --passkey-link; unparsable durations are refused.
        assert!(
            Cli::try_parse_from([
                "rust-authentication",
                "create-admin",
                "--email",
                "a@example.com",
                "--ttl",
                "5m"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "rust-authentication",
                "create-admin",
                "--email",
                "a@example.com",
                "--passkey-link",
                "--ttl",
                "soon"
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from(["rust-authentication", "seal-apple-key", "--pem-file", "-"])
            .unwrap();
        assert_eq!(cli.command.name(), "seal-apple-key");

        let cases: [(&[&str], &str); 12] = [
            (&["serve"], "serve"),
            (&["migrate"], "migrate"),
            (&["check-config"], "check-config"),
            (
                &["create-admin", "--email", "a@example.com"],
                "create-admin",
            ),
            (&["rotate-signing-key", "--emergency"], "rotate-signing-key"),
            (&["rotate-kek"], "rotate-kek"),
            (&["reencrypt"], "rotate-kek"),
            (&["verify-audit-chain"], "verify-audit-chain"),
            (
                &[
                    "verify-audit-chain",
                    "--anchor",
                    "12:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                ],
                "verify-audit-chain",
            ),
            (
                &["verify-audit-chain", "--legacy-until-seq", "41"],
                "verify-audit-chain",
            ),
            (&["rotate-audit-chain-key"], "rotate-audit-chain-key"),
            (
                &["migrate-legacy-hashes", "--input", "hashes.csv"],
                "migrate-legacy-hashes",
            ),
        ];
        for (args, name) in cases {
            let cli = Cli::try_parse_from(
                std::iter::once("rust-authentication").chain(args.iter().copied()),
            )
            .unwrap_or_else(|e| panic!("{args:?}: {e}"));
            assert_eq!(cli.command.name(), name);
        }
        assert!(Cli::try_parse_from(["rust-authentication", "unknown"]).is_err());
    }

    #[tokio::test]
    async fn ops_01_database_commands_fail_cleanly_without_configuration() {
        for command in [
            Command::CreateAdmin {
                email: "a@example.com".into(),
                passkey_link: false,
                ttl: None,
            },
            Command::CreateAdmin {
                email: "a@example.com".into(),
                passkey_link: true,
                ttl: None,
            },
            Command::SuspendAdmin {
                offline: OfflineArgs {
                    target: "a@example.com".into(),
                    reason: "incident".into(),
                    operator: "oncall".into(),
                },
            },
            Command::RotateSigningKey { emergency: false },
            Command::RotateKek,
            Command::VerifyAuditChain {
                anchor: None,
                legacy_until_seq: None,
            },
            Command::RotateAuditChainKey,
            Command::AuditCheckpoint,
            Command::ExportErasures {
                since: None,
                output: "-".into(),
            },
        ] {
            let err = run(Cli {
                config: Some("/nonexistent/authn.toml".into()),
                command,
            })
            .await
            .unwrap_err();
            assert!(matches!(err, ServerError::Config(_)), "{err}");
            assert_eq!(err.exit_code(), std::process::ExitCode::from(78));
        }
        let err = run(Cli {
            config: None,
            command: Command::MigrateLegacyHashes {
                input: "/nonexistent/hashes.csv".into(),
            },
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Io(_)));
        // The key file is read first; its path / content never reach the
        // error.
        let err = run(Cli {
            config: Some("/nonexistent/authn.toml".into()),
            command: Command::SealAppleKey {
                pem_file: "/nonexistent/apple.pem".into(),
            },
        })
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Io(_)), "{err}");
    }

    #[test]
    fn k_107_k_108_operator_commands_parse() {
        let cli = Cli::try_parse_from(["rust-authentication", "audit-checkpoint"]).unwrap();
        assert_eq!(cli.command, Command::AuditCheckpoint);
        assert_eq!(cli.command.name(), "audit-checkpoint");
        let cli = Cli::try_parse_from(["rust-authentication", "export-erasures", "--output", "-"])
            .unwrap();
        assert_eq!(
            cli.command,
            Command::ExportErasures {
                since: None,
                output: "-".into()
            }
        );
        let cli = Cli::try_parse_from([
            "rust-authentication",
            "export-erasures",
            "--since",
            "2026-11-05T00:00:00Z",
            "--output",
            "ledger.jsonl",
        ])
        .unwrap();
        assert_eq!(
            cli.command,
            Command::ExportErasures {
                since: Some(time::macros::datetime!(2026-11-05 00:00 UTC)),
                output: "ledger.jsonl".into()
            }
        );
        for bad in [
            &["export-erasures"][..],
            &["export-erasures", "--since", "today", "--output", "-"][..],
        ] {
            assert!(
                Cli::try_parse_from(
                    std::iter::once("rust-authentication").chain(bad.iter().copied())
                )
                .is_err(),
                "{bad:?}"
            );
        }
        let cli = Cli::try_parse_from(["rust-authentication", "reapply-erasures", "--from", "-"])
            .unwrap();
        assert_eq!(cli.command.name(), "reapply-erasures");
        assert!(Cli::try_parse_from(["rust-authentication", "reapply-erasures"]).is_err());
    }

    #[test]
    fn k_108_erasure_ledger_parsing_is_strict_and_never_echoes_input() {
        let ring = authn_crypto::kdf::KeyRing::derive(&[3_u8; 32]).unwrap();
        let key = ring
            .key(authn_crypto::kdf::KeyPurpose::ErasureLedger)
            .unwrap();
        let record = |id: &str, reason: &str| authn_account::ErasureRecord {
            user_id: serde_json::from_str(&format!("\"{id}\"")).unwrap(),
            erased_at: time::OffsetDateTime::from_unix_timestamp(1_793_000_000).unwrap(),
            reason: reason.to_owned(),
        };
        let text = format!(
            "# exported 2026-11-05\n\n{}\n{}\n",
            authn_account::ledger_line(
                &record(
                    "01900000-0000-7000-8000-0000000000aa",
                    "grace_period_elapsed"
                ),
                key
            ),
            authn_account::ledger_line(
                &record("01900000-0000-7000-8000-0000000000ab", "unverified_expired"),
                key
            ),
        );
        let entries = parse_erasure_ledger(&text, key).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].reason, "unverified_expired");
        let err = parse_erasure_ledger("{\"user_id\":\"secret@example.com\"}\n", key).unwrap_err();
        assert!(matches!(err, ServerError::Input(_)), "{err}");
        assert!(err.to_string().contains("line 1"), "{err}");
        assert!(!err.to_string().contains("secret@example.com"), "{err}");
        assert_eq!(err.exit_code(), std::process::ExitCode::from(65));
        // An unsigned line (the pre-K-108-audit format) is refused.
        let unsigned = serde_json::to_string(&record(
            "01900000-0000-7000-8000-0000000000aa",
            "grace_period_elapsed",
        ))
        .unwrap();
        let err = parse_erasure_ledger(&format!("# x\n{unsigned}\n"), key).unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn k_77_verify_anchor_argument_is_strict() {
        let hash = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let short = "00112233445566778899aabbccddeeff00112233445566778899aabbccddee";
        let anchor = parse_anchor(&format!("12:{hash}")).unwrap();
        assert_eq!(anchor.seq, 12);
        assert_eq!(anchor.hash_hex(), hash);
        for bad in [
            "12",
            "x:00",
            &format!("-1:{hash}"),
            &format!("12:{short}"),
            &format!("12:{hash}00"),
            &format!("12:{short}zz"),
        ] {
            assert!(parse_anchor(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn adm_05_k11_enrollment_link_keeps_the_token_in_the_fragment() {
        for base in [
            "https://auth.example.com",
            "https://auth.example.com/",
            "https://example.com/auth/",
        ] {
            let url = enrollment_url(&url::Url::parse(base).unwrap(), "TOKEN_abc-123");
            let parsed = url::Url::parse(&url).unwrap();
            assert!(parsed.path().ends_with("/admin/enroll"), "{url}");
            assert!(!parsed.path().contains("//"), "{url}");
            assert_eq!(parsed.query(), None, "{url}");
            assert_eq!(parsed.fragment(), Some("TOKEN_abc-123"), "{url}");
        }
    }

    #[tokio::test]
    async fn arc_07_check_config_rejects_missing_file() {
        let cli = Cli {
            config: Some("/nonexistent/authn.toml".into()),
            command: Command::CheckConfig,
        };
        let err = run(cli).await.unwrap_err();
        assert!(matches!(err, ServerError::Config(_)));
        assert_eq!(err.exit_code(), std::process::ExitCode::from(78));
    }
}
