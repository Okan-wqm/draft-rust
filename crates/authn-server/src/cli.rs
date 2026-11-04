//! Command line interface (OPS-01).

use std::path::PathBuf;

use std::sync::Arc;

use authn_core::config::AppConfig;
use authn_core::error::AuthError;
use authn_core::ports::{AuditSink, Clock, SystemClock};
use authn_crypto::CryptoServices;
use clap::{Parser, Subcommand};

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
    /// Create a break-glass platform admin (ADM-05).
    CreateAdmin {
        /// E-mail address of the admin account.
        #[arg(long)]
        email: String,
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
    /// Verify the audit log hash chain (AUD-02).
    VerifyAuditChain,
    /// Wrap legacy password hashes in bulk (CRY-04).
    MigrateLegacyHashes {
        /// Input file with `user_id,algorithm,hash` lines.
        #[arg(long)]
        input: PathBuf,
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
            Self::RotateSigningKey { .. } => "rotate-signing-key",
            Self::RotateKek => "rotate-kek",
            Self::VerifyAuditChain => "verify-audit-chain",
            Self::MigrateLegacyHashes { .. } => "migrate-legacy-hashes",
        }
    }
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
    let status = authn_store::migration_status(&pool).await?;
    if !status.is_up_to_date() {
        return Err(ServerError::SchemaOutdated(format!("{status:?}")));
    }
    Ok((config, pool))
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
                ServerError::Startup(
                    AuthError::internal("notification templates are invalid").with_source(e),
                )
            })?;
            Ok(Outcome::Message("configuration is valid".to_owned()))
        }
        Command::Migrate => {
            let config = AppConfig::load(cli.config.as_deref())?;
            crate::telemetry::init(&config.server)?;
            let pool = authn_store::connect(&config.database).await?;
            authn_store::run_migrations(&pool).await?;
            let status = authn_store::migration_status(&pool).await?;
            Ok(Outcome::Message(format!(
                "migrations applied; schema up to date: {}",
                status.is_up_to_date()
            )))
        }
        Command::Serve => {
            let config = AppConfig::load(cli.config.as_deref())?;
            crate::telemetry::init(&config.server)?;
            crate::serve::serve(config).await?;
            Ok(Outcome::Done)
        }
        Command::CreateAdmin { email } => {
            let (config, pool) = connect(&cli).await?;
            let crypto = crypto(&config).await?;
            let audit: Arc<dyn AuditSink> =
                Arc::new(authn_audit::PgAuditSink::new(pool.clone(), clock.clone()));
            let (id, password) =
                operations::create_break_glass_admin(&pool, &crypto, clock.as_ref(), &audit, email)
                    .await
                    .map_err(ServerError::Startup)?;
            Ok(Outcome::Message(format!(
                "break-glass admin {id} created.\nOne-time password (store it offline now, it is not shown again):\n{}",
                password.expose()
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
                    "emergency rotation done; active key {kid}; restart or wait signing_key_cache_ttl on every instance"
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
            Ok(Outcome::Message(format!(
                "re-wrapped: {} signing keys, {} webhook secrets, {} other values",
                report.signing_keys, report.webhook_secrets, report.other
            )))
        }
        Command::VerifyAuditChain => {
            let (_config, pool) = connect(&cli).await?;
            let report = authn_audit::verify_chain(&pool)
                .await
                .map_err(ServerError::Startup)?;
            if report.is_intact() {
                Ok(Outcome::Message(format!(
                    "audit chain intact; {} events verified",
                    report.events_verified
                )))
            } else {
                Err(ServerError::Integrity(format!(
                    "audit chain broken after {} verified events: {:?}",
                    report.events_verified, report.broken
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
        let cases: [(&[&str], &str); 9] = [
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
            },
            Command::RotateSigningKey { emergency: false },
            Command::RotateKek,
            Command::VerifyAuditChain,
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
