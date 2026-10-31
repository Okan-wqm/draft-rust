//! Command line interface (OPS-01).

use std::path::PathBuf;

use authn_core::config::AppConfig;
use clap::{Parser, Subcommand};

use crate::error::ServerError;

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

/// Runs a command.
pub async fn run(cli: Cli) -> Result<Outcome, ServerError> {
    authn_core::tls::install_crypto_provider();
    match cli.command {
        Command::CheckConfig => {
            AppConfig::load(cli.config.as_deref())?;
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
        // Owned by other modules; wired in by their agents. They fail with a
        // clear error instead of panicking.
        other @ (Command::CreateAdmin { .. }
        | Command::RotateSigningKey { .. }
        | Command::RotateKek
        | Command::VerifyAuditChain
        | Command::MigrateLegacyHashes { .. }) => Err(ServerError::NotImplemented(other.name())),
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
    async fn ops_01_unimplemented_commands_fail_cleanly() {
        for command in [
            Command::CreateAdmin {
                email: "a@example.com".into(),
            },
            Command::RotateSigningKey { emergency: false },
            Command::RotateKek,
            Command::VerifyAuditChain,
            Command::MigrateLegacyHashes { input: "x".into() },
        ] {
            let name = command.name();
            let err = run(Cli {
                config: None,
                command,
            })
            .await
            .unwrap_err();
            assert!(matches!(err, ServerError::NotImplemented(n) if n == name));
            assert_eq!(err.exit_code(), std::process::ExitCode::from(2));
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
