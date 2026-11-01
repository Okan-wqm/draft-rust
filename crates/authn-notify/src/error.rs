//! Errors of this crate.
//!
//! * [`NotifyError`] — startup / configuration problems (invalid template,
//!   unreadable file, forbidden setting for the environment). Messages name
//!   the file or key, never a secret value.
//! * [`RenderError`] — a notification could not be rendered at delivery
//!   time. Never contains rendered text, tokens or codes.

use std::borrow::Cow;
use std::path::PathBuf;

use authn_core::error::AuthError;

/// A startup or configuration problem.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotifyError {
    /// A setting is invalid or not allowed in this environment.
    #[error("invalid notification configuration: {0}")]
    Config(Cow<'static, str>),
    /// A template does not compile, does not render or breaks a rule
    /// (e.g. disables auto-escaping).
    #[error("template `{name}` is invalid: {detail}")]
    Template {
        /// Template name (`en/email/password_reset.html`).
        name: String,
        /// What is wrong (compiler message, rule).
        detail: String,
    },
    /// A file could not be read.
    #[error("cannot read `{path}`")]
    Io {
        /// The file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl NotifyError {
    pub(crate) fn config(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Config(message.into())
    }

    pub(crate) fn template(name: &str, detail: impl Into<String>) -> Self {
        Self::Template {
            name: name.to_owned(),
            detail: detail.into(),
        }
    }
}

impl From<NotifyError> for AuthError {
    fn from(err: NotifyError) -> Self {
        AuthError::internal("notification setup failed").with_source(err)
    }
}

/// Why a notification could not be rendered. Permanent: retrying the same
/// payload cannot succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RenderError {
    /// A link token is not a URL-safe token (CRY-06 format).
    #[error("link token has an invalid format")]
    InvalidToken,
    /// A code is not a short decimal code (CRY-07 format).
    #[error("one-time code has an invalid format")]
    InvalidCode,
    /// The template failed (only the template name and the error kind are
    /// kept: minijinja messages could quote values).
    #[error("template `{name}` failed: {kind}")]
    Template {
        /// Template name.
        name: String,
        /// minijinja error kind.
        kind: String,
    },
    /// The rendered subject is empty after sanitization.
    #[error("rendered subject is empty")]
    EmptySubject,
    /// The rendered SMS text is empty or too long.
    #[error("rendered SMS text is empty or longer than {max} characters")]
    SmsLength {
        /// Upper bound.
        max: usize,
    },
}

impl RenderError {
    pub(crate) fn template(name: &str, err: &minijinja::Error) -> Self {
        Self::Template {
            name: name.to_owned(),
            kind: format!("{:?}", err.kind()),
        }
    }
}

impl From<RenderError> for AuthError {
    fn from(err: RenderError) -> Self {
        AuthError::internal("notification rendering failed").with_source(err)
    }
}
