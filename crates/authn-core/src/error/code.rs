//! The [`ErrorCode`] registry entry type.

use std::fmt;

use http::StatusCode;

use crate::domain::Locale;

/// One entry of the error-code registry.
///
/// Codes are compared by their `code` string. A code, once released, never
/// changes meaning: clients and the error catalogue (DOC-04) depend on it.
#[derive(Clone, Copy)]
pub struct ErrorCode {
    code: &'static str,
    status: StatusCode,
    message_en: &'static str,
    message_tr: &'static str,
}

impl ErrorCode {
    /// Declares a code. Use only in `const` items inside
    /// `crate::error::codes::<module>`.
    #[must_use]
    pub const fn new(
        code: &'static str,
        status: StatusCode,
        message_en: &'static str,
        message_tr: &'static str,
    ) -> Self {
        Self {
            code,
            status,
            message_en,
            message_tr,
        }
    }

    /// Stable snake_case identifier, e.g. `invalid_credentials`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// HTTP status used when rendering.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Human readable, user-safe message in the requested locale.
    #[must_use]
    pub const fn message(&self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.message_en,
            Locale::Tr => self.message_tr,
        }
    }

    /// Whether this is a server-side (5xx) error.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }
}

impl PartialEq for ErrorCode {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Eq for ErrorCode {}

impl std::hash::Hash for ErrorCode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorCode({}, {})", self.code, self.status.as_u16())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
