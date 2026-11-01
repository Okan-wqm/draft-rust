//! Disposable e-mail domain block list (ACC-12).
//!
//! Configured with `account.disposable_domains_file` (default: disabled).
//! File format: one domain per line, `#` starts a comment, blank lines are
//! ignored, a leading `*.` or `.` is accepted and ignored. Domains are
//! normalized exactly like e-mail domains (IDNA / punycode, lowercase), and
//! a blocked domain also blocks all its subdomains (`mailinator.com` blocks
//! `x.mailinator.com`). Entries without a dot (a bare TLD would block
//! everything) and invalid entries are skipped and counted.
//!
//! The list is loaded once at start-up; an unreadable or oversized file
//! stops the server (fail-fast, ARC-07).

use std::collections::HashSet;
use std::io::Read as _;
use std::path::Path;

use authn_core::domain::EmailAddress;
use authn_core::error::{AuthError, codes};

/// Largest accepted list file (bytes).
pub const MAX_LIST_BYTES: u64 = 32 * 1024 * 1024;
/// Most entries kept.
pub const MAX_ENTRIES: usize = 2_000_000;

/// A loaded block list.
#[derive(Clone, Default)]
pub struct DisposableDomains {
    domains: HashSet<String>,
    skipped: usize,
}

impl std::fmt::Debug for DisposableDomains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisposableDomains")
            .field("domains", &self.domains.len())
            .field("skipped", &self.skipped)
            .finish()
    }
}

impl DisposableDomains {
    /// Builds a list from domain strings (invalid entries are skipped).
    pub fn from_domains<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Self::default();
        for domain in domains {
            list.insert_line(domain.as_ref());
        }
        list
    }

    /// Loads the list from a file (see the module docs for the format).
    pub fn from_file(path: &Path) -> Result<Self, AuthError> {
        let file = std::fs::File::open(path).map_err(|e| {
            AuthError::internal("account.disposable_domains_file cannot be opened").with_source(e)
        })?;
        let mut text = String::new();
        file.take(MAX_LIST_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| {
                AuthError::internal("account.disposable_domains_file is not readable UTF-8")
                    .with_source(e)
            })?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_LIST_BYTES {
            return Err(AuthError::internal(
                "account.disposable_domains_file exceeds 32 MiB",
            ));
        }
        let list = Self::from_domains(text.lines());
        if list.domains.len() >= MAX_ENTRIES {
            return Err(AuthError::internal(
                "account.disposable_domains_file has too many entries",
            ));
        }
        tracing::info!(
            domains = list.domains.len(),
            skipped = list.skipped,
            "disposable e-mail domain list loaded"
        );
        Ok(list)
    }

    /// Loads the configured list, if any.
    pub fn from_config(
        config: &authn_core::config::account::AccountConfig,
    ) -> Result<Option<Self>, AuthError> {
        config
            .disposable_domains_file
            .as_deref()
            .map(Self::from_file)
            .transpose()
    }

    fn insert_line(&mut self, line: &str) {
        let entry = line.split('#').next().unwrap_or_default().trim();
        if entry.is_empty() {
            return;
        }
        let entry = entry
            .strip_prefix("*.")
            .or_else(|| entry.strip_prefix('.'))
            .unwrap_or(entry);
        match idna::domain_to_ascii_strict(entry) {
            Ok(ascii)
                if ascii.contains('.')
                    && !ascii.ends_with('.')
                    && self.domains.len() < MAX_ENTRIES =>
            {
                self.domains.insert(ascii);
            }
            _ => self.skipped += 1,
        }
    }

    /// Number of blocked domains.
    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Number of skipped (invalid) entries.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Whether the address's domain or one of its parent domains is
    /// blocked.
    #[must_use]
    pub fn is_blocked(&self, email: &EmailAddress) -> bool {
        let mut domain = email.domain();
        loop {
            if self.domains.contains(domain) {
                return true;
            }
            match domain.split_once('.') {
                Some((_, parent)) if parent.contains('.') => domain = parent,
                _ => return false,
            }
        }
    }

    /// `email_domain_not_allowed` when the address is blocked.
    pub fn check(&self, email: &EmailAddress) -> Result<(), AuthError> {
        if self.is_blocked(email) {
            Err(AuthError::new(codes::account::EMAIL_DOMAIN_NOT_ALLOWED))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email(s: &str) -> EmailAddress {
        EmailAddress::parse(s).unwrap()
    }

    #[test]
    fn acc_12_blocks_listed_domains_and_subdomains() {
        let list = DisposableDomains::from_domains([
            "mailinator.com",
            "# comment",
            "",
            "  *.10minutemail.com  # trailing comment",
            ".guerrillamail.com",
            "ÖRNEK-ÇÖP.com",
            "com",
            "not a domain",
        ]);
        assert_eq!(list.len(), 4, "{list:?}");
        assert_eq!(list.skipped(), 2);
        assert!(list.is_blocked(&email("a@mailinator.com")));
        assert!(list.is_blocked(&email("a@MAILINATOR.com")));
        assert!(list.is_blocked(&email("a@x.y.mailinator.com")));
        assert!(list.is_blocked(&email("a@10minutemail.com")));
        assert!(list.is_blocked(&email("a@guerrillamail.com")));
        assert!(list.is_blocked(&email("a@örnek-çöp.com")));
        assert!(!list.is_blocked(&email("a@example.com")));
        assert!(!list.is_blocked(&email("a@notmailinator.com")));
        assert_eq!(
            list.check(&email("a@mailinator.com")).unwrap_err().code(),
            codes::account::EMAIL_DOMAIN_NOT_ALLOWED
        );
        assert!(list.check(&email("a@example.com")).is_ok());
    }

    #[test]
    fn acc_12_loads_from_file_and_fails_fast_when_missing() {
        let dir = std::env::temp_dir().join(format!("authn-acc12-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");
        std::fs::write(&path, "yopmail.com\ntrashmail.de\n").unwrap();
        let list = DisposableDomains::from_file(&path).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.is_blocked(&email("x@yopmail.com")));
        assert!(DisposableDomains::from_file(&dir.join("missing.txt")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
        let debug = format!("{list:?}");
        assert!(!debug.contains("yopmail"));
    }
}
