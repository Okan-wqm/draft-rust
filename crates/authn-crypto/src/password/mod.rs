//! Password hashing service (CRY-01 … CRY-05, ARC-12).
//!
//! * **CRY-01** Argon2id, configurable parameters (default OWASP m=19456,
//!   t=2, p=1), PHC strings ([`argon`]).
//! * **CRY-02** Argon2 input = `HMAC-SHA256(pepper[v], NFKC(password))`; the
//!   pepper version is returned with every hash and stored next to it
//!   ([`pepper`], [`canonicalize_password`]).
//! * **CRY-03** [`VerifyOutcome::Valid`] carries a [`RehashReason`] when the
//!   parameters or the pepper version are outdated.
//! * **CRY-04** bcrypt, PBKDF2-SHA256 and Argon2id-wrapped MD5/SHA-1 legacy
//!   hashes verify and report [`RehashReason::LegacyAlgorithm`] ([`legacy`]).
//! * **CRY-05** [`PasswordHasher::verify`] with `None` (unknown account)
//!   verifies against a hash precomputed at start-up with the current
//!   parameters and pepper, so the work is identical to a real verification.
//!   Malformed stored hashes, unknown pepper versions and oversized inputs
//!   also fall back to that dummy work and return `Invalid`, never an error
//!   that would distinguish the account.
//! * **ARC-12** Every Argon2 / bcrypt / PBKDF2 computation runs on the
//!   blocking pool (`spawn_blocking`) behind a semaphore of
//!   `crypto.max_concurrent_hashes` permits.

pub mod argon;
mod canonical;
pub mod legacy;
pub mod pepper;

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use authn_core::config::crypto::CryptoConfig;
use authn_core::secret::{ExposeSecret, SecretString, SensitiveString};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

pub use self::argon::{Argon2Phc, Argon2Settings};
pub use self::canonical::{MAX_PASSWORD_BYTES, canonicalize_password};
pub use self::legacy::LegacyDigest;
pub use self::pepper::Peppers;
use crate::CryptoError;

/// Value of the `password_credentials.algorithm` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// Argon2id over the peppered, canonical password (current scheme).
    Argon2id,
    /// Imported bcrypt hash.
    Bcrypt,
    /// Imported PBKDF2-HMAC-SHA256 hash.
    Pbkdf2Sha256,
    /// Argon2id over the peppered hex MD5 of the password (bulk-wrapped).
    Argon2idWrappedMd5,
    /// Argon2id over the peppered hex SHA-1 of the password (bulk-wrapped).
    Argon2idWrappedSha1,
}

impl HashAlgorithm {
    /// Every scheme.
    pub const ALL: &'static [Self] = &[
        Self::Argon2id,
        Self::Bcrypt,
        Self::Pbkdf2Sha256,
        Self::Argon2idWrappedMd5,
        Self::Argon2idWrappedSha1,
    ];

    /// The stored identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argon2id => "argon2id",
            Self::Bcrypt => "bcrypt",
            Self::Pbkdf2Sha256 => "pbkdf2_sha256",
            Self::Argon2idWrappedMd5 => "argon2id_wrapped_md5",
            Self::Argon2idWrappedSha1 => "argon2id_wrapped_sha1",
        }
    }

    /// Whether hashes of this scheme are always upgraded after a successful
    /// verification.
    #[must_use]
    pub const fn is_legacy(self) -> bool {
        !matches!(self, Self::Argon2id)
    }

    /// Whether the scheme requires a pepper version.
    #[must_use]
    pub const fn uses_pepper(self) -> bool {
        matches!(
            self,
            Self::Argon2id | Self::Argon2idWrappedMd5 | Self::Argon2idWrappedSha1
        )
    }

    const fn wrapped_digest(self) -> Option<LegacyDigest> {
        match self {
            Self::Argon2idWrappedMd5 => Some(LegacyDigest::Md5),
            Self::Argon2idWrappedSha1 => Some(LegacyDigest::Sha1),
            _ => None,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HashAlgorithm {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|a| a.as_str() == s)
            .ok_or(CryptoError::Unsupported)
    }
}

/// A new hash to store (`password_credentials`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHashRecord {
    /// PHC string (sensitive: enables offline guessing if leaked).
    pub hash: SensitiveString,
    /// Scheme identifier.
    pub algorithm: HashAlgorithm,
    /// Pepper version used (always `Some` for Argon2id-based schemes).
    pub pepper_version: Option<u32>,
}

/// A stored hash as read from `password_credentials`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPasswordHash {
    /// Stored hash string.
    pub hash: SensitiveString,
    /// `algorithm` column.
    pub algorithm: String,
    /// `pepper_version` column.
    pub pepper_version: Option<u32>,
}

impl StoredPasswordHash {
    /// Builds the value from the stored columns.
    #[must_use]
    pub fn new(hash: &SensitiveString, algorithm: &str, pepper_version: Option<u32>) -> Self {
        Self {
            hash: hash.clone(),
            algorithm: algorithm.to_owned(),
            pepper_version,
        }
    }
}

impl From<&PasswordHashRecord> for StoredPasswordHash {
    fn from(record: &PasswordHashRecord) -> Self {
        Self {
            hash: record.hash.clone(),
            algorithm: record.algorithm.as_str().to_owned(),
            pepper_version: record.pepper_version,
        }
    }
}

/// Why a successfully verified hash must be replaced (CRY-03, CRY-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RehashReason {
    /// Argon2 parameters (or salt/output length) differ from the current
    /// configuration.
    OutdatedParameters,
    /// The hash uses an older pepper version.
    OutdatedPepper,
    /// Legacy scheme (bcrypt, PBKDF2, wrapped MD5/SHA-1).
    LegacyAlgorithm,
}

/// Result of a password verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum VerifyOutcome {
    /// Wrong password, unknown account or unusable stored hash.
    Invalid,
    /// Correct password. `rehash` tells the caller to store a fresh
    /// [`PasswordHasher::hash`] of the same password.
    Valid {
        /// Reason to upgrade the stored hash, if any.
        rehash: Option<RehashReason>,
    },
}

impl VerifyOutcome {
    /// Whether the password was correct.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    /// The upgrade reason, if the password was correct and the hash is stale.
    #[must_use]
    pub const fn rehash_reason(self) -> Option<RehashReason> {
        match self {
            Self::Valid { rehash } => rehash,
            Self::Invalid => None,
        }
    }
}

/// The password hashing service. Cheap to clone (shared state).
#[derive(Clone)]
pub struct PasswordHasher {
    inner: Arc<Inner>,
}

struct Inner {
    settings: Argon2Settings,
    peppers: Peppers,
    permits: Arc<Semaphore>,
    dummy: Argon2Phc,
}

impl fmt::Debug for PasswordHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHasher")
            .field("settings", &self.inner.settings)
            .field("peppers", &self.inner.peppers)
            .field("available_permits", &self.inner.permits.available_permits())
            .finish_non_exhaustive()
    }
}

impl PasswordHasher {
    /// Builds the service from `[crypto]` and precomputes the dummy hash
    /// (one Argon2 computation on the blocking pool).
    pub async fn from_config(config: &CryptoConfig) -> Result<Self, CryptoError> {
        let permits =
            usize::try_from(config.max_concurrent_hashes).map_err(|_| CryptoError::Unsupported)?;
        Self::new(
            Argon2Settings::from(config.argon2),
            Peppers::from_config(config)?,
            permits,
        )
        .await
    }

    /// Builds the service from its parts.
    pub async fn new(
        settings: Argon2Settings,
        peppers: Peppers,
        max_concurrent: usize,
    ) -> Result<Self, CryptoError> {
        let settings = settings.validate()?;
        if max_concurrent == 0 {
            return Err(CryptoError::Unsupported);
        }
        let permits = Arc::new(Semaphore::new(max_concurrent));
        // The dummy "password" is random and discarded: nothing can match it.
        let dummy_input = crate::random::secret_bytes::<32>()?;
        let pepper = peppers.apply(peppers.current_version(), dummy_input.as_slice())?;
        let dummy = run_blocking(&permits, move || {
            argon::hash(settings, pepper.as_slice()).and_then(|phc| Argon2Phc::parse(&phc))
        })
        .await??;
        Ok(Self {
            inner: Arc::new(Inner {
                settings,
                peppers,
                permits,
                dummy,
            }),
        })
    }

    /// Current Argon2 parameters.
    #[must_use]
    pub fn settings(&self) -> Argon2Settings {
        self.inner.settings
    }

    /// Pepper version used for new hashes.
    #[must_use]
    pub fn current_pepper_version(&self) -> u32 {
        self.inner.peppers.current_version()
    }

    /// Hashes a new password (CRY-01, CRY-02). The password is normalized
    /// with [`canonicalize_password`]; policy checks happen before, in
    /// `authn-password`.
    pub async fn hash(&self, password: &SecretString) -> Result<PasswordHashRecord, CryptoError> {
        let canonical = canonicalize_password(password.expose_secret())?;
        let inner = Arc::clone(&self.inner);
        run_blocking(&self.inner.permits, move || {
            inner.hash_canonical(&canonical)
        })
        .await?
    }

    /// Verifies `password` against `stored`; `None` means "no such account"
    /// and performs the equal-cost dummy verification (CRY-05).
    pub async fn verify(
        &self,
        password: &SecretString,
        stored: Option<&StoredPasswordHash>,
    ) -> Result<VerifyOutcome, CryptoError> {
        let raw = Zeroizing::new(password.expose_secret().to_owned());
        let stored = stored.cloned();
        let inner = Arc::clone(&self.inner);
        run_blocking(&self.inner.permits, move || {
            inner.verify_blocking(&raw, stored.as_ref())
        })
        .await
    }

    /// Equal-cost verification against the dummy hash; always `Invalid`
    /// (CRY-05). Equivalent to `verify(password, None)`.
    pub async fn verify_dummy(
        &self,
        password: &SecretString,
    ) -> Result<VerifyOutcome, CryptoError> {
        self.verify(password, None).await
    }

    /// Cheap check (no hashing) whether `stored` would be upgraded after a
    /// successful verification. Unparseable hashes report `None` — they
    /// cannot be verified at all.
    #[must_use]
    pub fn needs_rehash(&self, stored: &StoredPasswordHash) -> Option<RehashReason> {
        let algorithm = HashAlgorithm::from_str(&stored.algorithm).ok()?;
        if algorithm.is_legacy() {
            return Some(RehashReason::LegacyAlgorithm);
        }
        let parsed = Argon2Phc::parse(stored.hash.expose()).ok()?;
        self.inner
            .argon_rehash_reason(&parsed, stored.pepper_version?)
    }

    /// Wraps an imported unsalted MD5/SHA-1 hex digest into Argon2id
    /// (`argon2id(HMAC(pepper, hex))`, CRY-04) for the
    /// `migrate-legacy-hashes` tool.
    pub async fn wrap_legacy_digest(
        &self,
        digest: LegacyDigest,
        legacy_hex: &str,
    ) -> Result<PasswordHashRecord, CryptoError> {
        let normalized = digest.normalize_hex(legacy_hex)?;
        let inner = Arc::clone(&self.inner);
        run_blocking(&self.inner.permits, move || {
            let version = inner.peppers.current_version();
            let input = inner.peppers.apply(version, normalized.as_bytes())?;
            let phc = argon::hash(inner.settings, input.as_slice())?;
            Ok(PasswordHashRecord {
                hash: SensitiveString::new(phc),
                algorithm: match digest {
                    LegacyDigest::Md5 => HashAlgorithm::Argon2idWrappedMd5,
                    LegacyDigest::Sha1 => HashAlgorithm::Argon2idWrappedSha1,
                },
                pepper_version: Some(version),
            })
        })
        .await?
    }
}

impl Inner {
    fn hash_canonical(&self, canonical: &str) -> Result<PasswordHashRecord, CryptoError> {
        let version = self.peppers.current_version();
        let input = self.peppers.apply(version, canonical.as_bytes())?;
        let phc = argon::hash(self.settings, input.as_slice())?;
        Ok(PasswordHashRecord {
            hash: SensitiveString::new(phc),
            algorithm: HashAlgorithm::Argon2id,
            pepper_version: Some(version),
        })
    }

    fn verify_blocking(&self, raw: &str, stored: Option<&StoredPasswordHash>) -> VerifyOutcome {
        let Some(stored) = stored else {
            self.dummy_work(raw);
            return VerifyOutcome::Invalid;
        };
        match self.verify_stored(raw, stored) {
            Ok(outcome) => outcome,
            Err(err) => {
                // The account is real but its hash is unusable (corrupt
                // import, removed pepper version, oversized input). Do the
                // same work as for an unknown account and fail closed.
                if err != CryptoError::TooLarge {
                    tracing::error!(
                        error = %err,
                        algorithm = %stored.algorithm,
                        pepper_version = ?stored.pepper_version,
                        "stored password hash cannot be verified"
                    );
                }
                self.dummy_work(raw);
                VerifyOutcome::Invalid
            }
        }
    }

    /// One Argon2 verification with the current parameters against the
    /// precomputed dummy hash; the result is discarded.
    fn dummy_work(&self, raw: &str) {
        let canonical = canonicalize_password(raw).unwrap_or_default();
        let version = self.peppers.current_version();
        if let Ok(input) = self.peppers.apply(version, canonical.as_bytes()) {
            let _ = self.dummy.verify(input.as_slice());
        }
    }

    fn verify_stored(
        &self,
        raw: &str,
        stored: &StoredPasswordHash,
    ) -> Result<VerifyOutcome, CryptoError> {
        if raw.len() > MAX_PASSWORD_BYTES {
            return Err(CryptoError::TooLarge);
        }
        let algorithm = HashAlgorithm::from_str(&stored.algorithm)?;
        let hash = stored.hash.expose();
        match algorithm {
            HashAlgorithm::Argon2id => {
                let parsed = Argon2Phc::parse(hash)?;
                let version = stored.pepper_version.ok_or(CryptoError::UnknownKey)?;
                let canonical = canonicalize_password(raw)?;
                let input = self.peppers.apply(version, canonical.as_bytes())?;
                Ok(if parsed.verify(input.as_slice())? {
                    VerifyOutcome::Valid {
                        rehash: self.argon_rehash_reason(&parsed, version),
                    }
                } else {
                    VerifyOutcome::Invalid
                })
            }
            HashAlgorithm::Argon2idWrappedMd5 | HashAlgorithm::Argon2idWrappedSha1 => {
                let parsed = Argon2Phc::parse(hash)?;
                let version = stored.pepper_version.ok_or(CryptoError::UnknownKey)?;
                let digest = algorithm
                    .wrapped_digest()
                    .ok_or(CryptoError::Internal("wrapped digest"))?
                    .digest_hex(raw.as_bytes());
                let input = self.peppers.apply(version, digest.as_bytes())?;
                Ok(legacy_outcome(parsed.verify(input.as_slice())?))
            }
            HashAlgorithm::Bcrypt => {
                Ok(legacy_outcome(legacy::verify_bcrypt(raw.as_bytes(), hash)?))
            }
            HashAlgorithm::Pbkdf2Sha256 => Ok(legacy_outcome(
                legacy::Pbkdf2Hash::parse(hash)?.verify(raw.as_bytes()),
            )),
        }
    }

    fn argon_rehash_reason(&self, parsed: &Argon2Phc, pepper_version: u32) -> Option<RehashReason> {
        if !parsed.is_current(self.settings) {
            Some(RehashReason::OutdatedParameters)
        } else if pepper_version != self.peppers.current_version() {
            Some(RehashReason::OutdatedPepper)
        } else {
            None
        }
    }
}

const fn legacy_outcome(matched: bool) -> VerifyOutcome {
    if matched {
        VerifyOutcome::Valid {
            rehash: Some(RehashReason::LegacyAlgorithm),
        }
    } else {
        VerifyOutcome::Invalid
    }
}

/// Runs `work` on the blocking pool while holding a permit (ARC-12). The
/// permit moves into the blocking task, so the concurrency bound holds even
/// when the awaiting request is cancelled.
async fn run_blocking<T, F>(permits: &Arc<Semaphore>, work: F) -> Result<T, CryptoError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = Arc::clone(permits)
        .acquire_owned()
        .await
        .map_err(|_| CryptoError::WorkerUnavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| CryptoError::WorkerUnavailable)
}

#[cfg(test)]
mod tests;
