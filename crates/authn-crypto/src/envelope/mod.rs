//! Envelope encryption of reversible secrets at rest (CRY-08).
//!
//! Every sealed value gets its **own** random 256-bit data key (DEK). The
//! DEK encrypts the value with XChaCha20-Poly1305; a [`KeyProvider`] wraps
//! the DEK with the current key-encryption key (KEK). The envelope is
//! self-contained:
//!
//! ```text
//! offset  size      field
//! 0       1         version (0x01)
//! 1       1         L = length of kek_id (1..=32)
//! 2       L         kek_id ([A-Za-z0-9_-])
//! 2+L     2         W = length of the wrapped DEK (big-endian, 1..=1024)
//! 4+L     W         wrapped DEK (provider-specific blob)
//! 4+L+W   24        data nonce
//! 28+L+W  n+16      ciphertext || Poly1305 tag   (n ≤ MAX_PLAINTEXT_LEN)
//! ```
//!
//! **AAD is mandatory.** Both the data and the DEK wrap are bound to an
//! [`EnvelopeContext`] (table, column, row id) and to the version byte, so a
//! ciphertext copied into another row, column or table fails to decrypt
//! (copy-paste attack), as does any modification of any byte.
//!
//! **KEK rotation** ([`EnvelopeCipher::rewrap`]) only re-wraps the DEK with
//! the current KEK; the data ciphertext is unchanged. Old KEKs stay
//! configured until `reencrypt` reports no envelope still references them.
//!
//! **Why XChaCha20-Poly1305** (and not AES-256-GCM): 192-bit random nonces
//! have no practical collision bound (AES-GCM's 96-bit random nonces must
//! stay below ~2^32 messages per key); the pure-software implementation is
//! constant-time on every CPU, without depending on AES-NI; and the crate is
//! already part of the audited RustCrypto set used by the workspace.
//! Because each DEK encrypts exactly one value, nonce reuse is impossible
//! even in theory.

mod provider;

use std::fmt;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub use self::provider::{
    DataKey, ENV_BLOB_LEN, EnvKeyProvider, KekId, KeyProvider, MAX_KEK_ID_LEN, WrappedDataKey,
};
use crate::secret::SecretBytes;
use crate::{CryptoError, random};

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;
/// Largest plaintext that may be sealed (1 MiB).
pub const MAX_PLAINTEXT_LEN: usize = 1 << 20;
/// Largest wrapped-DEK blob accepted from a provider.
pub const MAX_WRAPPED_KEY_LEN: usize = 1024;
/// Data nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Largest envelope accepted by the parser.
pub const MAX_ENVELOPE_LEN: usize =
    4 + MAX_KEK_ID_LEN + MAX_WRAPPED_KEY_LEN + NONCE_LEN + MAX_PLAINTEXT_LEN + TAG_LEN;

const CONTEXT_LABEL: &[u8] = b"authn-envelope/v1";

/// Where a sealed value lives: table, column and row id. Serialized
/// unambiguously (length-prefixed) into the AAD.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EnvelopeContext {
    table: &'static str,
    column: &'static str,
    row: String,
}

impl EnvelopeContext {
    /// Builds a context. `table` and `column` must be SQL identifiers
    /// (`[a-z][a-z0-9_]{0,62}`); `row` is the row's primary key in its
    /// canonical text form (1..=256 bytes).
    pub fn new(
        table: &'static str,
        column: &'static str,
        row: impl fmt::Display,
    ) -> Result<Self, CryptoError> {
        let row = row.to_string();
        if !is_identifier(table) || !is_identifier(column) || row.is_empty() || row.len() > 256 {
            return Err(CryptoError::Malformed);
        }
        Ok(Self { table, column, row })
    }

    /// Table name.
    #[must_use]
    pub const fn table(&self) -> &'static str {
        self.table
    }

    /// Column name.
    #[must_use]
    pub const fn column(&self) -> &'static str {
        self.column
    }

    /// Row id text.
    #[must_use]
    pub fn row(&self) -> &str {
        &self.row
    }

    fn encode(&self, purpose: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            CONTEXT_LABEL.len()
                + purpose.len()
                + self.table.len()
                + self.column.len()
                + self.row.len()
                + 8,
        );
        out.extend_from_slice(CONTEXT_LABEL);
        out.extend_from_slice(purpose);
        out.push(ENVELOPE_VERSION);
        for field in [
            self.table.as_bytes(),
            self.column.as_bytes(),
            self.row.as_bytes(),
        ] {
            // Each field is ≤ 256 bytes (validated in `new`).
            out.extend_from_slice(&u16::try_from(field.len()).unwrap_or(u16::MAX).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }
}

impl fmt::Debug for EnvelopeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnvelopeContext({}.{}#{})",
            self.table, self.column, self.row
        )
    }
}

fn is_identifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// A parsed (not yet authenticated) envelope.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    kek_id: &'a str,
    wrapped_key: &'a [u8],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

impl fmt::Debug for Envelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("kek_id", &self.kek_id)
            .field("wrapped_key_len", &self.wrapped_key.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl<'a> Envelope<'a> {
    /// Parses the wire format. Never panics, never allocates proportionally
    /// to attacker-declared lengths, and rejects trailing or missing bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_ENVELOPE_LEN {
            return Err(CryptoError::TooLarge);
        }
        let mut reader = Reader(bytes);
        let version = reader.u8()?;
        if version != ENVELOPE_VERSION {
            return Err(CryptoError::Unsupported);
        }
        let kek_len = usize::from(reader.u8()?);
        let kek_id =
            std::str::from_utf8(reader.take(kek_len)?).map_err(|_| CryptoError::Malformed)?;
        KekId::new(kek_id)?;
        let wrapped_len = usize::from(reader.u16()?);
        if wrapped_len == 0 || wrapped_len > MAX_WRAPPED_KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let wrapped_key = reader.take(wrapped_len)?;
        let nonce: [u8; NONCE_LEN] = reader
            .take(NONCE_LEN)?
            .try_into()
            .map_err(|_| CryptoError::Malformed)?;
        let ciphertext = reader.0;
        if ciphertext.len() < TAG_LEN || ciphertext.len() > MAX_PLAINTEXT_LEN + TAG_LEN {
            return Err(CryptoError::Malformed);
        }
        Ok(Self {
            kek_id,
            wrapped_key,
            nonce,
            ciphertext,
        })
    }

    /// KEK id recorded in the header.
    #[must_use]
    pub const fn kek_id(&self) -> &'a str {
        self.kek_id
    }

    /// Length of the sealed plaintext.
    #[must_use]
    pub const fn plaintext_len(&self) -> usize {
        self.ciphertext.len() - TAG_LEN
    }

    /// Serializes back to the wire format.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        encode(self.kek_id, self.wrapped_key, &self.nonce, self.ciphertext)
    }
}

fn encode(
    kek_id: &str,
    wrapped_key: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let kek_len = u8::try_from(kek_id.len()).map_err(|_| CryptoError::Malformed)?;
    let wrapped_len = u16::try_from(wrapped_key.len()).map_err(|_| CryptoError::Malformed)?;
    if kek_id.is_empty()
        || kek_id.len() > MAX_KEK_ID_LEN
        || wrapped_key.is_empty()
        || wrapped_key.len() > MAX_WRAPPED_KEY_LEN
    {
        return Err(CryptoError::Malformed);
    }
    let mut out =
        Vec::with_capacity(4 + kek_id.len() + wrapped_key.len() + NONCE_LEN + ciphertext.len());
    out.push(ENVELOPE_VERSION);
    out.push(kek_len);
    out.extend_from_slice(kek_id.as_bytes());
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(wrapped_key);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CryptoError> {
        if n > self.0.len() {
            return Err(CryptoError::Malformed);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, CryptoError> {
        self.take(1)?.first().copied().ok_or(CryptoError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, CryptoError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| CryptoError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }
}

/// Seals and opens envelopes with a [`KeyProvider`]. Cheap to clone.
#[derive(Clone)]
pub struct EnvelopeCipher {
    provider: Arc<dyn KeyProvider>,
}

impl fmt::Debug for EnvelopeCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeCipher")
            .field("current_kek_id", self.provider.current_kek_id())
            .finish_non_exhaustive()
    }
}

impl EnvelopeCipher {
    /// A cipher using `provider`.
    #[must_use]
    pub fn new(provider: Arc<dyn KeyProvider>) -> Self {
        Self { provider }
    }

    /// A cipher over the configured KEKs ([`EnvKeyProvider`]).
    pub fn from_config(
        config: &authn_core::config::crypto::CryptoConfig,
    ) -> Result<Self, CryptoError> {
        Ok(Self::new(Arc::new(EnvKeyProvider::from_config(config)?)))
    }

    /// KEK used for new envelopes.
    #[must_use]
    pub fn current_kek_id(&self) -> &KekId {
        self.provider.current_kek_id()
    }

    /// Encrypts `plaintext` for `context`.
    pub async fn seal(
        &self,
        plaintext: &[u8],
        context: &EnvelopeContext,
    ) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::TooLarge);
        }
        let dek = DataKey::generate()?;
        let wrapped = self.provider.wrap(&dek, &context.encode(b"/dek")).await?;
        let nonce = random::bytes::<NONCE_LEN>()?;
        let ciphertext = XChaCha20Poly1305::new(dek.expose().into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &context.encode(b"/data"),
                },
            )
            .map_err(|_| CryptoError::Internal("envelope encryption failed"))?;
        encode(wrapped.kek_id.as_str(), &wrapped.blob, &nonce, &ciphertext)
    }

    /// Decrypts an envelope sealed for `context`. Any mismatch (other row,
    /// other column, modified byte, unknown or wrong KEK) fails.
    pub async fn open(
        &self,
        envelope: &[u8],
        context: &EnvelopeContext,
    ) -> Result<SecretBytes, CryptoError> {
        let parsed = Envelope::parse(envelope)?;
        let dek = self.unwrap_dek(&parsed, context).await?;
        decrypt_data(&dek, &parsed, context)
    }

    /// Whether the envelope was wrapped by a KEK other than the current one
    /// (i.e. [`EnvelopeCipher::rewrap`] would change it).
    pub fn needs_rewrap(&self, envelope: &[u8]) -> Result<bool, CryptoError> {
        let parsed = Envelope::parse(envelope)?;
        Ok(parsed.kek_id() != self.provider.current_kek_id().as_str())
    }

    /// KEK rotation: re-wraps the DEK with the current KEK. The envelope is
    /// fully authenticated first (DEK *and* data), so garbage is never
    /// laundered into a freshly wrapped envelope. Returns `None` when the
    /// envelope already uses the current KEK.
    pub async fn rewrap(
        &self,
        envelope: &[u8],
        context: &EnvelopeContext,
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let parsed = Envelope::parse(envelope)?;
        let dek = self.unwrap_dek(&parsed, context).await?;
        drop(decrypt_data(&dek, &parsed, context)?);
        if parsed.kek_id() == self.provider.current_kek_id().as_str() {
            return Ok(None);
        }
        let wrapped = self.provider.wrap(&dek, &context.encode(b"/dek")).await?;
        encode(
            wrapped.kek_id.as_str(),
            &wrapped.blob,
            &parsed.nonce,
            parsed.ciphertext,
        )
        .map(Some)
    }

    async fn unwrap_dek(
        &self,
        parsed: &Envelope<'_>,
        context: &EnvelopeContext,
    ) -> Result<DataKey, CryptoError> {
        let kek_id = KekId::new(parsed.kek_id)?;
        self.provider
            .unwrap(&kek_id, parsed.wrapped_key, &context.encode(b"/dek"))
            .await
    }
}

fn decrypt_data(
    dek: &DataKey,
    parsed: &Envelope<'_>,
    context: &EnvelopeContext,
) -> Result<SecretBytes, CryptoError> {
    let plaintext = XChaCha20Poly1305::new(dek.expose().into())
        .decrypt(
            &XNonce::from(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: &context.encode(b"/data"),
            },
        )
        .map_err(|_| CryptoError::Unauthentic)?;
    Ok(SecretBytes::from(Zeroizing::new(plaintext)))
}

#[cfg(test)]
mod tests;
