//! Self-hosted proof-of-work CAPTCHA (PRT-05).
//!
//! Issuance is stateless: the challenge is
//! `base64url(payload) "." base64url(HMAC(K_pow, payload))` where the
//! payload binds a random id, a random nonce, the difficulty, the issue and
//! expiry instants and the protected action. Nothing is stored at issuance,
//! so flooding the challenge endpoint cannot fill the database.
//!
//! The client finds a `solution` (1–64 URL-safe characters) such that
//! `SHA-256(challenge ":" solution)` starts with `difficulty` zero bits and
//! answers `challenge ":" solution`.
//!
//! Verification order (cheap and stateless first): size and charset →
//! canonical encoding → HMAC (constant time; forged challenges never reach
//! the database) → action → expiry → work → **single use**: an
//! `INSERT … ON CONFLICT DO NOTHING` into `captcha_pow_challenges` keyed by
//! the challenge id and hash; a replay (even concurrent) finds the row and
//! fails.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authn_core::error::AuthError;
use authn_core::ports::{
    CaptchaChallenge, CaptchaContext, CaptchaProvider, CaptchaVerdict, CaptchaVerifier, Clock,
};
use authn_crypto::kdf::{HmacKey, KeyPurpose, KeyRing};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

const VERSION: u8 = 1;
const MAC_LABEL: &[u8] = b"authn/protect/pow-challenge/v1";
/// version(1) id(16) nonce(16) difficulty(1) issued(8) expires(8) len(1).
const FIXED_LEN: usize = 1 + 16 + 16 + 1 + 8 + 8 + 1;
const MAX_ACTION_LEN: usize = 64;
const MAX_RESPONSE_LEN: usize = 512;
const MAX_SOLUTION_LEN: usize = 64;

const CONSUME_SQL: &str = "\
INSERT INTO captcha_pow_challenges
    (id, challenge_hash, action, difficulty, created_at, expires_at, consumed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT DO NOTHING
RETURNING id";

const PURGE_SQL: &str = "DELETE FROM captcha_pow_challenges WHERE expires_at <= $1";

/// How long a consumed challenge's single-use record outlives the
/// challenge's signed expiry. Instances check the expiry against their own
/// clock: if the record were purged the moment *one* instance saw it
/// expire, an instance whose clock lags behind would still accept the
/// challenge and could not see that it was already spent (replay).
pub const PURGE_GRACE: Duration = Duration::from_secs(15 * 60);

/// Whether `action` is a valid protected-action name
/// (`^[a-z][a-z0-9_]{0,63}$`, the `captcha_pow_challenges` constraint).
#[must_use]
pub fn is_valid_action(action: &str) -> bool {
    let bytes = action.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= MAX_ACTION_LEN
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Leading zero bits of a digest.
#[must_use]
pub fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in digest {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

fn work_digest(challenge: &str, solution: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(challenge.len() + 1 + solution.len());
    input.extend_from_slice(challenge.as_bytes());
    input.push(b':');
    input.extend_from_slice(solution.as_bytes());
    authn_crypto::sha256(&input)
}

/// Reference solver (clients, tests): the first decimal counter meeting the
/// difficulty, formatted as the `challenge:solution` response.
#[must_use]
pub fn solve(challenge: &str, difficulty: u8) -> String {
    let mut counter: u64 = 0;
    loop {
        let solution = counter.to_string();
        if leading_zero_bits(&work_digest(challenge, &solution)) >= u32::from(difficulty) {
            return format!("{challenge}:{solution}");
        }
        counter = counter.wrapping_add(1);
    }
}

struct Payload {
    id: Uuid,
    difficulty: u8,
    issued_at: i64,
    expires_at: i64,
    action: String,
}

fn encode_payload(p: &Payload, nonce: &[u8; 16]) -> Result<Vec<u8>, AuthError> {
    let action_len =
        u8::try_from(p.action.len()).map_err(|_| AuthError::internal("captcha action too long"))?;
    let mut out = Vec::with_capacity(FIXED_LEN + p.action.len());
    out.push(VERSION);
    out.extend_from_slice(p.id.as_bytes());
    out.extend_from_slice(nonce);
    out.push(p.difficulty);
    out.extend_from_slice(&p.issued_at.to_be_bytes());
    out.extend_from_slice(&p.expires_at.to_be_bytes());
    out.push(action_len);
    out.extend_from_slice(p.action.as_bytes());
    Ok(out)
}

fn take<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
    let (head, rest) = input.split_first_chunk::<N>()?;
    *input = rest;
    Some(*head)
}

fn decode_payload(mut bytes: &[u8]) -> Option<Payload> {
    let [version] = take::<1>(&mut bytes)?;
    if version != VERSION {
        return None;
    }
    let id = Uuid::from_bytes(take::<16>(&mut bytes)?);
    let _nonce = take::<16>(&mut bytes)?;
    let [difficulty] = take::<1>(&mut bytes)?;
    let issued_at = i64::from_be_bytes(take::<8>(&mut bytes)?);
    let expires_at = i64::from_be_bytes(take::<8>(&mut bytes)?);
    let [len] = take::<1>(&mut bytes)?;
    if bytes.len() != usize::from(len) {
        return None;
    }
    let action = std::str::from_utf8(bytes).ok()?.to_owned();
    Some(Payload {
        id,
        difficulty,
        issued_at,
        expires_at,
        action,
    })
}

/// The proof-of-work verifier.
#[derive(Clone)]
pub struct ProofOfWorkCaptcha {
    pool: PgPool,
    clock: Arc<dyn Clock>,
    key: HmacKey,
    difficulty: u8,
    ttl: Duration,
}

impl std::fmt::Debug for ProofOfWorkCaptcha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofOfWorkCaptcha")
            .field("difficulty", &self.difficulty)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl ProofOfWorkCaptcha {
    /// A verifier signing with the `ProofOfWork` purpose key of `keys`.
    pub fn new(
        pool: PgPool,
        clock: Arc<dyn Clock>,
        keys: &KeyRing,
        difficulty: u8,
        ttl: Duration,
    ) -> Result<Self, AuthError> {
        if !(1..=64).contains(&difficulty) {
            return Err(AuthError::internal("proof-of-work difficulty must be 1-64"));
        }
        let key = keys
            .key(KeyPurpose::ProofOfWork)
            .map_err(|_| AuthError::internal("proof-of-work purpose key missing"))?
            .clone();
        Ok(Self {
            pool,
            clock,
            key,
            difficulty,
            ttl,
        })
    }

    /// Deletes single-use records of challenges that expired more than
    /// [`PURGE_GRACE`] ago (background job, OPS-06); expired challenges are
    /// refused by their signed expiry anyway, the grace covers clock skew
    /// between instances.
    pub async fn purge_expired(&self) -> Result<u64, AuthError> {
        Ok(sqlx::query(PURGE_SQL)
            .bind(self.clock.now() - PURGE_GRACE)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    fn tag(&self, payload: &[u8]) -> [u8; 32] {
        self.key.sign_fields(&[MAC_LABEL, payload])
    }

    /// Parses and authenticates a challenge string.
    fn open(&self, challenge: &str) -> Option<Payload> {
        let (payload_b64, tag_b64) = challenge.split_once('.')?;
        let payload = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
        let tag = URL_SAFE_NO_PAD.decode(tag_b64).ok()?;
        // Canonical encoding only: one challenge, one string.
        if URL_SAFE_NO_PAD.encode(&payload) != payload_b64
            || URL_SAFE_NO_PAD.encode(&tag) != tag_b64
        {
            return None;
        }
        if !self.key.verify_fields(&[MAC_LABEL, &payload], &tag) {
            return None;
        }
        decode_payload(&payload)
    }
}

#[async_trait]
impl CaptchaVerifier for ProofOfWorkCaptcha {
    fn provider(&self) -> CaptchaProvider {
        CaptchaProvider::ProofOfWork
    }

    async fn issue_challenge(&self, ctx: &CaptchaContext) -> Result<CaptchaChallenge, AuthError> {
        if !is_valid_action(ctx.action) {
            return Err(AuthError::internal("invalid captcha action name"));
        }
        let now = self.clock.now();
        let expires = now + self.ttl;
        let nonce = authn_crypto::random::bytes::<16>()
            .map_err(|_| AuthError::internal("csprng failure"))?;
        let payload = Payload {
            id: Uuid::now_v7(),
            difficulty: self.difficulty,
            issued_at: now.unix_timestamp(),
            expires_at: expires.unix_timestamp(),
            action: ctx.action.to_owned(),
        };
        let bytes = encode_payload(&payload, &nonce)?;
        let challenge = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(self.tag(&bytes))
        );
        let expires_at = OffsetDateTime::from_unix_timestamp(payload.expires_at)
            .map_err(|_| AuthError::internal("captcha expiry out of range"))?;
        Ok(CaptchaChallenge::ProofOfWork {
            challenge,
            difficulty: self.difficulty,
            expires_at,
        })
    }

    async fn verify(
        &self,
        response: &str,
        ctx: &CaptchaContext,
    ) -> Result<CaptchaVerdict, AuthError> {
        if response.len() > MAX_RESPONSE_LEN || !response.is_ascii() {
            return Ok(CaptchaVerdict::Failed);
        }
        let Some((challenge, solution)) = response.rsplit_once(':') else {
            return Ok(CaptchaVerdict::Failed);
        };
        if solution.is_empty()
            || solution.len() > MAX_SOLUTION_LEN
            || !solution
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Ok(CaptchaVerdict::Failed);
        }
        let Some(payload) = self.open(challenge) else {
            return Ok(CaptchaVerdict::Failed);
        };
        if payload.action != ctx.action || !(1..=64).contains(&payload.difficulty) {
            return Ok(CaptchaVerdict::Failed);
        }
        let now = self.clock.now();
        if now.unix_timestamp() >= payload.expires_at {
            return Ok(CaptchaVerdict::Failed);
        }
        if leading_zero_bits(&work_digest(challenge, solution)) < u32::from(payload.difficulty) {
            return Ok(CaptchaVerdict::Failed);
        }
        let (Ok(created_at), Ok(expires_at)) = (
            OffsetDateTime::from_unix_timestamp(payload.issued_at),
            OffsetDateTime::from_unix_timestamp(payload.expires_at),
        ) else {
            return Ok(CaptchaVerdict::Failed);
        };
        let consumed: Option<Uuid> = sqlx::query_scalar(CONSUME_SQL)
            .bind(payload.id)
            .bind(authn_crypto::sha256(challenge.as_bytes()).as_slice())
            .bind(&payload.action)
            .bind(i16::from(payload.difficulty))
            .bind(created_at)
            .bind(expires_at)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        Ok(if consumed.is_some() {
            CaptchaVerdict::Passed
        } else {
            CaptchaVerdict::Failed
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prt_05_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0, 0x0f]), 12);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn prt_05_action_names_are_restricted() {
        for ok in ["login", "register", "password_reset", "a1"] {
            assert!(is_valid_action(ok), "{ok}");
        }
        for bad in ["", "Login", "1login", "log-in", "log in", &"a".repeat(65)] {
            assert!(!is_valid_action(bad), "{bad}");
        }
    }

    #[test]
    fn prt_05_payload_round_trip_and_truncation_is_rejected() {
        let p = Payload {
            id: Uuid::now_v7(),
            difficulty: 9,
            issued_at: 10,
            expires_at: 20,
            action: "login".to_owned(),
        };
        let bytes = encode_payload(&p, &[1; 16]).unwrap();
        let back = decode_payload(&bytes).unwrap();
        assert_eq!(
            (back.id, back.difficulty, back.action.as_str()),
            (p.id, 9, "login")
        );
        for cut in 0..bytes.len() {
            assert!(decode_payload(&bytes[..cut]).is_none(), "{cut}");
        }
        let mut longer = bytes.clone();
        longer.push(b'x');
        assert!(decode_payload(&longer).is_none());
    }
}
