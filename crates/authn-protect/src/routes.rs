//! HTTP endpoints of authn-protect (ARC-03, ARC-09).
//!
//! | Method | Path | Requirement |
//! |--------|------|-------------|
//! | `GET` | `/v1/captcha/challenge?action=<action>` | PRT-05 |

use authn_core::error::AuthError;
use authn_core::http::{Json, Query, RequestContext};
use authn_core::ports::{CaptchaChallenge, CaptchaProvider};
use axum::Router;
use axum::extract::{FromRef, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::captcha::CaptchaService;

/// The module router. Requires [`CaptchaService`] from the state.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    CaptchaService: FromRef<S>,
{
    Router::new().route("/v1/captcha/challenge", get(captcha_challenge))
}

/// OpenAPI document of this crate's endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(captcha_challenge),
    components(schemas(ChallengeResponse, ChallengeType)),
    tags((name = "protect", description = "Abuse protection (CAPTCHA)"))
)]
pub struct ProtectApi;

/// Query of `GET /v1/captcha/challenge`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ChallengeQuery {
    /// Protected action (`login`, `register`, `password_reset`,
    /// `magic_link`, `login_code`, `email_verification`,
    /// `phone_verification`).
    pub action: String,
}

/// Kind of challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// No CAPTCHA is configured.
    None,
    /// Render the provider widget with `site_key`.
    Widget,
    /// Solve the proof-of-work puzzle.
    ProofOfWork,
}

/// A CAPTCHA challenge. For `proof_of_work`, find a `solution` (1–64
/// characters `[A-Za-z0-9_-]`) such that `SHA-256(challenge ":" solution)`
/// starts with `difficulty` zero bits and send `challenge ":" solution` as
/// the CAPTCHA response. For `widget`, send the provider token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ChallengeResponse {
    /// Challenge kind.
    #[serde(rename = "type")]
    pub kind: ChallengeType,
    /// Widget provider (`turnstile`, `hcaptcha`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub provider: Option<CaptchaProvider>,
    /// Widget site key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_key: Option<String>,
    /// Signed proof-of-work challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// Required leading zero bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<u8>,
    /// Challenge expiry (RFC 3339).
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub expires_at: Option<time::OffsetDateTime>,
}

impl From<CaptchaChallenge> for ChallengeResponse {
    fn from(challenge: CaptchaChallenge) -> Self {
        let empty = Self {
            kind: ChallengeType::None,
            provider: None,
            site_key: None,
            challenge: None,
            difficulty: None,
            expires_at: None,
        };
        match challenge {
            CaptchaChallenge::None => empty,
            CaptchaChallenge::Widget { provider, site_key } => Self {
                kind: ChallengeType::Widget,
                provider: Some(provider),
                site_key: Some(site_key),
                ..empty
            },
            CaptchaChallenge::ProofOfWork {
                challenge,
                difficulty,
                expires_at,
            } => Self {
                kind: ChallengeType::ProofOfWork,
                challenge: Some(challenge),
                difficulty: Some(difficulty),
                expires_at: Some(expires_at),
                ..empty
            },
        }
    }
}

/// Issues a CAPTCHA challenge for an action.
#[utoipa::path(
    get,
    path = "/v1/captcha/challenge",
    tag = "protect",
    params(ChallengeQuery),
    responses(
        (status = 200, description = "Challenge to solve", body = ChallengeResponse),
        (status = 422, description = "Unknown action", body = authn_core::error::ErrorEnvelope),
        (status = 429, description = "Too many challenges from this IP (Retry-After)", body = authn_core::error::ErrorEnvelope),
        (status = "5XX", description = "Server error", body = authn_core::error::ErrorEnvelope),
    )
)]
pub async fn captcha_challenge(
    State(service): State<CaptchaService>,
    ctx: RequestContext,
    Query(query): Query<ChallengeQuery>,
) -> Result<Response, AuthError> {
    let challenge = service
        .endpoint_challenge(&query.action, ctx.client_ip)
        .await?;
    let mut response = Json(ChallengeResponse::from(challenge)).into_response();
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
