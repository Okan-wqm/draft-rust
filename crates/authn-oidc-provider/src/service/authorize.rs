//! Authorization endpoint, interactions (login / consent hand-off) and the
//! user's consents (OIDP-02 … OIDP-05).

use authn_core::domain::{AuthMethodRef, Principal, PrincipalCredential, Subject};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::{SessionId, UserId};
use authn_core::ports::{Actor, RateLimitKey, SecurityEvent, SecurityEventKind};
use authn_crypto::token::{OpaqueToken, TokenHash};
use serde::Serialize;
use sqlx::PgConnection;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{OidcProviderService, after};
use crate::claims;
use crate::redirect;
use crate::request::{
    AuthorizeError, AuthorizeErrorCode, ClientPolicy, ValidatedAuthorization, parse_query,
};
use crate::store::{self, ClientRow, CodeRow, GRANT_AUTHORIZATION_CODE, GrantRow, InteractionRow};

/// What `GET /v1/oauth2/authorize` answers: always a `303` redirect.
#[derive(Debug)]
pub struct AuthorizeOutcome {
    /// Where to send the browser.
    pub location: String,
    /// A browser-binding cookie value to set (interaction hand-off).
    pub browser_cookie: Option<String>,
}

/// Where the front end sends the browser after accept / deny.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RedirectTarget {
    /// The client's redirect URI with `code` (or `error`), `state` and
    /// `iss`.
    pub redirect_to: String,
}

/// The client as shown on the consent screen.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientSummary {
    /// Public client id.
    pub client_id: String,
    /// Display name.
    pub name: String,
    /// First-party client (no consent needed).
    pub first_party: bool,
}

/// A pending authorization request, for the login / consent page.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InteractionView {
    /// Interaction id.
    pub interaction_id: Uuid,
    /// The requesting client.
    pub client: ClientSummary,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Requested resources (RFC 8707).
    pub resources: Vec<String>,
    /// Expiry of the request.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// The browser has a usable session.
    pub authenticated: bool,
    /// The user must (re-)authenticate before accepting: sign in when
    /// `authenticated` is false, otherwise step up with `POST /v1/reauth`.
    pub login_required: bool,
    /// Why: `no_session`, `prompt_login`, `max_age`, `acr`.
    pub login_reasons: Vec<String>,
    /// The consent screen must be shown.
    pub consent_required: bool,
    /// Requested `acr_values` (to choose the step-up method).
    pub acr_values: Vec<String>,
}

/// A consent of the user (OIDP-05).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ConsentView {
    /// The client.
    pub client_id: String,
    /// Its name.
    pub client_name: String,
    /// Approved scopes.
    pub scopes: Vec<String>,
    /// First approval.
    #[serde(with = "time::serde::rfc3339")]
    pub granted_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// The browser session a request may be authorized with: a cookie
/// session of a user, never an impersonation, an API key or a bearer
/// token.
#[derive(Debug, Clone)]
pub(crate) struct Eligible {
    pub(crate) user: UserId,
    pub(crate) session: SessionId,
    pub(crate) auth_time: OffsetDateTime,
    pub(crate) amr: Vec<AuthMethodRef>,
}

pub(crate) fn eligible(principal: Option<&Principal>) -> Option<Eligible> {
    let principal = principal?;
    let Subject::User { user_id } = principal.subject else {
        return None;
    };
    let PrincipalCredential::SessionCookie { session_id } = principal.credential else {
        return None;
    };
    if principal.impersonation.is_some() {
        return None;
    }
    Some(Eligible {
        user: user_id,
        session: session_id,
        auth_time: principal.auth_time?,
        amr: principal.amr.clone(),
    })
}

/// Why the user must authenticate again before the request completes.
fn login_reasons(
    prompt_login: bool,
    max_age: Option<i64>,
    acr_values: &[String],
    requested_at: OffsetDateTime,
    session: Option<&Eligible>,
    now: OffsetDateTime,
) -> Vec<&'static str> {
    let Some(session) = session else {
        return vec!["no_session"];
    };
    let mut reasons = Vec::new();
    if prompt_login && session.auth_time < requested_at {
        reasons.push("prompt_login");
    }
    if let Some(max_age) = max_age
        && (now - session.auth_time).whole_seconds() > max_age
    {
        reasons.push("max_age");
    }
    if !claims::satisfies(&session.amr, acr_values) {
        reasons.push("acr");
    }
    reasons
}

/// Whether a request of `client` to `redirect_uri` may be approved
/// without the user (single sign-on, `prompt=none`, first-party clients).
///
/// RFC 8252 §8.6: not for a public client whose redirect URI does not
/// prove its identity. Any local process can listen on the loopback
/// interface and any app can claim a private-use scheme; with its own PKCE
/// pair such an impostor would silently receive and redeem a code of the
/// genuine client. A confidential client needs its secret to redeem the
/// code; an `https` redirect is bound to its host by TLS (and, for native
/// apps, by the operating system's verified app links).
pub(crate) fn auto_approvable(client: &ClientRow, redirect_uri: &str) -> bool {
    client.is_confidential() || redirect_uri.starts_with("https://")
}

fn no_redirect(reason: &'static str) -> AuthError {
    AuthError::new(codes::oidc_provider::INVALID_AUTHORIZATION_REQUEST).with_context(reason)
}

fn interaction_invalid(reason: &'static str) -> AuthError {
    AuthError::new(codes::oidc_provider::OAUTH_INTERACTION_INVALID).with_context(reason)
}

/// The client's redirect URI with `params` appended to its query.
pub(crate) fn redirect_with(uri: &str, params: &[(&str, &str)]) -> Result<String, AuthError> {
    let mut url = url::Url::parse(uri)
        .map_err(|_| AuthError::internal("validated redirect URI unparsable"))?;
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in params {
            query.append_pair(name, value);
        }
    }
    Ok(url.into())
}

/// Parameters of a code to issue.
pub(crate) struct CodeRequest<'a> {
    pub(crate) redirect_uri: &'a str,
    pub(crate) scopes: &'a [String],
    pub(crate) resources: &'a [String],
    pub(crate) nonce: Option<&'a str>,
    pub(crate) code_challenge: &'a str,
    pub(crate) state: Option<&'a str>,
}

impl OidcProviderService {
    fn error_location(
        &self,
        redirect_uri: &str,
        error: AuthorizeError,
        state: Option<&str>,
    ) -> Result<String, AuthError> {
        let mut params = vec![
            ("error", error.code.as_str()),
            ("error_description", error.description),
        ];
        if let Some(state) = state {
            params.push(("state", state));
        }
        params.push(("iss", self.settings().issuer.as_str()));
        redirect_with(redirect_uri, &params)
    }

    /// Whether the user must see the consent screen. A stored consent
    /// counts only when it covers every requested scope **and** resource
    /// (the token audiences the user was shown).
    async fn needs_consent(
        &self,
        conn: &mut PgConnection,
        client: &ClientRow,
        redirect_uri: &str,
        user: UserId,
        request: (&[String], &[String]),
        prompt_consent: bool,
    ) -> Result<bool, AuthError> {
        let (scopes, resources) = request;
        if !auto_approvable(client, redirect_uri) {
            return Ok(true);
        }
        if client.skip_consent {
            return Ok(false);
        }
        if prompt_consent {
            return Ok(true);
        }
        let granted = store::consented(&mut *conn, user, client.id).await?;
        Ok(!granted.is_some_and(|(granted_scopes, granted_resources)| {
            scopes.iter().all(|s| granted_scopes.contains(s))
                && resources.iter().all(|r| granted_resources.contains(r))
        }))
    }

    /// Creates a grant and its single-use code in the caller's
    /// transaction; returns the redirect location with `code`, `state`
    /// and `iss` (RFC 9207).
    async fn issue_code(
        &self,
        conn: &mut PgConnection,
        client: &ClientRow,
        session: &Eligible,
        request: &CodeRequest<'_>,
    ) -> Result<String, AuthError> {
        let now = self.now();
        let grant = GrantRow {
            id: Uuid::now_v7(),
            client_id: client.id,
            user_id: session.user,
            session_id: session.session,
            scopes: request.scopes.to_vec(),
            resources: request.resources.to_vec(),
            nonce: request.nonce.map(str::to_owned),
            auth_time: session.auth_time,
            amr: session.amr.iter().map(|a| a.as_str().to_owned()).collect(),
            acr: Some(claims::acr_for(&session.amr).to_owned()),
            created_at: now,
            expires_at: after(now, self.settings().refresh_token_absolute_ttl),
            revoked_at: None,
        };
        store::insert_grant(&mut *conn, &grant).await?;
        let code = OpaqueToken::generate().map_err(AuthError::from)?;
        let row = CodeRow {
            id: Uuid::now_v7(),
            grant_id: grant.id,
            redirect_uri: request.redirect_uri.to_owned(),
            code_challenge: request.code_challenge.to_owned(),
            created_at: now,
            expires_at: after(now, self.settings().authorization_code_ttl),
            consumed_at: None,
        };
        store::insert_code(&mut *conn, &row, code.hash().as_bytes()).await?;
        let mut params = vec![("code", code.expose())];
        if let Some(state) = request.state {
            params.push(("state", state));
        }
        params.push(("iss", self.settings().issuer.as_str()));
        redirect_with(request.redirect_uri, &params)
    }

    /// `GET /v1/oauth2/authorize` (OIDP-02 … OIDP-04). `Err` only for a
    /// request that cannot be redirected (unknown / disabled client,
    /// unregistered redirect URI, malformed query) and for rate limits;
    /// every other outcome is a `303` to the client (code or error) or to
    /// the interaction page.
    pub async fn authorize(
        &self,
        ctx: &RequestContext,
        query: &str,
        principal: Option<&Principal>,
        browser: Option<String>,
    ) -> Result<AuthorizeOutcome, AuthError> {
        self.limit(
            &RateLimitKey::ip("oauth2_authorize", ctx.client_ip),
            self.settings().authorize_per_ip,
        )
        .await?;
        let params = parse_query(query).map_err(|e| no_redirect(e.reason()))?;
        let client = store::find_client(self.pool(), &params.client_id)
            .await?
            .filter(|c| !c.disabled)
            .ok_or_else(|| no_redirect("unknown_client"))?;
        if !redirect::matches(&client.redirect_uris, &params.redirect_uri) {
            return Err(no_redirect("redirect_uri_mismatch"));
        }
        let redirect_uri = params.redirect_uri.clone();
        let policy = ClientPolicy {
            allowed_scopes: &client.allowed_scopes,
            allowed_resources: &client.allowed_resources,
            code_grant_allowed: client.allows_grant(GRANT_AUTHORIZATION_CODE),
        };
        let request = match params.validate(&policy, &self.settings().supported_scopes) {
            Ok(request) => request,
            Err(error) => {
                return Ok(AuthorizeOutcome {
                    location: self.error_location(&redirect_uri, error, params.state.as_deref())?,
                    browser_cookie: None,
                });
            }
        };
        self.decide(
            &client,
            &redirect_uri,
            request,
            eligible(principal),
            browser,
        )
        .await
    }

    async fn decide(
        &self,
        client: &ClientRow,
        redirect_uri: &str,
        request: ValidatedAuthorization,
        session: Option<Eligible>,
        browser: Option<String>,
    ) -> Result<AuthorizeOutcome, AuthError> {
        let now = self.now();
        let state = request.state.as_deref();
        let reasons = login_reasons(
            request.prompt.login,
            request.max_age,
            &request.acr_values,
            now,
            session.as_ref(),
            now,
        );
        let mut conn = self.pool().acquire().await?;
        let consent = match &session {
            Some(s) => {
                self.needs_consent(
                    &mut conn,
                    client,
                    redirect_uri,
                    s.user,
                    (&request.scopes, &request.resources),
                    request.prompt.consent,
                )
                .await?
            }
            None => true,
        };
        drop(conn);
        let code_request = CodeRequest {
            redirect_uri,
            scopes: &request.scopes,
            resources: &request.resources,
            nonce: request.nonce.as_deref(),
            code_challenge: &request.code_challenge,
            state,
        };
        if request.prompt.none {
            let error = if session.is_none() || reasons.contains(&"max_age") {
                Some(AuthorizeError::new(
                    AuthorizeErrorCode::LoginRequired,
                    "the user must sign in",
                ))
            } else if !reasons.is_empty() {
                Some(AuthorizeError::new(
                    AuthorizeErrorCode::InteractionRequired,
                    "the requested authentication level needs user interaction",
                ))
            } else if consent {
                Some(AuthorizeError::new(
                    AuthorizeErrorCode::ConsentRequired,
                    "the user must consent",
                ))
            } else {
                None
            };
            let location = match (error, &session) {
                (Some(error), _) => self.error_location(redirect_uri, error, state)?,
                (None, Some(session)) => {
                    let mut tx = authn_store::begin(self.pool()).await?;
                    let location = self
                        .issue_code(&mut tx, client, session, &code_request)
                        .await?;
                    tx.commit().await?;
                    location
                }
                (None, None) => return Err(AuthError::internal("prompt=none without session")),
            };
            return Ok(AuthorizeOutcome {
                location,
                browser_cookie: None,
            });
        }
        if let Some(session) = &session
            && reasons.is_empty()
            && !consent
        {
            // Single sign-on: an existing session that already consented.
            let mut tx = authn_store::begin(self.pool()).await?;
            let location = self
                .issue_code(&mut tx, client, session, &code_request)
                .await?;
            tx.commit().await?;
            return Ok(AuthorizeOutcome {
                location,
                browser_cookie: None,
            });
        }
        // Hand-off to the operator's login / consent page.
        let binding = match browser.filter(|b| OpaqueToken::parse(b).is_ok()) {
            Some(existing) => existing,
            None => OpaqueToken::generate()
                .map_err(AuthError::from)?
                .expose()
                .to_owned(),
        };
        let interaction = InteractionRow {
            id: Uuid::now_v7(),
            client_id: client.id,
            browser_hash: TokenHash::digest(binding.as_bytes()).as_bytes().to_vec(),
            redirect_uri: redirect_uri.to_owned(),
            scopes: request.scopes.clone(),
            resources: request.resources.clone(),
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            prompt_login: request.prompt.login,
            prompt_consent: request.prompt.consent,
            max_age: request.max_age,
            acr_values: request.acr_values.clone(),
            created_at: now,
            expires_at: after(now, self.settings().authorization_request_ttl),
            completed_at: None,
        };
        store::insert_interaction(self.pool(), &interaction).await?;
        let base = self
            .settings()
            .interaction_url
            .as_ref()
            .ok_or_else(|| AuthError::internal("oidc_provider.interaction_url is not set"))?;
        let id = interaction.id.hyphenated().to_string();
        let location = redirect_with(base.as_str(), &[("interaction_id", id.as_str())])?;
        Ok(AuthorizeOutcome {
            location,
            browser_cookie: Some(binding),
        })
    }

    /// An open interaction bound to this browser, with its client.
    async fn bound_interaction(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
        browser: Option<&str>,
    ) -> Result<(InteractionRow, ClientRow), AuthError> {
        let now = self.now();
        let interaction = store::find_open_interaction(&mut *conn, id, now)
            .await?
            .ok_or_else(|| interaction_invalid("unknown"))?;
        let presented = browser.map(|b| TokenHash::digest(b.as_bytes()));
        let bound = TokenHash::from_slice(&interaction.browser_hash)
            .ok()
            .zip(presented)
            .is_some_and(|(stored, presented)| stored == presented);
        if !bound {
            return Err(interaction_invalid("browser_binding"));
        }
        let client = store::find_client_by_pk(&mut *conn, interaction.client_id)
            .await?
            .filter(|c| !c.disabled)
            .ok_or_else(|| interaction_invalid("client"))?;
        // The registration may have changed since the request.
        let still_allowed = redirect::matches(&client.redirect_uris, &interaction.redirect_uri)
            && interaction
                .scopes
                .iter()
                .all(|s| client.allowed_scopes.contains(s))
            && interaction
                .resources
                .iter()
                .all(|r| client.allowed_resources.contains(r));
        if !still_allowed {
            return Err(interaction_invalid("client_changed"));
        }
        Ok((interaction, client))
    }

    /// `GET /v1/oauth2/interactions/{interaction_id}`: what the login /
    /// consent page must show.
    pub async fn interaction(
        &self,
        id: Uuid,
        principal: Option<&Principal>,
        browser: Option<&str>,
    ) -> Result<InteractionView, AuthError> {
        let session = eligible(principal);
        let mut conn = self.pool().acquire().await?;
        let (interaction, client) = self.bound_interaction(&mut conn, id, browser).await?;
        let consent = match &session {
            Some(s) => {
                self.needs_consent(
                    &mut conn,
                    &client,
                    &interaction.redirect_uri,
                    s.user,
                    (&interaction.scopes, &interaction.resources),
                    interaction.prompt_consent,
                )
                .await?
            }
            None => !client.skip_consent || !auto_approvable(&client, &interaction.redirect_uri),
        };
        let reasons = login_reasons(
            interaction.prompt_login,
            interaction.max_age,
            &interaction.acr_values,
            interaction.created_at,
            session.as_ref(),
            self.now(),
        );
        Ok(InteractionView {
            interaction_id: interaction.id,
            client: ClientSummary {
                client_id: client.client_id.clone(),
                name: client.name.clone(),
                first_party: client.skip_consent,
            },
            scopes: interaction.scopes,
            resources: interaction.resources,
            expires_at: interaction.expires_at,
            authenticated: session.is_some(),
            login_required: !reasons.is_empty(),
            login_reasons: reasons.iter().map(|r| (*r).to_owned()).collect(),
            consent_required: consent,
            acr_values: interaction.acr_values,
        })
    }

    /// `POST /v1/oauth2/interactions/{interaction_id}/accept`: the signed-in
    /// user approves the request (consent is recorded unless the client is
    /// first-party). Single use. `401 step_up_required` while the session
    /// does not meet `prompt=login`, `max_age` or `acr_values`.
    pub async fn accept(
        &self,
        ctx: &RequestContext,
        id: Uuid,
        principal: &Principal,
        browser: Option<&str>,
    ) -> Result<RedirectTarget, AuthError> {
        principal.require_writable()?;
        let session = eligible(Some(principal)).ok_or_else(|| {
            AuthError::new(codes::common::UNAUTHENTICATED)
                .with_context("a browser session of the user is required")
        })?;
        let now = self.now();
        let mut tx = authn_store::begin(self.pool()).await?;
        let (interaction, client) = self.bound_interaction(&mut tx, id, browser).await?;
        let reasons = login_reasons(
            interaction.prompt_login,
            interaction.max_age,
            &interaction.acr_values,
            interaction.created_at,
            Some(&session),
            now,
        );
        if !reasons.is_empty() {
            return Err(AuthError::new(codes::common::STEP_UP_REQUIRED)
                .with_details(serde_json::json!({ "login_reasons": reasons })));
        }
        if !store::complete_interaction(&mut tx, interaction.id, now).await? {
            return Err(interaction_invalid("completed"));
        }
        let consent_recorded = !client.skip_consent;
        if consent_recorded {
            store::upsert_consent(
                &mut tx,
                session.user,
                client.id,
                (&interaction.scopes, &interaction.resources),
                now,
            )
            .await?;
        }
        let location = self
            .issue_code(
                &mut tx,
                &client,
                &session,
                &CodeRequest {
                    redirect_uri: &interaction.redirect_uri,
                    scopes: &interaction.scopes,
                    resources: &interaction.resources,
                    nonce: interaction.nonce.as_deref(),
                    code_challenge: &interaction.code_challenge,
                    state: interaction.state.as_deref(),
                },
            )
            .await?;
        if consent_recorded {
            let event = SecurityEvent::new(SecurityEventKind::OAuthConsentGranted, now)
                .with_context(ctx)
                .with_actor(Actor::User(session.user))
                .with_subject(session.user)
                .with_resource("oauth_client", &client.client_id)
                .with_meta("scopes", interaction.scopes.join(" "));
            self.deps().audit.record_in_tx(&mut tx, event).await?;
        }
        tx.commit().await?;
        Ok(RedirectTarget {
            redirect_to: location,
        })
    }

    /// `POST /v1/oauth2/interactions/{interaction_id}/deny`: the user
    /// refuses; the client gets `access_denied`. Single use.
    pub async fn deny(&self, id: Uuid, browser: Option<&str>) -> Result<RedirectTarget, AuthError> {
        let now = self.now();
        let mut tx = authn_store::begin(self.pool()).await?;
        let (interaction, _client) = self.bound_interaction(&mut tx, id, browser).await?;
        if !store::complete_interaction(&mut tx, interaction.id, now).await? {
            return Err(interaction_invalid("completed"));
        }
        tx.commit().await?;
        let location = self.error_location(
            &interaction.redirect_uri,
            AuthorizeError::new(
                AuthorizeErrorCode::AccessDenied,
                "the user denied the request",
            ),
            interaction.state.as_deref(),
        )?;
        Ok(RedirectTarget {
            redirect_to: location,
        })
    }

    /// The signed-in user's consents (OIDP-05).
    pub async fn list_consents(
        &self,
        principal: &Principal,
    ) -> Result<Vec<ConsentView>, AuthError> {
        let user = own_user(principal)?;
        let rows = store::list_consents(self.pool(), user).await?;
        Ok(rows
            .into_iter()
            .map(|r| ConsentView {
                client_id: r.client_id,
                client_name: r.client_name,
                scopes: r.scopes,
                granted_at: r.granted_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    /// Revokes the user's consent for a client and every grant (refresh
    /// tokens, access tokens) of that client for the user (OIDP-05).
    /// `404` when there is nothing to revoke.
    pub async fn revoke_consent(
        &self,
        ctx: &RequestContext,
        principal: &Principal,
        client_id: &str,
    ) -> Result<(), AuthError> {
        principal.require_writable()?;
        let user = own_user(principal)?;
        let client = store::find_client(self.pool(), client_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let now = self.now();
        let mut tx = authn_store::begin(self.pool()).await?;
        let had_consent = store::delete_consent(&mut tx, user, client.id).await?;
        let revoked =
            store::revoke_user_client_grants(&mut tx, user, client.id, "consent_revoked", now)
                .await?;
        if !had_consent && revoked == 0 {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        let event = SecurityEvent::new(SecurityEventKind::OAuthConsentRevoked, now)
            .with_context(ctx)
            .with_actor(Actor::User(user))
            .with_subject(user)
            .with_resource("oauth_client", &client.client_id)
            .with_meta("grants_revoked", revoked);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(())
    }
}

/// The user of a session principal (never an API key / service account).
fn own_user(principal: &Principal) -> Result<UserId, AuthError> {
    if principal.session_id().is_none() {
        return Err(AuthError::new(codes::common::FORBIDDEN));
    }
    principal.require_user()
}
