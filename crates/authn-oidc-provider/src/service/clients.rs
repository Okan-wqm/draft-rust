//! Client registry (OIDP-01, OIDP-02): staff-managed registrations.

use authn_core::domain::Principal;
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::ports::{Actor, SecurityEvent, SecurityEventKind};
use authn_core::secret::SensitiveString;
use authn_crypto::token::{OpaqueToken, TokenHash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use super::OidcProviderService;
use crate::hooks::ClientAdminAccess;
use crate::redirect::{self, ApplicationType};
use crate::store::{self, ClientRow, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN};

/// Most clients listed at once.
const MAX_LIST: i64 = 500;
/// Most redirect URIs / resources per client.
const MAX_URIS: usize = 10;

/// Body of `POST /v1/admin/oauth2/clients`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientInput {
    /// Display name shown on the consent screen (1–100 characters).
    pub name: String,
    /// `confidential` (holds a secret; server-side applications) or
    /// `public` (browser or native application; PKCE only).
    pub client_type: String,
    /// `web` or `native` (RFC 8252 redirect rules).
    pub application_type: String,
    /// Exact redirect URIs (1–10).
    pub redirect_uris: Vec<String>,
    /// Scopes the client may request (`openid`, `profile`, `email`, custom).
    pub allowed_scopes: Vec<String>,
    /// `authorization_code` and optionally `refresh_token`. Default both.
    #[serde(default)]
    pub allowed_grant_types: Option<Vec<String>>,
    /// Resource indicators (RFC 8707) the client may request: absolute
    /// URIs of APIs, used as token audiences. Default none.
    #[serde(default)]
    pub allowed_resources: Vec<String>,
    /// First-party client: no consent screen. Default `false`.
    #[serde(default)]
    pub skip_consent: bool,
}

/// Body of `PATCH /v1/admin/oauth2/clients/{client_id}`: fields to change.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientPatch {
    /// New name.
    pub name: Option<String>,
    /// New redirect URIs.
    pub redirect_uris: Option<Vec<String>>,
    /// New allowed scopes.
    pub allowed_scopes: Option<Vec<String>>,
    /// New allowed grant types.
    pub allowed_grant_types: Option<Vec<String>>,
    /// New allowed resources.
    pub allowed_resources: Option<Vec<String>>,
    /// New first-party flag.
    pub skip_consent: Option<bool>,
    /// Disable (`true`) or enable the client. Disabling revokes every
    /// grant of the client.
    pub disabled: Option<bool>,
}

/// A client registration (never contains the secret).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientView {
    /// Public client identifier.
    pub client_id: String,
    /// Display name.
    pub name: String,
    /// `confidential` / `public`.
    pub client_type: String,
    /// `web` / `native`.
    pub application_type: String,
    /// Redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed scopes.
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types.
    pub allowed_grant_types: Vec<String>,
    /// Allowed resources.
    pub allowed_resources: Vec<String>,
    /// First-party client.
    pub skip_consent: bool,
    /// Disabled.
    pub disabled: bool,
    /// Last secret rotation.
    #[serde(with = "time::serde::rfc3339::option")]
    pub secret_rotated_at: Option<OffsetDateTime>,
    /// Creation.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Last change.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&ClientRow> for ClientView {
    fn from(row: &ClientRow) -> Self {
        Self {
            client_id: row.client_id.clone(),
            name: row.name.clone(),
            client_type: row.client_type.clone(),
            application_type: row.application_type.clone(),
            redirect_uris: row.redirect_uris.clone(),
            allowed_scopes: row.allowed_scopes.clone(),
            allowed_grant_types: row.allowed_grant_types.clone(),
            allowed_resources: row.allowed_resources.clone(),
            skip_consent: row.skip_consent,
            disabled: row.disabled,
            secret_rotated_at: row.secret_rotated_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// A newly created client (or rotated secret): the secret is shown once.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedClient {
    /// The registration.
    pub client: ClientView,
    /// The client secret (confidential clients only). Shown once, stored
    /// only as a hash.
    #[schema(value_type = Option<String>)]
    pub client_secret: Option<SensitiveString>,
}

fn invalid(field: &'static str, message: &'static str) -> AuthError {
    AuthError::new(codes::oidc_provider::INVALID_CLIENT_METADATA)
        .with_context(message)
        .with_details(serde_json::json!({ "field": field, "reason": message }))
}

fn new_client_id() -> Result<String, AuthError> {
    let bytes = authn_crypto::random::bytes::<16>().map_err(AuthError::from)?;
    Ok(format!("oc_{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Normalized, validated registration fields.
struct Fields {
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    allowed_grant_types: Vec<String>,
    allowed_resources: Vec<String>,
}

impl OidcProviderService {
    fn validate_fields(
        &self,
        app: ApplicationType,
        name: &str,
        redirect_uris: &[String],
        scopes: &[String],
        grant_types: &[String],
        resources: &[String],
    ) -> Result<Fields, AuthError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
            return Err(invalid(
                "name",
                "must be 1-100 characters without control characters",
            ));
        }
        if redirect_uris.is_empty() || redirect_uris.len() > MAX_URIS {
            return Err(invalid("redirect_uris", "1-10 redirect URIs are required"));
        }
        let mut uris: Vec<String> = Vec::new();
        for uri in redirect_uris {
            redirect::validate_for_registration(uri, app)
                .map_err(|reason| invalid("redirect_uris", reason))?;
            if !uris.contains(uri) {
                uris.push(uri.clone());
            }
        }
        if scopes.is_empty() {
            return Err(invalid("allowed_scopes", "at least one scope is required"));
        }
        let supported = &self.settings().supported_scopes;
        let mut allowed_scopes: Vec<String> = Vec::new();
        for scope in scopes {
            if !supported.contains(scope) {
                return Err(invalid("allowed_scopes", "unknown scope"));
            }
            if !allowed_scopes.contains(scope) {
                allowed_scopes.push(scope.clone());
            }
        }
        let mut grants: Vec<String> = Vec::new();
        for grant in grant_types {
            if grant != GRANT_AUTHORIZATION_CODE && grant != GRANT_REFRESH_TOKEN {
                return Err(invalid(
                    "allowed_grant_types",
                    "only authorization_code and refresh_token are supported",
                ));
            }
            if !grants.contains(grant) {
                grants.push(grant.clone());
            }
        }
        if !grants.iter().any(|g| g == GRANT_AUTHORIZATION_CODE) {
            return Err(invalid(
                "allowed_grant_types",
                "authorization_code is required",
            ));
        }
        if resources.len() > MAX_URIS {
            return Err(invalid("allowed_resources", "at most 10 resources"));
        }
        let mut allowed_resources: Vec<String> = Vec::new();
        for resource in resources {
            let ok = url::Url::parse(resource).is_ok_and(|u| {
                // Matched as exact strings (never followed): RFC 8707
                // values such as `https://api.example.com` (no trailing
                // slash) are kept as registered.
                matches!(u.scheme(), "https" | "http")
                    && u.host().is_some()
                    && u.fragment().is_none()
                    && u.username().is_empty()
                    && u.password().is_none()
            }) && resource.len() <= 512
                && resource.bytes().all(|b| b.is_ascii_graphic());
            if !ok {
                return Err(invalid(
                    "allowed_resources",
                    "must be absolute http(s) URIs without fragment or user info",
                ));
            }
            // Token-type confusion (OIDP-08): a provider token must never
            // carry an audience of the native tokens or of `userinfo`.
            if self.settings().is_reserved_audience(resource)
                || *resource == self.settings().userinfo_url()
            {
                return Err(invalid(
                    "allowed_resources",
                    "this audience is reserved for the server's own tokens",
                ));
            }
            if !allowed_resources.contains(resource) {
                allowed_resources.push(resource.clone());
            }
        }
        Ok(Fields {
            name: name.to_owned(),
            redirect_uris: uris,
            allowed_scopes,
            allowed_grant_types: grants,
            allowed_resources,
        })
    }

    async fn authorize_admin(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        access: ClientAdminAccess,
    ) -> Result<(), AuthError> {
        self.deps()
            .client_admin
            .authorize(principal, ctx, access)
            .await
    }

    fn admin_event(
        &self,
        kind: SecurityEventKind,
        principal: &Principal,
        ctx: &RequestContext,
        client_id: &str,
    ) -> SecurityEvent {
        let mut event = SecurityEvent::new(kind, self.now())
            .with_context(ctx)
            .with_resource("oauth_client", client_id);
        if let Some(user) = principal.user_id() {
            event = event.with_actor(Actor::User(user));
        }
        event
    }

    /// Registers a client (OIDP-01). Confidential clients get a 256-bit
    /// secret, returned once and stored as SHA-256.
    pub async fn create_client(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        input: ClientInput,
    ) -> Result<CreatedClient, AuthError> {
        self.authorize_admin(principal, ctx, ClientAdminAccess::Manage)
            .await?;
        self.create_client_unchecked(ctx, Some(principal), input)
            .await
    }

    /// [`Self::create_client`] without the staff check: for the server's
    /// own provisioning (CLI, tests). Never expose it over HTTP.
    pub async fn create_client_unchecked(
        &self,
        ctx: &RequestContext,
        principal: Option<&Principal>,
        input: ClientInput,
    ) -> Result<CreatedClient, AuthError> {
        let app = ApplicationType::parse(&input.application_type)
            .ok_or_else(|| invalid("application_type", "must be web or native"))?;
        let confidential = match input.client_type.as_str() {
            "confidential" => true,
            "public" => false,
            _ => return Err(invalid("client_type", "must be confidential or public")),
        };
        let grants = input.allowed_grant_types.clone().unwrap_or_else(|| {
            vec![
                GRANT_AUTHORIZATION_CODE.to_owned(),
                GRANT_REFRESH_TOKEN.to_owned(),
            ]
        });
        let fields = self.validate_fields(
            app,
            &input.name,
            &input.redirect_uris,
            &input.allowed_scopes,
            &grants,
            &input.allowed_resources,
        )?;
        let now = self.now();
        let secret = if confidential {
            Some(OpaqueToken::generate().map_err(AuthError::from)?)
        } else {
            None
        };
        let row = ClientRow {
            id: Uuid::now_v7(),
            client_id: new_client_id()?,
            name: fields.name,
            client_type: if confidential {
                "confidential"
            } else {
                "public"
            }
            .to_owned(),
            application_type: app.as_str().to_owned(),
            secret_hash: secret.as_ref().map(|s| s.hash().as_bytes().to_vec()),
            secret_rotated_at: secret.as_ref().map(|_| now),
            redirect_uris: fields.redirect_uris,
            allowed_scopes: fields.allowed_scopes,
            allowed_grant_types: fields.allowed_grant_types,
            allowed_resources: fields.allowed_resources,
            skip_consent: input.skip_consent,
            disabled: false,
            created_at: now,
            updated_at: now,
        };
        let mut tx = authn_store::begin(self.pool()).await?;
        store::insert_client(&mut tx, &row).await?;
        let mut event = SecurityEvent::new(SecurityEventKind::OAuthClientCreated, now)
            .with_context(ctx)
            .with_resource("oauth_client", &row.client_id)
            .with_meta("client_type", row.client_type.clone())
            .with_meta("skip_consent", row.skip_consent);
        event = match principal.and_then(Principal::user_id) {
            Some(user) => event.with_actor(Actor::User(user)),
            None => event.with_actor(Actor::System),
        };
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(CreatedClient {
            client: ClientView::from(&row),
            client_secret: secret.map(OpaqueToken::into_sensitive),
        })
    }

    /// Lists the registrations (newest first, at most 500).
    pub async fn list_clients(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
    ) -> Result<Vec<ClientView>, AuthError> {
        self.authorize_admin(principal, ctx, ClientAdminAccess::Read)
            .await?;
        let rows = store::list_clients(self.pool(), MAX_LIST).await?;
        Ok(rows.iter().map(ClientView::from).collect())
    }

    async fn client_or_404(&self, client_id: &str) -> Result<ClientRow, AuthError> {
        store::find_client(self.pool(), client_id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))
    }

    /// One registration.
    pub async fn get_client(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        client_id: &str,
    ) -> Result<ClientView, AuthError> {
        self.authorize_admin(principal, ctx, ClientAdminAccess::Read)
            .await?;
        Ok(ClientView::from(&self.client_or_404(client_id).await?))
    }

    /// Changes a registration. Disabling the client or narrowing what it
    /// may do (redirect URIs, scopes, grant types, resources) revokes
    /// every grant of the client in the same transaction.
    pub async fn update_client(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        client_id: &str,
        patch: ClientPatch,
    ) -> Result<ClientView, AuthError> {
        self.authorize_admin(principal, ctx, ClientAdminAccess::Manage)
            .await?;
        let mut tx = authn_store::begin(self.pool()).await?;
        let current: ClientRow = sqlx::query_as::<_, ClientRow>(
            "SELECT id, client_id, name, client_type, application_type, secret_hash, \
             secret_rotated_at, redirect_uris, allowed_scopes, allowed_grant_types, \
             allowed_resources, skip_consent, disabled, created_at, updated_at \
             FROM oidc_clients WHERE client_id = $1 FOR UPDATE",
        )
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        let app = ApplicationType::parse(&current.application_type)
            .ok_or_else(|| AuthError::internal("stored application_type is invalid"))?;
        let fields = self.validate_fields(
            app,
            patch.name.as_deref().unwrap_or(&current.name),
            patch
                .redirect_uris
                .as_deref()
                .unwrap_or(&current.redirect_uris),
            patch
                .allowed_scopes
                .as_deref()
                .unwrap_or(&current.allowed_scopes),
            patch
                .allowed_grant_types
                .as_deref()
                .unwrap_or(&current.allowed_grant_types),
            patch
                .allowed_resources
                .as_deref()
                .unwrap_or(&current.allowed_resources),
        )?;
        let narrows = |old: &[String], new: &[String]| old.iter().any(|v| !new.contains(v));
        let disabled = patch.disabled.unwrap_or(current.disabled);
        let revoke = (disabled && !current.disabled)
            || narrows(&current.redirect_uris, &fields.redirect_uris)
            || narrows(&current.allowed_scopes, &fields.allowed_scopes)
            || narrows(&current.allowed_grant_types, &fields.allowed_grant_types)
            || narrows(&current.allowed_resources, &fields.allowed_resources);
        let now = self.now();
        let updated = ClientRow {
            name: fields.name,
            redirect_uris: fields.redirect_uris,
            allowed_scopes: fields.allowed_scopes,
            allowed_grant_types: fields.allowed_grant_types,
            allowed_resources: fields.allowed_resources,
            skip_consent: patch.skip_consent.unwrap_or(current.skip_consent),
            disabled,
            updated_at: now,
            ..current.clone()
        };
        store::update_client(&mut tx, &updated).await?;
        let revoked = if revoke {
            store::revoke_client_grants(&mut tx, current.id, "client_changed", now).await?
        } else {
            0
        };
        let event = self
            .admin_event(
                SecurityEventKind::OAuthClientUpdated,
                principal,
                ctx,
                client_id,
            )
            .with_meta("disabled", disabled)
            .with_meta("grants_revoked", revoked);
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(ClientView::from(&updated))
    }

    /// Replaces the secret of a confidential client; the old secret stops
    /// working at once. Returns the new secret (shown once).
    pub async fn rotate_client_secret(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        client_id: &str,
    ) -> Result<CreatedClient, AuthError> {
        self.authorize_admin(principal, ctx, ClientAdminAccess::Manage)
            .await?;
        let current = self.client_or_404(client_id).await?;
        if !current.is_confidential() {
            return Err(invalid("client_type", "public clients have no secret"));
        }
        let secret = OpaqueToken::generate().map_err(AuthError::from)?;
        let now = self.now();
        let mut tx = authn_store::begin(self.pool()).await?;
        if !store::set_client_secret(&mut tx, current.id, secret.hash().as_bytes(), now).await? {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        let event = self.admin_event(
            SecurityEventKind::OAuthClientSecretRotated,
            principal,
            ctx,
            client_id,
        );
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        let row = store::find_client_by_pk(self.pool(), current.id)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        Ok(CreatedClient {
            client: ClientView::from(&row),
            client_secret: Some(secret.into_sensitive()),
        })
    }

    /// Deletes a client; its grants, codes, tokens and consents go with it.
    pub async fn delete_client(
        &self,
        principal: &Principal,
        ctx: &RequestContext,
        client_id: &str,
    ) -> Result<(), AuthError> {
        self.authorize_admin(principal, ctx, ClientAdminAccess::Manage)
            .await?;
        let current = self.client_or_404(client_id).await?;
        let mut tx = authn_store::begin(self.pool()).await?;
        if !store::delete_client(&mut tx, current.id).await? {
            return Err(AuthError::new(codes::common::NOT_FOUND));
        }
        let event = self.admin_event(
            SecurityEventKind::OAuthClientDeleted,
            principal,
            ctx,
            client_id,
        );
        self.deps().audit.record_in_tx(&mut tx, event).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Checks a presented client secret against the registration in
    /// constant time. A public client never authenticates with a secret.
    pub(crate) fn secret_matches(client: &ClientRow, secret: &str) -> bool {
        let Some(stored) = client
            .secret_hash
            .as_deref()
            .and_then(|h| TokenHash::from_slice(h).ok())
        else {
            return false;
        };
        TokenHash::digest(secret.as_bytes()) == stored
    }
}
