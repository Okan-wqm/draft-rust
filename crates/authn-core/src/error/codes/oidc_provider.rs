//! Error codes owned by `authn-oidc-provider` (OIDP-*).
//!
//! Only the `authn-oidc-provider` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! The OAuth protocol endpoints (`/v1/oauth2/token`, `/revoke`,
//! `/introspect`, `/userinfo` and the error redirects of `/authorize`)
//! answer with the standard OAuth error format of RFC 6749 §5.2 / RFC 6750
//! §3 (`{"error": "invalid_grant"}`), which relying-party libraries
//! expect; the codes below are for the project's own JSON APIs (client
//! registry, interaction / consent, the authorization requests that cannot
//! be redirected).

use http::StatusCode;

use crate::error::ErrorCode;

/// The authorization request names an unknown or disabled client, or a
/// `redirect_uri` that is not registered for it (OIDP-02). Never
/// redirected: the browser stays on the provider (no open redirect).
pub const INVALID_AUTHORIZATION_REQUEST: ErrorCode = ErrorCode::new(
    "invalid_authorization_request",
    StatusCode::BAD_REQUEST,
    "The application sent an invalid sign-in request.",
    "Uygulama geçersiz bir giriş isteği gönderdi.",
);

/// The pending authorization request (interaction) is unknown, expired,
/// already completed or belongs to another browser (OIDP-04).
/// Deliberately generic.
pub const OAUTH_INTERACTION_INVALID: ErrorCode = ErrorCode::new(
    "oauth_interaction_invalid",
    StatusCode::BAD_REQUEST,
    "The sign-in request has expired or is no longer valid. Please return to the application and start again.",
    "Giriş isteğinin süresi doldu veya artık geçerli değil. Lütfen uygulamaya dönüp yeniden başlayın.",
);

/// A client registration is invalid (redirect URI rules, scopes, grant
/// types, resources; OIDP-01, OIDP-02). `details.field` names the field.
pub const INVALID_CLIENT_METADATA: ErrorCode = ErrorCode::new(
    "invalid_client_metadata",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The client registration is invalid.",
    "İstemci kaydı geçersiz.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    INVALID_AUTHORIZATION_REQUEST,
    OAUTH_INTERACTION_INVALID,
    INVALID_CLIENT_METADATA,
];
