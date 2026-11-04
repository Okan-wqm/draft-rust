//! Error codes owned by `authn-oidc-client` (SOC-*).
//!
//! Only the `authn-oidc-client` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! Deliberately generic codes: every state / binding / provider mismatch of
//! a callback is `oauth_state_invalid`; every ID-token or code-exchange
//! failure is `oauth_token_invalid` (the log has the reason). Unknown
//! identities of other users answer the common `not_found`.

use http::StatusCode;

use crate::error::ErrorCode;

/// The provider in the path is not configured (SOC-01).
pub const OAUTH_PROVIDER_UNKNOWN: ErrorCode = ErrorCode::new(
    "oauth_provider_unknown",
    StatusCode::NOT_FOUND,
    "This sign-in provider is not available.",
    "Bu giriş sağlayıcısı kullanılamıyor.",
);

/// The authorization state is unknown, expired, already used, belongs to
/// another provider or to another browser (SOC-02). Deliberately generic.
pub const OAUTH_STATE_INVALID: ErrorCode = ErrorCode::new(
    "oauth_state_invalid",
    StatusCode::BAD_REQUEST,
    "The sign-in request has expired or is no longer valid. Please start again.",
    "Giriş isteğinin süresi doldu veya artık geçerli değil. Lütfen yeniden başlayın.",
);

/// The native nonce is unknown, expired or already used (SOC-04).
pub const OAUTH_NONCE_INVALID: ErrorCode = ErrorCode::new(
    "oauth_nonce_invalid",
    StatusCode::BAD_REQUEST,
    "The sign-in request has expired or is no longer valid. Please start again.",
    "Giriş isteğinin süresi doldu veya artık geçerli değil. Lütfen yeniden başlayın.",
);

/// The ID token or the authorization code did not verify (signature,
/// issuer, audience, expiry, nonce, PKCE…) (SOC-03). Deliberately generic.
pub const OAUTH_TOKEN_INVALID: ErrorCode = ErrorCode::new(
    "oauth_token_invalid",
    StatusCode::UNAUTHORIZED,
    "The sign-in with the provider could not be verified.",
    "Sağlayıcı ile giriş doğrulanamadı.",
);

/// The user cancelled or the provider refused the authorization.
pub const OAUTH_AUTHORIZATION_DENIED: ErrorCode = ErrorCode::new(
    "oauth_authorization_denied",
    StatusCode::BAD_REQUEST,
    "The sign-in with the provider was cancelled or refused.",
    "Sağlayıcı ile giriş iptal edildi veya reddedildi.",
);

/// The provider did not assert a verified e-mail address, so no account
/// can be created for this identity (SOC-05, ADR 0002). Returned before any
/// account lookup: the answer never depends on existing accounts.
pub const OAUTH_EMAIL_NOT_VERIFIED: ErrorCode = ErrorCode::new(
    "oauth_email_not_verified",
    StatusCode::FORBIDDEN,
    "Your provider did not confirm a verified e-mail address. Verify it with the provider or sign up with e-mail.",
    "Sağlayıcınız doğrulanmış bir e-posta adresi bildirmedi. Adresi sağlayıcıda doğrulayın veya e-posta ile kaydolun.",
);

/// An account with the provider-verified address exists and automatic
/// linking is off (SOC-05): sign in to it and link the provider.
pub const OAUTH_LINK_REQUIRED: ErrorCode = ErrorCode::new(
    "oauth_link_required",
    StatusCode::CONFLICT,
    "An account with this e-mail address already exists. Sign in to it and link this provider from your account settings.",
    "Bu e-posta adresiyle bir hesap zaten var. O hesaba giriş yapın ve bu sağlayıcıyı hesap ayarlarınızdan bağlayın.",
);

/// The provider has no native (mobile SDK) flow configured (SOC-04).
pub const OAUTH_NATIVE_NOT_SUPPORTED: ErrorCode = ErrorCode::new(
    "oauth_native_not_supported",
    StatusCode::BAD_REQUEST,
    "This provider cannot be used from the mobile app.",
    "Bu sağlayıcı mobil uygulamadan kullanılamaz.",
);

/// The external identity is already linked to another account (SOC-06).
pub const IDENTITY_ALREADY_LINKED: ErrorCode = ErrorCode::new(
    "identity_already_linked",
    StatusCode::CONFLICT,
    "This provider account is already linked to another account.",
    "Bu sağlayıcı hesabı başka bir hesaba bağlı.",
);

/// The account already has an identity of this provider (one per
/// provider, `identities_user_provider_key`).
pub const IDENTITY_PROVIDER_ALREADY_LINKED: ErrorCode = ErrorCode::new(
    "identity_provider_already_linked",
    StatusCode::CONFLICT,
    "An account of this provider is already linked. Remove it first.",
    "Bu sağlayıcıya ait bir hesap zaten bağlı. Önce onu kaldırın.",
);

/// Removing the identity would leave the account without any way to sign
/// in (SOC-06, PWD-11).
pub const IDENTITY_LAST_LOGIN_METHOD: ErrorCode = ErrorCode::new(
    "identity_last_login_method",
    StatusCode::CONFLICT,
    "This is your last way to sign in. Add a password or a passkey before removing it.",
    "Bu, giriş yapmanın son yolu. Kaldırmadan önce bir şifre veya passkey ekleyin.",
);

/// Identities can only be linked to active accounts with a verified
/// address (ADR 0002: never to `pending_verification` accounts).
pub const IDENTITY_LINK_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "identity_link_not_allowed",
    StatusCode::FORBIDDEN,
    "Verify your e-mail address before linking a sign-in provider.",
    "Bir giriş sağlayıcısı bağlamadan önce e-posta adresinizi doğrulayın.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    OAUTH_PROVIDER_UNKNOWN,
    OAUTH_STATE_INVALID,
    OAUTH_NONCE_INVALID,
    OAUTH_TOKEN_INVALID,
    OAUTH_AUTHORIZATION_DENIED,
    OAUTH_EMAIL_NOT_VERIFIED,
    OAUTH_LINK_REQUIRED,
    OAUTH_NATIVE_NOT_SUPPORTED,
    IDENTITY_ALREADY_LINKED,
    IDENTITY_PROVIDER_ALREADY_LINKED,
    IDENTITY_LAST_LOGIN_METHOD,
    IDENTITY_LINK_NOT_ALLOWED,
];
