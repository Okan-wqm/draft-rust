//! Error codes owned by `authn-account` (ACC-*).
//!
//! Only the `authn-account` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! Enumeration safety (ACC-02): none of these codes is ever produced on an
//! unauthenticated path in a way that depends on whether an account exists.
//! Registration, verification resend and the code / link flows answer
//! unknown accounts exactly like wrong input (`invalid_code`,
//! `invalid_or_expired_token`, `202`). The account-status codes
//! (`account_locked`, `account_suspended`, …) are meant for the login flow
//! *after* a correct password (SES-01).

use http::StatusCode;

use crate::error::ErrorCode;

/// The e-mail address is syntactically invalid (ACC-03). Depends only on the
/// submitted text, never on an account.
pub const INVALID_EMAIL: ErrorCode = ErrorCode::new(
    "invalid_email",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The e-mail address is invalid.",
    "E-posta adresi geçersiz.",
);

/// The address belongs to a blocked (disposable) e-mail domain (ACC-12).
pub const EMAIL_DOMAIN_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "email_domain_not_allowed",
    StatusCode::UNPROCESSABLE_ENTITY,
    "E-mail addresses of this domain cannot be used. Please use another address.",
    "Bu alan adına ait e-posta adresleri kullanılamaz. Lütfen başka bir adres kullanın.",
);

/// The display name is empty, too long or contains invisible, mixed-script
/// or confusable characters (ACC-03, ACC-08).
pub const INVALID_DISPLAY_NAME: ErrorCode = ErrorCode::new(
    "invalid_display_name",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The display name is not allowed. Use letters of a single script, spaces and simple punctuation.",
    "Görünen ad kabul edilmiyor. Tek bir alfabeden harfler, boşluk ve basit noktalama işaretleri kullanın.",
);

/// The time zone is not an IANA time zone name (ACC-08).
pub const INVALID_TIME_ZONE: ErrorCode = ErrorCode::new(
    "invalid_time_zone",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The time zone is not a valid IANA time zone name (for example Europe/Istanbul).",
    "Saat dilimi geçerli bir IANA saat dilimi adı değil (örneğin Europe/Istanbul).",
);

/// E-mail change to the address the account already uses (ACC-07).
pub const EMAIL_UNCHANGED: ErrorCode = ErrorCode::new(
    "email_unchanged",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The new e-mail address is the same as the current one.",
    "Yeni e-posta adresi mevcut adresle aynı.",
);

/// The signed-in user's address is already verified (ACC-04). Only used on
/// authenticated endpoints.
pub const EMAIL_ALREADY_VERIFIED: ErrorCode = ErrorCode::new(
    "email_already_verified",
    StatusCode::CONFLICT,
    "Your e-mail address is already verified.",
    "E-posta adresiniz zaten doğrulanmış.",
);

/// The account must verify its e-mail address before signing in or using
/// the operation (ACC-05 `block` policy).
pub const EMAIL_VERIFICATION_REQUIRED: ErrorCode = ErrorCode::new(
    "email_verification_required",
    StatusCode::FORBIDDEN,
    "Please verify your e-mail address first. Check your inbox for the verification message.",
    "Lütfen önce e-posta adresinizi doğrulayın. Doğrulama iletisi için gelen kutunuzu kontrol edin.",
);

/// The account is temporarily locked (ACC-06 `locked`). Rendered with
/// `Retry-After` when the end of the lock is known.
pub const ACCOUNT_LOCKED: ErrorCode = ErrorCode::new(
    "account_locked",
    StatusCode::FORBIDDEN,
    "This account is temporarily locked. Please try again later.",
    "Bu hesap geçici olarak kilitlendi. Lütfen daha sonra tekrar deneyin.",
);

/// The account was suspended by an administrator (ACC-06 `suspended`).
pub const ACCOUNT_SUSPENDED: ErrorCode = ErrorCode::new(
    "account_suspended",
    StatusCode::FORBIDDEN,
    "This account has been suspended. Please contact support.",
    "Bu hesap askıya alındı. Lütfen destek ekibiyle iletişime geçin.",
);

/// The account is disabled or deleted (ACC-06 `disabled`, `deleted`).
pub const ACCOUNT_DISABLED: ErrorCode = ErrorCode::new(
    "account_disabled",
    StatusCode::FORBIDDEN,
    "This account is disabled.",
    "Bu hesap devre dışı.",
);

/// The requested account status change is not allowed by the lifecycle
/// state machine (ACC-06).
pub const ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "account_status_transition_not_allowed",
    StatusCode::CONFLICT,
    "This change is not possible in the account's current state.",
    "Bu değişiklik hesabın mevcut durumunda yapılamaz.",
);

/// The user is the last owner of at least one organization and must
/// transfer ownership before deleting the account (ACC-09). The envelope
/// `details` list the organization ids (the caller's own data).
pub const ACCOUNT_DELETION_BLOCKED_LAST_OWNER: ErrorCode = ErrorCode::new(
    "account_deletion_blocked_last_owner",
    StatusCode::CONFLICT,
    "You are the last owner of an organization. Transfer the ownership before deleting your account.",
    "Bir organizasyonun son sahibisiniz. Hesabınızı silmeden önce sahipliği devredin.",
);

/// Cancelling a deletion that is not scheduled (ACC-09, authenticated).
pub const ACCOUNT_DELETION_NOT_SCHEDULED: ErrorCode = ErrorCode::new(
    "account_deletion_not_scheduled",
    StatusCode::CONFLICT,
    "No account deletion is scheduled.",
    "Planlanmış bir hesap silme işlemi yok.",
);

/// Registration without accepting the current terms / privacy policy when
/// the deployment requires it (ACC-11).
pub const TERMS_ACCEPTANCE_REQUIRED: ErrorCode = ErrorCode::new(
    "terms_acceptance_required",
    StatusCode::UNPROCESSABLE_ENTITY,
    "Please accept the current terms of service and privacy policy.",
    "Lütfen güncel kullanım şartlarını ve gizlilik politikasını kabul edin.",
);

/// The accepted terms version is unknown or not the current one (ACC-11).
pub const TERMS_VERSION_NOT_CURRENT: ErrorCode = ErrorCode::new(
    "terms_version_not_current",
    StatusCode::CONFLICT,
    "This version of the document is not the current one. Please reload and accept the current version.",
    "Belgenin bu sürümü güncel değil. Lütfen sayfayı yenileyip güncel sürümü kabul edin.",
);

/// Reverting an e-mail change is impossible because the previous address is
/// now used by another account (ACC-07; prevented by address reservations,
/// only reachable with legacy data).
pub const EMAIL_CHANGE_REVERT_CONFLICT: ErrorCode = ErrorCode::new(
    "email_change_revert_conflict",
    StatusCode::CONFLICT,
    "The previous e-mail address can no longer be restored. Please contact support.",
    "Önceki e-posta adresi artık geri yüklenemiyor. Lütfen destek ekibiyle iletişime geçin.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    INVALID_EMAIL,
    EMAIL_DOMAIN_NOT_ALLOWED,
    INVALID_DISPLAY_NAME,
    INVALID_TIME_ZONE,
    EMAIL_UNCHANGED,
    EMAIL_ALREADY_VERIFIED,
    EMAIL_VERIFICATION_REQUIRED,
    ACCOUNT_LOCKED,
    ACCOUNT_SUSPENDED,
    ACCOUNT_DISABLED,
    ACCOUNT_STATUS_TRANSITION_NOT_ALLOWED,
    ACCOUNT_DELETION_BLOCKED_LAST_OWNER,
    ACCOUNT_DELETION_NOT_SCHEDULED,
    TERMS_ACCEPTANCE_REQUIRED,
    TERMS_VERSION_NOT_CURRENT,
    EMAIL_CHANGE_REVERT_CONFLICT,
];
