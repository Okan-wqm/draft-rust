//! Error codes owned by `authn-org` (ORG-*).
//!
//! Only the `authn-org` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.
//!
//! Common codes used by authn-org: `not_found` for unknown resources and for
//! every resource of *another* organization (ORG-10: tenants are invisible),
//! `forbidden` for members lacking a permission, `step_up_required`,
//! `rate_limited`, `validation_failed`, `invalid_or_expired_token`
//! (invitation and ownership-transfer tokens: unknown, used, revoked and
//! expired are indistinguishable) and `unauthenticated` (API keys: every
//! failure looks the same).

use http::StatusCode;

use crate::error::ErrorCode;

/// The organization slug is already used (ORG-01).
pub const ORG_SLUG_TAKEN: ErrorCode = ErrorCode::new(
    "org_slug_taken",
    StatusCode::CONFLICT,
    "This organization address is already taken.",
    "Bu organizasyon adresi zaten kullanılıyor.",
);

/// The change would leave the organization without an active owner
/// (ORG-02).
pub const ORG_LAST_OWNER: ErrorCode = ErrorCode::new(
    "org_last_owner",
    StatusCode::CONFLICT,
    "An organization must keep at least one owner. Make another member an owner first.",
    "Bir organizasyonun en az bir sahibi olmalıdır. Önce başka bir üyeyi sahip yapın.",
);

/// Privilege escalation guard (ORG-04): the caller tried to grant, edit or
/// act on permissions it does not hold itself, or to grant the `owner` role
/// without being an owner.
pub const ORG_ROLE_ESCALATION: ErrorCode = ErrorCode::new(
    "org_role_escalation",
    StatusCode::FORBIDDEN,
    "You cannot grant or manage permissions that you do not have yourself.",
    "Kendinizde olmayan yetkileri veremez veya yönetemezsiniz.",
);

/// The user is already a member of the organization.
pub const ORG_ALREADY_MEMBER: ErrorCode = ErrorCode::new(
    "org_already_member",
    StatusCode::CONFLICT,
    "This user is already a member of the organization.",
    "Bu kullanıcı zaten organizasyonun üyesi.",
);

/// An invitation for this address is already pending (ORG-05).
pub const ORG_INVITATION_PENDING: ErrorCode = ErrorCode::new(
    "org_invitation_pending",
    StatusCode::CONFLICT,
    "An invitation for this address is already pending. Resend it instead.",
    "Bu adres için bekleyen bir davet zaten var. Bunun yerine daveti yeniden gönderin.",
);

/// The accepting account's e-mail address differs from the invited address
/// (ORG-05). The message never reveals the invited address.
pub const ORG_INVITATION_EMAIL_MISMATCH: ErrorCode = ErrorCode::new(
    "org_invitation_email_mismatch",
    StatusCode::FORBIDDEN,
    "This invitation was sent to a different e-mail address. Sign in with the invited account.",
    "Bu davet farklı bir e-posta adresine gönderildi. Davet edilen hesapla giriş yapın.",
);

/// The caller's e-mail address must be verified first (accepting an
/// invitation, creating an organization).
pub const ORG_EMAIL_VERIFICATION_REQUIRED: ErrorCode = ErrorCode::new(
    "org_email_verification_required",
    StatusCode::FORBIDDEN,
    "Verify your e-mail address first.",
    "Önce e-posta adresinizi doğrulayın.",
);

/// A custom role with this key already exists in the organization.
pub const ORG_ROLE_KEY_TAKEN: ErrorCode = ErrorCode::new(
    "org_role_key_taken",
    StatusCode::CONFLICT,
    "A role with this key already exists.",
    "Bu anahtara sahip bir rol zaten var.",
);

/// Built-in roles cannot be changed or deleted (ORG-03).
pub const ORG_BUILTIN_ROLE_IMMUTABLE: ErrorCode = ErrorCode::new(
    "org_builtin_role_immutable",
    StatusCode::CONFLICT,
    "Built-in roles cannot be changed.",
    "Yerleşik roller değiştirilemez.",
);

/// The role is still assigned to members, invitations or service accounts.
pub const ORG_ROLE_IN_USE: ErrorCode = ErrorCode::new(
    "org_role_in_use",
    StatusCode::CONFLICT,
    "The role is still assigned. Reassign its members, invitations and service accounts first.",
    "Rol hâlâ atanmış durumda. Önce üyelerini, davetlerini ve servis hesaplarını başka role taşıyın.",
);

/// A per-organization resource limit (custom roles, domains, service
/// accounts, API keys, pending invitations) is reached.
pub const ORG_LIMIT_REACHED: ErrorCode = ErrorCode::new(
    "org_limit_reached",
    StatusCode::CONFLICT,
    "The limit for this kind of resource is reached.",
    "Bu kaynak türü için sınıra ulaşıldı.",
);

/// The domain is already added to this organization (ORG-06).
pub const ORG_DOMAIN_EXISTS: ErrorCode = ErrorCode::new(
    "org_domain_exists",
    StatusCode::CONFLICT,
    "This domain is already added to the organization.",
    "Bu alan adı organizasyona zaten eklenmiş.",
);

/// Another organization has already verified this domain (ORG-06).
pub const ORG_DOMAIN_CLAIMED: ErrorCode = ErrorCode::new(
    "org_domain_claimed",
    StatusCode::CONFLICT,
    "This domain is already verified by another organization.",
    "Bu alan adı başka bir organizasyon tarafından zaten doğrulanmış.",
);

/// The DNS TXT record with the verification value was not found (ORG-06).
pub const ORG_DOMAIN_VERIFICATION_FAILED: ErrorCode = ErrorCode::new(
    "org_domain_verification_failed",
    StatusCode::UNPROCESSABLE_ENTITY,
    "The verification TXT record was not found. DNS changes can take a while to propagate.",
    "Doğrulama TXT kaydı bulunamadı. DNS değişikliklerinin yayılması zaman alabilir.",
);

/// The operation needs a verified domain (auto-join, ORG-06).
pub const ORG_DOMAIN_NOT_VERIFIED: ErrorCode = ErrorCode::new(
    "org_domain_not_verified",
    StatusCode::CONFLICT,
    "Verify the domain first.",
    "Önce alan adını doğrulayın.",
);

/// The new policy would lock the caller out (IP allow-list without the
/// caller's address, MFA requirement the current session does not meet)
/// (ORG-07).
pub const ORG_POLICY_LOCKOUT: ErrorCode = ErrorCode::new(
    "org_policy_lockout",
    StatusCode::UNPROCESSABLE_ENTITY,
    "This policy would lock you out of the organization. Adjust it or sign in in a way that satisfies it first.",
    "Bu politika sizi organizasyonun dışında bırakır. Politikayı düzenleyin veya önce ona uygun şekilde giriş yapın.",
);

/// The organization's IP allow-list does not contain the client address
/// (ORG-07).
pub const ORG_POLICY_IP_DENIED: ErrorCode = ErrorCode::new(
    "org_policy_ip_denied",
    StatusCode::FORBIDDEN,
    "Access to this organization is not allowed from your network.",
    "Bu organizasyona ağınızdan erişime izin verilmiyor.",
);

/// The organization requires (phishing-resistant) multi-factor
/// authentication and the session does not have it (ORG-07).
pub const ORG_POLICY_MFA_REQUIRED: ErrorCode = ErrorCode::new(
    "org_policy_mfa_required",
    StatusCode::FORBIDDEN,
    "This organization requires a stronger sign-in. Verify with your second factor or passkey.",
    "Bu organizasyon daha güçlü bir giriş gerektiriyor. İkinci faktörünüz veya passkey ile doğrulayın.",
);

/// The organization is scheduled for deletion; only reading and cancelling
/// the deletion are allowed (ORG-12).
pub const ORG_PENDING_DELETION: ErrorCode = ErrorCode::new(
    "org_pending_deletion",
    StatusCode::CONFLICT,
    "The organization is scheduled for deletion.",
    "Organizasyon silinmek üzere planlandı.",
);

/// The organization is not scheduled for deletion (cancel).
pub const ORG_DELETION_NOT_SCHEDULED: ErrorCode = ErrorCode::new(
    "org_deletion_not_scheduled",
    StatusCode::CONFLICT,
    "The organization is not scheduled for deletion.",
    "Organizasyon silinmek üzere planlanmamış.",
);

/// The organization is suspended by the platform.
pub const ORG_SUSPENDED: ErrorCode = ErrorCode::new(
    "org_suspended",
    StatusCode::FORBIDDEN,
    "The organization is suspended.",
    "Organizasyon askıya alınmış.",
);

/// Only an owner of the organization may do this (ORG-11, ORG-12).
pub const ORG_OWNER_REQUIRED: ErrorCode = ErrorCode::new(
    "org_owner_required",
    StatusCode::FORBIDDEN,
    "Only an owner of the organization can do this.",
    "Bunu yalnızca organizasyonun sahibi yapabilir.",
);

/// The ownership transfer target must be another active member (ORG-11).
pub const ORG_TRANSFER_TARGET_INVALID: ErrorCode = ErrorCode::new(
    "org_transfer_target_invalid",
    StatusCode::UNPROCESSABLE_ENTITY,
    "Ownership can only be transferred to another active member.",
    "Sahiplik yalnızca başka bir aktif üyeye devredilebilir.",
);

/// The API key expiry is missing, in the past or beyond the maximum
/// lifetime (ORG-08).
pub const API_KEY_EXPIRY_INVALID: ErrorCode = ErrorCode::new(
    "api_key_expiry_invalid",
    StatusCode::UNPROCESSABLE_ENTITY,
    "Choose an expiry date in the future and within the allowed maximum lifetime.",
    "Gelecekte ve izin verilen en uzun süre içinde bir son kullanma tarihi seçin.",
);

/// Unknown, duplicate, owner-only or not grantable API key scope (ORG-08).
pub const API_KEY_SCOPE_INVALID: ErrorCode = ErrorCode::new(
    "api_key_scope_invalid",
    StatusCode::UNPROCESSABLE_ENTITY,
    "One or more scopes are invalid or cannot be granted to this key.",
    "Bir veya daha fazla kapsam geçersiz ya da bu anahtara verilemez.",
);

/// The API key is revoked, expired or already rotated (ORG-08).
pub const API_KEY_INACTIVE: ErrorCode = ErrorCode::new(
    "api_key_inactive",
    StatusCode::CONFLICT,
    "The API key is no longer active.",
    "API anahtarı artık etkin değil.",
);

/// The service account is disabled (ORG-09).
pub const SERVICE_ACCOUNT_DISABLED: ErrorCode = ErrorCode::new(
    "service_account_disabled",
    StatusCode::CONFLICT,
    "The service account is disabled.",
    "Servis hesabı devre dışı.",
);

/// A service account with this name already exists in the organization.
pub const SERVICE_ACCOUNT_NAME_TAKEN: ErrorCode = ErrorCode::new(
    "service_account_name_taken",
    StatusCode::CONFLICT,
    "A service account with this name already exists.",
    "Bu ada sahip bir servis hesabı zaten var.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    ORG_SLUG_TAKEN,
    ORG_LAST_OWNER,
    ORG_ROLE_ESCALATION,
    ORG_ALREADY_MEMBER,
    ORG_INVITATION_PENDING,
    ORG_INVITATION_EMAIL_MISMATCH,
    ORG_EMAIL_VERIFICATION_REQUIRED,
    ORG_ROLE_KEY_TAKEN,
    ORG_BUILTIN_ROLE_IMMUTABLE,
    ORG_ROLE_IN_USE,
    ORG_LIMIT_REACHED,
    ORG_DOMAIN_EXISTS,
    ORG_DOMAIN_CLAIMED,
    ORG_DOMAIN_VERIFICATION_FAILED,
    ORG_DOMAIN_NOT_VERIFIED,
    ORG_POLICY_LOCKOUT,
    ORG_POLICY_IP_DENIED,
    ORG_POLICY_MFA_REQUIRED,
    ORG_PENDING_DELETION,
    ORG_DELETION_NOT_SCHEDULED,
    ORG_SUSPENDED,
    ORG_OWNER_REQUIRED,
    ORG_TRANSFER_TARGET_INVALID,
    API_KEY_EXPIRY_INVALID,
    API_KEY_SCOPE_INVALID,
    API_KEY_INACTIVE,
    SERVICE_ACCOUNT_DISABLED,
    SERVICE_ACCOUNT_NAME_TAKEN,
];
