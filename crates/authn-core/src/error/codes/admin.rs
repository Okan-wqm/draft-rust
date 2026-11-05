//! Error codes owned by `authn-admin` (ADM-*).
//!
//! Only the `authn-admin` agent edits this file. Declare codes as
//! `pub const NAME: ErrorCode = ErrorCode::new("snake_case", StatusCode::…, "English", "Türkçe");`
//! and append every new constant to [`ALL`]. Never rename or repurpose a
//! released code. Conventions: `docs/architecture/contracts.md`.

use http::StatusCode;

use crate::error::ErrorCode;

/// A platform admin's session was not established with phishing-resistant
/// MFA (a passkey with user verification, `amr` `hwk`/`swk` + `mfa`;
/// ADM-01). The admin must sign in again with a passkey.
pub const PHISHING_RESISTANT_MFA_REQUIRED: ErrorCode = ErrorCode::new(
    "admin_phishing_resistant_mfa_required",
    StatusCode::FORBIDDEN,
    "Sign in with a passkey to use the admin console.",
    "Yönetim konsolunu kullanmak için passkey ile giriş yapın.",
);

/// The mandatory justification of an admin action is missing, too long or
/// contains control / invisible formatting characters (ADM-03, ADM-08).
pub const REASON_REQUIRED: ErrorCode = ErrorCode::new(
    "admin_reason_required",
    StatusCode::UNPROCESSABLE_ENTITY,
    "A justification of 1 to 1000 printable characters is required for this action.",
    "Bu işlem için 1 ile 1000 arasında yazdırılabilir karakterden oluşan bir gerekçe gereklidir.",
);

/// The action may not be applied to this account through the admin API:
/// the caller's own account, or a takeover-enabling action on another
/// platform admin or a break-glass account (ADM-03, ADM-04, ADM-05).
pub const TARGET_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "admin_target_not_allowed",
    StatusCode::FORBIDDEN,
    "This action is not allowed on this account.",
    "Bu işlem bu hesap üzerinde yapılamaz.",
);

/// An emergency operation (ADM-06) was not confirmed by repeating its name
/// in the `confirm` field.
pub const CONFIRMATION_REQUIRED: ErrorCode = ErrorCode::new(
    "admin_confirmation_required",
    StatusCode::UNPROCESSABLE_ENTITY,
    "Confirm the emergency operation by repeating its name in the confirm field.",
    "Acil durum işlemini, adını onay alanına yazarak onaylayın.",
);

/// A critical operation (emergency operation or action on another
/// platform admin) needs the approval of a second platform admin (K-66):
/// request one (`POST /v1/admin/approvals`) and retry with its
/// `approval_id` once approved.
pub const APPROVAL_REQUIRED: ErrorCode = ErrorCode::new(
    "admin_approval_required",
    StatusCode::FORBIDDEN,
    "This operation needs the approval of a second platform admin.",
    "Bu işlem ikinci bir platform yöneticisinin onayını gerektirir.",
);

/// The given four-eyes approval cannot be used for this operation: unknown,
/// requested by someone else, not approved, denied, expired, already used,
/// or approved for other parameters (K-66). Deliberately generic.
pub const APPROVAL_INVALID: ErrorCode = ErrorCode::new(
    "admin_approval_invalid",
    StatusCode::FORBIDDEN,
    "The approval is not valid for this operation. Request a new approval.",
    "Onay bu işlem için geçerli değil. Yeni bir onay isteyin.",
);

/// An admin tried to approve or deny their own four-eyes request (K-66).
pub const SELF_APPROVAL_NOT_ALLOWED: ErrorCode = ErrorCode::new(
    "admin_self_approval_not_allowed",
    StatusCode::FORBIDDEN,
    "A request must be approved by a different platform admin.",
    "Bir istek farklı bir platform yöneticisi tarafından onaylanmalıdır.",
);

/// Every code declared in this file (registry, uniqueness test, catalogue).
pub const ALL: &[ErrorCode] = &[
    PHISHING_RESISTANT_MFA_REQUIRED,
    REASON_REQUIRED,
    TARGET_NOT_ALLOWED,
    CONFIRMATION_REQUIRED,
    APPROVAL_REQUIRED,
    APPROVAL_INVALID,
    SELF_APPROVAL_NOT_ALLOWED,
];
