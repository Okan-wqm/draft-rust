//! Impersonation (ADM-04).
//!
//! The admin crate validates the request (justification, duration bounds,
//! target eligibility) and delegates to
//! `SessionIssuer::start_impersonation_with(ctx, request, client,
//! Some(admin_session))`. authn-session re-checks everything in its own
//! transaction, creates the session (read-only by default, the admin's
//! `amr`/`acr` inherited, RFC 8693 `act` claim in native access tokens),
//! notifies the user and records `admin.impersonation_started` — this
//! crate does **not** send a second notification or event. It only attaches
//! the justification to that event (`admin_action_reasons`, ADM-08).
//!
//! The impersonation ends at its expiry and whenever the admin is
//! suspended, demoted or has their sessions revoked (authn-session).

use std::time::Duration;

use authn_core::domain::{AccountStatus, ClientKind};
use authn_core::error::{AuthError, codes};
use authn_core::http::RequestContext;
use authn_core::id::UserId;
use authn_core::ports::{ImpersonationRequest, IssuedSession};
use authn_store::UserRepository;

use super::{AdminService, TargetPolicy, check_target};
use crate::guard::AdminCaller;
use crate::reason::Justification;
use crate::store;

/// Parameters of an impersonation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpersonationOptions {
    /// Duration in minutes; `None` = `admin.impersonation_default_ttl`
    /// (15 minutes). Must be 1 ..= `admin.impersonation_max_ttl` (≤ 60).
    pub ttl_minutes: Option<u32>,
    /// Read-only mode (default `true`).
    pub read_only: bool,
    /// Web cookie session or native tokens with the `act` claim.
    pub client: ClientKind,
}

impl Default for ImpersonationOptions {
    fn default() -> Self {
        Self {
            ttl_minutes: None,
            read_only: true,
            client: ClientKind::Web,
        }
    }
}

impl AdminService {
    /// The validated impersonation duration.
    pub(crate) fn impersonation_ttl(&self, minutes: Option<u32>) -> Result<Duration, AuthError> {
        let settings = self.settings();
        let ttl = match minutes {
            None => settings.impersonation_default_ttl,
            Some(m) => Duration::from_secs(u64::from(m) * 60),
        };
        if ttl.is_zero() || ttl > settings.impersonation_max_ttl {
            return Err(AuthError::new(codes::common::VALIDATION_FAILED)
                .with_details(serde_json::json!({ "field": "ttl_minutes" })));
        }
        Ok(ttl)
    }

    /// Starts impersonating `target` (ADM-04). Not applicable to the
    /// caller, platform admins, break-glass accounts or accounts that are
    /// not `active`.
    pub async fn impersonate(
        &self,
        caller: &AdminCaller,
        ctx: &RequestContext,
        target: UserId,
        reason: &Justification,
        options: &ImpersonationOptions,
    ) -> Result<IssuedSession, AuthError> {
        let ttl = self.impersonation_ttl(options.ttl_minutes)?;
        let record = UserRepository::find_by_id(self.pool(), target)
            .await?
            .ok_or_else(|| AuthError::new(codes::common::NOT_FOUND))?;
        check_target(caller, &record, TargetPolicy::RegularUsersOnly)?;
        if record.status != AccountStatus::Active {
            return Err(AuthError::new(codes::session::IMPERSONATION_NOT_ALLOWED)
                .with_context("only active accounts can be impersonated"));
        }
        let issued = self
            .deps()
            .issuer
            .start_impersonation_with(
                ctx,
                ImpersonationRequest {
                    admin_user_id: caller.user_id(),
                    target_user_id: target,
                    read_only: options.read_only,
                    ttl,
                    reason: reason.as_str().to_owned(),
                },
                options.client,
                Some(caller.session_id()),
            )
            .await?;
        self.attach_impersonation_reason(caller, target, &issued, reason)
            .await;
        crate::metrics::action("impersonation_started");
        tracing::info!(
            admin = %caller.user_id(),
            session = %issued.session_id,
            read_only = options.read_only,
            "impersonation started"
        );
        Ok(issued)
    }

    /// Links the justification to the `admin.impersonation_started` event
    /// recorded by authn-session. The impersonation is already committed;
    /// a failure here is logged (the reason also stays on the session row,
    /// `sessions.impersonation_reason`) and never undoes it.
    async fn attach_impersonation_reason(
        &self,
        caller: &AdminCaller,
        target: UserId,
        issued: &IssuedSession,
        reason: &Justification,
    ) {
        let result: Result<bool, AuthError> = async {
            let mut tx = self.begin().await?;
            let Some(event) = store::impersonation_event(&mut *tx, issued.session_id).await? else {
                return Ok(false);
            };
            store::insert_reason(
                &mut tx,
                event,
                Some(caller.user_id()),
                Some(target),
                "impersonation_started",
                reason.as_str(),
                self.now(),
            )
            .await?;
            authn_store::commit(tx).await?;
            Ok(true)
        }
        .await;
        match result {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                session = %issued.session_id,
                "impersonation audit event not found; justification kept on the session only"
            ),
            Err(err) => tracing::error!(
                session = %issued.session_id,
                code = err.code().code(),
                "could not store the impersonation justification"
            ),
        }
    }
}
