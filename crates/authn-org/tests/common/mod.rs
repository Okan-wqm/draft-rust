//! Shared harness of the authn-org integration tests.
#![allow(
    dead_code,
    unused_imports,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, Impersonation, Locale, Principal,
    PrincipalCredential, Subject,
};
use authn_core::http::RequestContext;
use authn_core::id::{MembershipId, OrgId, RequestId, RoleId, SessionId, UserId};
use authn_core::ports::{Clock, NotificationKind, RevocationReason};
use authn_org::api_key_middleware;
use authn_org::service::orgs::CreateOrganization;
use authn_org::{OrgService, OrgServiceDeps, OrgServiceSettings, router};
use authn_store::{NewUser, UserRepository};
use authn_testkit::TestPorts;
use authn_testkit::fakes::RevocationCall;
use authn_testkit::http::with_request_context;
use axum::{Extension, Router};
use sqlx::PgPool;

pub use authn_org::permission::{
    ADMIN_ROLE_ID, BILLING_ROLE_ID, MEMBER_ROLE_ID, OWNER_ROLE_ID, VIEWER_ROLE_ID,
};

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub service: OrgService,
    pub settings: OrgServiceSettings,
}

impl Harness {
    pub async fn new(pool: PgPool) -> Self {
        Self::with(pool, |_| {}).await
    }

    pub async fn with(pool: PgPool, tweak: impl FnOnce(&mut OrgServiceSettings)) -> Self {
        authn_testkit::init_tracing();
        let config = authn_testkit::config::test_config();
        let mut settings = OrgServiceSettings::from_app_config(&config);
        tweak(&mut settings);
        let ports = TestPorts::new();
        let service = build(&pool, &ports, settings.clone(), ports.rate_limiter.clone());
        Self {
            pool,
            ports,
            service,
            settings,
        }
    }

    /// The same harness with another rate limiter.
    pub fn with_rate_limiter(
        &self,
        limiter: Arc<dyn authn_core::ports::RateLimiter>,
    ) -> OrgService {
        build(&self.pool, &self.ports, self.settings.clone(), limiter)
    }

    pub fn now(&self) -> time::OffsetDateTime {
        self.ports.clock.now()
    }

    pub fn advance(&self, by: Duration) {
        self.ports.clock.advance(by);
    }

    /// An active user with a verified address.
    pub async fn user(&self, email: &str) -> UserId {
        let id = self.unverified_user(email).await;
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::mark_email_verified(&mut conn, id, self.now())
            .await
            .unwrap();
        id
    }

    /// An active user whose address is not verified.
    pub async fn unverified_user(&self, email: &str) -> UserId {
        let id = UserId::generate();
        let mut conn = self.pool.acquire().await.unwrap();
        UserRepository::create(
            &mut conn,
            &NewUser {
                id,
                email: EmailAddress::parse(email).unwrap(),
                status: AccountStatus::Active,
                created_at: self.now(),
            },
        )
        .await
        .unwrap();
        id
    }

    /// A session principal that authenticated `auth_age` ago.
    pub fn principal(&self, user: UserId, auth_age: Duration) -> Principal {
        Principal {
            subject: Subject::User { user_id: user },
            credential: PrincipalCredential::SessionCookie {
                session_id: SessionId::generate(),
            },
            active_org: None,
            amr: vec![AuthMethodRef::Pwd],
            acr: None,
            auth_time: Some(self.now() - auth_age),
            scopes: vec![],
            impersonation: None,
            is_platform_admin: false,
        }
    }

    /// A step-up-fresh session principal.
    pub fn fresh(&self, user: UserId) -> Principal {
        self.principal(user, Duration::from_secs(5))
    }

    /// A session principal whose last authentication is older than the
    /// step-up window.
    pub fn stale(&self, user: UserId) -> Principal {
        self.principal(user, Duration::from_secs(3600))
    }

    /// A fresh principal that used MFA.
    pub fn with_mfa(&self, user: UserId) -> Principal {
        let mut p = self.fresh(user);
        p.amr = vec![AuthMethodRef::Pwd, AuthMethodRef::Otp, AuthMethodRef::Mfa];
        p
    }

    pub fn impersonated(&self, user: UserId, read_only: bool) -> Principal {
        let mut p = self.fresh(user);
        p.impersonation = Some(Impersonation {
            admin_user_id: UserId::generate(),
            read_only,
            expires_at: self.now() + Duration::from_secs(900),
        });
        p
    }

    pub fn ctx(&self) -> RequestContext {
        self.ctx_from("203.0.113.10".parse().unwrap())
    }

    pub fn ctx_from(&self, ip: IpAddr) -> RequestContext {
        RequestContext {
            request_id: RequestId::generate(),
            client_ip: ip,
            peer_ip: ip,
            user_agent: Some("integration-test".to_owned()),
            device_id: None,
            locale: Locale::En,
        }
    }

    /// The router with `principal` injected (what the session layer does).
    pub fn app_as(&self, principal: Principal) -> Router {
        with_request_context(
            router()
                .with_state(self.service.clone())
                .layer(Extension(principal)),
        )
    }

    /// The router without any principal.
    pub fn app(&self) -> Router {
        with_request_context(router().with_state(self.service.clone()))
    }

    /// The router behind the API key middleware.
    pub fn app_with_api_keys(&self) -> Router {
        with_request_context(router().with_state(self.service.clone()).layer(
            axum::middleware::from_fn_with_state(self.service.clone(), api_key_middleware),
        ))
    }

    /// Creates an organization owned by `owner`.
    pub async fn org(&self, owner: UserId, slug: &str) -> OrgId {
        self.service
            .create_organization(
                &self.ctx(),
                &self.fresh(owner),
                CreateOrganization {
                    name: format!("Org {slug}"),
                    slug: slug.to_owned(),
                },
            )
            .await
            .unwrap()
            .id
    }

    /// Fixture: inserts a membership directly.
    pub async fn add_member(&self, org: OrgId, user: UserId, role: RoleId) -> MembershipId {
        let id = MembershipId::generate();
        sqlx::query(
            "INSERT INTO memberships (id, org_id, user_id, role_id, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'active', $5, $5)",
        )
        .bind(id)
        .bind(org)
        .bind(user)
        .bind(role)
        .bind(self.now())
        .execute(&self.pool)
        .await
        .unwrap();
        id
    }

    pub async fn membership_of(
        &self,
        org: OrgId,
        user: UserId,
    ) -> Option<(MembershipId, RoleId, String)> {
        sqlx::query_as(
            "SELECT id, role_id, status FROM memberships WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org)
        .bind(user)
        .fetch_optional(&self.pool)
        .await
        .unwrap()
    }

    /// The last invitation token e-mailed to `email`.
    pub fn invitation_token(&self, email: &str) -> String {
        self.ports
            .notifier
            .recorded()
            .into_iter()
            .rev()
            .find_map(|n| match n.kind {
                NotificationKind::Invitation { token, .. }
                    if n.recipient.email.as_str() == email =>
                {
                    Some(token.expose().to_owned())
                }
                _ => None,
            })
            .expect("invitation e-mail")
    }

    /// The last ownership-transfer token e-mailed.
    pub fn transfer_token(&self) -> String {
        self.ports
            .notifier
            .recorded()
            .into_iter()
            .rev()
            .find_map(|n| match n.kind {
                NotificationKind::OrgOwnershipTransfer { token, .. } => {
                    Some(token.expose().to_owned())
                }
                _ => None,
            })
            .expect("ownership transfer e-mail")
    }

    pub fn revocations(&self) -> Vec<RevocationCall> {
        self.ports.session_revoker.calls()
    }

    /// Sessions in `org` revoked because the membership's role or
    /// permissions changed (demotion, permission removed, previous owner
    /// demoted by a transfer; K-41: `RevocationReason::MembershipChanged`).
    pub fn changed_in_org(&self, user: UserId, org: OrgId) -> bool {
        self.revocations().iter().any(|c| {
            matches!(c, RevocationCall::UserInOrg(u, o, RevocationReason::MembershipChanged) if *u == user && *o == org)
        })
    }

    /// Sessions in `org` revoked because the membership ended or was
    /// suspended (`RevocationReason::MembershipRemoved`).
    pub fn revoked_in_org(&self, user: UserId, org: OrgId) -> bool {
        self.revocations().iter().any(|c| {
            matches!(c, RevocationCall::UserInOrg(u, o, RevocationReason::MembershipRemoved) if *u == user && *o == org)
        })
    }
}

fn build(
    pool: &PgPool,
    ports: &TestPorts,
    settings: OrgServiceSettings,
    rate_limiter: Arc<dyn authn_core::ports::RateLimiter>,
) -> OrgService {
    OrgService::new(
        OrgServiceDeps {
            pool: pool.clone(),
            clock: ports.clock.clone(),
            audit: ports.audit.clone(),
            events: ports.events.clone(),
            notifier: ports.notifier.clone(),
            rate_limiter,
            session_revoker: ports.session_revoker.clone(),
            dns: ports.dns.clone(),
        },
        settings,
    )
}

pub fn token_json(token: &str) -> serde_json::Value {
    serde_json::json!({ "token": token })
}

pub fn secret(token: &str) -> authn_core::secret::SensitiveString {
    authn_core::secret::SensitiveString::new(token)
}
