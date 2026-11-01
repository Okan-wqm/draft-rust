//! Shared fixtures of the authn-audit integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use authn_audit::{
    AccessDecision, AuditAccessPolicy, AuditPermission, AuditService, AuditServiceParts,
};
use authn_core::config::audit::AuditConfig;
use authn_core::domain::{
    AccountStatus, AuthMethodRef, EmailAddress, Impersonation, Principal, PrincipalCredential,
    Subject,
};
use authn_core::error::AuthError;
use authn_core::id::{ApiKeyId, OrgId, ServiceAccountId, SessionId, UserId};
use authn_core::ports::{Clock, RateLimiter};
use authn_crypto::envelope::EnvelopeCipher;
use authn_store::{NewUser, UserRepository};
use authn_testkit::TestPorts;
use axum::{Extension, Router};
use sqlx::PgPool;
use time::OffsetDateTime;

/// Grants permissions per (subject key, org) and records the client IP of
/// every check.
#[derive(Default)]
pub struct StaticPolicy {
    grants: Mutex<HashMap<(String, OrgId), HashSet<AuditPermission>>>,
    client_ips: Mutex<Vec<Option<IpAddr>>>,
}

fn subject_key(principal: &Principal) -> String {
    match principal.subject {
        Subject::User { user_id } => format!("user:{user_id}"),
        Subject::ServiceAccount {
            service_account_id, ..
        } => format!("sa:{service_account_id}"),
    }
}

impl StaticPolicy {
    pub fn grant_user(&self, user: UserId, org: OrgId, permissions: &[AuditPermission]) {
        self.grants
            .lock()
            .unwrap()
            .entry((format!("user:{user}"), org))
            .or_default()
            .extend(permissions.iter().copied());
    }

    /// Client IPs passed to `check`, in order.
    pub fn client_ips(&self) -> Vec<Option<IpAddr>> {
        self.client_ips.lock().unwrap().clone()
    }

    pub fn grant_service_account(
        &self,
        sa: ServiceAccountId,
        org: OrgId,
        permissions: &[AuditPermission],
    ) {
        self.grants
            .lock()
            .unwrap()
            .entry((format!("sa:{sa}"), org))
            .or_default()
            .extend(permissions.iter().copied());
    }
}

#[async_trait]
impl AuditAccessPolicy for StaticPolicy {
    async fn check(
        &self,
        principal: &Principal,
        org: OrgId,
        permission: AuditPermission,
        client_ip: Option<IpAddr>,
    ) -> Result<AccessDecision, AuthError> {
        self.client_ips.lock().unwrap().push(client_ip);
        let allowed = self
            .grants
            .lock()
            .unwrap()
            .get(&(subject_key(principal), org))
            .is_some_and(|p| p.contains(&permission));
        Ok(if allowed {
            AccessDecision::Allow
        } else {
            AccessDecision::Deny
        })
    }
}

pub struct Harness {
    pub pool: PgPool,
    pub ports: TestPorts,
    pub policy: Arc<StaticPolicy>,
    pub service: AuditService,
    pub cipher: EnvelopeCipher,
    pub config: AuditConfig,
}

pub fn cipher() -> EnvelopeCipher {
    EnvelopeCipher::from_config(&authn_testkit::config::test_config().crypto).unwrap()
}

impl Harness {
    pub fn new(pool: PgPool) -> Self {
        Self::with_config(pool, &AuditConfig::default())
    }

    pub fn with_config(pool: PgPool, config: &AuditConfig) -> Self {
        authn_testkit::init_tracing();
        let ports = TestPorts::new();
        let policy = Arc::new(StaticPolicy::default());
        let cipher = cipher();
        let service = AuditService::new(AuditServiceParts {
            pool: pool.clone(),
            clock: ports.clock.clone() as Arc<dyn Clock>,
            cipher: cipher.clone(),
            policy: policy.clone() as Arc<dyn AuditAccessPolicy>,
            rate_limiter: ports.rate_limiter.clone() as Arc<dyn RateLimiter>,
            config: *config,
            step_up_max_age: Duration::from_secs(600),
        });
        Self {
            pool,
            ports,
            policy,
            service,
            cipher,
            config: *config,
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        self.ports.clock.now()
    }

    pub fn clock(&self) -> Arc<dyn Clock> {
        self.ports.clock.clone() as Arc<dyn Clock>
    }

    /// The module router as seen by `principal` (None = unauthenticated).
    pub fn app(&self, principal: Option<Principal>) -> Router {
        let router = authn_audit::router().with_state(self.service.clone());
        let router = match principal {
            Some(p) => router.layer(Extension(p)),
            None => router,
        };
        authn_testkit::http::with_request_context(router)
    }
}

pub async fn create_user(pool: &PgPool) -> UserId {
    let mut conn = pool.acquire().await.unwrap();
    let id = UserId::generate();
    UserRepository::create(
        &mut conn,
        &NewUser {
            id,
            email: EmailAddress::parse(&format!("u{}@example.com", id.as_uuid().simple())).unwrap(),
            status: AccountStatus::Active,
            created_at: authn_testkit::FakeClock::DEFAULT_START,
        },
    )
    .await
    .unwrap();
    id
}

pub async fn create_org(pool: &PgPool) -> OrgId {
    let id = OrgId::generate();
    sqlx::query("INSERT INTO organizations (id, slug, name) VALUES ($1, $2, 'Test org')")
        .bind(id)
        .bind(format!(
            "org-{}",
            id.as_uuid().simple().to_string().get(..12).unwrap()
        ))
        .execute(pool)
        .await
        .unwrap();
    id
}

pub fn user_principal(user: UserId, auth_time: Option<OffsetDateTime>) -> Principal {
    Principal {
        subject: Subject::User { user_id: user },
        credential: PrincipalCredential::SessionCookie {
            session_id: SessionId::generate(),
        },
        active_org: None,
        amr: vec![AuthMethodRef::Pwd],
        acr: None,
        auth_time,
        scopes: vec![],
        impersonation: None,
        is_platform_admin: false,
    }
}

pub fn impersonated(mut principal: Principal, admin: UserId, read_only: bool) -> Principal {
    principal.impersonation = Some(Impersonation {
        admin_user_id: admin,
        read_only,
        expires_at: authn_testkit::FakeClock::DEFAULT_START + Duration::from_secs(900),
    });
    principal
}

pub fn service_account_principal(sa: ServiceAccountId, org: OrgId) -> Principal {
    Principal {
        subject: Subject::ServiceAccount {
            service_account_id: sa,
            org_id: org,
        },
        credential: PrincipalCredential::ApiKey {
            api_key_id: ApiKeyId::generate(),
        },
        active_org: Some(org),
        amr: vec![],
        acr: None,
        auth_time: None,
        scopes: vec!["webhooks:manage".into()],
        impersonation: None,
        is_platform_admin: false,
    }
}
