# Tamamlanan modüllerin genel API'si ve bağlama notları

> **Kaynak:** Bu dosya, modülleri yazan uzman agent'ların ve onları denetleyen bağımsız güvenlik denetçilerinin raporlarından derlendi. İçerik **İngilizce** bırakıldı (agent çıktısıdır, imzalar ve kod adlarıyla birebir uyumlu kalsın diye). Bir imza ile kod arasında fark görürsen **kod doğrudur**; ilgili crate'in `README.md` dosyasına ve `cargo doc` çıktısına bak.
>
> Bölümler: (1) `authn-session` çekirdeği, (2) `authn-account` kayıt yeniden tasarımı (pre-hijacking), (3) mimarın sözleşme değişikliği işlemesi, (4) Dalga A modülleri (protect, audit, notify, password, account, mfa, webauthn, org), (5) wave 3A sunucu bağlaması (authn-oidc-client, authn-admin, K-20, OPS-10, K-67).
> Genel sunucu bağlama tablosu için: [`docs/architecture/contracts.md`](../architecture/contracts.md) §15.


## 1. authn-session (oturum çekirdeği) — SES-03 … SES-17

### 1.1 Uygulayıcının raporu
I built the session core of authn-session for SES-03…SES-17. All per-crate gates pass. Nothing is committed; the reviewer commits. The login endpoints (SES-01/02/18–22) are not implemented: src/login/ is left to the next agent, and the API they build on is documented in crates/authn-session/README.md.

What was built:
- **Sessions and storage:** the `sessions`, `refresh_tokens` and `auth_challenges` tables, plus migration 2000. A session can be web or native, with remember-me (SES-06) and "not my device" (SES-07) lifetimes. Idle expiry is extended by activity, with writes throttled; absolute expiry is never extended. The optional concurrent-session limit evicts the oldest sessions and is safe under concurrent logins (SES-14).
- **Web sessions:**
  - The opaque 256-bit token sits in the `__Host-authn_session` cookie (HttpOnly, Secure, SameSite=Lax, Path=/). It is persistent only with remember-me.
  - CSRF for every state-changing cookie request is enforced in the middleware: an Origin / Sec-Fetch-Site check plus an HMAC token bound to the session and its current token, sent in X-CSRF-Token.
  - Login CSRF uses a pre-session cookie and token from `GET /v1/csrf`. A web session cannot be created without the CSRF proof; this is enforced by the type system.
- **Native tokens:**
  - Access tokens are EdDSA JWTs (`at+jwt`) with the SES-08 claims and no personal data. Impersonation tokens carry the RFC 8693 `act` claim and a `read_only` claim.
  - Refresh tokens are rotated on every use. Replaying a used token revokes the whole session, records an audit event and returns one uniform error. The optional grace window only ever returns the same successor.
- **Other services:** JWKS from a signing-key cache; RFC 7662 introspection, where an org API key only sees tokens of its own organization.
- **Middleware (`authenticate`):** it handles API keys (only on org routes), bearer tokens and the session cookie. By default it also checks that the token's session is still active. Read-only impersonation is blocked from every state-changing request except logout, across all modules. It replaces `authn_org::api_key_middleware`; the two must not both be installed.
- **Endpoints:** `/v1/me`, the session list, revoking one session or all others, logout, logout-all, org switch, step-up (`/v1/reauth`, plus the passkey options endpoint) and token refresh.
- **Ports:** the `SessionRevoker` port (`PgSessionRevoker`), and a `SessionIssuer` implementation with the post-login pipeline and impersonation.
- **API for the login agent:** `establish`, the challenge functions (create / open / record failure / update / consume) and the response helpers.
- **Tests:** 70 new ones (67 in authn-session, 3 in authn-core config). Every requirement ID SES-03…SES-17 has at least one test named with it.

### 1.2 Genel API
Crate authn_session (crates/authn-session/src):
- `SessionService::new(SessionServiceDeps { pool, clock, keys: KeyRing, envelopes, rate_limiter, audit, events, notifier, passwords: PasswordService, mfa: MfaService, webauthn: WebauthnService, orgs: OrgService, accounts: AccountService }, SessionSettings::from_app_config(&config)) -> Result<SessionService, AuthError>`
- Settings and helpers on the service: `settings()`, `now()`, `pool()`, `begin()`, `csrf() -> &CsrfProtector`, `revoker() -> PgSessionRevoker`, `invalidate_signing_keys()`.
- Building blocks for the login flows:
  - `verify_login_csrf(&HeaderMap) -> LoginCsrfVerified`
  - `verify_login_csrf_request(&HeaderMap, Option<&CurrentSession>)` — accepts a signed-in browser whose request already passed the session CSRF check.
  - `verify_login_org(&mut PgConnection, &ctx, user, org, LoginMethod) -> VerifiedOrg`
  - `establish(&mut PgConnection, &ctx, EstablishSession { user_id, method, amr, acr, auth_time, client: ClientChannel::{Web(LoginCsrfVerified) | Native}, remember_me, shared_device, org: Option<VerifiedOrg>, device: DeviceInfo }) -> EstablishedSession { session, credentials: IssuedCredentials::{Web | Native}, evicted }`
  - `login_succeeded_event(&ctx, &EstablishedSession, LoginMethod)`
  - Challenges: `create_challenge(&mut conn, &ctx, NewChallenge) -> IssuedChallenge`, `open_challenge(&mut conn, &ctx, token, ChallengeKind, ClientKind) -> ChallengeState`, `record_challenge_failure(ChallengeId) -> u32` (attempts left), `update_challenge(&mut conn, id, &ChallengeProgress)`, `consume_challenge(&mut conn, id)`
  - `complete_login(&ctx, PrimaryAuthentication, ClientChannel) -> LoginOutcome`
- Request handling: `authenticate_cookie`, `authenticate_bearer`, `verify_access_token -> VerifiedAccessToken`, `jwks`, `refresh(&ctx, token) -> RefreshedTokens`, `introspect(&ctx, &headers, token, hint) -> IntrospectionResponse`.
- Session management: `list_sessions`, `revoke_own_session`, `revoke_other_sessions`, `logout`, `logout_everywhere`, `me -> MeResponse`, `switch_org(&ctx, &principal, &CurrentSession, Option<OrgId>)`, `step_up(&ctx, &principal, &CurrentSession, StepUpProof::{Password | Totp | RecoveryCode | Passkey}, Option<binding cookie>)`, `start_passkey_step_up -> PasskeyStepUpStart`.
- Impersonation and jobs: `impersonate(&ctx, ImpersonationRequest, ClientKind, Option<SessionId>) -> EstablishedSession`, `purge_expired(limit) -> PurgeReport`.
- Ports implemented:
  - `PgSessionRevoker::new(clock, audit, events, mfa)` implements `SessionRevoker`. `RevokeOptions::also_trusted_devices` calls `MfaService::revoke_trusted_devices_in_tx` on the same connection.
  - `impl SessionIssuer for SessionService`.
- Middleware: `authenticate` (use with `from_fn_with_state`). It inserts `Principal` and `CurrentSession`; `CurrentSession` and `Option<CurrentSession>` work as extractors.
- HTTP: `router<S>()` where `SessionService: FromRef<S>`; OpenAPI struct `SessionApi`.
- Routes: `GET /v1/csrf`, `GET /v1/me`, `GET /v1/me/sessions`, `DELETE /v1/me/sessions/{session_id}`, `POST /v1/me/sessions/revoke-others`, `POST /v1/logout`, `POST /v1/logout/all`, `POST /v1/session/org`, `POST /v1/reauth`, `POST /v1/reauth/passkey/options`, `POST /v1/token/refresh`, `POST /v1/token/introspect`, `GET /.well-known/jwks.json`.
- Other modules: `SessionDataExporter` (export section `sessions`); `cookies::{SESSION_COOKIE, PRE_SESSION_COOKIE, CHALLENGE_COOKIE, PASSKEY_BINDING_COOKIE, session_cookie, challenge_cookie, …}`; `response::{credentials_response, challenge_response, redirect_with_session}`; `service::org_mfa_policy`; `claims::AccessTokenClaims`; `csrf::{CsrfProtector, LoginCsrfVerified, CSRF_HEADER}`; `metrics`.
- Port addition in authn-core (backward compatible, default body): `SessionIssuer::start_impersonation_with(ctx, request, client: ClientKind, admin_session: Option<SessionId>)`.
- New `[session]` config fields: `access_token_session_check`, `signing_key_cache_ttl`, `touch_interval`, `default_scopes`, `step_up_per_user`, `refresh_per_ip`.
- New error codes in `codes::session`: `csrf_failed`, `invalid_refresh_token`, `reauthentication_failed`, `step_up_method_not_allowed`, `challenge_invalid`, `login_method_not_allowed`, `impersonation_not_allowed`.

### 1.3 Denetim sonrası değişiklikler (bağlayıcı)
The review is finished and pushed to main as commit 4aa87d7 (one feat(session) commit containing the session core plus the fixes). I found 8 real problems in the authn-session session core (4 medium, 4 low) and fixed all of them. Each fix has a regression test, and I checked that all 9 of those tests fail when their fix is switched off.

Medium fixes:
1. A social or password login could claim it already proved MFA or a passkey. complete_login trusted the caller's mfa/hwk/swk values for any login method, which bypassed the MFA requirement and phishing-resistant org policies even with trust_provider_mfa off (SOC-09). Only a passkey login may claim them now.
2. An admin's impersonation sessions kept working for up to 60 minutes after the admin was suspended, demoted or had all sessions revoked. They now end at once; revocation covers sessions where the user is the impersonator, and migration 2000 gains an index for that lookup.
3. Step-up checked only the active organization's policy. With a stolen session and the password, someone could re-authenticate a member of a passkey-only organization from the personal context or a lax organization, then change e-mail, password or MFA. Step-up now applies the strictest policy across all of the user's organizations.
4. Password reset, suspension, "this wasn't me" and sign-out-everywhere left pending logins open, so a login started with the old password could finish after a reset. Those revocations now close them. A plain password change does not, because the SES-22 required actions (password change, e-mail verification) revoke sessions with that reason from inside the login they are completing.

Low fixes:
- A writable impersonation could end the user's other sessions one by one; it can now only end itself.
- VerifiedOrg is now tied to the user it was checked for.
- record_challenge_failure no longer hangs forever if the caller still holds the challenge lock; it errors after 5 seconds.
- Org switch now checks the allowed login method against the stored session when access_token_session_check is off.

I also removed the unused woothee dependency. The remaining accepted risks are written up in the README's Güvenlik notları, and the changed revocation behaviour is filed in docs/architecture/contract-change-requests.md.

Gates all pass: fmt and rustfmt checks, clippy with -D warnings, 76 authn-session tests, the authn-testkit tests, the authn-store schema test (the migration changed) and 144 authn-core lib tests. Every requirement SES-03 to SES-17 appears in a test name. cargo deny was not run; no dependency was added.

Still open: the login endpoints (SES-01, SES-02, SES-18 to SES-22) and DOC-05 for the next stage, the authn-server wiring, the architect's contracts updates, and a passkey step-up success test (TST-06). The login agent must also add risk evaluation and trusted-device checks to complete_login before social login ships.

Crate authn_session (unchanged from the implementer's report except): VerifiedOrg now carries and exposes user_id() and establish refuses a VerifiedOrg verified for another user; new pub const authn_session::service::CHALLENGE_LOCK_TIMEOUT (5 s) — record_challenge_failure(id) must be called after the open_challenge transaction ended, errors after the timeout otherwise (treat as a failed attempt); complete_login / SessionIssuer::complete_primary_authentication drop mfa/hwk/swk from PrimaryAuthentication.amr unless method == LoginMethod::Passkey; step_up applies the strictest OrgMfaPolicy over the active org and all memberships; revoke_own_session refuses impersonated principals for any session but the current one. SessionRevoker (PgSessionRevoker) semantics: revoke_all_for_user / revoke_all_except also revoke impersonation sessions where impersonator_user_id = user, and (for every reason except PasswordChanged) close the user's open auth_challenges (revoke_all_except keeps step-up challenges bound to the kept session; revoke_everything closes all). Authentication of impersonation sessions requires the impersonator to be an active platform admin. Migration 2000 adds sessions_impersonator_active_idx.

### 1.4 Server'ın yapması gerekenler
- Construct in this order: MfaService -> authn_session::PgSessionRevoker::new(clock, audit, events, mfa) -> AccountService (plain revoker as sessions) -> authn_account::AccountAwareSessionRevoker::new(Arc::new(revoker), account) for PasswordService, OrgService and other modules -> SessionService::new(SessionServiceDeps{..}, SessionSettings::from_app_config(&config))
- SessionIssuer port: Arc::new(session_service.clone()) as Arc<dyn SessionIssuer> for authn-oidc-client and authn-admin; authn-admin calls start_impersonation_with(ctx, req, client, Some(admin_session)) and must not resend the notification/audit; an admin's suspension or revoke-all now ends their impersonations automatically
- impl FromRef<AppState> for SessionService; .merge(authn_session::router::<AppState>()); nest authn_session::SessionApi in openapi.rs
- OPS-02 slot (8): from_fn_with_state(session_service, authn_session::authenticate) INSTEAD OF authn_org::api_key_middleware; every module's /v1/me* routes and /v1/email/change/confirm behind it
- Startup: SigningKeyRepository::rotate_if_due before issuing tokens; invalidate_signing_keys() after an in-process emergency rotation
- Background job (OPS-06): SessionService::purge_expired(limit)
- ACC-10: Arc::new(authn_session::SessionDataExporter) in AccountServiceDeps.exporters
- authn_protect::risk::NotMeTokenIssuer: provided by the login-flows stage of authn-session (not yet)

### 1.5 Açık konular ve kabul edilen riskler (uygulayıcının notları)
- Contract change requests were filed under `## authn-session` in docs/architecture/contract-change-requests.md. The architect still needs to update contracts §6 (migration 2000 row) and §15.2, §15.4 and §15.5 (revoker construction order, `authenticate` replacing `api_key_middleware`, the purge job). The server-side wiring itself is open for authn-server
- complete_login (used by SessionIssuer for social login) does not yet run risk evaluation (RSK-03) or the trusted-device check (MFA-09). The login agent must add both before social login ships
- Accepted risk (low): if a native client triggers two privilege changes at once (org switch plus step-up), the refresh token from the first response is already used; if the client then sends it, the session is revoked as a replay (fails safe)
- Accepted risk (low): with access_token_session_check = false, revocation and account suspension take effect only when the access token expires (at most 10 minutes). Bearer principals then never get platform-admin rights
- Accepted risk (low): signing keys are cached per process for signing_key_cache_ttl (30 s), so an emergency-revoked key can keep verifying on other instances for up to that long
- Accepted risk (low): org switch cannot re-check the org's allowed MFA factors against whichever factor added `mfa` to the session; the allowed-factors rule is only applied at step-up time, using the session's active org
- Session activity is recorded before the CSRF check, so a cross-site navigation (which sends SameSite=Lax cookies) can keep an idle session alive; it grants no access
- The `woothee` dependency in Cargo.toml is unused (device naming reuses authn_protect::risk::useragent::describe); it could be removed
- Passkey step-up was tested only for the error paths (no passkey registered, invalid ceremony); the success path needs a software-authenticator test, which fits the server's end-to-end tests (TST-06)


## 2. authn-account — kayıt akışının yeniden tasarımı (ADR 0002)

Fixed account pre-hijacking in authn-account (ADR 0002, docs/architecture/adr/0002-registration-pre-hijacking.md). A signup no longer writes credentials: the first registration of an address creates a credential-less pending_verification placeholder, and each registration stores its password hash, profile, consents and address spelling in the new pending_registrations table (migration 1201). Each registration is bound to its own e-mailed link, its own code and a 256-bit registration handle returned to the registering client (body field `registration` plus the __Host-authn_registration cookie: HttpOnly, Secure, SameSite=Strict). The response shape and timing are the same for every address.

A link completes a registration only when one of these comes with it: the handle (the browser that registered), the password chosen in that registration, or a new password (plus terms) chosen now by the mailbox owner. A link alone returns 403 registration_confirmation_required. A code completes only together with the handle, so e-mail + code no longer verifies. Each registration allows 5 wrong codes over its whole life (a resend does not reset this), the per-address budget is shared across registrations, and 5 wrong chosen-password answers are allowed per registration.

Completion runs in one transaction (address lock, then registration row, then user row). It activates exactly that registration's credentials, profile, consents and address spelling, marks the address verified and the account active, deletes every other registration, revokes verification tokens, and revokes all sessions and trusted devices. Registering again with an unverified address adds a separate registration and changes nothing; registering again with a verified address only notifies the owner.

Session-issued (limited-mode) verification links need the signed-in account holder, the account password or a new password. Registrations expire after unverified_purge_after. A placeholder is purged only once it has no live registration left.

Two related pre-hijack paths are also closed. E-mail change link confirmation now requires the account holder's session. AccountAwareSessionRevoker, a SessionRevoker decorator, ends pending email_change and email_change_code tokens on password reset, password change, sign-out-everywhere, not-me, refresh-token reuse, admin and emergency revocations; revert links are kept. A completed password reset on an unverified account verifies it for the mailbox owner and deletes pending registrations. confirm_mailbox_control_in_tx(MailboxProof::{PasswordReset, Passwordless, Administrator}) is exposed for session, oidc-client and admin; the passwordless and admin proofs remove an unproven password and revoke sessions.

The data export lists pending registrations without secrets. Two error codes were added. The README Güvenlik notları (new review table), the KVKK/GDPR inventory, the example.toml comments and a change request under the authn-account heading are updated. Committed as badc7c8 and pushed to origin/main.

### Genel API
authn_account (re-exported at the crate root):
- AccountService::signup(&self, ctx, SignupInput) -> Result<RegistrationReceipt, AuthError>; RegistrationReceipt::{handle() -> &SensitiveString, max_age() -> Duration}
- AccountService::verify_email(&self, ctx, VerificationProof); VerificationProof::{Link { token, confirmation: LinkConfirmation }, Code { code, registration: Option<SecretString>, email: Option<String> }}
- AccountService::verify_email_link(&self, ctx, token: &SecretString, confirmation: &LinkConfirmation); LinkConfirmation { registration: Option<SecretString>, signed_in_user: Option<UserId>, credentials: Option<CredentialConfirmation> }; CredentialConfirmation::{ChosenPassword(SecretString), NewPassword { password, accepted_terms }}
- AccountService::verify_email_code(&self, ctx, registration: Option<&SecretString>, email: Option<&str>, code: &SecretString)
- AccountService::resend_verification(&self, ctx, email: &str, registration: Option<&SecretString>)
- AccountService::confirm_email_change_link(&self, principal: Option<&Principal>, ctx, token)
- AccountService::confirm_mailbox_control_in_tx(&self, conn: &mut PgConnection, ctx: Option<&RequestContext>, user: UserId, proof: MailboxProof) -> Result<bool, AuthError>; MailboxProof::{PasswordReset, Passwordless, Administrator { admin: UserId }}
- AccountService::revoke_pending_email_changes_in_tx(&self, conn, user) -> Result<u64, AuthError>
- AccountService::on_sessions_revoked_in_tx(&self, conn, user, RevocationReason) -> Result<(), AuthError>
- AccountAwareSessionRevoker::new(inner: Arc<dyn SessionRevoker>, account: AccountService), which implements SessionRevoker
- Constants: REGISTRATION_COOKIE = "__Host-authn_registration", MAX_PASSWORD_CONFIRMATIONS = 5
- HTTP: POST /v1/signup returns {status, registration} plus Set-Cookie. POST /v1/email/verify takes token [+ password | new_password + accepted_terms] or code + registration (body or cookie), and reads an optional Principal. POST /v1/email/change/confirm now requires the account holder's session. POST /v1/email/verification/resend accepts an optional registration.
- Error codes: registration_confirmation_required (403), registration_password_mismatch (403).

### Server / Dalga B için bağlama
- authn-server: wrap authn-session's SessionRevoker once with AccountAwareSessionRevoker::new(inner, account) and give the wrapped port to password, session, mfa, org, admin and protect. Pass the inner revoker to AccountServiceDeps::sessions. RevocationReason::PasswordReset must only be used when an e-mailed password reset completes.
- authn-server: put POST /v1/email/change/confirm behind the session and CSRF layers, and have the session layer attach a Principal on POST /v1/email/verify when one is present.
- authn-session: call confirm_mailbox_control_in_tx(conn, Some(ctx), user, MailboxProof::Passwordless) in the same transaction, before issuing a magic-link (SES-18) or login-code (SES-19) session on an unverified account.
- authn-oidc-client: never attach identities to pending_verification accounts; call MailboxProof::Passwordless when linking by a provider-verified e-mail.
- authn-admin: ADM-03 'mark e-mail verified' calls confirm_mailbox_control_in_tx(..., MailboxProof::Administrator { admin }).
- Architect: add pending_registrations to contracts §5, §15 and the ER diagram (change request filed under authn-account).

### Kalan riskler ve notlar
- Residual risks: (1) code phishing — if the victim reads the e-mailed code to an attacker, the attacker can complete the attacker's own registration with the attacker's handle; (2) code guessing is bounded at about 1.5e-5 per targeted address per day; (3) a targeted registration DoS through the per-address daily limit and the 10 live registrations kept per account (the owner recovers with any link plus a new password). All three are documented in ADR 0002.
- Breaking API changes, with no wave B callers yet: signup returns RegistrationReceipt; the signatures of verify_email_link, verify_email_code, resend_verification and confirm_email_change_link changed; unauthenticated email+code verification no longer completes anything; /v1/email/change/confirm requires a session. Frontends must handle 403 registration_confirmation_required by offering 'password' or 'new_password'.
- Lock-order inversion between registration completion (registration row, then user) and the reset decorator (user, then registration rows). PostgreSQL detects the deadlock and aborts one transaction; no inconsistent state results. Documented.
- authn-account SharedReads and RevertLinkRepository could switch to the architect's new store helpers (claim_next, revoke_for_user_since). Left unchanged in this change to keep the scope tight; behaviour is equivalent.
- The authn-server example_config test was not re-run; only comments in example.toml changed.


## 3. Mimarın sözleşme değişikliklerini işlemesi (d48c3cd)

I went through every contract change request from the eight wave-A agents. Requests for me or for shared files are implemented. Requests for wave-B owners, authn-server, authn-notify and authn-crypto stay open; each status line names the owner and the matching row of the new server wiring section. Nothing was rejected. Committed as d48c3cd and pushed to origin/main.

What changed:
- **authn-store:** `UserRepository::find_many`, `UserRepository::claim_next` with `UserClaim` (row-claiming for maintenance jobs that is safe with several instances), `OneTimeTokenRepository::revoke_for_user_since` and `active_for_user`.
- **authn-core:** new `RevocationReason::MembershipChanged`. The `also_trusted_devices` option is now documented to run on the caller's connection, inside the caller's transaction. The environment-dependent `[notify]` rules are now enforced by `AppConfig::validate`, not only when the server starts.
- **authn-testkit:** `RecordingNotifier` now records SMS and can simulate "SMS unavailable"; `RecordingAuditSink` records pseudonymization calls. A new test (tests/routes.rs) checks that path-parameter names agree across every crate's routes and OpenAPI paths. Before, a mismatch only showed up as a panic at server start.
- **Migrations:** 0013 makes every argon2id-based hash store its pepper version, including the wrapped md5/sha1 legacy formats. 0014 marks `data_encryption_keys` as reserved and unused and adds an index for the unlock job.
- **Mailpit dev certificate:** a fixed, public, development-only certificate and key are in config/dev-certs (valid for localhost only, until 2046). docker-compose mounts them read-only and requires STARTTLS. Staging and production configs refuse this trust setting.
- **Docs:** contracts.md and overview.md now match wave A. contracts.md has a new §15 "Sunucu bağlama tablosu" listing every trait, port, service, router, middleware layer, job and CLI step the server must wire, with the owning crate and file.

One change from what authn-notify asked for: they wanted the `extra_ca_file` line enabled in config/example.toml, but their own test requires optional `[notify]` keys to stay commented out. The line is there with the dev certificate path but commented out, so developers have to uncomment it (or set the environment variable). As a side effect, a copied production config never trusts the dev certificate.

Gates: workspace clippy and tests pass and `cargo deny check` is clean, except for authn-account. Its clippy and tests are currently broken by the other agent's in-progress rewrite.

### Yeni API'ler
authn_store::users::UserClaim { UnverifiedCreatedBefore(OffsetDateTime), LockExpiredAt(OffsetDateTime) } (re-exported at authn_store::UserClaim)
authn_store::UserRepository::find_many<'e>(executor: impl PgExecutor<'e>, ids: &[UserId]) -> Result<Vec<UserRecord>, StoreError>  // ORDER BY id, unknown ids skipped
authn_store::UserRepository::claim_next(conn: &mut PgConnection, claim: UserClaim, skip: &[UserId]) -> Result<Option<UserRecord>, StoreError>  // FOR UPDATE SKIP LOCKED, oldest first; must run inside the caller's transaction
authn_store::OneTimeTokenRepository::revoke_for_user_since(conn, user: UserId, purposes: &[TokenPurpose], since: (OffsetDateTime, OneTimeTokenId), now) -> Result<u64, StoreError>
authn_store::OneTimeTokenRepository::active_for_user<'e>(executor, user: UserId, purposes: &[TokenPurpose], now) -> Result<Vec<OneTimeTokenRecord>, StoreError>  // newest first, hash never selected
authn_core::ports::RevocationReason::MembershipChanged => "membership_changed"
RevokeOptions::also_trusted_devices: documented to run on the same connection, inside the caller's transaction
AppConfig::validate: log e-mail transport, log SMS provider and notify.email.smtp.extra_ca_file are allowed only in development/test; the disabled e-mail transport is refused in production
authn_testkit::fakes::RecordingNotifier: notify_sms_in_tx, recorded_sms(), sms_with_template(), last_sms(), take_sms(), set_sms_available(bool)
authn_testkit::fakes::RecordingAuditSink: pseudonymize_subject records the user; pseudonymized() -> Vec<UserId>
Migrations: 0013 (password_credentials_wrapped_pepper_check), 0014 (data_encryption_keys comment, users_locked_until_idx)
Dev certificate: config/dev-certs/mailpit.{pem,key}

### Hâlâ açık olanlar

> **Güncelleme (wave 3A, 2026-11-04):** aşağıdaki maddelerin hepsi kapandı (account yeniden yazımı ve `pending_registrations` belgeleri, yeniden kullanım refaktörleri — K-41, notify/crypto talepleri — wave 1, §15 bağlaması — wave 3A). Mailpit hâlâ gerçek Docker ile çalıştırılmadı (K-55). Tarihsel kayıt olarak bırakıldı.

- authn-account is being rewritten by another agent: its clippy fails (redundant closure in routes.rs) and its tests do not compile. Re-run the workspace gates once that agent commits.
- The account agent is adding a new table, pending_registrations (migration 1201), and an ADR 0002. contracts.md §5 and overview.md need that table added once their work lands.
- authn-account can switch its SharedReads and RevertLinkRepository SQL to the new UserRepository::claim_next, active_for_user and revoke_for_user_since (same behaviour). authn-org can switch to find_many and RevocationReason::MembershipChanged. authn-mfa can drop its own TestNotifier.
- Approved requests still waiting for owners outside my files: authn-notify (generic registration_attempt wording, EmailChangeReverted, PasskeyCloneSuspected) and authn-crypto (KeyPurpose::KnownDevice). There is no active wave for these crates.
- authn-server and wave B (session, oidc-client, admin) must implement every row of contracts.md §15. The related requests stay open with pointers.
- Mailpit with the fixed certificate was not run end to end: there is no Docker daemon in this environment. The certificate was checked with rustls/webpki the same way lettre verifies it on Linux (rustls-platform-verifier with extra roots).


## 4. Dalga A modülleri (protect, audit, notify, password, account, mfa, webauthn, org)



### authn-protect

#### Public API for wave B / server
Signatures are unchanged from the implementer's report. One change in meaning for authn-session: LoginProtection::check_attempt(&LoginAttempt, &RequestContext) must be called exactly once per password attempt. It atomically consumes one unit of the identifier's CAPTCHA budget and, once the CAPTCHA gate is passed, one unit of its soft-lock budget. The attempt that exhausts the soft-lock budget engages the lock and gets login_temporarily_blocked + Retry-After (unless the device is trusted or known). record_success(&attempt, &ctx) refunds both budgets and must be called on success; otherwise the attempt counts as a failure. record_failure(&attempt, &ctx) now only updates the RSK-02 velocity counters (per user, with a throw-away key for unknown accounts, and per IP) and should still be called on failure. New public item: authn_protect::captcha::PURGE_GRACE (Duration, 15 minutes). ProofOfWorkCaptcha::purge_expired() now deletes only records whose expiry is older than PURGE_GRACE. Everything else is unchanged: KeyHasher, build_rate_limiter, Memory/Postgres/Redis limiters, HttpRateLimit/http_rate_limit, CaptchaService::{enforce,is_required,challenge,endpoint_challenge,with_endpoint_actions}, build_captcha_verifier, DefaultRiskEvaluator, risk::decide, RiskAlerts::{on_successful_login,on_blocked_login}, NotMeTokenIssuer, the web::{HostValidation,SecurityHeaders,CorsPolicy,RedirectValidator} middlewares, outbound::{SsrfSafeHttpClient,validate_user_supplied_url,classify,is_public}, router::<S>() and ProtectApi.

#### Traits/wiring the server must provide
- authn_protect::risk::NotMeTokenIssuer, implemented by authn-session: async fn issue_not_me_token(&self, conn: &mut sqlx::PgConnection, user: UserId, now: OffsetDateTime) -> Result<SensitiveString, AuthError>. It issues the one_time_tokens 'not_me' token inside the caller's transaction; consuming the token must revoke all sessions and force a password reset.
- authn-server: impl FromRef<AppState> for authn_protect::CaptchaService, .merge(authn_protect::router::<AppState>()), and nest authn_protect::ProtectApi in openapi.rs
- authn-server app.rs slot, outermost first: validate_host -> security_headers -> cors -> http_rate_limit, each via from_fn_with_state and all inside request_context_middleware (reference: crates/authn-protect/tests/web_stack.rs)
- authn-server background jobs (OPS-06): PostgresRateLimiter::purge_expired(batch), ProofOfWorkCaptcha::purge_expired(), LoginProtection::purge_expired()
- authn-server: provide the HttpClient port as Arc::new(SsrfSafeHttpClient::new(&cfg.protect.outbound)?), and optionally a GeoIpLookup adapter
- authn-session login flow: check_attempt exactly once per password attempt, then record_success or record_failure; RiskEvaluator::evaluate + risk::decide + RiskAlerts; RedirectValidator::validate for return_to
- authn-admin: LoginProtection::unlock(user, normalized_email); authn-account: CaptchaService::enforce("register", ...)

#### Remaining gaps / notes
- DOC-03 (docs/security/: threat model, ASVS mapping, SECURITY.md) is still deferred. docs/security/ is not on this module's commit path list, so this crate's security notes live in crates/authn-protect/README.md
- Wiring still to be done by the owning crates: authn-session (NotMeTokenIssuer, login flow calls), authn-server (layers, FromRef, OpenAPI, purge jobs, HttpClient port), authn-admin (unlock), authn-account (CAPTCHA enforce for registration)
- No GeoIpLookup adapter is bundled (the spec allows this), so impossible travel works only once the server plugs one in
- The timing test prt_03_lock_response_does_not_reveal_account_existence uses a 50% tolerance and could be flaky on a very noisy CI runner
- Redis integration tests skip when Redis is unreachable (CI coverage job); they ran for real here

#### Accepted risks / deferred findings
- [low/accepted_risk] Targeted soft lock. Because the lock is keyed on the identifier, an attacker who solves the CAPTCHAs can block a victim's password logins from unknown devices for soft_lock_duration. This is the PRT-03 design: passkeys, trusted and known devices, and password reset keep working, and the response does not leak account existence.
- [low/accepted_risk] Risk signal can be raised by an attacker. Failed attempts against a victim's e-mail raise the recent_failures signal. A victim logging in from a new device and a new network at the same time then scores high and, under the default high_action=block, is blocked and notified. Operators can set risk.high_action = "step_up".
- [low/accepted_risk] Small work difference when the soft lock engages. For an existing account the lock row and the audit event are written in one transaction; for an unknown account only the audit event is written. This happens once per identifier, at the lock threshold (default 50 failed attempts).
- [info/accepted_risk] Documented limitations. The HTTP-layer rate limiter fails open (the security-relevant per-action limits fail closed). PoW challenges are not bound to an IP and solving can be outsourced. Turnstile hostname is not checked, and action is checked only when the provider returns one. Entries in redirect_allow_list are trusted by exact match, with no scheme denylist. Handler-set CORS headers are not stripped while CORS is disabled (no handler in the workspace sets them). A stolen known-device id bypasses the soft lock for that one account.


### authn-audit

#### Public API for wave B / server
Unchanged from the implementer's report, except:
- `#[async_trait] pub trait AuditAccessPolicy { async fn check(&self, principal: &Principal, org: OrgId, permission: AuditPermission, client_ip: Option<std::net::IpAddr>) -> Result<AccessDecision, AuthError>; }`. Handlers pass `Some(ctx.client_ip)`.
- New `SecurityEventKind` variants: `OrgDomainAdded` ("org.domain_added"), `OrgDeletionCancelled` ("org.deletion_cancelled"), `OrgOwnershipTransferCancelled` ("org.ownership_transfer_cancelled").
- New sanitize helpers: `contains_embedded_identifier(&str) -> bool`, `is_user_reference_key(&str) -> bool`, `collect_user_reference_uuids(&Value, &mut Vec<Uuid>)`, `rewrite_uuids(&mut Value, &mut dyn FnMut(Uuid) -> Option<String>)`; new `RedactionRule` variants `EmbeddedIdentifier` and `TooManyIdentifiers`.
- `authn_audit_apply_least_privilege(app_role, maintenance_role)` now revokes all privileges on every audit/outbox/webhook table first. `create_checkpoint` and the `purge_*` functions must run on the maintenance-role pool.

#### Traits/wiring the server must provide
- authn_audit::AuditAccessPolicy — async fn check(&self, principal: &Principal, org: OrgId, permission: AuditPermission, client_ip: Option<IpAddr>) -> Result<AccessDecision, AuthError>. Implement it through authn_org OrgService::authorize_from(principal, Permission::{AuditRead, WebhooksRead, WebhooksManage}, org, client_ip). Deny by default, allow service accounts only in their own org, give platform admins no implicit access, and apply the org IP allow-list to client_ip
- authn_audit::OutboxHandler bridge for the 'notification' topic prefix to authn-notify's deliverer, registered via OutboxHandlers::register("notification", …) or merged into AuditService::outbox_handlers(http)
- impl FromRef<AppState> for AuditService, plus .merge(authn_audit::router::<AppState>()) and AuditApi nested into the server OpenAPI
- Background jobs: AuditService::outbox_worker(handlers).run(shutdown); a daily AuditService::run_maintenance(&maintenance_pool); CLI verify-audit-chain -> verify_chain / verify_chain_from; rotate-kek -> webhooks::rewrap_webhook_secrets; create_checkpoint on the maintenance pool

#### Remaining gaps / notes
- authn-server must implement AuditAccessPolicy (now with client_ip) on top of authn-org's authorize_from, and wire AuditService, the router, the OpenAPI doc, the outbox worker, maintenance and the CLI
- authn-account must call AuditSink::pseudonymize_subject inside the ACC-09 deletion transaction
- authn-admin must record platform staff actions as admin.* kinds or with an impersonator, or the org audit log shows the staff user id and masked IP
- Once least privilege is applied, create_checkpoint and the retention purge need the maintenance-role pool
- Two contract change requests are still open: audit reads users.id/status directly, and every router must use the {org_id} path parameter name
- Delivered outbox rows and webhook delivery history can contain user ids until their retention expires; they are not removed on account deletion

#### Accepted risks / deferred findings
- [low/accepted_risk] Value heuristics cannot catch every secret: a plain password under a neutral key, or a lowercase alphanumeric token shorter than 32 characters
- [low/accepted_risk] A deleted account's id under a neutral (non-user-reference) metadata key cannot be told apart from other UUIDs and stays verbatim
- [low/accepted_risk] The org audit log hides platform staff only for impersonation and admin.* kinds; authn-admin must log staff actions that way
- [info/accepted_risk] The hash chain is unkeyed. A compromised app role can append forged events at the tail or re-link a deleted pseudonym. The PII owner column is not covered by the digest. Detection needs external anchors (verify_chain_from)
- [info/accepted_risk] API-key credentials are exempt from step-up. Disabling an endpoint, changing its description and redelivering need no step-up (reversible and rate-limited)


### authn-notify

#### Public API for wave B / server
Unchanged from the implementer's report:
- Port additions in authn_core::ports: Notifier::notify_sms_in_tx(conn, SmsNotification) (default body returns sms_unavailable), SmsNotification, SmsNotificationKind::{MfaSmsCode, PhoneVerification}.
- Error codes: codes::notify::{DELIVERY_REJECTED (502), SMS_UNAVAILABLE (503)}.
- authn_notify: NotifyServices::from_config(&AppConfig, PgPool, EnvelopeCipher, Arc<dyn Clock>, Arc<dyn RateLimiter>, Arc<dyn HttpClient>) -> Result<NotifyServices, NotifyError>, with notifier_port() and the fields notifier, deliverer, renderer, email, sms.
- Topics: EMAIL_TOPIC, SMS_TOPIC, NOTIFICATION_TOPIC_PREFIX.
- Delivery: DeliveryRequest<'a> { id, topic, payload, sealed_payload, attempt, max_attempts }; NotificationDeliverer::deliver(DeliveryRequest) -> Result<(), DeliveryFailure>; DeliveryFailure::{Retry { reason, retry_after }, Permanent { reason }}.
- OutboxNotifier::{new, from_config, with_max_attempts, with_recipient_limit, enqueue_email, enqueue_sms, notify_sms}.
- TemplateRenderer::from_config(&AppConfig) (needs no runtime), email_transport_from_config, sms_sender_from_config, and the memory/log/disabled transports and senders for tests.

Behaviour changes from this review that producers should know:
- The per-recipient limit now has separate budgets: rate-limit actions notify_recipient_password_reset, notify_recipient_magic_link, notify_recipient_login_code, notify_recipient_mfa_email_code and notify_recipient_mfa_sms_code; all other user-triggerable kinds share notify_recipient.
- Budgets are keyed on the mailbox with the +tag removed, or on the E.164 number.
- Subject templates no longer receive link or code.
- The safe and tojson filters and the debug() function are not available in templates.

#### Traits/wiring the server must provide
- authn_audit::OutboxHandler bridge (in authn-server) for topic prefix `notification`: build a DeliveryRequest from the OutboxMessage (id, topic, payload, sealed_payload.as_bytes(), attempts, max_attempts), call NotificationDeliverer::deliver, and map DeliveryFailure::Retry { reason, retry_after } to HandlerError::Retry and DeliveryFailure::Permanent { reason } to HandlerError::permanent(reason). Example code is in crates/authn-notify/README.md.
- AppState wiring: Arc<dyn Notifier> = NotifyServices::notifier_port() for every producer module; Arc<dyn SmsSender> = NotifyServices.sms for authn-mfa. NotifyServices::from_config must be called inside the Tokio runtime.

#### Remaining gaps / notes
- authn-testkit RecordingNotifier does not override notify_sms_in_tx (change request open for the testkit owner)
- Environment-dependent [notify] rules (log transports, disabled transport, extra_ca_file) are enforced only by the startup builders, not by AppConfig::validate (change request open for the architect)
- Mailpit generates a new random dev certificate on each start, so a fixed dev certificate is needed (change request open for the architect)
- Producer-side equal-work timing for flows that must not reveal account existence, and de-duplication of SuspiciousLoginBlocked, belong to the producer crates (wave A/B)
- The SMS provider is sent no idempotency key (SmsMessage port has no field for it), so at-least-once delivery can rarely send the same SMS twice

#### Accepted risks / deferred findings
- [low/accepted_risk] notify_in_tx does extra work (limit check, sealing, INSERT) only on the branch that sends a notification; producers must do equivalent work on the other branch to avoid timing-based enumeration
- [low/accepted_risk] An attacker can exhaust one kind's budget for a victim (e.g. password reset); this is inherent to any per-recipient limit and matches the producers' own per-account limits
- [low/accepted_risk] The recipient limit fails open when the limiter is down, and budget is consumed even if the producer's transaction rolls back
- [low/accepted_risk] Security alerts (e.g. SuspiciousLoginBlocked) are never throttled; de-duplication belongs to the producer (RSK-03 / authn-session)
- [info/accepted_risk] Attacker-controlled user-agent text in alert e-mails (social-engineering text such as bare domains or phone numbers) is cleaned, capped and has URLs neutralised, but cannot be fully prevented
- [info/accepted_risk] The derived Debug of Recipient and NotificationKind shows personal data (display name, organisation name, device), not secrets; no current caller logs notifications
- [info/accepted_risk] Only the '+' sub-address separator is folded; provider-specific rules (Gmail dots, '-' separators) are not


### authn-password

#### Public API for wave B / server
Unchanged from the implementer's report. In crate authn_password: PasswordService::new(PasswordServiceDeps{pool, clock, hasher, otp, rate_limiter, notifier, audit, sessions, breach_checker, login_methods, profiles}, PasswordServiceSettings::from_app_config(&AppConfig)); HibpBreachChecker::from_config(&BreachCheckConfig, Arc<dyn HttpClient>); validator() -> Arc<dyn PasswordValidator>; drain_background_jobs(); router<S>() with FromRef plus PasswordApi. For authn-session: verify_login_password(&ctx, Option<UserId>, &SecretString) -> LoginPasswordOutcome {Valid, MustChangePassword, Invalid}; match on the enum, because is_valid() is also true for MustChangePassword. Also apply_required_password_change(&ctx, UserId, Option<SessionId>, &SecretString). For authn-admin: set_must_change_password(&ctx, Actor, UserId, bool). Also exposed: check_password, request_reset, complete_reset(ResetProof::{Link{token}, Code{email, code}}), change_password, add_password, remove_password. Behaviour change: reset link and code are now bound to the normalized address they were mailed to (one_time_tokens.target). They are refused if the account has since changed address, lost its password, or left an eligible status.

#### Traits/wiring the server must provide
- authn_password::LoginMethodInventory: async fn other_login_methods(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<LoginMethod>, AuthError>. Report passkeys as Passkey and oidc identities as Social. Read through the given conn, because the caller holds the user row FOR UPDATE.
- authn_password::ProfileLookup: async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError>, served from authn-account user_profiles (AccountService::profile_of).
- authn_core::ports::SessionRevoker (authn-session): revoke_all_for_user(conn, user, PasswordReset, RevokeOptions{also_trusted_devices:true}) must also delete the user's trusted devices on the same connection (PWD-09, MFA-09).
- authn-webauthn passkey deletion and authn-oidc-client unlinking must call UserRepository::lock_for_update(conn, user) first (PWD-11 race).
- authn-session must issue RequiredAction::ChangePassword (never a full session) on LoginPasswordOutcome::MustChangePassword.

#### Remaining gaps / notes
- fuzz/fuzz_targets/hibp_range_parse.rs is still not registered in fuzz/Cargo.toml (architect-owned; change request already filed). Its invariants run as proptests in tests/breach.rs.
- PWD-09 trusted-device deletion depends on authn-session's SessionRevoker honouring RevokeOptions{also_trusted_devices:true} in the caller's transaction (change request filed; tested only against the fake).
- The PWD-11 race needs authn-webauthn passkey deletion and authn-oidc-client unlinking to lock the user row (wiring)
- Reset secrets issued before this change have no target and are now rejected. This only affects tokens live at deploy time (30 min or less); there is no production data yet.
- The mobile code path does not use the display name as a zxcvbn input (deliberate, to avoid an enumeration oracle). The e-mail and service name are still used.

#### Accepted risks / deferred findings
- [low/accepted_risk] 6-digit reset-code brute force is bounded but not impossible: about 1e-5 per hour per targeted account under the default limits (5 per code, 10 per hour per address, 30 per hour per IP). This follows from the spec's 6-digit code design.
- [low/accepted_risk] Per-address limits let an attacker exhaust a victim's hourly reset budget or burn the code (targeted DoS). The limits must be keyed on the submitted address to avoid enumeration (PWD-07). The link stays valid when the code is burned.
- [info/accepted_risk] zxcvbn runs on spawn_blocking without a dedicated semaphore. Its work is bounded (first 100 chars, 32x64 user inputs, max_length gate, per-IP rate limit, server concurrency limit), and a panic inside zxcvbn is caught and returned as internal_error.
- [info/accepted_risk] LoginPasswordOutcome::is_valid() is true for MustChangePassword (it means the password is correct). authn-session must match on the enum, otherwise PWD-12 could be bypassed. Documented in the README wiring notes.
- [info/accepted_risk] The reset backlog is capped at 4096 pending jobs. When it is full, requests are dropped silently: the response is the same 202 and a metric is incremented.


### authn-account

#### Public API for wave B / server
Unchanged from the implementer's report, with one behaviour change: AccountService::change_status and change_status_in_tx now refuse StatusChange.to = PendingDeletion or Deleted with account_status_transition_not_allowed (these statuses are entered only through request_deletion and the purge jobs). Construction: AccountService::new(AccountServiceDeps{pool, clock, hasher, otp, rate_limiter, captcha, password_validator, notifier, audit, events, sessions, exporters, ownership}, AccountServiceSettings::from_app_config(&AppConfig)?)?; authn_account::router::<S>() where AccountService: FromRef<S>; authn_account::AccountApi; sync_terms_versions(); drain_background_jobs(). Jobs: purge_unverified_accounts(max), purge_due_deletions(max) -> PurgeReport, release_expired_locks(max), purge_expired_reservations(max). Session: assess_login(&UserRecord) / assess_login_by_id(UserId) -> LoginAssessment{Allowed{required_actions, deletion_scheduled_for} | Denied(DenialReason)}, DenialReason::into_error(now), unverified_login_policy(), terms_requirements(user), accept_terms(ctx, user, &[TermsAcceptance]), verify_own_email_code(principal, ctx, code). Admin: change_status / change_status_in_tx(conn, ctx, user, &StatusChange), check_transition, resting_status. Shared: profile_of(user), AccountDataExporter::new(clock), ACCOUNT_TOKEN_PURPOSES, ADDRESS_BOUND_PURPOSES, DisposableDomains, profile::{normalize_display_name, canonical_time_zone}.

#### Traits/wiring the server must provide
- authn_account::OrganizationOwnership: async fn sole_owner_organizations(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<OrgId>, AuthError>. Implement over authn-org on the given connection; the caller holds the user row lock. NoOrganizations is the no-op default.
- authn_core::ports::DataExporter: one section per module that holds personal data (mfa, webauthn, session, oidc-client, org, protect, audit), passed in AccountServiceDeps.exporters. Names must be unique, match ^[a-z][a-z0-9_]{0,63}$, and must not be 'account'.
- An authn_password::ProfileLookup adapter over AccountService::profile_of.
- impl FromRef<AppState> for AccountService; merge authn_account::router::<AppState>() behind the session auth layer for /v1/me*; add AccountApi to openapi.rs; call sync_terms_versions at startup, schedule the four maintenance jobs, call drain_background_jobs on shutdown.

#### Remaining gaps / notes
- Attacker-second overwrite of an unverified registration is accepted risk; a full fix (binding each registration's password to its own verification token, or setting the password at verification) changes the flow and is left for Phase 2
- Revert does not remove passkeys, TOTP factors or social identities that other modules hold (existing known limitation); a server-side revert hook is needed
- authn-password and authn-session do not revoke pending email_change / email_change_code tokens on password reset or sign-out-everywhere (accepted risk; change request suggested in the README)
- Change requests still open with the architect and other owners: contracts §5 email_reservations, store helpers for claim-by-status and revoke-since, notify template wording

#### Accepted risks / deferred findings
- [medium/accepted_risk] Unverified re-registration where the last registrant wins: an attacker who re-registers between the victim's signup and verification gets an account verified with the attacker's password
- [low/accepted_risk] A pending e-mail change link (24h) survives a password reset or sign-out-everywhere, because those modules do not revoke account purposes; the revert link sent at confirmation limits the damage
- [low/accepted_risk] Lock-order inversion between purge (deletion row, then user row) and cancel/revert (user row, then deletion row), and between link consumption and re-registration; PostgreSQL deadlock detection aborts one transaction
- [low/accepted_risk] GET /v1/me/export: a cross-site top-level navigation can use up the victim's daily export quota; no data leaves the victim's browser and step-up is required


### authn-mfa

#### Public API for wave B / server
crate authn_mfa (unchanged signatures; AuthError = authn_core::AuthError). Construction: MfaService::new(MfaServiceDeps { pool, clock, keys, otp, envelopes, rate_limiter, notifier, audit, sms: Option<Arc<dyn SmsSender>>, policy_source: Arc<dyn MfaPolicySource> }, MfaServiceSettings::from_app_config(&AppConfig)); router::<S>() where MfaService: FromRef<S>; MfaApi (utoipa); purge_expired(); MfaDataExporter; consts TRUSTED_DEVICE_COOKIE = "__Host-authn_trusted_device", TRUSTED_DEVICE_HEADER = "x-trusted-device". authn-session: evaluate_for_user(user, Option<OrgMfaPolicy>, phishing_resistant_required) -> MfaRequirement {NotRequired | Required{allowed_factors} | EnrollmentRequired{allowed_factors}} (an empty EnrollmentRequired list means deny); policy_input(...); policy::evaluate(&MfaPolicyInput); send_code(&ctx, user, Option<ChallengeId>, OtpChannel::{Email, Sms{factor_id}}) -> CodeDelivery; verify_factor(&ctx, user, Option<ChallengeId>, FactorProof::{Totp{code,factor_id}, RecoveryCode{code}, EmailOtp{code}, SmsOtp{code}}) -> VerifiedFactor{kind, factor_id, amr, recovery_codes_remaining}. The caller MUST reject proof.kind() values not in allowed_factors first. Codes bound to a challenge now verify only with that challenge (also for step-up). amr::combine / amr::for_factor; trust_device(&ctx, user, trusted_devices_allowed) -> Option<IssuedTrustedDevice> and is_trusted_device(user, token, trusted_devices_allowed) -> bool now also return None/false when ANY organization of the user (MfaPolicySource::org_policy_for_user, strictest combination) sets trusted_devices_allowed = false; revoke_trusted_devices_in_tx(&mut conn, user, RevocationReason) -> u64; status_for_user(user) -> MfaStatus. authn-admin: reset_user_mfa_in_tx(&mut conn, &ctx, user) -> MfaResetSummary, status_for_user. Self-service (router, step-up enforced inside): begin_totp_enrollment, begin_email_enrollment, begin_sms_enrollment, resend_enrollment_code, confirm_enrollment, remove_factor, regenerate_recovery_codes, recovery_codes_status, status, list_trusted_devices, revoke_trusted_device, revoke_all_trusted_devices.

#### Traits/wiring the server must provide
- authn_mfa::MfaPolicySource::org_policy_for_user(&self, conn: &mut PgConnection, user: UserId) -> Result<Option<OrgMfaPolicy>, AuthError>: the OrgMfaPolicy::strictest combination over the org_policies of the user's active memberships. It is used for the last-factor rule (MFA-07) and now also for trusted devices (MFA-09). It is called inside mfa transactions and, from is_trusted_device, on a plain connection, so it must read only through the given conn.
- authn_mfa::MfaPolicySource::webauthn_factor_count(&self, conn: &mut PgConnection, user: UserId) -> Result<u32, AuthError>: the number of passkeys usable as a second factor, read through the given conn (the caller holds row locks). StaticMfaPolicySource is available for single-tenant deployments and tests.

#### Remaining gaps / notes
- authn-session must reject proof.kind() values that are not in the challenge's allowed_factors before calling verify_factor; until then a policy bypass is possible (deferred to wave B and documented)
- authn-session must call revoke_trusted_devices_in_tx from SessionRevoker (also_trusted_devices) and on sign-out-everywhere; until then password reset and logout-all do not revoke trusted devices
- fuzz/Cargo.toml registration of mfa_input_parse is still pending (architect-owned; change request filed)
- authn-testkit RecordingNotifier still lacks notify_sms_in_tx (change request open; the tests use their own TestNotifier)
- cargo deny check not run; no new external crates were added
- fuzz/Cargo.lock has changes from several agents and was not committed (not in this module's path list)

#### Accepted risks / deferred findings
- [medium/deferred] verify_factor does not check the policy: whether the proof kind is allowed (admin phishing-resistant only, an organization's SMS ban, recovery codes) must be checked by authn-session against allowed_factors
- [low/accepted_risk] Per-user MFA lock (MFA-03) lets an attacker who knows the password delay the real user's MFA for 15-minute windows
- [low/accepted_risk] Requests waiting on the per-user row lock hold a pool connection for up to lock_timeout (5s), and the lock holder may use a second connection for RateLimiter; bursts against one user can briefly stall the pool
- [low/accepted_risk] Recovery-code regeneration sends no e-mail; there is no NotificationKind variant for it and the spec requires notification only on use. It is audited, needs step-up and revokes trusted devices
- [low/accepted_risk] Factor changes accept a step-up done with the password alone (SES-13), so a stolen session cookie plus the password can add a factor (the user is notified); requiring a second factor for step-up is authn-session's decision
- [info/accepted_risk] trust_device racing with revoke_trusted_devices_in_tx: a device committed right after sign-out-everywhere is not revoked (very narrow window, second factor already passed)
- [info/accepted_risk] Rotating crypto.hmac_root_key invalidates all recovery codes and trusted-device tokens (HKDF sub-keys); needs a runbook note


### authn-webauthn

#### Public API for wave B / server
Crate authn_webauthn. Enable features=["passkey"], because the workspace entry has default-features=false. Signatures are unchanged from the implementer's report:
- WebauthnServiceSettings::from_app_config(&AppConfig)
- WebauthnService::new(WebauthnServiceDeps { pool, clock, rate_limiter, notifier, audit, account_methods, policy_source }, settings)
- router<S>() (mount behind session auth + CSRF); well_known_router<S>() (mount at root); WebauthnApi
- start_authentication(&ctx, AuthenticationTarget, &PasskeyPolicy) -> AuthenticationStart { ceremony_id, binding_token, options, expires_at }
- finish_authentication(&ctx, AuthenticationFinish { ceremony_id, binding_token, target, credential }) -> AuthenticatedPasskey { user_id, credential_id, purpose, user_verified, backup_eligible, backup_state, amr }
- AuthenticationTarget::{Discoverable { conditional_ui }, SecondFactor { user_id, challenge_id }, StepUp { user_id, session_id }}
- start_registration / finish_registration / list_passkeys / rename_passkey / delete_passkey
- passkey_count_in(conn, user, login_capable_only); purge_expired_ceremonies(); well_known(); PasskeyDataExporter
- PasskeyPolicy::{unrestricted, allow_only, strictest, permits}

Behaviour changes from this review:
(1) The &PasskeyPolicy given to start_authentication is now an extra restriction. It is always combined, strictest wins, with PasskeyPolicySource::policy_for_user(conn, user, None): at start for SecondFactor/StepUp, at finish for Discoverable. Session can pass PasskeyPolicy::unrestricted() and the org policy still applies.
(2) start_registration and finish_registration return forbidden (403) for any impersonated principal, read-only or writable.
(3) passkey.clone_suspected and clone_suspected_at come only from a signature-verified counter regression, so the risk layer can treat them as a trustworthy signal.

Errors: passkey_ceremony_invalid (400), passkey_authentication_failed (401), passkey_not_available (400), rate_limited (429), unauthenticated, forbidden.

#### Traits/wiring the server must provide
- authn_webauthn::AccountMethodsSource — async fn other_login_methods(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<LoginMethod>, AuthError> and async fn mfa_facts(&self, conn: &mut PgConnection, user: UserId) -> Result<MfaFacts, AuthError>. Both are called inside the delete transaction with the users row locked FOR UPDATE and must read through conn.
- authn_webauthn::PasskeyPolicySource — async fn policy_for_user(&self, conn: &mut PgConnection, user: UserId, active_org: Option<OrgId>) -> Result<PasskeyPolicy, AuthError>. It is now also called with active_org = None for every authentication ceremony. For None it must return the policy that applies whichever organization the user switches to, e.g. PasskeyPolicy::strictest over the user's active memberships. Default: UnrestrictedPolicySource.
- FromRef<AppState> for authn_webauthn::WebauthnService and for authn_webauthn::WellKnownDocuments (service.well_known()).

#### Remaining gaps / notes
- Fuzz target webauthn_response_parse still needs registering in fuzz/Cargo.toml and the MPL-2.0 exceptions in fuzz/deny.toml; both files belong to the architect, so this is an open change request
- Server wiring is still open: FromRef impls, mounting the routers, the AccountMethodsSource and PasskeyPolicySource implementations (PasskeyPolicySource must handle active_org = None), the purge job, the exporter, passkey_count_in and features=["passkey"]
- authn-session still needs its passkey login, second-factor and step-up endpoints
- authn-server's example_config test was not run here because it depends on other agents' in-progress code; the [webauthn] section of example.toml is unchanged and already committed
- No passkey-specific notification kind yet: a clone is surfaced only as an audit event and a marker in the list (open change request to authn-notify)
- The disk is nearly full and shared with other agents (it hit 0 MB mid-run; Postgres test-DB setup failed transiently until another agent freed space). Builds used CARGO_INCREMENTAL=0; target/debug/incremental still holds about 9.4 GB of stale caches

#### Accepted risks / deferred findings
- [low/accepted_risk] A passkey flagged as possibly cloned stays usable: it gets a marker, an audit event and a flag in the list, and the user decides whether to remove it.
- [low/accepted_risk] The login-capable passkey count ignores discoverability (credProps.rk is an unsigned client hint), so a non-resident key could be counted as the last login method. Recovery is a password reset by e-mail.
- [low/accepted_risk] A security key registered with the second-factor intent but which performed UV is stored as usage both, so it can also be used for passwordless login.
- [low/accepted_risk] Step-up is not re-checked when registration finishes. It is checked at start, and the ceremony is bound to the same session for at most ceremony_ttl.
- [info/accepted_risk] The binding-token hash is compared in SQL, which is not constant-time. The value compared is the SHA-256 of a 256-bit random token, the same pattern as every other token lookup in the repo.
- [info/accepted_risk] Because credential_id is unique across all users, registering with another account's raw credential id returns passkey_already_registered. This only tells someone who already knows that id that it exists; it gives no way to take over an account.
- [info/accepted_risk] Passkey names get no NFC normalization or confusable-glyph check. Names are shown only to their owner; control, bidi-override, invisible and tag characters are already rejected.
- [info/accepted_risk] webauthn-rs checks attestation certificate validity with SystemTime, not the injected Clock. This only affects registrations under a restricting policy.


### authn-org

#### Public API for wave B / server
authn_org (crate root re-exports): OrgService::new(OrgServiceDeps { pool, clock, audit, events, notifier, rate_limiter, session_revoker, dns }, OrgServiceSettings::from_app_config(&AppConfig)); router::<S>() where OrgService: FromRef<S>; OrgApi (utoipa). api_key_middleware(State<OrgService>, Request, Next) reads `Authorization: Bearer ak_…` or `X-API-Key`. It now produces a Principal ONLY on /v1/orgs/{org_id} and /v1/orgs/{org_id}/… (authn_org::middleware::is_api_key_path); on every other path the request passes through untouched. OrgService::authenticate_api_key(&ctx, raw) -> Result<Principal, AuthError> is for SES-10 callers, which must call it directly. OrgService::authorize(&ctx, &principal, Permission, OrgId), authorize_from(&principal, Permission, OrgId, Option<IpAddr>), authorize_in(&mut PgConnection, …), check_membership(&principal, OrgId, Option<IpAddr>) -> Authorization { org_id, org_name, org_status, subject, role_id, is_owner, permissions, policy }. OrgService::policy(OrgId); policy_of(&mut conn, OrgId); policies_for_user(&mut conn, UserId) -> Vec<(OrgId, OrgPolicy)>; OrgPolicy helpers allows_ip / allows_login_method / allows_factor / session_lifetime_cap / check_session. sole_owner_organizations(&mut conn, UserId) -> Vec<OrgId>. OrgService::auto_join_verified_domains(UserId) -> Vec<OrgId>, which never re-adds removed or departed members. Jobs: purge_due_deletions(limit), expire_invitations(). OrgDataExporter (section 'organizations', now with auto_join_exclusions). HickoryDnsTxtResolver::{from_system_conf, with_name_servers}. Permission, PermissionSet, BuiltinRole, parse_api_key, GeneratedApiKey, actor_of. New config field [org] invitation_sends_per_recipient (default 5 per day). New migration 1501 adds the table org_auto_join_exclusions, owned by authn-org.

#### Traits/wiring the server must provide
- authn_account::OrganizationOwnership::sole_owner_organizations -> authn_org::sole_owner_organizations(conn, user)
- authn_mfa::MfaPolicySource::org_policy_for_user -> map authn_org::policies_for_user(conn, user) to OrgMfaPolicy and fold with strictest()
- authn_audit::AuditAccessPolicy::check -> OrgService::authorize_from(principal, Permission::{AuditRead|WebhooksRead|WebhooksManage}, org, client_ip): Ok => Allow, Err => Deny
- impl FromRef<AppState> for OrgService; merge authn_org::router::<AppState>() behind authentication; nest OrgApi; install api_key_middleware after the request context where it sees full /v1 paths; schedule purge_due_deletions and expire_invitations; register OrgDataExporter; DnsTxtResolver = HickoryDnsTxtResolver::from_system_conf(config.org.dns_timeout)
- authn-session: SES-10 API-key client authentication must call OrgService::authenticate_api_key directly, because the middleware no longer creates principals outside /v1/orgs/{org_id}; SES-17 uses check_membership + Authorization::policy; call auto_join_verified_domains after login and e-mail verification

#### Remaining gaps / notes
- ORG-06 sso_required is stored but not enforced (Phase 2 per spec)
- ORG-07 allowed login methods, allowed MFA factors, trusted devices and passkey AAGUIDs must be enforced by authn-session / authn-mfa / authn-webauthn through the exposed OrgPolicy (wiring CCR open)
- RevocationReason::MembershipChanged and UserRepository::find_many CCRs are still open
- fuzz/Cargo.lock was regenerated by the implementer's cargo fuzz build and is not in the allowed commit paths, so it is left uncommitted
- authn-server example_config test was not re-run (it would need a full server build on a nearly full disk); the only example.toml change is one commented line
- cargo clippy -p authn-core fails on pre-existing lints in config/protect.rs and config/webauthn.rs test code (not owned by authn-org); config/org.rs and codes/org.rs are clean

#### Accepted risks / deferred findings
- [low/accepted_risk] Personal API keys are exempt from org MFA and lifetime policy, and policy tightening revokes sessions but not existing keys
- [low/accepted_risk] Invitations sent by service accounts have invited_by NULL, so disabling or downgrading the SA does not revoke them
- [low/accepted_risk] A pending ownership transfer is not revoked when its initiator is demoted; it can complete only if the initiator is an active owner again within the TTL
- [low/accepted_risk] Org names chosen by the creator appear in genuine invitation and transfer e-mails (content is sanitized and rate-limited, not moderated)
- [info/accepted_risk] Verified domains are never re-verified; org_domain_claimed reveals to a DNS controller that another org verified the domain; toggling auto_join needs no step-up


## 5. Wave 3A — sunucu bağlaması (2026-11-04)

Wiring lives in `crates/authn-server/src/{services.rs,hooks.rs,state.rs,app.rs,cors.rs,openapi.rs,jobs.rs,serve.rs,cli.rs,operations.rs}`. Source of truth for the tables: `docs/architecture/contracts.md` §15.

### Construction order (`Services::build_with_maintenance_pool`)
1. crypto, rate limiter, SSRF-safe HTTP client, notifications; audit sink + outbox event publisher.
2. `MfaService` → `PgSessionRevoker` → `AccountService` (plain revoker; exporters: session, mfa, passkeys, org, `IdentityDataExporter`, `AdminActionsDataExporter::new(clock)`) → `AccountAwareSessionRevoker` (given to every other module).
3. password, webauthn, org, audit service; late hooks bound; login protection, risk, `SessionService` (= `SessionIssuer`).
4. `OidcClientService::build(OidcClientServiceDeps { …, sessions: issuer, login_methods: ServerOidcLoginMethods, session_liveness: ServerSessionLiveness, notifier }, settings).await` (test override: `Ports::oidc_registry`).
5. `accounts.register_erasure_hook(oidc.erasure_hook())` (K-35) and `accounts.register_revert_hook(ServerRevertHook { webauthn, mfa, oidc })` (K-20).
6. `AdminService::new(AdminServiceDeps { pool, clock, audit, sessions: account-aware revoker, issuer, accounts, mfa, webauthn, passwords, protection, hasher, envelopes, signing_keys: ServerSigningKeyCache(sessions), rate_limiter }, AdminSettings::from_app_config(&config))`.

### Server hook implementations (`hooks.rs`)
- `ServerLoginMethods` (password PWD-11) and `ServerAccountMethods` (webauthn PKY-04): `Social` when `OidcClientService::linked_identity_count_in(conn, user) > 0`.
- `ServerOidcLoginMethods` (oidc SOC-06): `Password`, `Passkey`; never `Social`. Passwordless e-mail login is not counted by any of the three adapters (it exists for every account with an address; PWD-11 asks for a *strong* method) — deliberate, the rules can only refuse, never strand.
- `ServerSessionLiveness` → `authn_session::is_session_active_in` (K-03).
- `ServerSigningKeyCache` → `SessionService::invalidate_signing_keys` (ADM-06).
- `ServerRevertHook` (K-20) → `remove_all_passkeys_in_tx`, `reset_user_mfa_in_tx`, `remove_all_identities_in_tx` in the revert transaction.

### Routing
- `module_routes()` (every module incl. `authn_oidc_client::router`, `authn_admin::router`) behind `authn_session::authenticate` (+ CSRF).
- `session_less_routes()` = `authn_admin::enrollment_router` (feature `passkey`), merged **outside** the authentication layer: the link token is the credential; a browser holding an unrelated session cookie without CSRF token must not be refused.
- K-67: `server.admin_console_origins` (each also in `protect.cors.allowed_origins`); `cors::admin_console_cors` answers only preflights from those origins asking for `x-impersonation-session`. Default: none.
- OpenAPI: `OidcClientApi`, `AdminApi`, `AdminEnrollmentApi` (passkey).

### Jobs
- `run_maintenance_once` adds `OidcClientService::purge_expired_states`.
- `jobs::process_token_revocations` (own task, every minute, 100 per run; K-35).
- Audit maintenance runs on `Services::maintenance_pool` (`database.maintenance_url`, OPS-10).

### CLI
`create-admin --email E [--passkey-link [--ttl D]]`, `admin-enrollment-link`, `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions` (all: `--target`, `--reason`, `--operator` required), `seal-apple-key --pem-file PATH|-`, `rotate-kek` (now also identities / oauth_states / oauth_token_revocations ciphertexts; prints the re-wrapped `apple.private_key_ciphertext`). One-time secrets (password, enrollment link) are printed once to stdout and never logged; the link token is in the URL fragment.

### Database roles (K-42)
Migration `2900`: `authn_apply_least_privilege(app_role, maintenance_role)`; runbook `docs/operations/least-privilege.md`.

### Tests (crates/authn-server/tests)
`social_e2e.rs`, `admin_e2e.rs` (passkey feature), `console_cors.rs`, `least_privilege.rs`, `operations.rs`, plus additions to `http_stack.rs` (SSRF, OpenAPI). See remaining-work.md §10 K-50 … K-54 rows for names.

