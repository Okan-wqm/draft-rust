# authn-account

Kayıt, e-posta doğrulama, hesap durum makinesi, profil, e-posta değişikliği, hesap silme, kişisel veri dışa aktarma (`DataExporter` toplayıcısı) ve onay (kullanım şartları / gizlilik politikası) kayıtları. KVKK/GDPR notları: [`docs/compliance/kvkk-gdpr.md`](../../docs/compliance/kvkk-gdpr.md) (DOC-07). Hesap ön-ele geçirme savunması: [ADR 0002](../../docs/architecture/adr/0002-registration-pre-hijacking.md).

## Sahip olunan gereksinimler

| Kimlik | Uygulama | Testler (örnek) |
|--------|----------|-----------------|
| ACC-01 | `AccountService::signup`, `POST /v1/signup` — şifre `PasswordValidator` portuyla, hash `authn-crypto` Argon2id ile; kimlik bilgisi kayda bağlı bekler (`pending_registrations`), yanıtta kayıt tutamacı (gövde + `__Host-authn_registration` çerezi) | `signup.rs`: `acc_01_*` |
| ACC-02 | Kaydın hesaba bağlı kısmı arka plan işinde; yanıt her adres için aynı (durum, gövde biçimi, süre); mevcut sahibe "biri kayıt olmaya çalıştı" e-postası (adres başına sınırlı); doğrulanmamış adrese yeniden kayıt hiçbir şeyi değiştirmez (ayrı kayıt) | `acc_02_existing_address_gets_identical_status_and_body`, `acc_02_signup_timing_does_not_reveal_existing_accounts`, `acc_02_registration_notices_are_throttled_per_address`, `prehijack.rs`: `acc_02_attacker_first_*`, `acc_02_attacker_second_*`, `acc_02_concurrent_registrations_*` |
| ACC-03 | `authn_core::domain::EmailAddress` sertleştirmesi (karışık alfabe, birleşik işaret dizileri, özel TLD'ler, `normalized` sabit nokta); görünen ad için UTS #39 karıştırılabilir/karışık alfabe kontrolü (`profile::normalize_display_name`) | core `acc_03_*`, `profile::tests::acc_03_*`, `acc_03_addresses_differing_only_in_case_or_width_are_the_same_account` |
| ACC-04 | Kayıt başına link (24 sa) + 6 haneli kod (15 dk, kayıt ömrü boyunca 5 deneme), adrese ve kayda bağlı, tek kullanımlık; link yalnızca kaydı yapan istemcide (tutamaç), kayıtta seçilen şifreyle veya yeni şifreyle tamamlanır; kod yalnızca tutamaçla; tekrar gönderme 60 sn bekleme + saatlik limit; adres başına toplam kod denemesi | `verification.rs`: `acc_04_*` (brute force kilidi, yarış, tek kullanım, zamanlama/gövde eşitliği); `prehijack.rs`: `acc_04_link_on_another_device_*`, `acc_04_code_needs_the_registering_clients_handle_*`, `acc_04_session_issued_link_needs_the_account_holder` |
| ACC-05 | `assess_login` (`block` / `limited` → `verify_email` zorunlu adımı); kayıtla oluşan hesabın doğrulanana kadar kimlik bilgisi yoktur; `purge_unverified_accounts` (7 gün; süresi dolan kayıtlar + canlı kaydı kalmayan hesaplar); doğrulanmamış hesapta şifre sıfırlama / şifresiz kanıt adresi posta kutusu sahibi için doğrular (`MailboxProof`) | `acc_05_*` (`prehijack.rs`: `acc_05_password_reset_on_unverified_account_hands_it_to_the_mailbox_owner`, `acc_05_passwordless_mailbox_proof_removes_an_unproven_password`) |
| ACC-06 | `lifecycle::check_transition` (tek tablo), `apply_transition` (satır kilidi + CAS + audit), `change_status` / `change_status_in_tx`, `release_expired_locks` | `lifecycle::tests::acc_06_*` (7×7×2 kapsamlı tablo, proptest), `lifecycle.rs` |
| ACC-07 | `is_address_reserved_in` (sosyal giriş vb. için rezervasyon sorgusu, K-02); step-up ile talep, yeni adrese link + kod (ikisi de hesap sahibinin oturumuyla onaylanır), eski adrese 7 günlük geri alma linki, eski adres rezervasyonu, geri almada oturum/güvenilir cihaz iptali + şifre sıfırlama zorunluluğu; bekleyen değişiklik şifre sıfırlama / "tümünü kapat" ile ölür (`AccountAwareSessionRevoker`) | `email_change.rs`: `acc_07_*`; `prehijack.rs`: `acc_07_email_change_link_requires_the_account_holders_session`, `acc_07_pending_email_change_ends_on_reset_and_sign_out_everywhere` |
| ACC-08 | `GET/PATCH /v1/me/profile` (görünen ad, `tr`/`en`, IANA saat dilimi); posta kutusunu kendisi kanıtlayan modüller için doğrulanmış hesap + profil sağlama (`provision_verified_user_in_tx`, K-33) | `profile.rs`, `profile::tests::acc_08_*`, `provisioning.rs`: `acc_08_provisioned_social_account_gets_a_profile`, `acc_07_provisioning_never_takes_an_existing_or_reserved_address`, `acc_07_reservation_lookup_on_the_given_connection`, `acc_12_provisioning_honours_the_disposable_domain_list` |
| ACC-09 | `DELETE /v1/me` (step-up) → `pending_deletion` + 30 gün; oturumla veya linkle iptal; `purge_due_deletions` (kaskad silme + audit takma adlaştırma); son sahip engeli (`OrganizationOwnership`); silme transaction'ında diğer modüllerin işi (`AccountErasureHook`, K-35) | `deletion.rs`: `acc_09_*`; `provisioning.rs`: `acc_09_erasure_hooks_run_in_the_erasure_transaction` |
| ACC-10 | `GET /v1/me/export` (step-up, rate limit): tüm `DataExporter`'lar tek `REPEATABLE READ, READ ONLY` transaction'ında | `export.rs`: `acc_10_*` |
| ACC-11 | `terms_versions` senkronu (`account.terms`), `consents` (zaman, IP, UA), `terms_requirements` / `accept_terms` (SES-22) | `consent.rs`: `acc_11_*` |
| ACC-12 | `DisposableDomains` (dosyadan, alt alan adları dahil; varsayılan kapalı) | `acc_12_*` |
| ACC-13 | `CaptchaVerifier` ile `always` / `risk_based` (IP başına eşik) / `never` | `acc_13_*` |
| DOC-07 | `docs/compliance/kvkk-gdpr.md` | `compliance.rs`: `doc_07_*` (envanter her şema tablosunu kapsar) |

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. Paylaşılan tablolardaki okumalar/iptaller authn-store API'leriyle yapılır (K-41: `UserRepository::claim_next` — kilit açma işi —, `OneTimeTokenRepository::active_for_user` — dışa aktarma ve geri alma linkleri —, `revoke_for_user_since` — geri alma); `SharedReads`'te yalnızca ACC-05 temizlik sorgusu kaldı, çünkü o canlı `pending_registrations` satırı olan hesapları da atlar (`claim_next` bunu ifade edemez; kullanmak satırları tek tek kilitleyip atlamak, yani farklı ve daha yavaş bir davranış olurdu). Başka modüllerin verisine ihtiyaç duyulan yerde bu crate bir trait tanımlar (`OrganizationOwnership`); uygulamayı `authn-server` verir. Diğer modüllerin olaylarının hesap sonuçları (şifre sıfırlama, "tümünü kapat") `SessionRevoker` portunu saran `AccountAwareSessionRevoker` ile uygulanır — authn-password ve authn-session'da değişiklik gerekmez. Yeni harici bağımlılık: yok (`tokio-util` ve `http` workspace'te zaten vardı; crate `Cargo.toml`'una eklendi).

## Genel API

```rust
// Kurulum (authn-server)
AccountService::new(AccountServiceDeps { pool, clock, hasher, otp, rate_limiter, captcha,
    password_validator, notifier, audit, events, sessions, exporters, ownership },
    AccountServiceSettings::from_app_config(&config)?)? -> AccountService
authn_account::router::<AppState>()            // AccountService: FromRef<AppState>
authn_account::AccountApi                       // utoipa::OpenApi
AccountAwareSessionRevoker::new(inner: Arc<dyn SessionRevoker>, account: AccountService) // SessionRevoker

// Kayıt ve doğrulama (ADR 0002)
async fn signup(&self, ctx, input: SignupInput) -> Result<RegistrationReceipt, AuthError>   // handle(), max_age()
async fn verify_email(&self, ctx, proof: VerificationProof) -> Result<(), AuthError>
async fn verify_email_link(&self, ctx, token: &SecretString, confirmation: &LinkConfirmation) -> Result<(), AuthError>
async fn verify_email_code(&self, ctx, registration: Option<&SecretString>, email: Option<&str>, code: &SecretString) -> Result<(), AuthError>
async fn resend_verification(&self, ctx, email: &str, registration: Option<&SecretString>) -> Result<(), AuthError>
// LinkConfirmation { registration, signed_in_user, credentials: Option<CredentialConfirmation> }
// CredentialConfirmation::{ChosenPassword(SecretString), NewPassword { password, accepted_terms }}
// REGISTRATION_COOKIE = "__Host-authn_registration", MAX_PASSWORD_CONFIRMATIONS = 5

// Posta kutusunu kendisi kanıtlayan modüller (authn-oidc-client; K-02, K-33)
async fn is_address_reserved_in(&self, conn, email: &EmailAddress) -> Result<bool, AuthError>          // ACC-07, salt okuma
async fn provision_verified_user_in_tx(&self, conn, ctx, VerifiedUserProvision { email, display_name, locale, method, provider })
    -> Result<ProvisionOutcome, AuthError>   // Created(UserId) | Existing(UserRecord) | Reserved | Conflict
async fn notification_recipient_in(&self, conn, user, fallback: Locale) -> Result<Option<(Recipient, Locale)>, AuthError>
fn register_erasure_hook(&self, hook: Arc<dyn AccountErasureHook>)                                    // K-35, açılışta

// Posta kutusu kanıtları ve iptal sonuçları (authn-server / Dalga B)
async fn confirm_mailbox_control_in_tx(&self, conn, ctx: Option<&RequestContext>, user, proof: MailboxProof) -> Result<bool, AuthError>
// MailboxProof::{PasswordReset, Passwordless, Administrator { admin }}
//   Administrator: kullanıcının olayları Actor::System, IP/UA yok (request_id var) — K-14
async fn revoke_pending_email_changes_in_tx(&self, conn, user) -> Result<u64, AuthError>
async fn on_sessions_revoked_in_tx(&self, conn, user, reason: RevocationReason) -> Result<(), AuthError>
async fn confirm_email_change_link(&self, principal: Option<&Principal>, ctx, token) -> Result<(), AuthError>

// authn-session (giriş, SES-01 / SES-22)
async fn assess_login(&self, user: &UserRecord) -> Result<LoginAssessment, AuthError>
async fn assess_login_by_id(&self, user: UserId) -> Result<Option<LoginAssessment>, AuthError>
fn unverified_login_policy(&self) -> UnverifiedLoginPolicy
async fn terms_requirements(&self, user: UserId) -> Result<Vec<TermsVersionView>, AuthError>
async fn accept_terms(&self, ctx: &RequestContext, user: UserId, accepted: &[TermsAcceptance]) -> Result<(), AuthError>
// LoginAssessment::{Allowed { required_actions, deletion_scheduled_for }, Denied(DenialReason)}
// DenialReason::into_error(now) -> AuthError (email_verification_required, account_locked + Retry-After, account_suspended, account_disabled)

// authn-admin (ADM-03)
async fn change_status(&self, ctx: &RequestContext, user: UserId, change: &StatusChange) -> Result<StatusTransition, AuthError>
async fn change_status_in_tx(&self, conn: &mut PgConnection, ctx: &RequestContext, user: UserId, change: &StatusChange) -> Result<StatusTransition, AuthError>
fn check_transition(from: AccountStatus, to: AccountStatus, email_verified: bool) -> Result<(), TransitionError>

// Diğer modüller (bildirim adı/dili, PWD-04 girdileri)
async fn profile_of(&self, user: UserId) -> Result<Option<ProfileView>, AuthError>

// Arka plan işleri (authn-server zamanlar; çoklu instance güvenli)
async fn purge_unverified_accounts(&self, max: u32) -> Result<u64, AuthError>        // ACC-05
async fn purge_due_deletions(&self, max: u32) -> Result<PurgeReport, AuthError>      // ACC-09
async fn release_expired_locks(&self, max: u32) -> Result<u64, AuthError>            // ACC-06
async fn purge_expired_reservations(&self, max: u32) -> Result<u64, AuthError>       // ACC-07
async fn sync_terms_versions(&self) -> Result<usize, AuthError>                       // açılışta (ACC-11)
async fn drain_background_jobs(&self)                                                  // zarif kapanış (OPS-07)

// Server'ın uygulayacağı / kaydedeceği trait'ler
#[async_trait] trait OrganizationOwnership: Send + Sync {
    async fn sole_owner_organizations(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<OrgId>, AuthError>;
}
#[async_trait] trait AccountErasureHook: Send + Sync {   // silme transaction'ında, users satırı silinmeden önce
    async fn before_erasure_in_tx(&self, conn: &mut PgConnection, user: UserId) -> Result<(), AuthError>;
}
```

## HTTP endpoint'leri

| Yöntem | Yol | Kimlik doğrulama | Gereksinim |
|--------|-----|------------------|------------|
| `POST` | `/v1/signup` → `{status, registration}` + `Set-Cookie: __Host-authn_registration` | — | ACC-01/02/03/12/13 |
| `POST` | `/v1/email/verification/resend` (`email`, isteğe bağlı `registration`) | — | ACC-04 |
| `POST` | `/v1/email/verify` (`token` [+ `password` \| `new_password` + `accepted_terms`] veya `code` + `registration`/çerez) | — (oturum varsa kullanılır) | ACC-04, ADR 0002 |
| `POST` | `/v1/email/change/confirm` (`token`) | **oturum** (hesap sahibi) | ACC-07, ADR 0002 |
| `POST` | `/v1/email/change/revert` (`token`) | — | ACC-07 |
| `POST` | `/v1/account/deletion/cancel` (`token`) | — | ACC-09 |
| `GET` | `/v1/terms` | — | ACC-11 |
| `GET`, `PATCH` | `/v1/me/profile` | oturum | ACC-08 |
| `POST` | `/v1/me/email/verification` | oturum | ACC-04 |
| `POST` | `/v1/me/email/verify` (`code`) | oturum | ACC-04/05 |
| `POST` | `/v1/me/email` (`new_email`) | oturum + step-up | ACC-07 |
| `POST` | `/v1/me/email/confirm` (`code`) | oturum | ACC-07 |
| `DELETE` | `/v1/me` | oturum + step-up | ACC-09 |
| `GET` | `/v1/me/deletion` | oturum | ACC-09 |
| `POST` | `/v1/me/deletion/cancel` | oturum | ACC-09 |
| `GET` | `/v1/me/export` | oturum + step-up | ACC-10 |
| `GET`, `POST` | `/v1/me/consents` | oturum | ACC-11 |

Link token'ları her zaman `POST` gövdesiyle gelir (e-postadaki link bir ön yüz sayfasına gider, sayfa token'ı gönderir): link önizleme botları token tüketemez. Doğrulama sayfası önce yalnızca `{token}` gönderir (kaydı yapan tarayıcıda çerez yeter); `403 registration_confirmation_required` dönerse kullanıcıya "kayıtta seçtiğiniz şifreyi girin" (`password`) ve "kaydı ben yapmadım / yeni şifre belirle" (`new_password`, zorunluysa `accepted_terms`) seçeneklerini sunar. Mobil istemci kayıt yanıtındaki `registration` değerini saklar ve kodla birlikte gönderir. Tüm gövdeler `SecretJson` ile okunur — ayrıştırma hataları gönderilen değeri (şifre, token, adres, ad) loglara kopyalamaz. `GET /v1/me` (SES-16) authn-session'a aittir; `DELETE /v1/me` ile aynı yolda birleşir (test: `acc_01_router_merges_with_other_module_routes`).

## Konfigürasyon (`[account]`, `crates/authn-core/src/config/account.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `verification.link_ttl` / `code_ttl` / `code_max_attempts` | `24h` / `15m` / 5 | ACC-04; kayıtlarda deneme sayısı kaydın ömrü boyuncadır (yeniden gönderme sıfırlamaz) |
| `verification.resend_cooldown` / `max_sends_per_hour` | `60s` / 5 | adres başına |
| `verification.code_attempts_per_email` | 10 / saat | **yeni** — yeniden gönderme deneme hakkını çoğaltmasın |
| `verification.verify_per_ip` / `resend_per_ip` | 30 / saat, 20 / saat | **yeni** |
| `unverified_login` | `block` | `limited` → `verify_email` zorunlu adımı |
| `unverified_purge_after` | `7d` | ACC-05; kayıt ömrü ve kayıt tutamacı çerezinin `Max-Age`'i |
| `email_change_revert_ttl` | `7d` | geri alma linki + eski adres rezervasyonu |
| `deletion_grace_period` | `30d` | ACC-09 |
| `disposable_domains_file` | yok (kapalı) | ACC-12; açılışta okunur, okunamazsa servis başlamaz |
| `registration_captcha` | `risk_based` | ACC-13 |
| `registration_per_ip` | 10 / saat | |
| `registration_captcha_free_per_ip` | 3 / saat | **yeni** — `risk_based` eşiği |
| `registration_notice_per_email` | 3 / gün | e-posta bombardımanı koruması; doğrulanmamış adrese ek kayıtları da sınırlar |
| `email_change_per_user` | 5 / gün | **yeni** |
| `link_actions_per_ip` | 30 / saat | **yeni** — onay/geri alma/iptal linkleri |
| `display_name_max_chars` | 64 (≤ 128) | **yeni** |
| `require_terms_acceptance` / `reaccept_terms_on_new_version` | `false` / `true` | ACC-11 |
| `terms[]` | boş | **yeni** — `{document, version, url, published_at, requires_reacceptance}` |
| `export_per_user` | 2 / gün | ACC-10 |

Ayrıca `session.step_up_max_age` (step-up penceresi) ve `protect.captcha.fail_open` kullanılır. `config/example.toml` `[account]` yorumları güncellendi.

## Hata kodları (`crates/authn-core/src/error/codes/account.rs`)

`invalid_email`, `email_domain_not_allowed`, `invalid_display_name`, `invalid_time_zone`, `email_unchanged`, `email_already_verified`, `email_verification_required`, `account_locked`, `account_suspended`, `account_disabled`, `account_status_transition_not_allowed`, `account_deletion_blocked_last_owner`, `account_deletion_not_scheduled`, `terms_acceptance_required`, `terms_version_not_current`, `email_change_revert_conflict`, `registration_confirmation_required` (403), `registration_password_mismatch` (403) — son ikisi yalnızca geçerli bir e-posta linkine sahip olana döner. Ortak kodlar: `invalid_or_expired_token`, `invalid_code`, `too_many_attempts`, `rate_limited`, `step_up_required`; CAPTCHA için `captcha_required` / `captcha_failed` (authn-protect).

## Migration'lar

- `1200_account_lifecycle.sql` — `account_deletions.previous_status`: iptalde dönülecek durum (doğrulanmamış hesap iptalle `active` olamaz); `email_reservations`: e-posta değişikliğinden sonra eski adres geri alma süresince yalnızca eski sahibine ayrılır (kaskad + temizlik işi).
- `1201_pending_registrations.sql` — `pending_registrations`: kayıt başına gönderilen şifre hash'i, profil, onaylar; link/kod/tutamacın yalnızca hash'i; deneme sayaçları; ömür (`unverified_purge_after`). Tamamlanınca hesabın tüm kayıtları silinir (ADR 0002).

## Güvenlik notları

- **Hesap varlığı sızmaz (ACC-02):** kayıt, doğrulamayı yeniden gönderme ve e-posta değişikliği talebi; hesaba bakmadan önceki her şeyi eşzamanlı yapar (rate limit, CAPTCHA, doğrulama, şifre politikası, Argon2 hash'i) ve hesaba bağlı kısmı sınırlı bir arka plan kuyruğunda yürütür. Kuyruk doluysa `503` — bu karar da hesaba bakılmadan verilir. Kodla doğrulama bilinmeyen adres, yanlış, süresi dolmuş ve kilitlenmiş kodu aynı `invalid_code` ve en az `code_failure_floor` (250 ms) süreyle yanıtlar. Zamanlama testi üretim Argon2 parametreleriyle çalışır.
- **Ön-ele geçirme (pre-hijacking, ADR 0002):** kayıt kimlik bilgisi yazmaz; her kaydın şifresi kendi linkine, koduna ve kaydı yapan istemcinin tutamacına bağlı bekler. Link yalnızca tutamaçla (kaydı yapan tarayıcı), o kayıtta seçilen şifreyle ya da posta kutusu sahibinin aynı adımda seçtiği **yeni** şifreyle tamamlanır; kod yalnızca tutamaçla. Aynı adrese ikinci kayıt hiçbir şeyi değiştirmez (ayrı kayıt; doğrulanmış adreste yalnızca bildirim). Tamamlama tek transaction'da hesabın tüm diğer kayıtlarını siler, tüm oturumları ve güvenilir cihazları kapatır. Kayıtla oluşan doğrulanmamış hesabın şifresi yoktur: şifreyle giriş yapılamaz, sıfırlama gönderilmez. Doğrulanmamış hesapta şifre sıfırlama / magic link / admin işaretlemesi adresi posta kutusu sahibi için doğrular, kanıtlanmamış şifreyi siler (`MailboxProof`).
- **E-posta değişikliği linki hesap sahibine bağlı (ACC-07, ADR 0002):** link onayı hesap sahibinin oturumunu ister; aksi hâlde istenmeyen bir "adresinizi onaylayın" e-postasına tıklayan kişi, adresini saldırganın (şifreli, passkey'li) hesabına bağlamış olurdu. Oturumsuz istek token'a bakmadan `unauthenticated`, başka kullanıcının oturumu `invalid_or_expired_token` alır (link tüketilmez). Bekleyen değişiklik şifre sıfırlama/değiştirme, "tümünü kapat", "bu ben değilim", refresh token yeniden kullanımı ve admin/acil iptallerle ölür (geri alma linkleri korunur).
- **Homograf / görünmez karakterler (ACC-03):** e-posta yerel kısmı ve IDN alan adı etiketleri UTS #39 "orta derecede kısıtlayıcı" profilini sağlamalı; görünen adlarda biçim karakterleri (ZWJ/ZWNJ, bidi), emoji, sembol, 2'den fazla birleşik işaret, karışık alfabe ve ayrılmış adların (`admin`, `support`, `security`…) karıştırılabilir iskeletleri reddedilir.
- **Token'lar:** link 256 bit, yalnızca SHA-256 hash'i; kod HMAC ile, kod başına 5 deneme + adres başına saatlik toplam; tüketim atomik (eşzamanlı kullanımda tam olarak biri başarılı — testli); link/kod gönderildiği adrese bağlı (`target`): adres değişirse eski doğrulama işe yaramaz.
- **E-posta değişikliği (ACC-07):** yeni adresin kayıtlı olup olmadığı talep edene sızmaz; onayda kullanıcının adresine gönderilmiş tüm token'lar (şifre sıfırlama, magic link, giriş kodu, "bu ben değilim", e-posta OTP…) iptal edilir; eski adres rezerve edilir (saldırgan eski adresle hesap açıp geri almayı engelleyemez); geri almada yalnızca **daha sonraki** değişikliklerin geri alma linkleri iptal edilir (daha önceki linkler geçerli kalır ve geri almayla terk edilen adres onlar için rezerve kalır), planlanmış silme iptal edilir, tüm oturumlar ve güvenilir cihazlar kapanır, şifre rastgele kullanılamaz bir hash'le değiştirilir (`must_change_password` = true) — saldırgan bildiği şifreyle giremez, sahip restore edilen adresle sıfırlar. Adres kontrol-yaz dizileri adres başına advisory lock (sıralı, kilitlenmesiz) altında.
- **Personel işlemleri kullanıcının görünümünde (K-14):** `MailboxProof::Administrator` ile yazılan `account.email_verified` ve `account.status_changed` olayları `Actor::System`'dir ve adminin IP/user-agent'ını taşımaz (yalnızca `request_id`; authn-admin'in aynı transaction'daki `admin.action` olayıyla ilişkilendirmek için). Aksi hâlde authn-audit IP'yi kullanıcının kişisel verisi olarak saklar ve `/v1/me/security-events` adminin ağını gösterirdi. Gerçek aktör authn-admin'in `admin.*` olayındadır (wave 1'deki `passkey.removed` deseniyle aynı). Testler: `adm_08_admin_mailbox_proof_shows_no_staff_identity_to_the_user`, authn-oidc-client `adm_03_admin_verification_shows_no_staff_identity_in_the_users_view` (gerçek audit sink ve kullanıcı görünümü). Aynı kural personelin durum değişikliklerinde de geçerlidir (`change_status[_in_tx]` ile askıya alma/kilit açma: istemci IP/UA yalnızca aktör bir kullanıcı (audit sink veriyi o kullanıcıya yazar) veya anonim ise eklenir; wave 2A denetimi, test `adm_08_staff_status_change_shows_no_staff_network_to_the_user`).
- **Sosyal hesap sağlama (K-33, ADR 0002):** `provision_verified_user_in_tx` yalnızca çağıranın posta kutusu kontrolünü kanıtladığı adres için (sağlayıcının doğruladığı e-posta) `active` + doğrulanmış hesap açar; adres kilidi (kayıt/e-posta değişikliğiyle aynı) altında var olan hesaba **dokunmaz** (`Existing`), rezerve adresi vermez (`Reserved`), ACC-12 listesini uygular; profil adı ACC-03 kurallarından geçmezse saklanmaz.
- **Durum makinesi (ACC-06):** `active` ⇒ doğrulanmış e-posta değişmezi tabloda; askıdan/silmeden dönüş doğrulamayı atlatamaz. Her geçiş audit'lenir; `pending_deletion`'dan silme dışında çıkış planlanmış silmeyi kapatır. `pending_deletion` ve `deleted` yalnızca silme akışı ve temizlik işleriyle girilir; `change_status` / `change_status_in_tx` bunları reddeder.
- **Silme (ACC-09):** step-up, impersonation ve API anahtarı ile yapılamaz; kalıcı silme son sahiplik kontrolünü tekrar yapar; audit takma adlaştırması aynı transaction'da.
- **Dışa aktarma (ACC-10):** sır içermez; dışa aktarıcı yazma yapamaz; bir bölüm hata verirse tüm dışa aktarma başarısız olur.
- **Loglar:** e-posta adresleri yalnızca maskeli; istek gövdesi ayrıştırma hataları değer içermez; `SignupInput`, `ProfileView`, `VerificationProof` `Debug` çıktıları maskeli/redakte.
- **Kanıtlanmamış adrese giden e-postalar:** kayıt sonrası doğrulama, doğrulamayı yeniden gönderme ve e-posta değişikliğinde yeni adrese giden doğrulama e-postaları görünen adı **taşımaz** (herkes servisi herhangi bir adrese e-posta göndermeye zorlayabilir; görünen ad "Merhaba <ad>," ve `To:` adı olarak saldırganın metnini gerçek bir servis e-postasına taşırdı).
- **Arka plan kuyruğu:** her iş, panik veya iptal durumunda da yuvasını geri verir (`PendingSlot` drop korumasıyla); başarısız bir iş kalıcı `503`'e yol açamaz.

### Güvenlik incelemesi (2026-11-01)

Düzeltilen bulgular (her biri regresyon testli):

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| Yüksek | Ele geçirilmiş (step-up yapılmış) oturumla adres iki kez değiştirilip (sahip → saldırgan1 → saldırgan2) saldırgan1'e giden geri alma linki kullanılınca **tüm** geri alma linkleri iptal ediliyordu: sahibin linki ölüyor, hesap kalıcı olarak saldırganda kalıyordu. | Geri alma yalnızca kendisiyle aynı anda veya sonra verilmiş geri alma linklerini iptal eder (`(created_at, id) >=`); terk edilen adres, onu hedefleyen daha eski bir link varsa o linkin süresince rezerve edilir. | `acc_07_intermediate_revert_cannot_cancel_the_owners_revert`, `acc_07_address_left_by_a_revert_stays_reserved_for_earlier_links` |
| Orta | Oturum açmış saldırgan için hesap varlığı sızıntısı: (a) kayıtlı bir adrese değişiklik talebi önceki bekleyen değişiklik link/kodunu iptal etmiyordu (boş adrese talep ediyordu) — saldırganın kendi adresine aldığı eski link çalışıyorsa hedef adres kayıtlıdır; (b) kodla onayda boş adreste kod 5 denemede kilitlenip `too_many_attempts`, kayıtlı adreste ise hep `invalid_code` dönüyordu. | Kullanılamayan adres dalında da `email_change` / `email_change_code` iptal edilir; tüm kod hataları `invalid_code` + `code_failure_floor`. | `acc_07_request_for_taken_address_ends_the_previous_pending_change`, `acc_07_code_attempts_do_not_reveal_whether_the_address_is_taken` |
| Orta | `change_status` / `change_status_in_tx` (authn-admin) hesabı `pending_deletion` (planı/iptal linki olmadan — hiç temizlenmez) veya `deleted` (kişisel veriyi ve adresi tutan, hiç silinmeyen satır) durumuna sokabiliyordu (ACC-09/KVKK). | Bu iki durum genel durum API'sinde reddedilir; yalnızca silme akışı ve temizlik işleri girer. | `acc_06_deletion_statuses_are_not_settable_through_the_status_api` |
| Düşük | Herkesin tetikleyebildiği doğrulama e-postalarında (kayıt, yeniden gönderme, yeni adrese e-posta değişikliği) kayıt olanın seçtiği görünen ad "Merhaba <ad>," ve `To:` adı olarak gönderiliyordu (içerik enjeksiyonu / oltalama). | Kanıtlanmamış adrese giden e-postalarda görünen ad boş. | `acc_04_mail_to_unproven_address_omits_the_chosen_display_name` |
| Düşük | `EmailAddress::normalized` sabit nokta değildi: küçük harfe çevirince uzayan yerel kısım (32 × `İ` = 64 bayt → 96 bayt) kabul ediliyor, benzersizlik biçimi yeniden ayrıştırılamıyordu (fuzz hedefi bu durumda panikler; yerel kısım RFC sınırını aşar). | Küçük harfli yerel kısım da aynı kurallarla doğrulanır. | core `acc_03_local_part_that_grows_when_lowercased_is_rejected` |
| Düşük | Arka plan işi paniklerse kuyruk sayacı geri verilmiyordu; birikince kayıt/yeniden gönderme/e-posta değişikliği kalıcı `503` olurdu. | Drop korumalı yuva. | `background::tests::acc_02_panicking_job_releases_its_queue_slot` |

### Ön-ele geçirme incelemesi (2026-11-01, ADR 0002)

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| Yüksek | **Saldırgan ikinci:** kurbanın kaydı ile doğrulaması arasında aynı adrese tekrar kayıt, şifreyi saldırganınkiyle değiştiriyordu ("son kayıt olan kazanır"); kurban en yeni linke tıklayınca hesap saldırganın şifresiyle doğrulanıyordu. | Kayıt kimlik bilgisi yazmaz; her kayıt kendi kimlik bilgisini kendi link/kod/tutamacına bağlı tutar; ikinci kayıt hiçbir şeyi değiştirmez. | `acc_02_attacker_second_cannot_overwrite_or_inherit_the_victims_registration` |
| Yüksek | **Saldırgan önce:** saldırganın kaydının linkine kurban tıklayınca hesap saldırganın şifresiyle doğrulanıyordu (link, tıklayanın şifreyi seçtiğini kanıtlamıyordu). | Link yalnızca tutamaç, seçilen şifre veya yeni şifreyle tamamlanır; yalnızca link → `registration_confirmation_required`. | `acc_02_attacker_first_link_alone_never_activates_the_attackers_password`, `acc_02_attacker_first_then_victim_registers_and_gets_own_credentials` |
| Yüksek | **E-posta değişikliğiyle ön-ele geçirme:** saldırgan kendi hesabının adresini kurbanın adresine değiştirmeyi isteyip kurban linke tıklayınca, saldırganın kimlik bilgileriyle kurbanın adresine doğrulanmış hesap oluşuyordu (passkey'ler sonraki şifre sıfırlamadan da sağ çıkar). | Link onayı hesap sahibinin oturumunu ister. | `acc_07_email_change_link_requires_the_account_holders_session` |
| Orta | **Kod, istemciye bağlı değildi:** `e-posta + kod` herhangi bir istemciden kabul ediliyordu; kod tahmini/oltalama hesabı saldırganın şifresiyle etkinleştirirdi. Yeniden gönderme kod denemesini sıfırlıyordu. | Kod yalnızca kaydın tutamacıyla; kayıt ömrü boyunca 5 deneme; adres başına toplam bütçe kayıtlar arasında ortak. | `acc_04_code_needs_the_registering_clients_handle_and_cannot_be_replayed`, `acc_04_resending_does_not_multiply_code_guesses`, `acc_04_code_budget_is_per_address_across_registrations` |
| Orta | **Oturumla verilen doğrulama linki** (`limited` mod) yalnız başına hesabı doğruluyordu (saldırganın şifreli doğrulanmamış hesabı, kurbanın tıklamasıyla doğrulanırdı). | Link, oturum sahibi / hesabın şifresi / yeni şifre ister; yeni şifre tüm oturumları kapatır. | `acc_04_session_issued_link_needs_the_account_holder` |
| Orta | **Bekleyen e-posta değişikliği** şifre sıfırlama ve "tümünü kapat"tan sağ çıkıyordu (önceden kabul edilen risk). | `AccountAwareSessionRevoker` (port dekoratörü) ve `revoke_pending_email_changes_in_tx`. | `acc_07_pending_email_change_ends_on_reset_and_sign_out_everywhere`, `acc_07_reset_keeps_the_revert_link_of_a_completed_change` |
| Orta | **Doğrulanmamış hesapta şifre sıfırlama** adresi doğrulamıyor, bekleyen kayıtları bırakıyordu. | Sıfırlama (dekoratör, `PasswordReset`) adresi doğrular, kayıtları siler; şifresiz kanıtlar kanıtlanmamış şifreyi de siler. | `acc_05_password_reset_on_unverified_account_hands_it_to_the_mailbox_owner`, `acc_05_rolled_back_reset_changes_nothing`, `acc_05_passwordless_mailbox_proof_removes_an_unproven_password` |
| Düşük | İlk kayıt olan, hesabın saklanan adres yazımını belirliyordu. | Tamamlama, kazanan kaydın yazımını yazar. | `acc_02_attacker_first_then_victim_registers_and_gets_own_credentials` |

Kabul edilen riskler (gerekçeli):

- **Kod oltalama ve kod tahmini** (ADR 0002 "Artık riskler"): kurbandan e-postadaki kodu okuması istenirse saldırgan kendi tutamacıyla kazanır (sırrın gönüllü verilmesi); tahmin hedeflenen adres başına günde ≈ 1,5·10⁻⁵.
- **Hedefli kayıt DoS'u:** adres başına günlük kayıt sınırı ve hesap başına 10 canlı kayıt, kurbanın aynı gün içindeki kaydının düşmesine yol açabilir; kurban gelen kutusundaki herhangi bir link + yeni şifre ile veya yeniden göndermeyle tamamlar.
- **Kilit sırası:** temizlik işi `account_deletions` satırını sonra `users` satırını, iptal/geri alma ise önce `users` sonra `account_deletions` satırını kilitler; kayıt tamamlama (kayıt satırı → kullanıcı) ile şifre sıfırlama dekoratörü (kullanıcı → kayıt satırları) de çakışabilir. Eşzamanlı rastlaşmada PostgreSQL kilitlenmeyi tespit edip bir transaction'ı geri alır; tutarsız durum oluşmaz, iş bir sonraki çalışmada yeniden dener, kullanıcı isteği `500` alıp tekrarlayabilir.
- **`GET /v1/me/export`:** GET olduğundan siteler arası üst düzey gezinme (SameSite=Lax) kurbanın günlük dışa aktarma hakkını (2/gün) tüketebilir; veri yalnızca kurbanın tarayıcısına iner ve step-up gerekir. Yöntem sözleşmede GET olarak tanımlı; değiştirilmedi.
- **Geri alma sonrası diğer modüllerin faktörleri** (passkey, TOTP, sosyal kimlik) — aşağıdaki "Bilinen sınırlamalar"a bakın.

### Wave 2A bağımsız denetimi (2026-11-04)

Yazarın K-02 / K-14 testleri, düzeltme satırları geçici olarak geri alınarak **eski davranışta başarısız oldukları** doğrulandı: rezervasyon kontrolü kaldırılınca `acc_07_provisioning_never_takes_an_existing_or_reserved_address`, `MailboxProof::Administrator` eski aktör/bağlamına döndürülünce `adm_08_admin_mailbox_proof_shows_no_staff_identity_to_the_user` başarısız oldu (`acc_07_reservation_lookup_on_the_given_connection` yalnızca okuma API'sini sınar; geri almayla etkilenmez). K-41 sorguları eski sorgularla birebir karşılaştırıldı (koşullar, `FOR UPDATE SKIP LOCKED`, sıralama aynı).

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| Orta | **K-14 eksikti:** personelin durum değişiklikleri (authn-admin askıya alma / askıdan çıkarma / kilit açma → `change_status[_in_tx]`, `Actor::System`) adminin IP'sini ve user-agent'ını kullanıcının kendi `account.status_changed` olayına yazıyordu; audit sink konu sahibinin olayındaki istemci verisini **kullanıcının** kişisel verisi olarak saklar ve kullanıcının olay listesi onu (maskeli) gösterir. | `lifecycle::transition_event`: istemci IP/UA yalnızca aktör bir kullanıcıysa (`Actor::User`; audit sink veriyi aktörün takma adına yazar, konununkine değil) veya anonim istekse (kullanıcının kendi linki/kodu) eklenir; sistem/personel, servis hesabı ve API anahtarı aktörlerinde (sink veriyi **konunun** takma adına yazardı) yalnızca `request_id` kalır (authn-admin'in `admin.action` olayıyla ilişkilendirme için). | `adm_08_staff_status_change_shows_no_staff_network_to_the_user` (düzeltme olmadan `left: Some(198.51.100.7)` ile başarısız) |

## authn-server / Dalga B'nin bağlaması gerekenler

0. **`SessionRevoker` sarmalama (ADR 0002):** `let revoker: Arc<dyn SessionRevoker> = Arc::new(AccountAwareSessionRevoker::new(session_revoker.clone(), account.clone()));` — sarılmış portu authn-password, authn-session (kendi "tümünü kapat"ı dahil), authn-mfa, authn-org, authn-admin ve authn-protect'e verin; `AccountServiceDeps::sessions`'a **iç** revoker'ı verin (döngüsel referans olmasın). `RevocationReason::PasswordReset` yalnızca e-postayla gelen sıfırlamanın tamamlanmasında kullanılmalıdır (adresi doğrular).
1. `AccountServiceDeps`: `hasher = crypto.passwords`, `otp = crypto.otp`, `captcha = authn-protect CaptchaVerifier`, `password_validator = password_service.validator()`, `notifier`, `audit`, `events` (authn-audit/notify), `sessions = authn-session SessionRevoker` (sarılmamış), `exporters = [mfa, webauthn, session, oidc-client, org, protect, audit…]` (her modülün `DataExporter`'ı; bölüm adları benzersiz, `account` ayrılmış), `ownership = authn-org üzerinden OrganizationOwnership`.
2. `impl FromRef<AppState> for AccountService`, `.merge(authn_account::router::<AppState>())` — `/v1/me*` **ve `/v1/email/change/confirm`** oturum katmanının (ve CSRF'in) arkasında; oturum katmanı `/v1/email/verify` için de, varsa, `Principal` eklemelidir (yoksa istek kimliksiz işlenir); `openapi.rs`'e `authn_account::AccountApi`.
3. Açılışta `sync_terms_versions()`; zamanlanmış işler: `purge_unverified_accounts`, `purge_due_deletions`, `release_expired_locks`, `purge_expired_reservations` (ör. 5–15 dakikada bir, `max` = 100–500); zarif kapanışta `drain_background_jobs()`.
4. authn-password `ProfileLookup` adaptörü: `profile_of(user)` → `ProfileHints { display_name, locale }`.
4a. `account.register_erasure_hook(Arc::new(oidc.erasure_hook()))` (K-35: Apple token iptali silme transaction'ında kuyruğa alınır). Sarılmış revoker `revoke_everything_except`'i de iletir (K-10, acil "çağıran hariç tümünü kapat"; test `acc_07_emergency_revoke_except_caller_ends_pending_email_changes`).
5. authn-session / authn-oidc-client / authn-admin — posta kutusu kanıtları: magic link (SES-18) ve giriş kodu (SES-19) doğrulanmamış bir hesaba oturum açmadan **önce**, aynı transaction'da `confirm_mailbox_control_in_tx(conn, Some(ctx), user, MailboxProof::Passwordless)`; sosyal girişte sağlayıcının doğruladığı e-postayla doğrulanmamış hesaba bağlama yapılacaksa aynı çağrı; admin "e-posta doğrulandı" işaretlemesi (ADM-03) `MailboxProof::Administrator { admin }`. **Hiçbir modül `pending_verification` bir hesaba kimlik bilgisi (sosyal kimlik, passkey) eklememelidir** ("Trojan identifier").
6. authn-session: girişte doğru şifreden sonra `assess_login`; `Denied` → `DenialReason::into_error`; `Allowed { required_actions }` → SES-22 challenge'ı (`verify_email` tamamlanırken kod doğrulaması için challenge'a bağlı bir akış gerekiyorsa `verify_own_email_code` sınırlı oturumla kullanılabilir; `accept_terms` için `accept_terms(ctx, user, …)`).
7. authn-admin: askıya alma / kilit / devre dışı → `change_status_in_tx` + aynı transaction'da `SessionRevoker`; "e-posta doğrulandı işaretleme" → `confirm_mailbox_control_in_tx(…, MailboxProof::Administrator { admin })`.
8. Ön yüz: doğrulama sayfası ve mobil akış yukarıdaki "HTTP endpoint'leri" notuna göre; e-posta değişikliği onay sayfası oturum açılmamışsa önce girişe yönlendirir.

## Bilinen sınırlamalar / SHOULD notları

- **`limited` mod (ACC-05) ve kayıt:** kayıtla oluşan hesabın doğrulanana kadar kimlik bilgisi olmadığından şifreyle "sınırlı" giriş yapılamaz; kayıt sonrasındaki sınırlı erişim, kaydı yapan istemcinin tutamaçla yaptığı işlemlerdir (kodla doğrulama, yeniden gönderme). Politika, kimlik bilgisi başka yoldan gelmiş doğrulanmamış hesaplar için `assess_login` ile aynen uygulanır (ADR 0002).
- Doğrulanmadan şifresini unutan kayıt sahibi şifre sıfırlama değil, doğrulama linkindeki "yeni şifre" yolunu kullanır (sıfırlama yalnızca var olan şifreyi değiştirir).
- Geri alma (ACC-07) oturumları ve şifreyi sıfırlar ancak saldırganın arada eklemiş olabileceği passkey / TOTP / sosyal kimlikleri kaldırmaz (başka modüllerin tabloları). Kullanıcıya geri alma sonrası güvenlik ayarlarını gözden geçirmesi söylenmelidir; istenirse server bir "e-posta değişikliği geri alındı" kancası ile bu modülleri çağırabilir.
- `RegistrationAttempt` bildirimi, e-posta değişikliğinde "adresiniz başka bir hesap için kullanılmak istendi" uyarısı olarak da kullanılır; şablon metni wave 1'de geneldir.
- Geri alma, geri yüklenen adrese aynı transaction'da (outbox) `email_change_reverted` bildirimi gönderir (K-40; şablon "şifrenizi yeniden belirleyin" bağlantısını ve güvenlik ayarlarını gözden geçirme uyarısını içerir; test `acc_07_revert_notifies_the_restored_address`). Sıfırlama token'ı otomatik üretilmez (şifre sıfırlama authn-password'dadır); yanıt `password_reset_required: true` döner ve ön yüz `POST /v1/password/forgot` çağırır.
- Unicode büyük/küçük harf katlaması Rust `to_lowercase` + NFKC'dir (tam Unicode case folding değil); Yunanca son sigma gibi sınır durumlarda iki yazım farklı hesap sayılabilir.
- Görünen adlarda ZWNJ reddedilir (Farsça gibi dillerde gerekebilir) ve emoji kabul edilmez — güvenlik lehine bilinçli tercih.
- Uygulanmayan MUST yoktur.

## Komutlar

```bash
cargo test -p authn-account --all-features
cargo clippy -p authn-account --all-targets --all-features -- -D warnings
cargo fmt -p authn-account
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
