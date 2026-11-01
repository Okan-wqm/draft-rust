# authn-account

Kayıt, e-posta doğrulama, hesap durum makinesi, profil, e-posta değişikliği, hesap silme, kişisel veri dışa aktarma (`DataExporter` toplayıcısı) ve onay (kullanım şartları / gizlilik politikası) kayıtları. KVKK/GDPR notları: [`docs/compliance/kvkk-gdpr.md`](../../docs/compliance/kvkk-gdpr.md) (DOC-07).

## Sahip olunan gereksinimler

| Kimlik | Uygulama | Testler (örnek) |
|--------|----------|-----------------|
| ACC-01 | `AccountService::signup`, `POST /v1/signup` — şifre `PasswordValidator` portuyla, hash `authn-crypto` Argon2id ile | `signup.rs`: `acc_01_*` |
| ACC-02 | Kaydın hesaba bağlı kısmı arka plan işinde; yanıt her adres için aynı (durum, gövde, süre); mevcut sahibe "biri kayıt olmaya çalıştı" e-postası (adres başına sınırlı) | `acc_02_existing_address_gets_identical_status_and_body`, `acc_02_signup_timing_does_not_reveal_existing_accounts`, `acc_02_registration_notices_are_throttled_per_address`, `acc_02_unverified_reregistration_replaces_squatted_password` |
| ACC-03 | `authn_core::domain::EmailAddress` sertleştirmesi (karışık alfabe, birleşik işaret dizileri, özel TLD'ler, `normalized` sabit nokta); görünen ad için UTS #39 karıştırılabilir/karışık alfabe kontrolü (`profile::normalize_display_name`) | core `acc_03_*`, `profile::tests::acc_03_*`, `acc_03_addresses_differing_only_in_case_or_width_are_the_same_account` |
| ACC-04 | Link (24 sa) + 6 haneli kod (15 dk, 5 deneme) aynı grupta, adrese bağlı, tek kullanımlık; tekrar gönderme 60 sn bekleme + saatlik limit; adres başına toplam kod denemesi | `verification.rs`: `acc_04_*` (brute force kilidi, yarış, tek kullanım, zamanlama/gövde eşitliği) |
| ACC-05 | `assess_login` (`block` / `limited` → `verify_email` zorunlu adımı), `purge_unverified_accounts` (7 gün) | `acc_05_*` |
| ACC-06 | `lifecycle::check_transition` (tek tablo), `apply_transition` (satır kilidi + CAS + audit), `change_status` / `change_status_in_tx`, `release_expired_locks` | `lifecycle::tests::acc_06_*` (7×7×2 kapsamlı tablo, proptest), `lifecycle.rs` |
| ACC-07 | Step-up ile talep, yeni adrese link + kod, eski adrese 7 günlük geri alma linki, eski adres rezervasyonu, geri almada oturum/güvenilir cihaz iptali + şifre sıfırlama zorunluluğu | `email_change.rs`: `acc_07_*` |
| ACC-08 | `GET/PATCH /v1/me/profile` (görünen ad, `tr`/`en`, IANA saat dilimi) | `profile.rs`, `profile::tests::acc_08_*` |
| ACC-09 | `DELETE /v1/me` (step-up) → `pending_deletion` + 30 gün; oturumla veya linkle iptal; `purge_due_deletions` (kaskad silme + audit takma adlaştırma); son sahip engeli (`OrganizationOwnership`) | `deletion.rs`: `acc_09_*` |
| ACC-10 | `GET /v1/me/export` (step-up, rate limit): tüm `DataExporter`'lar tek `REPEATABLE READ, READ ONLY` transaction'ında | `export.rs`: `acc_10_*` |
| ACC-11 | `terms_versions` senkronu (`account.terms`), `consents` (zaman, IP, UA), `terms_requirements` / `accept_terms` (SES-22) | `consent.rs`: `acc_11_*` |
| ACC-12 | `DisposableDomains` (dosyadan, alt alan adları dahil; varsayılan kapalı) | `acc_12_*` |
| ACC-13 | `CaptchaVerifier` ile `always` / `risk_based` (IP başına eşik) / `never` | `acc_13_*` |
| DOC-07 | `docs/compliance/kvkk-gdpr.md` | `compliance.rs`: `doc_07_*` (envanter her şema tablosunu kapsar) |

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. Başka modüllerin verisine ihtiyaç duyulan yerde bu crate bir trait tanımlar (`OrganizationOwnership`); uygulamayı `authn-server` verir. Yeni harici bağımlılık: yok (`tokio-util` ve `http` workspace'te zaten vardı; crate `Cargo.toml`'una eklendi).

## Genel API

```rust
// Kurulum (authn-server)
AccountService::new(AccountServiceDeps { pool, clock, hasher, otp, rate_limiter, captcha,
    password_validator, notifier, audit, events, sessions, exporters, ownership },
    AccountServiceSettings::from_app_config(&config)?)? -> AccountService
authn_account::router::<AppState>()            // AccountService: FromRef<AppState>
authn_account::AccountApi                       // utoipa::OpenApi

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

// Server'ın uygulayacağı trait
#[async_trait] trait OrganizationOwnership: Send + Sync {
    async fn sole_owner_organizations(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<OrgId>, AuthError>;
}
```

## HTTP endpoint'leri

| Yöntem | Yol | Kimlik doğrulama | Gereksinim |
|--------|-----|------------------|------------|
| `POST` | `/v1/signup` | — | ACC-01/02/03/12/13 |
| `POST` | `/v1/email/verification/resend` | — | ACC-04 |
| `POST` | `/v1/email/verify` (`token` veya `email`+`code`) | — | ACC-04 |
| `POST` | `/v1/email/change/confirm` (`token`) | — | ACC-07 |
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

Link token'ları her zaman `POST` gövdesiyle gelir (e-postadaki link bir ön yüz sayfasına gider, sayfa token'ı gönderir): link önizleme botları token tüketemez. Tüm gövdeler `SecretJson` ile okunur — ayrıştırma hataları gönderilen değeri (şifre, token, adres, ad) loglara kopyalamaz. `GET /v1/me` (SES-16) authn-session'a aittir; `DELETE /v1/me` ile aynı yolda birleşir (test: `acc_01_router_merges_with_other_module_routes`).

## Konfigürasyon (`[account]`, `crates/authn-core/src/config/account.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `verification.link_ttl` / `code_ttl` / `code_max_attempts` | `24h` / `15m` / 5 | ACC-04 |
| `verification.resend_cooldown` / `max_sends_per_hour` | `60s` / 5 | adres başına |
| `verification.code_attempts_per_email` | 10 / saat | **yeni** — yeniden gönderme deneme hakkını çoğaltmasın |
| `verification.verify_per_ip` / `resend_per_ip` | 30 / saat, 20 / saat | **yeni** |
| `unverified_login` | `block` | `limited` → `verify_email` zorunlu adımı |
| `unverified_purge_after` | `7d` | ACC-05 |
| `email_change_revert_ttl` | `7d` | geri alma linki + eski adres rezervasyonu |
| `deletion_grace_period` | `30d` | ACC-09 |
| `disposable_domains_file` | yok (kapalı) | ACC-12; açılışta okunur, okunamazsa servis başlamaz |
| `registration_captcha` | `risk_based` | ACC-13 |
| `registration_per_ip` | 10 / saat | |
| `registration_captcha_free_per_ip` | 3 / saat | **yeni** — `risk_based` eşiği |
| `registration_notice_per_email` | 3 / gün | **yeni** — e-posta bombardımanı koruması |
| `email_change_per_user` | 5 / gün | **yeni** |
| `link_actions_per_ip` | 30 / saat | **yeni** — onay/geri alma/iptal linkleri |
| `display_name_max_chars` | 64 (≤ 128) | **yeni** |
| `require_terms_acceptance` / `reaccept_terms_on_new_version` | `false` / `true` | ACC-11 |
| `terms[]` | boş | **yeni** — `{document, version, url, published_at, requires_reacceptance}` |
| `export_per_user` | 2 / gün | ACC-10 |

Ayrıca `session.step_up_max_age` (step-up penceresi) ve `protect.captcha.fail_open` kullanılır. `config/example.toml` `[account]` yorumları güncellendi.

## Hata kodları (`crates/authn-core/src/error/codes/account.rs`)

`invalid_email`, `email_domain_not_allowed`, `invalid_display_name`, `invalid_time_zone`, `email_unchanged`, `email_already_verified`, `email_verification_required`, `account_locked`, `account_suspended`, `account_disabled`, `account_status_transition_not_allowed`, `account_deletion_blocked_last_owner`, `account_deletion_not_scheduled`, `terms_acceptance_required`, `terms_version_not_current`, `email_change_revert_conflict`. Ortak kodlar: `invalid_or_expired_token`, `invalid_code`, `too_many_attempts`, `rate_limited`, `step_up_required`; CAPTCHA için `captcha_required` / `captcha_failed` (authn-protect).

## Migration (`1200_account_lifecycle.sql`)

- `account_deletions.previous_status`: iptalde dönülecek durum (doğrulanmamış hesap iptalle `active` olamaz).
- `email_reservations`: e-posta değişikliğinden sonra eski adres geri alma süresince yalnızca eski sahibine ayrılır (kaskad + temizlik işi).

## Güvenlik notları

- **Hesap varlığı sızmaz (ACC-02):** kayıt, doğrulamayı yeniden gönderme ve e-posta değişikliği talebi; hesaba bakmadan önceki her şeyi eşzamanlı yapar (rate limit, CAPTCHA, doğrulama, şifre politikası, Argon2 hash'i) ve hesaba bağlı kısmı sınırlı bir arka plan kuyruğunda yürütür. Kuyruk doluysa `503` — bu karar da hesaba bakılmadan verilir. Kodla doğrulama bilinmeyen adres, yanlış, süresi dolmuş ve kilitlenmiş kodu aynı `invalid_code` ve en az `code_failure_floor` (250 ms) süreyle yanıtlar. Zamanlama testi üretim Argon2 parametreleriyle çalışır.
- **Ön-ele geçirme (pre-hijacking):** doğrulanmamış bir hesabın adresiyle yeniden kayıt olunursa son kayıt olanın şifresi geçerli olur, önceki oturumlar ve güvenilir cihazlar iptal edilir, eski doğrulama linkleri geçersizleşir. Varsayılan `block` politikası doğrulanmamış hesaba oturum vermez.
- **Homograf / görünmez karakterler (ACC-03):** e-posta yerel kısmı ve IDN alan adı etiketleri UTS #39 "orta derecede kısıtlayıcı" profilini sağlamalı; görünen adlarda biçim karakterleri (ZWJ/ZWNJ, bidi), emoji, sembol, 2'den fazla birleşik işaret, karışık alfabe ve ayrılmış adların (`admin`, `support`, `security`…) karıştırılabilir iskeletleri reddedilir.
- **Token'lar:** link 256 bit, yalnızca SHA-256 hash'i; kod HMAC ile, kod başına 5 deneme + adres başına saatlik toplam; tüketim atomik (eşzamanlı kullanımda tam olarak biri başarılı — testli); link/kod gönderildiği adrese bağlı (`target`): adres değişirse eski doğrulama işe yaramaz.
- **E-posta değişikliği (ACC-07):** yeni adresin kayıtlı olup olmadığı talep edene sızmaz; onayda kullanıcının adresine gönderilmiş tüm token'lar (şifre sıfırlama, magic link, giriş kodu, "bu ben değilim", e-posta OTP…) iptal edilir; eski adres rezerve edilir (saldırgan eski adresle hesap açıp geri almayı engelleyemez); geri almada yalnızca **daha sonraki** değişikliklerin geri alma linkleri iptal edilir (daha önceki linkler geçerli kalır ve geri almayla terk edilen adres onlar için rezerve kalır), planlanmış silme iptal edilir, tüm oturumlar ve güvenilir cihazlar kapanır, şifre rastgele kullanılamaz bir hash'le değiştirilir (`must_change_password` = true) — saldırgan bildiği şifreyle giremez, sahip restore edilen adresle sıfırlar. Adres kontrol-yaz dizileri adres başına advisory lock (sıralı, kilitlenmesiz) altında.
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

Kabul edilen riskler (gerekçeli):

- **Doğrulanmamış kayıtta "son kayıt olan kazanır" (saldırgan ikinci):** kurban kayıt olup henüz doğrulamamışken saldırgan aynı adresle tekrar kayıt olursa şifre saldırganınki olur ve kurban (gelen ikinci) doğrulama linkine tıklarsa hesap saldırganın şifresiyle doğrulanır. Bu, saldırganın *önce* kayıt olduğu (daha yaygın) ön-ele geçirme saldırısına karşı seçilen tasarımın bedelidir. Pencere, kurbanın kaydı ile doğrulaması arasındaki kısa süredir; adres başına günde 3 deneme (`registration_notice_per_email`) ile sınırlıdır; kurban kendi şifresiyle giremeyince şifre sıfırlama tüm oturumları kapatır. Tam çözüm (her kaydın şifresini kendi doğrulama token'ına bağlamak veya şifreyi doğrulama anında belirlemek) akış değişikliği gerektirir; Faz 2'ye bırakıldı.
- **Bekleyen e-posta değişikliği linki (24 sa) şifre sıfırlama / tüm oturumları kapatma sonrasında da çalışır:** bu iptaller authn-password / authn-session'dadır ve account purpose'larını iptal etmez. Onay sonrası eski adrese giden geri alma linki hesabı geri getirir (ve oturumları/şifreyi sıfırlar). İstenirse bu modüller `email_change` / `email_change_code` purpose'larını da iptal edebilir.
- **Kilit sırası:** temizlik işi `account_deletions` satırını sonra `users` satırını, iptal/geri alma ise önce `users` sonra `account_deletions` satırını kilitler; doğrulama linki tüketimi ile doğrulanmamış adrese yeniden kayıt da token satırı / kullanıcı satırı sırasında çakışabilir. Eşzamanlı rastlaşmada PostgreSQL kilitlenmeyi tespit edip bir transaction'ı geri alır; tutarsız durum oluşmaz, iş bir sonraki çalışmada yeniden dener, kullanıcı isteği `500` alıp tekrarlayabilir.
- **`GET /v1/me/export`:** GET olduğundan siteler arası üst düzey gezinme (SameSite=Lax) kurbanın günlük dışa aktarma hakkını (2/gün) tüketebilir; veri yalnızca kurbanın tarayıcısına iner ve step-up gerekir. Yöntem sözleşmede GET olarak tanımlı; değiştirilmedi.
- **Geri alma sonrası diğer modüllerin faktörleri** (passkey, TOTP, sosyal kimlik) — aşağıdaki "Bilinen sınırlamalar"a bakın.

## authn-server / Dalga B'nin bağlaması gerekenler

1. `AccountServiceDeps`: `hasher = crypto.passwords`, `otp = crypto.otp`, `captcha = authn-protect CaptchaVerifier`, `password_validator = password_service.validator()`, `notifier`, `audit`, `events` (authn-audit/notify), `sessions = authn-session SessionRevoker`, `exporters = [mfa, webauthn, session, oidc-client, org, protect, audit…]` (her modülün `DataExporter`'ı; bölüm adları benzersiz, `account` ayrılmış), `ownership = authn-org üzerinden OrganizationOwnership`.
2. `impl FromRef<AppState> for AccountService`, `.merge(authn_account::router::<AppState>())` — `/v1/me*` yolları oturum katmanının arkasında; `openapi.rs`'e `authn_account::AccountApi`.
3. Açılışta `sync_terms_versions()`; zamanlanmış işler: `purge_unverified_accounts`, `purge_due_deletions`, `release_expired_locks`, `purge_expired_reservations` (ör. 5–15 dakikada bir, `max` = 100–500); zarif kapanışta `drain_background_jobs()`.
4. authn-password `ProfileLookup` adaptörü: `profile_of(user)` → `ProfileHints { display_name, locale }`.
5. authn-session: girişte doğru şifreden sonra `assess_login`; `Denied` → `DenialReason::into_error`; `Allowed { required_actions }` → SES-22 challenge'ı (`verify_email` tamamlanırken kod doğrulaması için challenge'a bağlı bir akış gerekiyorsa `verify_own_email_code` sınırlı oturumla kullanılabilir; `accept_terms` için `accept_terms(ctx, user, …)`).
6. authn-admin: askıya alma / kilit / devre dışı → `change_status_in_tx` + aynı transaction'da `SessionRevoker`; "e-posta doğrulandı işaretleme" için ileride bir `mark_email_verified` API'si eklenebilir (talep edilirse).

## Bilinen sınırlamalar / SHOULD notları

- Geri alma (ACC-07) oturumları ve şifreyi sıfırlar ancak saldırganın arada eklemiş olabileceği passkey / TOTP / sosyal kimlikleri kaldırmaz (başka modüllerin tabloları). Kullanıcıya geri alma sonrası güvenlik ayarlarını gözden geçirmesi söylenmelidir; istenirse server bir "e-posta değişikliği geri alındı" kancası ile bu modülleri çağırabilir.
- `RegistrationAttempt` bildirimi, e-posta değişikliğinde "adresiniz başka bir hesap için kullanılmak istendi" uyarısı olarak da kullanılır (port'ta ayrı tür yok); şablon metni genel tutulmalıdır.
- Geri alma sonrası "şifrenizi sıfırlayın" e-postası otomatik gönderilmez (şifre sıfırlama authn-password'dadır); yanıt `password_reset_required: true` döner ve ön yüz `POST /v1/password/forgot` çağırır.
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
