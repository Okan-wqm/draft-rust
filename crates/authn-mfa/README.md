# authn-mfa

İkinci faktörler: TOTP, kurtarma kodları, e-posta OTP, SMS OTP (`sms` feature'ı), MFA politika değerlendirmesi ve güvenilir cihazlar. Giriş akışının kendisi (`auth_challenges`, oturum açma) **authn-session**'a aittir; bu crate yalnızca "bu kanıt bu kullanıcı (ve challenge) için geçerli mi?" sorusunu yanıtlar, kod gönderir ve politikayı değerlendirir.

## Sahip olunan gereksinimler

| Kimlik | Uygulama | Başlıca testler |
|--------|----------|-----------------|
| MFA-01 | `MfaService::begin_totp_enrollment` / `confirm_enrollment`, `totp.rs` (URI + QR SVG), sır zarf şifreli (AAD = `mfa_factors/secret_ciphertext/<id>`) | `tests/totp.rs` (`mfa_01_*`), `tests/http.rs` |
| MFA-02 | `last_used_step` yalnızca ileri gider; tüm doğrulamalar kullanıcının MFA satır kilidi altında | `mfa_02_totp_code_cannot_be_replayed`, `mfa_02_concurrent_duplicate_submissions_only_one_succeeds`, `mfa_02_confirmation_code_cannot_be_replayed_at_login` |
| MFA-03 | Faktör başına (`mfa_factors.failed_attempts/locked_until`) ve kullanıcı başına (`mfa_user_settings`, migration 1300) sayaç, geçici kilit, `mfa.locked` olayı, `429 + Retry-After` | `tests/limits.rs` (`mfa_03_*`, eşzamanlı tam sayım dahil) |
| MFA-04 | `recovery.rs` (Crockford base32, 10 karakter = 50 bit, `XXXXX-XXXXX`), anahtarlı hash, atomik tek kullanım, step-up ile yeniden üretim, kalan sayı, kullanım bildirimi | `tests/recovery.rs` (`mfa_04_*`) |
| MFA-05 | `begin_email_enrollment`, `send_code(OtpChannel::Email)`, `verify_factor(EmailOtp)`; `mfa_email_otp` amacı, 6 hane / 10 dk / 5 deneme / 60 sn bekleme | `tests/email_sms.rs` (`mfa_05_*`) |
| MFA-06 | `phone.rs` (katı E.164, ülke izin listesi), `phone_verification` ile doğrulanmadan faktör olmaz, SMS pumping koruması, `weak: true` | `tests/email_sms.rs` (`mfa_06_*`), `policy::tests::mfa_06_org_policy_can_forbid_sms` |
| MFA-07 | Çoklu faktör, step-up, bildirim + audit, son faktör kuralı (`MfaPolicySource` ile), eşzamanlı silmeye karşı kilit | `tests/manage.rs` (`mfa_07_*`) |
| MFA-08 | `policy::evaluate(&MfaPolicyInput) -> MfaRequirement` (saf fonksiyon) + `MfaService::evaluate_for_user` | `policy::tests::mfa_08_exhaustive_invariants` (25 344 girdi), `mfa_08_policy_evaluation_over_stored_state` |
| MFA-09 | `device_token.rs` (HKDF amaç anahtarıyla imzalı, kullanıcıya bağlı token), `trusted_devices` satırı, 30 gün, iptal API'si, admin/politika/konfigürasyonla kapatma | `tests/trusted.rs` (`mfa_09_*`) |
| MFA-10 | `GET /v1/me/mfa` — sır yok, telefon/e-posta maskeli | `mfa_10_status_lists_factors_without_secrets`, `tests/http.rs` |

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. Başka modülün verisi `hooks::MfaPolicySource` trait'i ile gelir (sunucu uygular). Yeni harici bağımlılık eklenmedi; `http` (workspace'te zaten var) `[dependencies]`'e eklendi.

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `MfaService::new(MfaServiceDeps, MfaServiceSettings) -> Result<MfaService, AuthError>` | Servis; `MfaServiceSettings::from_app_config(&config)` |
| `router::<S>()` + `MfaApi` | `/v1/me/mfa/...` endpoint'leri ve OpenAPI belgesi |
| `verify_factor(&ctx, user, Option<ChallengeId>, FactorProof) -> Result<VerifiedFactor>` | authn-session: giriş challenge'ı / step-up. `VerifiedFactor.amr` RFC 8176 değerleri (`otp`, `sms`, `email`, `kba`) |
| `send_code(&ctx, user, Option<ChallengeId>, OtpChannel) -> Result<CodeDelivery>` | authn-session: giriş/step-up için e-posta/SMS kodu |
| `evaluate_for_user(user, Option<OrgMfaPolicy>, phishing_resistant) -> Result<MfaRequirement>` / `policy_input(...)` | authn-session: MFA-08 |
| `policy_input_in(&mut conn, user, Option<OrgMfaPolicy>, phishing_resistant)` (wave 4A, K-69) | authn-server kancaları: `policy_input` ile aynı girdi, **verilen bağlantıdan** okunur (contracts §4; çağıranın transaction'ının değişikliklerini görür, ikinci bir havuz bağlantısı istemez). Test: `mfa_08_k69_policy_input_in_reads_through_the_callers_connection` |
| `policy::evaluate(&MfaPolicyInput) -> MfaRequirement` | Saf politika fonksiyonu; `NotRequired` / `Required{allowed_factors}` / `EnrollmentRequired{allowed_factors}` |
| `amr::combine(primary, second)` | Birincil + ikinci faktör `amr` birleştirme (`mfa` ekler) |
| `trust_device(&ctx, user, trusted_devices_allowed) -> Result<Option<IssuedTrustedDevice>>` | MFA sonrası "bu cihazı hatırla" |
| `is_trusted_device(user, token, trusted_devices_allowed) -> Result<bool>` | Girişte MFA'yı atlamak için |
| `revoke_trusted_devices_in_tx(&mut conn, user, RevocationReason) -> Result<u64>` | Şifre sıfırlama, "her yerden çık", `SessionRevoker` (`also_trusted_devices`) — çağıranın transaction'ında |
| `reset_user_mfa_in_tx(&mut conn, &ctx, user) -> Result<MfaResetSummary>` | authn-admin ADM-03 |
| `status_for_user(user) -> Result<MfaStatus>` | `GET /v1/me` (SES-16), admin detay (ADM-02) |
| `purge_expired() -> Result<PurgeReport>` | OPS-06 arka plan işi |
| `MfaDataExporter` | ACC-10 `mfa` bölümü (`DataExporter`) |
| `TRUSTED_DEVICE_COOKIE` (`__Host-authn_trusted_device`), `TRUSTED_DEVICE_HEADER` (`x-trusted-device`) | Token taşıyıcıları (cookie'yi authn-session yazar) |

## Endpoint'ler

| Yöntem | Yol | Yetki | Gereksinim |
|--------|-----|-------|------------|
| `GET` | `/v1/me/mfa` | oturum (salt-okunur impersonation olabilir) | MFA-10 |
| `POST` | `/v1/me/mfa/totp` | oturum + step-up | MFA-01 |
| `POST` | `/v1/me/mfa/email` | oturum + step-up | MFA-05 |
| `POST` | `/v1/me/mfa/sms` | oturum + step-up | MFA-06 |
| `POST` | `/v1/me/mfa/factors/{factor_id}/confirm` | oturum + step-up | MFA-01/05/06 |
| `POST` | `/v1/me/mfa/factors/{factor_id}/resend` | oturum + step-up | MFA-05/06 |
| `DELETE` | `/v1/me/mfa/factors/{factor_id}` | oturum + step-up | MFA-07 |
| `GET` / `POST` | `/v1/me/mfa/recovery-codes` | oturum / oturum + step-up | MFA-04 |
| `GET` / `DELETE` | `/v1/me/mfa/trusted-devices` | oturum | MFA-09 |
| `DELETE` | `/v1/me/mfa/trusted-devices/{device_id}` | oturum | MFA-09 |

Tüm yanıtlar `Cache-Control: no-store` taşır. Gövdeler `SecretJson` ile okunur (reddedilen gövdenin içeriği loglanmaz). Başkasının ya da bilinmeyen kimlik `404 not_found` döner.

## Konfigürasyon (`[mfa]`, `crates/authn-core/src/config/mfa.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `totp.issuer` / `digits` / `period` / `skew_steps` | `rust-authentication` / 6 / `30s` / 1 | issuer 1–64 karakter, `:` ve kontrol karakteri yok (yeni doğrulama) |
| `recovery_codes.count` | 10 | 5–20 |
| `email_otp.enabled` / `ttl` / `max_attempts` / `resend_cooldown` | `true` / `10m` / 5 / `60s` | |
| `email_otp.sends_per_user` | 10 / saat | **yeni** |
| `sms.allowed_country_codes` | `[]` (SMS kapalı) | ör. `["90"]` |
| `sms.ttl` / `max_attempts` | `10m` / 5 | |
| `sms.per_number` / `per_ip` / `global_daily_budget` | 5/saat, 10/saat, 1000/gün | pumping koruması |
| `sms.resend_cooldown` / `sms.per_user` | `60s` / 5 / saat | **yeni** |
| `max_failed_attempts` | 5 | faktör başına, sonra `lockout_duration` kilit |
| `per_user_failures` | 10 / `15m` | kullanıcı başına sabit pencere |
| `lockout_duration` | `15m` | |
| `trusted_device.enabled` / `ttl` | `true` / `30d` | |
| `enrollment_ttl` | `15m` | **yeni**: bekleyen (onaylanmamış) faktörün ömrü |
| `max_factors_per_user` | 10 | **yeni**: bekleyenler dahil |

Step-up penceresi `session.step_up_max_age`'dir (varsayılan 10 dk).

## Veri modeli ve migration

Tablolar: `mfa_factors`, `recovery_codes`, `mfa_user_settings`, `trusted_devices` (0004/0005). `one_time_tokens` amaçları: `mfa_email_otp`, `mfa_sms_otp`, `phone_verification` (faktör kimliği `metadata.factor_id`'de).

`migrations/1300_mfa_user_lock.sql`: `mfa_user_settings`'e `failed_attempts`, `failure_window_start`, `locked_until`; kullanıcı başına tek e-posta faktörü için kısmi benzersiz indeks; bekleyen faktör ve güvenilir cihaz temizliği için indeksler.

## Güvenlik notları

- **Yarış durumları:** Her doğrulama ve her faktör değişikliği kullanıcının `mfa_user_settings` satırını `FOR UPDATE` ile kilitler (`lock_timeout = 5s`, aşılırsa `429`). Sonuç: aynı TOTP adımı en fazla bir kez kabul edilir, sayaçlar eşzamanlı istekte de tam sayılır (test: 16 eşzamanlı yanlış tahminde tam 4 `invalid_code` + 12 `too_many_attempts`), son iki faktörün eşzamanlı silinmesi tek faktör bırakır. Faktör silme ayrıca `users` satırını kilitler (PWD-11 ile aynı sözleşme).
- **E-posta/SMS kodları** `one_time_tokens.verify_code` ile, kullanıcının kilidi **alınmadan önce** doğrulanır: o fonksiyon kendi transaction'ını havuzdan açar; kilit tutulurken çağrılsaydı havuz tükenmesi (kilitlenme) mümkün olurdu. Kod başına deneme sınırı (5) store'da, faktör ve kullanıcı sayaçları burada; yeniden gönderilen kodlar sayaçları sıfırlamaz.
- **Challenge bağlama:** Giriş için gönderilen kod `(user, challenge)`'a bağlıdır ve yalnızca aynı challenge ile doğrulanır; challenge'sız (step-up) doğrulamada store'un kullanıcı aramasının bulduğu challenge'a bağlı kod da reddedilir (test: `mfa_05_login_challenge_code_is_rejected_without_its_challenge`). Kayıt kodları (`phone_verification`) giriş kodu olarak kullanılamaz (amaç ayrımı, HMAC'e bağlı); kayıt onayı da yalnızca challenge'a bağlı olmayan kodu kabul eder.
- **TOTP sırrı** 160 bit, XChaCha20-Poly1305 zarfında, AAD tablo/kolon/satır; başka satıra kopyalanan şifreli metin açılmaz (test: `mfa_01_secret_is_envelope_encrypted_and_bound_to_its_row`). Sır, URI ve QR yalnızca kayıt yanıtında bir kez döner; `Debug` çıktıları redakte.
- **Kurtarma kodları** `HMAC(K_recovery, user_id, kod)` olarak saklanır: başka kullanıcıda işe yaramaz, veritabanı sızıntısı tek başına çevrimdışı kaba kuvvete yetmez. Tek kullanım tek `UPDATE … WHERE used_at IS NULL RETURNING` ile.
- **SMS pumping:** ülke izin listesi → kullanıcı bekleme süresi → kullanıcı/numara/IP limitleri → global günlük bütçe (en sonda; dar limitlerce reddedilen istek global bütçeyi tüketmez). Bütçe tüketen limitler, diğer tüm retlerden (zaten kayıtlı numara, faktör sınırı) **sonra** çalışır; böyle reddedilen istek hiçbir bütçeyi tüketmez (test: `mfa_06_refused_enrollment_consumes_no_sms_budget`). Ret, veritabanına hiçbir şey yazmadan ve SMS göndermeden olur. Numara katı E.164'tür; boşluk, tire, Unicode rakam "normalleştirilmez", reddedilir.
- **Güvenilir cihaz token'ı** `td1.<id>.<exp>.<nonce>.<tag>`; etiket kullanıcı kimliğini de kapsar (başka kullanıcıya taşınamaz), sahte token veritabanına ulaşmadan reddedilir, yalnızca SHA-256'sı saklanır. Kullanıcı başına en fazla 20 aktif cihaz. Platform admin'leri için her zaman kapalı (sonradan admin yapılan hesabın cihazları da anında geçersiz). Çağıranın `trusted_devices_allowed` bayrağı yalnızca giriş bağlamını anlatır; kullanıcının **herhangi bir** organizasyonu özelliği kapattıysa (`MfaPolicySource::org_policy_for_user`, en katı birleşim) cihaz ne güvenilir yapılır ne de kabul edilir (test: `mfa_09_any_membership_policy_can_disable_trusted_devices`).
- **Kimlik/IDOR:** Tüm faktör/cihaz sorguları `user_id` ile filtrelenir; başkasının kimliği `404`.
- **Step-up / impersonation:** Faktör ekleme/onaylama/silme, kurtarma kodu üretimi step-up ister; impersonation (salt-okunur olmasa da) ve API anahtarı principal'ları reddedilir. Okuma salt-okunur impersonation'da serbesttir.
- **Sızıntı:** Hata gövdeleri kod/sır yansıtmaz (`SecretJson`), audit olaylarında kod, sır, telefon numarası yoktur (yalnızca faktör türü/kimliği).
- **`429` her zaman `Retry-After` taşır** (sözleşme §8, PRT-04): bekleyen kayıt çok fazla yanlış onay koduyla silindiğinde dönen `too_many_attempts` dahil (test: `mfa_03_discarded_enrollment_answers_429_with_retry_after`).

### Güvenlik incelemesi (2026-11-01) — kabul edilen riskler

Aşağıdakiler incelemede bulundu, ancak bu crate içinde düzeltilmesi gereken somut bir açık değildir; gerekçesiyle kabul edildi veya bağlayan modüle devredildi:

- **Politika, `verify_factor`'da zorlanmaz.** `verify_factor` kanıtın bu kullanıcı için geçerli olup olmadığını söyler; kanıt türünün o girişte **izinli** olup olmadığını (`evaluate(...).allowed_factors()`; ör. platform admin'i için yalnızca phishing'e dayanıklı faktör, organizasyonun SMS yasağı, kurtarma kodunun admin'ler için geçersizliği) authn-session `proof.kind()` ile kontrol etmelidir. Organizasyon bağlamı yalnızca session'da bilindiğinden bu kontrol buraya taşınamaz.
- **Kullanıcı başına MFA kilidi DoS'a açıktır.** Şifreyi bilen saldırgan 15 dakikada 10 yanlış denemeyle kullanıcının MFA'sını geçici olarak kilitleyebilir (MFA-03'ün doğal sonucu; kilit hiçbir şey vermez, yalnızca erişimi geciktirir). Azaltım: authn-protect yumuşak kilit/risk değerlendirmesi ve session'ın challenge deneme sayacı.
- **Satır kilidi bekleyen istekler havuz bağlantısı tutar.** Aynı kullanıcı için eşzamanlı çok sayıda istek, `lock_timeout = 5s` dolana kadar bağlantı tutar; kilidi tutan istek `RateLimiter` için ikinci bir bağlantı kullanabilir. Etki 5 saniyeyle sınırlıdır; HTTP katmanı rate limit'leri (PRT-02) ve challenge sayaçları ayrıca sınırlar.
- **Kurtarma kodu yeniden üretimi e-posta bildirimi göndermez.** MFA-04 yalnızca kod *kullanımında* bildirim ister ve `NotificationKind`'te uygun varyant yoktur (port sahibi authn-notify). İşlem step-up ister, `recovery_codes.generated` audit olayı yazılır ve güvenilir cihazlar iptal edilir.
- **Step-up yöntemi session'ındır.** Faktör değişiklikleri `auth_time`'ın `session.step_up_max_age` içinde olmasını ister; SES-13 şifreyle step-up'a izin verir. MFA'sı açık hesaplarda step-up'ın ikinci faktörle yapılmasını istemek authn-session'ın kararıdır (çalınmış oturum çerezi + şifre ile yeni faktör eklenebilir; ekleme bildirimi gider).
- **Güvenilir cihaz verme ile "her yerden çık" yarışı.** `trust_device` ile eşzamanlı çalışan `revoke_trusted_devices_in_tx`, ondan sonra commit edilen yeni cihazı göremez (çok dar pencere; saldırganın o anda ikinci faktörü geçmiş olması gerekir ve şifre sıfırlandıysa cihaz tek başına giriş sağlamaz).
- **Anahtar rotasyonu:** Kurtarma kodu hash'leri ve güvenilir cihaz token'ları `crypto.hmac_root_key`'den türetilen HKDF alt anahtarlarına bağlıdır; kök anahtar değişirse tüm kurtarma kodları ve güvenilir cihazlar geçersiz olur (kullanıcılar yeni kod üretmeli). Operasyon runbook'unda belirtilmelidir.
- **Challenge'a bağlı kodun step-up'ta tüketilmesi.** Store'un kullanıcıya göre araması en yeni kodu kilitleyip tükettiği için, step-up'ta girilen bir giriş kodu reddedilir ama o kod da kullanılmış olur (yalnızca kodu bilen kişi bunu yapabilir; giriş challenge'ı yeni kod ister).
- **E-posta faktörü hesap adresini izler.** Hesap e-postası (doğrulanarak) değişirse e-posta faktörü yeni adrese kod gönderir; eski adrese gönderilmiş `mfa_email_otp` kodları authn-account tarafından iptal edilir.

## authn-server / Dalga B'nin bağlaması gerekenler

1. **`MfaPolicySource` uygulaması** (authn-server; authn-org + authn-webauthn verisiyle):
   - `org_policy_for_user(&mut conn, user) -> Result<Option<OrgMfaPolicy>, AuthError>`: kullanıcının aktif üyeliklerindeki `org_policies` kayıtlarının `OrgMfaPolicy::strictest` birleşimi (`mfa_required`, `phishing_resistant_mfa_required`, `allowed_mfa_factors`, `trusted_devices_allowed`).
   - `webauthn_factor_count(&mut conn, user) -> Result<u32, AuthError>`: ikinci faktör olarak kullanılabilen passkey sayısı. Verilen bağlantı üzerinden okunmalı.
2. **Cargo:** workspace girdisi `authn-mfa = { …, default-features = false }` olduğundan authn-server SMS için `features = ["sms"]` açmalı (ARC-11: varsayılan açık). Özellik kapalıyken SMS faktörü hiç sunulmaz.
3. **`AppState`:** `MfaService::new(MfaServiceDeps { pool, clock, keys: crypto.keys, otp: crypto.otp, envelopes: crypto.envelopes, rate_limiter, notifier, audit, sms: Some(notify.sms), policy_source }, MfaServiceSettings::from_app_config(&config))`, `impl FromRef<AppState> for MfaService`, `.merge(authn_mfa::router::<AppState>())` (oturum kimlik doğrulama katmanının arkasında), `openapi.rs`'e `authn_mfa::MfaApi`. `webauthn_available` `passkey` feature'ı kapalıysa `false` yapılmalı.
4. **Notifier:** SMS kodları `Notifier::notify_sms_in_tx` ile outbox'tan gider (authn-notify uygular). `sms` alanındaki `SmsSender` yalnızca `is_configured()` için okunur.
5. **Arka plan işi:** `MfaService::purge_expired()` (OPS-06).
6. **authn-account:** `MfaDataExporter` dışa aktarma toplayıcısına kaydedilmeli (ACC-10).
7. **authn-session:**
   - Girişte `evaluate_for_user(user, aktif_org_politikası, pr)` → `Required` ise challenge `allowed_factors` ile; `EnrollmentRequired` ise `RequiredAction::EnrollMfa` — kullanıcının hâlâ (artık izinli olmayan) faktörleri varsa önce biri doğrulatılmalı; **boş liste = girişi reddet**.
   - Güvenilir cihaz: challenge'dan önce `is_trusted_device(user, token, org.trusted_devices_allowed)`; MFA başarılı ve kullanıcı istediyse `trust_device(...)` → cookie `__Host-authn_trusted_device` (HttpOnly, Secure, SameSite=Lax, `expires_at`) veya native yanıtında token.
   - `verify_factor(ctx, user, Some(challenge_id), proof)` — challenge'ın kullanıcıya ait ve geçerli olduğunu authn-session doğrular; challenge deneme sayacını da kendisi tutar. **`proof.kind()` challenge'ın `allowed_factors` listesinde değilse `verify_factor` çağrılmadan reddedilmeli** (politika burada zorlanmaz; ör. admin + TOTP/kurtarma kodu, SMS yasaklayan organizasyon). `amr` için `authn_mfa::amr::combine`.
   - `send_code(ctx, user, Some(challenge_id), OtpChannel::...)`.
   - `SessionRevoker::revoke_all_for_user(.., RevokeOptions { also_trusted_devices: true })` uygulamasında aynı bağlantıyla `revoke_trusted_devices_in_tx(conn, user, reason)`; "her yerden çık" da aynısını yapar.
8. **authn-admin:** MFA sıfırlama `reset_user_mfa_in_tx(conn, ctx, user)`; `mfa.reset` / `admin.action` audit olayını gerekçeyle admin yazar. Admin detayında `status_for_user`.

## Bilinen sınırlamalar / notlar

- Kullanıcı başına başarısızlık penceresi `RateLimiter` değil veritabanı satırıdır (sabit pencere, `per_user_failures`): satır kilidiyle birlikte tam ve kalıcı sayım sağlar. Gönderim limitleri (`RateLimiter`) ayrıdır.
- Kurtarma kodlarının faktör satırı yoktur; yalnızca kullanıcı başına sayaç ile sınırlanırlar (50 bit entropi + kilit).
- Challenge olmadan (yalnızca kullanıcı konusuyla) doğrulanan kodlar (step-up) için `one_time_tokens.verify_code` aynı kullanıcının challenge'a bağlı en yeni kodunu da bulabilir; böyle bir kod artık **reddedilir** (yalnızca kendi challenge'ı ile geçerlidir). Farklı kullanıcıya geçiş zaten mümkün değildir.
- Faktör yeniden adlandırma endpoint'i yoktur (etiket kayıtta verilir). Uygulanmayan SHOULD/MAY yok.

## Komutlar

```bash
cargo test -p authn-mfa --all-features
cargo clippy -p authn-mfa --all-targets --all-features -- -D warnings
cargo fmt -p authn-mfa
# Fuzz (kayıt talebi: contract-change-requests.md / authn-mfa)
cargo +nightly fuzz run mfa_input_parse -- -max_total_time=30
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
