# Mimari sözleşmeler (contracts)

Bu belge, aynı çalışma ağacında **paralel çalışan** modül agent'larının uyduğu bağlayıcı sözleşmedir. Gereksinimler için tek kaynak `docs/spec/requirements.md`'dir; bu belge **kimin neyi, nerede ve hangi arayüzle** yaptığını belirler. Bir kural burada yazılı değilse ve başka bir modülü etkiliyorsa, önce §13'teki süreçle sözleşme değişikliği talep edilir.

İçindekiler: 1. Crate'ler ve gereksinim sahipliği · 2. Bağımlılık grafiği · 3. Dosya sahipliği · 4. Portlar ve modül kancaları · 5. Tablo sahipliği · 6. Migration'lar · 7. AppState / FromRef router deseni · 8. Hata kodları · 9. Konfigürasyon · 10. HTTP katmanı ve istek bağlamı · 11. Güvenlik kuralları · 12. Test kuralları · 13. Sözleşme değişikliği talebi · 14. Mimari kararlar · 15. Sunucu bağlama tablosu

> **Durum (2026-11-01):** Dalga A (password, account, mfa, webauthn, org, protect, audit, notify) tamamlandı ve sözleşme değişikliği talepleri işlendi. Bu belge Dalga A'nın gerçekte dışa açtığı API'leri, tabloları ve bağlama gereksinimlerini yansıtır; Dalga B (session, oidc-client, admin) ve authn-server için bağlama listesi §15'tedir.

---

## 1. Crate'ler ve gereksinim sahipliği

| Crate | Katman | Sorumluluk |
|-------|--------|------------|
| `authn-core` | 0 | Tipli kimlikler, hata modeli, konfigürasyon, portlar, alan primitifleri, istek bağlamı (IP/dil/istek kimliği), TLS sağlayıcısı |
| `authn-crypto` | 1 | Argon2id + pepper, eski hash göçü, token/OTP üretimi, zarf şifreleme, EdDSA JWS/JWT, HKDF alt anahtarları, imza anahtarı yaşam döngüsü |
| `authn-store` | 2 | `PgPool`, gömülü migration'lar, transaction yardımcıları, DB hata sınıflandırması, `users`/`password_credentials` temel repository'si |
| `authn-testkit` | test | Tüm portlar için sahteler, `FakeClock`, test konfigürasyonu, HTTP ve zamanlama yardımcıları (yalnızca `dev-dependency`) |
| `authn-password` | Dalga A | Şifre politikası, HIBP, zxcvbn, değiştirme/ekleme/kaldırma, sıfırlama |
| `authn-account` | Dalga A | Kayıt, e-posta doğrulama, hesap durum makinesi, profil, e-posta değişikliği, silme, dışa aktarma, onaylar |
| `authn-mfa` | Dalga A | TOTP, kurtarma kodları, e-posta/SMS OTP, MFA politikası, güvenilir cihazlar |
| `authn-webauthn` | Dalga A | Passkey seremonileri, kimlik bilgisi yönetimi, mobil ilişkilendirme dosyaları |
| `authn-org` | Dalga A | Organizasyonlar, üyelik, RBAC, davetler, domain doğrulama, politikalar, API anahtarları, servis hesapları |
| `authn-protect` | Dalga A | Rate limit, CAPTCHA, yumuşak kilit, risk, güvenlik başlıkları, CORS, host/yönlendirme doğrulama, SSRF korumalı HTTP |
| `authn-audit` | Dalga A | Hash zincirli audit log, outbox işçisi, webhook'lar |
| `authn-notify` | Dalga A | Şablonlar (TR/EN), e-posta taşıyıcıları, SMS göndericileri |
| `authn-session` | Dalga B | Giriş akışı, web oturumu + CSRF, native token'lar + rotasyon, JWKS, introspection, step-up, şifresiz giriş |
| `authn-oidc-client` | Dalga B | Sosyal giriş (Google, Apple, Microsoft, GitHub, genel OIDC) |
| `authn-admin` | Dalga B | Platform admin API'si, impersonation, break-glass, acil durum işlemleri |
| `authn-server` | 3 | `rust-authentication` binary'si, `AppState`, middleware yığını, CLI, sağlık, arka plan işleri |

### Gereksinim → sahip crate eşlemesi

Spesifikasyondaki **her** gereksinim kimliği tam olarak bir crate'e aittir. Sahip crate, gereksinimin uygulanmasından ve adında kimliği geçen en az bir testten sorumludur; başka crate'ler katkıda bulunabilir (ör. her crate kendi testlerini yazar — TST-01), ama "bitti" kararını sahip verir.

<!-- 175 gereksinim kimliği; her biri tam olarak bir crate'e atanmıştır. -->
| Crate | Sahip olduğu gereksinim kimlikleri |
|-------|------------------------------------|
| `authn-core` | ARC-01, ARC-02, ARC-04, ARC-05, ARC-07, ARC-08, DOC-02, DOC-08, DOC-09, LIC-01, PRT-06, TST-03, TST-04, TST-07 |
| `authn-crypto` | ARC-12, CRY-01, CRY-02, CRY-03, CRY-04, CRY-05, CRY-06, CRY-07, CRY-08, CRY-09, CRY-10, CRY-11, CRY-12, CRY-13, CRY-14, TST-05 |
| `authn-store` | ARC-06, OPS-10 |
| `authn-testkit` | TST-01, TST-08 |
| `authn-password` | PWD-01, PWD-02, PWD-03, PWD-04, PWD-05, PWD-06, PWD-07, PWD-08, PWD-09, PWD-10, PWD-11, PWD-12 |
| `authn-account` | ACC-01, ACC-02, ACC-03, ACC-04, ACC-05, ACC-06, ACC-07, ACC-08, ACC-09, ACC-10, ACC-11, ACC-12, ACC-13, DOC-07 |
| `authn-mfa` | MFA-01, MFA-02, MFA-03, MFA-04, MFA-05, MFA-06, MFA-07, MFA-08, MFA-09, MFA-10 |
| `authn-webauthn` | PKY-01, PKY-02, PKY-03, PKY-04, PKY-05, PKY-06, PKY-07, PKY-08 |
| `authn-org` | ARC-10, ORG-01, ORG-02, ORG-03, ORG-04, ORG-05, ORG-06, ORG-07, ORG-08, ORG-09, ORG-10, ORG-11, ORG-12 |
| `authn-protect` | DOC-03, PRT-01, PRT-02, PRT-03, PRT-04, PRT-05, PRT-07, PRT-08, PRT-09, PRT-10, PRT-12, RSK-01, RSK-02, RSK-03, RSK-04 |
| `authn-audit` | AUD-01, AUD-02, AUD-03, AUD-04, AUD-05, AUD-06, AUD-07 |
| `authn-notify` | NTF-01, NTF-02, NTF-03, NTF-04 |
| `authn-session` | DOC-05, SES-01, SES-02, SES-03, SES-04, SES-05, SES-06, SES-07, SES-08, SES-09, SES-10, SES-11, SES-12, SES-13, SES-14, SES-15, SES-16, SES-17, SES-18, SES-19, SES-20, SES-21, SES-22 |
| `authn-oidc-client` | SOC-01, SOC-02, SOC-03, SOC-04, SOC-05, SOC-06, SOC-07, SOC-08, SOC-09 |
| `authn-admin` | ADM-01, ADM-02, ADM-03, ADM-04, ADM-05, ADM-06, ADM-07, ADM-08 |
| `authn-server` | ARC-03, ARC-09, ARC-11, DOC-01, DOC-04, DOC-06, OPS-01, OPS-02, OPS-03, OPS-04, OPS-05, OPS-06, OPS-07, OPS-08, OPS-09, PRT-11, TST-02, TST-06 |

Notlar:
- **PRT-06** (istemci IP'si) mimar tarafından `authn-core`'da uygulandı (`authn_core::http::client_ip`), çünkü `RequestContext` her crate'in ihtiyacıdır.
- **PRT-11** (gövde sınırı, zaman aşımı, eşzamanlılık) `authn-server` katman yığınındadır; ayarları `[server.limits]`.
- **ACC-03**'ün temel normalizasyonu `authn_core::domain::EmailAddress`'tedir; sahibi `authn-account`'tır ve sertleştirmeyi §13 süreciyle yapar.
- **ARC-10** kiracı izolasyonu `authn-org`'a aittir; veritabanı seviyesindeki korumalar (tetikleyici, bileşik FK) `0003` migration'ındadır ve `authn-store/tests/schema.rs` ile test edilir.
- **TST-02 / TST-06** uçtan uca senaryolar `authn-server`'dadır; modüller kendi güvenlik regresyon testlerini ayrıca yazar.

---

## 2. Bağımlılık grafiği

```
authn-core  ←  authn-crypto  ←  authn-store  ←  Dalga A  ←  Dalga B  ←  authn-server
```

| Crate | İzin verilen `authn-*` bağımlılıkları |
|-------|----------------------------------------|
| `authn-core` | — |
| `authn-crypto` | core |
| `authn-store` | core, crypto |
| Dalga A (`password`, `account`, `mfa`, `webauthn`, `org`, `protect`, `audit`, `notify`) | core, crypto, store — **birbirlerine asla** |
| Dalga B (`session`, `oidc-client`, `admin`) | core, crypto, store, tüm Dalga A — **birbirlerine asla** |
| `authn-server` | hepsi |
| `authn-testkit` | core (yalnızca diğerlerinin `[dev-dependencies]`'inde) |

- Kurallar `crates/authn-testkit/tests/architecture.rs` ile her `cargo test`'te zorlanır.
- Aynı dalgadaki modüller **yalnızca `authn-core` portları** üzerinden konuşur. Örnekler: şifre sıfırlama oturumları `SessionRevoker` ile kapatır; sosyal giriş oturumu `SessionIssuer` ile açar; webhook'lar SSRF korumalı `HttpClient` ile gider.
- Dalga A bir başka Dalga A modülünün **verisine** ihtiyaç duyuyorsa (ör. MFA politikası için organizasyon politikası) kendi API'sinde bir **girdi yapısı** tanımlar; veriyi Dalga B (`authn-session`) toplayıp verir.
- Harici crate'ler yalnızca kök `Cargo.toml` `[workspace.dependencies]` içindeki sürümlerle kullanılır (`foo.workspace = true`); her crate'in `Cargo.toml`'u öngörülen bağımlılıklarla önceden dolduruldu. Yeni harici crate gerekiyorsa §13 (lisans kontrolü zorunlu, LIC-01).

---

## 3. Dosya sahipliği

Bir agent yalnızca sahibi olduğu dosyaları değiştirir.

| Yol | Sahip |
|-----|-------|
| `crates/authn-<modül>/**` | ilgili modül agent'ı |
| `crates/authn-core/src/config/<modül>.rs` | ilgili modül (`server.rs` → authn-server, `database.rs` → authn-store, `crypto.rs` → authn-crypto, `oidc_client.rs` → authn-oidc-client, …) |
| `crates/authn-core/src/error/codes/<modül>.rs` | ilgili modül |
| `crates/authn-core/src/ports/<port>.rs` | portu **uygulayan** crate (§4 tablosu) — yalnızca geriye uyumlu ekleme |
| `crates/authn-core/src/**` (diğer her şey: `config/mod.rs`, `config/common.rs`, `config/duration.rs`, `error/*.rs`, `error/codes/mod.rs`, `error/codes/common.rs`, `domain/**`, `http/**`, `id.rs`, `secret.rs`, `redact.rs`, `tls.rs`, `macros.rs`, `lib.rs`) | mimar |
| `migrations/0001`–`0099` | mimar; modüller kendi aralıklarına yazar (§6) |
| `fuzz/fuzz_targets/<hedef>.rs` | dosya başlığındaki crate (`jwt_parse`, `envelope_parse`, `password_hash_parse`, `token_parse`, `webhook_verify` → crypto; `api_key_parse` → org; `webhook_signature` → audit; `return_to` → protect; `hibp_range_parse` → password; `mfa_input_parse` → mfa; `webauthn_response_parse` → webauthn; `email_normalize` → core/account; `client_ip` → core). Yeni hedefin `fuzz/Cargo.toml` kaydı mimarın işidir (§13) |
| `config/example.toml` | authn-server (her modül kendi bölümünün yorumlarını §13 ile günceller) |
| Kök dosyalar: `Cargo.toml`, `deny.toml`, `clippy.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `.cargo/*`, `.github/**`, `docker-compose.yml`, `config/dev-certs/**` (yalnızca geliştirme sertifikası), `docs/architecture/**`, `fuzz/Cargo.toml`, `fuzz/deny.toml` | mimar |
| `Cargo.lock` | yalnızca cargo üretir; birleştirme çakışmasında elle düzenlenmez, `cargo update --workspace` ile yeniden üretilir |
| `docs/architecture/contract-change-requests.md` | herkes — yalnızca **kendi başlığı altına** ekleme yapar |

Yeni bir modül dosyası eklemek (`config/<modül>.rs` alanları, yeni hata kodu, yeni migration) sahibinin işidir ve onay gerektirmez. Başka bir sahibin dosyasındaki değişiklik §13'e tabidir.

---

## 4. Portlar ve modül kancaları

Tüm portlar `crates/authn-core/src/ports/` altında, nesne güvenli (`Arc<dyn Port>`), `Send + Sync`, `#[async_trait]` ile tanımlıdır. Hata tipi her zaman `AuthError`'dır.

| Port | Dosya | Uygulayan | Başlıca tüketiciler | Transaction semantiği |
|------|-------|-----------|---------------------|-----------------------|
| `Clock` | `clock.rs` | core (`SystemClock`) | herkes | — |
| `AuditSink` | `audit.rs` | audit (`PgAuditSink`) | herkes | `record` kendi kısa transaction'ı (başarısız iş işleminde de yazılır); `record_in_tx` ve `pseudonymize_subject` (AUD-05, ACC-09; varsayılan gövde no-op) çağıranın transaction'ında |
| `EventPublisher` | `event_publisher.rs` | audit (`OutboxEventPublisher`) | account, org, session | çağıranın transaction'ında (outbox) |
| `Notifier` | `notifier.rs` | notify (`OutboxNotifier`) | account, password, mfa, org, session, admin, protect | `notify` kendi transaction'ı, `notify_in_tx` ve `notify_sms_in_tx` (MFA-06; varsayılan gövde `sms_unavailable`) çağıranınkinde; teslim outbox ile asenkron, sırlar zarf şifreli |
| `EmailTransport` | `email_transport.rs` | notify | notify (outbox işçisi) | — |
| `SmsSender` | `sms.rs` | notify | mfa | — |
| `RateLimiter` | `rate_limit.rs` | protect | herkes | atomik, kendi bağlantısı |
| `CaptchaVerifier` | `captcha.rs` | protect | account, session | tek kullanımlık |
| `RiskEvaluator` | `risk.rs` | protect | session | — |
| `GeoIpLookup` | `geoip.rs` | protect (opsiyonel) | protect, session | — |
| `HttpClient` | `http_client.rs` | protect | password (HIBP), audit (webhook), oidc-client, protect (CAPTCHA), notify (SMS) | — |
| `BreachedPasswordChecker` | `breached_password.rs` | password | password, account | — |
| `PasswordValidator` | `password_validator.rs` | password | account (ACC-01), password, admin | — |
| `DnsTxtResolver` | `dns.rs` | org | org | — |
| `SessionRevoker` | `session_revoker.rs` | session | password, account, mfa, org, admin, protect | **çağıranın transaction'ında** (`&mut PgConnection`); `RevokeOptions::also_trusted_devices` aynı bağlantıda authn-mfa'nın `revoke_trusted_devices_in_tx`'i ile uygulanır (PWD-09, MFA-09). Bir kullanıcının oturumlarını kapatmak o kullanıcının **impersonation oturumlarını** ve **bekleyen girişlerini** (`auth_challenges`) de bitirir; askıya alınan bir adminin başlattığı impersonation oturumları da biter. `revoke_everything_except(conn, keep, reason)` (wave 2B, K-10) acil "tümünü kapat" içindir (varsayılan gövde reddeder). Modüllere verilen uygulama `authn_account::AccountAwareSessionRevoker` ile sarılmış `PgSessionRevoker`'dır (§15.2) |
| `SessionIssuer` | `session_issuer.rs` | session | oidc-client (sosyal giriş), admin (impersonation), webauthn akışları session üzerinden | kendi transaction'ı; `start_impersonation_audited` (wave 1, K-06) **çağıranın transaction'ında**, çağıranın verdiği `EventId` ile (varsayılan gövde reddeder) |
| `DataExporter` | `data_exporter.rs` | her modül kendi bölümü için; toplayıcı account | account | çağıranın bağlantısı |

Kurallar:
- Port dosyası yalnızca **geriye uyumlu ekleme** alır: yeni metot (varsayılan gövdeli), yeni enum varyantı (tüketiciler için kırıcıysa §13), yeni alan (yapı `Default`/yapıcı ile). İmza değişikliği ve silme §13'e tabidir.
- Tüketiciler belgelenmiş imzaya ve semantiğe göre kod yazar ve testlerde `authn_testkit::TestPorts` sahtelerini kullanır; gerçek uygulama hazır olmadan da paralel çalışabilir.
- `&mut PgConnection` alan metotlar çağıranın transaction'ının parçasıdır: çağıran commit etmezse etki yoktur (ARC-06).
- Sır içeren port verileri (`SensitiveString`: token, OTP) yalnızca amacına uygun yere serileştirilir (outbox'ta zarf şifreli `sealed_payload`); `Debug` çıktıları redakte edilmiştir.
- `RevocationReason` (`session_revoker.rs`) Dalga A'da `MembershipChanged` (`membership_changed`: rol düşürme, özel rolden izin çıkarma, devirde eski sahibin düşürülmesi) ile genişletildi. Değerler `sessions.revoked_reason` / `trusted_devices.revoked_reason` biçim kısıtına (`^[a-z][a-z0-9_]{0,63}$`) uyar; yeni neden migration gerektirmez.

### Modül kancaları (Dalga A trait'leri, uygulayan: authn-server)

Aynı dalgadaki modüller birbirini göremediği için, başka bir modülün verisine ihtiyaç duyan Dalga A crate'i **kendi crate'inde** küçük bir trait tanımlar; uygulamayı (adaptörü) diğer modüllerin API'leriyle authn-server yazar. Varsayılan uygulamalar yalnızca tek kiracılı kurulum ve testler içindir (`NoOtherLoginMethods`, `NoProfiles`, `NoOrganizations`, `StaticMfaPolicySource`, `PasswordOnlyMethods`, `UnrestrictedPolicySource`); son giriş yöntemi kuralı gibi kontrollerde güvenli tarafta kalırlar (bilinmeyen yöntem yok sayılır → silme reddedilir), ama kuruluş politikalarını uygulamazlar — üretimde server adaptörleri zorunludur. Uygulama ayrıntıları ve veri kaynakları §15.1'dedir.

| Trait | Tanımlayan dosya | Çağrı bağlamı |
|-------|------------------|---------------|
| `authn_password::LoginMethodInventory` | `crates/authn-password/src/hooks.rs` | verilen `&mut PgConnection` (çağıran `users` satırını `FOR UPDATE` kilitlemiştir) |
| `authn_password::ProfileLookup` | `crates/authn-password/src/hooks.rs` | havuz |
| `authn_account::OrganizationOwnership` | `crates/authn-account/src/hooks.rs` | verilen bağlantı (kullanıcı satırı kilitli) |
| `authn_mfa::MfaPolicySource` | `crates/authn-mfa/src/hooks.rs` | verilen bağlantı (transaction içinde **ve** düz bağlantıyla) |
| `authn_webauthn::AccountMethodsSource`, `authn_webauthn::PasskeyPolicySource` | `crates/authn-webauthn/src/hooks.rs` | verilen bağlantı (kullanıcı satırı kilitli) |
| `authn_protect::risk::NotMeTokenIssuer` | `crates/authn-protect/src/risk/alerts.rs` | verilen bağlantı (uygulayan: authn-session) |
| `authn_audit::AuditAccessPolicy` | `crates/authn-audit/src/policy.rs` | `check(principal, org, permission, client_ip)` |
| `authn_audit::OutboxHandler` | `crates/authn-audit/src/outbox/worker.rs` | outbox işçisi (konu öneki başına) |
| `authn_account::AccountErasureHook` | `crates/authn-account/src/hooks.rs` | silme transaction'ı, kaskaddan önce (yalnızca verilen bağlantı, ağ yok) |
| `authn_account::EmailChangeRevertHook` (wave 3A, K-20) | `crates/authn-account/src/hooks.rs` | e-posta değişikliği geri alma transaction'ı, oturumlar kapatıldıktan sonra, commit'ten önce (yalnızca verilen bağlantı; hata geri almayı geri alır) |
| `authn_oidc_client::LoginMethodInventory`, `authn_oidc_client::SessionLiveness` | `crates/authn-oidc-client/src/hooks.rs` | ayırma / bağlama transaction'ı (kullanıcı satırı kilitli) |
| `authn_admin::SigningKeyCache` | `crates/authn-admin/src/hooks.rs` | acil anahtar rotasyonundan sonra (senkron) |

Kural: kanca uygulaması **yalnızca verilen bağlantıdan** okur (ikinci bir havuz bağlantısı kilitli satırı göremez veya kilitlenmeye yol açar) ve yan etki üretmez; yazma gerekiyorsa sahibin `*_in_tx` API'si aynı bağlantıyla çağrılır.

---

## 5. Tablo sahipliği

Şema tek bir yerde tasarlandı (`migrations/0001`–`0012`); Dalga A modülleri kendi aralıklarında tablo/kolon/indeks ekledi (§6). Sahip modül tabloya yazan **tek** crate'tir; diğerleri yalnızca sahibin API'si veya portu üzerinden erişir. Okuma için doğrudan SQL gerekiyorsa §13; onaylanmış istisnalar aşağıda listelidir.

| Tablo | Sahip | Not |
|-------|-------|-----|
| `users`, `password_credentials` | store | Temel CRUD `UserRepository` (`find_many`, bakım işleri için `claim_next` dahil); durum geçiş kuralları account, hash mantığı crypto/password. Salt-okunur istisna: authn-audit takma ad çözümünde `users.id`/`users.status`'u kendi `audit_subjects` tablosuyla tek ifadede birleştirir (AUD-03, AUD-05) |
| `user_profiles`, `terms_versions`, `consents`, `account_deletions`, `email_reservations`, `pending_registrations` | account | `email_reservations` (1200): e-posta değişikliğinden sonra eski adres, geri alma süresi boyunca eski sahibine ayrılır (ACC-07); kayıt ve değişiklik ayrılmış adrese kayıtlı adres gibi yanıt verir. `pending_registrations` (1201, ADR 0002): her kaydın kimlik bilgileri (şifre hash'i, profil, şartlar) kendi doğrulamasına bağlı bekler; yalnızca o kayıt doğrulanınca hesaba yazılır (ön-ele geçirme savunması) |
| `sessions`, `refresh_tokens`, `auth_challenges` | session | |
| `one_time_tokens` | paylaşımlı | Her `purpose` değeri tek bir modüle aittir (aşağıda) |
| `mfa_factors`, `recovery_codes`, `mfa_user_settings`, `trusted_devices` | mfa | |
| `webauthn_user_handles`, `webauthn_credentials`, `webauthn_ceremonies` | webauthn | |
| `identities`, `oauth_states`, `oauth_token_revocations` | oidc-client | `identities` Faz 2 kurumsal SSO'nun da bağlantı noktasıdır; `identities.token_client_id` (2102). `oauth_states.remember_me` / `shared_device` (2100), `session_id` (2101, bağlama akışında zorunlu; FK yok — oturum silinse de state 10 dk'da ölür). `oauth_token_revocations` (2102): silinen / ayrılan kimliklerin sağlayıcı token iptal kuyruğu (zarf şifreli, **kullanıcı kimliği yok**, sınırlı yeniden deneme) |
| `admin_action_reasons`, `admin_reason_restrictions`, `admin_passkey_enrollments`, `admin_operation_leases` | admin | `admin_action_reasons` (2200): admin işlem gerekçeleri, `audit_events(id)`'ye FK, ekleme-yalnızca tetikleyici. `admin_reason_restrictions` (2201): yasal kısıtlamalar, ekleme-yalnızca. `admin_passkey_enrollments` (2201): break-glass kayıt bağlantıları (yalnızca token hash'i). `admin_operation_leases` (2201): küme genelinde tek eşzamanlı pahalı işlem kiralaması. Wave 3B eklemeleri (`admin_approvals`, `admin_reason_restriction_periods`, migration `2202`) authn-admin README'sinde |
| `organizations`, `roles`, `role_permissions`, `memberships`, `invitations`, `org_domains`, `org_policies`, `service_accounts`, `api_keys`, `org_auto_join_exclusions` | org | Yerleşik roller sabit kimliklerle `0012`'de. `org_auto_join_exclusions` (1501): çıkarılan/ayrılan üye domain otomatik katılımıyla geri eklenmez (ORG-02, ORG-06). `memberships_last_owner` ertelenmiş kısıtı (1500) bir organizasyonun son aktif sahibinin `users` satırının silinmesini commit'te reddeder (ACC-09'un ikinci savunma hattı) |
| `rate_limit_buckets` (UNLOGGED), `login_soft_locks`, `captcha_pow_challenges`, `known_devices`, `known_networks` | protect | |
| `audit_subjects`, `audit_events`, `audit_event_pii`, `audit_chain_head`, `audit_chain_checkpoints`, `outbox`, `webhook_endpoints`, `webhook_deliveries` | audit | notify, `outbox`'a `notification.*` konulu kayıt **ekler** (Notifier uygulaması) |
| `signing_keys`, `data_encryption_keys` | crypto | `data_encryption_keys` **ayrılmış, kullanılmıyor** (0014 yorumu): CRY-08 zarfı kendi KEK ile sarılmış DEK'ini taşır (`version ‖ kek_id ‖ wrapped_dek ‖ nonce ‖ ciphertext`); tablo ileride KMS sarılmış-DEK önbelleği için boş tutulur |

`one_time_tokens.purpose` kaydı:

| Purpose | Sahip | Tür |
|---------|-------|-----|
| `email_verification` / `email_verification_code` | account | link / code |
| `email_change` / `email_change_code` / `email_change_revert` | account | link / code / link |
| `account_deletion_cancel` | account | link |
| `password_reset` / `password_reset_code` | password | link / code |
| `magic_link` / `login_code` / `not_me` | session | link / code / link |
| `mfa_email_otp` / `mfa_sms_otp` / `phone_verification` | mfa | code |
| `org_ownership_transfer` | org | link |

Purpose kayıt defteri **kodda** `authn_store::TokenPurpose` enum'udur (bu tablonun birebir karşılığı; link/kod türü `TokenPurpose::kind()`'dan türetilir, dize ile yeni amaç yaratılamaz, bilinmeyen değer okumada `Corrupt` hatasıdır). Yeni purpose = `TokenPurpose` varyantı + `kind()` kolu + bu tabloya satır; sahibi §13 kaydıyla mimardan ister.

Purpose'a özgü sözleşmeler:
- `password_reset` / `password_reset_code`: `target` = gönderildiği normalize adres; adres değiştiyse, şifre kaldırıldıysa veya hesap uygun durumdan çıktıysa tüketim reddedilir (PWD-07, PWD-09).
- `email_change_revert`: geri alma, `OneTimeTokenRepository::revoke_for_user_since` ile yalnızca kendisinden **sonra** verilmiş geri alma linklerini iptal eder; eski sahibin önceki linki korunur (ACC-07).
- `org_ownership_transfer`: `group_id` = `target` = organizasyon kimliği, `metadata.from_user_id` = başlatan; `revoke_group(org)` organizasyonun tüm bekleyen devirlerini iptal eder (ORG-11).

Başka modülün purpose'ları üzerinde **yalnızca iptal** istisnaları (iptal erişimi kaldırır, hiçbir şey vermez; okuma ve tüketme yasaktır):
- authn-account, adres değiştiğinde veya değişiklik geri alındığında kullanıcının adresine gönderilmiş **tüm** purpose'ları iptal eder (`authn_account::ADDRESS_BOUND_PURPOSES`: `password_reset*`, `magic_link`, `login_code`, `not_me`, `mfa_email_otp` dahil). Adrese gönderilen yeni bir purpose eklenirse bu listeye de eklenir.
- authn-password (şifre sıfırlama) ve authn-session ("tümünü kapat", "bu ben değilim") account'un bekleyen `email_change` / `email_change_code` token'larını iptal **edebilir** (önerilir; aksi hâlde 24 saatlik değişiklik linki ele geçirilmiş oturumdan sonra da çalışır).

Okuma API'leri: `OneTimeTokenRepository::active_for_user(executor, user, purposes, now)` (hash hariç, yalnızca kendi purpose'larınız — ör. ACC-10 dışa aktarma), `find_active_link`, `find_by_id`.

Yeni purpose eklemek sahibin işidir; bu tabloya §13 ile eklenir. Kurallar: link token = 256 bit, `token_hash = SHA-256(token)`, global benzersiz; kod = 6 hane, `token_hash = HMAC-SHA256(alt anahtar, kod)`, yalnızca `(user_id | challenge_id, purpose)` ile aranır; tüketim tek atomik `UPDATE … WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $now RETURNING` ile yapılır; yeni istek öncekileri `revoked_at` ile geçersiz kılar; birlikte üretilen link + kod aynı `group_id`'yi taşır.

Şema kuralları (tüm migration'lar için):
- Birincil anahtarlar uygulamada üretilen UUIDv7'dir; dışa sıralı tamsayı açılmaz.
- Zaman alanları `timestamptz`; değerler enjekte edilen `Clock`'tan gelir (DB varsayılanları yalnızca yedek).
- Enum'lar `text` + `CHECK`; PostgreSQL ENUM tipi kullanılmaz.
- Sırlar düz saklanmaz: token/kod → 32 baytlık hash; geri dönüştürülebilir sırlar → `*_ciphertext bytea` (CRY-08 zarfı, AAD = tablo/kolon/satır kimliği).
- Kullanıcıya ait satırlar `REFERENCES users ON DELETE CASCADE`; "oluşturan" türü referanslar `ON DELETE SET NULL`; rol referansları `ON DELETE RESTRICT`. Hesap silme `users` satırını siler ve tüm kişisel veriyi kaskadla temizler (ACC-09, AUD-05).
- Organizasyon kapsamlı her tabloda `org_id` vardır; çapraz kiracı referansları tetikleyici (`authn_check_role_tenant`) ve bileşik FK'larla engellenir.

---

## 6. Migration'lar

- Dosya adı: `migrations/<SÜRÜM>_<açıklama>.sql`, sürüm 4 hanelidir (ör. `1105_password_history.sql`). Sürümler sayısal sıralanır.
- Her modül **yalnızca kendi aralığına** yazar (`authn_store::MIGRATION_RANGES`, test ile zorlanır):

| Aralık | Sahip |
|--------|-------|
| 0001–0099 | mimar (core/store; ilk şema `0001`–`0012`) |
| 1000–1099 | authn-crypto |
| 1100–1199 | authn-password |
| 1200–1299 | authn-account |
| 1300–1399 | authn-mfa |
| 1400–1499 | authn-webauthn |
| 1500–1599 | authn-org |
| 1600–1699 | authn-protect |
| 1700–1799 | authn-audit |
| 1800–1899 | authn-notify |
| 2000–2099 | authn-session |
| 2100–2199 | authn-oidc-client |
| 2200–2299 | authn-admin |
| 2900–2999 | authn-server |
| 3000+ | Faz 2/3 için ayrılmış |

- Uygulanmış bir migration **asla değiştirilmez** (sqlx checksum'ı uyuşmazlığı hazır olma kontrolünü düşürür). Düzeltme yeni bir migration ile yapılır.
- Bir modül yalnızca **kendi tablolarını** değiştirir; başka tabloya kolon/indeks gerekiyorsa §13.
- Migration'lar eklemelidir (expand/contract): kolon silme/yeniden adlandırma iki adımda yapılır.
- `authn-store` ve `authn-testkit`'in `build.rs` dosyaları `migrations/` değiştiğinde yeniden gömmeyi tetikler.
- Düşük sürümlü yeni migration'lar (ör. mimarın `0013`'ü, `1200` uygulanmış bir veritabanında) da uygulanır: sqlx sürüm sırasına değil "uygulanmamış" kümesine bakar (`authn-store/tests/schema.rs` `ops_10_architect_migrations_added_after_module_ranges_still_apply`).
- En az yetki (OPS-10, AUD-02): uygulama rolü `audit_events` üzerinde `UPDATE`/`DELETE`/`TRUNCATE` yetkisine sahip olmamalıdır; tablo ayrıca tetikleyiciyle ekleme-yalnızca korunur. Tüm şema için çalıştırılabilir yardımcı (2900, authn-server, wave 3A): `SELECT authn_apply_least_privilege('<uygulama_rolü>', '<bakım_rolü>');` — her tablodaki yetkileri geri alıp modül tablolarına `SELECT, INSERT, UPDATE, DELETE`, ekleme-yalnızca admin tablolarına `SELECT, INSERT` verir ve audit kısmı için aşağıdaki 1700 fonksiyonunu çağırır (ayrıntı ve runbook: [`docs/operations/least-privilege.md`](../operations/least-privilege.md)). Audit yardımcısı (1700, authn-audit): `SELECT authn_audit_apply_least_privilege('<uygulama_rolü>', '<bakım_rolü>');` — iki rolden de tüm audit/outbox/webhook tablolarındaki yetkileri önce geri alır; sonra uygulama rolüne `audit_events` üzerinde yalnızca `SELECT, INSERT` (ve takma ad / PII tablolarında ekleme-silme, outbox/webhook tablolarında olağan yetkiler), bakım rolüne saklama temizliği (`audit_events`/`outbox`/`webhook_deliveries` üzerinde `DELETE`) ve kontrol noktası ekleme yetkisi verir. Kurulum runbook'unda (DOC-06) uygulama rolü bu çağrıdan sonra tablo sahibi **olmamalıdır** (sahip her yetkiye sahiptir). `AuditService::run_maintenance` ve `create_checkpoint` bakım rolünün havuzuyla çalışır (ayrı `PgPool`, §15.6). Saklama temizliği yalnızca `SET LOCAL authn.audit_purge_before = '<zaman>'` ile ve `audit_chain_checkpoints` kaydıyla yapılır.

Dalga A sonrası migration'lar:

| Sürüm | Sahip | İçerik |
|-------|-------|--------|
| `0013` | mimar | `password_credentials_wrapped_pepper_check`: `argon2id*` şemaları (`argon2id_wrapped_md5/sha1` dahil) `pepper_version` taşır (CRY-02, CRY-04) |
| `0014` | mimar | `data_encryption_keys` "ayrılmış" yorumu (CRY-08); `users_locked_until_idx` (ACC-06 kilit açma işi) |
| `1200` | account | `account_deletions.previous_status`, `email_reservations` |
| `1300` | mfa | `mfa_user_settings` kullanıcı kilidi kolonları, kullanıcı başına tek e-posta faktörü, temizlik indeksleri |
| `1400` | webauthn | `webauthn_credentials.clone_suspected_at`, `discoverable`; seremoni bağlama CHECK'leri |
| `1500`, `1501` | org | API anahtarı tek sahip / üyelik FK, servis hesabı sahip olamaz, `role_permissions_owner_only`, `memberships_last_owner` ertelenmiş kısıtı; `org_auto_join_exclusions` |
| `1600` | protect | `rate_limit_buckets.allowed` (tek ifadede GCRA kararı), risk ve temizlik indeksleri |
| `1700` | audit | `webhook_endpoints.failing_since`, `last_success_at`, teslim/kiralama indeksleri, `authn_audit_apply_least_privilege` |
| `0015` | mimar (wave 1) | `users_created_id_idx (created_at DESC, id DESC)`: admin kullanıcı listesi keyset sayfalaması (`UserRepository::search`, ADM-02, K-38) |
| `1201` | account | `pending_registrations` (ADR 0002 ön-ele geçirme savunması) |
| `1401` | webauthn (wave 2B) | kayıt seremonisi oturuma **veya** break-glass bağlantı hash'ine bağlı (tam olarak biri, K-11) |
| `2000` | session | oturum çekirdeği: `sessions.login_method` (org politikası yeniden uygulaması, SES-17), `sessions.scopes`, `auth_challenges.primary_method`; temizlik işi ve ardıl token indeksleri |
| `2100` | oidc-client (wave 2A) | `oauth_states.remember_me`, `shared_device` (yalnızca `login` akışında, K-32) |
| `2101` | oidc-client (wave 2A) | `oauth_states.session_id` (bağlama akışında zorunlu; yarıda kalan bağlama akışları silinir, K-03) |
| `2102` | oidc-client (wave 2A) | `identities.token_client_id`, `oauth_token_revocations` (K-35) |
| `2200` | admin | `admin_action_reasons` + ekleme-yalnızca tetikleyici (ADM-08) |
| `2201` | admin (wave 2B) | `admin_passkey_enrollments`, `admin_operation_leases`, `admin_reason_restrictions` (K-09, K-11, K-39) |
| `2900` | authn-server (wave 3A) | `authn_apply_least_privilege(app_role, maintenance_role)`: tüm şema için en az yetki (OPS-10, K-42; `docs/operations/least-privilege.md`) |

---

## 7. AppState / FromRef router deseni (ARC-03)

`AppState` yalnızca `authn-server`'da tanımlıdır. Her modül crate'i:

```rust
/// Modülün ihtiyaç duyduğu her şey (portlar Arc<dyn …> olarak).
#[derive(Clone)]
pub struct PasswordService { /* pool, clock, notifier, revoker, config … */ }

pub fn router<S>() -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
    PasswordService: axum::extract::FromRef<S>,
{
    axum::Router::new().route("/v1/password/reset", axum::routing::post(request_reset))
}

async fn request_reset(
    axum::extract::State(svc): axum::extract::State<PasswordService>,
    ctx: authn_core::http::RequestContext,
    authn_core::http::Json(body): authn_core::http::Json<ResetRequest>,
) -> Result<axum::http::StatusCode, authn_core::AuthError> { /* … */ }
```

`authn-server` tarafında: `impl FromRef<AppState> for PasswordService` ve `build_router` içinde `.merge(authn_password::router::<AppState>())`. Çalışan referans: `crates/authn-server/src/routes/example.rs` (`GET /v1/time`) ve `src/state.rs`.

Kurallar:
- Handler'lar `AppState`'i görmez; testlerde router doğrudan servisin kendisiyle kurulabilir (`router().with_state(service)`), çünkü `FromRef<T> for T` vardır.
- Kimlik doğrulanmış çağıran `authn_core::domain::Principal` extractor'ı ile alınır (session/org middleware'i request extension'a koyar). Step-up: `principal.require_recent_authentication(now, max_age)`; salt-okunur impersonation: `principal.require_writable()`.
- İstek bilgisi `authn_core::http::RequestContext` extractor'ı ile alınır (istek kimliği, istemci IP'si, user-agent, cihaz kimliği, dil).
- Gövde/sorgu/yol için `authn_core::http::{Json, Query, Path}` kullanılır (reddedilmeler standart hata zarfıyla döner); axum'un orijinalleri kullanılmaz.
- Tüm endpoint'ler `/v1/...` altında, JSON alanları `snake_case`, her handler `#[utoipa::path]` ile belgelenir; modül kendi `#[derive(utoipa::OpenApi)]` yapısını dışa açar, server birleştirir.
- **Yol parametresi adları:** axum 0.8 (matchit), aynı statik önekten sonra aynı konumda farklı adla kaydedilmiş parametreleri çakışma sayar ve `Router::merge` açılışta panikler (`/v1/orgs/{id}/members` + `/v1/orgs/{org_id}/webhooks`). Bu yüzden: parametre adları `snake_case`'tir ve kaynağın kimliği için `<kaynak>_id` biçimindedir; aynı konumdaki parametre her router'da (ve `#[utoipa::path(path = …)]`'ta) **aynı adı** taşır. Kanonik adlar: `/v1/orgs/{org_id}/…`, `/v1/admin/users/{user_id}/…`, `/v1/me/sessions/{session_id}`; alt kaynaklar `{member_id}`, `{role_id}`, `{key_id}`, `{factor_id}`, `{passkey_id}` vb. Zorlayan test: `crates/authn-testkit/tests/routes.rs` (`arc_09_*`; tüm crate'lerin `.route(` ve `path = ` dizelerini tarar).
- **Aynı yol, farklı metot:** iki router aynı yolu yalnızca farklı HTTP metotlarıyla kaydedebilir (axum metotları birleştirir, aynı metotta panikler). Ayrılmış: `GET /v1/me` → authn-session (SES-16), `DELETE /v1/me` → authn-account (ACC-09).
- **API anahtarı kapsamı:** `authn_org::api_key_middleware` `Principal`'ı yalnızca `/v1/orgs/{org_id}` ve altındaki yollarda üretir; SES-10 gibi istemci kimlik doğrulaması isteyen uç noktalar `OrgService::authenticate_api_key`'i doğrudan çağırır. `/v1/me/…` okuyucuları derinlemesine savunma olarak `principal.session_id().is_none()` (API anahtarı) olan principal'ları reddetmelidir.
- Modülün middleware'i (ör. protect katmanları, session kimlik doğrulaması) `pub fn layer(…)`/`from_fn_with_state` olarak dışa açılır; yığına yerleştirme `authn-server`'ın işidir (OPS-02 sırası: `src/app.rs`).

---

## 8. Hata kodları (ARC-08)

- Her kod `ErrorCode::new("snake_case", StatusCode, "English", "Türkçe")` ile, sahibinin dosyasında (`error/codes/<modül>.rs`) bir `pub const` olarak tanımlanır ve aynı dosyadaki `ALL` dizisine eklenir. Benzersizlik ve biçim `error/codes/mod.rs` testleriyle zorlanır.
- Ortak kodlar `codes::common` içindedir ve herkes kullanabilir: `internal_error`, `bad_request`, `validation_failed`, `unauthenticated`, `forbidden`, `not_found`, `method_not_allowed`, `conflict`, `payload_too_large`, `unsupported_media_type`, `request_timeout`, `rate_limited`, `too_many_attempts`, `service_unavailable`, `step_up_required`, `invalid_or_expired_token`, `invalid_code`. `codes::session::INVALID_CREDENTIALS` (`invalid_credentials`) önceden tanımlıdır.
- Yayınlanmış bir kod asla yeniden adlandırılmaz veya anlamı değiştirilmez.
- Zarf: `{"error":{"code":"…","message":"…","request_id":"…","details"?:…}}`. `details` yalnızca kimliği doğrulanmamış bir saldırgana gösterilmesi güvenli veriler içindir.
- `AuthError::internal(...)`/`with_source(...)`/`with_context(...)` ile iç ayrıntılar **yalnızca loglanır**; 5xx yanıtlar her zaman genel `internal_error` mesajını taşır. `?` ile gelen `sqlx::Error` otomatik `internal_error` olur (havuz zaman aşımı → `service_unavailable`).
- Yerelleştirme: handler kullanıcı tercihini biliyorsa yanıta `Locale` extension'ı ekler; yoksa `Accept-Language`, o da yoksa `server.default_locale` kullanılır.
- Hesap varlığı sızdırılmaz: kayıt (ACC-02), şifre sıfırlama (PWD-07), magic link (SES-18), giriş (SES-01) akışlarında var olan/olmayan hesap için **aynı durum kodu, gövde ve benzer süre** döner. `StoreError::UniqueViolation` bu akışlarda `conflict`'e dönüştürülmeden ele alınmalıdır.
- `429` yanıtları `Retry-After` taşır: `RateLimitDecision::into_result()` veya `AuthError::with_retry_after`.

---

## 9. Konfigürasyon (ARC-07)

- `AppConfig::load(path)` = TOML dosyası + `AUTHN__BÖLÜM__ANAHTAR` ortam değişkenleri (figment). Bilinmeyen anahtarlar reddedilir (`deny_unknown_fields`).
- Her modülün bölümü kendi dosyasındadır (`config/<modül>.rs`): tipli alanlar, alan başına belgelenmiş varsayılan (spesifikasyon değeri), `validate(&self, &mut ConfigProblems)`. Yeni alan eklemek sahibin işidir; `config/example.toml`'daki yorumlu satırlar da güncellenir (test: `authn-server/tests/example_config.rs`).
- Süreler `#[serde(with = "authn_core::config::duration")]` ile (`"30s"`, `"15m"`, `"2h"`, `"7d"`), rate limit politikaları `RateLimitPolicy { limit, period }` ile ifade edilir.
- Sırlar `SecretString`'dir, `Debug`'da görünmez; doğrulama mesajları anahtar adını verir, **değeri asla**. Anahtar materyali base64 ≥ 32 bayt (`ConfigProblems::require_key`).
- Zorunlu alanlar: `server.public_base_url`, `database.url`, `crypto.peppers`, `crypto.current_pepper_version`, `crypto.keks`, `crypto.current_kek_id`, `crypto.hmac_root_key`.
- `server.environment` varsayılanı `production`'dır (en katı). Üretim/staging'de depoda yayımlanmış örnek/test anahtarları reddedilir (`KNOWN_PUBLIC_KEYS`). Üretimde `public_base_url` https olmalıdır; bellek içi rate limit ve özel ağlara giden istek izni yasaktır.
- Ortama bağlı `[notify]` kuralları (`AppConfig::validate`, `check-config` dahil; authn-notify builder'ları açılışta yeniden uygular): `notify.email.transport = "log"` ve `notify.sms.provider = "log"` yalnızca `development`/`test`'te; `notify.email.transport = "disabled"` üretimde yasak; `notify.email.smtp.extra_ca_file` yalnızca `development`/`test`'te (docker-compose Mailpit'in sabit, **herkese açık** geliştirme sertifikası `config/dev-certs/mailpit.pem` için; bkz. `config/dev-certs/README.md`).

---

## 10. HTTP katmanı ve istek bağlamı

- `authn_core::http::request_context_middleware` en dış katmandır: her istek için yeni bir UUIDv7 istek kimliği üretir (istemcinin `x-request-id`'si **yok sayılır**), istemci IP'sini PRT-06'ya göre çözer, user-agent'ı temizler/kısaltır (≤ 512 bayt), cihaz kimliğini doğrular (`x-device-id` başlığı veya `__Host-authn_device` çerezi, `[A-Za-z0-9_-]{16,128}`), dili belirler ve `RequestContext`'i extension olarak ekler. Çıkışta tüm hata yanıtlarını standart zarfa çevirir (JSON olmayan 4xx/5xx yanıtlar dahil — panik metinleri sızmaz) ve `x-request-id` başlığını ekler.
- TCP eşi `ConnectInfo<SocketAddr>`'dan okunur (`into_make_service_with_connect_info`); yoksa istek `internal_error` ile reddedilir. Testlerde `authn_testkit::http::TestRequest` bunu otomatik ekler.
- IP çözümü: eş güvenilir proxy değilse eşin IP'si; güvenilir ise yalnızca yapılandırılan başlık (`x-forwarded-for` **veya** `forwarded`) sağdan sola yürünür, ilk güvenilmeyen adres istemcidir; ayrıştırılamayan adımda en yakın güvenilir adımda durulur; en fazla 32 adım.
- Middleware sırası (OPS-02) `crates/authn-server/src/app.rs`'de belgelidir; protect ve session katmanları işaretli yerlere eklenir.

---

## 11. Güvenlik kuralları (tüm crate'ler)

- `unsafe` yasak (`unsafe_code = "forbid"`); production kodunda `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`/`dbg!`/`process::exit` yok (clippy `deny`).
- Rastgelelik yalnızca CSPRNG (`getrandom`/`rand` OS RNG); kriptografi yalnızca `authn-crypto` üzerinden; kendi algoritmanızı yazmayın.
- Sır karşılaştırmaları sabit zamanlı (`authn_core::secret::constant_time_eq` veya `subtle`).
- Sırlar `SecretString`/`SensitiveString`/`Zeroizing` içinde; log'a, audit'e, hata mesajına, `Debug` çıktısına girmez. Kişisel veri loglanacaksa `authn_core::redact::{mask_email, mask_ip}` ile.
- SQL metinleri `&'static str`'dir (sqlx 0.9 dinamik SQL'i derleme hatasıyla reddeder); değerler daima bind parametresidir. `AssertSqlSafe` yalnızca sabit test fixture'larında.
- `reqwest` istemcisi oluşturmadan önce `authn_core::tls::install_crypto_provider()` çağrılır (rustls yalnızca `ring` sağlayıcısıyla derlenir; aksi halde reqwest panikler). Kullanıcı tarafından verilen URL'ler yalnızca `HttpClient` portu (`OutboundTarget::UserSupplied`) ile çağrılır.
- Linkler yalnızca `server.public_base_url` ile kurulur; `Host` başlığı hiçbir URL üretiminde kullanılmaz.
- Yetkilendirme varsayılan reddet; başka kiracının kaynağı `404` döner (ORG-10).
- Zamanlama: kimliği doğrulanmamış akışlarda kullanıcı bulunamadığında da eşdeğer iş yapılır (sahte Argon2 doğrulaması, CRY-05); testlerde `authn_testkit::timing::compare_timings`.
- Argon2 `spawn_blocking` + semafor altında (ARC-12).

---

## 12. Test kuralları

- Test adları gereksinim kimliğini içerir: `pwd_07_reset_token_is_single_use`.
- Veritabanı testleri: `#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]` (her test kendi geçici veritabanını alır). `DATABASE_URL` `.cargo/config.toml`'da varsayılanlıdır ve sunucuda `authn` veritabanı bulunmalıdır (`docker compose up -d` oluşturur).
- HTTP testleri: `authn_testkit::http::{with_request_context, TestRequest}` ile router üzerinden `oneshot`; hata zarfı `TestResponse::assert_error(status, "code")`.
- Portlar için `authn_testkit::TestPorts` (ortak `FakeClock`); zaman `ports.clock.advance(..)` ile ilerletilir, `OffsetDateTime::now_utc()` çağrılmaz. `RecordingNotifier` SMS'i de kaydeder (`recorded_sms`, `set_sms_available(false)` → `sms_unavailable`); `RecordingAuditSink::pseudonymized()` `pseudonymize_subject` çağrılarını verir.
- Mimari testler (`crates/authn-testkit/tests/`): `architecture.rs` (bağımlılık grafiği, §2), `routes.rs` (yol parametresi adları, §7), `dev_certs.rs` (geliştirme sertifikası, §9).
- Dış servisler `wiremock` veya `FakeHttpClient` ile; ağ bağımlılığı yok (TST-08).
- Entegrasyon test dosyaları (`tests/*.rs`) ilk satırda şunu taşır (clippy test gevşetmeleri yardımcı fonksiyonlara uygulanmaz):
  `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate`
- Crate başına komutlar (paralel çalışırken **asla** `cargo fmt --all` çalıştırmayın):

```bash
cargo test -p <crate>
cargo clippy -p <crate> --all-targets -- -D warnings
cargo fmt -p <crate>
```

- Tam kapılar (orkestratör / CI): `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo deny check`, `cargo audit`, `cargo llvm-cov`, `cargo +nightly fuzz build` (`.github/workflows/ci.yml`).

---

## 13. Sözleşme değişikliği talebi

Başka bir sahibin dosyasında (port imzası, ortak tip, başka modülün tablosu/konfigürasyonu, kök `Cargo.toml`, `deny.toml`) değişiklik gerektiğinde:

1. `docs/architecture/contract-change-requests.md` dosyasına **kendi crate başlığınızın altına** bir kayıt ekleyin (başkalarının bölümünü düzenlemeyin):
   - Tarih, talep eden crate, etkilenen dosya/sahip
   - Gerekçe (gereksinim kimliğiyle)
   - Önerilen değişiklik (imza/şema taslağı)
   - Geriye uyumluluk etkisi
2. Bu arada kendi crate'inizde geçici bir yerel tip/adaptör ile ilerleyin; sahibin dosyasını değiştirmeyin.
3. Sahip (veya mimar) talebi uygular ve kaydı "Uygulandı" olarak işaretler.

Geriye uyumlu **eklemeler** (yeni port metodu varsayılan gövdeyle, yeni hata kodu kendi dosyanızda, yeni konfigürasyon alanı kendi dosyanızda, kendi aralığınızda yeni migration) talep gerektirmez.

---

## 14. Mimari kararlar (özet)

| Karar | Gerekçe |
|-------|---------|
| JWT için `jsonwebtoken` yerine `ed25519-dalek` üzerinde sabit algoritmalı minimal JWS (CRY-09) | `alg` karışıklığı saldırı yüzeyini ortadan kaldırır; `jsonwebtoken`'ın `rust_crypto` arka ucu `rsa 0.9` ve `p256/p384 0.13` (RUSTSEC-2023-0071, RUSTSEC-2026-0387) getiriyordu |
| rustls yalnızca `ring` sağlayıcısıyla; `reqwest` `rustls-no-provider` | aws-lc-sys (OpenSSL lisans ifadesi, C derleme) yok; tek sağlayıcı, `authn_core::tls::install_crypto_provider()` |
| Redis istemcisi `fred` (MIT) | `redis-rs`'in async yığını `xxhash-rust` (BSL-1.0) getiriyor; BSL-1.0 LIC-01 listesinde değil |
| `openidconnect`/`oauth2` varsayılan özellikler kapalı | eski `reqwest 0.12` yerine kendi (SSRF korumalı) HTTP istemcimiz bağlanır |
| `webauthn-rs` MPL-2.0 istisnası (`deny.toml`'da crate bazında) | LIC-01'in tek onaylı istisnası; aile `crypto-glue`, `compact_jwt`, `base64urlsafedata`, `webauthn-attestation-ca` içerir |
| `deny.toml` advisory istisnaları: RUSTSEC-2023-0071 (`rsa` 0.9), RUSTSEC-2026-0387 (`crypto-bigint` 0.5) | Yalnızca `openidconnect` içinde, yalnızca **açık anahtarla imza doğrulaması** (gizli veri yok). Gizli anahtar EC işlemleri (Apple ES256 client secret) yalnızca `p256 0.14` ile yapılır |
| Audit kişisel verisi zincir dışında (`audit_subjects`, `audit_event_pii`, `pii_digest`) | Hesap silmede zincir bozulmadan takma adlaştırma (AUD-05) |
| Hesap silme = `users` satırının silinmesi + `account_deletions` kaydı | FK kaskadları tüm modül verisini garantili temizler |
| SQL'de enum yerine `text` + `CHECK` | Değer eklemek basit bir kısıt değişikliğidir |
| `EmailAddress` `sqlx::Decode` uygulamaz | Kurallar sertleştiğinde eski satırlar okunamaz hale gelmez |
| `AuthError` kutulanmış (`Box<Inner>`) | `Result<T, AuthError>` işaretçi boyutunda; `clippy::result_large_err` yok |
| `fuzz/` ayrı workspace | `libfuzzer-sys` (NCSA; BSD benzeri, ticari kullanıma izin verir; proje sahibi onayladı) yalnızca geliştirme aracında; `fuzz/deny.toml` istisnayı yalnızca o crate için tanır (webauthn-rs ailesinin MPL-2.0 istisnaları kökle aynı); kök `deny.toml` `[bans]` crate'i ürün workspace'inde yasaklar |
| Dalga A modülleri arası veri ihtiyacı → modülün kendi crate'inde kanca trait'i, uygulaması server'da (§4, §15.1) | Dalga A'nın birbirine bağımlı olmaması korunur; varsayılan uygulamalar testleri ve tek kiracılı kurulumu basit tutar |
| `data_encryption_keys` tablosu ayrılmış (kullanılmıyor) | Değer başına DEK zarfın içinde taşınır: şifre çözmede DB araması yok, nonce yeniden kullanımı imkânsız, KEK rotasyonu satır bazında `rewrap` |
| Bakım işleri `UserRepository::claim_next` (`FOR UPDATE SKIP LOCKED`) ile satır talep eder | Çoklu instance güvenli (OPS-06); kilitli satır beklenmez, atlanır |
| Mailpit için depoda sabit, herkese açık geliştirme sertifikası (`config/dev-certs`) | SMTP taşıyıcısı TLS'i doğrular (NTF-03); her açılışta değişen sertifikaya güvenilemez. `extra_ca_file` geliştirme/test dışında reddedilir |

---

## 15. Sunucu bağlama tablosu

Dalga A modüllerinin authn-server (ve gerekli yerlerde Dalga B) tarafından bağlanması gereken her trait, port uygulaması, servis, router, katman, iş ve CLI adımı. Kaynak: modül README'lerinin "server'ın bağlaması gerekenler" bölümleri ve `contract-change-requests.md`'deki bağlama kayıtları. Bir satır uygulanınca ilgili talep kaydı "Uygulandı" olarak işaretlenir.

### 15.1 Kanca trait'leri (server uygular)

| Trait | Sahip / dosya | Server uygulaması (veri kaynağı) | Tüketen ve gereksinim |
|-------|---------------|----------------------------------|-----------------------|
| `authn_password::LoginMethodInventory::other_login_methods(conn, user)` | password / `crates/authn-password/src/hooks.rs` | `WebauthnService::passkey_count_in(conn, user, true) > 0` → `LoginMethod::Passkey`; `OidcClientService::linked_identity_count_in(conn, user) > 0` → `LoginMethod::Social`; **yalnızca `conn`'dan** (`ServerLoginMethods`) | `PasswordService` şifre kaldırma (PWD-11) |
| `authn_password::ProfileLookup::profile(user)` | password / `hooks.rs` | `AccountService::profile_of(user)` → `ProfileHints { display_name, locale }` | zxcvbn girdileri ve bildirim dili (PWD-04) |
| `authn_account::OrganizationOwnership::sole_owner_organizations(conn, user)` | account / `crates/authn-account/src/hooks.rs` | `authn_org::sole_owner_organizations(conn, user)` | hesap silme (ACC-09) |
| `authn_mfa::MfaPolicySource::org_policy_for_user(conn, user)` | mfa / `crates/authn-mfa/src/hooks.rs` | `authn_org::policies_for_user(conn, user)` → her biri `OrgMfaPolicy`'ye, `OrgMfaPolicy::strictest` ile birleştir (tüm aktif üyelikler); düz bağlantıyla da çağrılır | son faktör kuralı, güvenilir cihaz izni (MFA-07, MFA-08, MFA-09) |
| `authn_mfa::MfaPolicySource::webauthn_factor_count(conn, user)` | mfa / `hooks.rs` | `WebauthnService::passkey_count_in(conn, user, false)` | son faktör kuralı (MFA-07) |
| `authn_webauthn::AccountMethodsSource::other_login_methods(conn, user)` | webauthn / `crates/authn-webauthn/src/hooks.rs` | şifre (`UserRepository::find_password(conn, user)`), bağlı sosyal kimlikler (`linked_identity_count_in`). Parolasız e-posta girişi (magic link / e-posta kodu) **sayılmaz**: adresi olan her hesapta vardır, sayılsa "son güçlü yöntem" kuralı (PWD-11 "güçlü yöntem", SOC-06) anlamsızlaşırdı; üç adaptör aynı kuralı uygular | passkey silme (PKY-04, PWD-11) |
| `authn_webauthn::AccountMethodsSource::mfa_facts(conn, user)` | webauthn / `hooks.rs` | `MfaService` durumu + kuruluş politikası (`mfa_required`, passkey dışı etkin faktör sayısı) | passkey silme (MFA-07) |
| `authn_webauthn::PasskeyPolicySource::policy_for_user(conn, user, active_org)` | webauthn / `hooks.rs` | `active_org = Some` → o organizasyonun AAGUID politikası; `None` (her kimlik doğrulamada) → tüm aktif üyeliklerin `PasskeyPolicy::strictest` birleşimi | PKY-08 |
| `authn_protect::risk::NotMeTokenIssuer::issue_not_me_token(conn, user, now)` | protect / `crates/authn-protect/src/risk/alerts.rs` | **authn-session**: `one_time_tokens` `not_me` linki; tüketimi tüm oturumları kapatır ve şifre sıfırlamaya zorlar | RSK-04 |
| `authn_audit::AuditAccessPolicy::check(principal, org, permission, client_ip)` | audit / `crates/authn-audit/src/policy.rs` | `OrgService::authorize_from(principal, Permission::{AuditRead, WebhooksRead, WebhooksManage}, org, client_ip)`: `Ok` → izin, `Err` → ret; servis hesabı yalnızca kendi organizasyonunda, platform admini örtük erişimsiz, IP izin listesi `client_ip`'ye uygulanır | AUD-04, AUD-07, ORG-07 |
| `authn_audit::OutboxHandler` (`notification` öneki) | audit / `crates/authn-audit/src/outbox/worker.rs` | `OutboxMessage` → `authn_notify::DeliveryRequest`, `NotificationDeliverer::deliver`; `DeliveryFailure::Retry` → `HandlerError::Retry`, `Permanent` → `HandlerError::permanent` (örnek: `crates/authn-notify/README.md`); `OutboxHandlers::register("notification", …)` | AUD-06, NTF-03 |
| `authn_core::ports::DataExporter` (bölüm başına) | her modül | `SessionDataExporter`, `MfaDataExporter`, `PasskeyDataExporter`, `OrgDataExporter`, `IdentityDataExporter` (`identities`), `AdminActionsDataExporter::new(clock)` (`admin_actions`, K-39/K-62). `AccountServiceDeps.exporters`'a verilir; adlar benzersiz, `^[a-z][a-z0-9_]{0,63}$`, `account` ayrılmış | ACC-10 |
| `authn_oidc_client::LoginMethodInventory::other_login_methods(conn, user)` | oidc-client / `crates/authn-oidc-client/src/hooks.rs` | `ServerOidcLoginMethods`: şifre → `Password`, `passkey_count_in(conn, user, true) > 0` → `Passkey`; **asla `Social`**, parolasız e-posta girişi sayılmaz (yukarıdaki gerekçe); yalnızca `conn`'dan | kimlik ayırma (SOC-06) |
| `authn_oidc_client::SessionLiveness::is_active(conn, session, user, now)` | oidc-client / `hooks.rs` | `ServerSessionLiveness` → `authn_session::is_session_active_in(conn, session, user, now)` (varsayılan uygulama yok) | bağlama callback'i (K-03) |
| `authn_account::AccountErasureHook` | account / `hooks.rs` | `account.register_erasure_hook(Arc::new(oidc.erasure_hook()))`: silme transaction'ında Apple token'ı iptal kuyruğuna (K-35) | ACC-09 |
| `authn_account::EmailChangeRevertHook::after_revert_in_tx(conn, ctx, user)` | account / `hooks.rs` | `ServerRevertHook`: aynı transaction'da `WebauthnService::remove_all_passkeys_in_tx`, `MfaService::reset_user_mfa_in_tx`, `OidcClientService::remove_all_identities_in_tx` (K-20) | ACC-07 geri alma |
| `authn_admin::SigningKeyCache::invalidate_signing_keys()` | admin / `hooks.rs` | `ServerSigningKeyCache(SessionService)` → `SessionService::invalidate_signing_keys()` | ADM-06 |

### 15.2 Port uygulamaları (`AppState`)

| Port | Uygulama | Yapıcı / kaynak |
|------|----------|-----------------|
| `Clock` | `SystemClock` | `crates/authn-core/src/ports/clock.rs` |
| `AuditSink`, `EventPublisher` | `PgAuditSink`, `OutboxEventPublisher` | `crates/authn-audit/src/{sink.rs,outbox/publisher.rs}` (`AuditService`) |
| `Notifier`, `EmailTransport`, `SmsSender` | `OutboxNotifier`, SMTP/log/disabled, HTTP/log/none | `authn_notify::NotifyServices::from_config(&config, pool, envelopes, clock, rate_limiter, http)` — Tokio runtime içinde; `notifier_port()`, `.email`, `.sms` (`crates/authn-notify/src/services.rs`) |
| `RateLimiter` | Postgres (varsayılan) / Redis (`authn-protect` `redis` feature) / bellek (yalnızca geliştirme) | `authn_protect::build_rate_limiter` (`crates/authn-protect/src/rate_limit/mod.rs`) |
| `CaptchaVerifier` | Turnstile / hCaptcha / proof-of-work / kapalı | `authn_protect::build_captcha_verifier` (`captcha/mod.rs`); `CaptchaService` (`FromRef`) |
| `RiskEvaluator` | `DefaultRiskEvaluator` | `crates/authn-protect/src/risk/mod.rs` |
| `GeoIpLookup` | opsiyonel — paketle gelen adaptör yok; takılmazsa imkânsız seyahat sinyali kapalı (RSK-02) | — |
| `HttpClient` | `SsrfSafeHttpClient::new(&config.protect.outbound)` | `crates/authn-protect/src/outbound/mod.rs` (HIBP, webhook, CAPTCHA, SMS, OIDC) |
| `BreachedPasswordChecker` | `HibpBreachChecker::from_config(&config.password.breach_check, http)` | `crates/authn-password/src/breach.rs` |
| `PasswordValidator` | `PasswordService::validator()` | `crates/authn-password/src/service/mod.rs` (authn-account'a ACC-01 için) |
| `DnsTxtResolver` | `HickoryDnsTxtResolver::from_system_conf(config.org.dns_timeout)` | `crates/authn-org/src/dns.rs` |
| `SessionRevoker`, `SessionIssuer` | authn-session | İnşa sırası (`crates/authn-server/src/services.rs`): `MfaService` → `PgSessionRevoker::new(clock, audit, events, mfa)` → `AccountService` (sarılmamış revoker'ı `sessions` olarak alır) → `AccountAwareSessionRevoker::new(Arc::new(revoker), account)` — **sarılmış** revoker password, org, admin ve diğer modüllere verilir → `SessionService` → `SessionIssuer` = `SessionService` (oidc-client, admin). `also_trusted_devices` ⇒ aynı `conn` ile `MfaService::revoke_trusted_devices_in_tx` |

### 15.3 Servisler, router'lar, OpenAPI

| Crate | `FromRef<AppState>` | Router ve yerleşim | OpenAPI |
|-------|---------------------|--------------------|---------|
| password | `PasswordService` (`PasswordService::new(PasswordServiceDeps{…}, PasswordServiceSettings::from_app_config(&config))`) | `authn_password::router` — `/v1/password/*` kimliksiz, `/v1/me/password*` kimlik doğrulama katmanının arkasında | `PasswordApi` |
| account | `AccountService` (`AccountService::new(…, AccountServiceSettings::from_app_config(&config)?)?`) | `authn_account::router` — `/v1/signup`, `/v1/email/*`, `/v1/terms` kimliksiz; `/v1/me*` oturum arkasında (`GET /v1/me` session'ın) | `AccountApi` |
| mfa | `MfaService` (`sms: Some(notify.sms)`, `policy_source`) | `authn_mfa::router` — oturum arkasında; `passkey` kapalıysa `settings.webauthn_available = false` | `MfaApi` |
| webauthn | `WebauthnService`, `WellKnownDocuments` (`service.well_known()`) | `authn_webauthn::router` oturum + CSRF arkasında; `authn_webauthn::well_known_router` kökte, kimliksiz | `WebauthnApi` |
| org | `OrgService` (`dns`, `session_revoker`) | `authn_org::router` kimlik doğrulama arkasında | `OrgApi` |
| protect | `CaptchaService` | `authn_protect::router` (`/v1/captcha/challenge`) | `ProtectApi` |
| audit | `AuditService` (`policy`: §15.1) | `authn_audit::router` (`/v1/me/security-events`, `/v1/orgs/{org_id}/audit-events`, webhook'lar) | `AuditApi` |
| notify | — (router yok) | — | — |
| session | `SessionService` | `authn_session::router` (`/v1/me`, `/v1/me/sessions*`, `/v1/logout*`, `/v1/reauth*`, `/v1/token/*`, `/.well-known/jwks.json`) + giriş rotaları | `SessionApi`, `LoginApi` |
| oidc-client | `OidcClientService` (`OidcClientService::build(deps, OidcClientSettings::from_app_config(&config)).await?` — Apple anahtarı açılışta çözülür) | `authn_oidc_client::router` — `/v1/oauth/*` kimliksiz (Apple `form_post` callback'i çapraz site POST'udur: oturum çerezi gelmez, CSRF katmanı devreye girmez; koruma tarayıcıya bağlı tek kullanımlık `state`), `/v1/me/identities*` oturum + CSRF arkasında | `OidcClientApi` |
| admin | `AdminService` (`AdminServiceDeps { pool, clock, audit: PgAuditSink, sessions: sarılmış revoker, issuer, accounts, mfa, webauthn, passwords, protection, hasher, envelopes, signing_keys, rate_limiter }`) | `authn_admin::router` oturum + CSRF arkasında; `authn_admin::enrollment_router` (`passkey` özelliği) **kimlik doğrulama katmanının dışında** birleştirilir (`app.rs::session_less_routes`): bağlantı token'ı gövdede kimlik bilgisidir, oturum çerezi taşıyan bir tarayıcıda CSRF katmanı onu reddetmemeli | `AdminApi`, `AdminEnrollmentApi` |

Cargo feature'ları (ARC-11): workspace girdileri `default-features = false` olduğundan authn-server `authn-mfa`'yı `features = ["sms"]`, `authn-webauthn`'u, `authn-session`'ı ve `authn-admin`'i `["passkey"]`, `authn-notify`'ı `["sms"]` ile; Redis isteniyorsa `authn-protect`'i `["redis"]` ile alır.

### 15.4 Katmanlar (OPS-02, `crates/authn-server/src/app.rs`)

| Yuva | Katman (dıştan içe) | Kaynak |
|------|---------------------|--------|
| (7) | `validate_host` → `security_headers` → `admin_console_cors` (K-67) → `cors` → `http_rate_limit` (`from_fn_with_state`, hepsi `request_context_middleware`'in içinde) | `crates/authn-protect/src/web/{host,headers,cors}.rs`, `rate_limit/layer.rs`, `crates/authn-server/src/cors.rs`. `admin_console_cors` yalnızca `server.admin_console_origins`'tan (her biri `protect.cors.allowed_origins`'ta da olmalı) gelen ve `x-impersonation-session` isteyen preflight'ları yanıtlar; varsayılan kapalı, diğer her istek `cors`'a gider |
| (8) | `authn_session::authenticate` (API anahtarı → bearer → impersonation başlığı → oturum çerezi + CSRF; salt-okunur impersonation yazma yöntemlerini reddeder). **`authn_org::api_key_middleware`'in yerine geçer — ikisi birlikte kurulmaz** (org ara katmanı zaten `Principal` taşıyan isteği reddeder); org API anahtarlarını yalnızca `/v1/orgs/{org_id}…` yollarında `Principal`'a çevirir. Oturumsuz admin kayıt rotaları bu yuvanın dışında birleştirilir (§15.3) | `crates/authn-session/src/middleware.rs` |

### 15.5 Arka plan işleri (OPS-06, çoklu instance güvenli)

| İş | Fonksiyon | Dosya |
|----|-----------|-------|
| Outbox teslimi (bildirim + webhook + domain olayları) | `AuditService::outbox_worker(handlers).run(shutdown)`; `handlers = AuditService::outbox_handlers(http)` + `notification` köprüsü | `crates/authn-audit/src/service.rs` |
| Audit saklama ve kontrol noktaları (günlük) | `AuditService::run_maintenance(&maintenance_pool)` | `crates/authn-audit/src/service.rs`, `retention.rs` |
| Doğrulanmamış hesap temizliği (ACC-05) | `AccountService::purge_unverified_accounts(max)` | `crates/authn-account/src/service/maintenance.rs` |
| Hesap silme tamamlama (ACC-09) | `AccountService::purge_due_deletions(max)` | `crates/authn-account/src/service/deletion.rs` |
| Geçici kilitlerin açılması (ACC-06) | `AccountService::release_expired_locks(max)` | `maintenance.rs` |
| Süresi dolan adres rezervasyonları (ACC-07) | `AccountService::purge_expired_reservations(max)` | `maintenance.rs` |
| Organizasyon silme tamamlama (ORG-12) | `OrgService::purge_due_deletions(limit)` | `crates/authn-org/src/service/orgs.rs` |
| Süresi dolan davetler (ORG-05) | `OrgService::expire_invitations()` | `orgs.rs` |
| MFA bekleyen kayıt / güvenilir cihaz temizliği | `MfaService::purge_expired()` | `crates/authn-mfa/src/service/manage.rs` |
| Passkey seremonileri | `WebauthnService::purge_expired_ceremonies()` | `crates/authn-webauthn/src/service/mod.rs` |
| Rate limit kovaları | `PostgresRateLimiter::purge_expired(batch)` | `crates/authn-protect/src/rate_limit/postgres.rs` |
| PoW CAPTCHA kayıtları | `ProofOfWorkCaptcha::purge_expired()` (`PURGE_GRACE` = 15 dk) | `crates/authn-protect/src/captcha/pow.rs` |
| Yumuşak kilitler | `LoginProtection::purge_expired()` | `crates/authn-protect/src/login.rs` |
| Tek kullanımlık token'lar | `OneTimeTokenRepository::delete_expired(conn, before, limit)` | `crates/authn-store/src/one_time_tokens.rs` |
| İmza anahtarı rotasyonu (CRY-10) | `SigningKeyRepository::rotate_if_due` | `crates/authn-store/src/signing_keys.rs` |
| Oturum / challenge / ardıl token temizliği | `SessionService::purge_expired(batch)` | `crates/authn-session/src/service/` |
| Süresi dolan OAuth state'leri ve native nonce'lar | `OidcClientService::purge_expired_states(limit)` | `crates/authn-oidc-client/src/service/accounts.rs` |
| Sağlayıcı token iptalleri (K-35; ağ çağrısı, ayrı görev, dakikada bir) | `OidcClientService::process_token_revocations(limit)` (`UPDATE … SKIP LOCKED` kiralama, HTTP sırasında bağlantı tutulmaz) | `crates/authn-oidc-client/src/service/revocation.rs`; sunucuda `jobs::process_token_revocations` |

### 15.6 Açılış, kapanış ve CLI

- **Açılış:** `authn_core::tls::install_crypto_provider()`; `NotifyServices::from_config` Tokio runtime içinde; `AccountService::sync_terms_versions()`; ayrı **bakım rolü havuzu** (OPS-10, `database.maintenance_url` → `DatabaseConfig::maintenance()`; yapılandırılmamışsa uygulama havuzu ve açılışta uyarı) `run_maintenance` / `create_checkpoint` için (`Services::build_with_maintenance_pool`).
- **Zarif kapanış (OPS-07):** outbox işçisine kapanış sinyali; `PasswordService::drain_background_jobs()`, `AccountService::drain_background_jobs()`.
- **`check-config`:** `AppConfig::load` (ortama bağlı `[notify]` kuralları dahil) + `TemplateRenderer::from_config(&config)` şablon doğrulaması + `serve`'ün router/servis kurarken doğruladığı ayarlar (`cli.rs::check_startup_settings`: `HostValidation`, `SecurityHeaders`, `CorsPolicy`, `AdminConsoleCors`, `CryptoServices::from_config`, şifreli Apple anahtarının açılması, `ProviderRegistry::from_settings`); `serve`'ün reddettiği yapılandırma "geçerli" sayılmaz (wave 3A denetimi).
- **`verify-audit-chain`:** `authn_audit::verify_chain` / `verify_chain_from` (`crates/authn-audit/src/verify.rs`).
- **`rotate-kek` / `reencrypt`:** `SigningKeyRepository::rewrap_private_keys`, `authn_audit::webhooks::rewrap_webhook_secrets` ve zarf şifreli her `*_ciphertext` kolonu için `EnvelopeCipher::rewrap`: `mfa_factors.secret_ciphertext`, `refresh_tokens.successor_ciphertext`, `outbox.sealed_payload`, `identities.access_token_ciphertext` / `refresh_token_ciphertext`, `oauth_states.pkce_verifier_ciphertext`, `oauth_token_revocations.token_ciphertext` (test `cry_08_rotate_kek_covers_every_sealed_column_of_the_schema` şemadaki her `*_ciphertext` kolonunun kapsandığını zorlar). Yapılandırmadaki `oidc_client.apple.private_key_ciphertext` yeniden sarılır ve yeni değer operatöre yazdırılır (yapılandırma dosyası değiştirilemez).
- **Admin / break-glass (ADM-05, K-07, K-11):** `create-admin --email <adres> [--passkey-link [--ttl 30m]]` → `authn_admin::create_break_glass_admin` (tek seferlik şifre) veya `create_break_glass_admin_with_passkey_link` (`{public_base_url}/admin/enroll#<token>`; token URL parçasında, sunucu loglarına gitmez; bir kez yazdırılır, loglanmaz); `admin-enrollment-link`, `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions` (`--target`, `--reason`, `--operator` zorunlu) → `AdminService::{issue_break_glass_enrollment_link_offline, suspend_admin_offline, unsuspend_admin_offline, revoke_admin_sessions_offline}`.
- **`seal-apple-key --pem-file <yol|->`** (SOC-07, K-34): PEM dosyadan/stdin'den okunur (16 KiB'tan büyükse kesilmez, reddedilir; tampon sıfırlanır), asla yazdırılmaz; çıktı `apple.private_key_ciphertext` değeridir. Çevrimdışı admin komutlarında `--operator` / `--reason` veritabanına bağlanmadan önce doğrulanır; geçersiz girdi çıkış kodu 65.
- **En az yetki kurulumu:** `SELECT authn_apply_least_privilege('<uygulama_rolü>', '<bakım_rolü>');` (2900; §6, `docs/operations/least-privilege.md`). Fonksiyon `SECURITY INVOKER`, `search_path`'i sabit; tablo sahibine veya birbirine üye, süper kullanıcı / `BYPASSRLS` / `pg_*_all_data` üyesi rolleri reddeder.

### 15.7 Dalga B için bağlayıcı çağrı kuralları (özet)

| Sahip | Kural | Kaynak talep |
|-------|-------|--------------|
| authn-session | `verify_login_password` sonucunu **enum ile** eşle (`MustChangePassword` ⇒ `RequiredAction::ChangePassword`, tam oturum yok; `is_valid()` tek başına kullanılmaz) | password: "authn-session / authn-admin için şifre API'si" |
| authn-session | `LoginProtection::check_attempt` her şifre denemesinde **tam bir kez**; başarıda `record_success`, başarısızlıkta `record_failure` | protect: "LoginProtection" |
| authn-session | `verify_factor`'dan önce `proof.kind()` challenge'ın `allowed_factors` listesinde değilse reddet | mfa: "Güvenlik incelemesi sonrası bağlama notları" |
| authn-session | `SessionRevoker` uygulaması `also_trusted_devices`'ı aynı bağlantıda `revoke_trusted_devices_in_tx` ile uygular; "tümünü kapat" güvenilir cihazları da iptal eder | password: PWD-09, mfa |
| authn-session | Passkey: `binding_token` web'de `HttpOnly; Secure; SameSite=Strict` çerezde; `target` istemciden değil session kaydından | webauthn: "passkey kimlik doğrulama API'si" |
| authn-session | SES-10 istemci doğrulaması `OrgService::authenticate_api_key`'i doğrudan çağırır; giriş ve e-posta doğrulamasından sonra `auto_join_verified_domains` | org: "Server / Dalga B bağlama notları" |
| authn-session | doğru şifreden sonra `AccountService::assess_login`; `Denied(reason)` ⇒ `reason.into_error(now)`; `required_actions` ⇒ SES-22 | account: "Server / Dalga B bağlama notları" |
| authn-oidc-client | kimlik ayırma transaction'ının başında `UserRepository::lock_for_update(conn, user)` (PWD-11 yarışı) | password: "PWD-11 yarışına karşı kullanıcı satırı kilidi" |
| authn-admin | `change_status_in_tx` + aynı transaction'da `SessionRevoker`; `reset_user_mfa_in_tx` + aynı transaction'da `WebauthnService::remove_all_passkeys_in_tx` (K-01); `users` erişimi yalnızca `UserRepository::{search, stale_passwords, set_admin_flags}` (K-38); impersonation `SessionIssuer::start_impersonation_audited` (K-06); `set_must_change_password`; `LoginProtection::unlock`; personel işlemleri `admin.*` olay türleriyle veya impersonator ile | account, mfa, password, protect, audit |
