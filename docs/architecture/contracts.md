# Mimari sözleşmeler (contracts)

Bu belge, aynı çalışma ağacında **paralel çalışan** modül agent'larının uyduğu bağlayıcı sözleşmedir. Gereksinimler için tek kaynak `docs/spec/requirements.md`'dir; bu belge **kimin neyi, nerede ve hangi arayüzle** yaptığını belirler. Bir kural burada yazılı değilse ve başka bir modülü etkiliyorsa, önce §13'teki süreçle sözleşme değişikliği talep edilir.

İçindekiler: 1. Crate'ler ve gereksinim sahipliği · 2. Bağımlılık grafiği · 3. Dosya sahipliği · 4. Portlar · 5. Tablo sahipliği · 6. Migration'lar · 7. AppState / FromRef router deseni · 8. Hata kodları · 9. Konfigürasyon · 10. HTTP katmanı ve istek bağlamı · 11. Güvenlik kuralları · 12. Test kuralları · 13. Sözleşme değişikliği talebi · 14. Mimari kararlar

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
| `fuzz/fuzz_targets/<hedef>.rs` | dosya başlığındaki crate (`jwt_parse`, `envelope_parse` → crypto; `api_key_parse` → org; `webhook_signature` → audit; `return_to` → protect; `email_normalize` → core/account; `client_ip` → core) |
| `config/example.toml` | authn-server (her modül kendi bölümünün yorumlarını §13 ile günceller) |
| Kök dosyalar: `Cargo.toml`, `deny.toml`, `clippy.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `.cargo/*`, `.github/**`, `docker-compose.yml`, `docs/architecture/**`, `fuzz/Cargo.toml`, `fuzz/deny.toml` | mimar |
| `Cargo.lock` | yalnızca cargo üretir; birleştirme çakışmasında elle düzenlenmez, `cargo update --workspace` ile yeniden üretilir |
| `docs/architecture/contract-change-requests.md` | herkes — yalnızca **kendi başlığı altına** ekleme yapar |

Yeni bir modül dosyası eklemek (`config/<modül>.rs` alanları, yeni hata kodu, yeni migration) sahibinin işidir ve onay gerektirmez. Başka bir sahibin dosyasındaki değişiklik §13'e tabidir.

---

## 4. Portlar

Tüm portlar `crates/authn-core/src/ports/` altında, nesne güvenli (`Arc<dyn Port>`), `Send + Sync`, `#[async_trait]` ile tanımlıdır. Hata tipi her zaman `AuthError`'dır.

| Port | Dosya | Uygulayan | Başlıca tüketiciler | Transaction semantiği |
|------|-------|-----------|---------------------|-----------------------|
| `Clock` | `clock.rs` | core (`SystemClock`) | herkes | — |
| `AuditSink` | `audit.rs` | audit | herkes | `record` kendi kısa transaction'ı (başarısız iş işleminde de yazılır); `record_in_tx` çağıranın transaction'ında |
| `EventPublisher` | `event_publisher.rs` | audit | account, org, session | çağıranın transaction'ında (outbox) |
| `Notifier` | `notifier.rs` | notify | account, password, mfa, org, session, admin, protect | `notify` kendi transaction'ı, `notify_in_tx` çağıranınkinde; teslim outbox ile asenkron |
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
| `SessionRevoker` | `session_revoker.rs` | session | password, account, mfa, org, admin, protect | **çağıranın transaction'ında** (`&mut PgConnection`) |
| `SessionIssuer` | `session_issuer.rs` | session | oidc-client (sosyal giriş), admin (impersonation), webauthn akışları session üzerinden | kendi transaction'ı |
| `DataExporter` | `data_exporter.rs` | her modül kendi bölümü için; toplayıcı account | account | çağıranın bağlantısı |

Kurallar:
- Port dosyası yalnızca **geriye uyumlu ekleme** alır: yeni metot (varsayılan gövdeli), yeni enum varyantı (tüketiciler için kırıcıysa §13), yeni alan (yapı `Default`/yapıcı ile). İmza değişikliği ve silme §13'e tabidir.
- Tüketiciler belgelenmiş imzaya ve semantiğe göre kod yazar ve testlerde `authn_testkit::TestPorts` sahtelerini kullanır; gerçek uygulama hazır olmadan da paralel çalışabilir.
- `&mut PgConnection` alan metotlar çağıranın transaction'ının parçasıdır: çağıran commit etmezse etki yoktur (ARC-06).
- Sır içeren port verileri (`SensitiveString`: token, OTP) yalnızca amacına uygun yere serileştirilir (outbox'ta zarf şifreli `sealed_payload`); `Debug` çıktıları redakte edilmiştir.

---

## 5. Tablo sahipliği

Şema tek bir yerde tasarlandı (`migrations/0001`–`0012`). Sahip modül tabloya yazan **tek** crate'tir; diğerleri yalnızca sahibin API'si veya portu üzerinden erişir. Okuma için doğrudan SQL gerekiyorsa §13.

| Tablo | Sahip | Not |
|-------|-------|-----|
| `users`, `password_credentials` | store | Temel CRUD `UserRepository`; durum geçiş kuralları account, hash mantığı crypto/password |
| `user_profiles`, `terms_versions`, `consents`, `account_deletions` | account | |
| `sessions`, `refresh_tokens`, `auth_challenges` | session | |
| `one_time_tokens` | paylaşımlı | Her `purpose` değeri tek bir modüle aittir (aşağıda) |
| `mfa_factors`, `recovery_codes`, `mfa_user_settings`, `trusted_devices` | mfa | |
| `webauthn_user_handles`, `webauthn_credentials`, `webauthn_ceremonies` | webauthn | |
| `identities`, `oauth_states` | oidc-client | `identities` Faz 2 kurumsal SSO'nun da bağlantı noktasıdır |
| `organizations`, `roles`, `role_permissions`, `memberships`, `invitations`, `org_domains`, `org_policies`, `service_accounts`, `api_keys` | org | Yerleşik roller sabit kimliklerle `0012`'de |
| `rate_limit_buckets` (UNLOGGED), `login_soft_locks`, `captcha_pow_challenges`, `known_devices`, `known_networks` | protect | |
| `audit_subjects`, `audit_events`, `audit_event_pii`, `audit_chain_head`, `audit_chain_checkpoints`, `outbox`, `webhook_endpoints`, `webhook_deliveries` | audit | notify, `outbox`'a `notification.*` konulu kayıt **ekler** (Notifier uygulaması) |
| `data_encryption_keys`, `signing_keys` | crypto | |

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
- En az yetki önerisi (OPS-10, AUD-02): uygulama rolü `audit_events` üzerinde `UPDATE`/`DELETE`/`TRUNCATE` yetkisine sahip olmamalıdır; tablo ayrıca tetikleyiciyle ekleme-yalnızca korunur. Saklama temizliği yalnızca `SET LOCAL authn.audit_purge_before = '<zaman>'` ile ve `audit_chain_checkpoints` kaydıyla yapılır.

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
- `server.environment` varsayılanı `production`'dır (en katı). Üretim/staging'de depoda yayımlanmış örnek/test anahtarları reddedilir (`KNOWN_PUBLIC_KEYS`), `public_base_url` https olmalıdır, log e-posta taşıyıcısı, bellek içi rate limit ve özel ağlara giden istek izni yasaktır.

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
- Portlar için `authn_testkit::TestPorts` (ortak `FakeClock`); zaman `ports.clock.advance(..)` ile ilerletilir, `OffsetDateTime::now_utc()` çağrılmaz.
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
| `fuzz/` ayrı workspace | `libfuzzer-sys` (NCSA) yalnızca geliştirme aracında; `fuzz/deny.toml` istisnayı yalnızca o crate için tanır |
