# authn-core

Tüm workspace'in ortak sözleşmeleri. Başka hiçbir `authn-*` crate'ine bağımlı değildir; diğer tüm crate'ler buna bağımlıdır.

## Sahip olunan gereksinimler

ARC-01, ARC-02, ARC-04, ARC-05, ARC-07, ARC-08, PRT-06, LIC-01, TST-03, TST-04, TST-07, DOC-02, DOC-08, DOC-09

## İçerik

| Modül | Açıklama |
|-------|----------|
| `id` | UUIDv7 tabanlı tipli kimlikler (`UserId`, `OrgId`, `SessionId`, …), serde + sqlx (`uuid`, `uuid[]`) desteği, katı ayrıştırma (ARC-05) |
| `error` | `ErrorCode` kaydı (modül başına `error/codes/<modül>.rs`), `AuthError`, JSON hata zarfı `{"error":{"code","message","request_id"}}` (ARC-08) |
| `config` | `AppConfig` ve modül başına `config/<modül>.rs`; figment (TOML + `AUTHN__` ortam değişkenleri), spesifikasyon varsayılanları, fail-fast doğrulama (ARC-07). Çapraz bölüm kuralları `config/mod.rs`'te: production/staging'de yayımlanmış anahtar reddi; production'da https, bellek içi rate limit ve özel ağ izni yasağı; ortama bağlı `[notify]` kuralları (log e-posta/SMS ve `smtp.extra_ca_file` yalnızca development/test, `disabled` taşıyıcı production'da yasak — NTF-03, NTF-04) |
| `ports` | Nesne güvenli (`dyn`) async trait'ler: `Clock`, `AuditSink`, `EventPublisher`, `Notifier`, `EmailTransport`, `SmsSender`, `RateLimiter`, `CaptchaVerifier`, `RiskEvaluator`, `GeoIpLookup`, `HttpClient`, `BreachedPasswordChecker`, `PasswordValidator`, `DnsTxtResolver`, `SessionRevoker`, `SessionIssuer`, `DataExporter` (ARC-02) |
| `domain` | `EmailAddress` (ACC-03 temel normalizasyon), `PhoneNumber`, `Locale`, `AccountStatus`, `AuthMethodRef` (RFC 8176), `FactorKind`, `LoginMethod`, `ClientKind`, `Principal` + extractor, sayfalama |
| `http` | `RequestContext` + middleware (istek kimliği, güvenilir proxy arkasında istemci IP'si — PRT-06, user-agent, cihaz kimliği, dil), hata zarfının yerelleştirilmesi, zarf üreten `Json`/`Query`/`Path` extractor'ları |
| `secret`, `redact` | `SensitiveString`, sabit zamanlı karşılaştırma, e-posta/IP maskeleme |
| `tls` | Tek rustls kripto sağlayıcısının (`ring`) kurulumu |

Dalga A ile gelen port eklemeleri: `Notifier::notify_sms_in_tx` + `SmsNotification` (authn-notify), `AuditSink::pseudonymize_subject` (authn-audit), `RevocationReason::MembershipChanged` ve `RevokeOptions::also_trusted_devices`'ın "aynı bağlantı" semantiği (mimar; `SessionRevoker`'ı authn-session uygular).

## Dosya sahipliği

Bu crate'te bazı dosyalar diğer modüllerin agent'larına aittir (tam tablo `docs/architecture/contracts.md`):

- `src/config/<modül>.rs` → ilgili modül
- `src/error/codes/<modül>.rs` → ilgili modül
- `src/ports/<port>.rs` → portu **uygulayan** crate (yalnızca geriye uyumlu, ekleme niteliğinde değişiklik)

Geri kalan her şey mimarın (authn-core) sorumluluğundadır.

## Komutlar

```bash
cargo test -p authn-core
cargo clippy -p authn-core --all-targets -- -D warnings
cargo fmt -p authn-core
```
