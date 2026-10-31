# authn-mfa

İkinci faktörler: TOTP, kurtarma kodları, e-posta OTP, SMS OTP (`sms` feature'ı), MFA politika değerlendirmesi ve güvenilir cihazlar.

## Sahip olunan gereksinimler

MFA-01 … MFA-10

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-mfa/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/mfa.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/mfa.rs` |
| Uygulanan portlar | — (port uygulamaz; `SmsSender`, `Notifier`, `RateLimiter`, `AuditSink` tüketir) |
| Sahip olunan tablolar | `mfa_factors`, `recovery_codes`, `mfa_user_settings`, `trusted_devices` |
| `one_time_tokens.purpose` değerleri | `mfa_email_otp`, `mfa_sms_otp`, `phone_verification` |
| Migration aralığı | `1300–1399` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- MFA politika değerlendirmesi (MFA-08) girdi olarak kendi tanımladığı bir yapıyı alır (organizasyon politikası verisi, admin rolü vb.); bu veriyi `authn-session` toplar. `authn-org`'a bağımlılık yoktur.
- Cargo feature: `sms` (varsayılan açık); sağlayıcı yapılandırılmamışsa (`SmsSender::is_configured() == false`) SMS faktörü sunulmaz.

## Komutlar

```bash
cargo test -p authn-mfa
cargo clippy -p authn-mfa --all-targets -- -D warnings
cargo fmt -p authn-mfa
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
