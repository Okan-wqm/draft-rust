# authn-password

Şifre politikası (NIST 800-63B), NFKC normalizasyonu, HIBP k-anonimlik sızıntı kontrolü, zxcvbn güç tahmini, şifre değiştirme/ekleme/kaldırma ve sıfırlama akışı.

## Sahip olunan gereksinimler

PWD-01 … PWD-12

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-password/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/password.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/password.rs` |
| Uygulanan portlar | `BreachedPasswordChecker`, `PasswordValidator` (`crates/authn-core/src/ports/breached_password.rs`, `password_validator.rs`) |
| Sahip olunan tablolar | `password_credentials` (CRUD `authn_store::UserRepository` üzerinden; tablo sahibi `authn-store`) |
| `one_time_tokens.purpose` değerleri | `password_reset` (link), `password_reset_code` (kod) |
| Migration aralığı | `1100–1199` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- HIBP çağrıları `HttpClient` portu (`OutboundTarget::Trusted`) ile yapılır; doğrudan `reqwest` kullanılırsa önce `authn_core::tls::install_crypto_provider()` çağrılmalıdır.
- Oturum kapatma `SessionRevoker` portu ile, bildirimler `Notifier` portu ile yapılır.

## Komutlar

```bash
cargo test -p authn-password
cargo clippy -p authn-password --all-targets -- -D warnings
cargo fmt -p authn-password
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
