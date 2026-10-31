# authn-webauthn

Passkey / WebAuthn: kayıt ve doğrulama seremonileri (`webauthn-rs`, `passkey` feature'ı), kimlik bilgisi yönetimi, mobil ilişkilendirme dosyaları.

## Sahip olunan gereksinimler

PKY-01 … PKY-08

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-webauthn/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/webauthn.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/webauthn.rs` |
| Uygulanan portlar | — |
| Sahip olunan tablolar | `webauthn_user_handles`, `webauthn_credentials`, `webauthn_ceremonies` |
| `one_time_tokens.purpose` değerleri | — |
| Migration aralığı | `1400–1499` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- `webauthn-rs` ailesi MPL-2.0 lisanslıdır: tek onaylı istisna (LIC-01), `deny.toml` içinde crate bazında. `passkey` feature'ı varsayılan açıktır.
- Etkin `webauthn-rs` özellikleri: `conditional-ui`, `danger-allow-state-serialisation` (seremoni durumunu DB'de saklamak için), `danger-credential-internals`, `resident-key-support`. Testler için `webauthn-authenticator-rs` (`softpasskey`) dev-dependency olarak hazırdır.

## Komutlar

```bash
cargo test -p authn-webauthn
cargo clippy -p authn-webauthn --all-targets -- -D warnings
cargo fmt -p authn-webauthn
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
