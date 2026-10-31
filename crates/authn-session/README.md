# authn-session

Giriş akışı, CSRF korumalı web oturumları, rotasyonlu ve yeniden kullanım tespitli native access/refresh token'lar, JWKS, introspection, step-up, organizasyon değiştirme ve şifresiz giriş.

## Sahip olunan gereksinimler

SES-01 … SES-22, DOC-05

## Bağımlılık kuralı

Dalga B. Dalga A crate'lerine bağımlı olabilir; `authn-oidc-client` ve `authn-admin`'e bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-session/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/session.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/session.rs` |
| Uygulanan portlar | `SessionRevoker`, `SessionIssuer` |
| Sahip olunan tablolar | `sessions`, `refresh_tokens`, `auth_challenges` |
| `one_time_tokens.purpose` değerleri | `magic_link`, `login_code`, `not_me` |
| Migration aralığı | `2000–2099` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- Kimlik doğrulama middleware'i istekte `authn_core::domain::Principal`'ı request extension olarak ekler; diğer crate'ler `Principal` extractor'ı ile okur.
- `invalid_credentials` hata kodu (SES-01) `codes/session.rs` içinde önceden tanımlandı.
- Cargo feature: `passkey` (`authn-webauthn/passkey`'i iletir).

## Komutlar

```bash
cargo test -p authn-session
cargo clippy -p authn-session --all-targets -- -D warnings
cargo fmt -p authn-session
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
