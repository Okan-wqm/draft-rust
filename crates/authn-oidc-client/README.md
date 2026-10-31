# authn-oidc-client

OIDC/OAuth2 istemcisi olarak sosyal giriş: Google, Apple, Microsoft (çok kiracılı), GitHub ve genel OIDC sağlayıcıları; web ve native akışlar, hesap bağlama.

## Sahip olunan gereksinimler

SOC-01 … SOC-09

## Bağımlılık kuralı

Dalga B. Dalga A crate'lerine bağımlı olabilir; `authn-session` ve `authn-admin`'e bağımlı olamaz (oturum `SessionIssuer` portu ile açılır). Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-oidc-client/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/oidc_client.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/oidc_client.rs` |
| Uygulanan portlar | — |
| Sahip olunan tablolar | `identities`, `oauth_states` |
| `one_time_tokens.purpose` değerleri | — |
| Migration aralığı | `2100–2199` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- `openidconnect`/`oauth2` varsayılan özellikleri kapalıdır; HTTP istemcisi olarak `authn-protect`'in SSRF korumalı `HttpClient`'ı (veya `reqwest` 0.13) bağlanır.
- Apple `client_secret` (ES256) **yalnızca `p256` 0.14** ile imzalanır. `openidconnect`'in içindeki `p256/p384 0.13` (RUSTSEC-2026-0387) sadece açık anahtar doğrulaması için kullanılır; gizli anahtar işlemi yapılamaz (bkz. `deny.toml`).

## Komutlar

```bash
cargo test -p authn-oidc-client
cargo clippy -p authn-oidc-client --all-targets -- -D warnings
cargo fmt -p authn-oidc-client
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
