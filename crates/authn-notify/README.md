# authn-notify

Bildirim üretimi (TR/EN, HTML + metin, minijinja), e-posta taşıyıcıları (zorunlu TLS'li SMTP, log, test) ve SMS göndericileri.

## Sahip olunan gereksinimler

NTF-01 … NTF-04

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-notify/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/notify.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/notify.rs` |
| Uygulanan portlar | `Notifier`, `EmailTransport`, `SmsSender` |
| Sahip olunan tablolar | — (`outbox` tablosuna `notification.*` konulu kayıt yazar) |
| `one_time_tokens.purpose` değerleri | — |
| Migration aralığı | `1800–1899` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- Bildirimlerdeki `SensitiveString` alanları (token, kod) outbox'a `authn-crypto` zarf şifrelemesiyle (`sealed_payload`) yazılır ve teslimden sonra silinir.
- Linkler yalnızca `server.public_base_url` + `notify.links.*` yollarıyla kurulur; token URL fragment'ında (`#token=…`) taşınır.
- Cargo feature: `sms` (varsayılan açık).

## Komutlar

```bash
cargo test -p authn-notify
cargo clippy -p authn-notify --all-targets -- -D warnings
cargo fmt -p authn-notify
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
