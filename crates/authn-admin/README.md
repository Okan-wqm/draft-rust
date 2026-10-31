# authn-admin

`/v1/admin` altındaki platform admin API'si: kullanıcı yönetimi, impersonation, break-glass, acil durum işlemleri ve audit sorguları.

## Sahip olunan gereksinimler

ADM-01 … ADM-08

## Bağımlılık kuralı

Dalga B. Dalga A crate'lerine bağımlı olabilir; `authn-session` ve `authn-oidc-client`'e bağımlı olamaz (impersonation `SessionIssuer`, oturum kapatma `SessionRevoker` portu ile). Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-admin/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/admin.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/admin.rs` |
| Uygulanan portlar | — |
| Sahip olunan tablolar | — (diğer modüllerin API'leri ve portları üzerinden çalışır) |
| `one_time_tokens.purpose` değerleri | — |
| Migration aralığı | `2200–2299` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- Her admin işlemi gerekçe alanıyla `AuditSink`'e yazılır (ADM-08).

## Komutlar

```bash
cargo test -p authn-admin
cargo clippy -p authn-admin --all-targets -- -D warnings
cargo fmt -p authn-admin
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
