# authn-org

Organizasyonlar, üyelikler, `authorize()` tabanlı RBAC, davetler, DNS ile domain doğrulama, organizasyon politikaları, API anahtarları ve servis hesapları.

## Sahip olunan gereksinimler

ORG-01 … ORG-12, ARC-10

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-org/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/org.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/org.rs` |
| Uygulanan portlar | `DnsTxtResolver` (`crates/authn-core/src/ports/dns.rs`, `hickory-resolver` ile) |
| Sahip olunan tablolar | `organizations`, `roles`, `role_permissions`, `memberships`, `invitations`, `org_domains`, `org_policies`, `service_accounts`, `api_keys` |
| `one_time_tokens.purpose` değerleri | `org_ownership_transfer` |
| Migration aralığı | `1500–1599` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- Yerleşik roller `0012_builtin_roles.sql` ile sabit kimliklerle eklendi (owner …0001, admin …0002, member …0003, billing …0004, viewer …0005).
- Kiracı izolasyonu veritabanında da zorlanır: `authn_check_role_tenant` tetikleyicisi ve `api_keys → service_accounts` bileşik FK.

## Komutlar

```bash
cargo test -p authn-org
cargo clippy -p authn-org --all-targets -- -D warnings
cargo fmt -p authn-org
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
