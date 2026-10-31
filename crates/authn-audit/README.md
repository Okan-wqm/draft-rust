# authn-audit

Hash zinciri ve takma adlı kişisel verilerle kurcalamaya dayanıklı audit log, transactional outbox işçisi ve imzalı webhook'lar (Standard Webhooks).

## Sahip olunan gereksinimler

AUD-01 … AUD-07

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-audit/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/audit.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/audit.rs` |
| Uygulanan portlar | `AuditSink`, `EventPublisher` |
| Sahip olunan tablolar | `audit_subjects`, `audit_events`, `audit_event_pii`, `audit_chain_head`, `audit_chain_checkpoints`, `outbox` (işçi), `webhook_endpoints`, `webhook_deliveries` |
| `one_time_tokens.purpose` değerleri | — |
| Migration aralığı | `1700–1799` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- `audit_events` ekleme-yalnızca tetikleyicisiyle korunur; saklama süresi temizliği yalnızca `SET LOCAL authn.audit_purge_before = …` ile ve kontrol noktası kaydıyla yapılır.
- Webhook teslimatı SSRF korumalı `HttpClient` portu (`OutboundTarget::UserSupplied`) ile yapılır.

## Komutlar

```bash
cargo test -p authn-audit
cargo clippy -p authn-audit --all-targets -- -D warnings
cargo fmt -p authn-audit
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
