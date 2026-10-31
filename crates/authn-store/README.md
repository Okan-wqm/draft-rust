# authn-store

Ortak kalıcılık altyapısı: `PgPool` oluşturma, gömülü migration'lar, transaction yardımcıları, veritabanı hata sınıflandırması ve paylaşılan `users` / `password_credentials` tabloları için temel repository.

## Sahip olunan gereksinimler

ARC-06, OPS-10

## API

| Öğe | Açıklama |
|-----|----------|
| `connect`, `connect_lazy` | Konfigürasyondan havuz; `statement_timeout`, `timezone=UTC`, `application_name` ayarlı. URL hatası asla URL'yi/parolayı yansıtmaz |
| `MIGRATOR`, `run_migrations`, `migration_status` | `/migrations` dizinindeki tüm migration'lar; hazır olma kontrolü (OPS-05) |
| `MIGRATION_RANGES`, `migrate::range_owner` | Modül başına migration sürüm aralıkları (test ile zorlanır) |
| `begin`, `begin_serializable`, `commit`, `with_tx` | Transaction yardımcıları (ARC-06) |
| `StoreError` | Unique/FK/check ihlali, yeniden denenebilir hata (40001/40P01), yetki reddi (append-only tetikleyici) sınıflandırması |
| `UserRepository` | `create`, `find_by_id`, `find_by_email`, `lock_for_update`, `update_status` (compare-and-set), `mark_email_verified`, `update_email`, `record_login`, `delete`, `find_password`, `set_password`, `rehash_password`, `set_must_change_password`, `delete_password` |
| `OneTimeTokenRepository` (`one_time_tokens`) | Genel tek kullanımlık token/kod deposu (ARC-06, CRY-06, CRY-07): `create` (önceki token'ları iptal ederek, advisory lock ile), `find_active_link`, `consume_link` (atomik `UPDATE … RETURNING`, çağıranın transaction'ında), `verify_code` (kendi transaction'ında; deneme sayacı ve kilit), `revoke_*`, `delete_expired`. `TokenPurpose` = contracts §5 amaç tablosu. Sahibi: authn-crypto agent'ı |
| `SigningKeyRepository` (`signing_keys`) | JWT imza anahtarı yaşam döngüsü (CRY-10): `create_pending`, `activate_due`, `activate`, `revoke`, `emergency_rotate`, `rotate_if_due`, `load_active_signer`, `publishable`, `jwks`, `verifier`, `rewrap_private_keys`. Sahibi: authn-crypto agent'ı |

## Kurallar

- Tüm sorgular çalışma zamanı sorgularıdır (`sqlx::query_as` + `FromRow`), SQL metinleri `&'static str` olmalıdır (sqlx 0.9 dinamik SQL'i reddeder; sütun listeleri için `concat!` kullanılır).
- `UniqueViolation` otomatik olarak `conflict`'e çevrilir; hesap varlığını sızdırmaması gereken akışlar (ACC-02, PWD-07) bu hatayı kendileri ele almalıdır.
- `users` ve `password_credentials` tablolarına yeni sorgu gerekiyorsa sözleşme değişikliği talebi açın.
- `one_time_tokens` ve `signing_keys` modülleri `authn-crypto`'ya bağımlıdır (izinli: store → crypto); token/kod düz metni bu crate'e hiç girmez, yalnızca `TokenHash` gelir.

## Testler

`tests/users.rs` (repository), `tests/one_time_tokens.rs` (tek kullanımlık token'lar: tek kullanım, eşzamanlı tüketim, deneme sınırı, grup iptali), `tests/signing_keys.rs` (rotasyon yaşam döngüsü, acil iptal, eşzamanlı rotasyon, KEK rotasyonu), `tests/schema.rs` (şema değişmezleri: kiracı izolasyonu tetikleyicisi, append-only audit, tek aktif refresh token, tek aktif imza anahtarı, takma ad silme), `tests/tx.rs`.

```bash
cargo test -p authn-store
```
