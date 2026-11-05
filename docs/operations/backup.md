# Yedekleme ve geri yükleme (DOC-06)

## 1. Ne yedeklenir

| Varlık | Nerede | Yedek |
|--------|--------|-------|
| Tüm uygulama durumu (kullanıcılar, kimlik bilgileri, oturumlar, MFA, passkey, organizasyonlar, audit log, outbox, webhook'lar, imza anahtarları, tek kullanımlık token'lar) | **PostgreSQL** (tek veritabanı) | Zorunlu: sürekli WAL arşivi + düzenli taban yedek (PITR) önerilir |
| Yapılandırma ve **anahtarlar** (`crypto.peppers`, `crypto.keks`, `crypto.hmac_root_key`, sağlayıcı sırları) | Yapılandırma dosyası / secret yöneticisi | Zorunlu, **veritabanı yedeğinden ayrı** saklanır (§3) |
| Audit zinciri dış çıpaları (`verify-audit-chain` çıktısındaki `head <seq>:<hash>`, `chain_key_switch` kontrol noktaları) | WORM depo | Zorunlu ([key-management.md §5](key-management.md#5-audit-zinciri-anahtarı-k-77)) |
| Redis (yalnızca `protect.rate_limit.backend = "redis"`) | Redis | Gerekmez: yalnızca oran sınırı sayaçları; kaybı sayaçları sıfırlar |
| `rate_limit_buckets` (PostgreSQL arka ucunda) | `UNLOGGED` tablo | Önemsiz: çökme sonrası PostgreSQL boşaltır, replikalara gitmez; kaybı yalnızca sayaçları sıfırlar |

Uygulama sunucuları durumsuzdur; disklerinde yedeklenecek bir şey yoktur.

## 2. Yöntem

- **Fiziksel + PITR (önerilen):** `pg_basebackup` / yönetilen veritabanının anlık görüntüsü + WAL arşivi. Belirli bir ana geri dönmeyi sağlar.
- **Mantıksal (`pg_dump`):** taşıma ve denetim için. Yedeği **şema sahibi** veya `pg_read_all_data` üyesi bir rolle alın; uygulama ve bakım rolleri tüm tabloları okuyamaz (bilinçli, [least-privilege.md](least-privilege.md)). Geri yüklemeden sonra `SELECT authn_apply_least_privilege('authn_app', 'authn_maintenance');` çalıştırın: `pg_dump` yetkileri ve rolleri birebir taşımayabilir.
- Yedekleri **şifreli** saklayın: veritabanı şifre hash'leri, e-posta adresleri, audit PII'si ve zarf şifreli sırlar (KEK olmadan açılamaz ama yine de) içerir. Silinen kişisel veri yedek rotasyonu dolana kadar yedeklerde kalır ([kvkk-gdpr.md](../compliance/kvkk-gdpr.md)).

## 3. Anahtarlar ve yedekler

Veritabanı yedeği tek başına işe yaramaz; eşleşen anahtarlar gerekir:

| Anahtar yoksa | Sonuç |
|---------------|-------|
| Yedeğin yazıldığı tarihteki **KEK**'ler | İmza anahtarları, TOTP sırları, webhook sırları, saklanan sağlayıcı token'ları, outbox yükleri açılamaz. Sunucu imza anahtarını açamaz |
| **Pepper** sürümleri | O sürümle hash'lenmiş şifreler doğrulanamaz (kullanıcılar sıfırlama yapmalı) |
| **HMAC kök anahtarı** | Kurtarma kodları, bekleyen kodlar, güvenilir cihazlar geçersiz; anahtarlı audit zinciri doğrulanamaz |

Kurallar: KEK/pepper rotasyonundan sonra eski değerleri en eski yedeğin saklama süresi boyunca **ayrı bir kasada** tutun. Anahtarları veritabanı yedeğiyle aynı yerde saklamayın (biri sızınca diğeri de sızmasın).

## 4. Geri yükleme prosedürü

1. Tüm `serve` örneklerini durdurun (eski veriyle yeni yazma karışmasın).
2. Veritabanını geri yükleyin (PITR hedef zamanı veya yedek).
3. Rolleri ve yetkileri doğrulayın: `authn_apply_least_privilege(...)` ([least-privilege.md](least-privilege.md#doğrulama)).
4. Yedeğin alındığı tarihteki anahtarları içeren yapılandırmayla `rust-authentication check-config`, ardından `rust-authentication migrate` (ikili yedekten yeniyse; şema sürümü ikiliyle eşleşmeden `serve` başlamaz).
5. `rust-authentication verify-audit-chain` — zincir sağlam olmalı. Dış çıpanız yedekten **daha yeniyse** `--anchor` ile doğrulama başarısız olur; bu beklenir (geri sarma) ve olay kaydına geçirilmelidir.
6. Sunucuyu başlatın; `/health/ready` `200` olmalı.

## 5. Geri yükleme sonrası güvenlik etkileri

Eski bir ana dönmek, o andan sonra yapılan **güvenlik eylemlerini geri alır**:

- O tarihten sonra iptal edilmiş oturumlar ve refresh token'lar yeniden geçerli olur; değiştirilmiş şifreler eski değerine döner; kaldırılmış passkey/MFA faktörleri ve iptal edilmiş API anahtarları geri gelir; silinmiş imza anahtarları geri gelebilir.
  - **Öneri:** geri yüklemeden sonra `POST /v1/admin/emergency/revoke-all-sessions` (veya CLI ile kurtarılan bir admin hesabıyla) tüm oturumları kapatın; olay sırasında bir anahtar sızdıysa `rotate-signing-key --emergency`.
- **Silinen hesaplar geri gelir.** KVKK/GDPR gereği, yedek noktasından sonra tamamlanmış silmeler yeniden uygulanmalıdır ([kvkk-gdpr.md](../compliance/kvkk-gdpr.md)). `account_deletions` tablosu da geri yüklenen veritabanının parçası olduğu için yeni tamamlanan silmeleri **içermez**: geri yüklemeden önce (mantıksal bozulma senaryosunda canlı veritabanı hâlâ okunabiliyorsa) şunu dışarı alın:
  ```sql
  SELECT user_id, completed_at FROM account_deletions
   WHERE status = 'completed' AND completed_at > '<yedek zamanı>';
  ```
  Toplam kayıpta bu listeyi düzenli olarak veritabanı dışına aktarmanız gerekir. **Bu sürümde yeniden silmeyi uygulayan bir CLI komutu veya admin ucu yoktur**; `users` satırını elle silmek audit takma adlaştırmasını (AUD-05) ve Apple token iptal kuyruğunu atlar. Yeniden silme bir kod değişikliği gerektirir (hesap silme servisinin bir kullanıcı listesiyle çağrılması).
- Outbox'ta bekleyen bildirim/webhook'lar yeniden gönderilebilir (webhook alıcıları `webhook-id` ile tekilleştirir).

## 6. Test

Geri yüklemeyi en az üç ayda bir ayrı bir ortamda deneyin: §4 adımları + bir test hesabıyla giriş + `verify-audit-chain`. Anahtar kasasından geri yükleme de bu teste dahil olmalıdır.
