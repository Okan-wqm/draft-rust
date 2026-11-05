# Yedekleme ve geri yükleme (DOC-06)

## 1. Ne yedeklenir

| Varlık | Nerede | Yedek |
|--------|--------|-------|
| Tüm uygulama durumu (kullanıcılar, kimlik bilgileri, oturumlar, MFA, passkey, organizasyonlar, audit log, outbox, webhook'lar, imza anahtarları, tek kullanımlık token'lar) | **PostgreSQL** (tek veritabanı) | Zorunlu: sürekli WAL arşivi + düzenli taban yedek (PITR) önerilir |
| Yapılandırma ve **anahtarlar** (`crypto.peppers`, `crypto.keks`, `crypto.hmac_root_key`, sağlayıcı sırları) | Yapılandırma dosyası / secret yöneticisi | Zorunlu, **veritabanı yedeğinden ayrı** saklanır (§3) |
| Audit zinciri dış çıpaları (sunucunun `audit.checkpoint_interval` başına logladığı `anchor` değerleri, `audit-checkpoint` çıktısı, `verify-audit-chain` çıktısındaki `head <seq>:<hash>`, `chain_key_switch` kontrol noktaları) | WORM depo | Zorunlu ([key-management.md §5](key-management.md#5-audit-zinciri-anahtarı-k-77)) |
| **Silme defteri** (`export-erasures` çıktısı, JSON satırları: `user_id`, `erased_at`, `reason`, `mac`; K-108) | Veritabanı yedeklerinden **ayrı**, geri yüklemeyle birlikte geri sarılmayan bir depo (WORM / ayrı nesne deposu) | Zorunlu (KVKK md. 7, GDPR md. 17): geri yüklemeden sonra silmeleri yeniden uygulamanın tek kaynağı (§5) |
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
4. Yedeğin alındığı tarihteki anahtarları içeren yapılandırmayla `rust-authentication check-config`, ardından `rust-authentication migrate` (ikili yedekten yeniyse; ikilinin migration'ları uygulanmadan `serve` başlamaz).
5. **Silmeleri yeniden uygulayın (K-108), `serve`'den önce:** veritabanı dışındaki defterin tamamını (ya da en azından yedek zamanından biraz önceki andan bu yana olan kısmını) verin:
   ```bash
   cat /ledger/erasures-*.jsonl > /tmp/ledger.jsonl        # birleştirme; tekrarlar zararsız
   rust-authentication --config prod.toml reapply-erasures --from /tmp/ledger.jsonl
   # 1520 ledger entries: 37 accounts erased again, 1483 already erased, 0 blocked
   ```
   Ayrıntı ve son dışa aktarımdan sonraki boşluk: §5.
6. `rust-authentication verify-audit-chain` — zincir sağlam olmalı. Dış çıpanız yedekten **daha yeniyse** `--anchor` ile doğrulama başarısız olur; bu beklenir (geri sarma) ve olay kaydına geçirilmelidir. Geri yüklenen zincir üzerine yeni bir çıpa alın: `rust-authentication audit-checkpoint | tail -n1`.
7. Sunucuyu başlatın; `/health/ready` `200` olmalı.

## 5. Geri yükleme sonrası güvenlik etkileri

Eski bir ana dönmek, o andan sonra yapılan **güvenlik eylemlerini geri alır**:

- O tarihten sonra iptal edilmiş oturumlar ve refresh token'lar yeniden geçerli olur; değiştirilmiş şifreler eski değerine döner; kaldırılmış passkey/MFA faktörleri ve iptal edilmiş API anahtarları geri gelir; silinmiş imza anahtarları geri gelebilir.
  - **Öneri:** geri yüklemeden sonra `POST /v1/admin/emergency/revoke-all-sessions` (veya CLI ile kurtarılan bir admin hesabıyla) tüm oturumları kapatın; olay sırasında bir anahtar sızdıysa `rotate-signing-key --emergency`.
- **Silinen hesaplar geri gelir (K-108).** KVKK md. 7 / GDPR md. 17 gereği yedek noktasından sonra tamamlanmış silmeler yeniden uygulanmalıdır ([kvkk-gdpr.md §4](../compliance/kvkk-gdpr.md)). Geri yüklenen veritabanındaki `erasure_ledger` ve `account_deletions` tabloları yedek anındaki hâldedir, sonraki silmeleri **bilmez**; bu yüzden kaynak veritabanının dışında tutulur:
  - **Defter:** her silme (ACC-09 bekleme süresi sonu, ACC-05 doğrulanmamış hesap temizliği, yeniden uygulama) aynı transaction'da `erasure_ledger`'a `user_id`, `erased_at`, `reason` yazar. Kişisel veri yoktur: silmeden sonra kimliğe hiçbir kayıt bağlanmaz.
  - **Dışa aktarma (zamanlanmış, ör. saatlik cron/Kubernetes CronJob):**
    ```bash
    rust-authentication --config prod.toml export-erasures \
      --since "$(date -u -d '-2 hours' +%Y-%m-%dT%H:%M:%SZ)" \
      --output /ledger/erasures-$(date -u +%Y%m%dT%H%M).jsonl
    ```
    İmleç bir zamandır (dizi numarası değil: geri yüklenen veritabanı aynı numaraları yeniden dağıtırdı); aralıkları **çakıştırın** (yukarıda 2 saatlik pencere, saatlik çalışma), tekrarlanan satırlar zararsızdır. Dosyaları yedeklerden ayrı, değiştirilemez bir depoya yazın.
  - **Son dışa aktarımdan sonraki boşluk:** defter dosyası en son dışa aktarım anına kadar günceldir. Veritabanı mantıksal bozulmayla geri yükleniyorsa ve canlı veritabanı hâlâ okunabiliyorsa geri yüklemeden **önce** son bir `export-erasures --since <son dışa aktarım>` çalıştırın. Toplam kayıpta aradaki silmeler uygulama loglarında `account erased` satırları olarak bulunur (`user_id`, `reason`, zaman damgası): bunları aynı JSON biçimine çevirip (`{"user_id":"…","erased_at":"<log zamanı>","reason":"<reason>"}`) deftere ekleyin.
  - **Bütünlük (MAC):** her satır `crypto.hmac_root_key`'den türetilen bir anahtarla (`KeyPurpose::ErasureLedger`) imzalanır; `reapply-erasures` imzasız, değiştirilmiş ya da başka bir anahtarla imzalanmış bir satırda **hiçbir şey silmeden** çıkış `65` ile durur ve yalnızca satır numarasını yazar. Böylece defter deposuna yazabilen biri bir sonraki geri yüklemede istediği hesabı sildiremez. MAC bir satırın **çıkarılmasını** yakalamaz: depoyu ekleme-yalnızca / sürümlü (WORM) tutun. `crypto.hmac_root_key` döndürüldükten sonra eski dosyalar yeni anahtarla doğrulanmaz: döndürmeden hemen sonra defterin tamamını (`--since` olmadan) canlı veritabanından yeniden dışa aktarın; eski bir dosyayı yeniden uygulamak gerekirse komutu o dosyayı yazan anahtarı içeren yapılandırmayla çalıştırın.
  - **Yeniden uygulama:** `reapply-erasures --from <dosya|->` idempotenttir. Hesap yoksa yalnızca defter satırı (asıl zaman ve nedenle) yazılır; geri gelmişse normal silme yolundan silinir (denetimli durum geçişleri, `user.deleted` olayı, audit takma adlaştırması, silme kancaları — ör. Apple token iptal kuyruğu —, kaskad). Geri yüklenen silme takvimi tamamlanır. Geri yüklenen veride bir organizasyonun **son sahibi** olan hesaba dokunulmaz: komut kimlikleri listeler ve `1` ile çıkar; organizasyonu devredip/silip komutu yeniden çalıştırın. Geçersiz bir defter satırı hiçbir şey silinmeden `65` ile reddedilir (satır numarası yazılır, içerik yazılmaz).
  - **Sınır:** organizasyon silmeleri (ORG-12) defterde değildir; yedekten sonra silinmiş organizasyonlar elle yeniden silinmelidir (`DELETE /v1/orgs/{org_id}`, sahibinin oturumuyla; geri yüklenen veride silme takvimi zaten varsa temizlik işi onu kendisi tamamlar).
- Outbox'ta bekleyen bildirim/webhook'lar yeniden gönderilebilir (webhook alıcıları `webhook-id` ile tekilleştirir).

## 6. Test

Geri yüklemeyi en az üç ayda bir ayrı bir ortamda deneyin: §4 adımları + bir test hesabıyla giriş + `verify-audit-chain` + yedekten sonra silinmiş bir test hesabının `reapply-erasures` ile yeniden silindiğinin doğrulanması. Otomatik karşılığı: `crates/authn-server/tests/erasure_restore.rs` (`k_108_erasure_is_reapplied_after_restoring_an_older_backup`, gerçek bir veritabanı kopyasıyla). Anahtar kasasından geri yükleme de bu teste dahil olmalıdır.
