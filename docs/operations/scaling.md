# Ölçekleme (DOC-06)

Ölçümler, darboğazlar ve gecikme bütçeleri [performance.md](performance.md)'dedir; bu belge onlardan çıkan kapasite kararlarını özetler. Oradaki sayılar 4 vCPU'lu, uygulama ile PostgreSQL'in aynı makinede olduğu bir ortamda ölçüldü; kendi donanımınızda `performance.md` "Yeniden üretmek" adımlarıyla tekrar ölçün.

## 1. Yatay ölçek

- `serve` örnekleri durumsuzdur; yük dengeleyicinin arkasında istediğiniz kadar çalıştırın. Yapışkan oturum (sticky session) gerekmez: oturumlar, challenge'lar, seremoniler, OAuth state'leri ve oran sınırları veritabanında (veya Redis'te) tutulur.
- Arka plan işleri her örnekte çalışır ve çoklu örnekte güvenlidir (`FOR UPDATE SKIP LOCKED`, advisory lock); ayrı bir "lider" gerekmez ([deployment.md §7](deployment.md#7-arka-plan-işleri)).
- İmza anahtarı değişiklikleri `LISTEN/NOTIFY` ile tüm örneklere anında yayılır; her örnek bunun için havuz dışında **bir ek** PostgreSQL bağlantısı tutar.
- `server.limits.max_concurrent_requests` (1024) ve `request_timeout` (30 sn) örnek başınadır.

## 2. Darboğazlar ve ayarlar

| Konu | Bulgu ([performance.md](performance.md)) | Ne yapmalı |
|------|-------------------------------------------|------------|
| **Şifre girişi ≈ Argon2id** | Örnek başına giriş/sn ≈ `crypto.max_concurrent_hashes` / Argon2 süresi (ölçüm makinesinde ~75/sn, varsayılan m=19 MiB, t=2) | Giriş kapasitesini **örnek ekleyerek** artırın. `max_concurrent_hashes`'ı çekirdek sayısının üstüne çıkarmak verimi artırmaz, yalnızca kuyruğu uzatır. Bellek: `max_concurrent_hashes × memory_kib`. Argon2 parametrelerini düşürmeyin (OWASP alt sınırı yapılandırmada zorlanır) |
| **Giriş başına 26 SQL ifadesi** (K-128 öncesi 42) | `users` satırı 2 kez (arama + kilit), hız sınırı 3 + HTTP katmanı 1, audit 3, MFA durumu 4; ayrı veritabanı sunucusunda (0,5 ms RTT) ≈ +13 ms (önce +21 ms) | Uygulama ile veritabanı arasındaki gecikmeyi düşük tutun (aynı bölge/AZ). Kalan adaylar `performance.md` "K-128" bölümünde |
| **Oran sınırı arka ucu** | Her istekte en az bir karar; PostgreSQL arka ucunda bu bir yazma. Redis ile `GET /v1/time` +%42, introspection +%46, refresh +%14 | Birkaç bin istek/sn'nin üzerinde `protect.rate_limit.backend = "redis"` (güvenlik aynı: aynı GCRA, atomik). Redis özelliğiyle derleyin ([deployment.md §1](deployment.md#1-ikili-ve-komutlar)). `memory` üretimde reddedilir |
| **Bağlantı havuzu** | Okumalar küçük havuzu, refresh (transaction tutar) büyüğünü sever; 40'ta çekişme p99'u büyütüyor | `database.max_connections` ≈ veritabanı çekirdek sayısının 2–4 katı (varsayılan 20). **Toplam** = örnek sayısı × (`max_connections` + `maintenance_max_connections` + 1 dinleyici) PostgreSQL'in `max_connections`'ını aşmamalı; gerekirse önüne PgBouncer (transaction modu, `LISTEN` bağlantısı hariç) koymayı değerlendirin — bu kurulum bu depoda test edilmedi |
| **Soğuk havuz** | İlk yükte tekil yüzlerce ms'lik gecikmeler | Gecikmeye duyarlı kurulumlarda `database.min_connections`'ı beklenen eşzamanlılığa yaklaştırın |
| **Audit zinciri başı** | Her audit olayı tek `audit_chain_head` satırını çağıranın `COMMIT`'ine kadar kilitler; kilit altında 2 ifade + `COMMIT` (K-128 öncesi 5); uzak veritabanında tavan kabaca ~650 audit'li olay/sn (önce ~330–400; sistem genelinde) | Audit'li yazma yoğun iş yüklerinde (toplu işlemler) bu, örnek sayısından bağımsız bir tavandır. Kaldırmak port değişikliği ister (authn-audit README "Bilinen sınırlamalar") |
| **Bearer başına oturum kontrolü** | +1 birincil anahtar sorgusu (~0,55 ms ölçüldü) | Bilinçli: iptal anında etkili. Üretimde kapatılamaz |
| **Introspection** | 4 ifade/istek | Kaynak sunucularınızda varsayılan olarak yerel JWT doğrulaması yapın, introspection'ı yüksek riskli işlemlere saklayın ([resource-server.md](../integration/resource-server.md)) |

## 3. Veritabanı

- Tek bir PostgreSQL 16 birincil sunucusu yazma yolundadır; uygulama okuma replikası kullanmaz (tüm okumalar birincile gider).
- Büyüyen tablolar ve temizlikleri: `audit_events` (`audit.retention` 400 g), `outbox` (`delivered_retention` 7 g, `dead_retention` 30 g), `webhook_deliveries` (30 g), `sessions` / `refresh_tokens` / `auth_challenges` / `one_time_tokens` (süre dolunca dakikalık işler), `rate_limit_buckets` (UNLOGGED). Saklama sürelerini kısaltmak tablo boyutunu doğrudan düşürür.
- Yabancı anahtar indeksleri bir testle zorlanır (`crates/authn-server/tests/schema_foreign_keys.rs`); büyük tablolarda yeni indeksler `CREATE INDEX CONCURRENTLY` migration'larıyla gelir ([deployment.md §3](deployment.md#3-migrationlar)).

## 4. Gecikme bütçeleri

İfade sayıları CI'da zorlanır (`crates/authn-server/tests/query_budget.rs`): `GET` kimlik doğrulamalı uçlar 2, `GET /v1/me` 10, refresh 10, introspection 4, şifre girişi 42. Hedef p50/p99 değerleri ve yük testi tabanları için [performance.md § Gecikme bütçeleri](performance.md#gecikme-bütçeleri).
