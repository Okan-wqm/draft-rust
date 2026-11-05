# Performans: ölçüm, darboğazlar ve gecikme bütçeleri (K-70)

Bu belge sıcak yolların nasıl ölçüldüğünü, bu konteynerde ölçülen sayıları, bulunan darboğazları ve yapılan düzeltmeleri, uç başına gecikme bütçelerini ve CI'daki gerileme kontrolünü anlatır. İlke: **hız güvenlikten taviz verilerek alınmaz.** Argon2id parametreleri, her istekteki oturum kontrolü (`session.access_token_session_check`), dağıtık hız sınırı ve sabit zamanlı karşılaştırmalar olduğu gibi kalır; yapılan her iyileştirme aynı kararı daha az iş ile verir.

## Araçlar

| Araç | Yer | Ne ölçer |
|------|-----|----------|
| Bench hedefi `hot_paths` | `crates/authn-server/benches/hot_paths.rs` | Tek çağıran, release profili: JWT EdDSA imza/doğrulama, anahtar önbelleği üzerinden doğrulama, istek başına oturum kontrolü (bearer, çerez), hız sınırı kararı (bellek / PostgreSQL / Redis), Argon2id parametre setleri ve eşzamanlı Argon2 tavanı, gerçek router + tüm middleware üzerinden tam HTTP istekleri (ucuz kimlik doğrulamalı `GET`, `GET /v1/me`, refresh rotasyonu, introspection, yerel şifre girişi, passkey girişi) |
| Yük testi | `crates/authn-server/tests/load.rs` (`#[ignore]`) | Yüksek eşzamanlılıkta gerçek router + gerçek PostgreSQL: uç başına p50/p95/p99 ve istek/saniye |
| Sorgu bütçesi testi | `crates/authn-server/tests/query_budget.rs` | Uç başına SQL ifadesi sayısı (yapısal, gürültüsüz gerileme kontrolü; her `cargo test`'te çalışır) |
| İndeks testleri | `crates/authn-session/tests/k70_indexes.rs` | Oturum tablolarındaki her yabancı anahtarın indeksli olması; temizlik kaskadının indeksi kullanması |
| Ölçüm kitaplığı | `authn_testkit::bench` | Gecikme istatistikleri (en yakın sıra yüzdelikleri), bağımlılıksız bench döngüsü, `count_queries` |

Harici bir benchmark/yük aracı kullanılmadı: `criterion` kilit dosyasında yoktu ve geçişli bağımlılıklarıyla birlikte ~20 yeni crate getirecekti; aynı istatistikleri veren küçük bir ölçüm modülü (`authn_testkit::bench`) hiçbir yeni bağımlılık eklemeden hem bench hedefine hem yük testine hizmet ediyor (LIC-01 riski sıfır, `cargo deny` ve `THIRD_PARTY_LICENSES.txt` değişmedi).

### Yeniden üretmek

```bash
# Tek çağıran gecikmeleri (release profili, ~4 dk; geçici bir veritabanı açar ve siler)
cargo bench -p authn-server --bench hot_paths
cargo bench -p authn-server --features redis --bench hot_paths      # + Redis hız sınırı
cargo bench -p authn-server --bench hot_paths -- argon2/            # yalnızca bir grup
AUTHN_BENCH_ITERS=500 cargo bench -p authn-server --bench hot_paths

# Yük testi (release, ~1 dk)
cargo test -p authn-server --release --test load -- --ignored --nocapture
AUTHN_LOAD_SECS=20 AUTHN_LOAD_CONCURRENCY=128 AUTHN_LOAD_POOL=32 AUTHN_LOAD_RATE_LIMIT=redis \
  cargo test -p authn-server --release --features redis --test load -- --ignored --nocapture

# Sorgu bütçeleri (her CI koşusunda zaten çalışır; ayrıntılı döküm için)
cargo test -p authn-server --test query_budget -- --nocapture
```

`DATABASE_URL` (varsayılanı `.cargo/config.toml`) bir PostgreSQL sunucusunu göstermelidir; bench ve yük testi orada `authn_perf_<rastgele>` adlı geçici bir veritabanı oluşturup sonunda siler. Gürültüden kaçınmak için ölçümü boş bir makinede, `RUST_LOG=error` ile çalıştırın.

**Ölçüm modeli.** Tüm HTTP ölçümleri istekleri `tower::ServiceExt::oneshot` ile süreç içinde gönderir: yönlendirme, her middleware (istek bağlamı, izleme, zaman aşımı, eşzamanlılık sınırı, gövde sınırı, host doğrulama, güvenlik başlıkları, CORS, IP başına hız sınırı, kimlik doğrulama + CSRF), handler, serileştirme ve PostgreSQL dahildir; TCP/TLS ve HTTP ayrıştırma (hyper) dahil değildir. Yapılandırma üretim biçimindedir: **PostgreSQL hız sınırlayıcı** (varsayılan arka uç), **üretim Argon2id parametreleri**, gerçek saat. Her istek farklı bir istemci IP'sinden gelir (çok sayıda istemcinin trafiği gibi; tek IP yalnızca IP başına sınırı ölçerdi). Girişler kullanıcının kendi `/24` ağından ve kendi cihaz kimliğiyle (`x-device-id`) gelir: ilk girişten sonra ağ ve cihaz tanınır, risk puanı düşük kalır (RSK-02/RSK-03) — geri dönen kullanıcının olağan durumu. Ölçüm uğruna gevşetilen tek ayar introspection'ın API anahtarı başına sınırıdır (`session.introspection_per_client`, varsayılan 600/dk): tüm introspection istekleri tek anahtarla yapıldığından aksi halde yalnızca sınırlayıcı ölçülürdü.

## Ölçüm ortamı (önemli uyarı)

| | |
|---|---|
| Makine | Bu geliştirme konteyneri: 4 vCPU (Intel Xeon @ 2.80 GHz), 15 GB RAM, paylaşımlı sanal makine |
| Veritabanı | PostgreSQL 16.15, **aynı makinede** (`shared_buffers` 128 MB, `synchronous_commit = on`), localhost bağlantısı |
| Redis | 7.0.15, aynı makinede |
| Derleme | rustc 1.97.1, release profili |
| Gürültü | Ölçümler sırasında makinede paralel çalışan başka bir agent derleme/test yapıyordu (yük ortalaması 3–8). Aynı koşunun tekrarları arasında p50'ler **±%15**, maksimumlar çok daha fazla oynadı |

Bu sayılar **mutlak üretim tahmini değildir**. Uygulama ile PostgreSQL aynı 4 vCPU'yu paylaştığından yük altında darboğaz CPU'dur; ayrı bir veritabanı sunucusunda istek başına gecikmeye her SQL ifadesi için bir ağ gidiş-dönüşü (tipik olarak 0,2–1 ms) eklenir, buna karşılık uygulama CPU'su serbest kalır. Bu yüzden bütçeler aşağıda hem mutlak hedef hem de **ifade sayısı** (makineden bağımsız) olarak verilmiştir.

## Sonuçlar

### Tek çağıran gecikmeleri (`cargo bench`, sonrası)

| Durum | p50 | p99 | Not |
|-------|-----|-----|-----|
| `jwt/sign_access_token` | 22 µs | 60 µs | Ed25519 imza + JSON |
| `jwt/verify_access_token` | 44–61 µs | 150–190 µs | `verify_strict`, katı JSON (yinelenen alan reddi), claim kontrolleri |
| `session/verify_access_token` (anahtar önbelleği) | 45–67 µs | 150–480 µs | önbellekten doğrulama; veritabanı yok |
| `session/authenticate_bearer` (doğrulama + oturum sorgusu) | 0,40 ms | 2–4,5 ms | 1 SQL ifadesi |
| `GET /v1/time` (bearer, tam yığın) | 0,9–1,1 ms | 3–7 ms | 2 ifade |
| `GET /v1/time` (oturum çerezi) | 1,1–1,3 ms | 3,4–7,8 ms | 2 ifade |
| `GET /v1/me` (bearer) | 3,3–3,7 ms | 9–13 ms | 10 ifade |
| `POST /v1/token/refresh` | 3,1–4,2 ms | 8–17 ms | 10 ifade, tek transaction |
| `POST /v1/token/introspect` | 1,5–2,3 ms | 4–11 ms | 4 ifade |
| `POST /v1/login/password` (yerel, Argon2id varsayılan) | 41–61 ms | 70–118 ms | Argon2id ≈ 23–30 ms + 42 ifade |
| `POST /v1/login/passkey` (doğrulama isteği) | 18–31 ms | 45–57 ms | WebAuthn doğrulama, oturum, risk/uyarı, audit |
| `ratelimit/memory` | 2 µs | 3–9 µs | yalnızca tek örnek |
| `ratelimit/postgres` | 0,36–0,42 ms | 0,9–4 ms | tek `INSERT … ON CONFLICT … RETURNING` |
| `ratelimit/redis` | 0,11–0,15 ms | 0,3–0,6 ms | tek Lua betiği |

Aralıklar birden fazla koşunun p50/p99'larıdır. Önce/sonra karşılaştırması aşağıda; tek çağıranda bir gidiş-dönüşün (~0,35 ms) kazancı bu makinedeki gürültünün içinde kaldı.

### Yük testi (64 eşzamanlı çağıran, havuz 20, PostgreSQL hız sınırı, 8 sn/senaryo)

Önce (`4184b38`) ve sonra, **aynı koşullarda art arda iki tur** (ortalamalar):

| Senaryo | Önce istek/sn | Sonra istek/sn | Önce p50 / p99 | Sonra p50 / p99 |
|---------|---------------|----------------|----------------|-----------------|
| `GET /v1/time` (bearer) | 4 410 | 3 940 | 13,7 / 24,9 ms | 15,6 / 27,4 ms |
| `GET /v1/me` (bearer) | 1 630 | 1 650 | 38,7 / 59,0 ms | 38,2 / 57,7 ms |
| `POST /v1/token/introspect` | 2 630 | 2 500 | 23,7 / 38,9 ms | 25,0 / 39,0 ms |
| `POST /v1/token/refresh` | 1 145 | 1 150 | 55,4 / 80,2 ms | 55,2 / 79,5 ms |
| `POST /v1/login/password` (yerel) | 79 | 77 | 0,80 / 0,92 s | 0,83 / 0,94 s |

**Dürüst yorum:** iki sürüm bu makinede gürültü içinde aynıdır ("sonra" turları daha yüksek yük ortalamasında koştu: 7,9 karşı 5,3–6,8; `GET /v1/time`'ın ifade sayısı bu dalgada değişmedi, yalnızca doğrulayıcı kopyası kalktı). Uygulama ve PostgreSQL aynı 4 vCPU'yu paylaştığından yük altında sınır CPU'dur, localhost gidiş-dönüşü değil; ifade sayısındaki azalmanın etkisi ayrı bir veritabanı sunucusunda (her ifade = bir ağ gidiş-dönüşü) ve veritabanı tarafındaki yükte görülür. Bu dalganın ölçülebilir büyük kazancı temizlik işindeki indeks düzeltmesidir (aşağıda, 23,8 s → 17 ms).

Girişte gecikme Little yasasıyla açıklanır: 64 bekleyen istek / ~78 giriş/sn ≈ 0,8 s. Tavan Argon2id'dir (aşağıda: bu makinede 4 izinle ~75–77 doğrulama/sn); kalan CPU PostgreSQL ve girişin 42 ifadesi arasında paylaşılır.

### Hız sınırı arka ucu (64 eşzamanlı, havuz 20)

| Senaryo | PostgreSQL | Redis | Bellek (yalnızca tek örnek) |
|---------|-----------|-------|------------------------------|
| `GET /v1/time` (bearer) | 3 930 istek/sn, p50 15,7 ms | 5 580 (+%42), p50 10,2 ms | 6 890 (+%75), p50 8,1 ms |
| `POST /v1/token/introspect` | 2 320 | 3 380 (+%46) | 3 850 |
| `POST /v1/token/refresh` | 1 130 | 1 290 (+%14) | 1 480 |

Her istekte en az bir hız sınırı kararı verilir (IP başına genel sınır, PRT-01); PostgreSQL arka ucunda bu bir yazma (UNLOGGED tablo, satır kilidi, yeni tuple). **Yüksek trafikte (birkaç bin istek/sn üzeri) Redis arka ucu önerilir** — güvenlik aynıdır (aynı GCRA, atomik tek işlem), yalnızca karar daha ucuzdur. Bellek arka ucu dağıtık değildir; birden fazla örnekte sınırlar örnek sayısıyla çarpılır, üretimde kullanılmaz.

### Bağlantı havuzu (`database.max_connections`)

| Havuz | `GET /v1/time` | `POST /v1/token/refresh` |
|-------|----------------|--------------------------|
| 8 | 4 305 istek/sn, p99 23,6 ms | 945 istek/sn, p50 67 ms |
| 20 (varsayılan) | 4 100, p99 25,3 ms | 1 190, p50 52 ms |
| 40 | 3 850, p99 34,6 ms | 1 120, p50 56 ms |

Tek ifadeli okumalar küçük havuzu sever (daha az PostgreSQL arka uç süreci aynı CPU'lar için yarışır); transaction tutan refresh daha büyüğünü ister. 40'ta çekişme p95/p99'u büyütür. **Öneri:** `max_connections` ≈ veritabanı çekirdek sayısının 2–4 katı (varsayılan 20 bu makinede dengeli); birden fazla uygulama örneğinde toplam bağlantı PostgreSQL'in `max_connections`'ını aşmamalıdır. Her yük testinin ilk senaryosunda görülen yüzlerce ms'lik tekil maksimumlar havuzun soğuk başlangıcıdır (`min_connections` dışındaki bağlantılar ilk yükte açılır; havuz büyüdükçe artar). Gecikmeye duyarlı kurulumlarda `min_connections`'ı beklenen eşzamanlılığa yakın tutun.

## Argon2id: güvenlik / gecikme dengesi

Tek doğrulama (p50, iki koşunun aralığı) ve aynı makinede tüm izinler meşgulken verim:

| Parametre seti | Bellek | p50 | Not |
|----------------|--------|-----|-----|
| **m=19456 KiB, t=2, p=1 (varsayılan, CRY-01)** | 19 MiB | 23–30 ms | OWASP'ın 2. seti; 4 izinle **~75–77 doğrulama/sn** |
| m=47104, t=1, p=1 | 46 MiB | 61–70 ms | OWASP 1. set; bu makinede en yavaşı ve eşzamanlı hash başına 2,4× bellek |
| m=12288, t=3, p=1 | 12 MiB | 21–27 ms | OWASP 3. set |
| m=9216, t=4, p=1 | 9 MiB | 21–27 ms | OWASP 4. set |
| m=7168, t=5, p=1 | 7 MiB | 18–31 ms | OWASP 5. set (yapılandırmanın izin verdiği en düşük bellek) |
| m=65536, t=3, p=4 | 64 MiB | 190–230 ms | RFC 9106 ikinci öneri; tek giriş başına 4 çekirdek |

Bulgular:

- OWASP'ın beş seti "eşdeğer koruma" olarak önerilir; bu makinede düşük bellekli setler **anlamlı ölçüde hızlı değil** (t arttıkça süre geri geliyor), saldırganın GPU/ASIC maliyetini artıran bellek ise azalıyor. Varsayılan (19 MiB, t=2) bu yüzden doğru denge: gecikme diğer setlerle aynı aralıkta, bellek-sertliği daha yüksek, eşzamanlı hash başına bellek makul (`max_concurrent_hashes` × 19 MiB).
- **Varsayılan düşürülmedi.** Yapılandırma doğrulaması zaten OWASP alt sınırının altını reddeder (`crypto.argon2.memory_kib` ≥ 7168, `iterations` ≥ 1).
- Giriş verimi Argon2id ile sınırlıdır ve bu bilinçli bir tercihtir (çevrimdışı kaba kuvvet maliyeti). Kapasite planı: örnek başına giriş/sn ≈ `max_concurrent_hashes` / Argon2 süresi; bu makinede ~75/sn. `max_concurrent_hashes`'ı çekirdek sayısının üstüne çıkarmak verimi artırmaz, yalnızca bekleyen işi artırır; daha fazla giriş kapasitesi yatay ölçekle (örnek ekle) sağlanır.
- Hesap varlığı süreden anlaşılmaz: bilinmeyen hesapta da eşit maliyetli sahte doğrulama yapılır (CRY-05); bu dalgada giriş yoluna dokunulmadı.

## Bulunan darboğazlar ve yapılan düzeltmeler

| # | Bulgu | Etki | Düzeltme | Testler |
|---|-------|------|----------|---------|
| 1 | `refresh_tokens.parent_id` / `replaced_by_id` kendine başvuran `ON DELETE SET NULL` yabancı anahtarlarının indeksi yoktu: silinen her refresh token için PostgreSQL tüm tabloyu iki kez tarıyordu. Oturum temizlik işi (OPS-06) oturumları silince token'lar kaskadla silinir. | `EXPLAIN ANALYZE`, 100 bin oturum / 300 bin token: **100 oturumu silmek 23,8 s** (tetikleyiciler: 11,0 s + 12,8 s) | Migration `2050`, `2051` (kısmi indeksler); aynı desen için `auth_challenges.session_id` (`2052`) ve `requested_org_id` (`2053`). `CREATE INDEX CONCURRENTLY` (canlı tabloda yazma kilidi yok; `-- no-transaction`, dosya başına tek ifade) | Sonra: **17 ms** (~1100–1400×; koşular arasında 17–22 ms). `k_70_session_table_foreign_keys_are_indexed`, `k_70_purging_sessions_cascades_through_refresh_token_chains` |
| 2 | API anahtarıyla kimlik doğrulama (introspection, organizasyon uçları) her istekte sahibin durumunu ayrı bir sorguyla okuyor ve kısıtlanmış `last_used_at` güncellemesini (çoğu zaman 0 satır) her istekte gönderiyordu | istek başına 2 gereksiz gidiş-dönüş | Sahip durumu anahtar sorgusuna `LEFT JOIN users` ile katıldı (aynı anlık görüntü); okunan `last_used_at` aralık içindeyse güncelleme hiç gönderilmiyor (SQL koşulu eşzamanlı yazıcılara karşı koruma olarak duruyor). Askıya alınmış sahip yine anında reddedilir | introspection 6 → 4 ifade. `org_08_k_70_recently_used_key_authenticates_in_one_statement` (1/2 ifade, askıya alma), mevcut `org_08_*` testleri |
| 3 | Refresh rotasyonunda ardılı bağlama ve ebeveynin mühürlü ardılını silme iki ayrı `UPDATE` idi | rotasyon transaction'ında (oturum satırı kilitliyken) 1 fazla gidiş-dönüş | Tek ifade (veri değiştiren CTE; iki güncelleme ayrık satırlara dokunur) | refresh 11 → 10 ifade. `ses_05_rotation_keeps_only_the_latest_sealed_successor` (yeni), tüm `ses_05_*` testleri |
| 4 | `GET /v1/me` aynı `users` satırını iki kez okuyordu (`profile_of` zaten e-posta, doğrulama ve durumu taşıyor) | 1 fazla gidiş-dönüş | Profil görünümü kullanıldı | 11 → 10 ifade; mevcut `ses_16_*` testleri |
| 5 | Her bearer isteğinde imza anahtarı önbelleğinden doğrulayıcı (`HashMap<kid, anahtar>`) **kopyalanıyordu** | istek başına `String` ayırmaları | Değişmez anahtar anlık görüntüsü (`Arc<KeySnapshot>`) paylaşılıyor; eşzamanlı yeniden yükleme çağıranın görüntüsünü değiştirmez | `ses_08_*`, `ses_09_*` (anahtar rotasyonu, iptal edilen anahtar) |

Hiçbiri bir güvenlik kontrolünü kaldırmaz veya gevşetmez: oturum kontrolü her istekte, hız sınırı her istekte, imza doğrulaması `verify_strict`, Argon2id parametreleri aynı.

**`CONCURRENTLY` migration'ları yarıda kalırsa (2050–2053):** dağıtım indeks kurulurken öldürülürse, `statement_timeout` dolarsa ya da aynı anda migration çalıştıran ikinci bir örnekle kilitlenme (deadlock) olursa PostgreSQL geride **INVALID** bir indeks bırakır ve migration kaydedilmez. Bu dosyalarda bilinçli olarak `IF NOT EXISTS` yoktur: olsaydı yeniden çalıştırma INVALID indeksi atlayıp migration'ı uygulanmış sayardı ve indeks hiç kullanılmadan kalırdı. Yeniden çalıştırma bunun yerine `already exists` hatasıyla durur (`serve` başlamaz, hazır olma kontrolü şemayı güncel saymaz). Çözüm: `DROP INDEX CONCURRENTLY <indeks>;` ve migration'ları yeniden çalıştırmak. Büyük tablolarda `database.migrate_on_start` yerine `rust-authentication migrate` komutunu tek bir örnekten çalıştırın: migration'ı aynı anda çalıştıran örneklerden biri deadlock hatası alıp başlamayabilir. Test: `k_70_rerun_after_an_interrupted_index_build_never_keeps_an_invalid_index` (düzeltmeden önce kırmızıydı).

### Ölçülüp bilinçli olarak dokunulmayanlar (izleme adayları)

- **Şifre girişi 42 ifade.** Aynı `users` satırı 6 kez okunuyor (giriş hattı, parola modülü, politika, MFA, risk/bildirim), hız sınırı 9 ifade (4 karar, 2 `peek`, 2 başarı sonrası sıfırlama), audit zinciri 5 ifade. Tek çağıranda ~17 ms'lik bu veritabanı işi Argon2id'nin (~25 ms) yanında küçük değil; ayrı veritabanı sunucusunda (0,5 ms RTT) +21 ms. Düzeltme birden çok modülün (session giriş hattı, password, protect, mfa) arayüzünü etkiler ve bilinmeyen hesap yolundaki eşit maliyet garantisine (CRY-05, SES-01) dokunur; ayrı bir iş olarak, zamanlama testleriyle birlikte yapılmalı.
- **Audit zinciri başı tek satır.** Her audit olayı `audit_chain_head` satırını kilitler ve kilit çağıranın `COMMIT`'ine kadar tutulur (olay çağıranın transaction'ında yazılır). Sistem genelinde audit'li yazmaları sıralar: bu makinede sorun değil, uzak veritabanında (0,5 ms RTT, kilit altında ~5 ifade) tavan kabaca ~400 audit'li olay/sn. Kaldırmak bir port değişikliği ister (authn-audit README "Bilinen sınırlamalar", wave 5A).
- **`GET /v1/me` 10 ifade** (profil, parola bayrağı, passkey sayısı, MFA durumunun 4 ifadesi). MFA için yalnızca etkin faktör türlerini döndüren daha ucuz bir API, account/mfa sahipleriyle sözleşme değişikliği gerektirir; uç sayfa açılışında bir kez çağrılır, sıcak istek yolunda değildir.
- **Webauthn seremonileri** (`webauthn_ceremonies.session_id`, `user_id`, `challenge_id`) ve birkaç seyrek silinen referansın (`organizations.created_by` vb.) yabancı anahtar indeksleri yok; tablolar kısa ömürlü veya silme nadir. Gerekirse sahip modüller kendi aralıklarında ekler.
- **Erişim token'ı başına oturum kontrolü** (1 ifade) bilinçli: iptal anında geçerli olur. `session.access_token_session_check = false` bir ifade kazandırır ama iptali token ömrüne (≤ `access_token_ttl`) erteler — varsayılan açık kalmalı.

## Gecikme bütçeleri

Hedefler sunucu tarafıdır (istemci ağı hariç), "nominal yükte" (doygunluğun ~%70'i altı), veritabanı ayrı bir sunucuda ve RTT ≤ 1 ms varsayılarak verilmiştir. İfade sayısı makineden bağımsızdır ve **CI'da zorlanır** (`query_budget.rs`, `mod budget`); bir değişiklik bir ifade eklerse test düşer: ya gerekçelendirilip bütçe ve bu tablo aynı committe güncellenir ya da ifade kaldırılır. Bu tablo ile testteki sabitler aynı tutulur (test tabloyu da okur).

| Uç | İfade bütçesi | p50 hedefi | p99 hedefi | Bu makinede (tek çağıran) p50 / p99 |
|----|---------------|------------|------------|-------------------------------------|
| `GET` kimlik doğrulamalı (bearer) | 2 | 3 ms | 15 ms | 1,0 / 3–7 ms |
| `GET` kimlik doğrulamalı (oturum çerezi) | 2 | 3 ms | 15 ms | 1,2 / 3–8 ms |
| `GET /v1/me` | 10 | 10 ms | 40 ms | 3,5 / 9–13 ms |
| `POST /v1/token/refresh` | 10 | 10 ms | 40 ms | 3,5 / 8–17 ms |
| `POST /v1/token/introspect` | 4 | 5 ms | 25 ms | 1,8 / 4–11 ms |
| `POST /v1/login/password` | 42 | 80 ms | 250 ms | 41–61 / 70–118 ms |
| `POST /v1/login/passkey` | — | 50 ms | 150 ms | 18–31 / 45–57 ms |

Yük testi için taban (bu makine sınıfında, 4 vCPU, veritabanı aynı makinede, PostgreSQL hız sınırı): `GET /v1/time` ≥ 3 000 istek/sn, `GET /v1/me` ≥ 1 200, introspection ≥ 2 000, refresh ≥ 900, şifre girişi ≥ 60/sn. Bunlar CI'da zorlanmaz (duvar saati eşikleri paylaşımlı makinelerde dalgalanır); sürüm öncesi elle koşulur.

## CI'daki gerileme kontrolü

- **Sorgu bütçeleri** (`k_70_query_budget_of_hot_endpoints`): yapısal, gürültüsüz; her `cargo test`'te çalışır. Hesap: istek, sayacın kendi `tracing` dağıtıcısıyla sarılı future içinde gönderilir; sqlx'in her ifade için yaydığı `sqlx::query` olayları sayılır (yalnızca o isteğin görevinde, başka testlerin ifadeleri karışmaz).
- **İndeks testleri** (`k70_indexes.rs`): yeni bir yabancı anahtar indeksiz eklenirse oturum tablolarında düşer.
- **Bench duman koşusu:** `hot_paths` hedefi `test = true` ile tanımlıdır; `cargo test` onu `--bench` olmadan çalıştırır ve her durum iki kez koşar (~7 sn): her sıcak yolun hâlâ çalıştığını kanıtlar, ölçmez. Redis yoksa Redis durumu atlanır.
- Duvar saati eşiği bilinçli olarak yok.
