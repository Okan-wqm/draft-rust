# authn-protect

Kötüye kullanım koruması ve HTTP sertleştirmesi: rate limit (bellek / PostgreSQL / Redis, GCRA), giriş koruması ve yumuşak kilit, CAPTCHA (Cloudflare Turnstile, hCaptcha, kendi barındırılan proof-of-work), risk değerlendirmesi ve yeni cihaz bildirimi, güvenlik başlıkları, sıkı CORS, `Host` doğrulama, `return_to` doğrulama ve SSRF korumalı giden HTTP istemcisi.

## Sahip olunan gereksinimler

| Kimlik | Nerede | Başlıca testler |
|--------|--------|-----------------|
| PRT-01 | `rate_limit::{MemoryRateLimiter, PostgresRateLimiter, RedisRateLimiter}`, `rate_limit::gcra` | `prt_01_postgres_limiter_is_race_safe`, `prt_01_redis_limiter_is_race_safe`, `prt_01_never_admits_more_than_burst_plus_rate` (proptest) |
| PRT-02 | `RateLimitKey` boyutları (core), `KeyHasher`, `login::LoginProtection`, `rate_limit::http_rate_limit` | `prt_02_captcha_is_required_after_identifier_failures`, `prt_02_concurrent_attempts_cannot_outrun_the_failure_counters`, `prt_02_postgres_stores_only_keyed_hashes`, `prt_02_ipv6_clients_share_their_slash_64_budget` |
| PRT-03 | `login::LoginProtection` (yumuşak kilit) | `prt_03_soft_lock_blocks_only_untrusted_password_attempts`, `prt_03_lock_response_does_not_reveal_account_existence` |
| PRT-04 | `RateLimitDecision::retry_after` → `429` + `Retry-After` | `prt_04_http_layer_answers_429_with_retry_after`, `prt_04_retry_after_is_exact` |
| PRT-05 | `captcha::{SiteVerifyCaptcha, ProofOfWorkCaptcha, CaptchaService}`, `GET /v1/captcha/challenge` | `prt_05_pow_concurrent_double_spend_passes_once`, `prt_05_policy_modes_always_risk_based_never`, `prt_05_turnstile_through_the_ssrf_safe_client` |
| PRT-07 | `web::security_headers` | `prt_07_security_headers_have_the_specified_values` |
| PRT-08 | `web::cors` | `prt_08_other_origins_are_never_reflected_or_wildcarded`, `prt_08_preflight_is_strict_and_cache_bounded` |
| PRT-09 | `web::validate_host` | `prt_09_host_matching_is_exact_and_strict`, `prt_09_host_poisoning_is_stopped_before_routing` |
| PRT-10 | `web::RedirectValidator`, `fuzz/fuzz_targets/return_to.rs` | `prt_10_open_redirect_tricks_are_rejected`, `prt_10_accepted_targets_never_leave_the_allow_list` (proptest) |
| PRT-12 | `outbound::SsrfSafeHttpClient`, `outbound::ip` | `prt_12_connection_is_pinned_to_the_vetted_resolution`, `prt_12_embedded_ipv4_forms_inherit_the_ipv4_class` (proptest) |
| RSK-01 | `risk::DefaultRiskEvaluator` (`RiskEvaluator` portu) | `rsk_01_known_context_is_low_risk_and_input_comes_from_the_request` |
| RSK-02 | yeni cihaz / ağ (/24, /48), hata hızı, TOR/proxy listesi, imkânsız seyahat (yalnızca `GeoIpLookup` ile) | `rsk_02_new_device_new_network_and_failures_raise_the_level`, `rsk_02_impossible_travel_requires_a_geoip_provider` |
| RSK-03 | `risk::decide`, `RiskAlerts::on_blocked_login` | `rsk_03_policy_mapping_is_configurable`, `rsk_03_blocked_login_is_audited_and_notified_without_mail_bombing` |
| RSK-04 | `RiskAlerts::on_successful_login` + `NotMeTokenIssuer` | `rsk_04_new_device_login_sends_notification_with_not_me_token`, `rsk_04_alert_and_device_record_commit_together`, `aud_03_new_device_audit_metadata_holds_no_free_text` |
| RSK-05 | `risk::MmdbGeoIp` (`GeoIpLookup` uygulaması, MaxMind DB okuyucu; K-98) | `rsk_05_mmdb_lookup_returns_only_a_coarse_location`, `rsk_05_unknown_private_and_reserved_addresses_have_no_location`, `rsk_05_reload_swaps_a_changed_file_and_keeps_the_old_one_on_failure`, `rsk_05_impossible_travel_through_the_mmdb_reader`, `rsk_05_login_from_a_private_address_keeps_the_last_public_fix` |

DOC-03 (`docs/security/`) dokümantasyon aşamasında üretilecek; bu crate'in güvenlik notları aşağıdadır. PRT-06 (istemci IP'si) `authn-core`'da, PRT-11 (gövde/zaman aşımı/eşzamanlılık) `authn-server`'dadır.

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. Başka bir modüle ihtiyaç duyulan yerde ya core portu (`Notifier`, `AuditSink`, `HttpClient`, `GeoIpLookup`, `Clock`) ya da bu crate'te tanımlı küçük bir trait (`NotMeTokenIssuer`) kullanılır. Yeni harici crate eklenmedi; yalnızca workspace'te zaten bulunan `utoipa`, `base64`, `unicode-normalization` bağlandı, kullanılmayan `governor`, `tower`, `tower-http`, `rustls`, `secrecy`, `subtle` çıkarıldı.

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `KeyHasher::new(&KeyRing)` | Rate limit anahtarları (amaç `RateLimitKey`) ve cihaz kimlikleri (amaç `KnownDevice`, CRY-11; wave 1, K-21) için HMAC, kullanım başına ayrıca ayrı etiket. Ham e-posta/IP/cihaz kimliği hiçbir yerde saklanmaz. **Geçiş etkisi:** eski anahtarla yazılmış `known_devices` satırları artık eşleşmez; her hatırlanan cihaz bir sonraki girişte bir kez "yeni cihaz" sayılır (risk sinyali / `new_device_login` bildirimi) ve yeni anahtarla yeniden öğrenilir — başka etkisi yoktur (`cry_11_device_hashes_use_the_known_device_purpose_key`) |
| `rate_limit::build_rate_limiter(&RateLimitConfig, PgPool, Arc<dyn Clock>, KeyHasher) -> Result<Arc<dyn RateLimiter>>` | Yapılandırılan arka uç (`redis` seçilip feature yoksa başlangıçta hata) |
| `MemoryRateLimiter`, `PostgresRateLimiter` (`purge_expired`), `RedisRateLimiter` (`connect`, `quit`; feature `redis`) | Aynı GCRA aritmetiği (`rate_limit::gcra`), enjekte edilen saat. Çok anahtarlı port metotları (K-128): `check_chain` (sıralı adımlar; reddi zinciri bitiren adımdan sonrası çalışmaz, hiçbir şey tüketmez), `peek_many`, `reset_many` — PostgreSQL'de tek ifade (adım başına aynı koşullu UPSERT, veri değiştiren CTE), Redis'te eşzamanlı gönderim (Cluster uyumlu), bellekte tek tek çağrı. `LoginProtection::check_attempt` bir denemenin dört sınır adımını tek zincirde çalıştırır; soft-lock bütçesi yalnızca CAPTCHA kapısı kesin geçecekse zincirdedir. Testler: `prt_01_k_128_*`, `prt_02_k_128_*`, `prt_03_k_128_*` |
| `rate_limit::{HttpRateLimit, http_rate_limit}` | IP başına kaba HTTP limiti (`/health/` muaf; limiter hatasında açık başarısızlık, `fail_open(false)` ile kapatılabilir) |
| `login::{LoginProtection, LoginAttempt}` | `check_attempt`, `record_failure`, `record_success`, `unlock`, `soft_lock_remaining`, `locked_until`, `purge_expired` |
| `captcha::{CaptchaService, build_captcha_verifier, SiteVerifyCaptcha, ProofOfWorkCaptcha, DisabledCaptcha, solve}` | `CaptchaService::{enforce, is_required, challenge, endpoint_challenge, with_endpoint_actions}` |
| `risk::{DefaultRiskEvaluator, decide, RiskResponse, RiskAlerts, NotMeTokenIssuer, AnonymizingNetworks, RiskStore}` | RSK-01…04 |
| `web::{HostValidation, validate_host, SecurityHeaders, security_headers, CorsPolicy, cors, RedirectValidator, RedirectTarget}` | PRT-07…10 |
| `outbound::{SsrfSafeHttpClient, validate_user_supplied_url, classify, is_public, HostResolver, SystemResolver, StaticResolver}` | PRT-12 (`HttpClient` portu) |
| `router::<S>()`, `ProtectApi` | `GET /v1/captcha/challenge` ve OpenAPI belgesi |

## Endpoint'ler

| Yöntem | Yol | Açıklama |
|--------|-----|----------|
| `GET` | `/v1/captcha/challenge?action=<eylem>` | Eylem için CAPTCHA görevi: `{"type":"none"}`, `{"type":"widget","provider","site_key"}` veya `{"type":"proof_of_work","challenge","difficulty","expires_at"}`. IP başına rate limit (`captcha.challenge_per_ip`), yalnızca bilinen eylemler (`login`, `register`, `password_reset`, `magic_link`, `login_code`, `email_verification`, `phone_verification`), `Cache-Control: no-store` |

Proof-of-work yanıtı: `SHA-256(challenge ":" solution)` en az `difficulty` sıfır bitle başlayacak şekilde 1–64 karakterlik `[A-Za-z0-9_-]` bir `solution` bulunur ve CAPTCHA yanıtı olarak `challenge:solution` gönderilir (`captcha::solve` referans çözücüdür).

## Hata kodları (`authn_core::error::codes::protect`)

`captcha_required` (403, `details.challenge` içerir), `captcha_failed` (403), `login_temporarily_blocked` (429 + `Retry-After`), `suspicious_login_blocked` (403), `host_not_allowed` (421), `cors_origin_not_allowed` (403), `invalid_redirect` (400), `outbound_destination_not_allowed` (422). Ortak: `rate_limited` (429 + `Retry-After`), `service_unavailable`.

## Konfigürasyon (`[protect]`, `crates/authn-core/src/config/protect.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `allowed_hosts` | `[]` → `public_base_url` host'u | `host` veya `host:port`; portsuz giriş 80/443'ü de kabul eder |
| `redirect_allow_list` | `[]` | Bayt bayt tam eşleşme; ASCII, parça (fragment)/kimlik bilgisi/joker/boşluk/ters bölü yok |
| `rate_limit.backend` | `postgres` | `memory` üretimde reddedilir; `redis` için `redis` feature'ı ve `redis_url` (`redis://`/`rediss://`) |
| `rate_limit.login_per_account_captcha` | 10 / 15 dk | Tanımlayıcı başına başarısı kanıtlanmamış şifre denemesi → CAPTCHA |
| `rate_limit.login_per_account_soft_lock` | 50 / 1 sa | Tanımlayıcı başına başarısı kanıtlanmamış şifre denemesi → yumuşak kilit |
| `rate_limit.login_per_ip` | 100 / 15 dk | Tüm giriş yöntemleri |
| `rate_limit.soft_lock_duration` | `1h` | 1 dk – 1 gün |
| `rate_limit.requests_per_ip` | 600 / 1 dk | HTTP katmanı (yeni) |
| `captcha.provider` | `disabled` | `turnstile`, `hcaptcha` (site/secret anahtarı zorunlu), `proof_of_work` |
| `captcha.login_policy` | `risk_based` | `always` (sağlayıcı zorunlu) / `risk_based` / `never` |
| `captcha.verify_url` | — | Yalnızca test |
| `captcha.pow_difficulty` / `pow_ttl` | 18 / `5m` | 8–32 bit; 30 sn – 30 dk |
| `captcha.fail_open` | `false` | Sağlayıcı erişilemezse |
| `captcha.challenge_per_ip` | 30 / 1 dk | (yeni) |
| `security_headers.*` | HSTS 2 yıl + `includeSubDomains`, preload kapalı | `permissions_policy` geçerli başlık değeri olmalı |
| `cors.allowed_origins` / `max_age` | `[]` / `10m` | Boş = CORS kapalı; en fazla 2 sa |
| `risk.enabled`, `anonymizing_networks_file`, `failure_window`, `failure_threshold`, `medium_action`, `high_action` | `true`, —, `1h`, 5, `step_up`, `block` | Dosya bozuksa başlangıçta hata (satır numarası, içerik loglanmaz) |
| `risk.impossible_travel_speed_kmh` | 1000 | Yalnızca `GeoIpLookup` takılıysa (yeni) |
| `risk.geoip_database` | — | MaxMind DB (`.mmdb`) yolu (RSK-05). Ayarlıysa sunucu `MmdbGeoIp`'i takar; okunamaz, 512 MiB'tan büyük ya da doğrulamadan geçmeyen dosyada başlangıç başarısız |
| `risk.geoip_reload_interval` | `1h` | 1 dk – 7 gün; değişen dosya bu aralıkla yeniden yüklenir |
| `outbound.timeout` / `connect_timeout` | `10s` / `5s` | `connect_timeout` (yeni) ≤ `timeout` |
| `outbound.max_response_bytes` | 1 MiB | |
| `outbound.allow_private_networks` | `false` | **Yalnızca test/geliştirme**: özel ağlar *ve* düz `http`; üretimde reddedilir |

## Tasarım ve güvenlik notları

### Rate limit (PRT-01/02/04)
- **GCRA**, mikro saniye hassasiyetinde, doymalı tamsayı aritmetiği. Yayılım aralığı `T = ⌈period/limit⌉` (yukarı yuvarlama: patlama tam olarak `limit`, kalıcı hız asla politikadan hızlı değil). Ret kararı, isteğin kabul edileceği ana kadar geçen kesin süreyi (`Retry-After`) taşır; retler kota tüketmez.
- **PostgreSQL:** tek `INSERT … ON CONFLICT (key_hash) DO UPDATE … RETURNING tat, allowed` ifadesi; satır kilidi eşzamanlı çağrıları serileştirir (60 eşzamanlı istekte tam 10 kabul testi). Tablo UNLOGGED; çökmede limitler kısa süre gevşer. `purge_expired` toplu siler.
- **Redis:** tek Lua betiği (`EVAL`) — atomik; anahtar `authn:rl:<hex hmac>`, TTL kova boşalana kadar. Komut zaman aşımı 2 sn; Redis erişilemezse `service_unavailable` (sessizce sınırsız değil).
- **Bellek:** 16 parçaya bölünmüş, periyodik süpürme, parça başına üst sınır; dolarsa **yeni** anahtarlar reddedilir (bellek tükenmesine karşı kapalı başarısızlık).
- Tüm arka uçlar yalnızca anahtarlı hash saklar; IPv6 /64'e toplanır (core).
- `governor` kullanılmadı: kendi saatini kullanır (`FakeClock` ile sürülemez, ARC-04) ve kota limiter başına sabittir; burada politika çağrı başına gelir. Üç arka uç aynı saf GCRA fonksiyonunu paylaşır (`prt_04_postgres_and_memory_backends_agree`).

### Giriş koruması ve yumuşak kilit (PRT-02/03)
- Tüm sayaçlar ve kilit **gönderilen tanımlayıcıya** (normalize e-posta) bağlıdır; var olmayan hesaplar da aynı şekilde sayılır, CAPTCHA'ya yükseltilir ve kilitlenir. Kilit yanıtı (kod, durum, `Retry-After`, gövde) ve iş miktarı (bilinen cihaz sorgusu yer tutucu kimlikle de çalışır) iki durumda aynıdır; `prt_03_lock_response_does_not_reveal_account_existence` istatistiksel zamanlama karşılaştırması içerir.
- Kilit **hesabı kapatmaz**: yalnızca güvenilmeyen cihazdan gelen **şifre** denemelerini reddeder. Passkey, sihirli bağlantı/kod, MFA-09 güvenilir cihaz token'ı (session doğrular) ve kullanıcının bilinen cihazı (`known_devices`) geçer; şifre sıfırlama bu servisi hiç çağırmaz. Başka kullanıcının bilinen cihazı işe yaramaz (hash kullanıcıya bağlı).
- Bilinen **ağ** kilidi aşmaz (bilinçli olarak spesifikasyondan daha sıkı): CGNAT/ofis ağları paylaşılır.
- **Bütçeler doğrulamadan önce, atomik olarak tüketilir:** `check_attempt` tanımlayıcının CAPTCHA bütçesinden bir birimi (tek `check` = kontrol + tüketim) ve CAPTCHA kapısı geçildikten sonra yumuşak kilit bütçesinden bir birimi ayırır; `record_success` bunları geri verir. Her deneme başarılı olduğu kanıtlanana kadar başarısız sayılır. Böylece aynı anda uçuştaki denemeler (Argon2 semaforunda bekleyen ya da çok sayıda IP'den paralel gönderilen tahminler) sayaçları geçemez: en fazla `login_per_account_captcha.limit` deneme CAPTCHA'sız, en fazla `login_per_account_soft_lock.limit` deneme kilitten önce doğrulamaya ulaşır. Yanlış/eksik CAPTCHA kilit bütçesini tüketmez (kilidi tetiklemek saldırgana CAPTCHA'lara mal olur). Yumuşak kilit bütçesini tüketen deneme kilidi devreye sokar ve (güvenilmeyen cihazda) `login_temporarily_blocked` alır.
- `record_failure` yalnızca risk hız sayaçlarını (kullanıcı ve IP başına, RSK-02) artırır; tanımlayıcı eşleşmeyen hesaplarda kullanıcı sayacının yerine atılabilir bir anahtar kullanılır — başarısız giriş yolu var olan ve olmayan hesaplar için aynı işi yapar.
- Başarılı girişte CAPTCHA/kilit bütçeleri sıfırlanır; etkin kilit süresi dolana veya admin `unlock` yapana kadar sürer; risk hız sayaçları korunur (çok hatadan sonra başarı da bir sinyaldir).
- Saldırganın tetiklediği olaylar (rate limit, CAPTCHA hatası) pencere başına bir kez audit'lenir — her reddedilen istek kalıcı bir yazmaya dönüşmez (amplifikasyon yok). Kilit devreye girişi bir kez, `login_soft_locks` kaydı (yalnızca var olan hesaplar için, admin görünümü) ve audit aynı transaction'da.

### CAPTCHA (PRT-05)
- Turnstile/hCaptcha: `siteverify` çağrısı `HttpClient` portuyla (trusted hedef, zaman aşımı ve 16 KiB yanıt sınırı). Token'lar sağlayıcıda tek kullanımlık; Turnstile'ın döndürdüğü `action` korunan eylemle eşleşmezse ret; hCaptcha'ya `sitekey` gönderilir. 4096 bayttan uzun/geçersiz token'lar dış çağrı yapılmadan reddedilir; gizli anahtar `Debug`'da görünmez. Yalnızca gerçek kesinti (`Unavailable` → `fail_open`'a göre): ağ hatası/zaman aşımı, 5xx, 429, 408 ve gövdesi karar olmayan 2xx. Sağlayıcının **cevap verdiği** her durum — herhangi bir durum kodunda `success: false` ya da diğer 4xx/3xx — `Failed`'dır; aksi halde sağlayıcıyı 4xx döndürmeye zorlayan bir token `fail_open = true` iken CAPTCHA'yı atlatırdı. Hatalı/eksik gizli anahtar (`invalid-input-secret`) yapılandırma kesintisi sayılır.
- Proof-of-work: görev **durumsuz** üretilir (`base64url(payload).base64url(HMAC)`; id, nonce, zorluk, zamanlar, eylem). Doğrulama sırası: boyut/karakter seti → kanonik kodlama → sabit zamanlı HMAC → eylem → süre → iş → **tek kullanım** (`captcha_pow_challenges`'a `INSERT … ON CONFLICT DO NOTHING`; eşzamanlı 16 denemede tam bir başarı). Görev uç noktasını spamlamak veritabanı yazması üretmez. Tüketilmiş görev kayıtları süreleri dolduktan `captcha::PURGE_GRACE` (15 dk) sonra silinir: süre her instance'ın kendi saatiyle denetlendiği için kayıt, saati geride kalan bir instance görevi hâlâ geçerli sayarken silinirse aynı çözüm tekrar kullanılabilirdi.
- Sağlayıcı `disabled` iken CAPTCHA hiçbir zaman zorunlu tutulmaz (`always` + `disabled` konfigürasyonda reddedilir).

### Risk (RSK-01…05)
- Puan: yeni cihaz 1, yeni ağ 1, son hatalar 1, anonimleştirici ağ 2, imkânsız seyahat 3; 0 → low, 1–2 → medium, ≥3 → high. Geçmişi olmayan kullanıcıda (kayıttan sonraki ilk giriş) yenilik sinyali üretilmez. Passkey girişlerinde yenilik ve hata sinyalleri sayılmaz.
- İmkânsız seyahat yalnızca bir `GeoIpLookup` takılırsa; doğruluk yarıçapları mesafeden düşülür, süre en az 1 dk kabul edilir. GeoIP hatası girişi düşürmez (sinyal atlanır, loglanır).
### GeoIP (RSK-05, K-98) — `risk::MmdbGeoIp`
- **Veritabanı gömülmez.** İşletmeci City düzeyinde bir MaxMind DB dosyası sağlar (`protect.risk.geoip_database`): MaxMind GeoLite2-City / GeoIP2-City, DB-IP City Lite, IPinfo vb. **Okuyucu crate'i** `maxminddb` ISC lisanslıdır (izin verici, `cargo deny` geçer); **verinin lisansı ayrıdır ve bu projenin sorumluluğunda değildir:** GeoLite2 MaxMind'ın GeoLite EULA'sıyla (hesap ve lisans anahtarı; EULA'daki atıf ve eski sürümleri güncelleme/silme yükümlülükleri), DB-IP Lite CC BY 4.0 ile (atıf zorunlu), ticari GeoIP2 ise ücretli lisansla gelir. Bazıları izin verici değildir; seçmeden önce şartları okuyun. Depoda üçüncü taraf GeoIP verisi **yoktur**: test fikstürleri `authn_testkit::mmdb` ile deterministik olarak üretilir.
- **Dosya bellek içine okunur** (`mmap` yok: `memmap2` `unsafe` gerektirir; `maxminddb` varsayılan özellikleri kapalı). Açılışta `Reader::verify` tüm arama ağacını ve veri bölümünü bir kez dolaşır: kesik/bozuk dosya başlangıçta reddedilir, aramalar sırasında değil.
- **Yeniden yükleme: periyodik, değişince.** Sunucu her `geoip_reload_interval`'da dosyanın değişme zamanı/boyutuna bakar; değiştiyse yeni dosyayı okuyup doğrular ve **atomik** olarak değiştirir. Bozuk ya da silinmiş yeni dosya eskisini korur (hata loglanır). Güncelleyiciler dosyayı yerinde yazmak yerine `rename` ile değiştirmelidir (yarım dosya zaten reddedilir, ama gereksiz hata logu üretir).
- **Konum yok = sinyal yok:** özel (RFC 1918), loopback, CGNAT, link-local, belge, ayrılmış, ULA vb. adresler (`outbound::is_public` sınıflandırıcısı, IPv4-eşlemeli IPv6 dahil) veritabanına **sorulmaz**; bilinmeyen adres, koordinatsız (ülke düzeyi) kayıt ve IPv4-only veritabanında IPv6 da konumsuzdur. Böyle bir giriş imkânsız seyahat üretmez ve son bilinen konumu silmez (`COALESCE`; VPN'den sonra gerçek bir sıçrama yine yakalanır).
- **Veri en aza indirme (KVKK/GDPR):** sonuçta yalnızca ülke kodu, İngilizce şehir adı (64 karakter, kontrol karakterleri atılır) ve **0,1°'ye yuvarlanmış** koordinatlar (≈ 11 km; şehir veritabanlarından daha kaba) bulunur. Posta kodu, bölge, ISS/ASN, saat dilimi çözülmez. Doğruluk yarıçapına yuvarlama payı (8 km) eklenir; böylece seyahat testi temkinli kalır. `known_devices.last_latitude/last_longitude` yalnızca bu kaba değerleri tutar.
- GeoIP hatası (bozuk kayıt) girişi düşürmez: sinyal atlanır, loglanır.

- `RiskAlerts::on_successful_login`: cihaz/ağ kaydı, "bu ben değilim" token'ı (session'ın `NotMeTokenIssuer`'ı), `NewDeviceLogin` bildirimi ve `risk.new_device_login` audit'i **tek transaction**'da (biri başarısızsa hiçbiri). Bildirimde IP maskeli, cihaz adı woothee'nin sabit sözlüğünden. Audit olayının metadata'sında cihaz açıklaması ("Firefox on Linux") **yok** (wave 6B): AUD-03 serbest metni reddettiği için her yeni cihaz girişi bir sansür uyarısı loglanıyor ve değer `[REDACTED]` saklanıyordu. Açıklama user agent'tan türetilir; user agent kişisel veridir ve yalnızca silinebilir `audit_event_pii` tablosunda tutulur (`with_context`, AUD-05), değişmez zincire girmez. Metadata yalnızca `new_network` taşır.
- `on_blocked_login`: her blok audit'lenir; kullanıcıya bildirim 15 dk'da en fazla bir (şifreyi bilen saldırgan kurbanı e-postaya boğamaz). `suspicious_login_blocked` yalnızca kimlik bilgisi doğrulandıktan **sonra** döner (SES-01).

### HTTP sertleştirme (PRT-07…10)
- Başlıklar spesifikasyondaki değerlerle; `Cache-Control: no-store` her yanıtta varsayılan (handler kendi değerini koyabilir, ör. JWKS). CSP ve CORP handler tarafından değiştirilebilir; HSTS, `nosniff`, `Referrer-Policy`, COOP, `Permissions-Policy` her zaman yazılır.
- CORS: yalnızca izinli origin'ler (ASCII serileştirmesine normalize), bayt bayt eşleşme; asla `*`, `null` veya keyfi yansıtma; kimlik bilgisi yalnızca izinli origin'le; handler'ın koyduğu `Access-Control-*` başlıkları silinir; birden fazla `Origin` başlığı = CORS yok; preflight burada cevaplanır, yöntem/başlık listeleri sabit, `Max-Age` sınırlı; her yanıtta `Vary: Origin`.
- Host: `Host` ve istek hedefindeki authority (HTTP/2 `:authority`, mutlak biçim) ayrı ayrı denetlenir; birden fazla `Host` veya hiç olmaması reddedilir; katı ASCII ayrıştırma (userinfo, yüzde kodlama, IDNA/sayısal IP normalizasyonu yok); `/health/` muaf.
- `return_to`: izin listesiyle bayt bayt eşleşme **veya** güvenli göreli yol. Ham girdide yazdırılabilir ASCII dışı her şey, `\` ve hatalı `%` kaçışı reddedilir; yol 4 katmana kadar çözülür ve her katman UTF-8, kontrol karakteri/ters bölü içermeyen, `//` ile başlamayan, NFKC altında URL söz dizimine dönüşen Unicode içermeyen (`／`, `＼`) ve WHATWG çözümlemesinden sonra (`/..//evil`) aynı origin'de kalan bir yol olmalıdır. Normalize edilmiş göreli biçim döner. Fuzz hedefi (`return_to`) ve proptest değişmezleri doğrular.

### SSRF korumalı HTTP (PRT-12)
- İki reqwest istemcisi: **trusted** (operatör yapılandırması: HIBP, OIDC, CAPTCHA, SMS) ve **user-supplied** (webhook vb.). Ortak: proxy yok (proxy adı kendisi çözer ve sabitlemeyi atlatırdı), otomatik yönlendirme yok (3xx çağırana döner), otomatik açma yok, bağlantı + toplam zaman aşımı (istek başına üst sınır 2 dk), yanıt gövdesi artımlı okunur ve sınır aşılınca kesilir (`Content-Length` de denetlenir), çağıranın `Host` başlığı atılır, URL (sorgu dizisi) asla loglanmaz/hata metnine girmez.
- User-supplied: yalnızca `https`, kimlik bilgisi yok, port 0 yok. DNS'i **biz** çözeriz (`SystemResolver` = hickory + sistem yapılandırması; okunamazsa getaddrinfo), dönen adreslerin **hepsi** genel olmalıdır (biri bile özelse tamamı reddedilir), reqwest tam olarak bu adreslere bağlanır — bağlantı başına tek çözümleme, kontrol ile bağlantı arasında ikinci çözümleme yok (DNS rebinding). IP sabitleri çözücüye hiç gitmez; önceden sınıflandırılır (`2130706433`, `0x7f.1`, `[::ffff:127.0.0.1]` dahil).
- Sınıflandırıcı: IPv4 tüm IANA özel blokları (0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4, 255.255.255.255) + bulut metadata uç noktaları (genel alandaki Azure `168.63.129.16` dahil). IPv6 **izin listesi**: yalnızca `2000::/3` ve içindeki özel bloklar hariç (Teredo, 2001::/23, 2001:db8::/32, 3fff::/20); IPv4-mapped, NAT64 (`64:ff9b::/96`) ve 6to4 gömülü IPv4'ün sınıfını alır; IPv4-compatible, ULA (`fd00:ec2::254` dahil), link-local, site-local, multicast, `64:ff9b:1::/48`, `100::/64` reddedilir. Tablo testleri + proptest.

## Güvenlik notları

### Güvenlik incelemesi (2026-11-01) — düzeltilen bulgular

| Önem | Bulgu | Düzeltme | Regresyon testi |
|------|-------|----------|-----------------|
| Yüksek | Giriş korumasında kontrol-sonra-eylem (TOCTOU): tanımlayıcı sayaçları doğrulamadan önce yalnızca `peek` ediliyor, doğrulamadan **sonra** `record_failure`'da sayılıyordu. Aynı anda uçuştaki N tahminin hepsi kontrolü geçiyordu → N şifre doğrulaması CAPTCHA'sız ve yumuşak kilitsiz (eşik 10/50 yerine yalnızca IP limiti ve eşzamanlılık sınırı). | `check_attempt` bütçeleri atomik `check` ile tüketir, `record_success` geri verir; kilit, bütçeyi tüketen denemede devreye girer. | `prt_02_concurrent_attempts_cannot_outrun_the_failure_counters` |
| Orta | CAPTCHA `siteverify`: 2xx olmayan durumla gelen kesin ret (`success: false`) ve diğer 4xx yanıtları `Unavailable` sayılıyordu; `fail_open = true` iken bu **geçti** demek (sağlayıcıyı 4xx döndürmeye zorlayan herhangi bir token ile CAPTCHA atlatma). | Yalnızca gerçek kesintiler (`5xx`, `429`, `408`, ağ hatası, karar olmayan 2xx) `Unavailable`; cevap veren sağlayıcı = `Failed`. | `prt_05_provider_rejections_on_error_statuses_never_count_as_outage` |
| Düşük | Başarısız giriş yolunda zamanlama farkı: `record_failure` var olan hesaplar için fazladan bir limiter yazması (kullanıcı hız sayacı) yapıyordu (hesap varlığı sızıntısı, SES-01). | Hesap yoksa atılabilir bir anahtarla aynı iş yapılır. | `prt_03_failure_path_does_the_same_work_for_unknown_accounts` |
| Düşük | Proof-of-work tek kullanım kaydı, süresi **bir** instance'ın saatine göre dolduğu anda silinebiliyordu; saati geride kalan instance aynı çözümü yeniden kabul ederdi (tekrar oynatma). | Temizlik `PURGE_GRACE` (15 dk) sonra. | `prt_05_pow_purge_does_not_reopen_replays_across_clock_skew` |
| Düşük | `LoginAttempt` ve `DeviceObservation`'ın türetilmiş `Debug` çıktısı ham e-postayı, CAPTCHA token'ını ve cihaz kimliğini (bilinen cihaz = yumuşak kilit atlatma) içeriyordu. | Elle yazılmış `Debug`: e-posta/IP maskeli, token ve cihaz kimliği `[REDACTED]`. | `prt_03_login_attempt_debug_masks_personal_data_and_tokens`, `rsk_02_device_observation_debug_redacts_the_device_id` |

### Kabul edilen riskler

- **Yumuşak kilit ile hedefli engelleme:** kilit tanımlayıcıya bağlı olduğundan saldırgan (CAPTCHA'ları çözerek) bir kurbanın bilinmeyen cihazlardan şifreli girişini `soft_lock_duration` boyunca engelleyebilir. PRT-03'ün tasarımı budur: hesap kapanmaz; passkey, güvenilir/bilinen cihaz ve şifre sıfırlama çalışır. Kilit yanıtı hesap varlığını sızdırmaz.
- **Risk sinyalinin saldırganca yükseltilmesi:** "son hatalar" sinyali kurbanın e-postasıyla yapılan başarısız denemelerle artırılabilir; kurban aynı anda yeni cihaz **ve** yeni ağdan girerse seviye `high` olur ve (varsayılan `high_action = "block"`) giriş engellenir + bildirim gider. Bilinen cihazdan/ağdan girişte en fazla `medium` (adım yükseltme). İstenmiyorsa `risk.high_action = "step_up"`.
- **Kilit devreye girişinde küçük iş farkı:** var olan hesapta `login_soft_locks` satırı ve audit aynı transaction'da, olmayan hesapta yalnızca audit yazılır. Bu, tanımlayıcı başına kilit eşiğinde (varsayılan 50 başarısız deneme) bir kez olur; ölçmek için kilidin kendisini tetiklemek gerekir.
- **HTTP katmanı açık başarısız:** `http_rate_limit` limiter hatasında isteği geçirir (kaba taşkın koruması); güvenlikle ilgili eylem limitleri (giriş, CAPTCHA, sıfırlama) kapalı başarısız olur. `HttpRateLimit::fail_open(false)` ile değiştirilebilir.
- **Bellek limiter'ı dolunca yeni anahtarları reddeder** (bellek sınırı). HTTP katmanında bir anahtar en fazla bir yayılım aralığı (600/dk → 100 ms) yaşar; doldurmak bu süre içinde 1M'dan fazla farklı IP/64 gerektirir.
- **Proof-of-work bot kanıtı değil, maliyettir:** görev IP'ye/tanımlayıcıya bağlı değildir; çözüm başka yerde (GPU, üçüncü taraf) üretilebilir. Tek kullanımlık, eyleme bağlı ve süreli olduğu için her deneme bir çözüme mal olur; daha güçlü koruma için Turnstile/hCaptcha.
- **CAPTCHA sağlayıcı alanları:** `hostname` doğrulanmıyor; Turnstile `action` yalnızca sağlayıcı boş olmayan bir değer döndürdüğünde karşılaştırılır (widget'ta `data-action` ayarlanmalı). Site anahtarı sağlayıcı tarafında alan adlarına bağlıdır.
- **`redirect_allow_list` operatöre güvenilir:** girişler bayt bayt eşleşir; konfigürasyon doğrulaması `javascript:`/`data:` gibi şemaları ayrıca yasaklamaz — listeye yalnızca gerçek geri dönüş adresleri yazılmalıdır.
- **CORS kapalıyken** (varsayılan) handler'ların koyduğu `Access-Control-*` başlıkları silinmez; workspace'te bunu yapan handler yoktur.
- **Bilinen cihaz kimliği çalınırsa** yumuşak kilit o hesap için aşılabilir (şifre yine gerekir); güçlü kanıt MFA-09 güvenilir cihaz token'ıdır.

### K-58 değerlendirmesi (2026-11-05)

Yukarıdaki maddeler yeniden değerlendirildi. Bu dalgada hiçbiri kod değişikliğiyle kapatılmadı. Kararlar:

- **Yumuşak kilitle hedefli engelleme:** PRT-03'ün tasarımıdır. Tanımlayıcıya bağlı olmayan bir kilit, hedefli parola denemesini durduramaz. Hesap kapanmaz: passkey, güvenilir/bilinen cihaz ve şifre sıfırlama çalışır. Gerekçeli kalır.
- **Risk sinyalinin saldırganca yükseltilmesi:** Sinyal olmasa saldırganın denemeleri görünmez olurdu. Etki, operatörün seçebileceği `high_action = "step_up"` ile sınırlanır. Gerekçeli kalır.
- **Kilit devreye girişinde küçük iş farkı:** Var olmayan hesaba satır yazmak, hesap tablosunu kirletir. Fark, eşik başına tek seferliktir ve ölçmek için kilidi tetiklemek gerekir. Gerekçeli kalır.
- **HTTP katmanının açık başarısız olması:** Limiter kesintisi tüm API'yi düşürmemelidir. Güvenlikle ilgili limitler kapalı başarısız olur. Gerekçeli kalır (yapılandırılabilir).
- **Bellek limiter'ının dolunca reddetmesi:** Sınırsız bellek DoS demektir. Üretimde bellek arka ucu reddedilir. Gerekçeli kalır.
- **Proof-of-work'ün bot kanıtı olmaması:** Kriptografik iş kanıtının doğası budur, imkânsız. Daha güçlü koruma için Turnstile/hCaptcha.
- ~~**CAPTCHA `hostname`**~~ — **kapatıldı (wave 4B denetimi):** `[protect.captcha] hostnames` ayarlıysa, sağlayıcının bildirdiği `hostname` bu listede olmalıdır (büyük/küçük harf duyarsız). `hostname` yoksa ya da başka bir siteyse sonuç `Failed` olur. **Üretimde Turnstile/hCaptcha için liste zorunludur** (yapılandırma doğrulaması). Testler: `prt_05_k58_tokens_solved_on_another_site_are_rejected` (düzeltmeden önce başka sitede çözülen token geçiyordu), `prt_05_k58_captcha_hostnames_are_host_names`, `prt_05_k58_captcha_hostnames_are_required_in_production`. `action` denetimi zaten vardı.
- ~~**`redirect_allow_list` şemaları**~~ — **kapatıldı (wave 4B denetimi):** `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:` ve `filesystem:` yapılandırma doğrulamasında reddedilir (`authn_core::config::protect::is_forbidden_redirect_scheme`). `RedirectValidator` da bu şemaları derinlemesine savunma olarak reddeder: listeye girmiş olsalar bile hedef olamazlar. Testler: `prt_10_k58_redirect_allow_list_rejects_script_and_document_schemes`, `prt_10_k58_script_and_document_schemes_are_never_redirect_targets` (ikisi de düzeltmeden önce kırmızıydı).
- **CORS kapalıyken handler başlıkları:** Workspace'te bu başlıkları koyan handler yoktur. Gerekçeli kalır.
- **Bilinen cihaz kimliği çalınırsa:** Şifre yine gerekir. Güçlü kanıt MFA-09 güvenilir cihaz token'ıdır. Gerekçeli kalır.

## authn-server'ın bağlaması gerekenler

```rust,ignore
// Servisler (AppState inşası)
let keys = crypto.keys.clone();                                   // authn_crypto::CryptoServices
let hasher = authn_protect::KeyHasher::new(&keys)?;
let limiter = authn_protect::rate_limit::build_rate_limiter(&cfg.protect.rate_limit, pool.clone(), clock.clone(), hasher.clone()).await?;
let http: Arc<dyn HttpClient> = Arc::new(authn_protect::outbound::SsrfSafeHttpClient::new(&cfg.protect.outbound)?);
let verifier = authn_protect::captcha::build_captcha_verifier(&cfg.protect.captcha, http.clone(), pool.clone(), clock.clone(), &keys)?;
let captcha = authn_protect::CaptchaService::new(verifier, limiter.clone(), audit.clone(), clock.clone(), &cfg.protect.captcha);
// RSK-05: Some(Arc::new(MmdbGeoIp::open(path)?)) when protect.risk.geoip_database is set
let risk = authn_protect::DefaultRiskEvaluator::new(pool.clone(), hasher.clone(), limiter.clone(), &cfg.protect.risk, geoip /* Option<Arc<dyn GeoIpLookup>> */)?;
let alerts = authn_protect::RiskAlerts::new(risk.clone(), notifier.clone(), audit.clone(), limiter.clone(), clock.clone());
let login = authn_protect::LoginProtection::new(pool.clone(), clock.clone(), limiter.clone(), audit.clone(), captcha.clone(), risk.store().clone(), &cfg.protect);
let redirects = authn_protect::RedirectValidator::from_config(&cfg.protect, &cfg.server.public_base_url);

// Router: impl FromRef<AppState> for CaptchaService; .merge(authn_protect::router::<AppState>())
// OpenAPI: authn_protect::ProtectApi'yi openapi.rs'e nest edin.

// app.rs (7) yuvası — axum `.layer` içten dışa uygular; dıştan içe sıra:
//   validate_host → security_headers → cors → http_rate_limit
.layer(from_fn_with_state(HttpRateLimit::new(limiter.clone(), cfg.protect.rate_limit.requests_per_ip), http_rate_limit))
.layer(from_fn_with_state(CorsPolicy::from_config(&cfg.protect.cors)?, cors))          // is_enabled() false ise atlanabilir
.layer(from_fn_with_state(SecurityHeaders::from_config(&cfg.protect.security_headers)?, security_headers))
.layer(from_fn_with_state(HostValidation::from_config(&cfg.protect, &cfg.server.public_base_url)?, validate_host))
```

- Katmanlar `RequestContext`'e ihtiyaç duyar (rate limit) → authn-core request-context middleware'i dışta kalmalıdır. Çalışan örnek: `tests/web_stack.rs`.
- Arka plan işleri (OPS-06): `PostgresRateLimiter::purge_expired(batch)`, `ProofOfWorkCaptcha::purge_expired()`, `LoginProtection::purge_expired()`.
- `HttpRateLimit` için bellek arka ucu (instance başına kaba koruma) önerilir; böylece her istek veritabanına yazmaz. Eylem bazlı limitler (giriş, sıfırlama, kayıt) dağıtık arka ucu kullanmalıdır.
- `HostValidation` dıştaki katman olduğu için 421 yanıtları güvenlik başlıklarını taşımaz (yalnızca standart hata zarfı ve `no-store`); OPS-02 sırası korunmuştur.

## authn-session (Dalga B) için

- `NotMeTokenIssuer`'ı uygular (`one_time_tokens` amaç `not_me`, çağıranın transaction'ında); token tüketildiğinde tüm oturumları kapatıp şifre sıfırlamaya zorlar.
- Şifreli giriş akışı (SES-01): `LoginProtection::check_attempt` (kullanıcı aramasından sonra, şifre doğrulamasından önce; `LoginAttempt.user_id` bulunan hesap, `trusted_device` MFA-09 token doğrulaması; **her şifre denemesi için tam bir kez** — tanımlayıcı bütçelerini o anda tüketir) → başarısızlıkta `record_failure`, başarıda `record_success` (bütçeleri geri verir; çağrılmazsa deneme başarısız sayılır) → `RiskEvaluator::evaluate` → `authn_protect::risk::decide(&cfg.protect.risk, &assessment, mfa_enrolled)` → `Block` ise `RiskAlerts::on_blocked_login` (dönen hatayı gönderin), aksi halde oturum açıldıktan sonra `RiskAlerts::on_successful_login`.
- Passkey/sihirli bağlantı/kod girişlerinde de `check_attempt` çağrılabilir (yalnızca IP limiti uygulanır).
- `return_to`/`redirect_uri` için `RedirectValidator::validate`.
- authn-account (ACC-13): `CaptchaService::enforce("register", cfg.account.registration_captcha, risky, response, &ctx)`.
- authn-admin (ADM-03): `LoginProtection::unlock(user_id, normalized_email)`.
- authn-audit (AUD-07 webhook'ları): uç nokta kaydederken `outbound::validate_user_supplied_url`, teslimatta `OutboundTarget::UserSupplied`.

## Bilinen sınırlamalar / SHOULD notları

- Saat: GCRA zamanı enjekte edilen `Clock`'tan gelir; çoklu instance'ta saatler NTP ile senkron olmalıdır (sapma limitleri sapma kadar gevşetir/sıkılaştırır).
- Redis arka ucu Redis'in ayakta olmasına bağlıdır; erişilemezse eylem limitleri `service_unavailable` döner (bilinçli kapalı başarısızlık). HTTP katmanı varsayılan olarak açık başarısız olur.
- Bilinen cihaz kontrolü istemci cihaz kimliğine (`__Host-authn_device` çerezi / `x-device-id`) dayanır; kimlik çalınırsa yumuşak kilit o hesap için aşılabilir (şifre yine gerekir). Daha güçlü kanıt MFA-09 imzalı güvenilir cihaz token'ıdır.
- ~~Cihaz hash'i için ayrı bir `KeyPurpose` yok~~ — **kapatıldı (K-21):** `known_devices.device_hash` kendi `KeyPurpose::KnownDevice` alt anahtarını kullanır (`src/keys.rs`).
- ~~CAPTCHA sağlayıcılarının `hostname` alanı doğrulanmıyor~~ — **kapatıldı (K-58):** Turnstile/hCaptcha yanıtının `hostname`'i `protect.captcha.hostnames` listesine karşı denetlenir (`captcha/siteverify.rs`); liste production ve staging'de zorunludur. Turnstile `action` da doğrulanır.
- Anonimleştirici ağ listesi başlangıçta okunur; yenilemek için `DefaultRiskEvaluator::with_anonymizing_networks` ile yeni bir değerlendirici kurulmalı (otomatik yenileme yok).
- GeoIP veritabanının doğruluğu (özellikle mobil operatör ve VPN çıkışları) veri sağlayıcısına bağlıdır; yanlış konum yanlış imkânsız seyahat (yüksek risk → blok) üretebilir. Etki `high_action = "step_up"` ile yumuşatılabilir. Hız eşiği `impossible_travel_speed_kmh` (varsayılan 1000 km/sa) ve iki tarafın doğruluk yarıçapı mesafeden düşülerek yanlış pozitifler azaltılır.
- Kullanıcı tarafından verilen URL'lerde port kısıtı yok (adres sınıflandırması iç ağları zaten dışlar).

## Testler

- Birim + proptest (`src/**`): GCRA değişmezleri, IP sınıflandırıcı (tablo + proptest), yönlendirme doğrulayıcı (saldırı listesi + proptest), başlıklar, CORS, host, PoW yük biçimi, ağ listesi, coğrafya, konfigürasyon.
- Entegrasyon (`tests/`): `geoip.rs` (RSK-05: üretilen MMDB fikstürüyle kaba konum, özel/ayrılmış/bilinmeyen adres, yeniden yükleme ve bozuk dosya, gerçek değerlendiriciyle imkânsız seyahat), `rate_limit.rs` (PostgreSQL + Redis, eşzamanlılık), `outbound.rs` (wiremock: sabitleme, yönlendirme, boyut, zaman aşımı, engellenen hedefe hiç bağlantı yok), `captcha.rs` (PoW tek kullanım/eşzamanlı çift harcama/sahtecilik/saat sapmasında tekrar, uç nokta, Turnstile), `login.rs` (CAPTCHA yükseltme, eşzamanlı denemeler, yumuşak kilit, hesap varlığı sızıntısı + zamanlama + eşit iş), `risk.rs` (RSK-01…04), `web_stack.rs` (OPS-02 sırasında katmanlar).
- Fuzz: `fuzz/fuzz_targets/return_to.rs` (`cargo +nightly fuzz run return_to`).
- Redis testleri Redis'e (`REDIS_URL`, varsayılan `redis://127.0.0.1:6379`) erişemezse not düşerek atlanır.

## Komutlar

```bash
cargo test -p authn-protect --all-features
cargo clippy -p authn-protect --all-targets --all-features -- -D warnings
cargo fmt -p authn-protect
cargo +nightly fuzz run return_to -- -max_total_time=60
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
