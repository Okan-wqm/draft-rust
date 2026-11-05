# Konfigürasyon referansı (DOC-06)

Bu belge `rust-authentication`'ın **her** konfigürasyon anahtarını listeler. Kaynak: `crates/authn-core/src/config/*.rs` (her bölüm kendi dosyasında; alanların rustdoc'u, `Default` uygulamaları ve `validate` fonksiyonları). Yorumlu örnek dosya: [`config/example.toml`](../../config/example.toml) (geçerliliği `crates/authn-server/tests/example_config.rs` ile test edilir).

> Belge kodla birebir yazıldı (2026-11-05, `47c84a7`). Bir ayar eklenir veya kuralı değişirse bu tablo da güncellenmelidir.

## 1. Yükleme, öncelik ve biçimler

- **Kaynaklar:** `AppConfig::load(path)` önce TOML dosyasını (`--config <yol>` / `-c` veya `AUTHN_CONFIG` ortam değişkeni; verilmezse dosya okunmaz), sonra `AUTHN__` önekli ortam değişkenlerini okur. **Sonra gelen kazanır:** ortam değişkeni dosyadaki değeri ezer (`crates/authn-core/src/config/mod.rs`, `crates/authn-server/src/cli.rs`).
- **Ortam değişkeni sözdizimi:** `AUTHN__<BÖLÜM>__<ANAHTAR>[__<ALT_ANAHTAR>…]`, iç içe geçiş ayırıcısı çift alt çizgi (`__`). Örnekler:
  - `AUTHN__SESSION__ACCESS_TOKEN_TTL=5m`
  - `AUTHN__SERVER__LIMITS__REQUEST_TIMEOUT=10s`
  - `AUTHN__DATABASE__URL=postgres://authn_app:…@db/authn?sslmode=verify-full`

  Değerler figment'in `Env` sağlayıcısıyla ayrıştırılır; dizi ve tablolar satır içi sözdizimiyle verilebilir (bu belge yazılırken `check-config` ile denendi):
  - `AUTHN__PASSWORD__CHECK_ENDPOINT_PER_IP='{limit=30,period="1m"}'`
  - `AUTHN__CRYPTO__PEPPERS='[{version=1,key="…"},{version=2,key="…"}]'` — ortam değişkeni dosyadaki diziyi **tamamen** değiştirir, birleştirmez.
- **Bilinmeyen anahtar reddedilir** (`deny_unknown_fields`): yazım hatası sessizce varsayılana düşmez, sunucu açılmaz.
- **Hata mesajları değeri asla yankılamaz**, yalnızca anahtar adını ve kuralı söyler (`ConfigProblems`, `ConfigError::from_figment`). Tüm sorunlar bir arada raporlanır.
- **Doğrulama:** `rust-authentication check-config` hem `AppConfig::validate`'i hem de `serve`'ün açılışta kurduğu bileşenlerin ek kontrollerini (host doğrulama, güvenlik başlıkları, CORS, admin konsolu CORS, kripto servisleri, şifreli Apple anahtarı, sosyal giriş sağlayıcı kaydı, e-posta şablonları) çalıştırır (`cli.rs::check_startup_settings`). Dağıtımdan önce CI'da çalıştırın.

### Değer biçimleri

| Tür | Biçim | Kaynak |
|-----|-------|--------|
| Süre | `"500ms"`, `"30s"`, `"15m"`, `"2h"`, `"7d"` ya da çıplak tamsayı (saniye). Birimler yalnızca `ms`, `s`, `m`, `h`, `d`; en fazla 32 karakter | `config/duration.rs` |
| Oran sınırı politikası (`RateLimitPolicy`) | `{ limit = 30, period = "1m" }` — `limit` hem pencere başına izin hem patlama (burst) boyutudur. Doğrulama: `limit >= 1`, `period > 0` | `ports/rate_limit.rs`, `config/password.rs::validate_policy` |
| Anahtar materyali | base64 (standart veya URL-safe, dolgulu/dolgusuz), çözülünce **en az 32 bayt** (KEK'lerde **tam 32 bayt**). Üretim: `openssl rand -base64 32` | `config/common.rs` |
| Sır (`SecretString`) | düz metin; `Debug` çıktısında `[REDACTED]`, loglara ve hata mesajlarına girmez | `authn_core::secret` |
| `environment` | `production` (varsayılan) · `staging` · `development` · `test` | `config/common.rs` |

### Ortama bağlı (üretim) kurallar

`server.environment` **varsayılanı `production`'dır**: ayarlamayı unutmak doğrulamayı yalnızca sıkılaştırır. Bölüm kurallarına ek olarak `AppConfig::validate_cross_section` şunları uygular:

| Kural | Ortam |
|-------|-------|
| `crypto.peppers[*].key`, `crypto.keks[*].key`, `crypto.hmac_root_key` depoda yayımlanmış örnek/test anahtarlarından biri olamaz (`KNOWN_PUBLIC_KEYS`: `config/example.toml` ve `authn-testkit` anahtarları) | production, staging |
| `server.public_base_url` `https` olmalı | production |
| `webauthn.allowed_origins` web origin'leri `https://` olmalı (`android:apk-key-hash:` serbest) | production |
| `protect.outbound.allow_private_networks = false` olmalı (SSRF, PRT-12) | production |
| `protect.rate_limit.backend` `memory` olamaz (instance başına sayar) | production |
| `admin.four_eyes = false` yasak (K-66) | production |
| `session.access_token_session_check = true` olmalı (K-58) | production |
| `protect.captcha.provider` `turnstile` / `hcaptcha` ise `protect.captcha.hostnames` boş olamaz (PRT-05) | production |
| `notify.email.transport = "log"` ve `notify.sms.provider = "log"` yalnızca development/test | staging, production'da yasak |
| `notify.email.transport = "disabled"` yasak | production |
| `notify.email.smtp.extra_ca_file` yalnızca development/test | staging, production'da yasak |
| `crypto.signing_keys.retired_retention >= session.access_token_ttl` | her ortam |
| `admin.step_up_max_age <= session.step_up_max_age` | her ortam |

Zorunlu anahtarlar (varsayılanı yok): `server.public_base_url`, `database.url`, `crypto.peppers`, `crypto.current_pepper_version`, `crypto.keks`, `crypto.current_kek_id`, `crypto.hmac_root_key`.

---

## 2. `[server]` — `config/server.rs` (sahip: authn-server)

| Anahtar | Tür | Varsayılan | Doğrulama / not |
|---------|-----|-----------|-----------------|
| `environment` | enum | `production` | yukarıdaki tablo |
| `bind_addr` | soket adresi | `0.0.0.0:8080` | Genel API dinleyicisi |
| `metrics_bind_addr` | soket adresi | `127.0.0.1:9090` | Prometheus dinleyicisi (OPS-04); `bind_addr`'dan farklı olmalı. TOML'da kapatma değeri yoktur (alan `Option`, ama varsayılan doludur) — dışarı açmayın, yalnızca iç ağdan kazıyın |
| `public_base_url` | URL | **zorunlu** | Mutlak http(s), kimlik bilgisi/sorgu/parça yok; üretimde https. E-postadaki her link yalnızca buradan kurulur; JWT `iss` varsayılanı ve CSRF'in izinli origin'i |
| `trusted_proxies` | CIDR listesi | `[]` | Yönlendirme başlığını ayarlamasına izin verilen ters vekiller (PRT-06). IPv4'te `/8`'den kısa, özel olmayan IPv6'da `/16`'dan kısa ağlar reddedilir (K-57: `0.0.0.0/0` istemci IP'sini sahtelenebilir yapardı) |
| `client_ip_header` | enum | `x-forwarded-for` | veya `forwarded` (RFC 7239). Yalnızca eş güvenilir vekil ise okunur; sağdan sola yürünür, en fazla 32 adım |
| `default_locale` | enum | `en` | `en` · `tr`; `Accept-Language` eşleşmezse |
| `openapi_enabled` | bool | `true` | `GET /openapi.json` (OPS-09) |
| `shutdown_grace_period` | süre | `30s` | 1s–10m (OPS-07) |
| `log_format` | enum | `json` | `json` · `pretty` |
| `log_filter` | string | `info` | `tracing` filtre yönergesi; boş olamaz |
| `admin_console_origins` | origin listesi | `[]` | Başka origin'den sunulan admin konsolu (K-67): yalnızca bunlar `x-impersonation-session` başlığını siteler arası gönderebilir; her biri `protect.cors.allowed_origins`'ta da olmalı (açılışta `AdminConsoleCors::from_config` denetler) |

### `[server.limits]` (PRT-11)

| Anahtar | Tür | Varsayılan | Doğrulama |
|---------|-----|-----------|-----------|
| `body_limit_bytes` | tamsayı | `65536` (64 KiB) | 1 KiB – 10 MiB; aşımda `413 payload_too_large` |
| `request_timeout` | süre | `30s` | 1s–300s; aşımda `408 request_timeout` |
| `max_concurrent_requests` | tamsayı | `1024` | ≥ 1; instance başına eşzamanlı istek |

## 3. `[database]` — `config/database.rs` (sahip: authn-store)

| Anahtar | Tür | Varsayılan | Doğrulama / not |
|---------|-----|-----------|-----------------|
| `url` | sır | **zorunlu** | `postgres://` veya `postgresql://`. Yerel geliştirme dışında `?sslmode=verify-full` kullanın |
| `max_connections` | tamsayı | `20` | 1–1000 |
| `min_connections` | tamsayı | `1` | ≤ `max_connections` |
| `acquire_timeout` | süre | `5s` | 1s–5m; havuzdan bağlantı beklenir, aşılırsa `503 service_unavailable` |
| `idle_timeout` | süre | `10m` | — |
| `max_lifetime` | süre | `30m` | — |
| `statement_timeout` | süre | `30s` | 1s–30m; her bağlantıda sunucu tarafı `statement_timeout` |
| `migrate_on_start` | bool | `false` | `serve` açılırken bekleyen migration'ları uygular. Üretimde kapalı tutun, `migrate`'i ayrı çalıştırın ([deployment.md](deployment.md#3-migrationlar)) |
| `maintenance_url` | sır (opsiyonel) | yok | Bakım rolü (OPS-10): audit saklama temizliği ve kontrol noktaları bu rolle çalışır. Yoksa uygulama havuzu kullanılır ve açılışta uyarı loglanır. Bkz. [least-privilege.md](least-privilege.md) |
| `maintenance_max_connections` | tamsayı | `2` | 1–100; bakım havuzunun `min_connections` değeri 0'dır |

## 4. `[crypto]` — `config/crypto.rs` (sahip: authn-crypto)

| Anahtar | Tür | Varsayılan | Doğrulama / not |
|---------|-----|-----------|-----------------|
| `peppers` | `[[crypto.peppers]]` dizisi | **zorunlu** | En az bir. Her girdi `version` (≥ 1, benzersiz) + `key` (≥ 32 bayt base64). Eski sürümleri kullanıcılar yeniden hash'lenene kadar tutun (CRY-02) |
| `current_pepper_version` | tamsayı | **zorunlu** | Yapılandırılmış bir pepper'a işaret etmeli; yeni hash'ler bununla |
| `keks` | `[[crypto.keks]]` dizisi | **zorunlu** | En az bir. `id` 1–32 karakter `[A-Za-z0-9_-]`, benzersiz; `key` **tam 32 bayt** base64 (CRY-08) |
| `current_kek_id` | string | **zorunlu** | Yapılandırılmış bir KEK'e işaret etmeli; yeni zarflar bununla |
| `hmac_root_key` | sır | **zorunlu** | ≥ 32 bayt. HKDF amaç alt anahtarlarının kökü (CRY-11): OTP hash'leri, CSRF token'ları, güvenilir cihaz token'ları, PoW, audit zinciri anahtarı (K-77). **Değiştirmek bu türetilmiş anahtarlara bağlı her şeyi geçersiz kılar** ([key-management.md](key-management.md#4-hmac-kök-anahtarı-cryptohmac_root_key)) |
| `jwt_leeway` | süre | `30s` | 0–5m; JWT saat kayması toleransı |
| `max_concurrent_hashes` | tamsayı | `4` | 1–256; eşzamanlı Argon2 hesaplaması (ARC-12 semaforu) |

### `[crypto.argon2]` (CRY-01)

| Anahtar | Varsayılan | Doğrulama |
|---------|-----------|-----------|
| `memory_kib` | `19456` | 7168 – 4194304 |
| `iterations` | `2` | 1–16 |
| `parallelism` | `1` | 1–16 |

### `[crypto.signing_keys]` (CRY-10)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `jwks_cache_ttl` | `1h` | 1m–1d; JWKS yanıtının `Cache-Control: public, max-age` değeri |
| `pending_period` | `2h` | 1m–30d; ≥ `jwks_cache_ttl` ve < `rotation_interval`. Yeni anahtar bu süre JWKS'te `pending` yayımlanır, sonra etkinleşir |
| `rotation_interval` | `30d` | 1d–365d; otomatik rotasyon aralığı |
| `retired_retention` | `1d` | 1m–90d; emekli anahtar JWKS'te kalma süresi; ≥ `session.access_token_ttl` |

## 5. `[password]` — `config/password.rs` (sahip: authn-password)

| Anahtar | Tür | Varsayılan | Doğrulama / not |
|---------|-----|-----------|-----------------|
| `min_length` | tamsayı | `12` | 8–64 (NFKC sonrası karakter); yalnızca şifreli hesaplar için 15 önerilir |
| `max_length` | tamsayı | `128` | 64–1024, ≥ `min_length` |
| `min_strength_score` | 0–4 | `3` | zxcvbn skoru |
| `service_name` | string | `rust-authentication` | ≤ 128 karakter; zxcvbn'e kullanıcı girdisi olarak verilir |
| `check_endpoint_per_ip` | politika | 30 / `1m` | Canlı güç kontrolü ucu (PWD-05), IP başına |
| `change_attempts_per_user` | politika | 5 / `15m` | Mevcut şifreyi doğrulayan değişiklik denemeleri (PWD-06), kullanıcı başına |

### `[password.breach_check]` (PWD-03)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `enabled` | `true` | HIBP Pwned Passwords sorgusu (k-anonimlik aralık API'si) |
| `hibp_range_url` | `https://api.pwnedpasswords.com/range/` | https olmalı (yalnızca `localhost`/`127.0.0.1` için http) |
| `timeout` | `3s` | 100ms–30s |
| `fail_open` | `true` | HIBP erişilemezse şifre kabul edilir ve uyarı loglanır; `false` ise `503 password_breach_check_unavailable` |
| `offline_list_file` | yok | Satır başına bir SHA-1 hex (`HASH:COUNT` de olur) |

### `[password.reset]` (PWD-07, PWD-08)

| Anahtar | Varsayılan | Doğrulama |
|---------|-----------|-----------|
| `token_ttl` | `30m` | 5m–24h (link) |
| `code_enabled` | `true` | mobil için 6 haneli kod |
| `code_ttl` | `15m` | 1m–1h |
| `code_max_attempts` | `5` | 1–10 |
| `per_email` | 3 / `1h` | politika |
| `per_ip` | 20 / `1h` | politika |
| `verify_per_ip` | 30 / `1h` | tamamlamalar (link veya kod), IP başına |
| `code_attempts_per_email` | 10 / `1h` | hesap var olsun olmasın uygulanır |

## 6. `[account]` — `config/account.rs` (sahip: authn-account)

| Anahtar | Tür | Varsayılan | Doğrulama / not |
|---------|-----|-----------|-----------------|
| `unverified_login` | enum | `block` | `block` (doğrulanana kadar giriş yok) · `limited` (giriş + `verify_email` zorunlu adımı) |
| `unverified_purge_after` | süre | `7d` | 1d–365d (ACC-05) |
| `email_change_revert_ttl` | süre | `7d` | 1d–30d (ACC-07) |
| `deletion_grace_period` | süre | `30d` | 0–365d (ACC-09) |
| `disposable_domains_file` | yol | yok | ACC-12 tek kullanımlık domain listesi; verilirse boş olamaz |
| `registration_captcha` | enum | `risk_based` | `always` · `risk_based` · `never` (ACC-13) |
| `registration_per_ip` | politika | 10 / `1h` | |
| `registration_captcha_free_per_ip` | politika | 3 / `1h` | `risk_based` iken pencerede bundan sonrası CAPTCHA ister |
| `registration_notice_per_email` | politika | 3 / `1d` | "Adresinizle kayıt denendi" bildirimleri (ACC-02) |
| `email_change_per_user` | politika | 5 / `1d` | |
| `link_actions_per_ip` | politika | 30 / `1h` | Kimliksiz link eylemleri (e-posta değişikliği onayı/geri alma, silme iptali) |
| `display_name_max_chars` | tamsayı | `64` | 1–128 |
| `require_terms_acceptance` | bool | `false` | Kayıtta güncel şartların kabulü (ACC-11) |
| `reaccept_terms_on_new_version` | bool | `true` | `requires_reacceptance` işaretli yeni sürümde girişte yeniden sorulur |
| `export_per_user` | politika | 2 / `1d` | `POST /v1/me/export` (ACC-10) |
| `terms` | `[[account.terms]]` dizisi | `[]` | Aşağıda |

### `[account.verification]` (ACC-04)

| Anahtar | Varsayılan | Doğrulama |
|---------|-----------|-----------|
| `link_ttl` | `24h` | 15m–7d |
| `code_ttl` | `15m` | 1m–1h |
| `code_max_attempts` | `5` | 1–10 |
| `resend_cooldown` | `60s` | 10s–1h |
| `max_sends_per_hour` | `5` | 1–100 |
| `code_attempts_per_email` | 10 / `1h` | politika |
| `verify_per_ip` | 30 / `1h` | politika |
| `resend_per_ip` | 20 / `1h` | politika |

### `[[account.terms]]` (ACC-11)

| Alan | Tür | Not |
|------|-----|-----|
| `document` | enum | `terms_of_service` · `privacy_policy` |
| `version` | string | 1–64 yazdırılabilir karakter, baş/son boşluk yok; (`document`, `version`) çifti benzersiz |
| `url` | string (opsiyonel) | mutlak http(s), boşluksuz, ≤ 2048 bayt |
| `published_at` | RFC 3339 zaman | Belgenin en yeni yayımlanmış sürümü güncel sürümdür |
| `requires_reacceptance` | bool, varsayılan `false` | |

Listelenen sürümler açılışta eksikse `terms_versions` tablosuna eklenir (`AccountService::sync_terms_versions`); yayımlanmış sürüm değiştirilemez.

## 7. `[session]` — `config/session.rs` (sahip: authn-session)

Ömür çiftleri (`idle_timeout` + `absolute_timeout`): `idle_timeout > 0` ve `≤ absolute_timeout`, `absolute_timeout ≤ 400d`. Mutlak ömür etkinlik veya rotasyonla **asla uzamaz** (SES-06).

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `web` | boşta `2h`, mutlak `12h` | tarayıcı oturumu |
| `remember_me` | boşta `14d`, mutlak `30d` | "beni hatırla" (kalıcı çerez) |
| `shared_device` | boşta `30m`, mutlak `4h` | "bu benim cihazım değil" (SES-07); mutlak ömrü `web`'inkini aşamaz |
| `refresh_token` | boşta `30d`, mutlak `90d` | native refresh token ailesi |
| `access_token_ttl` | `10m` | 1m–1h |
| `refresh_reuse_grace` | `0s` | 0–10s; rotasyon yarışı toleransı (SES-05) |
| `issuer` | `server.public_base_url` (sondaki `/` atılır, ör. `https://auth.example.com`) | JWT `iss`; kaynak sunucuları bununla **tam** eşleştirir |
| `audiences` | `["rust-authentication"]` | boş olamaz; **ilk** değer bu API'nin kendi doğruladığı `aud`'dur |
| `mfa_challenge_ttl` | `5m` | 1m–15m |
| `challenge_max_attempts` | `5` | 1–10 |
| `step_up_max_age` | `10m` | 1m–1h |
| `max_concurrent_sessions` | yok (sınırsız) | verilirse ≥ 1; aşılınca en eski oturum kapatılır (SES-14) |
| `csrf_allowed_origins` | `[]` | `public_base_url` origin'ine ek origin'ler (yol/joker yok) |
| `magic_link_ttl` | `15m` | 1m–1h |
| `email_code_ttl` | `10m` | 1m–30m |
| `email_code_max_attempts` | `5` | 1–10 |
| `introspection_per_client` | 600 / `1m` | API anahtarı başına (SES-10) |
| `access_token_session_check` | `true` | Her bearer isteğinde oturumun canlılığı kontrol edilir; **üretimde `false` reddedilir** |
| `signing_key_cache_ttl` | `30s` | 1s–5m; süreç başına imza anahtarı önbelleği (LISTEN/NOTIFY ile ayrıca anında boşaltılır) |
| `touch_interval` | `1m` | ≤ 5m ve her `idle_timeout`'tan kısa; "son görülme" yazımı seyreltme |
| `default_scopes` | `["api"]` | ≤ 32 adet, her biri RFC 6749 scope token'ı (1–64 yazdırılabilir ASCII; boşluk, `"` ve `\` yok) |
| `step_up_per_user` | 10 / `15m` | |
| `refresh_per_ip` | 300 / `1m` | |

## 8. `[mfa]` — `config/mfa.rs` (sahip: authn-mfa)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `max_failed_attempts` | `5` | 1–20; faktör başına geçici kilitten önce (MFA-03) |
| `per_user_failures` | 10 / `15m` | faktörler arası kullanıcı başına |
| `lockout_duration` | `15m` | 1m–24h |
| `enrollment_ttl` | `15m` | 1m–1h; onaylanmamış faktör kaydı |
| `max_factors_per_user` | `10` | 1–50 (bekleyenler dahil) |

| Alt bölüm | Anahtar | Varsayılan | Doğrulama |
|-----------|---------|-----------|-----------|
| `[mfa.totp]` | `issuer` | `rust-authentication` | 1–64 karakter, `:` ve kontrol karakteri yok |
| | `digits` | `6` | 6 veya 8 |
| | `period` | `30s` | 15s–120s |
| | `skew_steps` | `1` | 0, 1 veya 2 |
| `[mfa.recovery_codes]` | `count` | `10` | 5–20 |
| `[mfa.email_otp]` | `enabled` | `true` | |
| | `ttl` | `10m` | 1m–30m |
| | `max_attempts` | `5` | 1–10 |
| | `resend_cooldown` | `60s` | 10s–15m |
| | `sends_per_user` | 10 / `1h` | politika |
| `[mfa.sms]` | `allowed_country_codes` | `[]` (SMS faktörü kapalı) | `+`'sız 1–3 hane, `0` ile başlamaz (ör. `"90"`). SMS ayrıca `[notify.sms]` sağlayıcısı ve `sms` derleme özelliği ister |
| | `ttl` | `10m` | 1m–30m |
| | `max_attempts` | `5` | 1–10 |
| | `per_number` | 5 / `1h` | |
| | `per_ip` | 10 / `1h` | |
| | `global_daily_budget` | 1000 / `1d` | SMS pompalama koruması |
| | `resend_cooldown` | `60s` | 10s–15m |
| | `per_user` | 5 / `1h` | |
| `[mfa.trusted_device]` | `enabled` | `true` | MFA-09 |
| | `ttl` | `30d` | 1d–90d |

## 9. `[webauthn]` — `config/webauthn.rs` (sahip: authn-webauthn)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `rp_id` | `localhost` | küçük harfli DNS adı (IP değil; WHATWG URL ayrıştırıcısının da aynı domain olarak gördüğü). **Sonradan değiştirmek kayıtlı tüm passkey'leri geçersiz kılar** |
| `rp_name` | `rust-authentication` | 1–64 karakter |
| `allowed_origins` | `["http://localhost:8080"]` | 1–100 adet. Web origin'i `rp_id` ya da alt alan adı olmalı veya `related_origins`'ta listelenmeli; düz `http` yalnızca `localhost`; üretimde https. Android uygulama origin'i: `android:apk-key-hash:<imza sertifikasının dolgusuz base64url SHA-256'sı>` (PKY-06). En az bir web origin'i `rp_id`'ye ait olmalı |
| `ceremony_ttl` | `5m` | 1m–15m |
| `apple_app_ids` | `[]` | `TEAMID.bundle.id` (10 büyük harf/rakam ekip kimliği); `/.well-known/apple-app-site-association` |
| `android_apps` | `[]` | `[[webauthn.android_apps]]`: `package_name` (Java paket adı), `sha256_cert_fingerprints` (1–10 adet, `AA:BB:…` 32 büyük harf hex bayt); `/.well-known/assetlinks.json` |
| `related_origins` | `[]` | `/.well-known/webauthn` (WebAuthn Related Origin Requests) |
| `app_link_paths` | `[]` | Uygulamaların universal link / app link olarak açacağı yollar (`/` ile başlar, `?`/`#` yok, ≤ 256); en az bir Apple veya Android uygulaması ister |
| `well_known_max_age` | `1h` | 1m–7d |
| `max_credentials_per_user` | `20` | 1–100 |
| `step_up_for_first_passkey` | `true` | `false` ise yalnızca ek passkey'ler step-up ister |
| `registration_per_user` | 10 / `1h` | |
| `authentication_per_ip` | 60 / `15m` | |
| `attestation_roots` | `[]` | `[[webauthn.attestation_roots]]`: `name` (1–64), `ca_pem` (tek PEM sertifika, ≤ 16 KiB), `aaguids` (1–100 sıfır olmayan UUID). Yalnızca organizasyon AAGUID izin listesi için (PKY-08) |

## 10. `[org]` — `config/org.rs` (sahip: authn-org)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `invitation_ttl` | `7d` | 1h–30d |
| `invitation_sends_per_org` | 50 / `1h` | |
| `invitation_resend_cooldown` | `1m` | 0–1h |
| `invitation_sends_per_recipient` | 5 / `1d` | organizasyon + alıcı adresi başına |
| `creates_per_user` | 10 / `1d` | |
| `token_attempts_per_user` | 30 / `1h` | davet önizleme/kabul ve sahiplik devri kabulü |
| `domain_verification_label` | `_authn-verification` | `_` + 1–62 karakter `[a-z0-9-]` |
| `domain_checks_per_org` | 30 / `1h` | |
| `dns_timeout` | `5s` | 1s–30s |
| `ownership_transfer_ttl` | `7d` | 1h–30d |
| `ownership_transfers_per_org` | 10 / `1h` | |
| `deletion_grace_period` | `30d` | 0–365d |

| Alt bölüm | Anahtar | Varsayılan | Doğrulama |
|-----------|---------|-----------|-----------|
| `[org.limits]` | `custom_roles` | `50` | 1–1000 |
| | `domains` | `20` | 1–1000 |
| | `service_accounts` | `100` | 1–10000 |
| | `api_keys` | `500` | 1–100000 (iptal edilmemiş) |
| | `pending_invitations` | `1000` | 1–100000 |
| `[org.api_keys]` | `environment` | `live` | 1–8 küçük harf; anahtar öneki `ak_<env>_…`; başka ortamın anahtarı veritabanına gitmeden reddedilir |
| | `max_lifetime` | `365d` | 1d–365d (bitiş zorunlu) |
| | `default_lifetime` | `90d` | > 0, ≤ `max_lifetime` |
| | `rotation_grace` | `24h` | 0–7d |
| | `last_used_update_interval` | `1m` | 0–1h |
| | `auth_failures_per_ip` | 30 / `15m` | iyi biçimli ama geçersiz anahtarlar, IP başına → `429` |

## 11. `[admin]` — `config/admin.rs` (sahip: authn-admin)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `ip_allow_list` | `[]` (her yer) | `/v1/admin` için istemci IP izin listesi (CIDR) |
| `step_up_max_age` | `10m` | 1m–1h; ≤ `session.step_up_max_age` |
| `impersonation_default_ttl` | `15m` | > 0, ≤ `impersonation_max_ttl` |
| `impersonation_max_ttl` | `60m` | 1m–60m |
| `four_eyes` | ayarsız | Ayarsız: production/staging'de açık, development/test'te kapalı. Üretimde `false` reddedilir (K-66) |
| `four_eyes_approval_ttl` | `30m` | 5m–2h |
| `four_eyes_max_pending_requests` | `3` | 1–10 |
| `four_eyes_max_requests_per_hour` | `10` | 1–60, ≥ `four_eyes_max_pending_requests` |

## 12. `[oidc_client]` — `config/oidc_client.rs` (sahip: authn-oidc-client)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `state_ttl` | `10m` | 1m–30m; tarayıcı akışının `state` ömrü (SOC-02) |
| `native_nonce_ttl` | `10m` | 1m–30m; `POST /v1/oauth/nonce` nonce ömrü (SOC-04) |
| `allowed_return_to` | `[]` | göreli yollara ek, tam eşleşmeli `return_to` değerleri (PRT-10) |
| `auto_link_verified_email` | `false` | Sağlayıcının doğruladığı aynı e-postalı mevcut hesaba otomatik bağlama (SOC-05) |
| `auto_link_trusted_providers` | `[]` | `auto_link_verified_email = true` ise boş olamaz |
| `trust_provider_mfa` | `false` | Sağlayıcının bildirdiği MFA'yı MFA sayar (SOC-09) |
| `store_provider_tokens` | `false` | Sağlayıcı token'larını zarf şifreli saklar (SOC-08) |
| `jwks_cache_ttl` | `1h` | 1m–24h; bilinmeyen `kid`'de erken yenilenir |
| `jwks_refresh_min_interval` | `60s` | 10s–1h; bilinmeyen `kid`'in zorladığı iki indirme arası en kısa süre |
| `jwks_max_staleness` | `24h` | `max(jwks_cache_ttl, 1m)` – 7d; sağlayıcı JWKS'i erişilemezken eski anahtarların kullanılabileceği süre, sonra `503` (K-61) |
| `start_per_ip` | 60 / `10m` | tarayıcı akışı başlatma |
| `native_per_ip` | 60 / `10m` | native nonce + native giriş |
| `callback_per_ip` | 60 / `10m` | geri dönüşler (state aramasından önce) |
| `error_redirect` | yok | Tarayıcı geri dönüşü başarısızsa yönlendirme hedefi: aynı origin yolu (`/login/error`) veya `https://` URL (allow-list'te olmalı, açılışta denetlenir); hata kodu `error=<kod>` olarak eklenir. Yoksa JSON hata zarfı |

Sağlayıcı alt bölümleri (yalnızca yapılandırılanlar etkindir):

| Bölüm | Alanlar |
|-------|---------|
| `[oidc_client.google]`, `[oidc_client.github]` | `client_id`, `client_secret` (sır), `native_client_ids` (varsayılan `[]`; mobil SDK'ların ID token `aud` değerleri, SOC-04). GitHub OAuth2 + `/user/emails` ile çalışır |
| `[oidc_client.microsoft]` | yukarıdakiler + `tenant` (varsayılan `common`; `common`/`organizations`/`consumers`/kiracı GUID'i/domain), `allowed_tenants` (GUID listesi; `tenant` bir domain adıysa zorunlu), `trust_personal_account_email` (varsayılan `false`: kişisel Microsoft hesabının e-postası doğrulanmış sayılmaz) |
| `[oidc_client.apple]` | `client_id` (Services ID), `team_id`, `key_id`, özel anahtar için **tam olarak biri**: `private_key_pem` (sır, satır içi), `private_key_file` (yol, açılışta bir kez okunur), `private_key_ciphertext` (KEK ile zarf şifreli; `rust-authentication seal-apple-key` üretir); `native_client_ids` (bundle id'ler), `revoke_tokens_on_deletion` (varsayılan `true`: Apple refresh token'ı silmede/ayırmada iptal için şifreli saklanır, K-35) |
| `[[oidc_client.generic]]` | `slug` (`[a-z0-9-]{1,32}`, yerleşik sağlayıcı adı olamaz, benzersiz; rotada `/v1/oauth/{slug}/…`), `display_name`, `issuer_url` (https; discovery), `client_id`, `client_secret`, `native_client_ids`, `scopes` (varsayılan `["openid","email","profile"]`), `trust_email_verified` (varsayılan `false`) |

## 13. `[protect]` — `config/protect.rs` (sahip: authn-protect)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `allowed_hosts` | `[]` (yalnızca `public_base_url` host'u) | Kabul edilen `Host` değerleri (PRT-09), `host` veya `host:port`; aksi `421 host_not_allowed` |
| `redirect_allow_list` | `[]` | Tam (bayt bayt) eşleşmeyle izinli mutlak yönlendirme hedefleri (PRT-10); parça/kimlik bilgisi/joker/boşluk/ters bölü yok; `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`, `about:`, `filesystem:` şemaları yasak |

### `[protect.rate_limit]` (PRT-01 … PRT-04)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `backend` | `postgres` | `memory` (instance başına; üretimde yasak) · `postgres` · `redis` (`redis` derleme özelliği gerekir) |
| `redis_url` | yok | `backend = "redis"` iken zorunlu; `redis://` veya `rediss://` |
| `login_per_account_captcha` | 10 / `15m` | hesap başına başarısız giriş → CAPTCHA |
| `login_per_account_soft_lock` | 50 / `1h` | hesap başına başarısız giriş → yumuşak kilit (PRT-03) |
| `login_per_ip` | 100 / `15m` | |
| `soft_lock_duration` | `1h` | 1m–1d |
| `requests_per_ip` | 600 / `1m` | Genel HTTP katmanı (her istek, `/health/` hariç); bkz. [API: oran sınırı](../api/rate-limiting.md) |

### `[protect.captcha]` (PRT-05)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `provider` | `disabled` | `disabled` · `turnstile` · `hcaptcha` · `proof_of_work` |
| `login_policy` | `risk_based` | `always` · `risk_based` · `never`; `always` sağlayıcı ister |
| `site_key` | yok | Turnstile/hCaptcha'da zorunlu; 1–256 görünür ASCII |
| `secret_key` | yok (sır) | Turnstile/hCaptcha'da zorunlu |
| `verify_url` | yok | Yalnızca testler için sağlayıcı doğrulama URL'si |
| `pow_difficulty` | `18` | 8–32 (baştaki sıfır bit) |
| `pow_ttl` | `5m` | 30s–30m |
| `fail_open` | `false` | Sağlayıcıya erişilemezse geçti say |
| `hostnames` | `[]` | Widget'ın çözüldüğü host adları; üretimde Turnstile/hCaptcha için zorunlu |
| `challenge_per_ip` | 30 / `1m` | `GET /v1/captcha/challenge` |

### `[protect.security_headers]` (PRT-07)

| Anahtar | Varsayılan | Doğrulama |
|---------|-----------|-----------|
| `hsts_max_age` | `730d` (2 yıl) | ≥ 365d |
| `hsts_include_subdomains` | `true` | |
| `hsts_preload` | `false` | |
| `permissions_policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()` | açılışta `SecurityHeaders::from_config` başlık değeri olarak doğrular |

### `[protect.cors]` (PRT-08)

| Anahtar | Varsayılan | Doğrulama |
|---------|-----------|-----------|
| `allowed_origins` | `[]` (CORS kapalı) | tam origin, joker/yol yok |
| `max_age` | `10m` | 0–2h; preflight önbelleği |

### `[protect.risk]` (RSK-01 … RSK-03)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `enabled` | `true` | |
| `anonymizing_networks_file` | yok | TOR çıkış / vekil CIDR dosyası |
| `failure_window` | `1h` | 1m–1d |
| `failure_threshold` | `5` | ≥ 1 |
| `medium_action` | `step_up` | `step_up` (kayıtlı faktör ya da e-posta onayı) · `allow` |
| `high_action` | `block` | `block` (engelle + kullanıcıya bildir) · `step_up` |
| `impossible_travel_speed_kmh` | `1000` | 100–20000; yalnızca bir `GeoIpLookup` takılıysa |

### `[protect.outbound]` (PRT-12)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `timeout` | `10s` | 1s–2m |
| `connect_timeout` | `5s` | 100ms – `timeout` |
| `max_response_bytes` | `1048576` (1 MiB) | 1 KiB – 50 MiB |
| `allow_private_networks` | `false` | Kullanıcının verdiği URL'lerde özel/loopback hedeflere **ve düz http'ye** izin; yalnızca test/geliştirme, üretimde yasak |

## 14. `[audit]` — `config/audit.rs` (sahip: authn-audit)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `retention` | `400d` | 30d–3650d, ≥ `user_visible_window` (AUD-05) |
| `user_visible_window` | `90d` | 1d–3650d; `GET /v1/me/security-events` penceresi |

| Alt bölüm | Anahtar | Varsayılan | Doğrulama / not |
|-----------|---------|-----------|-----------------|
| `[audit.chain]` (K-77) | `key_version` | `1` | 1–32767; yeni olayların zincir anahtarı sürümü (`crypto.hmac_root_key`'den türetilir). Rotasyon: bir artırıp yeniden başlatın veya `rotate-audit-chain-key` |
| | `legacy_until_seq` | ayarsız | Hâlâ anahtarsız (eski SHA-256) olabilecek son `seq`; ayarlanınca sonrasındaki anahtarsız olaylar doğrulamada reddedilir. ≥ 0 |
| `[audit.outbox]` (AUD-06) | `poll_interval` | `1s` | 100ms–1m |
| | `batch_size` | `100` | 1–1000 |
| | `max_attempts` | `10` | 1–100; sonra dead-letter |
| | `backoff_base` | `2s` | 100ms–1h, ≤ `backoff_max`; her denemede iki katı + jitter |
| | `backoff_max` | `1h` | 1s–1d |
| | `lease` | `60s` | 5s–30m |
| | `concurrency` | `16` | 1–256 |
| | `delivered_retention` | `7d` | 1h–365d |
| | `dead_retention` | `30d` | 1d–365d |
| `[audit.webhooks]` (AUD-07) | `timeout` | `10s` | 1s–1m, < `audit.outbox.lease` |
| | `max_attempts` | `8` | 1–50 |
| | `secret_rotation_overlap` | `24h` | 0–7d; rotasyondan sonra eski sırrın da imzalamaya devam ettiği süre |
| | `max_endpoints_per_org` | `10` | 1–100 |
| | `backoff_base` | `1m` | 1s–1h, ≤ `backoff_max`; alıcının `Retry-After`'ı `backoff_max`'a kadar dikkate alınır |
| | `backoff_max` | `6h` | 1s–1d |
| | `disable_after_failures` | `20` | 1–10000; `disable_after` ile birlikte otomatik devre dışı bırakma |
| | `disable_after` | `24h` | 0–30d |
| | `delivery_retention` | `30d` | 1d–365d |
| `[audit.rate_limits]` | `events_read` | 60 / `1m` | principal başına olay listeleme. Bu bölümde limit 1–1000000, periyot 1s–7d |
| | `webhook_write` | 60 / `1h` | organizasyon başına |
| | `webhook_redeliver` | 30 / `1h` | organizasyon başına |

## 15. `[notify]` — `config/notify.rs` (sahip: authn-notify)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `app_name` | `rust-authentication` | 1–64 karakter, kontrol karakteri yok; mesajlarda ürün adı |
| `template_dir` | yok (yerleşik şablonlar) | `<dir>/<locale>/email/<ad>.{subject.txt,txt,html}` ve `<dir>/<locale>/sms/<ad>.txt`; her dosya açılışta doğrulanır |
| `max_attempts` | `10` | 1–100; mesaj başına teslim denemesi (outbox) |
| `recipient_limit` | 30 / `1h` | Alıcı kutusu (`+etiket` katlanır) veya numara başına kullanıcının tetikleyebildiği mesajlar; şifre sıfırlama, magic link, giriş kodu ve MFA kodlarının ayrı bütçeleri var, diğerleri birini paylaşır. Fazlası **sessizce** düşer (hesap varlığı sızmaz); güvenlik uyarıları sınırlanmaz. Limit 1–1000000, periyot 1s–7d |

### `[notify.email]` (NTF-03)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `transport` | `smtp` | `smtp` · `log` (yalnızca development/test) · `disabled` (production'da yasak) |
| `from_address` | `no-reply@localhost.localdomain` | geçerli e-posta adresi; gerçek teslimde değiştirin |
| `from_name` | `rust-authentication` | ≤ 64 karakter; satır sonu, `<`, `>`, `"` yok |
| `smtp` | yok | `transport = "smtp"` iken zorunlu (aşağıda) |

`[notify.email.smtp]`: `host` (zorunlu; sertifika buna karşı doğrulanır), `port` (varsayılan `587`, 0 olamaz), `tls` (`starttls` varsayılan · `tls`; düz metin SMTP yok), `username` + `password` (birlikte verilir; parola sır), `timeout` (`10s`, 1s–2m), `extra_ca_file` (yalnızca development/test; docker-compose Mailpit sertifikası için), `hello_name` (varsayılan `from_address`'in domain'i; makinenin host adı asla gönderilmez).

### `[notify.links]` (NTF-02)

Linkler `server.public_base_url` + bu yol + `#token=…` (URL parçası: token sunucu loglarına ve `Referer`'a girmez) olarak kurulur. Her yol `/` ile başlar, `//` ile başlamaz, `?`/`#`/`\`/boşluk içermez.

| Anahtar | Varsayılan |
|---------|-----------|
| `email_verification` | `/verify-email` |
| `password_reset` | `/reset-password` |
| `password_reset_request` | `/forgot-password` |
| `sign_in` | `/login` |
| `email_change_verification` | `/email-change/verify` |
| `email_change_revert` | `/email-change/revert` |
| `magic_link` | `/magic-link` |
| `invitation` | `/invitations/accept` |
| `account_deletion_cancel` | `/account/deletion/cancel` |
| `not_me` | `/security/not-me` |
| `org_ownership_transfer` | `/organizations/ownership/accept` |

### `[notify.sms]` (NTF-04)

| Anahtar | Varsayılan | Doğrulama / not |
|---------|-----------|-----------------|
| `provider` | `none` | `none` (SMS faktörü yok) · `http` · `log` (yalnızca development/test) |
| `http_url` | yok | `http` için zorunlu, `https://` |
| `http_api_key` | yok (sır) | `http` için zorunlu |
| `http_auth_header` | `authorization` | geçerli HTTP başlık adı |
| `http_auth_scheme` | `Bearer` | boş (ham anahtar) veya ≤ 32 karakter `[A-Za-z0-9-]` |
| `http_body_template` | `{"to":"{{to}}","text":"{{text}}","from":"{{sender_id}}"}` | JSON nesnesi (≤ 8 KiB), string değerlerde `{{to}}` ve `{{text}}` zorunlu; yer tutucular ayrıştırılmış JSON ağacında değiştirilir (JSON enjeksiyonu yok) |
| `http_message_id_pointer` | yok | `/` ile başlayan JSON pointer (≤ 256) |
| `sender_id` | yok | 1–16 karakter |
| `timeout` | `10s` | 1s–1m |

---

## 16. Asgari üretim yapılandırması (örnek)

```toml
[server]
environment = "production"
public_base_url = "https://auth.example.com"
trusted_proxies = ["10.0.0.0/8"]          # yük dengeleyicinin ağı

[database]
url = "postgres://authn_app:…@db.internal:5432/authn?sslmode=verify-full"
maintenance_url = "postgres://authn_maintenance:…@db.internal:5432/authn?sslmode=verify-full"

[crypto]
current_pepper_version = 1
current_kek_id = "kek-2026-11"
hmac_root_key = "<openssl rand -base64 32>"
[[crypto.peppers]]
version = 1
key = "<openssl rand -base64 32>"
[[crypto.keks]]
id = "kek-2026-11"
key = "<openssl rand -base64 32>"

[webauthn]
rp_id = "example.com"
allowed_origins = ["https://auth.example.com", "https://app.example.com"]

[notify.email]
from_address = "no-reply@example.com"
[notify.email.smtp]
host = "smtp.example.com"
username = "authn"
password = "…"
```

Sırları dosyada tutmak yerine ortamdan verebilirsiniz (ör. `AUTHN__DATABASE__URL`, `AUTHN__CRYPTO__HMAC_ROOT_KEY`, `AUTHN__NOTIFY__EMAIL__SMTP__PASSWORD`). Dağıtımdan önce: `rust-authentication --config prod.toml check-config`.
