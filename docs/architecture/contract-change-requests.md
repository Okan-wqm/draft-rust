# Sözleşme değişikliği talepleri

Kurallar: [`contracts.md` §13](contracts.md#13-sözleşme-değişikliği-talebi). Her crate **yalnızca kendi başlığı altına** ekleme yapar; başka bölümleri düzenlemez. Uygulanan talepler silinmez, durumu güncellenir.

Kayıt şablonu:

```markdown
### <YYYY-AA-GG> — <kısa başlık>
- **Talep eden:** authn-<crate>
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/…` / authn-<sahip>
- **Gereksinim:** <ID>
- **Gerekçe:** …
- **Önerilen değişiklik:** …
- **Geriye uyumluluk:** …
- **Durum:** Açık | Uygulandı (<tarih>, <commit/özet>) | Reddedildi (<gerekçe>)
```

## authn-crypto

### 2026-10-31 — `authn-store` bağımlılığı ve yeni store modülleri
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `crates/authn-store/Cargo.toml`, `crates/authn-store/src/lib.rs`, `crates/authn-store/README.md` / authn-store
- **Gereksinim:** ARC-06, CRY-06, CRY-07, CRY-10
- **Gerekçe:** Görev ataması gereği `one_time_tokens` ve `signing_keys` modülleri `authn-store` içinde authn-crypto agent'ı tarafından yazıldı. Modüller `TokenHash`, `EnvelopeCipher`, `JwtSigner` tiplerini kullandığından `authn-store` → `authn-crypto` bağımlılığı eklendi (contracts §2'de zaten izinli; `architecture.rs` testi geçiyor). `lib.rs`'e yalnızca `pub mod` ve yeniden dışa aktarma satırları, README'ye iki API satırı eklendi.
- **Önerilen değişiklik:** Uygulandı; store sahibinin bilgisine.
- **Geriye uyumluluk:** Ekleme; mevcut API değişmedi.
- **Durum:** Uygulandı (2026-10-31, authn-crypto görevi)

### 2026-10-31 — `data_encryption_keys` tablosu kullanılmıyor
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `migrations/0011_keys.sql` (`data_encryption_keys`) / authn-crypto (tablo), mimar (migration)
- **Gereksinim:** CRY-08
- **Gerekçe:** Zarf şifreleme değer başına DEK kullanır; DEK, KEK ile sarılmış olarak zarfın içinde taşınır (`version ‖ kek_id ‖ wrapped_dek ‖ nonce ‖ ciphertext`). Bu, şifre çözme yolunda veritabanı araması/önbellek gerektirmez, nonce yeniden kullanımını imkânsız kılar ve KEK rotasyonunu `EnvelopeCipher::rewrap` ile satır bazında yapar. `0011` yorumundaki "zarf başlığı DEK kimliğini taşır" modeli uygulanmadı.
- **Önerilen değişiklik:** Tablo şimdilik olduğu gibi kalsın (ileride KMS sağlayıcısı için sarılmış-DEK önbelleği olarak kullanılabilir); `0011_keys.sql` yorumu ve `overview.md` bir sonraki mimar düzenlemesinde "kullanılmıyor / ayrılmış" olarak güncellensin. Tablo silinmesi istenirse authn-crypto aralığında (`1000–1099`) bir `DROP TABLE` migration'ı yazılabilir.
- **Geriye uyumluluk:** Etkisi yok (tabloya yazan/okuyan kod yok).
- **Durum:** Açık

### 2026-10-31 — Sarmalanmış eski hash'ler için pepper zorunluluğu (şema kısıtı)
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `password_credentials` tablosu / authn-store (yeni migration mimar aralığında)
- **Gereksinim:** CRY-02, CRY-04
- **Gerekçe:** `argon2id_wrapped_md5` ve `argon2id_wrapped_sha1` hash'leri de pepper ile üretilir; `pepper_version` olmadan doğrulanamazlar (kod `Invalid` döner ve loglar). Mevcut kısıt yalnızca `algorithm = 'argon2id'` için `pepper_version`'ı zorunlu kılıyor.
- **Önerilen değişiklik:** `ALTER TABLE password_credentials ADD CONSTRAINT password_credentials_wrapped_pepper_check CHECK (algorithm NOT LIKE 'argon2id%' OR pepper_version IS NOT NULL);`
- **Geriye uyumluluk:** Mevcut veride bu biçimde satır yok; ekleme.
- **Durum:** Açık

### 2026-10-31 — Fuzz harness'ine authn-crypto hedefleri eklendi
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `fuzz/Cargo.toml` / mimar
- **Gereksinim:** TST-04, CRY-14
- **Gerekçe:** Görev kapsamı `fuzz/**`'i içerdiğinden üç yeni hedef (`password_hash_parse`, `token_parse`, `webhook_verify`) ve harness yardımcı bağımlılıkları (`base64 0.23.1`, `serde_json 1.0.154`, `time 0.3.55`; workspace ile aynı sürümler, MIT/Apache-2.0) eklendi. `webhook_signature` hedefi authn-audit'e ait olarak bırakıldı; `webhook_verify` yalnızca `authn_crypto::webhook` ayrıştırıcısını kapsar. CI'daki `cargo +nightly fuzz build` adımı yeni hedefleri otomatik derler.
- **Önerilen değişiklik:** Uygulandı.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-10-31)

### 2026-10-31 — Yeni `one_time_tokens.purpose` değerleri artık bir enum'a eklenir
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `crates/authn-store/src/one_time_tokens.rs` (`TokenPurpose`) / authn-crypto agent'ı
- **Gereksinim:** ARC-06
- **Gerekçe:** Amaçlar dize değil, contracts §5 tablosunun birebir karşılığı olan `TokenPurpose` enum'udur (link/kod türü enum'dan türetilir, yazım hatası yeni bir amaç yaratamaz). Yeni amaç isteyen modül §13 kaydıyla birlikte enum'a varyant eklenmesini talep eder.
- **Önerilen değişiklik:** contracts §5'e "Yeni purpose = `TokenPurpose` varyantı" notu eklensin.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Açık

## authn-store

## authn-password

## authn-account

## authn-mfa

## authn-webauthn

## authn-org

## authn-protect

### 2026-11-01 — Cihaz kimliği hash'i için `KeyPurpose::RateLimitKey` paylaşımı
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `crates/authn-crypto/src/kdf.rs` (`KeyPurpose`) / authn-crypto
- **Gereksinim:** RSK-02, CRY-11
- **Gerekçe:** `known_devices.device_hash` için anahtarlı hash gerekiyor; `KeyPurpose` içinde uygun bir amaç yok. Şimdilik `RateLimitKey` amaç anahtarı, alanları uzunluk önekli ve **ayrı etiketli** (`authn/protect/known-device/v1` ↔ `authn/protect/rate-limit-key/v1`, `HmacKey::sign_fields`) olarak kullanılıyor; iki kullanım birbirine çakışamaz.
- **Önerilen değişiklik:** `KeyPurpose::KnownDevice` (`info = "authn/v1/known-device"`) eklenmesi. Eklenirse authn-protect `KeyHasher::device`'ı yeni anahtara taşır (mevcut satırlar bir sonraki girişte yeniden öğrenilir; tek etkisi bir kerelik "yeni cihaz" sinyalidir).
- **Geriye uyumluluk:** Ekleme; acil değil.
- **Durum:** Açık

### 2026-11-01 — Migration 1600: `rate_limit_buckets.allowed` ve risk indeksleri
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `migrations/1600_protect_rate_limit_decision.sql` / authn-protect (kendi tabloları, kendi aralığı)
- **Gereksinim:** PRT-01, RSK-02, OPS-06
- **Gerekçe:** PostgreSQL 16 upsert'ten eski satırı döndüremez; GCRA kararı tek `INSERT … ON CONFLICT DO UPDATE … RETURNING` ile verilirken sonucun (kabul/ret) aynı satırda dönmesi için `allowed boolean NOT NULL DEFAULT true` kolonu eklendi. Ayrıca `known_devices (user_id, last_seen_at DESC)` (imkânsız seyahat) ve `login_soft_locks (locked_until)` (temizlik) indeksleri.
- **Önerilen değişiklik:** Uygulandı; bilgi amaçlı (onay gerektirmez, contracts §6).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — `protect.outbound.allow_private_networks` düz `http`'ye de izin verir
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `crates/authn-core/src/config/protect.rs` (authn-protect) — `config/mod.rs`'teki üretim kuralı (mimar) değişmeden geçerli
- **Gereksinim:** PRT-12, TST-08
- **Gerekçe:** Kullanıcı tarafından verilen URL'ler yalnızca `https` ile çağrılır. Testlerde/yerelde `wiremock` (`http://127.0.0.1:…`) kullanılabilsin diye tek geliştirme anahtarı hem özel ağlara hem düz `http`'ye izin verir. Üretimde bu anahtar `config/mod.rs` tarafından zaten reddedildiği için ek bir üretim kuralı gerekmez. Yeni alanlar (kendi dosyamda): `rate_limit.requests_per_ip`, `captcha.challenge_per_ip`, `risk.impossible_travel_speed_kmh`, `outbound.connect_timeout`; `allowed_hosts`, `redirect_allow_list`, `redis_url`, `verify_url`, `site_key` için daha sıkı doğrulama. `config/example.toml`'daki `[protect]` yorumları güncellendi.
- **Önerilen değişiklik:** Uygulandı; bilgi amaçlı.
- **Geriye uyumluluk:** Yeni alanlar varsayılanlı; mevcut konfigürasyonlar geçerli kalır (`authn-server/tests/example_config.rs` geçiyor).
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — authn-server ve authn-session için bağlama notları
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{app.rs,state.rs,openapi.rs}` / authn-server; `crates/authn-session` / authn-session
- **Gereksinim:** OPS-02, OPS-06, ARC-03, PRT-03, RSK-04
- **Gerekçe:** Katmanlar ve servisler hazır; yerleştirme sahiplerin işidir.
- **Önerilen değişiklik:** (1) `app.rs` (7) yuvasına, dıştan içe: `validate_host` → `security_headers` → `cors` → `http_rate_limit` (`from_fn_with_state`, ayrıntı: `crates/authn-protect/README.md`, örnek: `crates/authn-protect/tests/web_stack.rs`). (2) `AppState`: `CaptchaService: FromRef`, `.merge(authn_protect::router::<AppState>())`, `openapi.rs`'e `authn_protect::ProtectApi` nest. (3) Arka plan işleri: `PostgresRateLimiter::purge_expired`, `ProofOfWorkCaptcha::purge_expired`, `LoginProtection::purge_expired`. (4) authn-session: `NotMeTokenIssuer`'ı (`one_time_tokens` amaç `not_me`) uygular, giriş akışında `LoginProtection::{check_attempt, record_failure, record_success}`, `RiskEvaluator::evaluate` + `authn_protect::risk::decide` + `RiskAlerts::{on_successful_login, on_blocked_login}` çağırır; `return_to` için `RedirectValidator`. (5) authn-admin: kilit açma için `LoginProtection::unlock`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

### 2026-11-01 — `fuzz/Cargo.lock` yeniden üretildi
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `fuzz/Cargo.lock` (cargo üretir) / mimar
- **Gereksinim:** TST-04
- **Gerekçe:** `return_to` hedefinin gövdesi yazıldı; `cargo +nightly fuzz build return_to` authn-protect'in güncel bağımlılık listesiyle kilit dosyasını yeniden üretti (`governor`, `tower-http`, `rustls`, `secrecy`, `subtle` authn-protect'ten çıktı; `base64`, `unicode-normalization`, `utoipa` workspace sürümleriyle eklendi). `fuzz/Cargo.toml` değişmedi.
- **Önerilen değişiklik:** Bilgi amaçlı.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — `LoginProtection`: tanımlayıcı bütçeleri `check_attempt`'ta tüketilir (güvenlik incelemesi)
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `crates/authn-protect/src/login.rs` / authn-protect; tüketici authn-session (SES-01)
- **Gereksinim:** PRT-02, PRT-03, PRT-05, SES-01
- **Gerekçe:** Güvenlik incelemesi bir kontrol-sonra-eylem açığı buldu: CAPTCHA/yumuşak kilit sayaçları doğrulamadan önce yalnızca okunuyor, başarısızlık doğrulamadan sonra sayılıyordu; eşzamanlı denemeler eşikleri aşabiliyordu.
- **Önerilen değişiklik:** (uygulandı) İmzalar değişmedi. `check_attempt` her şifre denemesinde tanımlayıcının CAPTCHA bütçesinden ve (CAPTCHA kapısından sonra) yumuşak kilit bütçesinden birer birimi atomik olarak tüketir; `record_success` bunları geri verir; `record_failure` yalnızca risk hız sayaçlarını artırır. authn-session: her şifre denemesi için `check_attempt`'ı **tam bir kez** çağırın, başarıda `record_success`'i mutlaka çağırın (çağrılmazsa deneme başarısız sayılır), başarısızlıkta `record_failure`'ı çağırmaya devam edin (RSK-02 hız sinyali).
- **Geriye uyumluluk:** API aynı; henüz tüketici yok (Dalga B).
- **Durum:** Uygulandı (2026-11-01)

## authn-audit

## authn-notify

## authn-session

## authn-oidc-client

## authn-admin

## authn-server
