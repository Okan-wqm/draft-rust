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

### 2026-11-01 — Fuzz hedefi `hibp_range_parse` kaydı
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `fuzz/Cargo.toml` / mimar
- **Gereksinim:** TST-04, PWD-03
- **Gerekçe:** HIBP aralık yanıtı ve çevrimdışı sızıntı listesi dış kaynaklı girdidir. Hedef dosyası yazıldı (`fuzz/fuzz_targets/hibp_range_parse.rs`, sahibi authn-password); aynı değişmezler `crates/authn-password/tests/breach.rs` içinde `proptest` ile de çalışıyor.
- **Önerilen değişiklik:** `fuzz/Cargo.toml`'a `authn-password = { path = "../crates/authn-password" }` bağımlılığı ve `[[bin]] name = "hibp_range_parse", path = "fuzz_targets/hibp_range_parse.rs", test = false, doc = false, bench = false`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — Şifre sıfırlamada güvenilir cihazların silinmesi `SessionRevoker` üzerinden
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/session_revoker.rs` (semantik) / authn-session; `trusted_devices` / authn-mfa
- **Gereksinim:** PWD-09, MFA-09, SES-15
- **Gerekçe:** PWD-09 "güvenilir cihazlar silinir" der; authn-password `trusted_devices` tablosuna erişemez. Mevcut sözleşmede yol zaten var: `RevokeOptions { also_trusted_devices: true }`. authn-password sıfırlamayı `revoke_all_for_user(conn, user, RevocationReason::PasswordReset, RevokeOptions { also_trusted_devices: true })` ile, kendi transaction'ında çağırır (test: `pwd_09_reset_revokes_every_session_refresh_token_and_trusted_device`).
- **Önerilen değişiklik:** authn-session'ın `SessionRevoker` uygulaması bu bayrakta authn-mfa'nın güvenilir cihaz silme API'sini **aynı `&mut PgConnection` üzerinde** çağırmalı (commit edilmezse cihazlar da kalır). Port belgesine "also_trusted_devices çağıranın transaction'ında uygulanır" cümlesi eklenebilir.
- **Geriye uyumluluk:** Semantik netleştirme; imza değişmez.
- **Durum:** Açık (authn-session uygulaması bekleniyor)

### 2026-11-01 — Server'ın uygulayacağı trait'ler ve bağlama
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,serve.rs}` / authn-server
- **Gereksinim:** PWD-04, PWD-11, ARC-03, OPS-07
- **Gerekçe:** Dalga A modülleri birbirine bağımlı olamaz; PWD-11 başka giriş yöntemlerini (webauthn, oidc-client), PWD-04 ve bildirimler görünen ad/dili (account) bilmelidir.
- **Önerilen değişiklik:** (1) `authn_password::LoginMethodInventory` — `async fn other_login_methods(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<LoginMethod>, AuthError>`; passkey → `LoginMethod::Passkey`, bağlı kimlik → `LoginMethod::Social`; verilen bağlantı üzerinden okunur (çağıran kullanıcı satırını `FOR UPDATE` kilitlemiştir). (2) `authn_password::ProfileLookup` — `async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError>` (`display_name`, `locale`). (3) `PasswordService::new(PasswordServiceDeps { … }, PasswordServiceSettings::from_app_config(&config))`, `breach_checker = HibpBreachChecker::from_config(&config.password.breach_check, protect_http_client)`, `impl FromRef<AppState> for PasswordService`, `.merge(authn_password::router::<AppState>())` (`/v1/me/password*` kimlik doğrulama katmanının arkasında), `openapi.rs`'e `authn_password::PasswordApi`. (4) Zarif kapanışta `drain_background_jobs().await`. (5) authn-account'a `PasswordValidator` olarak `password_service.validator()`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

### 2026-11-01 — authn-session / authn-admin için şifre API'si
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session; `crates/authn-admin` / authn-admin
- **Gereksinim:** SES-01, SES-13, SES-22, PWD-12, ADM-03, CRY-03/04/05
- **Gerekçe:** Şifre doğrulama, rehash ve `must_change_password` mantığı tek yerde (authn-password) kalmalı.
- **Önerilen değişiklik:** Giriş ve step-up: `verify_login_password(&ctx, Option<UserId>, &SecretString) -> Result<LoginPasswordOutcome, AuthError>` (`Valid` / `MustChangePassword` / `Invalid`; kullanıcı yoksa `None` verin — sahte doğrulama ve eşdeğer sorgu içeride). `MustChangePassword` → `RequiredAction::ChangePassword` challenge'ı; tamamlama `apply_required_password_change(&ctx, user, Some(session), &new)` (bayrak yoksa `forbidden`). Admin: `set_must_change_password(&ctx, Actor::User(admin), user, bool)`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — PWD-11 yarışına karşı kullanıcı satırı kilidi
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** passkey silme (authn-webauthn), kimlik ayırma (authn-oidc-client)
- **Gereksinim:** PWD-11, PKY-04, SOC-06
- **Gerekçe:** "Son giriş yöntemi silinemez" kuralı üç modüle dağılmıştır. authn-password şifre kaldırmayı `users` satırı `FOR UPDATE` kilitliyken kontrol eder; diğer modüller de aynı satırı kilitlerse "son passkey'i sil" ile "şifreyi kaldır" eşzamanlı olarak ikisi birden başarılı olamaz.
- **Önerilen değişiklik:** Passkey silme ve kimlik ayırma transaction'larının başında `authn_store::UserRepository::lock_for_update(conn, user)`.
- **Geriye uyumluluk:** Davranış değişikliği yok (yalnızca serileştirme).
- **Durum:** Açık

### 2026-11-01 — `[password]` yeni alanlar
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-core/src/config/password.rs` (authn-password), `config/example.toml` `[password]` yorumları
- **Gereksinim:** PWD-06, PWD-08
- **Gerekçe:** Mevcut şifre tahminini (çalınan oturumla) ve kod denemelerini (hesap var olsun olmasın, adres başına) sınırlamak.
- **Önerilen değişiklik:** Uygulandı: `change_attempts_per_user` (5/15 dk), `reset.verify_per_ip` (30/saat), `reset.code_attempts_per_email` (10/saat), `service_name` ≤ 128 karakter doğrulaması. Hata kodları `error/codes/password.rs`'e eklendi. Bilgi amaçlı.
- **Geriye uyumluluk:** Varsayılanlı yeni alanlar; mevcut konfigürasyonlar geçerli.
- **Durum:** Uygulandı (2026-11-01)

## authn-account

### 2026-11-01 — ACC-03: `EmailAddress` sertleştirmesi
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `crates/authn-core/src/domain/email.rs` / mimar (ACC-03 sahibi authn-account; bu dalgada düzenleme yetkisi authn-account'a verildi), `fuzz/fuzz_targets/email_normalize.rs` (core/account)
- **Gereksinim:** ACC-03, TST-03, TST-04
- **Gerekçe:** Homograf ve görünmez karakter saldırıları (`pаypal@…` Kiril `а`, `alice@exаmple.com`, "Zalgo" metin) ve teslim edilemeyen özel alan adları.
- **Önerilen değişiklik:** (uygulandı) ASCII olmayan yerel kısım ve IDN alan adı etiketleri (Unicode biçimleri üzerinde) UTS #39 *moderately restrictive* olmalı; 2'den fazla ardışık birleşik işaret reddi; `localhost` / `invalid` TLD'leri reddi; `normalized()` = NFKC(lowercase(yerel)) — ayrıştırma hattının sabit noktası. Testler `acc_03_*`; fuzz hedefi normalized sabit nokta özelliğini de doğrular. `fuzz/Cargo.toml` değişmedi.
- **Geriye uyumluluk:** Daha sıkı ayrıştırma. Veritabanındaki adresler `EmailAddress` ile decode edilmediği için (mimari karar) mevcut satırlar okunmaya devam eder; yalnızca yeni girdiler etkilenir. Workspace'te bu kurallara takılan test girdisi yoktur (grep ile kontrol edildi).
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Hata kodları, `[account]` alanları, migration 1200 (bilgi)
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `crates/authn-core/src/error/codes/account.rs`, `crates/authn-core/src/config/account.rs`, `migrations/1200_account_lifecycle.sql`, `config/example.toml` `[account]` yorumları / authn-account
- **Gereksinim:** ACC-04 … ACC-13
- **Gerekçe:** Kendi dosyalarımda eklemeler (onay gerektirmez, bilgi amaçlı).
- **Önerilen değişiklik:** (uygulandı) 16 hata kodu (bkz. crate README). Yeni alanlar: `verification.{code_attempts_per_email, verify_per_ip, resend_per_ip}`, `registration_captcha_free_per_ip`, `registration_notice_per_email`, `email_change_per_user`, `link_actions_per_ip`, `display_name_max_chars`, `terms[]` (`TermsVersionConfig`, `TermsDocument` enum'u). Migration: `account_deletions.previous_status` + `account_deletions_user_idx`, yeni tablo `email_reservations` (account'a ait).
- **Geriye uyumluluk:** Tüm alanlar varsayılanlı; `authn-server/tests/example_config.rs` geçiyor.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — contracts §5'e `email_reservations` tablosu
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `docs/architecture/contracts.md` §5, `docs/architecture/overview.md` (ER diyagramı) / mimar
- **Gereksinim:** ACC-07
- **Gerekçe:** E-posta değişikliğinden sonra eski adres, geri alma süresi boyunca eski sahibine rezerve edilir; aksi hâlde saldırgan eski adresle yeni hesap açarak geri almayı imkânsız kılabilir.
- **Önerilen değişiklik:** §5 tablosunda authn-account satırına `email_reservations` eklenmesi; ER diyagramına `users ||--o{ email_reservations`.
- **Geriye uyumluluk:** Belge güncellemesi.
- **Durum:** Açık

### 2026-11-01 — Paylaşılan tablolarda salt-okunur sorgular ve adrese bağlı token iptali
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `users` / authn-store; `one_time_tokens` (diğer modüllerin purpose'ları) / authn-password, authn-session, authn-mfa
- **Gereksinim:** ACC-05, ACC-06, ACC-07, ACC-10
- **Gerekçe:** (1) Temizlik işleri aday satırları tek sorguda, çoklu instance güvenli seçmeli: `SELECT id FROM users WHERE status='pending_verification' AND email_verified_at IS NULL AND created_at < $1 … FOR UPDATE SKIP LOCKED` (ACC-05) ve `… WHERE status='locked' AND locked_until <= $1 … FOR UPDATE SKIP LOCKED` (ACC-06). Yazma yine `UserRepository` (`update_status`, `delete`) ile yapılır. (2) Dışa aktarma, `one_time_tokens`'tan **yalnızca account purpose'larının** aktif satırlarını (hash hariç) okur. (3) E-posta adresi değiştiğinde / geri alındığında, kullanıcının adresine gönderilmiş **tüm** token'lar `OneTimeTokenRepository::revoke_for_user` ile iptal edilir: `password_reset`, `password_reset_code`, `magic_link`, `login_code`, `not_me`, `mfa_email_otp` dahil (`authn_account::ADDRESS_BOUND_PURPOSES`). Aksi hâlde eski adrese (veya geri almada saldırganın adresine) gönderilmiş bir şifre sıfırlama linki hesabı yeniden ele geçirmeye yarar. İptal yalnızca erişimi kaldırır, hiçbir şey vermez.
- **Önerilen değişiklik:** (1) için authn-store'a `UserRepository::claim_by_status(conn, status, before, skip) -> Option<UserId>` eklenirse account ona geçer. (3) için contracts §5'e not: "adres değişikliği, adrese gönderilmiş tüm purpose'ları iptal eder (authn-account)".
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Açık (kod bu sorgularla çalışıyor)

### 2026-11-01 — `RegistrationAttempt` bildirimi ve olası yeni bildirim türleri
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/notifier.rs` ve şablonlar / authn-notify
- **Gereksinim:** ACC-02, ACC-07, NTF-01
- **Gerekçe:** `RegistrationAttempt` iki durumda gönderilir: kayıtlı adresle kayıt denemesi ve e-posta değişikliğinde başka bir hesabın adresinin istenmesi. Geri alma sonrası "şifrenizi sıfırlayın" uyarısı için tür yok.
- **Önerilen değişiklik:** Şablon metni genel olsun ("Bu adres bir hesap için kullanılmak istendi; siz değilseniz bir şey yapmanıza gerek yok"). İsteğe bağlı yeni tür: `EmailChangeReverted { at }` (account geri almada gönderir).
- **Geriye uyumluluk:** Şablon metni; yeni tür ekleme.
- **Durum:** Açık

### 2026-11-01 — Server / Dalga B bağlama notları
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,serve.rs}` / authn-server; authn-session; authn-admin; authn-org; tüm `DataExporter` uygulayıcıları
- **Gereksinim:** ACC-05, ACC-06, ACC-09, ACC-10, ACC-11, ARC-03, OPS-06, OPS-07
- **Gerekçe:** Dalga A modülleri birbirine bağımlı olamaz.
- **Önerilen değişiklik:** (1) `authn_account::OrganizationOwnership` — `async fn sole_owner_organizations(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<OrgId>, AuthError>`; authn-org ile, verilen bağlantı üzerinden (çağıran kullanıcı satırını kilitlemiştir). (2) `AccountService::new(AccountServiceDeps { … }, AccountServiceSettings::from_app_config(&config)?)?`, `impl FromRef<AppState> for AccountService`, `.merge(authn_account::router::<AppState>())` (`/v1/me*` oturum katmanının arkasında; `GET /v1/me` session'ındır), `openapi.rs`'e `authn_account::AccountApi`. (3) Açılışta `sync_terms_versions()`; işler: `purge_unverified_accounts`, `purge_due_deletions`, `release_expired_locks`, `purge_expired_reservations`; kapanışta `drain_background_jobs()`. (4) Her modül kendi tabloları için `DataExporter` uygular (bölüm adı `^[a-z][a-z0-9_]{0,63}$`, benzersiz, `account` ayrılmış) ve server `exporters` listesine ekler. (5) authn-session: doğru şifreden sonra `assess_login(&UserRecord)`; `Denied(reason)` → `reason.into_error(now)`; `required_actions` (`verify_email`, `accept_terms`) → SES-22; `accept_terms(ctx, user, …)`. (6) authn-admin: `change_status_in_tx` + aynı transaction'da `SessionRevoker`. (7) authn-password `ProfileLookup` adaptörü: `AccountService::profile_of`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

## authn-mfa

### 2026-11-01 — Migration 1300: kullanıcı başına MFA kilidi ve indeksler
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `migrations/1300_mfa_user_lock.sql` / authn-mfa (kendi tabloları, kendi aralığı)
- **Gereksinim:** MFA-03, MFA-05, OPS-06
- **Gerekçe:** Kullanıcı başına başarısız doğrulama penceresi ve geçici kilit kalıcı ve satır kilidiyle tam sayılmalı; kullanıcı başına tek e-posta faktörü; temizlik sorguları için indeks.
- **Önerilen değişiklik:** Uygulandı: `mfa_user_settings` + `failed_attempts`, `failure_window_start`, `locked_until`; `mfa_factors_one_email_idx` (kısmi benzersiz), `mfa_factors_pending_idx`, `trusted_devices_expiry_idx`. Bilgi amaçlı (contracts §6).
- **Geriye uyumluluk:** Ekleme (varsayılanlı kolonlar).
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — `[mfa]` yeni alanlar, sıkılaştırılmış doğrulama ve hata kodları (bilgi)
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-core/src/config/mfa.rs`, `crates/authn-core/src/error/codes/mfa.rs`, `config/example.toml` `[mfa]` yorumları / authn-mfa
- **Gereksinim:** MFA-01, MFA-03, MFA-05, MFA-06, MFA-07
- **Gerekçe:** E-posta kodu için kullanıcı başına gönderim bütçesi, SMS için kullanıcı bekleme süresi ve kullanıcı başına limit, bekleyen kayıt ömrü ve kullanıcı başına faktör sınırı yapılandırılabilir olmalı (ARC-07).
- **Önerilen değişiklik:** Uygulandı: `email_otp.sends_per_user` (10/saat), `sms.resend_cooldown` (60 sn), `sms.per_user` (5/saat), `enrollment_ttl` (15 dk), `max_factors_per_user` (10). `totp.issuer` artık `:` ve kontrol karakteri içeremez, ≤ 64 karakter (otpauth etiketi). Hata kodları: `mfa_factor_not_available` (403), `mfa_factor_already_enrolled` (409), `mfa_factor_limit_reached` (409), `mfa_last_factor_required` (409), `mfa_invalid_phone_number` (422), `mfa_phone_country_not_allowed` (422), `mfa_enrollment_not_pending` (409).
- **Geriye uyumluluk:** Yeni alanlar varsayılanlı; `config/example.toml` geçerli kalır.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Fuzz hedefi `mfa_input_parse` kaydı
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `fuzz/Cargo.toml` / mimar
- **Gereksinim:** TST-04, MFA-04, MFA-06, MFA-09
- **Gerekçe:** Kurtarma kodu, E.164 telefon ve güvenilir cihaz token'ı kullanıcı girdisidir. Hedef dosyası yazıldı (`fuzz/fuzz_targets/mfa_input_parse.rs`, sahibi authn-mfa) ve `fuzz/Cargo.toml`'un geçici bir kopyasında `cargo +nightly check` ile derlendi; aynı değişmezler `crates/authn-mfa/tests/properties.rs` içinde `proptest` ile de çalışıyor.
- **Önerilen değişiklik:** `fuzz/Cargo.toml`'a `authn-mfa = { path = "../crates/authn-mfa" }` ve `[[bin]] name = "mfa_input_parse", path = "fuzz_targets/mfa_input_parse.rs", test = false, doc = false, bench = false`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — authn-server'ın uygulayacağı `MfaPolicySource` ve bağlama
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,jobs}` / authn-server
- **Gereksinim:** MFA-07, MFA-08, MFA-09, ARC-03, OPS-06
- **Gerekçe:** Son faktör kuralı ve güvenilir cihaz izni organizasyon politikasına (authn-org) ve passkey sayısına (authn-webauthn) bağlıdır; Dalga A modülleri birbirini göremez.
- **Önerilen değişiklik:** (1) `authn_mfa::MfaPolicySource` uygulaması: `async fn org_policy_for_user(&self, conn: &mut PgConnection, user: UserId) -> Result<Option<OrgMfaPolicy>, AuthError>` (aktif üyeliklerin `org_policies` kayıtlarının `OrgMfaPolicy::strictest` birleşimi) ve `async fn webauthn_factor_count(&self, conn: &mut PgConnection, user: UserId) -> Result<u32, AuthError>`; ikisi de verilen bağlantıdan okur (çağıran kullanıcı satırlarını kilitlemiştir). (2) `MfaService::new(MfaServiceDeps { pool, clock, keys, otp, envelopes, rate_limiter, notifier, audit, sms: Some(sms_sender), policy_source }, MfaServiceSettings::from_app_config(&config))`, `impl FromRef<AppState> for MfaService`, `.merge(authn_mfa::router::<AppState>())` oturum katmanının arkasında, `openapi.rs`'e `authn_mfa::MfaApi`; `passkey` feature'ı kapalıysa `settings.webauthn_available = false`. (3) Arka plan işi `MfaService::purge_expired()`. (4) authn-account dışa aktarma toplayıcısına `authn_mfa::MfaDataExporter`. (5) Workspace girdisi `default-features = false` olduğundan authn-server'ın `authn-mfa`'yı `features = ["sms"]` ile alması (ARC-11).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

### 2026-11-01 — authn-session / authn-admin için MFA API'si
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session; `crates/authn-admin` / authn-admin
- **Gereksinim:** SES-02, SES-13, SES-15, SES-21, SES-22, MFA-09, ADM-03
- **Gerekçe:** Giriş challenge durumu authn-session'dadır; faktör doğrulama, kod gönderme, politika ve güvenilir cihaz mantığı tek yerde (authn-mfa) kalmalı.
- **Önerilen değişiklik:** Giriş: `evaluate_for_user(user, Option<OrgMfaPolicy>, phishing_resistant_required) -> MfaRequirement` (`EnrollmentRequired` + boş liste ⇒ reddet; kullanıcının izin dışı kalmış faktörleri varsa önce biri doğrulatılsın), `is_trusted_device(user, token, trusted_devices_allowed)`, `send_code(&ctx, user, Some(challenge_id), OtpChannel::{Email, Sms{factor_id}})`, `verify_factor(&ctx, user, Some(challenge_id), FactorProof) -> VerifiedFactor { kind, factor_id, amr, recovery_codes_remaining }` (`amr` birleştirmesi `authn_mfa::amr::combine`), başarılı MFA + "hatırla" için `trust_device(&ctx, user, trusted_devices_allowed) -> Option<IssuedTrustedDevice>` (cookie `authn_mfa::TRUSTED_DEVICE_COOKIE`, başlık `TRUSTED_DEVICE_HEADER`). `SessionRevoker` uygulamasında `RevokeOptions::also_trusted_devices` ⇒ aynı bağlantıyla `revoke_trusted_devices_in_tx(conn, user, reason)` (authn-password'un PWD-09 talebiyle aynı). `GET /v1/me` için `status_for_user(user)`. Admin: `reset_user_mfa_in_tx(conn, &ctx, user) -> MfaResetSummary` (audit olayını gerekçesiyle admin yazar).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — authn-testkit: `RecordingNotifier` SMS kaydı
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-testkit/src/fakes/notifier.rs` / authn-testkit (mimar)
- **Gereksinim:** MFA-06, TST-01
- **Gerekçe:** authn-mfa SMS kodlarını `Notifier::notify_sms_in_tx` ile (outbox) gönderir; `RecordingNotifier` bu metodu uygulamadığından testlerde varsayılan gövde `sms_unavailable` döner. authn-mfa testleri şimdilik kendi `TestNotifier` sarmalayıcısını kullanıyor (`crates/authn-mfa/tests/common/mod.rs`). authn-notify'ın aynı öneriyi içeren kaydını destekler.
- **Önerilen değişiklik:** `RecordingNotifier`'a `sms: Mutex<Vec<SmsNotification>>`, `recorded_sms()` ve `notify_sms_in_tx` uygulaması.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — Güvenlik incelemesi sonrası bağlama notları (authn-session / authn-server)
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session; `MfaPolicySource` uygulaması / authn-server
- **Gereksinim:** MFA-08, MFA-09, SES-02, SES-21
- **Gerekçe:** (1) `verify_factor` kanıtın geçerliliğini denetler, kanıt türünün o girişte izinli olup olmadığını değil (organizasyon bağlamı yalnızca session'da bilinir). (2) Güvenilir cihazlar artık kullanıcının **tüm** üyeliklerinin en katı politikasına da bağlıdır: herhangi bir organizasyon `trusted_devices_allowed = false` ise cihaz ne verilir ne kabul edilir (çağıranın bayrağı yalnızca giriş bağlamıdır).
- **Önerilen değişiklik:** (1) authn-session, `proof.kind()` challenge'ın `MfaRequirement::allowed_factors()` listesinde değilse `verify_factor`'ı çağırmadan reddetmeli (admin'ler için yalnızca phishing'e dayanıklı faktör; kurtarma kodu yalnızca listedeyse). (2) `MfaPolicySource::org_policy_for_user` `is_trusted_device` tarafından transaction'sız düz bir bağlantıyla da çağrılır; uygulama yalnızca verilen bağlantıdan okumalıdır (mevcut sözleşmeyle uyumlu).
- **Geriye uyumluluk:** İmza değişikliği yok; davranış yalnızca sıkılaştı.
- **Durum:** Bilgi


## authn-webauthn

### 2026-11-01 — `[webauthn]` yeni alanlar, sıkılaştırılmış doğrulama, hata kodları ve migration 1400 (bilgi)
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-core/src/config/webauthn.rs`, `crates/authn-core/src/error/codes/webauthn.rs`, `config/example.toml` `[webauthn]` yorumları, `migrations/1400_webauthn_hardening.sql` / authn-webauthn
- **Gereksinim:** PKY-01, PKY-04, PKY-05, PKY-06, PKY-07, PKY-08
- **Gerekçe:** Kayıt/giriş sınırları, ilk passkey için step-up seçeneği, uygulama bağlantıları ve kuruluş AAGUID izin listesi için güvenilir attestation kökleri yapılandırılabilir olmalı (ARC-07); yanlış RP yapılandırması ya tüm passkey'leri bozar ya da phishing yüzeyini büyütür.
- **Önerilen değişiklik:** Uygulandı: alanlar `app_link_paths`, `well_known_max_age` (1 sa), `max_credentials_per_user` (20), `step_up_for_first_passkey` (true), `registration_per_user` (10/sa), `authentication_per_ip` (60/15 dk), `[[attestation_roots]] {name, ca_pem, aaguids}`; doğrulama: `rp_id` geçerli küçük harfli alan adı (IP değil), web origin'leri `rp_id` veya alt alan adı ya da `related_origins` içinde (düz `http` yalnızca `localhost`), `android:apk-key-hash:` 43 karakter base64url SHA-256, en az bir origin `rp_id` ile aynı site, Apple app id / Android paket / SHA-256 parmak izi / yol biçimleri, liste uzunluk sınırları. Yardımcılar `is_valid_rp_id`, `web_origin_host`, `host_matches_rp_id`, `ANDROID_ORIGIN_PREFIX` dışa açık. Hata kodları: `passkey_ceremony_invalid` (400), `passkey_registration_failed` (400), `passkey_authentication_failed` (401), `passkey_already_registered` (409), `passkey_limit_reached` (409), `passkey_last_login_method` (409), `passkey_not_allowed` (403), `passkey_not_available` (400). Migration 1400: `webauthn_credentials.clone_suspected_at`, `discoverable`; `webauthn_ceremonies` bağlama CHECK'leri (kayıt ⇒ kullanıcı + oturum, step-up ⇒ kullanıcı + oturum, kimlik doğrulama ⇒ `binding_hash`, kind/purpose tutarlılığı).
- **Geriye uyumluluk:** Yeni alanlar varsayılanlı; `config/example.toml` ve test konfigürasyonu geçerli kalır. Var olan yapılandırmalarda `rp_id` ile aynı sitede olmayan ve `related_origins`'te listelenmeyen origin'ler artık reddedilir (zaten hiçbir tarayıcıda çalışmazlardı).
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Fuzz hedefi `webauthn_response_parse` kaydı
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `fuzz/Cargo.toml`, `fuzz/deny.toml` / mimar
- **Gereksinim:** TST-04, PKY-01, PKY-04, PKY-06
- **Gerekçe:** İstemcinin gönderdiği WebAuthn JSON'u (içindeki CBOR attestation nesnesi ve authenticator verisi dahil), passkey adları ve RP yapılandırma değerleri saldırgan kontrollü girdidir. Hedef dosyası yazıldı (`fuzz/fuzz_targets/webauthn_response_parse.rs`, sahibi authn-webauthn) ve `fuzz/Cargo.toml`'un geçici bir kopyasında `cargo +nightly check` ile derlendi.
- **Önerilen değişiklik:** `fuzz/Cargo.toml`'a `authn-webauthn = { path = "../crates/authn-webauthn" }`, `webauthn-rs = { version = "0.6.2", features = ["conditional-ui", "danger-allow-state-serialisation", "danger-credential-internals", "resident-key-support"] }` ve `[[bin]] name = "webauthn_response_parse", path = "fuzz_targets/webauthn_response_parse.rs", test = false, doc = false, bench = false`; `fuzz/deny.toml`'a kök `deny.toml`'daki webauthn-rs ailesi MPL-2.0 istisnalarının aynısı.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — authn-server'ın uygulayacağı trait'ler ve bağlama
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,jobs}` / authn-server
- **Gereksinim:** PKY-04, PKY-07, PKY-08, ARC-03, OPS-06, MFA-07, PWD-11
- **Gerekçe:** Son giriş yöntemi kuralı şifreye (authn-password/store), bağlı kimliklere (authn-oidc-client) ve MFA zorunluluğuna (authn-mfa/authn-org) bağlıdır; kuruluş AAGUID politikası authn-org'dadır. Dalga A modülleri birbirini göremez.
- **Önerilen değişiklik:** (1) `authn_webauthn::AccountMethodsSource`: `async fn other_login_methods(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<LoginMethod>, AuthError>` (passkey dışındaki yöntemler: şifre, bağlı sosyal kimlikler, deployment'a göre magic link/e-posta kodu) ve `async fn mfa_facts(&self, conn, user) -> Result<MfaFacts, AuthError>` (`mfa_required`, passkey dışı etkin faktör sayısı; authn-mfa `MfaService`/politika); ikisi de verilen bağlantıdan okur (çağıran `users` satırını `FOR UPDATE` kilitlemiştir). Varsayılan `PasswordOnlyMethods` yalnızca şifreyi bilir (güvenli tarafta kalır). (2) `authn_webauthn::PasskeyPolicySource`: `async fn policy_for_user(&self, conn, user, active_org: Option<OrgId>) -> Result<PasskeyPolicy, AuthError>` (örn. etkin üyeliklerin `PasskeyPolicy::strictest` birleşimi); varsayılan `UnrestrictedPolicySource`. (3) `WebauthnService::new(WebauthnServiceDeps { pool, clock, rate_limiter, notifier, audit, account_methods, policy_source }, WebauthnServiceSettings::from_app_config(&config)?)`, `impl FromRef<AppState> for WebauthnService`, `.merge(authn_webauthn::router::<AppState>())` oturum + CSRF katmanının arkasında; `impl FromRef<AppState> for WellKnownDocuments` (`service.well_known()`), `.merge(authn_webauthn::well_known_router::<AppState>())` kökte, kimlik doğrulamasız; `openapi.rs`'e `authn_webauthn::WebauthnApi`. (4) Arka plan işi `WebauthnService::purge_expired_ceremonies()`. (5) authn-account dışa aktarma toplayıcısına `authn_webauthn::PasskeyDataExporter`. (6) authn-mfa `MfaPolicySource::webauthn_factor_count` ⇒ `service.passkey_count_in(conn, user, false)`; authn-password `LoginMethodInventory` ⇒ `passkey_count_in(conn, user, true) > 0` ise `LoginMethod::Passkey`. (7) Workspace girdisi `default-features = false` olduğundan authn-server `authn-webauthn`'u `features = ["passkey"]` ile almalı (ARC-11).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

### 2026-11-01 — authn-session için passkey kimlik doğrulama API'si
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session
- **Gereksinim:** SES-02, SES-13, SES-20, SES-21, PKY-01, PKY-02, PKY-05
- **Gerekçe:** Passkey ile giriş, ikinci faktör ve step-up uç noktaları authn-session'dadır; WebAuthn doğrulaması, seremoni durumu ve klon tespiti tek yerde (authn-webauthn) kalmalı.
- **Önerilen değişiklik:** `start_authentication(&ctx, AuthenticationTarget, &PasskeyPolicy) -> AuthenticationStart { ceremony_id, binding_token, options, expires_at }` ve `finish_authentication(&ctx, AuthenticationFinish { ceremony_id, binding_token, target, credential }) -> AuthenticatedPasskey { user_id, credential_id, purpose, user_verified, backup_eligible, backup_state, amr }`. Hedefler: `Discoverable { conditional_ui }` (kullanıcı adısız giriş, UV zorunlu), `SecondFactor { user_id, challenge_id }` (giriş challenge'ına bağlı), `StepUp { user_id, session_id }` (oturuma bağlı, UV zorunlu). `binding_token` web'de `HttpOnly; Secure; SameSite=Strict` kısa ömürlü bir çerezde, native'de yanıt gövdesinde taşınmalı ve bitişte aynen geri verilmeli; `target` istemciden değil, session'ın kendi kaydından (challenge/oturum) kurulmalı. Başarıdan sonra hesap durumu, oturum/challenge geçerliliği, `login.*`/`step_up.*`/`mfa.*` audit olayları ve AMR birleştirmesi session'ın işidir (`amr` alanı `hwk`/`swk` + `user` + UV'de `mfa`). Hatalar: `passkey_ceremony_invalid`, `passkey_authentication_failed` (giriş akışında `invalid_credentials`'a eşlenebilir), `passkey_not_available`, `rate_limited`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — `NotificationKind` için passkey'e özel tür (öneri)
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/notifier.rs` / authn-notify
- **Gereksinim:** PKY-04, NTF-01
- **Gerekçe:** Passkey ekleme/kaldırma bildirimleri şimdilik `MfaFactorAdded/MfaFactorRemoved { factor: FactorKind::Webauthn }` ile gönderiliyor (NTF-01 "MFA eklendi/kaldırıldı" kapsamında). Şablonda "passkey" ifadesi ve şüpheli klon (PKY-05) için ayrı bir uyarı e-postası kullanıcı deneyimini iyileştirir.
- **Önerilen değişiklik:** İsteğe bağlı: `NotificationKind::PasskeyCloneSuspected { at }` ve şablonları; eklenirse authn-webauthn klon tespitinde kullanıcıyı da bilgilendirir.
- **Geriye uyumluluk:** Yeni varyant (tam eşleşme yapan tüketiciler için kırıcı olabilir, §13).
- **Durum:** Açık

## authn-org

### 2026-11-01 — Hata kodları, `[org]` alanları, migration 1500 (bilgi)
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-core/src/error/codes/org.rs`, `crates/authn-core/src/config/org.rs`, `config/example.toml` `[org]` yorumları, `migrations/1500_org_tenant_hardening.sql` / authn-org
- **Gereksinim:** ORG-01 … ORG-12, ARC-10
- **Gerekçe:** Kendi dosyalarımda eklemeler (onay gerektirmez).
- **Önerilen değişiklik:** (uygulandı) 28 hata kodu (liste: `crates/authn-org/README.md`). Yeni alanlar: `invitation_resend_cooldown`, `creates_per_user`, `token_attempts_per_user`, `domain_checks_per_org`, `dns_timeout`, `ownership_transfers_per_org`, `limits.*`, `api_keys.last_used_update_interval`, `api_keys.auth_failures_per_ip`. Migration: `api_keys_single_owner_check`, `api_keys_member_fk` (kişisel anahtar üyelikle silinir), `service_accounts_not_owner_check`, `role_permissions_owner_only` tetikleyicisi, **`memberships_last_owner` ertelenmiş kısıt tetikleyicisi** (var olan organizasyon commit anında en az bir aktif sahibe sahip olmalı) ve indeksler.
- **Etki (authn-account için önemli):** son sahip tetikleyicisi, bir organizasyonun tek aktif sahibinin `users` satırının silinmesini **commit anında** `check_violation` (`org_last_owner_check`) ile reddeder. ACC-09 akışı zaten `OrganizationOwnership::sole_owner_organizations` ile önceden kontrol ediyor; tetikleyici yalnızca ikinci savunma hattıdır. Organizasyon silme (kaskad) etkilenmez. `authn-store/tests/schema.rs` testleri bu kısıtlarla uyumlu.
- **Geriye uyumluluk:** Varsayılanlı yeni alanlar; mevcut konfigürasyonlar geçerli (`authn-server/tests/example_config.rs`). Migration eklemeli.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Server / Dalga B bağlama notları
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,jobs}` / authn-server; `crates/authn-session` / authn-session
- **Gereksinim:** ORG-05, ORG-06, ORG-07, ORG-08, ORG-12, ARC-03, OPS-06, SES-10, SES-17, MFA-08, ACC-09, AUD-04
- **Gerekçe:** Dalga A modülleri birbirini göremez.
- **Önerilen değişiklik:** (1) `OrgService::new(OrgServiceDeps { pool, clock, audit, events, notifier, rate_limiter, session_revoker, dns: Arc::new(HickoryDnsTxtResolver::from_system_conf(config.org.dns_timeout)?) }, OrgServiceSettings::from_app_config(&config))`, `impl FromRef<AppState> for OrgService`, `.merge(authn_org::router::<AppState>())`, `openapi.rs`'e `authn_org::OrgApi`. (2) `authn_org::api_key_middleware` (`from_fn_with_state(org_service, …)`) request-context'ten sonra, session kimlik doğrulama katmanının yanında. (3) İşler: `purge_due_deletions(limit)`, `expire_invitations()`. (4) `authn_account::OrganizationOwnership` → `authn_org::sole_owner_organizations(conn, user)`. (5) `authn_mfa::MfaPolicySource::org_policy_for_user` → `authn_org::policies_for_user(conn, user)` → `OrgMfaPolicy` eşlemesi + `strictest`. (6) `authn_audit::AuditAccessPolicy` → `OrgService::authorize_from(principal, Permission::{AuditRead,WebhooksRead,WebhooksManage}, org, None)`. (7) `OrgDataExporter` dışa aktarma listesine. (8) authn-session: SES-10 istemci kimlik doğrulaması `authenticate_api_key(&ctx, raw)`; SES-17 `check_membership(principal, org, Some(ip))` + `Authorization::policy` (`allows_login_method`, `session_lifetime_cap`, `allows_ip`); girişten / e-posta doğrulamasından sonra `auto_join_verified_domains(user)`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

### 2026-11-01 — `AuditAccessPolicy::check` için istemci IP'si
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-audit/src/policy.rs` / authn-audit
- **Gereksinim:** ORG-07, AUD-04, AUD-07
- **Gerekçe:** Organizasyon IP izin listesi her organizasyon isteğinde uygulanır ve IP bilinmiyorsa kapalı başarısız olur. `AuditAccessPolicy::check` IP almadığı için, IP izin listesi olan organizasyonlarda audit / webhook uç noktaları her zaman reddedilir.
- **Önerilen değişiklik:** `check(&self, principal, org, permission, client_ip: Option<IpAddr>)` (veya `&RequestContext`) — server adaptörü `authorize_from(…, client_ip)` çağırır.
- **Geriye uyumluluk:** İmza değişikliği (authn-audit iç trait'i; tek uygulayıcı server).
- **Durum:** Uygulandı (2026-11-01, authn-audit güvenlik incelemesi: `check(&self, principal, org, permission, client_ip: Option<IpAddr>)`; handler'lar `Some(ctx.client_ip)` iletir)

### 2026-11-01 — `RevocationReason` için rol değişikliği nedeni
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/session_revoker.rs` / authn-session
- **Gereksinim:** ORG-02, ORG-04, SES-03
- **Gerekçe:** Rol düşürme, özel rolden izin çıkarma ve sahiplik devrinde eski sahibin düşürülmesi oturumları kapatır; şu an en yakın neden `MembershipRemoved` kullanılıyor.
- **Önerilen değişiklik:** `RevocationReason::MembershipChanged => "membership_changed"` eklenmesi; eklenirse authn-org ona geçer.
- **Geriye uyumluluk:** Ekleme (yeni enum varyantı; `match` yapan tüketici yok).
- **Durum:** Açık

### 2026-11-01 — Audit olay türleri: domain ekleme, silme iptali, devir iptali
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/audit.rs` (`SecurityEventKind`) / authn-audit
- **Gereksinim:** AUD-01, ORG-06, ORG-11, ORG-12
- **Gerekçe:** Bu olaylar şimdilik `org.updated` + `metadata.action` (`domain_added`, `deletion_cancelled`, `ownership_transfer_cancelled`) olarak yazılıyor; domain otomatik katılım değişikliği `org.policy_changed` olarak.
- **Önerilen değişiklik:** `OrgDomainAdded => "org.domain_added"`, `OrgDeletionCancelled => "org.deletion_cancelled"`, `OrgOwnershipTransferCancelled => "org.ownership_transfer_cancelled"`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-11-01, authn-audit: `OrgDomainAdded`, `OrgDeletionCancelled`, `OrgOwnershipTransferCancelled`)

### 2026-11-01 — `UserRepository` toplu okuma
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-store/src/users.rs` / authn-store
- **Gereksinim:** ORG-02
- **Gerekçe:** Üye listesi e-posta adreslerini satır başına `find_by_id` ile okur (sayfa ≤ 100 sorgu); `users` tablosuna doğrudan SQL yazılmadı.
- **Önerilen değişiklik:** `UserRepository::find_many(executor, &[UserId]) -> Vec<UserRecord>` (`WHERE id = ANY($1)`).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık

### 2026-11-01 — `org_ownership_transfer` token'larında `group_id` sözleşmesi ve fuzz kilidi (bilgi)
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `one_time_tokens` (purpose `org_ownership_transfer`) / authn-org; `fuzz/Cargo.lock` / mimar
- **Gereksinim:** ORG-11, TST-04
- **Gerekçe:** Devir token'larının `group_id`'si organizasyon kimliğidir (`target` = organizasyon kimliği, `metadata.from_user_id` = başlatan); `revoke_group(org)` organizasyonun tüm bekleyen devirlerini iptal eder. `api_key_parse` fuzz hedefinin gövdesi yazıldı; `cargo +nightly fuzz build api_key_parse` `fuzz/Cargo.lock`'u authn-org'un güncel bağımlılıklarıyla yeniden üretti (`fuzz/Cargo.toml` değişmedi).
- **Önerilen değişiklik:** contracts §5 purpose tablosuna not olarak eklenebilir.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Uygulandı (2026-11-01)

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

### 2026-11-01 — `AuditSink::pseudonymize_subject` ve iki yeni olay türü
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/audit.rs` / authn-audit (portu uygulayan)
- **Gereksinim:** AUD-05, AUD-07, ACC-09
- **Gerekçe:** Hesap silme, kullanıcının audit takma adını zincir bozulmadan bağlantısız hâle getirmeli. `users` satırı kaskadla silindiğinde bu zaten olur; ancak hesabın `deleted` durumuyla anonimleştirildiği (satırın kaldığı) akışta açık bir çağrı gerekir. Webhook otomatik devre dışı bırakma ve elle yeniden teslim de güvenlik açısından izlenmesi gereken olaylardır.
- **Önerilen değişiklik:** (uygulandı) `async fn pseudonymize_subject(&self, conn: &mut PgConnection, user: UserId) -> Result<(), AuthError>` — varsayılan gövde `Ok(())` (sahteler), gerçek uygulama `authn_audit::PgAuditSink`. Çağıranın transaction'ında `audit_subjects` eşlemesini ve ona bağlı `audit_event_pii` satırlarını siler; aynı transaction'da sonradan kaydedilen olaylar o kullanıcı için yeni eşleme oluşturmaz. `SecurityEventKind`'e `WebhookEndpointAutoDisabled` (`webhook.endpoint_auto_disabled`) ve `WebhookRedeliveryRequested` (`webhook.redelivery_requested`) eklendi.
- **authn-account için:** ACC-09 silme transaction'ında `record_in_tx(AccountDeleted)` + `pseudonymize_subject(user)` + kullanıcı silme/anonimleştirme sırası önerilir (sıra fark etmez; `pseudonymize_subject` sonrası kayıtlar tek kullanımlık takma ad alır ve kişisel veri saklamaz).
- **authn-testkit için (öneri):** `RecordingAuditSink` `pseudonymize_subject` çağrılarını kaydedebilir (şu an varsayılan gövde kullanılıyor).
- **Geriye uyumluluk:** Ekleme; mevcut uygulayıcılar/sahteler varsayılan gövdeyle derlenir. Yeni enum varyantları yalnızca `SecurityEventKind` üzerinde tam eşleşme (`match`) yapan koda etki eder (bilinen tüketici yok).
- **Durum:** Uygulandı (2026-11-01, authn-audit görevi)

### 2026-11-01 — Takma ad çözümü için `users` tablosunun salt-okunur kullanımı
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** `users` tablosu / authn-store
- **Gereksinim:** AUD-03, AUD-05
- **Gerekçe:** `PgAuditSink`, olaydaki kullanıcı kimliklerini (aktör, taklitçi, özne ve kaynak/metadata içindeki kullanıcı kimlikleri) tek sorguda takma ada çevirir: `SELECT u.id, u.status = 'deleted' … FROM unnest($1::uuid[]) JOIN users u … LEFT JOIN audit_subjects s …`. `UserRepository::find_by_id` her UUID için ayrı sorgu gerektirirdi (metadata'da onlarca UUID olabilir). Yalnızca `id` ve `status` okunur; yazma yoktur. `audit_subjects.user_id → users` FK'sı zaten bu ilişkiyi şemada tanımlar.
- **Önerilen değişiklik:** contracts §5'e not: "authn-audit, takma ad çözümü için `users.id`/`users.status`'u salt-okunur sorgular". Alternatif: authn-store'a `UserRepository::statuses(conn, &[UserId]) -> Vec<(UserId, AccountStatus)>` eklenirse audit ona geçer.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Açık (kod bu okuma ile çalışıyor)

### 2026-11-01 — Yol parametresi adları: `/v1/orgs/{org_id}/…`
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** authn-org ve diğer `/v1/orgs/…` router'ları / authn-server (birleştirme)
- **Gereksinim:** ARC-03, ARC-09
- **Gerekçe:** axum 0.8 (matchit), aynı konumdaki yol parametrelerinin farklı adlarla kaydını çakışma sayar (`/v1/orgs/{id}/members` ile `/v1/orgs/{org_id}/webhooks` birleştirilemez; `merge` panikler). authn-audit şu yolları kullanır: `/v1/orgs/{org_id}/audit-events`, `/v1/orgs/{org_id}/webhooks[/{endpoint_id}[/rotate-secret|/deliveries[/{delivery_id}/redeliver]]]`, `/v1/me/security-events`.
- **Önerilen değişiklik:** contracts §7'ye "organizasyon yol parametresi her router'da `{org_id}`" kuralı eklensin.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Açık

### 2026-11-01 — Migration 1700 ve en az yetki yardımcı fonksiyonu
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** `migrations/1700_audit_webhooks_least_privilege.sql` (authn-audit aralığı); OPS-10 belgeleri / authn-server, authn-store
- **Gereksinim:** AUD-02, AUD-07, OPS-10
- **Gerekçe:** `webhook_endpoints`'e `failing_since`, `last_success_at` kolonları (sürekli hata sonrası otomatik devre dışı bırakma), teslim geçmişi ve kiralama indeksleri eklendi. AUD-02/OPS-10'daki "ayrı rol önerisi" çalıştırılabilir hâle getirildi: `SELECT authn_audit_apply_least_privilege('<uygulama_rolü>', '<bakım_rolü>')` uygulama rolünden `audit_events`/`audit_chain_checkpoints` üzerindeki `UPDATE`/`DELETE`/`TRUNCATE` yetkisini kaldırır; saklama temizliği bakım rolüyle çalışır (`AuditService::run_maintenance(maintenance_pool)`).
- **Önerilen değişiklik:** authn-server: bakım işi için ayrı havuz (yapılandırılmışsa) ve OPS-10 dokümantasyonunda bu fonksiyona atıf.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Güvenlik incelemesi: `AuditAccessPolicy` imzası, yeni olay türleri, migration 1700 sıkılaştırması
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** `crates/authn-audit/src/policy.rs`, `crates/authn-core/src/ports/audit.rs` (authn-audit); `migrations/1700_audit_webhooks_least_privilege.sql` (authn-audit aralığı); tüketici: authn-server (policy uygulaması), authn-org (olay türleri), authn-account (ACC-09)
- **Gereksinim:** AUD-01, AUD-02, AUD-04, AUD-05, AUD-07, ORG-07, OPS-10
- **Gerekçe:** Bağımsız güvenlik incelemesi bulguları (ayrıntı: `crates/authn-audit/README.md` → "Güvenlik notları").
- **Değişiklik:** (1) `AuditAccessPolicy::check(&self, principal, org, permission, client_ip: Option<IpAddr>)` — authn-org talebi; server adaptörü `OrgService::authorize_from(principal, permission, org, client_ip)` çağırır. (2) `SecurityEventKind`'e `org.domain_added`, `org.deletion_cancelled`, `org.ownership_transfer_cancelled` (authn-org talebi; authn-org `org.updated` + `metadata.action` yerine bunlara geçebilir). (3) `authn_audit_apply_least_privilege` artık iki rolden de tüm audit/outbox/webhook tablolarındaki **tüm** yetkileri önce geri alır (migration 1700 henüz yayımlanmamıştı; yerinde düzeltildi). (4) `status = deleted` olan kullanıcı, eşlemesi kalmış olsa bile bir daha bağlanmaz (port belgesi güncellendi). (5) Üreticiler için: kullanıcı kimliklerini metadata'da yalnızca tam UUID olarak ve `…user_id(s)` / `owner` adlı anahtarlarla verin; `format!("{id:?}")`, `urn:uuid:…` gibi gömülü biçimler `[REDACTED]` olur; personel işlemleri `admin.*` türüyle veya impersonator ile kaydedilmelidir.
- **Geriye uyumluluk:** (1) imza değişikliği — tek uygulayıcı henüz yazılmamış server adaptörü; (2) ekleme; (3)–(5) davranış sıkılaştırması.
- **Durum:** Uygulandı (2026-11-01)

## authn-notify

### 2026-11-01 — `Notifier::notify_sms_in_tx` ve SMS bildirim tipleri (port eklemesi)
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/notifier.rs` / authn-notify (portu uygulayan); `crates/authn-core/src/ports/mod.rs` (yeniden dışa aktarma satırı) / mimar
- **Gereksinim:** NTF-01, NTF-04, MFA-06
- **Gerekçe:** SMS kodlarının da e-posta gibi outbox üzerinden (istek yolunu bloklamadan, yeniden denenerek, kod zarf şifreli olarak) gönderilebilmesi için. Port yalnızca e-posta alıcısı (`Recipient.email`) taşıyordu.
- **Önerilen değişiklik:** (uygulandı) `SmsNotification { to: PhoneNumber, user_id: Option<UserId>, locale: Locale, kind: SmsNotificationKind }`, `SmsNotificationKind::{MfaSmsCode, PhoneVerification} { code: SensitiveString, expires_at }` + `template_name()`, `Notifier::notify_sms_in_tx(&self, conn, sms) -> Result<(), AuthError>` — varsayılan gövde `sms_unavailable` döner. `ports/mod.rs`'e yalnızca `SmsNotification, SmsNotificationKind` yeniden dışa aktarımı eklendi (tipler aksi halde erişilemezdi).
- **Geriye uyumluluk:** Ekleme; mevcut uygulayıcılar/sahteler varsayılan gövdeyle derlenir. `SmsSender`'ı doğrudan çağırmak (senkron) geçerli kalır.
- **authn-testkit için (öneri):** `RecordingNotifier` `notify_sms_in_tx` çağrılarını kaydetsin (şu an varsayılan gövde `sms_unavailable` döner).
- **Durum:** Uygulandı (2026-11-01, authn-notify görevi) — testkit önerisi Açık

### 2026-11-01 — Yeni hata kodları ve `[notify]` alanları (bilgi)
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `crates/authn-core/src/error/codes/notify.rs`, `crates/authn-core/src/config/notify.rs`, `config/example.toml` `[notify]` yorumları / authn-notify
- **Gereksinim:** NTF-02, NTF-03, NTF-04
- **Gerekçe:** Kalıcı/geçici teslim hatalarının ayrımı ve yapılandırılabilir SMS sağlayıcısı.
- **Önerilen değişiklik:** (uygulandı) Kodlar `delivery_rejected` (502), `sms_unavailable` (503). Alanlar: `notify.app_name`, `notify.max_attempts`, `notify.recipient_limit`, `notify.email.smtp.extra_ca_file`, `notify.email.smtp.hello_name`, `notify.sms.http_auth_header`, `notify.sms.http_auth_scheme`, `notify.sms.http_body_template`, `notify.sms.http_message_id_pointer`; daha sıkı doğrulama (başlık güvenli adlar, link yollarında boşluk yok, `sender_id` uzunluğu). `NotifyConfig`'in `Default`'u elle yazıldı (değerler aynı + yeni alanlar).
- **Geriye uyumluluk:** Tüm yeni alanlar varsayılanlı; mevcut konfigürasyonlar geçerli kalır.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Ortama bağlı `[notify]` kurallarının `AppConfig::validate`'e taşınması
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `crates/authn-core/src/config/mod.rs` (`validate_cross_section`) / mimar
- **Gereksinim:** NTF-03, NTF-04, ARC-07
- **Gerekçe:** `NotifyConfig::validate` `server.environment`'ı göremez. Şu kurallar şimdilik authn-notify builder'larında açılışta (fail-fast) uygulanıyor; `check-config`'in de görmesi için çapraz bölüm doğrulamasına eklenmeleri önerilir.
- **Önerilen değişiklik:** production **ve staging**'de `notify.email.transport = "log"` ve `notify.sms.provider = "log"` reddi; production'da `notify.email.transport = "disabled"` reddi; development/test dışında `notify.email.smtp.extra_ca_file` reddi.
- **Geriye uyumluluk:** Builder'lar zaten reddediyor; davranış değişmez, yalnızca hata daha erken görünür.
- **Durum:** Açık

### 2026-11-01 — Mailpit için sabit geliştirme sertifikası
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `docker-compose.yml` / mimar
- **Gereksinim:** NTF-03, OPS-08
- **Gerekçe:** SMTP taşıyıcısı TLS'i zorunlu kılar ve sertifikayı doğrular. Mailpit `MP_SMTP_TLS_CERT: "sans:localhost"` ile her açılışta yeni bir kendinden imzalı sertifika üretir; `notify.email.smtp.extra_ca_file` ile güvenilecek sabit bir dosya yoktur, bu yüzden `config/example.toml` (`smtp`, `localhost:1025`) yerelde TLS doğrulamasında başarısız olur.
- **Önerilen değişiklik:** Depoya yalnızca geliştirme amaçlı (herkese açık) bir `localhost` sertifikası/anahtarı (ör. `config/dev-certs/mailpit.{pem,key}`) eklenip Mailpit'e bağlanması (`MP_SMTP_TLS_CERT=/certs/mailpit.pem`, `MP_SMTP_TLS_KEY=/certs/mailpit.key`) ve `config/example.toml`'da `extra_ca_file = "config/dev-certs/mailpit.pem"` satırının açılması. Alternatif: örnek konfigürasyonda `transport = "log"`.
- **Geriye uyumluluk:** Yalnızca geliştirme ortamı.
- **Durum:** Açık

### 2026-11-01 — authn-server ve authn-mfa için bağlama notları
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,…}` / authn-server; `crates/authn-mfa` / authn-mfa
- **Gereksinim:** NTF-01, NTF-03, NTF-04, AUD-06, OPS-06
- **Gerekçe:** Teslim `authn-audit`'in outbox işçisinde yapılır; authn-notify ona bağımlı olamaz.
- **Önerilen değişiklik:** (1) Açılışta Tokio runtime içinde `authn_notify::NotifyServices::from_config(&config, pool, crypto.envelopes, clock, rate_limiter, http)`; `AppState`'e `Arc<dyn Notifier>` = `notifier_port()`, `Arc<dyn SmsSender>` = `sms`. (2) `notification` öneki için `authn_audit::OutboxHandler` köprüsü: `DeliveryRequest`'i `OutboxMessage`'dan doldurup `NotificationDeliverer::deliver` çağırır; `DeliveryFailure::Retry { reason, retry_after }` → `HandlerError::Retry`, `Permanent { reason }` → `HandlerError::permanent` (örnek kod: `crates/authn-notify/README.md`). (3) `check-config`: `TemplateRenderer::from_config` ile şablon doğrulaması. (4) authn-mfa: `SmsSender::is_configured() == false` iken SMS faktörünü sunmamalı; asenkron gönderim için `Notifier::notify_sms_in_tx`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık (sahiplerin uygulaması bekleniyor)

## authn-session

## authn-oidc-client

## authn-admin

## authn-server
