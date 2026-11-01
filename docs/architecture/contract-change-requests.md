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

## Mimar — Dalga A işleme özeti (2026-11-01)

Dalga A'nın tüm talepleri işlendi; her kaydın **Durum** satırı güncellendi. Özet:

- **Uygulandı (mimar):** `UserRepository::{find_many, claim_next}` + `UserClaim`; `OneTimeTokenRepository::{revoke_for_user_since, active_for_user}`; `RevocationReason::MembershipChanged`; `RevokeOptions::also_trusted_devices` semantiği; `RecordingNotifier` SMS kaydı ve `RecordingAuditSink::pseudonymized`; migration `0013` (sarmalanmış hash'lerde pepper zorunluluğu) ve `0014` (ayrılmış DEK tablosu, kilit açma indeksi); ortama bağlı `[notify]` kuralları `AppConfig::validate`'te; Mailpit sabit geliştirme sertifikası (`config/dev-certs/`); contracts §4/§5/§6/§7/§9/§14 ve yeni **§15 Sunucu bağlama tablosu**; yol parametresi kuralını zorlayan `authn-testkit/tests/routes.rs`.
- **Reddedilen:** yok.
- **Açık kalanlar** durum satırında sahibine yönlendirildi: **authn-server** ve **Dalga B** (authn-session, authn-oidc-client, authn-admin) için ilgili contracts §15 satırları; **authn-notify** (bildirim türleri/şablon metni — mimar onaylı) ve **authn-crypto** (`KeyPurpose::KnownDevice` — mimar onaylı, düşük öncelik). Kendi kayıtlarınızı bulmak için bu dosyada `Açık — **authn-<crate>` arayın.

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
- **Durum:** Uygulandı (2026-11-01, mimar: `migrations/0014_reserved_dek_table_and_user_job_index.sql` tabloya "ayrılmış, kullanılmıyor" yorumu ekler; `0011` yorumunun yerini alır; `overview.md` ve contracts §5/§14 güncellendi. Tablo silinmedi: ileride KMS sarılmış-DEK önbelleği için ayrılmış; test `cry_08_data_encryption_keys_is_documented_as_reserved`)

### 2026-10-31 — Sarmalanmış eski hash'ler için pepper zorunluluğu (şema kısıtı)
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `password_credentials` tablosu / authn-store (yeni migration mimar aralığında)
- **Gereksinim:** CRY-02, CRY-04
- **Gerekçe:** `argon2id_wrapped_md5` ve `argon2id_wrapped_sha1` hash'leri de pepper ile üretilir; `pepper_version` olmadan doğrulanamazlar (kod `Invalid` döner ve loglar). Mevcut kısıt yalnızca `algorithm = 'argon2id'` için `pepper_version`'ı zorunlu kılıyor.
- **Önerilen değişiklik:** `ALTER TABLE password_credentials ADD CONSTRAINT password_credentials_wrapped_pepper_check CHECK (algorithm NOT LIKE 'argon2id%' OR pepper_version IS NOT NULL);`
- **Geriye uyumluluk:** Mevcut veride bu biçimde satır yok; ekleme.
- **Durum:** Uygulandı (2026-11-01, mimar: `migrations/0013_password_wrapped_pepper_check.sql` — `CHECK (NOT starts_with(algorithm, 'argon2id') OR pepper_version IS NOT NULL)`; önek gelecekteki argon2id şemalarını da kapsar; test `cry_04_wrapped_legacy_hashes_require_pepper_version`)

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
- **Durum:** Uygulandı (2026-11-01, mimar: contracts §5 — purpose kayıt defteri kodda `authn_store::TokenPurpose`; yeni purpose = varyant + `kind()` kolu + tablo satırı)

## authn-store

## authn-password

### 2026-11-01 — Fuzz hedefi `hibp_range_parse` kaydı
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `fuzz/Cargo.toml` / mimar
- **Gereksinim:** TST-04, PWD-03
- **Gerekçe:** HIBP aralık yanıtı ve çevrimdışı sızıntı listesi dış kaynaklı girdidir. Hedef dosyası yazıldı (`fuzz/fuzz_targets/hibp_range_parse.rs`, sahibi authn-password); aynı değişmezler `crates/authn-password/tests/breach.rs` içinde `proptest` ile de çalışıyor.
- **Önerilen değişiklik:** `fuzz/Cargo.toml`'a `authn-password = { path = "../crates/authn-password" }` bağımlılığı ve `[[bin]] name = "hibp_range_parse", path = "fuzz_targets/hibp_range_parse.rs", test = false, doc = false, bench = false`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-11-01, mimar: `fuzz/Cargo.toml`, commit 339cc7d)

### 2026-11-01 — Şifre sıfırlamada güvenilir cihazların silinmesi `SessionRevoker` üzerinden
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/session_revoker.rs` (semantik) / authn-session; `trusted_devices` / authn-mfa
- **Gereksinim:** PWD-09, MFA-09, SES-15
- **Gerekçe:** PWD-09 "güvenilir cihazlar silinir" der; authn-password `trusted_devices` tablosuna erişemez. Mevcut sözleşmede yol zaten var: `RevokeOptions { also_trusted_devices: true }`. authn-password sıfırlamayı `revoke_all_for_user(conn, user, RevocationReason::PasswordReset, RevokeOptions { also_trusted_devices: true })` ile, kendi transaction'ında çağırır (test: `pwd_09_reset_revokes_every_session_refresh_token_and_trusted_device`).
- **Önerilen değişiklik:** authn-session'ın `SessionRevoker` uygulaması bu bayrakta authn-mfa'nın güvenilir cihaz silme API'sini **aynı `&mut PgConnection` üzerinde** çağırmalı (commit edilmezse cihazlar da kalır). Port belgesine "also_trusted_devices çağıranın transaction'ında uygulanır" cümlesi eklenebilir.
- **Geriye uyumluluk:** Semantik netleştirme; imza değişmez.
- **Durum:** Kısmen uygulandı (2026-11-01, mimar: `RevokeOptions::also_trusted_devices` belgesine "aynı bağlantıda, çağıranın transaction'ında; bayrak yok sayılamaz" sözleşmesi eklendi — `crates/authn-core/src/ports/session_revoker.rs`; contracts §4, §15.2). Açık — **authn-session:** `SessionRevoker` uygulaması (contracts §15.7)

### 2026-11-01 — Server'ın uygulayacağı trait'ler ve bağlama
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,serve.rs}` / authn-server
- **Gereksinim:** PWD-04, PWD-11, ARC-03, OPS-07
- **Gerekçe:** Dalga A modülleri birbirine bağımlı olamaz; PWD-11 başka giriş yöntemlerini (webauthn, oidc-client), PWD-04 ve bildirimler görünen ad/dili (account) bilmelidir.
- **Önerilen değişiklik:** (1) `authn_password::LoginMethodInventory` — `async fn other_login_methods(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<LoginMethod>, AuthError>`; passkey → `LoginMethod::Passkey`, bağlı kimlik → `LoginMethod::Social`; verilen bağlantı üzerinden okunur (çağıran kullanıcı satırını `FOR UPDATE` kilitlemiştir). (2) `authn_password::ProfileLookup` — `async fn profile(&self, user: UserId) -> Result<ProfileHints, AuthError>` (`display_name`, `locale`). (3) `PasswordService::new(PasswordServiceDeps { … }, PasswordServiceSettings::from_app_config(&config))`, `breach_checker = HibpBreachChecker::from_config(&config.password.breach_check, protect_http_client)`, `impl FromRef<AppState> for PasswordService`, `.merge(authn_password::router::<AppState>())` (`/v1/me/password*` kimlik doğrulama katmanının arkasında), `openapi.rs`'e `authn_password::PasswordApi`. (4) Zarif kapanışta `drain_background_jobs().await`. (5) authn-account'a `PasswordValidator` olarak `password_service.validator()`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-server:** contracts §15.1 (`LoginMethodInventory`, `ProfileLookup`), §15.2 (`BreachedPasswordChecker`, `PasswordValidator`), §15.3, §15.6 (`drain_background_jobs`)

### 2026-11-01 — authn-session / authn-admin için şifre API'si
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session; `crates/authn-admin` / authn-admin
- **Gereksinim:** SES-01, SES-13, SES-22, PWD-12, ADM-03, CRY-03/04/05
- **Gerekçe:** Şifre doğrulama, rehash ve `must_change_password` mantığı tek yerde (authn-password) kalmalı.
- **Önerilen değişiklik:** Giriş ve step-up: `verify_login_password(&ctx, Option<UserId>, &SecretString) -> Result<LoginPasswordOutcome, AuthError>` (`Valid` / `MustChangePassword` / `Invalid`; kullanıcı yoksa `None` verin — sahte doğrulama ve eşdeğer sorgu içeride). `MustChangePassword` → `RequiredAction::ChangePassword` challenge'ı; tamamlama `apply_required_password_change(&ctx, user, Some(session), &new)` (bayrak yoksa `forbidden`). Admin: `set_must_change_password(&ctx, Actor::User(admin), user, bool)`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-session / authn-admin:** contracts §15.7

### 2026-11-01 — PWD-11 yarışına karşı kullanıcı satırı kilidi
- **Talep eden:** authn-password
- **Etkilenen dosya / sahip:** passkey silme (authn-webauthn), kimlik ayırma (authn-oidc-client)
- **Gereksinim:** PWD-11, PKY-04, SOC-06
- **Gerekçe:** "Son giriş yöntemi silinemez" kuralı üç modüle dağılmıştır. authn-password şifre kaldırmayı `users` satırı `FOR UPDATE` kilitliyken kontrol eder; diğer modüller de aynı satırı kilitlerse "son passkey'i sil" ile "şifreyi kaldır" eşzamanlı olarak ikisi birden başarılı olamaz.
- **Önerilen değişiklik:** Passkey silme ve kimlik ayırma transaction'larının başında `authn_store::UserRepository::lock_for_update(conn, user)`.
- **Geriye uyumluluk:** Davranış değişikliği yok (yalnızca serileştirme).
- **Durum:** Kısmen uygulandı: authn-webauthn passkey silme transaction'ı `UserRepository::lock_for_update` ile başlıyor (`crates/authn-webauthn/src/service/manage.rs`). Açık — **authn-oidc-client:** kimlik ayırma (contracts §15.7)

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
- **Durum:** Uygulandı (2026-11-01, mimar: contracts §5 account satırı; `overview.md` ER diyagramına `users ||--o{ email_reservations`)

### 2026-11-01 — Paylaşılan tablolarda salt-okunur sorgular ve adrese bağlı token iptali
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `users` / authn-store; `one_time_tokens` (diğer modüllerin purpose'ları) / authn-password, authn-session, authn-mfa
- **Gereksinim:** ACC-05, ACC-06, ACC-07, ACC-10
- **Gerekçe:** (1) Temizlik işleri aday satırları tek sorguda, çoklu instance güvenli seçmeli: `SELECT id FROM users WHERE status='pending_verification' AND email_verified_at IS NULL AND created_at < $1 … FOR UPDATE SKIP LOCKED` (ACC-05) ve `… WHERE status='locked' AND locked_until <= $1 … FOR UPDATE SKIP LOCKED` (ACC-06). Yazma yine `UserRepository` (`update_status`, `delete`) ile yapılır. (2) Dışa aktarma, `one_time_tokens`'tan **yalnızca account purpose'larının** aktif satırlarını (hash hariç) okur. (3) E-posta adresi değiştiğinde / geri alındığında, kullanıcının adresine gönderilmiş **tüm** token'lar `OneTimeTokenRepository::revoke_for_user` ile iptal edilir: `password_reset`, `password_reset_code`, `magic_link`, `login_code`, `not_me`, `mfa_email_otp` dahil (`authn_account::ADDRESS_BOUND_PURPOSES`). Aksi hâlde eski adrese (veya geri almada saldırganın adresine) gönderilmiş bir şifre sıfırlama linki hesabı yeniden ele geçirmeye yarar. İptal yalnızca erişimi kaldırır, hiçbir şey vermez.
- **Önerilen değişiklik:** (1) için authn-store'a `UserRepository::claim_by_status(conn, status, before, skip) -> Option<UserId>` eklenirse account ona geçer. (3) için contracts §5'e not: "adres değişikliği, adrese gönderilmiş tüm purpose'ları iptal eder (authn-account)".
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Uygulandı (2026-11-01, mimar): (1) `UserRepository::claim_next(conn, UserClaim::{UnverifiedCreatedBefore(t), LockExpiredAt(t)}, skip: &[UserId]) -> Option<UserRecord>` — aynı koşullar ve sıralama, `FOR UPDATE SKIP LOCKED`, `users_locked_until_idx` (0014); (2) `OneTimeTokenRepository::active_for_user(executor, user, purposes, now)` (hash hariç; dışa aktarma kendi purpose'larını verir); (3) contracts §5 "yalnızca iptal" istisnaları (adrese bağlı purpose'lar; password/session'ın `email_change*` iptali). Testler `acc_05_claim_next_returns_only_expired_unverified_accounts`, `acc_06_claim_next_is_exclusive_across_instances`, `acc_10_active_for_user_lists_only_usable_tokens_of_the_given_purposes`. authn-account `SharedReads`'i bunlara geçirebilir (davranış aynı)

### 2026-11-01 — `RegistrationAttempt` bildirimi ve olası yeni bildirim türleri
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/notifier.rs` ve şablonlar / authn-notify
- **Gereksinim:** ACC-02, ACC-07, NTF-01
- **Gerekçe:** `RegistrationAttempt` iki durumda gönderilir: kayıtlı adresle kayıt denemesi ve e-posta değişikliğinde başka bir hesabın adresinin istenmesi. Geri alma sonrası "şifrenizi sıfırlayın" uyarısı için tür yok.
- **Önerilen değişiklik:** Şablon metni genel olsun ("Bu adres bir hesap için kullanılmak istendi; siz değilseniz bir şey yapmanıza gerek yok"). İsteğe bağlı yeni tür: `EmailChangeReverted { at }` (account geri almada gönderir).
- **Geriye uyumluluk:** Şablon metni; yeni tür ekleme.
- **Durum:** Açık — **authn-notify** (port ve şablon sahibi). Mimar kararı: onaylandı — `registration_attempt` metni kayıt ve e-posta değişikliği girişimlerini kapsayacak şekilde genelleştirilsin (şu an yalnızca kaydı anlatıyor); `NotificationKind::EmailChangeReverted { at }` eklensin (eklemeli varyant; tam eşleşme yapan üretici yok)

### 2026-11-01 — Server / Dalga B bağlama notları
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,serve.rs}` / authn-server; authn-session; authn-admin; authn-org; tüm `DataExporter` uygulayıcıları
- **Gereksinim:** ACC-05, ACC-06, ACC-09, ACC-10, ACC-11, ARC-03, OPS-06, OPS-07
- **Gerekçe:** Dalga A modülleri birbirine bağımlı olamaz.
- **Önerilen değişiklik:** (1) `authn_account::OrganizationOwnership` — `async fn sole_owner_organizations(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<OrgId>, AuthError>`; authn-org ile, verilen bağlantı üzerinden (çağıran kullanıcı satırını kilitlemiştir). (2) `AccountService::new(AccountServiceDeps { … }, AccountServiceSettings::from_app_config(&config)?)?`, `impl FromRef<AppState> for AccountService`, `.merge(authn_account::router::<AppState>())` (`/v1/me*` oturum katmanının arkasında; `GET /v1/me` session'ındır), `openapi.rs`'e `authn_account::AccountApi`. (3) Açılışta `sync_terms_versions()`; işler: `purge_unverified_accounts`, `purge_due_deletions`, `release_expired_locks`, `purge_expired_reservations`; kapanışta `drain_background_jobs()`. (4) Her modül kendi tabloları için `DataExporter` uygular (bölüm adı `^[a-z][a-z0-9_]{0,63}$`, benzersiz, `account` ayrılmış) ve server `exporters` listesine ekler. (5) authn-session: doğru şifreden sonra `assess_login(&UserRecord)`; `Denied(reason)` → `reason.into_error(now)`; `required_actions` (`verify_email`, `accept_terms`) → SES-22; `accept_terms(ctx, user, …)`. (6) authn-admin: `change_status_in_tx` + aynı transaction'da `SessionRevoker`. (7) authn-password `ProfileLookup` adaptörü: `AccountService::profile_of`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-server / authn-session / authn-admin:** contracts §15.1 (`OrganizationOwnership`, `ProfileLookup`, `DataExporter`), §15.3, §15.5 (dört bakım işi), §15.6 (`sync_terms_versions`, `drain_background_jobs`), §15.7

### 2026-11-01 — Güvenlik incelemesi: `email_change_revert` satırlarında hedefli iptal ve okuma
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `one_time_tokens` (yalnızca account'a ait `email_change_revert` purpose'u) / paylaşımlı tablo, authn-store repository'si
- **Gereksinim:** ACC-07
- **Gerekçe:** Geri alma, kendisinden **sonra** verilmiş geri alma linklerini iptal etmeli, öncekileri korumalı (aksi hâlde ara adresi kontrol eden saldırgan, sahibin geri alma linkini iptal edebiliyordu). `OneTimeTokenRepository::revoke_for_user` purpose'un tüm satırlarını iptal eder; zamana göre süzme yok.
- **Önerilen değişiklik:** (uygulandı, `crates/authn-account/src/repo.rs` `RevertLinkRepository`) `UPDATE one_time_tokens SET revoked_at = $5 WHERE user_id = $1 AND purpose = 'email_change_revert' AND consumed_at IS NULL AND revoked_at IS NULL AND (created_at, id) >= ($3, $4)` ve aynı purpose'un aktif satırlarının `target`/`expires_at` okuması. authn-store'a `revoke_for_user_since(conn, user, purposes, since: (OffsetDateTime, OneTimeTokenId), now)` eklenirse account ona geçer. Ayrıca `change_status` / `change_status_in_tx` artık `pending_deletion` ve `deleted` hedeflerini reddeder (authn-admin bilgi notu: silme yalnızca silme akışıyla).
- **Geriye uyumluluk:** Yalnızca account'un kendi purpose'u; şema değişikliği yok.
- **Durum:** Uygulandı (2026-11-01, mimar: `OneTimeTokenRepository::revoke_for_user_since(conn, user, purposes, (created_at, id), now)` ve `active_for_user` — `crates/authn-store/src/one_time_tokens.rs`; test `acc_07_revoke_since_cancels_later_links_but_keeps_earlier_ones`). authn-account `RevertLinkRepository`'yi bunlara geçirebilir

### 2026-11-01 — Kayıtta ön-ele geçirme savunması (ADR 0002): `pending_registrations`, `SessionRevoker` dekoratörü, oturuma bağlı e-posta değişikliği onayı
- **Talep eden:** authn-account
- **Etkilenen dosya / sahip:** `docs/architecture/contracts.md` §5 ve §15, `docs/architecture/overview.md` (ER, kayıt akışı) / mimar; `crates/authn-server` (bağlama) / authn-server; authn-session, authn-oidc-client, authn-admin (çağrılar). authn-password ve authn-session kodunda değişiklik **gerekmez**.
- **Gereksinim:** ACC-01, ACC-02, ACC-04, ACC-05, ACC-07, PWD-09, SES-18, SES-19, SOC-05, ADM-03
- **Gerekçe:** "Son kayıt olan kazanır" ve "link tek başına hesabı doğrular" kuralları saldırgan ikinci / saldırgan önce ön-ele geçirmeye izin veriyordu; e-posta değişikliği linki de aynı sınıftaydı (ADR 0002).
- **Önerilen değişiklik:** (authn-account'ta uygulandı) (1) Yeni tablo `pending_registrations` (migration `1201`, account'a ait): §5 account satırına ve ER diyagramına `users ||--o{ pending_registrations` eklenmesi. (2) `authn_account::AccountAwareSessionRevoker::new(inner, account)` — `SessionRevoker` dekoratörü; server sarılmış portu tüm modüllere verir, `AccountServiceDeps::sessions`'a iç revoker'ı verir. Toplu iptallerde (`Logout`, `UserRequest`, `PasswordChanged`, `PasswordReset`, `EmailChangeReverted`, `NotMe`, `RefreshTokenReuse`, `AccountSuspended`, `AdminAction`, `Emergency`) bekleyen `email_change` / `email_change_code` iptal edilir (§5'teki "password/session iptal edebilir" notu böylece kendiliğinden sağlanır); `PasswordReset` doğrulanmamış hesabı posta kutusu sahibi için doğrular. Sözleşme kuralı: `RevocationReason::PasswordReset` yalnızca e-postayla gelen sıfırlamanın tamamlanmasında kullanılır. (3) `POST /v1/email/change/confirm` hesap sahibinin oturumunu ister: server oturum (ve CSRF) katmanını bu yola da uygular; `POST /v1/email/verify` isteğe bağlı `Principal` okur. (4) `POST /v1/signup` yanıtı `{status, registration}` + `Set-Cookie: __Host-authn_registration` (`HttpOnly; Secure; SameSite=Strict; Path=/`); `POST /v1/email/verify` gövdesi `token` [+ `password` | `new_password` + `accepted_terms`] veya `code` + `registration` (ya da çerez); yeni hata kodları `registration_confirmation_required`, `registration_password_mismatch` (403). (5) Posta kutusu kanıtları: authn-session magic link / giriş kodu ile doğrulanmamış hesaba oturum açmadan önce ve authn-oidc-client sağlayıcının doğruladığı e-postayla doğrulanmamış hesaba bağlamadan önce `AccountService::confirm_mailbox_control_in_tx(conn, ctx, user, MailboxProof::Passwordless)`; authn-admin "e-posta doğrulandı" (ADM-03) için `MailboxProof::Administrator { admin }`. (6) Kural: hiçbir modül `pending_verification` bir hesaba kimlik bilgisi (sosyal kimlik, passkey) eklemez.
- **Geriye uyumluluk:** Kayıt ve doğrulama HTTP sözleşmesi değişti (henüz istemci yok): `{email, code}` tutamaçsız artık doğrulamaz; yalnızca link, kaydı yapan tarayıcı dışında `403 registration_confirmation_required` döner; e-posta değişikliği linki oturum ister. Kayıtla oluşan doğrulanmamış hesapların şifresi yoktur (doğrulanana kadar şifreyle giriş ve sıfırlama yok). `AccountService::signup` artık `RegistrationReceipt` döner; `verify_email_link` / `verify_email_code` / `resend_verification` / `confirm_email_change_link` imzaları genişledi (Dalga B'de çağıran yok).
- **Durum:** Açık — mimar (§5, §15, ER), authn-server (dekoratör, oturum katmanı), authn-session / authn-oidc-client / authn-admin (`MailboxProof` çağrıları)

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
- **Durum:** Uygulandı (2026-11-01, mimar: `fuzz/Cargo.toml`, commit 339cc7d)

### 2026-11-01 — authn-server'ın uygulayacağı `MfaPolicySource` ve bağlama
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,jobs}` / authn-server
- **Gereksinim:** MFA-07, MFA-08, MFA-09, ARC-03, OPS-06
- **Gerekçe:** Son faktör kuralı ve güvenilir cihaz izni organizasyon politikasına (authn-org) ve passkey sayısına (authn-webauthn) bağlıdır; Dalga A modülleri birbirini göremez.
- **Önerilen değişiklik:** (1) `authn_mfa::MfaPolicySource` uygulaması: `async fn org_policy_for_user(&self, conn: &mut PgConnection, user: UserId) -> Result<Option<OrgMfaPolicy>, AuthError>` (aktif üyeliklerin `org_policies` kayıtlarının `OrgMfaPolicy::strictest` birleşimi) ve `async fn webauthn_factor_count(&self, conn: &mut PgConnection, user: UserId) -> Result<u32, AuthError>`; ikisi de verilen bağlantıdan okur (çağıran kullanıcı satırlarını kilitlemiştir). (2) `MfaService::new(MfaServiceDeps { pool, clock, keys, otp, envelopes, rate_limiter, notifier, audit, sms: Some(sms_sender), policy_source }, MfaServiceSettings::from_app_config(&config))`, `impl FromRef<AppState> for MfaService`, `.merge(authn_mfa::router::<AppState>())` oturum katmanının arkasında, `openapi.rs`'e `authn_mfa::MfaApi`; `passkey` feature'ı kapalıysa `settings.webauthn_available = false`. (3) Arka plan işi `MfaService::purge_expired()`. (4) authn-account dışa aktarma toplayıcısına `authn_mfa::MfaDataExporter`. (5) Workspace girdisi `default-features = false` olduğundan authn-server'ın `authn-mfa`'yı `features = ["sms"]` ile alması (ARC-11).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-server:** contracts §15.1 (`MfaPolicySource`, `MfaDataExporter`), §15.3 (`features = ["sms"]`), §15.5 (`purge_expired`)

### 2026-11-01 — authn-session / authn-admin için MFA API'si
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session; `crates/authn-admin` / authn-admin
- **Gereksinim:** SES-02, SES-13, SES-15, SES-21, SES-22, MFA-09, ADM-03
- **Gerekçe:** Giriş challenge durumu authn-session'dadır; faktör doğrulama, kod gönderme, politika ve güvenilir cihaz mantığı tek yerde (authn-mfa) kalmalı.
- **Önerilen değişiklik:** Giriş: `evaluate_for_user(user, Option<OrgMfaPolicy>, phishing_resistant_required) -> MfaRequirement` (`EnrollmentRequired` + boş liste ⇒ reddet; kullanıcının izin dışı kalmış faktörleri varsa önce biri doğrulatılsın), `is_trusted_device(user, token, trusted_devices_allowed)`, `send_code(&ctx, user, Some(challenge_id), OtpChannel::{Email, Sms{factor_id}})`, `verify_factor(&ctx, user, Some(challenge_id), FactorProof) -> VerifiedFactor { kind, factor_id, amr, recovery_codes_remaining }` (`amr` birleştirmesi `authn_mfa::amr::combine`), başarılı MFA + "hatırla" için `trust_device(&ctx, user, trusted_devices_allowed) -> Option<IssuedTrustedDevice>` (cookie `authn_mfa::TRUSTED_DEVICE_COOKIE`, başlık `TRUSTED_DEVICE_HEADER`). `SessionRevoker` uygulamasında `RevokeOptions::also_trusted_devices` ⇒ aynı bağlantıyla `revoke_trusted_devices_in_tx(conn, user, reason)` (authn-password'un PWD-09 talebiyle aynı). `GET /v1/me` için `status_for_user(user)`. Admin: `reset_user_mfa_in_tx(conn, &ctx, user) -> MfaResetSummary` (audit olayını gerekçesiyle admin yazar).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-session / authn-admin:** contracts §15.7 (`also_trusted_devices` için port belgesi güncellendi)

### 2026-11-01 — authn-testkit: `RecordingNotifier` SMS kaydı
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-testkit/src/fakes/notifier.rs` / authn-testkit (mimar)
- **Gereksinim:** MFA-06, TST-01
- **Gerekçe:** authn-mfa SMS kodlarını `Notifier::notify_sms_in_tx` ile (outbox) gönderir; `RecordingNotifier` bu metodu uygulamadığından testlerde varsayılan gövde `sms_unavailable` döner. authn-mfa testleri şimdilik kendi `TestNotifier` sarmalayıcısını kullanıyor (`crates/authn-mfa/tests/common/mod.rs`). authn-notify'ın aynı öneriyi içeren kaydını destekler.
- **Önerilen değişiklik:** `RecordingNotifier`'a `sms: Mutex<Vec<SmsNotification>>`, `recorded_sms()` ve `notify_sms_in_tx` uygulaması.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-11-01, mimar: `RecordingNotifier::notify_sms_in_tx` + `recorded_sms`, `sms_with_template`, `last_sms`, `take_sms`, `set_sms_available(false)` → `sms_unavailable`; test `mfa_06_recording_notifier_records_sms_and_can_switch_it_off`). authn-mfa kendi `TestNotifier` sarmalayıcısını bırakabilir

### 2026-11-01 — Güvenlik incelemesi sonrası bağlama notları (authn-session / authn-server)
- **Talep eden:** authn-mfa
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session; `MfaPolicySource` uygulaması / authn-server
- **Gereksinim:** MFA-08, MFA-09, SES-02, SES-21
- **Gerekçe:** (1) `verify_factor` kanıtın geçerliliğini denetler, kanıt türünün o girişte izinli olup olmadığını değil (organizasyon bağlamı yalnızca session'da bilinir). (2) Güvenilir cihazlar artık kullanıcının **tüm** üyeliklerinin en katı politikasına da bağlıdır: herhangi bir organizasyon `trusted_devices_allowed = false` ise cihaz ne verilir ne kabul edilir (çağıranın bayrağı yalnızca giriş bağlamıdır).
- **Önerilen değişiklik:** (1) authn-session, `proof.kind()` challenge'ın `MfaRequirement::allowed_factors()` listesinde değilse `verify_factor`'ı çağırmadan reddetmeli (admin'ler için yalnızca phishing'e dayanıklı faktör; kurtarma kodu yalnızca listedeyse). (2) `MfaPolicySource::org_policy_for_user` `is_trusted_device` tarafından transaction'sız düz bir bağlantıyla da çağrılır; uygulama yalnızca verilen bağlantıdan okumalıdır (mevcut sözleşmeyle uyumlu).
- **Geriye uyumluluk:** İmza değişikliği yok; davranış yalnızca sıkılaştı.
- **Durum:** Bilgi — **authn-session / authn-server:** contracts §15.1 (`MfaPolicySource` yalnızca verilen bağlantıdan okur), §15.7 (`allowed_factors` kontrolü)


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
- **Durum:** Uygulandı (2026-11-01, mimar: `fuzz/Cargo.toml` ve `fuzz/deny.toml` MPL-2.0 istisnaları, commit 339cc7d)

### 2026-11-01 — authn-server'ın uygulayacağı trait'ler ve bağlama
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,jobs}` / authn-server
- **Gereksinim:** PKY-04, PKY-07, PKY-08, ARC-03, OPS-06, MFA-07, PWD-11
- **Gerekçe:** Son giriş yöntemi kuralı şifreye (authn-password/store), bağlı kimliklere (authn-oidc-client) ve MFA zorunluluğuna (authn-mfa/authn-org) bağlıdır; kuruluş AAGUID politikası authn-org'dadır. Dalga A modülleri birbirini göremez.
- **Önerilen değişiklik:** (1) `authn_webauthn::AccountMethodsSource`: `async fn other_login_methods(&self, conn: &mut PgConnection, user: UserId) -> Result<Vec<LoginMethod>, AuthError>` (passkey dışındaki yöntemler: şifre, bağlı sosyal kimlikler, deployment'a göre magic link/e-posta kodu) ve `async fn mfa_facts(&self, conn, user) -> Result<MfaFacts, AuthError>` (`mfa_required`, passkey dışı etkin faktör sayısı; authn-mfa `MfaService`/politika); ikisi de verilen bağlantıdan okur (çağıran `users` satırını `FOR UPDATE` kilitlemiştir). Varsayılan `PasswordOnlyMethods` yalnızca şifreyi bilir (güvenli tarafta kalır). (2) `authn_webauthn::PasskeyPolicySource`: `async fn policy_for_user(&self, conn, user, active_org: Option<OrgId>) -> Result<PasskeyPolicy, AuthError>` (örn. etkin üyeliklerin `PasskeyPolicy::strictest` birleşimi); varsayılan `UnrestrictedPolicySource`. (3) `WebauthnService::new(WebauthnServiceDeps { pool, clock, rate_limiter, notifier, audit, account_methods, policy_source }, WebauthnServiceSettings::from_app_config(&config)?)`, `impl FromRef<AppState> for WebauthnService`, `.merge(authn_webauthn::router::<AppState>())` oturum + CSRF katmanının arkasında; `impl FromRef<AppState> for WellKnownDocuments` (`service.well_known()`), `.merge(authn_webauthn::well_known_router::<AppState>())` kökte, kimlik doğrulamasız; `openapi.rs`'e `authn_webauthn::WebauthnApi`. (4) Arka plan işi `WebauthnService::purge_expired_ceremonies()`. (5) authn-account dışa aktarma toplayıcısına `authn_webauthn::PasskeyDataExporter`. (6) authn-mfa `MfaPolicySource::webauthn_factor_count` ⇒ `service.passkey_count_in(conn, user, false)`; authn-password `LoginMethodInventory` ⇒ `passkey_count_in(conn, user, true) > 0` ise `LoginMethod::Passkey`. (7) Workspace girdisi `default-features = false` olduğundan authn-server `authn-webauthn`'u `features = ["passkey"]` ile almalı (ARC-11).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-server:** contracts §15.1 (`AccountMethodsSource`, `PasskeyPolicySource`, `PasskeyDataExporter`), §15.3 (`features = ["passkey"]`, `well_known_router`), §15.5

### 2026-11-01 — authn-session için passkey kimlik doğrulama API'si
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-session` / authn-session
- **Gereksinim:** SES-02, SES-13, SES-20, SES-21, PKY-01, PKY-02, PKY-05
- **Gerekçe:** Passkey ile giriş, ikinci faktör ve step-up uç noktaları authn-session'dadır; WebAuthn doğrulaması, seremoni durumu ve klon tespiti tek yerde (authn-webauthn) kalmalı.
- **Önerilen değişiklik:** `start_authentication(&ctx, AuthenticationTarget, &PasskeyPolicy) -> AuthenticationStart { ceremony_id, binding_token, options, expires_at }` ve `finish_authentication(&ctx, AuthenticationFinish { ceremony_id, binding_token, target, credential }) -> AuthenticatedPasskey { user_id, credential_id, purpose, user_verified, backup_eligible, backup_state, amr }`. Hedefler: `Discoverable { conditional_ui }` (kullanıcı adısız giriş, UV zorunlu), `SecondFactor { user_id, challenge_id }` (giriş challenge'ına bağlı), `StepUp { user_id, session_id }` (oturuma bağlı, UV zorunlu). `binding_token` web'de `HttpOnly; Secure; SameSite=Strict` kısa ömürlü bir çerezde, native'de yanıt gövdesinde taşınmalı ve bitişte aynen geri verilmeli; `target` istemciden değil, session'ın kendi kaydından (challenge/oturum) kurulmalı. Başarıdan sonra hesap durumu, oturum/challenge geçerliliği, `login.*`/`step_up.*`/`mfa.*` audit olayları ve AMR birleştirmesi session'ın işidir (`amr` alanı `hwk`/`swk` + `user` + UV'de `mfa`). Hatalar: `passkey_ceremony_invalid`, `passkey_authentication_failed` (giriş akışında `invalid_credentials`'a eşlenebilir), `passkey_not_available`, `rate_limited`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-session:** contracts §15.7

### 2026-11-01 — `NotificationKind` için passkey'e özel tür (öneri)
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/notifier.rs` / authn-notify
- **Gereksinim:** PKY-04, NTF-01
- **Gerekçe:** Passkey ekleme/kaldırma bildirimleri şimdilik `MfaFactorAdded/MfaFactorRemoved { factor: FactorKind::Webauthn }` ile gönderiliyor (NTF-01 "MFA eklendi/kaldırıldı" kapsamında). Şablonda "passkey" ifadesi ve şüpheli klon (PKY-05) için ayrı bir uyarı e-postası kullanıcı deneyimini iyileştirir.
- **Önerilen değişiklik:** İsteğe bağlı: `NotificationKind::PasskeyCloneSuspected { at }` ve şablonları; eklenirse authn-webauthn klon tespitinde kullanıcıyı da bilgilendirir.
- **Geriye uyumluluk:** Yeni varyant (tam eşleşme yapan tüketiciler için kırıcı olabilir, §13).
- **Durum:** Açık — **authn-notify**. Mimar kararı: onaylandı (isteğe bağlı) — `NotificationKind::PasskeyCloneSuspected { at }` + TR/EN şablonları eklenirse authn-webauthn klon tespitinde kullanıcıyı da bilgilendirir; eklemeli varyant

### 2026-11-01 — Güvenlik incelemesi: `PasskeyPolicySource` her kimlik doğrulamada, impersonation kaydı yasak (bilgi)
- **Talep eden:** authn-webauthn
- **Etkilenen dosya / sahip:** `crates/authn-server` (`PasskeyPolicySource` uygulaması), `crates/authn-session` (passkey uç noktaları), `crates/authn-admin` (impersonation) / ilgili sahipler
- **Gereksinim:** PKY-05, PKY-08, ADM-04
- **Gerekçe:** Güvenlik incelemesi: (1) kullanıcı adısız girişte kuruluş AAGUID politikası uygulanmıyordu; (2) imzadan önce üretilen yedekleme bayrağı hataları sahte klon işaretlerine yol açıyordu; (3) yazılabilir impersonation passkey ekleyebiliyordu.
- **Önerilen değişiklik:** Uygulandı (yalnızca authn-webauthn içinde, imza değişikliği yok): `start_authentication`'a verilen politika artık her seremonide `PasskeyPolicySource::policy_for_user(conn, user, None)` ile `PasskeyPolicy::strictest` birleştirilir (bilinen kullanıcıda başlangıçta, kullanıcı adısız girişte bitişte). **authn-server için:** `policy_for_user` kimlik doğrulamada `active_org = None` ile çağrılır; bu durumda kullanıcının etkin üyeliklerinin en katı politikasını döndürmelidir. **authn-session için:** passkey uç noktaları politikayı yine geçirebilir (birleştirilir), ama artık zorunlu değildir. `start_registration`/`finish_registration` her impersonation'ı `forbidden` ile reddeder. `passkey.clone_suspected` yalnızca imzası doğrulanmış sayaç gerilemesinde üretilir; risk katmanı bu olayı güvenilir sinyal olarak kullanabilir.
- **Geriye uyumluluk:** Daha katı davranış; API değişmedi. Politikasız (varsayılan `UnrestrictedPolicySource`) kurulumlar etkilenmez.
- **Durum:** Uygulandı (2026-11-01)

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
- **Durum:** Açık — **authn-server / authn-session:** contracts §15.1 (`OrganizationOwnership`, `MfaPolicySource`, `AuditAccessPolicy`, `PasskeyPolicySource`, `OrgDataExporter`), §15.2 (`DnsTxtResolver`), §15.4 (`api_key_middleware`), §15.5, §15.7

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
- **Durum:** Uygulandı (2026-11-01, mimar: `RevocationReason::MembershipChanged => "membership_changed"` — `crates/authn-core/src/ports/session_revoker.rs`; migration gerekmez (`sessions_revoked_reason_check` biçim kısıtıdır); test `ses_15_membership_changed_is_a_distinct_revocation_reason`). authn-org ona geçebilir

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
- **Durum:** Uygulandı (2026-11-01, mimar: `UserRepository::find_many(executor, &[UserId]) -> Vec<UserRecord>` — `WHERE id = ANY($1) ORDER BY id`, bilinmeyenler atlanır, tekrarlar bir kez döner; `crates/authn-store/src/users.rs`; test `org_02_find_many_loads_a_page_in_one_query`)

### 2026-11-01 — `org_ownership_transfer` token'larında `group_id` sözleşmesi ve fuzz kilidi (bilgi)
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `one_time_tokens` (purpose `org_ownership_transfer`) / authn-org; `fuzz/Cargo.lock` / mimar
- **Gereksinim:** ORG-11, TST-04
- **Gerekçe:** Devir token'larının `group_id`'si organizasyon kimliğidir (`target` = organizasyon kimliği, `metadata.from_user_id` = başlatan); `revoke_group(org)` organizasyonun tüm bekleyen devirlerini iptal eder. `api_key_parse` fuzz hedefinin gövdesi yazıldı; `cargo +nightly fuzz build api_key_parse` `fuzz/Cargo.lock`'u authn-org'un güncel bağımlılıklarıyla yeniden üretti (`fuzz/Cargo.toml` değişmedi).
- **Önerilen değişiklik:** contracts §5 purpose tablosuna not olarak eklenebilir.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Uygulandı (2026-11-01)
- **Mimar notu (2026-11-01):** contracts §5 "purpose'a özgü sözleşmeler"e eklendi.

### 2026-11-01 — Güvenlik incelemesi: API anahtarları yalnızca organizasyon yollarında, `org_auto_join_exclusions` tablosu, yeni `[org]` alanı (bilgi)
- **Talep eden:** authn-org
- **Etkilenen dosya / sahip:** `crates/authn-org/src/middleware.rs`, `migrations/1501_org_auto_join_exclusions.sql`, `crates/authn-core/src/config/org.rs`, `config/example.toml` `[org]` yorumları / authn-org; bilgi: authn-server, authn-session, authn-account, authn-webauthn, authn-audit; contracts §5 tablo listesi / mimar
- **Gereksinim:** ORG-02, ORG-04, ORG-05, ORG-06, ORG-08, SES-10
- **Gerekçe:** Güvenlik incelemesi: (1) `api_key_middleware` kişisel API anahtarını her yolda kullanıcının `Principal`'ına çeviriyordu; kapsam ve kimlik bilgisi türü denetlemeyen `/v1/me/…` okuma uç noktaları (ör. `GET /v1/me/profile`, `GET /v1/me/passkeys`, `GET /v1/me/security-events`) organizasyona bağlı, dar kapsamlı bir anahtarla çağrılabiliyordu. (2) Domain otomatik katılımı çıkarılan / ayrılan üyeyi bir sonraki girişte yeniden ekliyordu. (3) Davet başına bekleme süresi iptal + yeniden davetle aşılabiliyordu.
- **Önerilen değişiklik:** (uygulandı, yalnızca authn-org dosyalarında) (1) Ara katman anahtarı yalnızca `/v1/orgs/{org_id}` ve `/v1/orgs/{org_id}/…` yollarında doğrular (`authn_org::middleware::is_api_key_path`); diğer yollarda istek dokunulmadan geçer. **authn-server:** ara katman tam (`/v1/...`) yolu görmeli. **authn-session (SES-10):** API anahtarıyla istemci doğrulaması yapan uç noktalar `OrgService::authenticate_api_key`'i doğrudan çağırmalı (ara katmana güvenmemeli). **authn-account / authn-webauthn / authn-audit (öneri, derinlemesine savunma):** `/v1/me/…` okuyucuları da `principal.session_id().is_none()` olan (API anahtarı) principal'ları reddetmeli (authn-mfa zaten reddediyor). (2) Yeni tablo `org_auto_join_exclusions (org_id, user_id, reason ∈ {removed, left}, created_at)`, sahibi authn-org, `users`/`organizations` silinince kaskad; contracts §5 org tablo listesine eklenmeli. Dışa aktarma bölümü `organizations` artık `auto_join_exclusions` içerir. (3) `[org] invitation_sends_per_recipient` (varsayılan 5 / 1 gün; organizasyon + alıcı adresi başına davet e-postası).
- **Geriye uyumluluk:** Varsayılanlı yeni alan; eklemeli migration. Davranış değişikliği: API anahtarı `/v1/orgs/{org_id}` dışındaki yollarda artık `Principal` üretmez (ör. `POST /v1/orgs`, `GET /v1/org-permissions` API anahtarıyla `401`).
- **Durum:** Uygulandı (2026-11-01)
- **Mimar notu (2026-11-01):** `org_auto_join_exclusions` contracts §5 org satırına ve `overview.md` ER diyagramına eklendi; API anahtarı kapsam kuralı contracts §7'de.

## authn-protect

### 2026-11-01 — Cihaz kimliği hash'i için `KeyPurpose::RateLimitKey` paylaşımı
- **Talep eden:** authn-protect
- **Etkilenen dosya / sahip:** `crates/authn-crypto/src/kdf.rs` (`KeyPurpose`) / authn-crypto
- **Gereksinim:** RSK-02, CRY-11
- **Gerekçe:** `known_devices.device_hash` için anahtarlı hash gerekiyor; `KeyPurpose` içinde uygun bir amaç yok. Şimdilik `RateLimitKey` amaç anahtarı, alanları uzunluk önekli ve **ayrı etiketli** (`authn/protect/known-device/v1` ↔ `authn/protect/rate-limit-key/v1`, `HmacKey::sign_fields`) olarak kullanılıyor; iki kullanım birbirine çakışamaz.
- **Önerilen değişiklik:** `KeyPurpose::KnownDevice` (`info = "authn/v1/known-device"`) eklenmesi. Eklenirse authn-protect `KeyHasher::device`'ı yeni anahtara taşır (mevcut satırlar bir sonraki girişte yeniden öğrenilir; tek etkisi bir kerelik "yeni cihaz" sinyalidir).
- **Geriye uyumluluk:** Ekleme; acil değil.
- **Durum:** Açık — **authn-crypto** (`kdf.rs` sahibi). Mimar kararı: onaylandı, öncelik düşük — CRY-11 her amaç için ayrı HKDF `info` etiketi ister; mevcut kullanım ayrı etiketli ve uzunluk önekli alanlarla çakışmasız olduğundan acil güvenlik açığı değildir. `KeyPurpose::KnownDevice` eklenince authn-protect `KeyHasher::device`'ı taşır (tek etkisi bir kerelik "yeni cihaz" sinyali)

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
- **Durum:** Açık — **authn-server / authn-session / authn-admin:** contracts §15.2 (`RateLimiter`, `CaptchaVerifier`, `RiskEvaluator`, `HttpClient`), §15.3 (`CaptchaService`), §15.4 (yuva 7), §15.5 (üç temizlik işi), §15.7

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
- **Mimar notu (2026-11-01):** authn-testkit önerisi uygulandı — `RecordingAuditSink::pseudonymized()` (test `aud_05_recording_audit_sink_records_pseudonymization`).

### 2026-11-01 — Takma ad çözümü için `users` tablosunun salt-okunur kullanımı
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** `users` tablosu / authn-store
- **Gereksinim:** AUD-03, AUD-05
- **Gerekçe:** `PgAuditSink`, olaydaki kullanıcı kimliklerini (aktör, taklitçi, özne ve kaynak/metadata içindeki kullanıcı kimlikleri) tek sorguda takma ada çevirir: `SELECT u.id, u.status = 'deleted' … FROM unnest($1::uuid[]) JOIN users u … LEFT JOIN audit_subjects s …`. `UserRepository::find_by_id` her UUID için ayrı sorgu gerektirirdi (metadata'da onlarca UUID olabilir). Yalnızca `id` ve `status` okunur; yazma yoktur. `audit_subjects.user_id → users` FK'sı zaten bu ilişkiyi şemada tanımlar.
- **Önerilen değişiklik:** contracts §5'e not: "authn-audit, takma ad çözümü için `users.id`/`users.status`'u salt-okunur sorgular". Alternatif: authn-store'a `UserRepository::statuses(conn, &[UserId]) -> Vec<(UserId, AccountStatus)>` eklenirse audit ona geçer.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Uygulandı (2026-11-01, mimar: contracts §5'te kayıtlı salt-okunur istisna. `audit_subjects` ile tek ifadede birleştirme atomik olduğu için repository'ye taşınmadı; toplu kullanıcı okuması gerekirse `UserRepository::find_many` mevcut)

### 2026-11-01 — Yol parametresi adları: `/v1/orgs/{org_id}/…`
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** authn-org ve diğer `/v1/orgs/…` router'ları / authn-server (birleştirme)
- **Gereksinim:** ARC-03, ARC-09
- **Gerekçe:** axum 0.8 (matchit), aynı konumdaki yol parametrelerinin farklı adlarla kaydını çakışma sayar (`/v1/orgs/{id}/members` ile `/v1/orgs/{org_id}/webhooks` birleştirilemez; `merge` panikler). authn-audit şu yolları kullanır: `/v1/orgs/{org_id}/audit-events`, `/v1/orgs/{org_id}/webhooks[/{endpoint_id}[/rotate-secret|/deliveries[/{delivery_id}/redeliver]]]`, `/v1/me/security-events`.
- **Önerilen değişiklik:** contracts §7'ye "organizasyon yol parametresi her router'da `{org_id}`" kuralı eklensin.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Uygulandı (2026-11-01, mimar: contracts §7 kuralı — aynı konumda aynı ad, `snake_case` `<kaynak>_id`, `/v1/orgs/{org_id}`; zorlayan testler `crates/authn-testkit/tests/routes.rs` `arc_09_*` tüm crate'lerin rota ve OpenAPI yollarını her `cargo test`'te tarar)

### 2026-11-01 — Migration 1700 ve en az yetki yardımcı fonksiyonu
- **Talep eden:** authn-audit
- **Etkilenen dosya / sahip:** `migrations/1700_audit_webhooks_least_privilege.sql` (authn-audit aralığı); OPS-10 belgeleri / authn-server, authn-store
- **Gereksinim:** AUD-02, AUD-07, OPS-10
- **Gerekçe:** `webhook_endpoints`'e `failing_since`, `last_success_at` kolonları (sürekli hata sonrası otomatik devre dışı bırakma), teslim geçmişi ve kiralama indeksleri eklendi. AUD-02/OPS-10'daki "ayrı rol önerisi" çalıştırılabilir hâle getirildi: `SELECT authn_audit_apply_least_privilege('<uygulama_rolü>', '<bakım_rolü>')` uygulama rolünden `audit_events`/`audit_chain_checkpoints` üzerindeki `UPDATE`/`DELETE`/`TRUNCATE` yetkisini kaldırır; saklama temizliği bakım rolüyle çalışır (`AuditService::run_maintenance(maintenance_pool)`).
- **Önerilen değişiklik:** authn-server: bakım işi için ayrı havuz (yapılandırılmışsa) ve OPS-10 dokümantasyonunda bu fonksiyona atıf.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-11-01)
- **Mimar notu (2026-11-01):** contracts §6 (verilen yetkiler, bakım havuzu) ve §15.6 (kurulum adımı) bu fonksiyona atıf yapıyor; authn-server bakım havuzu için Açık.

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
- **Durum:** Uygulandı (2026-11-01, authn-notify görevi; testkit önerisi mimar tarafından uygulandı: `RecordingNotifier::notify_sms_in_tx`)

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
- **Durum:** Uygulandı (2026-11-01, mimar: `AppConfig::validate_notify_environment` — `crates/authn-core/src/config/mod.rs`: log e-posta/SMS yalnızca development/test, `disabled` üretimde yasak, `extra_ca_file` yalnızca development/test; testler `ntf_03_development_only_notify_settings_are_refused_outside_development`, `ntf_03_disabled_email_transport_is_refused_in_production_only`)

### 2026-11-01 — Mailpit için sabit geliştirme sertifikası
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `docker-compose.yml` / mimar
- **Gereksinim:** NTF-03, OPS-08
- **Gerekçe:** SMTP taşıyıcısı TLS'i zorunlu kılar ve sertifikayı doğrular. Mailpit `MP_SMTP_TLS_CERT: "sans:localhost"` ile her açılışta yeni bir kendinden imzalı sertifika üretir; `notify.email.smtp.extra_ca_file` ile güvenilecek sabit bir dosya yoktur, bu yüzden `config/example.toml` (`smtp`, `localhost:1025`) yerelde TLS doğrulamasında başarısız olur.
- **Önerilen değişiklik:** Depoya yalnızca geliştirme amaçlı (herkese açık) bir `localhost` sertifikası/anahtarı (ör. `config/dev-certs/mailpit.{pem,key}`) eklenip Mailpit'e bağlanması (`MP_SMTP_TLS_CERT=/certs/mailpit.pem`, `MP_SMTP_TLS_KEY=/certs/mailpit.key`) ve `config/example.toml`'da `extra_ca_file = "config/dev-certs/mailpit.pem"` satırının açılması. Alternatif: örnek konfigürasyonda `transport = "log"`.
- **Geriye uyumluluk:** Yalnızca geliştirme ortamı.
- **Durum:** Uygulandı (2026-11-01, mimar: `config/dev-certs/{mailpit.pem,mailpit.key,README.md}` — P-256, SAN `localhost`/`127.0.0.1`/`::1`, `CA:FALSE`, `serverAuth`, 2046'ya kadar, konu adında "DEVELOPMENT ONLY"; `docker-compose.yml` dizini salt-okunur bağlar ve `MP_SMTP_REQUIRE_STARTTLS=true`; `config/example.toml`'da hazır, yorumlu `# extra_ca_file = "config/dev-certs/mailpit.pem"` satırı — yerelde açılır (authn-notify'ın `ntf_03_example_config_documents_every_notify_key` testi isteğe bağlı `[notify]` anahtarlarının yorum satırı olarak belgelenmesini ister; ayrıca üretime kopyalanan dosyada ayar kendiliğinden gelmez) ya da `AUTHN__NOTIFY__EMAIL__SMTP__EXTRA_CA_FILE` ile verilir; staging/production'da `AppConfig::validate` reddeder; testler `crates/authn-testkit/tests/dev_certs.rs`)

### 2026-11-01 — authn-server ve authn-mfa için bağlama notları
- **Talep eden:** authn-notify
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,…}` / authn-server; `crates/authn-mfa` / authn-mfa
- **Gereksinim:** NTF-01, NTF-03, NTF-04, AUD-06, OPS-06
- **Gerekçe:** Teslim `authn-audit`'in outbox işçisinde yapılır; authn-notify ona bağımlı olamaz.
- **Önerilen değişiklik:** (1) Açılışta Tokio runtime içinde `authn_notify::NotifyServices::from_config(&config, pool, crypto.envelopes, clock, rate_limiter, http)`; `AppState`'e `Arc<dyn Notifier>` = `notifier_port()`, `Arc<dyn SmsSender>` = `sms`. (2) `notification` öneki için `authn_audit::OutboxHandler` köprüsü: `DeliveryRequest`'i `OutboxMessage`'dan doldurup `NotificationDeliverer::deliver` çağırır; `DeliveryFailure::Retry { reason, retry_after }` → `HandlerError::Retry`, `Permanent { reason }` → `HandlerError::permanent` (örnek kod: `crates/authn-notify/README.md`). (3) `check-config`: `TemplateRenderer::from_config` ile şablon doğrulaması. (4) authn-mfa: `SmsSender::is_configured() == false` iken SMS faktörünü sunmamalı; asenkron gönderim için `Notifier::notify_sms_in_tx`.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-server:** contracts §15.1 (`OutboxHandler` köprüsü), §15.2 (`NotifyServices`), §15.6 (`check-config`); authn-mfa maddesi (4) uygulanmış durumda (`SmsSender::is_configured`, `notify_sms_in_tx`)

## authn-session

### 2026-11-01 — Oturum çekirdeği: migration 2000, `[session]` alanları, hata kodları (bilgi)
- **Talep eden:** authn-session
- **Etkilenen dosya / sahip:** `migrations/2000_session_core.sql`, `crates/authn-core/src/config/session.rs`, `crates/authn-core/src/error/codes/session.rs`, `config/example.toml` `[session]` yorumları / authn-session; contracts §6 migration tablosu / mimar
- **Gereksinim:** SES-03 … SES-17
- **Gerekçe:** SES-17 izinli giriş yöntemi kontrolü oturumun birincil yöntemini, SES-08 `scope` claim'i oturum kapsamlarını gerektirir; oturum kontrolü, anahtar önbelleği, touch seyreltme ve oran sınırları yapılandırılabilir olmalı (ARC-07).
- **Önerilen değişiklik:** (uygulandı, yalnızca sahip olunan dosyalarda) Migration `2000`: `sessions.login_method` (CHECK, NULL = impersonation / bilinmiyor), `sessions.scopes text[]`, `auth_challenges.primary_method`, `sessions_revoked_idx`, `refresh_tokens_successor_idx`, `sessions_impersonator_active_idx` (güvenlik incelemesi, aşağıya bakın). Yeni `[session]` alanları: `access_token_session_check` (true), `signing_key_cache_ttl` (30s), `touch_interval` (1m), `default_scopes` (`["api"]`), `step_up_per_user` (10/15dk), `refresh_per_ip` (300/dk). Yeni hata kodları: `csrf_failed`, `invalid_refresh_token`, `reauthentication_failed`, `step_up_method_not_allowed`, `challenge_invalid`, `login_method_not_allowed`, `impersonation_not_allowed`. **Mimar için:** contracts §6 "Dalga A sonrası migration'lar" tablosuna `2000 | session | sessions.login_method/scopes, auth_challenges.primary_method, temizlik indeksleri` satırı.
- **Geriye uyumluluk:** Ekleme (yeni kolonlar NULL/varsayılanlı; diğer modüllerin test fixture'ları etkilenmez).
- **Durum:** Uygulandı (2026-11-01). Açık — **mimar:** contracts §6 satırı

### 2026-11-01 — `SessionIssuer::start_impersonation_with` (port eklemesi)
- **Talep eden:** authn-session
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/session_issuer.rs` / authn-session; tüketici authn-admin
- **Gereksinim:** ADM-04, SES-08
- **Gerekçe:** RFC 8693 `act` claim'li impersonation token'ları native oturum gerektirir ve impersonation oturumu adminin kendi oturumunun `amr`/`acr`'ını miras almalıdır; `ImpersonationRequest`'e alan eklemek yapı literal'lerini kırardı.
- **Önerilen değişiklik:** (uygulandı) varsayılan gövdeli yeni metot `start_impersonation_with(ctx, request, client: ClientKind, admin_session: Option<SessionId>) -> Result<IssuedSession, AuthError>`; varsayılan gövde web için `start_impersonation`'a devreder, native için `bad_request`. authn-session uygulaması: admin DB'de etkin platform admini + canlı kendi oturumu (verilmezse en son doğrulanmış canlı oturumu), hedef etkin/admin değil/break-glass değil/kendisi değil, süre ≤ `admin.impersonation_max_ttl`, gerekçe 1–1000 karakter; kullanıcı bildirimi (`ImpersonationStarted`) ve `admin.impersonation_started` audit'i aynı transaction'da (authn-admin tekrar göndermez). Yeni tip eklenmedi (ports `mod.rs` mimarındır).
- **Geriye uyumluluk:** Ekleme; mevcut uygulayıcılar (testkit `FakeSessionIssuer`) değişmeden derlenir.
- **Durum:** Uygulandı (2026-11-01)

### 2026-11-01 — Server bağlaması: oturum katmanı, revoker inşa sırası, işler
- **Talep eden:** authn-session
- **Etkilenen dosya / sahip:** `crates/authn-server/src/{state.rs,app.rs,openapi.rs,serve.rs}` / authn-server; contracts §15.2, §15.3, §15.4, §15.5 / mimar
- **Gereksinim:** SES-03, SES-04, SES-05, SES-15, OPS-02, OPS-06, ACC-10
- **Gerekçe:** Kimlik doğrulama tek katmanda yapılmalı (çerez, bearer, API anahtarı); `SessionRevoker` hem `AccountService`'in bağımlılığı hem de `SessionService`'in (dolaylı) kullanıcısıdır.
- **Önerilen değişiklik:** (1) İnşa sırası: `MfaService` → `authn_session::PgSessionRevoker::new(clock, audit, events, mfa)` → `AccountService` (`sessions` = iç revoker) → `AccountAwareSessionRevoker::new(Arc::new(revoker), account)` diğer modüllere → `SessionService::new(SessionServiceDeps{…, passwords, mfa, webauthn, orgs, accounts}, SessionSettings::from_app_config(&config))`. (2) `SessionIssuer` portu = `Arc::new(session_service.clone())`. (3) OPS-02 yuva (8): `from_fn_with_state(session_service, authn_session::authenticate)` — `authn_org::api_key_middleware`'in **yerine** (API anahtarlarını yalnızca `is_api_key_path` yollarında principal yapar; ikisi birlikte kurulursa org katmanı principal taşıyan istekleri reddeder). (4) `FromRef<AppState> for SessionService`, `.merge(authn_session::router::<AppState>())`, `openapi.rs`'e `authn_session::SessionApi`. (5) İş: `SessionService::purge_expired(limit)`; açılışta `SigningKeyRepository::rotate_if_due` (anahtar yoksa token basılamaz). (6) `AccountServiceDeps.exporters`'a `authn_session::SessionDataExporter` (`sessions` bölümü).
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Açık — **authn-server** (bağlama), **mimar** (contracts §15.2 `SessionRevoker/SessionIssuer` satırı, §15.4 yuva 8 "`api_key_middleware` yerine `authn_session::authenticate`", §15.5 "Oturum / challenge temizliği → `SessionService::purge_expired`")

### 2026-11-01 — Dalga A bağlama taleplerinin session tarafı (bilgi)
- **Talep eden:** authn-session
- **Etkilenen dosya / sahip:** yalnızca `crates/authn-session` / authn-session
- **Gereksinim:** PWD-09, MFA-09, SES-10, SES-13, SES-15, SES-17
- **Gerekçe:** Dalga A kayıtlarındaki "Açık — authn-session" maddelerinin bu aşamada kapananları.
- **Önerilen değişiklik:** (uygulandı) `RevokeOptions::also_trusted_devices` aynı bağlantıda `MfaService::revoke_trusted_devices_in_tx` ile (password PWD-09 / mfa talepleri); "tümünü kapat" ve "diğerlerini kapat" güvenilir cihazları ve bekleyen e-posta değişikliğini (`AccountService::on_sessions_revoked_in_tx`) de iptal eder; SES-10 `OrgService::authenticate_api_key` doğrudan çağrılır (org talebi); SES-17 `check_membership` + `OrgPolicy` (org talebi); passkey step-up `AuthenticationTarget::StepUp`, `binding_token` web'de `__Host-authn_passkey` (`SameSite=Strict`) çerezinde, `target` istemciden değil oturum kaydından (webauthn talebi); step-up'ta şifre `verify_login_password` enum eşlemesiyle (password talebi). **Giriş akışları aşamasına kalan:** `LoginProtection` çağrıları, `allowed_factors` kontrolü (challenge API'si `ChallengeState::allows_factor` sağlar), `assess_login` / `MailboxProof` / `auto_join_verified_domains` (federe boru hattında `assess_login` ve `auto_join_verified_domains` uygulandı), `NotMeTokenIssuer` (RSK-04).
- **Geriye uyumluluk:** —
- **Durum:** Bilgi — sahiplerin kayıtlarında ilgili satırlar "authn-session tarafı uygulandı" olarak işaretlenebilir (mimar)

### 2026-11-01 — `SessionRevoker` anlamı: impersonation oturumları ve bekleyen girişler (güvenlik incelemesi, bilgi)
- **Talep eden:** authn-session (bağımsız güvenlik incelemesi)
- **Etkilenen dosya / sahip:** `crates/authn-session/src/service/revoke.rs`, `src/store/sessions.rs`, `migrations/2000_session_core.sql` / authn-session; tüketiciler authn-password, authn-account, authn-org, authn-admin; contracts §4 `SessionRevoker` satırı / mimar
- **Gereksinim:** ADM-04, PWD-09, RSK-04, SES-15, SES-22
- **Gerekçe:** Askıya alınan / tüm oturumları iptal edilen bir adminin impersonation oturumları 60 dakikaya kadar yaşıyordu; eski şifreyle başlamış bekleyen bir giriş (ör. `change_password` zorunlu adımı) şifre sıfırlamasından sonra tamamlanabiliyordu.
- **Önerilen değişiklik:** (uygulandı, yalnızca sahip olunan dosyalarda) (1) `revoke_all_for_user(user, …)` / `revoke_all_except(user, keep, …)` `user`'ın admin olarak başlattığı impersonation oturumlarını (`impersonator_user_id = user`) da iptal eder; kimlik doğrulama ayrıca impersonator'ın etkin platform admini olmasını ister (yetkisi alınan admin için iptal gerekmez). (2) Kullanıcı genelindeki iptaller (`revoke_all_for_user`, `revoke_all_except`, `revoke_everything`) kullanıcının açık `auth_challenges` kayıtlarını da kapatır — `RevocationReason::PasswordChanged` **hariç** (SES-22 zorunlu adımları bu nedenle bekleyen girişin içinden iptal eder; giriş akışı başka bir nedenle iptal yapan adımı challenge ortasında çalıştırmamalı). (3) Yeni kısmi indeks `sessions_impersonator_active_idx`. **authn-admin için:** adminin askıya alınması / ADM-03 iptali impersonation oturumlarını kendiliğinden bitirir; ayrıca çağrı gerekmez. **Mimar için:** contracts §4 `SessionRevoker` satırına bu iki anlam notu.
- **Geriye uyumluluk:** Port imzası değişmedi; yalnızca daha fazla şey iptal edilir (güvenli yön).
- **Durum:** Uygulandı (2026-11-01). Açık — **mimar:** contracts §4 notu

## authn-oidc-client

## authn-admin

## authn-server
