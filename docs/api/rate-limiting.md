# Oran sınırı davranışı (DOC-04)

Kaynaklar: `crates/authn-protect/src/rate_limit/{mod,gcra,layer}.rs`, `crates/authn-protect/src/login.rs`, `crates/authn-core/src/error/auth_error.rs` ve her modülün kendi sınırları (`crates/authn-core/src/config/*.rs`). Değerlerin tamamı ve doğrulama kuralları: [`docs/operations/configuration.md`](../operations/configuration.md).

## 1. Algoritma ve depolama

- **GCRA:** `{ limit = N, period = P }` politikası, `P / N` aralıkla yenilenen ve en fazla `N` birimlik patlamaya izin veren bir kovadır (sabit pencere değil; "son P süresinde en fazla N" gibi davranır, sürekli yenilenir). Ret, isteğin kabul edileceği **tam** süreyi hesaplar.
- **Arka uçlar** (`protect.rate_limit.backend`): `postgres` (varsayılan; UNLOGGED tablo, tek atomik UPSERT), `redis` (tek atomik Lua betiği; `redis` derleme özelliği gerekir), `memory` (instance başına; üretimde reddedilir). Üçü aynı aritmetiği aynı enjekte saatle çalıştırır, yani aynı kararı verir.
- Anahtarlar (IP, e-posta, kullanıcı…) depoda yalnızca anahtarlı hash olarak tutulur. IPv6 istemci adresleri /64'e toplanır.
- İstemci IP'si `server.trusted_proxies` ve `server.client_ip_header` ile çözülür (PRT-06). Vekil arkasında bu ayar yanlışsa **tüm istemciler vekilin IP'sini paylaşır** ve IP sınırları herkesi birlikte keser.

## 2. Katmanlar

1. **Genel HTTP sınırı** — `protect.rate_limit.requests_per_ip` (varsayılan 600 / 1 dk), IP başına, `/health/` hariç **her** istek. Bu katman bir sel koruyucusudur: sınırlayıcı hata verirse istek geçirilir (fail-open, uyarı loglanır).
2. **Eylem sınırları** — modüllerin kendi kararları (giriş, kayıt, sıfırlama, MFA kodları, passkey seremonileri, introspection, refresh, webhook yazma…). Bunlar güvenlik sınırlarıdır ve sınırlayıcı hatasında **kapalı** başarısız olur (istek hata ile reddedilir, geçirilmez).
3. **Giriş koruması** (`crates/authn-protect/src/login.rs`, PRT-02/03/05): her şifre denemesinde IP başına sınır (`login_per_ip`), hesap başına CAPTCHA eşiği (`login_per_account_captcha`) ve yumuşak kilit eşiği (`login_per_account_soft_lock`, süre `soft_lock_duration`). Passkey, magic link ve kodlar yumuşak kilide ve CAPTCHA yükseltmesine tabi değildir.
4. **Bildirim alıcı bütçesi** (`notify.recipient_limit`, 30 / 1 saat): aynı posta kutusuna/numaraya giden kullanıcı tetiklemeli mesajlar. Fazlası **sessizce düşer**, istemciye hata dönmez (hesap varlığı sızmaz). Güvenlik uyarıları sınırlanmaz.

## 3. İstemcinin gördüğü yanıtlar

| Durum | Kod | Başlık | Ne yapmalı |
|-------|-----|--------|------------|
| `429` | `rate_limited` | `Retry-After: <saniye>` | En az `Retry-After` kadar bekleyip tekrar deneyin. Değer saniyeye **yukarı** yuvarlanır, en az `1` |
| `429` | `login_temporarily_blocked` | `Retry-After` | Hesap yumuşak kilitli; passkey/magic link/e-posta kodu ile giriş hâlâ mümkündür |
| `429` | `too_many_attempts` | MFA kilidinde `Retry-After` | Kodun/faktörün deneme hakkı bitti veya MFA geçici kilidi (`mfa.lockout_duration`); bekleyin ya da yeni kod isteyin |
| `403` | `captcha_required` | — | İsteği CAPTCHA yanıtıyla tekrarlayın (`GET /v1/captcha/challenge?action=…`, ardından gövdede `captcha`) |
| `403` | `captcha_failed` | — | CAPTCHA yanıtı geçersiz/eski |

- Başarılı yanıtlar `X-RateLimit-*` türünde kalan kota başlıkları **taşımaz**; yalnızca ret `Retry-After` taşır.
- Cross-origin tarayıcı kodu `Retry-After`'ı okuyabilir (CORS `Access-Control-Expose-Headers: x-request-id, retry-after`).
- Hesap varlığını sızdırmamak için kimliksiz akışlardaki sınırlar (ör. `password.reset.per_email`, `password.reset.code_attempts_per_email`) **hesap var olsun olmasın** aynı şekilde uygulanır.
- Örnek: `POST /v1/password/forgot` IP **ve** gönderilen adres başına sınırlıdır ve aşımda `429` döner; adres sınırı adres kayıtlı olmasa da aynı sayaçla işler, dolayısıyla `429` hesap varlığını göstermez. Sınırın altında yanıt her zaman `202`'dir (iş arka planda yapılır; kuyruk doluysa e-posta gönderilmez, yanıt yine `202`).

## 4. Eylem sınırları özeti (varsayılanlar)

| Eylem | Anahtar | Varsayılan |
|-------|---------|-----------|
| Her istek (IP) | `protect.rate_limit.requests_per_ip` | 600 / 1 dk |
| Şifre girişi (IP) | `protect.rate_limit.login_per_ip` | 100 / 15 dk |
| Hesap başına başarısız giriş → CAPTCHA | `protect.rate_limit.login_per_account_captcha` | 10 / 15 dk |
| Hesap başına başarısız giriş → yumuşak kilit | `protect.rate_limit.login_per_account_soft_lock` | 50 / 1 saat (kilit `1h`) |
| CAPTCHA challenge (IP) | `protect.captcha.challenge_per_ip` | 30 / 1 dk |
| Kayıt (IP) / CAPTCHA'sız kayıt (IP) | `account.registration_per_ip` / `account.registration_captcha_free_per_ip` | 10 / 1 saat · 3 / 1 saat |
| "Adresinizle kayıt denendi" bildirimi (adres) | `account.registration_notice_per_email` | 3 / 1 gün |
| Doğrulama denemesi / yeniden gönderme (IP) | `account.verification.verify_per_ip` / `resend_per_ip` | 30 / 1 saat · 20 / 1 saat |
| Doğrulama kodu (adres) | `account.verification.code_attempts_per_email` | 10 / 1 saat |
| Kimliksiz link eylemleri (IP) | `account.link_actions_per_ip` | 30 / 1 saat |
| E-posta değişikliği (kullanıcı) | `account.email_change_per_user` | 5 / 1 gün |
| Veri dışa aktarma (kullanıcı) | `account.export_per_user` | 2 / 1 gün |
| Şifre sıfırlama isteği (adres / IP) | `password.reset.per_email` / `per_ip` | 3 / 1 saat · 20 / 1 saat |
| Sıfırlama tamamlama (IP) / kod denemesi (adres) | `password.reset.verify_per_ip` / `code_attempts_per_email` | 30 / 1 saat · 10 / 1 saat |
| Şifre güç denetimi (IP) | `password.check_endpoint_per_ip` | 30 / 1 dk |
| Mevcut şifreyle değişiklik (kullanıcı) | `password.change_attempts_per_user` | 5 / 15 dk |
| Step-up (kullanıcı) | `session.step_up_per_user` | 10 / 15 dk |
| Refresh (IP) | `session.refresh_per_ip` | 300 / 1 dk |
| Introspection (API anahtarı) | `session.introspection_per_client` | 600 / 1 dk |
| MFA başarısız doğrulama (kullanıcı) | `mfa.per_user_failures` | 10 / 15 dk (sonra `mfa.lockout_duration`) |
| E-posta OTP gönderimi (kullanıcı) | `mfa.email_otp.sends_per_user` | 10 / 1 saat |
| SMS (numara / IP / kullanıcı / küresel günlük) | `mfa.sms.per_number` / `per_ip` / `per_user` / `global_daily_budget` | 5 / 1 saat · 10 / 1 saat · 5 / 1 saat · 1000 / 1 gün |
| Passkey kaydı (kullanıcı) / girişi (IP) | `webauthn.registration_per_user` / `authentication_per_ip` | 10 / 1 saat · 60 / 15 dk |
| Sosyal giriş başlatma / native / geri dönüş (IP) | `oidc_client.start_per_ip` / `native_per_ip` / `callback_per_ip` | 60 / 10 dk (her biri) |
| Organizasyon kurma (kullanıcı) | `org.creates_per_user` | 10 / 1 gün |
| Davet gönderimi (org / org + alıcı) | `org.invitation_sends_per_org` / `invitation_sends_per_recipient` | 50 / 1 saat · 5 / 1 gün |
| Davet / devir token denemesi (kullanıcı) | `org.token_attempts_per_user` | 30 / 1 saat |
| Domain doğrulama (org) / sahiplik devri (org) | `org.domain_checks_per_org` / `ownership_transfers_per_org` | 30 / 1 saat · 10 / 1 saat |
| Geçersiz API anahtarı (IP) | `org.api_keys.auth_failures_per_ip` | 30 / 15 dk |
| Audit listeleme (principal) | `audit.rate_limits.events_read` | 60 / 1 dk |
| Webhook yazma / yeniden teslim (org) | `audit.rate_limits.webhook_write` / `webhook_redeliver` | 60 / 1 saat · 30 / 1 saat |

Platform admin API'sinin kendi admin başına ve küresel bütçeleri vardır (dört göz istekleri `admin.four_eyes_max_*`; diğerleri authn-admin içinde sabit, bkz. `crates/authn-admin/README.md`).
