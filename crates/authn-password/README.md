# authn-password

Şifre yönetimi: NIST SP 800-63B rev.4 / OWASP ASVS uyumlu politika, NFKC normalizasyonu, HIBP k-anonimlik sızıntı kontrolü (+ çevrimdışı liste), zxcvbn güç tahmini (TR/EN geri bildirim), şifre değiştirme / ekleme / kaldırma, hesap varlığını sızdırmayan sıfırlama akışı, `must_change_password` bayrağı ve giriş akışı için şifre doğrulama (rehash, eski hash göçü, sahte doğrulama).

Dalga A crate'idir: yalnızca `authn-core`, `authn-crypto`, `authn-store`'a bağımlıdır. Diğer modüllerle yalnızca `authn-core` portları ve bu crate'in tanımladığı küçük trait'ler (`hooks`) üzerinden konuşur.

## Sahip olunan gereksinimler

| Kimlik | Uygulama | Testler (örnek) |
|--------|----------|-----------------|
| PWD-01 | `policy`: NFKC sonrası karakter (Unicode skaler değer) sayısı ile `min_length` ≤ n ≤ `max_length` (12 / 128); karakter sınıfı kuralı yok; her Unicode karakter ve boşluk serbest; 4096 bayt üstü girdi işlem yapılmadan `too_long` | `tests/policy.rs::pwd_01_*` |
| PWD-02 | Tek kanonik normalizasyon: `authn_crypto::password::canonicalize_password` (NFKC). Politika, HIBP sorgusu ve Argon2 aynı biçimi kullanır | `pwd_02_length_and_verdict_use_the_nfkc_form`, `tests/login.rs::pwd_02_*` |
| PWD-03 | `breach::HibpBreachChecker`: SHA-1'in yalnızca ilk 5 hex karakteri, `Add-Padding: true`, dolgu satırları (sayı 0) yok sayılır, `HttpClient` portu (`OutboundTarget::Trusted`, zaman aşımı + yanıt boyutu sınırı + dıştan ek `tokio` zaman aşımı), çevrimdışı liste (dosya, sıralı dizi), erişilemezse `Unknown` → fail-open (varsayılan; uyarı logu + metrik + `breach_check_skipped`) veya fail-closed (`503 password_breach_check_unavailable`) | `tests/breach.rs`, `tests/policy.rs::pwd_03_*` |
| PWD-04 | zxcvbn; minimum skor (3); kullanıcıya özel girdiler: görünen ad (+ kelimeleri), e-posta (+ yerel kısım parçaları, domain etiketi), servis adı (+ kelimeleri). Geri bildirim TR/EN, zxcvbn uyarıları/önerileri statik çevirilere eşlenir | `tests/policy.rs::pwd_04_*` |
| PWD-05 | `POST /v1/password/check`: IP başına rate limit, şifre loglanmaz (`SecretJson` çıkarıcısı gövde içeriğini hiçbir hatada yansıtmaz; `SecretString` `Debug`'ı redakte) | `tests/http.rs::pwd_05_*`, `tests/no_password_logging.rs` |
| PWD-06 | `POST /v1/me/password/change`: mevcut şifre (kullanıcı başına deneme limiti) **veya** son `session.step_up_max_age` içinde step-up; politika; mevcut şifreden farklı (NFKC eşdeğeri de "aynı"); mevcut oturum hariç tüm oturumlar `SessionRevoker::revoke_all_except`; bekleyen sıfırlama token'ları iptal; bildirim; audit | `tests/manage.rs::pwd_06_*` |
| PWD-07 | `POST /v1/password/forgot`: aynı durum/gövde/süre (hesaba özgü iş arka plan işinde); IP ve e-posta başına limit; 256 bit link token'ı, yalnızca SHA-256 saklanır, 30 dk; yeni istek öncekileri iptal eder; link ve kod gönderildikleri adrese bağlıdır (`target`) | `tests/reset.rs::pwd_07_*`, `tests/http.rs::pwd_07_*` (zamanlama dahil) |
| PWD-08 | Link'ler yalnızca `notify` tarafından `public_base_url` ile kurulur (bu crate yalnızca ham token verir, `Host` hiçbir yerde okunmaz); mobil için 6 haneli kod (aynı `group_id`, kod başına deneme limiti + e-posta başına gönderim limiti, tüm hatalar aynı `invalid_code`, başarısız yanıtlar için minimum süre) | `tests/http.rs::pwd_08_*`, `tests/reset.rs::pwd_08_*` |
| PWD-09 | `POST /v1/password/reset`: token/kod atomik tüketilir (eşzamanlı denemelerde tam olarak biri kazanır), politika ihlali token'ı yakmaz; aynı transaction'da şifre + `must_change` temizliği + tüm sıfırlama token'ları iptali + `revoke_all_for_user(PasswordReset, RevokeOptions { also_trusted_devices: true })` + bildirim + audit; oturum açılmaz (MFA atlanamaz) | `tests/reset.rs::pwd_09_*`, `tests/http.rs::pwd_09_*` |
| PWD-10 | `POST /v1/me/password`: step-up; şifre varsa `409 password_already_set`; eşzamanlı eklemelerde tek kazanan (kullanıcı satırı kilidi) | `tests/manage.rs::pwd_10_*` |
| PWD-11 | `DELETE /v1/me/password`: step-up; `LoginMethodInventory` en az bir güçlü yöntem (passkey veya bağlı kimlik) bildirmeli — transaction içinde, kullanıcı satırı kilitliyken; bekleyen sıfırlama token'ları iptal | `tests/manage.rs::pwd_11_*` |
| PWD-12 | `set_must_change_password` (admin), girişte `LoginPasswordOutcome::MustChangePassword`, `apply_required_password_change` (SES-22) bayrağı temizler | `tests/login.rs::pwd_12_*`, `tests/manage.rs::pwd_12_*` |

Ayrıca CRY-03/04/05'in giriş tarafı entegrasyonu: `tests/login.rs::cry_03_*`, `cry_04_*`, `cry_05_*`.

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `PasswordService::new(PasswordServiceDeps, PasswordServiceSettings)` | Servis (ucuz klonlanır). `PasswordServiceSettings::from_app_config(&AppConfig)` |
| `check_password(&ctx, &password, Option<EmailAddress>, Option<String>) -> Result<PasswordCheck>` | PWD-05 (rate limit'li) |
| `verify_login_password(&ctx, Option<UserId>, &password) -> Result<LoginPasswordOutcome>` | authn-session için: `Valid` / `MustChangePassword` / `Invalid`; kullanıcı yoksa sahte doğrulama, eski hash'lerde otomatik yükseltme |
| `request_reset(&ctx, &EmailAddress) -> Result<()>` | PWD-07 (yalnızca `rate_limited` ile başarısız olur) |
| `complete_reset(&ctx, ResetProof, &new_password) -> Result<()>` | PWD-08/09; `ResetProof::Link { token }` / `ResetProof::Code { email, code }` |
| `change_password(&ctx, &Principal, Option<&current>, &new) -> Result<()>` | PWD-06 |
| `add_password(&ctx, &Principal, &new)`, `remove_password(&ctx, &Principal)` | PWD-10, PWD-11 |
| `apply_required_password_change(&ctx, UserId, Option<SessionId>, &new)` | PWD-12 / SES-22 zorunlu adım |
| `set_must_change_password(&ctx, Actor, UserId, bool)` | PWD-12 / ADM-03 |
| `validator() -> Arc<dyn PasswordValidator>`, `policy()` | ACC-01 kaydı için port |
| `drain_background_jobs()` | Arka plan sıfırlama işlerini bekler (zarif kapanış, testler) |
| `HibpBreachChecker::from_config(&BreachCheckConfig, Arc<dyn HttpClient>)` | `BreachedPasswordChecker` portu |
| `PasswordPolicy`, `PolicySettings`, `policy::policy_violation_error` | Politika |
| `router<S>()`, `PasswordApi` | HTTP + OpenAPI |
| `LoginMethodInventory`, `ProfileLookup`, `ProfileHints`, `NoOtherLoginMethods`, `NoProfiles`, `is_strong_login_method` | Server'ın uygulayacağı trait'ler |
| `SecretJson<T>` | Gövdeyi asla loglarda yansıtmayan JSON çıkarıcısı |
| `breach::lookup_in_range_response`, `OfflineBreachList` | HIBP yanıtı / çevrimdışı liste ayrıştırıcıları (fuzz edilir) |

## Endpoint'ler

| Yöntem | Yol | Kimlik doğrulama | Başarılı yanıt | Hatalar |
|--------|-----|------------------|----------------|---------|
| `POST` | `/v1/password/check` | — | `200` `{acceptable, score, violations[], feedback[], breach_check_skipped}` | `415`, `400`, `422`, `429`, `503` |
| `POST` | `/v1/password/forgot` | — | `202 {"status":"accepted"}` (her zaman) | `422` (bozuk e-posta), `429` |
| `POST` | `/v1/password/reset` | link token **veya** e-posta + kod | `200 {"status":"password_reset"}` | `400 invalid_or_expired_token` / `invalid_code`, `422 password_policy_violation`, `429` |
| `POST` | `/v1/me/password/change` | oturum | `204` | `401 unauthenticated/step_up_required`, `403 current_password_incorrect/forbidden`, `409 password_not_set`, `422`, `429` |
| `POST` | `/v1/me/password` | oturum + step-up | `204` | `401`, `409 password_already_set`, `422` |
| `DELETE` | `/v1/me/password` | oturum + step-up | `204` | `401`, `409 password_not_set/password_removal_not_allowed` |

Hata kodları: `crates/authn-core/src/error/codes/password.rs` (`password_policy_violation`, `password_breach_check_unavailable`, `current_password_incorrect`, `password_unchanged`, `password_already_set`, `password_not_set`, `password_removal_not_allowed`) ve ortak kodlar.

## Konfigürasyon (`[password]`, `crates/authn-core/src/config/password.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `min_length` / `max_length` | 12 / 128 | NFKC sonrası karakter; tek faktörlü hesaplar için 15 önerilir |
| `min_strength_score` | 3 | zxcvbn 0–4 |
| `service_name` | `rust-authentication` | zxcvbn kullanıcı girdisi (≤ 128 karakter) |
| `check_endpoint_per_ip` | 30 / 1 dk | PWD-05 |
| `change_attempts_per_user` | 5 / 15 dk | **yeni** — mevcut şifre denemeleri (PWD-06) |
| `breach_check.enabled` / `hibp_range_url` / `timeout` | `true` / `https://api.pwnedpasswords.com/range/` / `3s` | |
| `breach_check.fail_open` | `true` | `false`: HIBP erişilemezken yeni şifre kabul edilmez (503) |
| `breach_check.offline_list_file` | yok | SHA-1 hex / `HASH:COUNT`, `#` yorum; açılışta yüklenir, hatalıysa servis açılmaz |
| `reset.token_ttl` / `code_ttl` / `code_max_attempts` | 30 dk / 15 dk / 5 | |
| `reset.code_enabled` | `true` | |
| `reset.per_email` / `per_ip` | 3 / saat, 20 / saat | İstek limitleri (gönderilen adrese göre — var/yok aynı) |
| `reset.verify_per_ip` | 30 / saat | **yeni** — tamamlama denemeleri (link + kod) |
| `reset.code_attempts_per_email` | 10 / saat | **yeni** — kod gönderimleri, hesap var olsun olmasın |

Konfigürasyon dışı ayarlar (`PasswordServiceSettings`): `step_up_max_age` (`session.step_up_max_age`), `code_failure_floor` (250 ms; başarısız kod yanıtlarının minimum süresi).

## Güvenlik notları

- **Hesap varlığı (PWD-07):** `forgot` yanıtı yalnızca rate limit (gönderilen adrese göre) ve iş kuyruğa alma içerir; kullanıcı araması, token üretimi, e-posta ve audit arka plan işindedir (`TaskTracker`, 16 eşzamanlı, en fazla 4096 bekleyen — taşmada aynı `202`, e-posta gitmez, metrik artar). Arka plan işi de her iki yolda eşdeğer iş yapar (token + kod üretimi/hash'i, aynı sorgular, audit). Kod yolunda bilinmeyen adres rastgele bir kimlik için aynı doğrulama transaction'ını çalıştırır; tüm başarısızlıklar (bilinmeyen adres, kod yok, yanlış, kilitli) aynı `invalid_code` ve en az `code_failure_floor` süre. Kod yolunda politika ön kontrolü yalnızca istemcinin verdiği girdilerle yapılır (görünen ad kullanılmaz), böylece politika yanıtı hesap verisine göre değişemez.
- **Tek kullanım ve yarışlar:** link `consume_link` (`UPDATE … RETURNING`), kod `verify_code` (`FOR UPDATE` + deneme sayacı, kendi transaction'ı — başarısız deneme her zaman sayılır). Tüm akışlarda kilit sırası: kullanıcı satırı → token'lar (kilitlenme yok).
- **Politika ihlali token yakmaz:** link önce tüketilmeden bakılır; kod yolunda politika koddan önce kontrol edilir.
- **MFA atlanamaz (PWD-09):** sıfırlama oturum açmaz; güvenilir cihazlar `RevokeOptions { also_trusted_devices: true }` ile silinir; MFA faktörlerine dokunulmaz.
- **Kimliğe bürünme / API anahtarı:** tüm `/v1/me/password*` işlemleri yalnızca oturumlu, kimliğe bürünülmemiş insan kullanıcıya açıktır.
- **Loglar:** şifre, token, kod, SHA-1 öneki asla loglanmaz; bozuk gövde hataları yalnızca hata kategorisi ve konumu loglar. Audit olaylarında e-posta yoktur.
- **DoS:** 4096 bayt üstü girdi normalizasyondan önce reddedilir; `max_length` üstü girdi zxcvbn/HIBP'ye gitmez; zxcvbn `spawn_blocking`'te ve yalnızca ilk 100 karaktere bakar; kullanıcı girdileri 32 adet × 64 karakterle sınırlı; HIBP yanıtı 512 KiB ile sınırlı; Argon2 `authn-crypto` semaforu altında.
- **Hash yükseltme:** CRY-03/04 yükseltmesi doğrulanan hash'e karşı compare-and-set'tir; eşzamanlı şifre değişikliğini ezmez; hatası girişi bozmaz.
- **Sıfırlama sırları adrese bağlıdır:** link ve kod, gönderildikleri normalize adresle (`one_time_tokens.target`) saklanır. Hem üretimde hem kullanımda kullanıcı satırı kilitliyken yeniden kontrol edilir: hesap uygun durumda olmalı, **hâlâ o adrese sahip olmalı** ve **hâlâ bir şifresi olmalı**. E-posta değişikliğinden (ACC-07) sonra eski adrese gitmiş link/kod çalışmaz; arka plan işi kilitsiz aramadan sonra adres değiştiyse e-posta hiç gönderilmez (alıcı her zaman kilitli kayıttan alınır). Sıfırlama şifre **ekleyemez**: şifresi kaldırılmış hesapta bekleyen sır reddedilir (PWD-10 step-up'ı atlatılamaz). Testler: `pwd_07_reset_secrets_die_when_the_account_changes_its_address`, `pwd_07_reset_mail_never_goes_to_an_address_the_account_left_during_the_request`, `pwd_10_reset_never_adds_a_password_to_a_passwordless_account`, `pwd_10_reset_is_not_issued_when_the_password_is_removed_during_the_request`.
- **Kod yolunda eşdeğer iş:** bilinmeyen adresle yapılan başarısız kod denemesi de bilinen hesaptaki gibi bir audit olayı yazar (`unknown_account`, konu yok, adres yok) — iki yol aynı veritabanı işini yapar, `code_failure_floor` yalnızca ek güvencedir (`pwd_08_unknown_address_code_failures_do_the_same_audit_work`).

### Güvenlik incelemesi — kabul edilen riskler

| Risk | Gerekçe / azaltım |
|------|-------------------|
| 6 haneli sıfırlama kodunun kaba kuvvetle tahmini | Kod başına 5 deneme, adres başına saatte 10 gönderim (hesap var olsun olmasın), IP başına saatte 30 tamamlama, adres başına saatte 3 istek. Hedeflenen tek hesap için başarı olasılığı saatte ≈ 10⁻⁵ (yılda ≈ %9); spesifikasyonun "6 haneli kod, deneme limitli" tasarımının gereği. Daha sıkı ortamlar `reset.code_enabled = false` (yalnızca 256 bit link) veya daha düşük `code_attempts_per_email` kullanmalıdır. |
| Adres başına limitlerle hedefli sıfırlama engelleme (DoS) | Saldırgan kurbanın adresi için saatlik istek/kod bütçesini tüketebilir veya kodu yakabilir. Limitler gönderilen adrese göre olmak zorunda (hesap varlığı sızmasın, PWD-07). Kod kilitlenince aynı gruptaki link geçerli kalır; IP limiti saldırganı da yavaşlatır. |
| zxcvbn ayrı bir semafor olmadan `spawn_blocking`'te | zxcvbn yalnızca ilk 100 karaktere bakar, kullanıcı girdileri 32 × 64 karakterle sınırlı, `max_length` üstü girdi zxcvbn'e hiç gitmez; kimliği doğrulanmamış uç IP başına dakikada 30 ile sınırlı; genel eşzamanlılık `authn-server` katmanında (PRT-11). zxcvbn içinde olası bir panik `spawn_blocking` tarafından yakalanır → `internal_error` (süreç düşmez, panik metni parolayı içermez). |
| Başarısız kod yanıt süresi ağır yük altında farklılaşabilir | Her iki yol aynı sorguları ve bir audit yazımını yapar, ek olarak minimum süre (`code_failure_floor`, 250 ms) uygulanır; kalan fark istatistikseldir. |
| `LoginPasswordOutcome::is_valid()` `MustChangePassword` için de `true` döner | Bilinçli: "şifre doğru mu" sorusunun cevabıdır. **authn-session oturum kararını `match` ile vermelidir**; `MustChangePassword` → yalnızca `RequiredAction::ChangePassword` (SES-22), asla tam oturum. |
| Bu değişiklikten önce üretilmiş, adres bağı (`target`) olmayan sıfırlama sırları reddedilir | Yalnızca dağıtım anındaki ≤ 30 dk'lık sırları etkiler; kullanıcı yeni istek yapar. Henüz üretim verisi yok. |
| Arka plan kuyruğu dolunca istek sessizce düşer | Bellek sınırı (4096 bekleyen iş); yanıt aynı `202`, metrik `authn_password_reset_requests_dropped_total` artar. |

## authn-server / Dalga B'nin bağlaması gerekenler

1. `PasswordServiceDeps` doldurulur: `pool`, `clock`, `CryptoServices::{passwords, otp}`, protect'in `RateLimiter`'ı, notify'ın `Notifier`'ı, audit'in `AuditSink`'i, session'ın `SessionRevoker`'ı, `HibpBreachChecker::from_config(&config.password.breach_check, protect_http_client)`, ve aşağıdaki iki trait'in uygulamaları.
2. **`LoginMethodInventory`** (server): webauthn passkey'leri → `LoginMethod::Passkey`, oidc-client bağlı kimlikleri → `LoginMethod::Social` (ve istenirse `MagicLink`/`EmailCode`), verilen `&mut PgConnection` üzerinden. Passkey silme / kimlik ayırma akışları aynı kullanıcı satırını `UserRepository::lock_for_update` ile kilitlemelidir.
3. **`ProfileLookup`** (server, authn-account üzerinden): görünen ad ve dil.
4. `impl FromRef<AppState> for PasswordService`, `.merge(authn_password::router::<AppState>())`, `openapi.rs`'e `PasswordApi`; `/v1/me/password*` session kimlik doğrulama katmanının arkasında olmalı.
5. Zarif kapanışta `password_service.drain_background_jobs().await`.
6. authn-account (ACC-01) için `PasswordValidator` portu: `password_service.validator()`.
7. **authn-session:** giriş/step-up → `verify_login_password` (sonuç `match` ile ele alınır; `is_valid()` `MustChangePassword` için de `true`'dur); `MustChangePassword` → `RequiredAction::ChangePassword` challenge'ı → `apply_required_password_change(ctx, user, Some(yeni_oturum), yeni_şifre)`. `SessionRevoker::revoke_all_for_user(.., RevokeOptions { also_trusted_devices: true })` güvenilir cihazları (authn-mfa) **aynı transaction'da** silmelidir (PWD-09, MFA-09).
8. **authn-admin:** ADM-03/06 → `set_must_change_password(ctx, Actor::User(admin), user, true)` (+ kendi `admin.action` olayı, gerekçe ile).

## Bilinen sınırlamalar / SHOULD notları

- Şifresi olmayan (passkey/sosyal) hesaplara sıfırlama e-postası gönderilmez: e-posta ile şifre eklemek PWD-10'un step-up şartını atlatırdı. Bu hesaplar sıfırlama isteğinde bilinmeyen hesapla aynı yanıtı alır. Kural hem sır üretiminde hem kullanımında kilit altında yeniden kontrol edilir.
- `suspended`, `disabled`, `pending_deletion`, `deleted` hesaplar sıfırlama alamaz; `locked` (yumuşak kilit, PRT-03) ve `pending_verification` alabilir. Sıfırlama sonrası kilidin açılması / e-postanın doğrulanmış sayılması authn-account'un (ACC-06) kararıdır, bu crate durum değiştirmez.
- Kod doğrulandıktan sonra (kendi transaction'ında tüketilir) şifre yazma transaction'ı başarısız olursa veya kilit altındaki son kontrol (durum, adres, şifre varlığı) geçmezse kullanıcı yeni kod ister (nadir; veritabanı hatası veya eşzamanlı hesap değişikliği).
- zxcvbn kütüphanesi şifrenin ilk 100 karakterinin sıfırlanmayan bir kopyasını oluşturur; serde/axum gövde tamponları da sıfırlanmaz (bellek dökümü tehdidi kapsam dışı).
- HIBP'ye giden 5 karakterlik önek, k-anonimlik tasarımının gereğidir (≈ 20 bit); başka bilgi gitmez.
- Arka plan işleri süreç ölürse kaybolur (kullanıcı tekrar ister); `drain_background_jobs` zarif kapanışta bekler.
- Şifre geçmişi (eski şifrelerin tekrar kullanımı) spesifikasyonda yok; NIST bunu önermediği için eklenmedi. Migration gerekmedi (`1100–1199` aralığı boş).

## Fuzz

`fuzz/fuzz_targets/hibp_range_parse.rs` (HIBP aralık yanıtı ve çevrimdışı liste ayrıştırıcıları). `fuzz/Cargo.toml` kaydı sözleşme değişikliği talebiyle istendi; aynı değişmezler `tests/breach.rs` içinde `proptest` ile çalışır.

## Komutlar

```bash
cargo test -p authn-password --all-features
cargo clippy -p authn-password --all-targets --all-features -- -D warnings
cargo fmt -p authn-password
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
