# Kalan işler — ayrıntılı görev tarifleri

> Önce [`docs/HANDOFF.md`](../HANDOFF.md)'yi oku. Bu dosya, devralan LLM'in **ne yapacağını, hangi sırayla, hangi kurallarla ve nasıl doğrulayacağını** anlatır. Her görev, bir önceki bölümlerde tarif edilen "uzman yazar + bağımsız denetçi" deseniyle yapılmalı (bkz. HANDOFF §6).

## 0. Sıra ve bağımlılıklar

```
1. Login akışları (authn-session/src/login) ──┐
2a. Sosyal giriş (authn-oidc-client) ─────────┼──► 3. Sunucu entegrasyonu ──► 4. Uçtan uca testler
2b. Admin API (authn-admin) ──────────────────┘                                      │
                                                                                      ▼
                                              5. Genel güvenlik denetimi ──► 6. QA sertleştirme ──► 7. Dokümantasyon
```

- **2a ve 2b birbirinden bağımsız** (ikisi de `SessionIssuer` portunu kullanır, `authn-session`'a bağımlı olamaz); 1 ile paralel çalışabilir. Disk/CPU sınırı nedeniyle aynı anda en fazla 2 ağır iş çalıştır.
- **3, hepsi bitmeden başlamamalı** (sunucu hepsini bağlar). İstersen 1. maddeden önce sunucu iskeletini hazırlayıp bitenleri bağlamaya başlayabilirsin; ama uçtan uca testleri (4) ancak 1, 2a, 2b ve 3'ten sonra yazabilirsin.
- **5 ve 6, entegre sistem üzerinde** yapılır; modül bazlı denetimler zaten yapıldı, buradaki amaç **modüller arası** akışlar.
- Her adımda kapılar yeşil kalmalı, her modül kendi ayrıntılı commit'iyle push edilmeli.

Tüm görevlerde geçerli: HANDOFF §5 (kurallar) ve `contracts.md` §3 (dosya sahipliği), §11 (güvenlik), §15.7 (Dalga B için bağlayıcı çağrı kuralları).

---

## 1. Login akışları — `crates/authn-session/src/login/**` (SES-01, 02, 18, 19, 20, 21, 22)

**Durum:** Oturum çekirdeği (`SessionService`, `establish`, challenge API'si, `complete_login`, middleware) bitti ve push edildi. `src/login/` **henüz yok**; çekirdeğin README'si ve [`module-apis.md`](module-apis.md) §1 hangi yapı taşlarını sunduğunu anlatıyor. Çekirdek dosyalarını yalnızca zorunluysa değiştir ve onların testlerini yeşil tut.

**Yazılacaklar:**

1. **`POST /v1/login/password` (SES-01).** Sıra kritik:
   1. `LoginProtection::check_attempt` — **her denemede tam bir kez** (bütçe tüketir; başarıda `record_success` iade eder, başarısızlıkta `record_failure` çağır). Aynı identifier için eşzamanlı denemelerin eşiği aşamaması bu sözleşmeye dayanıyor.
   2. CAPTCHA istenirse doğrula (`CaptchaService`).
   3. `PasswordService` ile şifre doğrulama: kullanıcı yoksa sahte hash yolu (CRY-05), eski hash yükseltme/rehash, `must_change_password`. Sonucu **enum ile eşle** (`MustChangePassword` ⇒ `RequiredAction::ChangePassword`, tam oturum yok; `is_valid()` tek başına kullanılmaz).
   4. Hesap durumu ve doğrulanmamış hesap politikası: doğru şifreden **sonra** `AccountService::assess_login`; `Denied(reason)` ⇒ `reason.into_error(now)`; `required_actions` ⇒ SES-22. Durum bilgisi yalnızca doğru şifreden sonra açıklanır.
   5. Risk: `RiskEvaluator` — `medium` ⇒ MFA iste (kayıtlıysa) ya da e-posta onayı; `high` ⇒ engelle + bildir (politika `risk.high_action` ile değişir).
   6. MFA politikası: `authn-mfa` politika değerlendirmesi (org politikası + admin bayrağı); güvenilir cihaz varsa ve politika izin veriyorsa atla (MFA-09).
   7. Zorunlu adımlar (SES-22): şifre değiştir, yeniden onay (`AccountService` terms), MFA kaydı. Bunlar tamamlanmadan tam oturum yok.
   8. Hepsi geçerse `establish`, aksi halde `create_challenge`.
   Başarısızlık yanıtı **her durumda aynı** (`invalid_credentials`), süre eşitlenmiş.
2. **MFA challenge tamamlama (SES-02).** `POST /v1/login/challenge/{id}/...` ile TOTP, kurtarma kodu, e-posta OTP, SMS OTP, passkey. **`verify_factor` çağrılmadan önce kanıtın türü challenge'ın `allowed_factors` listesinde değilse reddet** (MFA denetçisi bunu bilinçle Dalga B'ye bıraktı; atlanırsa politika atlatılır: örn. org SMS'i yasaklasa da SMS kabul edilir, admin için phishing-resistant şartı atlanır). Deneme sınırı, tek kullanımlık, challenge'ı başlatan istemciye bağlı. OTP gönderme uçları bekleme süreli.
3. **Zorunlu adım tamamlama uçları** challenge üzerinde (şifre değiştirme → `PasswordService`, şartları kabul → `AccountService`, MFA kaydı).
4. **Magic link (SES-18)** `POST /v1/login/magic-link` (hesap varlığını sızdırmaz). Doğrulama **POST ile**, GET ile tüketilmez (link önizleme botları). Cihaz bağlama çerezi; başka cihazda açılırsa açık onay ekranı. `one_time_tokens` amacı `magic_link`.
5. **E-posta kodu ile giriş (SES-19)**: amaç `login_code`, challenge kimliğine bağlı, 6 hane/10 dk/5 deneme.
6. **Passkey ile giriş (SES-20, 21)**: `authn-webauthn` kimlik doğrulama API'si; discoverable + conditional UI. `binding_token` web'de `HttpOnly; Secure; SameSite=Strict` çerezde; `target` istemciden değil **session kaydından**. UV'li passkey tek başına MFA sayılır (`amr`: `hwk`/`swk` + `mfa`) — org politikası aksini söylemedikçe. Passkey ikinci faktör olarak da kullanılabilir.
7. **RSK-04 "bu ben değilim":** yeni cihazdan girişte bildirim + `not_me` token'ı. `authn_protect::risk::NotMeTokenIssuer` trait'ini **authn-session uygular**; `POST /v1/login/not-me/{token}` tüm oturumları ve güvenilir cihazları iptal eder ve şifre sıfırlamaya zorlar.
8. **Org bağlamı:** girişte kullanıcının varsayılan/seçili organizasyonunun politikaları (izinli giriş yöntemleri, phishing-resistant MFA zorunluluğu, IP izin listesi) uygulanır; `verify_login_org` bunun için var.

**Mutlaka kapatılacak çekirdek açıkları** ([`module-apis.md`](module-apis.md) §1.5):
- `complete_login` **henüz risk değerlendirmesi (RSK-03) ve güvenilir cihaz kontrolü (MFA-09) yapmıyor.** Sosyal giriş bunu kullanacağı için, sosyal giriş yayınlanmadan önce eklenmeli.
- Kayıtsız (`pending_verification`) hesaplarda magic link / e-posta kodu oturumu açmadan önce **aynı transaction'da** `AccountService::confirm_mailbox_control_in_tx(conn, Some(ctx), user, MailboxProof::Passwordless)` çağrılmalı (pre-hijacking savunması, ADR 0002).
- `woothee` bağımlılığı kullanılmıyor, kaldırılabilir.

**Testler (en az):** tüm akışlar uçtan uca (sahte portlarla); şifre girişi ve magic link için hesap varlığı sızıntısı (gövde/durum/**zamanlama** — `authn_testkit::timing`); MFA atlatma denemeleri (yanlış faktör türü, challenge'ı yeniden kullan, challenge'ı başka kullanıcıya/istemciye taşı, zorunlu adımı atla, org SMS'i yasaklıyken SMS, admin phishing-resistant gerektirirken kurtarma kodu); CAPTCHA/yumuşak kilit entegrasyonu ve **eşzamanlı** denemeler; magic link'in GET ile tüketilmemesi; `not_me` akışı; `webauthn-authenticator-rs` yazılımsal authenticator ile passkey girişi; kayıtsız hesapta magic link ve pre-hijacking senaryosu.

**Commit:** `feat(session-login): …`.

---

## 2a. Sosyal giriş — `crates/authn-oidc-client` (SOC-01 … SOC-09)

**Durum:** Crate boş iskelet (yalnızca README). Tablolar hazır: `identities`, `oauth_states` (migration `0007`). Migration aralığı **2100–2199**; konfigürasyon `crates/authn-core/src/config/oidc_client.rs`; hata kodları `error/codes/oidc_client.rs`.

**Kurallar / sözleşmeler:**
- `authn-session`'a **bağımlı olamazsın**; oturumu `SessionIssuer` portuyla aç. MFA gerekiyorsa tam oturum yerine, portun/çekirdeğin belgelediği yolla bir **challenge** al (SOC-09: sağlayıcının MFA'sına varsayılan olarak güvenme; `trust_provider_mfa` ayarı kapalı).
- HTTP'yi `authn-protect`'in SSRF-güvenli `HttpClient` portundan geçir; `openidconnect`/`oauth2` varsayılan özellikleri kapalı. Herhangi bir `reqwest` kullanımından önce `authn_core::tls::install_crypto_provider()`.
- Apple `client_secret` (ES256 JWT) **yalnızca `p256 0.14`** ile imzalanır (bkz. HANDOFF §7: eski `p256/p384 0.13` yalnızca açık anahtar doğrulaması için).
- **Pre-hijacking'i geri getirme** (ADR 0002): kimlikleri hiçbir zaman `pending_verification` hesaplara bağlama; sağlayıcının doğrulanmış e-postasıyla bağlıyorsan `MailboxProof::Passwordless` ile `confirm_mailbox_control_in_tx` çağır.
- Kimlik ayırma transaction'ının başında `UserRepository::lock_for_update(conn, user)` (PWD-11 yarışı: son giriş yöntemini iki eşzamanlı istekle silmeyi önler); son giriş yöntemi kontrolü için server'ın uygulayacağı `LoginMethodInventory` benzeri bir trait tanımla.

**Yazılacaklar:**
1. Sağlayıcı kaydı konfigürasyondan: **Google, Apple, Microsoft (çok kiracılı; `iss` kontrolü `https://login.microsoftonline.com/{tid}/v2.0` ile token'daki `tid`, isteğe bağlı kiracı izin listesi), GitHub (OAuth2; `/user` ve `/user/emails`, yalnızca birincil+doğrulanmış e-posta "doğrulanmış" sayılır), genel OIDC (discovery, önbellek, issuer birebir eşleşmeli)** (SOC-01).
2. Web akışı (SOC-02): `GET /v1/oauth/{provider}/start` → sunucu tarafı `oauth_states` satırı (state, nonce, PKCE S256 verifier, `return_to` — `authn-protect` redirect doğrulayıcısıyla, 10 dk, tek kullanımlık, tarayıcıya bağlama çerezi); `GET|POST /v1/oauth/{provider}/callback` (Apple `form_post` kullanır) → state + bağlama doğrula, PKCE ile kod takası.
3. ID token doğrulama (SOC-03): imza (sağlayıcı JWKS'i önbellekli, bilinmeyen `kid`'de rate limit'li yenileme), `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`; `alg: none`/HS* reddi.
4. Native akış (SOC-04): `POST /v1/oauth/nonce`, sonra `POST /v1/oauth/{provider}/native` (SDK'dan gelen ID token; nonce zorunlu; audience = yapılandırılmış native client id'leri).
5. Hesap eşleştirme (SOC-05, 06): kimlik `(provider, subject)` ile; **e-postayla otomatik birleştirme yok** (yalnızca yapılandırma `email_verified=true` + güvenilir sağlayıcı için açarsa); aksi halde "bağlama gerekli" sonucu. `/v1/me/identities` bağla/ayır (step-up, son giriş yöntemi koruması). Yeni kullanıcı yalnızca sağlayıcı doğrulanmış e-posta bildiriyorsa doğrulanmış açılır.
6. Apple (SOC-07): ES256 `client_secret`, süresi dolmaya yakın yenilenir; ilk girişte gelen ad; özel röle adresleri.
7. SOC-08: sağlayıcı token'ları varsayılan saklanmaz; saklanırsa zarf şifreli (AAD ile).

**Testler (wiremock sahte sağlayıcılarla):** her sağlayıcı türü için web+native akış; state/nonce/PKCE uyuşmazlığı; state yeniden oynatma; yanlış `iss`/`aud`/`azp`/süresi dolmuş/gelecek `iat`; alg karışıklığı; JWKS rotasyonu; `return_to` ile open redirect; Microsoft kiracı sahteciliği; GitHub doğrulanmamış e-posta; bağlama kuralları; pre-hijacking etkileşimi; PWD-11 yarışı.

**Commit:** `feat(oidc): …`.

---

## 2b. Admin API — `crates/authn-admin` (ADM-01 … ADM-08)

**Durum:** Crate boş iskelet. Migration aralığı **2200–2299**. Platform admin durumu `users.is_platform_admin` (ve `is_break_glass`, `0002_users.sql`) sütunlarında.

**Kullanılacak API'ler** (hepsi push edilmiş): `AccountService::change_status_in_tx` (+ aynı transaction'da `SessionRevoker`), `MfaService::reset_user_mfa_in_tx`, `PasswordService::set_must_change_password`, `LoginProtection::unlock`, `AccountService::confirm_mailbox_control_in_tx(…, MailboxProof::Administrator{admin})`, authn-audit sorgu/doğrulama API'leri, `SigningKeyRepository` (acil rotasyon). Personel işlemleri `admin.*` olay türleriyle veya impersonator alanıyla audit'e yazılmalı (aksi halde org audit log'unda personel kimliği maskeli IP ile görünür).

**Yazılacaklar:**
1. `/v1/admin/**` router'ı: yalnızca platform admini, oturumda **phishing-resistant MFA (passkey) `amr`'si**, **her admin işlemi için son 10 dk içinde step-up**, isteğe bağlı IP izin listesi. Salt-okunur impersonation yapılmış principal'lar ve impersonator'lar admin uçlarını **kullanamaz** (ADM-01).
2. Kullanıcı arama/listeleme (keyset sayfalama, filtre, sırsız), detay (ADM-02).
3. İşlemler (ADM-03): askıya al/geri al, kilit aç, oturumları kapat, şifre sıfırlamaya zorla, `must_change_password`, MFA sıfırla (**gerekçe zorunlu**, kullanıcıya bildirim), e-postayı doğrulanmış işaretle (gerekçe zorunlu). Her biri tek transaction + audit (ADM-08, gerekçe alanı kaydedilir).
4. Impersonation (ADM-04): süreli (varsayılan 15, en çok 60 dk), gerekçe zorunlu, **varsayılan salt-okunur**, `act` claim'i (RFC 8693). `SessionIssuer::start_impersonation_with(ctx, req, client, Some(admin_session))` çağır; **kullanıcı bildirimini ve audit olayını bu çağrı zaten yazıyor, tekrar gönderme.** Adminlere ve break-glass hesaplarına uygulanamaz. Admin askıya alınınca/oturumları kapatılınca impersonation otomatik biter (session çekirdeğinde var).
5. Break-glass (ADM-05): CLI `create-admin` için fonksiyon; güçlü rastgele şifre bir kez yazdırılır ya da passkey kayıt bağlantısı; her kullanım yüksek öncelikli güvenlik olayı üretir.
6. Acil durum (ADM-06): tüm kullanıcıların oturumlarını kapat; imza anahtarını acil rotasyon (`SigningKeyRepository::emergency_rotate`, ardından `SessionService::invalidate_signing_keys()`); belirli tarihten önce şifresi değişmemiş herkese sıfırlama zorunluluğu.
7. Audit sorgu/dışa aktarma/zincir doğrulama (ADM-07).

**Testler:** yetki matrisi (admin olmayan, passkey amr'siz admin, step-up'sız admin, impersonated principal, IP izinli değil → hepsi reddedilir); her işlem gerekçe ile audit'lenir; impersonation kısıtları; acil durum işlemleri; sayfalama.

**Commit:** `feat(admin): …`.

---

## 3. Sunucu entegrasyonu — `crates/authn-server` (ARC-03, ARC-09, ARC-11, OPS-01 … OPS-10, PRT-11)

**Durum:** Yalnızca iskelet: `app.rs` (katman sırası dokümante), `state.rs` (`AppState` + `FromRef` örneği), `serve.rs`, `cli.rs` (beş komut "henüz uygulanmadı" hatasıyla çıkıyor, panik yok), `/health/live`, `/health/ready`, `/openapi.json`, `GET /v1/time` örnek route.

**Tek kaynak:** [`docs/architecture/contracts.md`](../architecture/contracts.md) **§15** — her kanca trait'inin, port uygulamasının, servisin, router'ın, katmanın, arka plan işinin ve CLI adımının tablosu; ayrıca [`module-apis.md`](module-apis.md). Her satırı uygula ve uygulanınca `contract-change-requests.md`'de ilgili talebi "Uygulandı" işaretle.

**Yazılacaklar:**
1. **Servis inşası ve `AppState`** — sıra önemli: `MfaService` → `authn_session::PgSessionRevoker::new(clock, audit, events, mfa)` → `AccountService` (düz revoker'ı `sessions` olarak al) → `authn_account::AccountAwareSessionRevoker::new(Arc::new(revoker), account)`; **sarmalanmış revoker**'ı password, org ve diğer modüllere ver → `SessionService::new(…)`. `PasswordReset` nedeni yalnızca e-postayla gelen sıfırlama tamamlandığında kullanılmalı.
2. **Kanca trait uygulamaları** (§15.1): `LoginMethodInventory`, `ProfileLookup`, `OrganizationOwnership`, `MfaPolicySource`, `AccountMethodsSource`, `PasskeyPolicySource`, `AuditAccessPolicy`, outbox `notification` köprüsü, her modülün `DataExporter`'ı.
3. **Router'lar ve OpenAPI** (§15.3): her modülün `router::<AppState>()`'ı, `/.well-known/*`, OpenAPI birleştirme. Cargo feature'ları: `authn-mfa/sms`, `authn-webauthn/passkey`, `authn-notify/sms`, isteğe bağlı `authn-protect/redis`.
4. **Katmanlar** (§15.4, OPS-02 sırası): request id → izleme → zaman aşımı → gövde sınırı (PRT-11) → host doğrulama → güvenlik başlıkları → CORS → rate limit → kimlik doğrulama → CSRF → handler. Kimlik doğrulama yuvasında **`authn_session::authenticate`** kullanılır; `authn_org::api_key_middleware` ile **birlikte kurma** (ikisi birden isteği bozar). Org API anahtarlarının hangi route'larda nasıl çözüldüğünü `authn-session` ve `authn-org` README'lerinden doğrula. `/v1/me*` rotaları ve `/v1/email/change/confirm` oturum + CSRF arkasında olmalı; `POST /v1/email/verify` oturum varsa `Principal` eklemeli.
5. **Arka plan işleri** (§15.5, OPS-06; çoklu instance güvenli): outbox teslimi, audit saklama/kontrol noktası, doğrulanmamış hesap/silme/kilit/rezervasyon temizliği, organizasyon silme/davet süresi, MFA/passkey/rate limit/CAPTCHA/yumuşak kilit/token temizliği, imza anahtarı rotasyonu (`rotate_if_due`, token üretilmeden **önce** çağrılmalı), `SessionService::purge_expired`.
6. **Açılış/kapanış** (§15.6, OPS-07): TLS sağlayıcı kurulumu, `NotifyServices::from_config` (Tokio içinde), terms senkronu, ayrı **bakım rolü havuzu** (OPS-10), zarif kapanış.
7. **CLI** (OPS-01): `serve`, `migrate`, `check-config` (şablon doğrulaması dahil), `create-admin` (ADM-05), `rotate-signing-key`, `rotate-kek`/`reencrypt` (zarf şifreli her `*_ciphertext` kolonu için `EnvelopeCipher::rewrap`, imza anahtarları, webhook sırları, MFA sırları), `verify-audit-chain`, `migrate-legacy-hashes` (`PasswordHasher::wrap_legacy_digest`). Beşi şu an "uygulanmadı" hatası veriyor.
8. **Gözlemlenebilirlik** (OPS-03, 04): kişisel veri maskeli JSON log (`mask_email`/`mask_ip`), Prometheus metrikleri ayrı portta (giriş başarı/başarısızlık neden koduna göre, MFA kullanımı, kayıt, sıfırlama, rate limit tetiklenmesi, token yeniden kullanım tespiti, outbox derinliği, gecikme histogramları). Prometheus yükleyici kurulu ama **hiçbir metrik yayılmıyor**; modüllerde (`authn-session/src/metrics.rs` vb.) tanımlı olanları bağla.
9. **Dockerfile** (çok aşamalı, root olmayan kullanıcı, minimal imaj) — `docker-compose.yml` zaten var (PostgreSQL 16, Redis 7, Mailpit + sabit dev sertifikası). `config/example.toml` son hâli. **Not:** Docker daemon olmayan ortamlarda Dockerfile/compose doğrulanamaz; bunu rapor et, doğrulanmış gibi gösterme.

**Commit'ler:** `feat(server): …` (mümkünse mantıklı parçalara böl: servis inşası, router/katman, işler, CLI, gözlemlenebilirlik).

---

## 4. Uçtan uca testler — `crates/authn-server/tests/` (TST-02, TST-06)

Gerçek router + gerçek PostgreSQL + dış servisler için sahte/`wiremock` (ağ yok, TST-08).

**TST-06 senaryoları (spesifikasyondan):**
- kayıt → e-posta doğrulama → giriş → TOTP kaydı → çıkış → TOTP ile giriş → kurtarma kodu ile giriş
- şifre sıfırlama (link ve mobil kod), sıfırlama sonrası tüm oturumların ve güvenilir cihazların düşmesi
- passkey kaydı/girişi (yazılımsal authenticator); **passkey step-up başarı yolu** (yalnızca hata yolları test edilmişti)
- mobil token akışı: refresh rotasyonu, eski token ile yeniden kullanım tespiti → aile iptali
- organizasyon: oluştur → davet → kabul → rol değişikliği → politika (MFA zorunlu) etkisi; API anahtarı ile erişim
- sosyal giriş (`wiremock` sahte sağlayıcı)
- admin impersonation (salt-okunur, sonlanma)

**TST-02 güvenlik regresyonları (HTTP düzeyinde):** hesap varlığı sızıntısı (gövde, durum kodu, **zamanlama**, istatistiksel tolerans), token ve OTP yeniden kullanımı, refresh yeniden kullanım tespiti, TOTP replay, CSRF + login CSRF, open redirect, Host başlığı zehirlenmesi, IDOR/kiracılar arası erişim, ayrıcalık yükseltme, **tek kullanımlık token'ın eşzamanlı tüketimi (tam olarak biri başarılı)**, rate limit, JWT `alg`/`none`/yanlış `kid`/süresi dolmuş/yanlış `aud`, SSRF (webhook URL'si).

Bu aşama ilk kez **modüller arası uyumsuzlukları** ortaya çıkaracak. Bulduğun her uyumsuzluğu kök nedenine göre düzelt (çoğu zaman bir modülün API'sini yanlış sırayla/yanlış varsayımla çağırmaktır) ve regresyon testi ekle.

---

## 5. Genel güvenlik denetimi (entegre sistem üzerinde)

Modül bazlı denetimler yapıldı; burada **sistem düzeyinde, modüller arası** zincirleri ara. Önerilen 6 bağımsız denetçi (her biri yalnızca okur + bulgu testi yazar, sonra bulgular ikinci bir ajanla "çürütmeye çalışarak" doğrulanır, doğrulananlar düzeltilir):

1. **Kimlik doğrulama zincirleri:** giriş → MFA → oturum → step-up → org politikası; MFA/politika atlatma, oturum sabitleme, token çalma/yeniden kullanım, refresh ailesi, JWT doğrulama boşlukları.
2. **Hesap ele geçirme yolları:** şifre sıfırlama, e-posta değişikliği + geri alma, sosyal giriş bağlama, magic link, pre-hijacking varyantları, hesap kurtarma, destek/admin yolları.
3. **Yetkilendirme ve kiracı izolasyonu:** her endpoint için yetki matrisi, IDOR, ayrıcalık yükseltme, API anahtarı kapsamları, servis hesapları, impersonation.
4. **Web saldırı yüzeyi:** CSRF/CORS/başlıklar/cookie öznitelikleri, open redirect, SSRF (webhook, OIDC, HIBP, SMS), header/CRLF enjeksiyonu, Host zehirlenmesi, HTTP request smuggling'e açık yapılandırmalar.
5. **Kriptografi, sırlar, loglama:** zarf şifreleme AAD'leri, anahtar rotasyonu prosedürleri (KEK, pepper, imza anahtarı, webhook sırları), loglarda/`Debug`'da/audit'te/outbox'ta/hata mesajlarında sır sızıntısı taraması (`grep` + test), sabit zamanlı karşılaştırmalar, rastgelelik kaynakları.
6. **Kullanılabilirlik / DoS / zamanlama:** kimlik doğrulama öncesi pahalı işler (Argon2 semaforu, HIBP, DNS), sınırsız girdi, kuyruk büyümesi, yarışlar/deadlock (hesap tamamlama ile sıfırlama arasındaki kilit sırası ADR 0002'de belgeli), hesap varlığı zamanlama farkları (bcrypt/PBKDF2 hesaplarının Argon2'den farklı süre alması bilinen kısmi sızıntı — göç tamamlanana dek).

Her bulgu için: şiddet, kanıt (başarısız test), düzeltme, regresyon testi. Düzeltilmeyenler gerekçeyle `docs/security/` altına yazılır.

---

## 6. QA sertleştirme

- **Fuzz:** tüm hedefleri en az 10–30 dk koştur (şimdiye dek yalnızca 30 sn–2 dk); korpus/artefakt klasörlerini sonra sil (disk).
- **Flaky tarama:** test paketini üç kez art arda ve CPU yükü altında koştur; zamanlama testleri ve yarış testleri için toleransları gözden geçir.
- **Kapsam:** `cargo llvm-cov --workspace --all-features` yerelde tamamlanmadı (CI'da çalışır); raporu üret, güvenlik açısından kritik yollardaki (kimlik doğrulama, token, kripto) kapsanmayan dalları test et.
- **İzlenebilirlik:** spesifikasyondaki her gereksinim kimliği için en az bir test adında kimliğin geçtiğini doğrulayan küçük bir betik (`scripts/check-requirement-coverage.sh`) ve bunu CI'ya ekle. Eksikleri kapat.
- **Bağımlılık hijyeni:** `cargo deny check`, `cargo audit`; CI'daki GitHub Actions'ları sürüm etiketi yerine commit SHA'sına sabitle (tedarik zinciri sertleştirmesi).
- Test geçmesi dışında: `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`.

---

## 7. Dokümantasyon (Türkçe; kodla birebir doğru olmalı)

Mevcut: mimari belgeler, ADR'ler, KVKK envanteri, her crate'in README'si (yazılmış olanlar). Eksikler:

| Gereksinim | Dosya | İçerik |
|------------|-------|--------|
| DOC-01 | `README.md` (kök) | Ne olduğu, özellik listesi, docker compose ile 5 dakikada çalıştırma, mimari özet, lisans politikası |
| DOC-02 | `docs/architecture/` | Büyük ölçüde var; akış diyagramları ekle (kayıt, giriş+MFA, token rotasyonu, şifre sıfırlama, sosyal giriş, davet) |
| DOC-03 | `docs/security/threat-model.md`, `asvs-mapping.md`, `cryptography.md`, `known-limitations.md`, `SECURITY.md` (kök) | STRIDE tehdit modeli (varlıklar, güven sınırları, saldırgan profilleri); **OWASP ASVS eşleme tablosu: her gereksinim → kod → test**; kriptografi kararları; kabul edilen riskler (`module-apis.md`'deki "Accepted risks" ve ADR 0002 kalan riskleri); zafiyet bildirim süreci |
| DOC-04 | `docs/api/` | Endpoint referansı (OpenAPI'den üret), hata kodları kataloğu, kimlik doğrulama başlıkları/çerezleri, rate limit davranışı, sayfalama |
| DOC-05 | `docs/integration/` | web (aynı site çerez, BFF, SPA), iOS (passkey, Sign in with Apple, Keychain), Android (Credential Manager, passkey, Keystore), kaynak sunucusu (JWKS ile JWT doğrulama örneği), B2B (organizasyon, davet, roller, API anahtarı), webhook alıcısı (imza doğrulama örneği) |
| DOC-06 | `docs/operations/` | Konfigürasyon referansı (her ayar), dağıtım, anahtar yönetimi ve rotasyon runbook'ları (KEK, pepper, imza anahtarı), olay müdahalesi runbook'ları (hesap ele geçirme, toplu oturum kapatma, imza anahtarı sızıntısı, pepper/KEK sızıntısı), yedekleme, izleme/alarm önerileri, ölçekleme, en az yetki veritabanı rolleri (OPS-10) |
| DOC-09 | `docs/roadmap.md` | Faz 2 (OAuth 2.1/OIDC sağlayıcısı + RFC 8252 + device flow, kurumsal SSO, SCIM 2.0, DPoP, Single Logout) ve Faz 3 (SAML 2.0) kapsamı ve **mevcut mimarideki genişleme noktaları** (`identities` tablosu, `amr`/`acr` modeli, JWKS/anahtar altyapısı, organizasyon politikaları) |

İlke: kodda olmayan bir davranışı belgeleme; her belgelenen endpoint/ayar için kodu aç ve doğrula. ASVS eşleme tablosunun "test" sütunu gerçek test adlarına işaret etmeli.

---

## 8. Hızlı kontrol listesi (görev bitti sayılmadan)

- [ ] İlgili tüm gereksinim kimlikleri için en az bir test (adında kimlik var).
- [ ] `cargo fmt`, `cargo clippy … -D warnings`, `cargo test` (crate ve/veya workspace), `cargo deny check` yeşil.
- [ ] Production kodunda `unwrap/expect/panic!/todo!/unimplemented!` yok; public öğelerde rustdoc; crate README'si (Türkçe) güncel; endpoint'ler `#[utoipa::path]`.
- [ ] Bağımsız denetçi geçti; bulgular regresyon testiyle kapatıldı; kabul edilen riskler README "Güvenlik notları"nda gerekçeli.
- [ ] `contract-change-requests.md` ilgili girdileri güncellendi; gerekiyorsa `contracts.md` / `overview.md` güncellendi.
- [ ] Ayrıntılı commit mesajıyla push edildi; GitHub Actions yeşil.

---

## 9. Açık küçük işler (sahibi olmayan / ertelenmiş)

Büyük görevlerin dışında kalan, [`contract-change-requests.md`](../architecture/contract-change-requests.md)'de ve denetçi raporlarında açık duran maddeler:

- **`authn-notify`:** `registration_attempt` bildirim metnini genel hâle getir; yeni bildirim türleri `EmailChangeReverted` ve `PasskeyCloneSuspected` (talep onaylı, uygulayacak aktif agent yoktu). Passkey klonu şu an yalnızca audit olayı ve listede işaret olarak görünüyor.
- **`authn-crypto`:** `KeyPurpose::KnownDevice` (düşük öncelik, onaylı).
- **Mimari belgeler:** `contracts.md` §5/§15 ve `overview.md` ER diyagramına `pending_registrations` tablosu; §6'ya migration `2000` satırı; §15.2/15.4/15.5'te revoker inşa sırası, `authenticate`'in `api_key_middleware` yerine geçmesi ve `purge_expired` işi (talepler `## authn-session` ve `## authn-account` başlıklarında).
- **Yeniden kullanım fırsatları (davranış aynı):** `authn-account` `SharedReads`/`RevertLinkRepository` → `UserRepository::claim_next`, `active_for_user`, `revoke_for_user_since`; `authn-org` → `find_many` ve `RevocationReason::MembershipChanged`; `authn-mfa` testlerinde kendi `TestNotifier`'ı yerine `RecordingNotifier`.
- **Kabul edilmiş kalan riskler:** ADR 0002 (kod phishing'i, hedefli kayıt DoS'u, hedef başına kod tahmini ~1.5e-5/gün), session notları (access token oturum kontrolü kapatılırsa iptal gecikmesi ≤ 10 dk; imza anahtarı önbelleği 30 sn; iki eşzamanlı ayrıcalık değişiminde refresh yeniden kullanım olarak algılanma — güvenli taraf), audit (teslim edilmiş outbox satırları ve webhook geçmişi saklama süresi dolana dek kullanıcı kimliği içerebilir), `Revert` passkey/TOTP/sosyal kimlikleri kaldırmıyor (sunucu tarafı kanca gerekli).
- **Doğrulanamayanlar:** Mailpit + sabit sertifika ve Dockerfile gerçek Docker ile hiç çalıştırılmadı.
- **Proje sahibine sorulacak:** `libfuzzer-sys` NCSA lisans istisnasını onaylıyor mu? Depo adı `rust-authentication` olarak değişecek mi? Faz 2/3 ne zaman?
