# authn-session

Oturum çekirdeği (CSRF korumalı web oturumları, rotasyonlu ve yeniden kullanım tespitli native access/refresh token'lar, JWKS, introspection, step-up, aktif organizasyon değiştirme, impersonation oturumları, kimlik doğrulama ara katmanı) ve giriş akışları (`src/login/**`: şifre, MFA challenge'ı, zorunlu adımlar, magic link, e-posta kodu, passkey girişi, risk değerlendirmesi, güvenilir cihaz, "bu ben değilim").

## Sahip olunan gereksinimler ve durum

| Kimlik | Durum | Nerede |
|--------|-------|--------|
| SES-03 | Uygulandı | `cookies`, `service/establish.rs`, `service/org_switch.rs` (rotasyon) |
| SES-04 | Uygulandı | `csrf`, `middleware`, `GET /v1/csrf` |
| SES-05 | Uygulandı | `service/refresh.rs`, `service/tokens.rs`, `POST /v1/token/refresh` |
| SES-06 | Uygulandı | `settings`, `service/establish.rs`, `service/authenticate.rs` |
| SES-07 | Uygulandı | `SessionShape::SharedDevice` |
| SES-08 | Uygulandı | `claims`, `service/tokens.rs` |
| SES-09 | Uygulandı | `GET /.well-known/jwks.json`, `keys.rs` |
| SES-10 | Uygulandı | `service/introspect.rs`, `POST /v1/token/introspect` |
| SES-11 | Uygulandı | `service/manage.rs`, `GET/DELETE /v1/me/sessions…` |
| SES-12 | Uygulandı | `POST /v1/logout`, `POST /v1/logout/all` |
| SES-13 | Uygulandı (uç nokta mekaniği + `Principal` alanları; faktör doğrulaması password/mfa/webauthn API'lerine bağlı) | `service/step_up.rs`, `POST /v1/reauth`, `POST /v1/reauth/passkey/options` |
| SES-14 | Uygulandı | `service/establish.rs` (`max_concurrent_sessions`) |
| SES-15 | Uygulandı (`SessionRevoker` + `SessionIssuer` portları) | `service/revoke.rs`, `service/issuer.rs` |
| SES-16 | Uygulandı | `GET /v1/me` |
| SES-17 | Uygulandı | `service/org_switch.rs`, `POST /v1/session/org` |
| SES-01 | Uygulandı | `login/password.rs`, `POST /v1/login/password` |
| SES-02 | Uygulandı | `login/challenge.rs`, `POST /v1/login/challenge/{verify,send-code,passkey/options}` |
| SES-18 | Uygulandı | `login/passwordless.rs`, `POST /v1/login/magic-link[/verify]` |
| SES-19 | Uygulandı | `login/passwordless.rs`, `POST /v1/login/email-code[/verify]` |
| SES-20, SES-21 | Uygulandı | `login/passkey.rs`, `POST /v1/login/passkey[/options]`; tüm yöntemlerde `login/pipeline.rs` |
| SES-22 | Uygulandı | `login/challenge.rs`, `POST /v1/login/challenge/step`; passkey kaydı `login/challenge/passkey_enrollment.rs` (K-112) |
| RSK-03, RSK-04 | Uygulandı (session tarafı) | `login/pipeline.rs` (risk tepkisi, yeni cihaz bildirimi), `login/not_me.rs` (`NotMeTokenIssuer`, `POST /v1/login/not-me`) |
| MFA-09 | Uygulandı (session tarafı) | `login/pipeline.rs` (token kontrolü), `login/challenge.rs` (`trust_device`) |
| DOC-05 | Sonraki aşama | `docs/integration/` |

## Bağımlılık kuralı

Dalga B. `authn-core`, `authn-crypto`, `authn-store` ve tüm Dalga A crate'lerine bağımlıdır; `authn-oidc-client` ve `authn-admin`'e **asla** (onlar `SessionIssuer` / `SessionRevoker` portlarıyla konuşur). Yeni harici bağımlılık eklenmedi; `data-encoding` (MIT/Apache-2.0, zaten workspace'te) crate'in `Cargo.toml`'una eklendi.

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `SessionService::new(SessionServiceDeps, SessionSettings)` | Servis (ucuz kopyalanır, `FromRef<AppState>`). Bağımlılıklar: `pool`, `clock`, `keys` (`CryptoServices::keys`), `envelopes`, `rate_limiter`, `audit`, `events`, `notifier`, `passwords`, `mfa`, `webauthn`, `orgs`, `accounts` |
| `SessionSettings::from_app_config(&AppConfig)` | `[session]` + `server.public_base_url` (issuer, izinli origin), `crypto.jwt_leeway`, `crypto.signing_keys.jwks_cache_ttl`, `admin.impersonation_max_ttl`, `oidc_client.trust_provider_mfa`, `webauthn.ceremony_ttl` |
| `PgSessionRevoker::new(clock, audit, events, mfa)` | `SessionRevoker` port uygulaması (SES-15); wave 2B: `revoke_everything_except(conn, keep, reason)` (K-10, acil iptalde çağıran adminin oturumu korunur) |
| `is_session_active_in(conn, session, user, now) -> bool` | Wave 2B (K-03 desteği): oturum canlı mı, `user`'a mı ait, impersonation değil mi, sahibi giriş yapabilir mi — **yalnızca verilen bağlantıyla** (havuz kullanılmaz). authn-oidc-client'ın `SessionLiveness` kancası için sunucu adaptörü bunu çağırır |
| `IMPERSONATION_SESSION_HEADER` (`x-impersonation-session`), `SessionService::authenticate_impersonation_token` | Wave 2B (K-12): web impersonation token'ı çerez yerine bu başlıkla |
| `impl SessionIssuer for SessionService` | `complete_primary_authentication`, `login_response`, `start_impersonation`, `start_impersonation_with`, `start_impersonation_audited` (ADM-04, ADM-08; wave 1, K-06: çağıranın transaction'ında, çağıranın verdiği olay kimliğiyle `admin.impersonation_started`; commit çağıranın); `impersonation_response` (wave 2B, K-12: port varsayılan gövdesi — **`Set-Cookie` yok**, web token'ı gövdede `impersonation_token`) |
| `authenticate` | Kimlik doğrulama ara katmanı (`from_fn_with_state(service, authenticate)`) |
| `router::<S>()`, `SessionApi` | Uç noktalar ve OpenAPI |
| `SessionDataExporter` | ACC-10 dışa aktarma bölümü `sessions` |
| `CurrentSession` | Ara katmanın `Principal` yanına koyduğu oturum (extractor; `Option<CurrentSession>` de olur) |
| `SessionService::{authenticate_cookie, authenticate_bearer, verify_access_token, jwks, refresh, introspect, list_sessions, revoke_own_session, revoke_other_sessions, logout, logout_everywhere, me, switch_org, step_up, start_passkey_step_up, purge_expired, impersonate, complete_login}` | Servis işlemleri (uç noktalar bunları çağırır) |
| `cookies::*`, `response::{credentials_response, challenge_response, redirect_with_session}` | Çerez ve yanıt yardımcıları |

### Giriş akışları ajanı için API (`src/login/**`)

Giriş uç noktaları (SES-01/02/18–22) yalnızca şu yapı taşlarını kullanır; oturum tablosuna doğrudan SQL yazmaz:

1. **Login CSRF (SES-04):** web giriş isteği `SessionService::verify_login_csrf_request(&headers, current.as_ref())` ile doğrulanır. Tarayıcı oturumsuzsa `GET /v1/csrf` pre-session çerezi (`__Host-authn_csrf`, `SameSite=Strict`) ve token'ı verir; istek `Origin` + `X-CSRF-Token` taşır. Tarayıcı zaten giriş yapmışsa `GET /v1/csrf` oturum token'ını verir ve ara katmanın oturum CSRF kontrolü kanıt sayılır. Dönen `LoginCsrfVerified` değeri crate dışında **üretilemez**; `ClientChannel::Web(proof)` olmadan web oturumu kurulamaz (tip düzeyinde zorlama). Native istemci `ClientChannel::Native` kullanır (çerez yok, CSRF riski yok).
2. **Organizasyon (SES-17/21):** istenen organizasyon `verify_login_org(&mut conn, &ctx, user, org, method)` ile doğrulanır (aktif üyelik, IP izin listesi, izinli giriş yöntemleri; başka kiracı = `404`). Dönen `VerifiedOrg` yine crate dışında üretilemez, doğrulandığı kullanıcıya bağlıdır (`establish` başka kullanıcı için reddeder) ve politikayı taşır (`policy()`); MFA gereksinimi için `authn_session::service::org_mfa_policy(policy)` (→ `MfaService::evaluate_for_user`).
3. **Bekleyen giriş (SES-02/22):** `create_challenge(&mut conn, &ctx, NewChallenge{…})` → `IssuedChallenge { challenge, token }`. Token istemciye bir kez verilir (`response::challenge_response`: web'de `__Host-authn_challenge` çerezi, native'de gövde). Her adımda `open_challenge(&mut conn, &ctx, token, kind, client_kind)` satırı kilitler ve tek tip `challenge_invalid` ile reddeder (kullanılmış, süresi dolmuş, deneme hakkı bitmiş, başka cihaz/istemci türü). Yanlış faktör: `record_challenge_failure(id)` (kendi transaction'ı; sınırda challenge yanar) — **önce `open_challenge` transaction'ını bitirin (rollback)**: o transaction satır kilidini tutar; tutarken çağrılırsa `CHALLENGE_LOCK_TIMEOUT` (5 sn) sonra hata döner ve deneme sayılmaz, bu yüzden hata da başarısız deneme gibi ele alınmalıdır. İlerleme: `update_challenge(&mut conn, id, &ChallengeProgress)`. Bitiş: `consume_challenge(&mut conn, id)` — oturumu kuran transaction'da, tam bir kez. `verify_factor`'dan önce `state.allows_factor(proof.kind())` kontrolü **zorunludur** (contracts §15.7).
4. **Oturum (SES-03/05/06/07/14):** `establish(&mut conn, &ctx, EstablishSession { user_id, method, amr, mfa_factors, acr, auth_time, client, remember_me, shared_device, org, device })` (`mfa_factors`: bu girişte ikinci faktör olarak doğrulanan türler, K-78) → `EstablishedSession { session, credentials, evicted }`. Her çağrı yeni oturum kimliği ve token'ı üretir (sabitlemeye karşı). Aynı transaction'da `login_succeeded_event(&ctx, &established, method)` ile audit yazılır, `UserRepository::record_login` çağrılır; yanıt `response::credentials_response(&session, credentials, now)` (web: çerez + yeni CSRF token'ı + pre-session çerezinin silinmesi + gerekirse cihaz çerezi; native: token çifti).
5. **Boru hattı:** `complete_login(&ctx, PrimaryAuthentication, ClientChannel)` birincil doğrulamadan sonraki ortak karar noktasıdır (hesap durumu → organizasyon → MFA → zorunlu adımlar → oturum veya challenge). `PrimaryAuthentication.amr` içindeki `mfa` / `hwk` / `swk` yalnızca `LoginMethod::Passkey` için dikkate alınır; diğer yöntemlerde atılır (sağlayıcı MFA'sı yalnızca `provider_asserted_mfa` + `oidc_client.trust_provider_mfa` ile, SOC-09). Giriş ajanı bunu **risk değerlendirmesi (RSK-03, `RiskEvaluator` + `authn_protect::risk::decide` + `RiskAlerts`) ve güvenilir cihaz (MFA-09, `MfaService::is_trusted_device`)** ile genişletir; şifre girişinde `LoginProtection::check_attempt` / `record_success` / `record_failure` ve `verify_login_password` sonucunun enum ile eşlenmesi (`MustChangePassword` ⇒ `RequiredAction::ChangePassword`) contracts §15.7'dedir.
6. **Toplu iptal ve bekleyen girişler:** kullanıcı genelindeki her iptal (`revoke_all_for_user` / `revoke_all_except` / `revoke_everything`) kullanıcının açık challenge'larını da kapatır — **`password_changed` hariç**: SES-22 zorunlu adımları (şifre değiştirme, e-posta doğrulama) iptali tamamladıkları girişin *içinden* bu nedenle yapar. Giriş ajanı başka bir nedenle iptal tetikleyen bir adımı challenge'ın ortasında çalıştırmamalıdır.
7. **NotMeTokenIssuer (RSK-04):** `authn_protect::risk::NotMeTokenIssuer` uygulaması ve `not_me` linkinin tüketimi giriş ajanına kalır (`one_time_tokens` amaçları `magic_link`, `login_code`, `not_me`).

## Giriş akışları (`src/login/`)

**Ortak boru hattı** (`login/pipeline.rs`, `complete_login` ve `SessionIssuer` de bunu kullanır): hesap durumu (yalnızca doğru birincil kimlik bilgisinden sonra açıklanır) → istenen organizasyon (üyelik, IP, izinli yöntem) → MFA gereksinimi (MFA-08) → **risk** (RSK-03: `high` ⇒ engel + kullanıcıya bildirim, `medium` ⇒ kayıtlı faktör ya da e-postayla gönderilen onay kodu) → **güvenilir cihaz** (MFA-09; yalnızca politika kaynaklı MFA'yı karşılar, riskin istediğini asla) → oturum ya da challenge. Oturumdan sonra: cihaz/ağ kaydı, yeni cihazda bildirim + "bu ben değilim" linki (RSK-04, cihaz kimliği oturuma yeni atansa bile), doğrulanmış domain'lere otomatik katılım.

**Challenge adım sırası** (`login/challenge.rs`): `verify_mfa` (kanıt türü `allowed_factors`'ta değilse doğrulamadan **önce** reddedilir) → `enroll_mfa` → `change_password` / `accept_terms` / `verify_email`. Kayıtlı bir faktörü olan kullanıcı yeni faktör kaydetmeden önce mevcut faktörünü doğrular; riskli girişte ve "şifre değiştirmeye zorlanmış" hesapta (PWD-12, RSK-04) e-posta onayı şifre değişikliğinden önce gelir — şifre tek başına ne faktör kaydettirir ne de şifreyi değiştirir.

**İstemci türü:** tarayıcı varsayılan (başlık yoksa ya da `X-Authn-Client: web` ise; login CSRF zorunlu, challenge token'ı `__Host-authn_challenge` çerezinde); native `X-Authn-Client: native` gönderir, token'lar gövdede, challenge token'ı `X-Authn-Challenge` başlığında. Başka bir değer ya da tekrarlanan başlık `400 bad_request` alır.

| Metot ve yol | Gereksinim |
|--------------|-----------|
| `POST /v1/login/password` | SES-01 |
| `POST /v1/login/passkey/options`, `POST /v1/login/passkey` | SES-20, SES-21 |
| `POST /v1/login/magic-link`, `POST /v1/login/magic-link/verify` | SES-18 (GET ile tüketilmez; başka cihazda `confirm_other_device` gerekir → `409 magic_link_confirmation_required`) |
| `POST /v1/login/email-code`, `POST /v1/login/email-code/verify` | SES-19 (her hata tek tip `invalid_code`, en az 50 ms) |
| `POST /v1/login/challenge/verify` | SES-02 (`totp`, `recovery_code`, `email`, `sms`, `passkey`, `email_confirmation`; `trust_device`) |
| `POST /v1/login/challenge/send-code` | SES-02, RSK-03 |
| `POST /v1/login/challenge/passkey/options` | SES-02 |
| `POST /v1/login/challenge/passkey/register/options` | SES-22, MFA-07 (K-112): `enroll_mfa` adımında passkey kaydı başlatma |
| `POST /v1/login/challenge/passkey/register/verify` | SES-22, MFA-07 (K-112): passkey kaydını bitirme |
| `POST /v1/login/challenge/step` | SES-22 (`change_password`, `accept_terms`, `enroll_totp`/`enroll_email`/`enroll_sms`, `confirm_enrollment`) |
| `POST /v1/login/not-me` | RSK-04 (token gövdede; tüm oturumlar + güvenilir cihazlar + bekleyen girişler kapanır, şifre değişikliği zorunlu, sıfırlama e-postası) |

Yeni bağımlılıklar (`SessionServiceDeps`): `protection: LoginProtection`, `risk: Arc<dyn RiskEvaluator>`, `risk_alerts: RiskAlerts`, `otp: OtpHasher`. Kapanışta `drain_background_jobs()` (şifresiz isteklerin arka plan işi). Yeni hata kodları: `magic_link_confirmation_required` (409), `challenge_step_not_allowed` (403).

### Giriş challenge'ı içinde passkey kaydı (K-112, wave 9A)

`enroll_mfa` bekleyen ve `allowed_factors` içinde `webauthn` olan bir challenge (platform adminleri: izinli tek faktör passkey; `webauthn` isteyen kuruluş politikası) passkey'i `POST /v1/login/challenge/passkey/register/options` + `/verify` ile kaydeder. Önceden passkey'i olmayan böyle bir hesabın girişi hiç tamamlanamıyordu (ör. şifreyle oluşturulmuş break-glass hesabı).

- **Ne zaman:** challenge yalnızca birincil faktörden sonra vardır; `verify_mfa` (e-posta kodu, mevcut faktör, risk onayı) bekliyorsa uçlar `403 challenge_step_not_allowed` döner — şifre tek başına passkey kaydettiremez. Platform admini için (ör. `grant-admin` sonrası passkey'i olmayan mevcut hesap) risk düşük olsa bile önce e-posta kodu istenir (`verify_mfa`, `allowed_factors: ["email"]`); giriş zaten posta kutusu kanıtıysa (magic link, e-posta kodu) istenmez. Kuruluş politikasıyla kayıt SES-22'deki TOTP kaydıyla aynı kalır (birincil faktörden sonra).
- **Bağlama:** seremoni kullanıcıya, bu challenge'a ve yeni bir 256 bit bağlama token'ına bağlıdır (`WebauthnService::start_challenge_registration` / `verify_challenge_registration`); web'de `__Host-authn_passkey` çerezi (`SameSite=Strict`), native'de gövde (`binding_token`). Başka challenge'ın (aynı kullanıcınınki dahil), başka kullanıcının seremonisi ya da yanlış token `passkey_ceremony_invalid`'dır ve seremoniyi tüketmez; seremoni doğrulamadan önce tüketilir (tek kullanım).
- **Politika:** UV zorunlu passkey (`RegistrationIntent::Passwordless`), yapılandırılan RP kimliği ve origin'ler, kullanıcının tüm kuruluşlarının en katı AAGUID politikası (`PasskeyPolicySource`, `active_org = None`).
- **Sayım:** passkey, challenge yeniden satır kilidiyle açıldıktan sonra challenge ilerlemesiyle (ya da oturumla) aynı transaction'da saklanır (`store_enrollment_in_tx`). Ancak bundan sonra `mfa_factors`'a `webauthn` (K-78) ve `amr`'ye `hwk`/`swk`, `user`, `mfa` eklenir; `enroll_mfa` kapanır. Yanıtın `data.passkey`'i yeni passkey'in özetidir.
- **Sınırlar:** `webauthn.registration_per_user` (başlatma başına), `webauthn.max_credentials_per_user`, challenge deneme sınırı (`session.challenge_max_attempts`; başarısız doğrulamalar sayılır).
- **Audit / bildirim:** `passkey.registered` (`enrollment: login_challenge`, `login_challenge_id`, aktör kullanıcı), `mfa_factor_added` e-postası.
- **Varlık sızıntısı yok:** uçlar yalnızca geçerli bir challenge token'ıyla çalışır; yoksa tek tip `401 challenge_invalid`.
- Testler: `authn-server/tests/login_passkey_enrollment.rs` (break-glass uçtan uca, native, bağlama/tekrar oynatma/sunulmama), `authn-webauthn/tests/registration.rs` (`pky_01_k112_…`, `pky_08_k112_…`).

### Giriş akışları — bağımsız güvenlik incelemesi

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| yüksek | "Bu ben değilim" yalnızca `must_change_password` koyuyordu; eski şifreyi bilen saldırgan yeniden girip `change_password` adımını eski şifreyle tamamlayarak tam oturum alabiliyordu | Şifre değişikliğine zorlanmış girişte (bekleyen ikinci faktör yoksa) önce e-postayla onay | `login::rsk_04_not_me_locks_out_whoever_knows_the_old_password` |
| yüksek | Kayıtlı faktörü organizasyonca izinli olmayan kullanıcıda (`EnrollmentRequired`) yalnızca şifreyle saldırganın kendi faktörü kaydedilebiliyordu | Önce mevcut faktör doğrulanır, sonra kayıt (`enroll_factors` metadata) | `login::ses_22_policy_enrollment_needs_an_existing_factor_first` |
| orta | Orta riskte MFA kaydı beklerken e-posta onayı atlanıyordu | Önce e-posta onayı, sonra kayıt | `login::rsk_03_medium_risk_enrollment_needs_the_email_confirmation_first` |
| orta | SES-19: yanlış kodun yanıt süresi hesabın varlığını sızdırıyordu (~%80 fark) | Bilinmeyen challenge'da aynı iş + 50 ms alt sınır | `login::ses_19_wrong_code_takes_as_long_for_unknown_addresses` |
| orta | Girişten sonra doğrulanmış domain'e otomatik katılım düşmüştü | `after_login` | `login::org_06_login_auto_joins_verified_domain_organizations` |
| orta | Cihaz çerezi olmayan (yeni) tarayıcıdan girişte yeni cihaz bildirimi gitmiyordu | Oturuma atanan cihaz kimliği risk kaydına verilir | `login::rsk_04_browser_without_device_cookie_is_a_new_device` |
| orta | Giriş akışı kullanıcı satırını kilitleyen transaction'ı tutarken hesap/MFA/risk servisleri ve imza anahtarı önbelleği için havuzdan ikinci bağlantı alıyordu: eşzamanlı girişler havuzu tüketip 30 sn kilitleniyordu (503; CI'da da yakalandı) | Boru hattı "planla (bağlantı tutmadan) / tamamla (tek transaction)" olarak ayrıldı; challenge adımları kanıtı transaction dışında doğrular; alıcı/anahtar transaction'dan önce yüklenir | `login::ses_01_concurrent_logins_never_starve_the_connection_pool` |
| orta | Güvenilir cihaz çerezi hiç yazılmıyordu (imzalı token'daki `.` çerez alfabesinde yoktu) — MFA-09 çalışmıyordu | Çerez alfabesine `.` (RFC 6265) | `login::mfa_09_trusted_device_skips_the_second_factor` |

### Giriş akışları — kabul edilen riskler / bilinen sınırlamalar

- [düşük] Challenge adımları kanıtı doğrularken challenge satırını kilitli tutmaz (oku → doğrula → yeniden kilitle ve değişmediğini kontrol et): aynı challenge'a paralel yanlış denemeler sayılırken birkaç tanesi sınırı aynı anda geçebilir; faktör modüllerinin kendi kullanıcı bazlı deneme sınırları ve kilitleri ayrıca geçerlidir.
- [düşük] Passkey girişi organizasyonun `allowed_mfa_factors` listesini ve kayıt adımını atlar (passkey tek başına MFA sayılır, SES-21; giriş yöntemleri ayrıca kısıtlanabilir).
- [düşük] Phishing'e dayanıklı MFA isteyen organizasyonda yalnızca TOTP'si olan kullanıcı girişte webauthn kaydı adımında takılır (challenge passkey kaydı sunmaz; atlatma yok, kullanıcı passkey'ini oturum açıkken başka bir yoldan kaydetmelidir).
- [düşük] `verify_email` adımı (doğrulanmamış hesap) ADR 0002 gereği doğrulanmamış şifreyi siler; aynı challenge'da bekleyen `change_password` sonra `password_not_set` ile başarısız olur (kullanılabilirlik).
- [düşük] Federe girişte (`SessionIssuer`) güvenilir cihaz token'ı taşınmaz: sosyal girişte MFA-09 atlaması yoktur (güvenli taraf).
- [düşük] Şifresiz arka plan iş kuyruğu 1024 ile sınırlı; dağıtık selde fazlası sessizce düşer (hesap varlığı sızmaz, e-postalar gecikebilir).
- [info] `magic_link_confirmation_required`, 256 bit bir token'ın geçerli olduğunu gösterir (tahmin edilemez).
- [info] `POST /v1/login/not-me` CSRF/oran sınırı olmadan yalnızca 256 bit tek kullanımlık token'la yetkilendirilir.

## Uç noktalar

| Metot ve yol | Gereksinim | Kimlik |
|--------------|-----------|--------|
| `GET /v1/csrf` | SES-04 | isteğe bağlı (oturum → oturum token'ı, yoksa pre-session) |
| `GET /v1/me` | SES-16 | oturum |
| `GET /v1/me/sessions` | SES-11 | oturum |
| `DELETE /v1/me/sessions/{session_id}` | SES-11 | oturum (başkasının oturumu `404`) |
| `POST /v1/me/sessions/revoke-others` | SES-11 | oturum (güvenilir cihazlar da iptal) |
| `POST /v1/logout` | SES-12 | oturum (web: çerez silinir + `Clear-Site-Data: "cookies"`) |
| `POST /v1/logout/all` | SES-11, SES-12 | oturum (tüm oturumlar + güvenilir cihazlar + bekleyen e-posta değişikliği) |
| `POST /v1/session/org` | SES-17 | oturum (oturum rotasyonu) |
| `POST /v1/reauth` | SES-13 | oturum (`password` / `totp` / `recovery_code` / `passkey`; oturum rotasyonu) |
| `POST /v1/reauth/passkey/options` | SES-13 | oturum (`passkey` özelliği yoksa `passkey_not_available`) |
| `POST /v1/token/refresh` | SES-05 | gövdede refresh token |
| `POST /v1/token/introspect` | SES-10 | organizasyon API anahtarı (`Authorization: Bearer ak_…` / `X-API-Key`), form veya JSON |
| `GET /.well-known/jwks.json` | SES-09 | yok (`Cache-Control: public, max-age=<jwks_cache_ttl>`) |

`GET /v1/me` session'ındır; `DELETE /v1/me` authn-account'undur (contracts §7). Tüm yanıtlar (JWKS hariç) `Cache-Control: no-store`.

"Kimlik" sütunu OpenAPI'de her işlemin `security` bildirimidir (K-129): "oturum" = `session_cookie` | `bearer_jwt`, introspect = `api_key` | `api_key_bearer`, "yok" ve giriş uçları = `[]`. `authn-server/tests/openapi.rs` (`arc_09_k129_declared_security_matches_the_router`) bildirimi router'ın gerçek davranışıyla karşılaştırır; yeni bir korumalı uç `#[utoipa::path(security(...))]` olmadan eklenirse test kırmızıdır.

## Kimlik doğrulama ara katmanı

`authenticate`, OPS-02 sırasındaki (8) yuvasıdır ve `authn_org::api_key_middleware`'in **yerine** kurulur (ikisi birlikte kurulmaz: org ara katmanı principal taşıyan isteği reddeder). Tam olarak bir kimlik bilgisi karar verir:

0. **Web impersonation başlığı** `x-impersonation-session` (wave 2B, K-12; önce bakılır): yalnızca canlı bir **impersonation** web oturumunun token'ı kabul edilir — normal oturum token'ı bu başlıkla `401` (çerezin CSRF korumasını atlatmak için kullanılamaz). Tek değer, `Authorization` ile birlikte değil; geçersizse `401` ve adminin çerezine **geri düşülmez** (aynı tarayıcının admin çerezi yok sayılır). CSRF token'ı gerekmez (özel başlık tarayıcıca siteler arası eklenmez). `POST /v1/logout` bu başlıkla yalnızca impersonation oturumunu bitirir; çerez silinmez, `Clear-Site-Data` gönderilmez — adminin kendi oturumu yaşar.

1. **API anahtarı** (`Authorization: Bearer ak_…` / `X-API-Key`): yalnızca `authn_org::middleware::is_api_key_path` yollarında (`/v1/orgs/{org_id}[/…]`) `Principal` olur; diğer yollarda principal üretilmez (introspection anahtarı kendisi doğrular), çerez de okunmaz. Birden fazla/çelişen başlık `401`.
2. **Bearer access token**: imza/claim doğrulaması (CRY-09) + varsayılan olarak oturumun hâlâ etkin olması, sahibin aynı olması ve aktif organizasyonun token'daki ile eşleşmesi (organizasyon değiştikten sonra eski token reddedilir). Hata: `401` + `WWW-Authenticate: Bearer error="invalid_token"`. `Authorization` varsa çerez yok sayılır.
3. **Oturum çerezi**: durum değiştiren her yöntemde CSRF (origin + senkronize token) burada kontrol edilir; başarısızsa `403 csrf_failed`, handler çalışmaz. Geçersiz çerez yalnızca principal üretmez (çerez silinmez: eşzamanlı rotasyonun yeni çerezini ezmemek için).
4. **Salt-okunur impersonation**: `POST /v1/logout` dışındaki her durum değiştiren istek tüm modüllerde `403 forbidden` (handler'ların `require_writable` kontrolüne ek savunma).

Ara katman başka bir katmanın koyduğu `Principal`'ı her istekte siler; principal yalnızca burada üretilir.

## Konfigürasyon (`[session]`, `crates/authn-core/src/config/session.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `web` / `remember_me` / `shared_device` / `refresh_token` | 2s/12s · 14g/30g · 30dk/4s · 30g/90g (boşta/mutlak) | SES-06, SES-07 |
| `access_token_ttl` | `10m` | 1dk–1s |
| `refresh_reuse_grace` | `0s` | en fazla `10s` (SES-05) |
| `issuer` / `audiences` | `public_base_url` (sondaki `/` olmadan) / `["rust-authentication"]` | ilk audience bu API'nin kendi doğruladığıdır |
| `mfa_challenge_ttl` / `challenge_max_attempts` | `5m` / 5 | challenge API'si |
| `step_up_max_age` | `10m` | `require_recent_authentication` |
| `max_concurrent_sessions` | sınırsız | SES-14 |
| `csrf_allowed_origins` | `[]` | `public_base_url` origin'i her zaman izinli; liste ek origin'lerdir |
| `introspection_per_client` | 600/dk | API anahtarı başına |
| `access_token_session_check` | `true` | **yeni** — bearer token'da oturum kontrolü |
| `signing_key_cache_ttl` | `30s` | **yeni** — 1sn–5dk |
| `touch_interval` | `1m` | **yeni** — son görülme yazımı seyreltme |
| `default_scopes` | `["api"]` | **yeni** — `scope` claim'i |
| `step_up_per_user` | 10/15dk | **yeni** |
| `refresh_per_ip` | 300/dk | **yeni** |
| `magic_link_ttl`, `email_code_ttl`, `email_code_max_attempts` | | giriş ajanının |

## Hata kodları (`codes::session`)

`invalid_credentials` (401), `csrf_failed` (403), `invalid_refresh_token` (401, tüm nedenler için tek tip), `reauthentication_failed` (401), `step_up_method_not_allowed` (403), `challenge_invalid` (401, tek tip), `login_method_not_allowed` (403), `impersonation_not_allowed` (403). Ayrıca ortak kodlar ve org kodları (`org_policy_mfa_required`, `org_policy_ip_denied`) geçirilir.

## Veritabanı

Sahip olunan tablolar: `sessions`, `refresh_tokens`, `auth_challenges` (şema `0004`). Migration `2000_session_core.sql`: `sessions.login_method`, `sessions.scopes`, `auth_challenges.primary_method`, temizlik indeksleri, `sessions_impersonator_active_idx` (adminin tüm oturumları iptal edilirken başlattığı impersonation oturumları). Kilit sırası her yerde önce `sessions` satırı, sonra `refresh_tokens` (iptal ile rotasyon kilitlenmez).

## Güvenlik notları

- **Oturum token'ı:** 256 bit CSPRNG, base64url; veritabanında yalnızca SHA-256'sı. Çerez `__Host-authn_session`, `HttpOnly; Secure; SameSite=Lax; Path=/`, `Domain` yok (alt alan adı çerez enjekte edemez). "Beni hatırla" dışında tarayıcı oturumu çerezi; "bu benim cihazım değil" her zaman tarayıcı oturumu + kısa ömür. Token hiçbir yanıt gövdesine, loga veya audit'e girmez (`Debug` redakte).
- **Oturum sabitleme (SES-03):** her giriş yeni kimlik + token; MFA tamamlanınca (challenge → `establish`), organizasyon değişince ve step-up'ta token (native'de token çifti) rotasyonu. Rotasyon satır kilidi altında ve "istekteki token hâlâ geçerli mi" kontrolüyle yapılır; eşzamanlı ikinci rotasyon `401` alır. Yetki değişikliklerinde (rol düşürme, üyelik, politika) oturumlar `SessionRevoker` ile kapatılır.
- **CSRF (SES-04):** origin kontrolü (izin listesi tam eşleşme; `Origin` yoksa yalnızca `Sec-Fetch-Site: same-origin`; ikisi de yoksa ret; `null` ret) **ve** oturuma ve güncel token'a bağlı HMAC (`KeyPurpose::CsrfToken`, sabit zamanlı karşılaştırma, tekrarlanan başlık ret). Login CSRF: pre-session sırrı + HMAC; `LoginCsrfVerified` tip düzeyinde zorunlu. Federe geri dönüşler (OIDC) `state`/PKCE ile korunur.
- **Access token (SES-08, CRY-09):** EdDSA, `typ: at+jwt`, `kid`; doğrulamada algoritma sabit (`none`/HS*/RS* ret), bilinmeyen `kid` en fazla 5 sn'de bir anahtar yeniden yüklemesi tetikler (DoS sınırı), `iss`/`aud`/`exp`/`nbf`/`iat`/en uzun ömür kontrolü, kişisel veri yok (`sub` opak kullanıcı kimliği). `exp` oturumun mutlak bitişini aşmaz. Step-up öncesi basılmış token eski `auth_time`'ını korur (step-up'tan yararlanmaz).
- **Refresh token (SES-05):** 256 bit, yalnızca hash; her kullanımda rotasyon; aile başına tek canlı token (kısmi benzersiz indeks); kullanılmış token tekrar gelirse aile (oturum) iptal + `session.refresh_token_reused` + metrik; tüm hatalar tek tip `invalid_refresh_token`. Eşzamanlı aynı token: biri kazanır, diğeri tekrar sayılır (tolerans 0 iken aile iptal). Tolerans penceresi yalnızca **aynı** ardılı (zarf şifreli, AAD = ebeveyn satırı) döndürür, ardıl kullanılmışsa yeniden kullanım sayılır; mühürlü ardıl temizlik işiyle silinir.
- **Oturum kontrolü (K-58):** `access_token_session_check = true` (varsayılan) iptali bir sonraki istekte etkili kılar; maliyeti istek başına birincil anahtarla tek bir sorgudur. Ölçüm (yerel PostgreSQL 16, debug derleme, 3000 istek, `ses_08_k58_measure_bearer_session_check`): kontrol kapalıyken bearer doğrulaması ≈ 0,12–0,16 ms, açıkken ≈ 0,68–0,75 ms, yani istek başına ≈ +0,55 ms. **Üretimde `false` reddedilir** (yapılandırma doğrulaması, `config::tests::ses_08_k58_session_check_cannot_be_switched_off_in_production_or_staging`). Kontrol yalnızca geliştirme/test/staging ortamında kapatılabilir; o zaman iptal en geç `access_token_ttl` (10 dk) içinde etkili olur ve bearer principal'ı asla platform admini sayılmaz.
- **İmza anahtarı değişiklikleri (K-58, CRY-10):** `signing_keys` tablosundaki her değişiklik (rotasyon, etkinleştirme, acil rotasyon, iptal; bu instance, başka bir instance ya da CLI) commit anında `authn_signing_keys` kanalına PostgreSQL bildirimi gönderir (migration `2001`, tetikleyici). `SessionService::run_signing_key_listener` (sunucu bunu `jobs::spawn` içinde başlatır) her bildirimde önbelleği boşaltır, böylece acil iptal edilen anahtar her instance'ta bildirim gecikmesi içinde (ms) doğrulamayı keser. Dinleyici kendi ayrılmış bağlantısını kullanır (havuzdan değil) ve 1–30 sn geri çekilmeyle yeniden bağlanır. Her (yeniden) bağlantıda önbellek boşaltılır (kaçan bildirimler). Bağlantı koptuğu sürece önbellek ömrü 5 sn'ye iner. Nesil sayacı sayesinde, iptalden önce başlamış bir yeniden yükleme önbelleğe yazılmaz (`ses_09_k58_emergency_rotation_reaches_other_instances_at_once`, `cry_10_k58_every_signing_key_change_notifies`).
- **Introspection (SES-10):** API anahtarıyla istemci doğrulaması zorunlu; yalnızca anahtarın organizasyonunu aktif organizasyon olarak taşıyan token'lar `active: true` (kiracı izolasyonu, ARC-10); iptal edilmiş/süresi dolmuş/yabancı/kişisel token'lar ayırt edilemez biçimde `{"active": false}`. Kişisel (organizasyonsuz) token'lar JWKS ile çevrimdışı doğrulanır.
- **Step-up (SES-13):** impersonation ve API anahtarı asla step-up yapamaz; platform adminleri ve phishing'e dayanıklı MFA isteyen organizasyonlar yalnızca passkey ile; izinli faktörler uygulanır — **aktif organizasyon ve kullanıcının tüm üyeliklerinin en katı birleşimi** (step-up hesap genelindeki işlemleri açar: kişisel bağlamda veya gevşek bir organizasyonda katı organizasyonun kuralı atlanamaz); kullanıcı başına oran sınırı; tek tip `reauthentication_failed` ve `step_up.failed` audit'i (şifre/kod asla loglanmaz, gövde ayrıştırma hataları gövdeyi yankılamaz — `SecretJson`).
- **Organizasyon değiştirme (SES-17):** üyelik ve politika authn-org `check_membership` ile (başka kiracı `404`); izinli giriş yöntemi kontrolü (passkey step-up passkey-only politikayı karşılar); oturum ömrü üst sınırı mutlak bitişi yalnızca kısaltır.
- **Principal'daki giriş bilgisi (K-57):** oturumdan kurulan her `Principal` oturumun birincil giriş yöntemini (`login_method`) ve doğrulanan ikinci faktör türlerini (`mfa_factors`, K-78) taşır. authn-org bunları organizasyonu etkinleştirmemiş oturumlar dahil **her** organizasyon isteğinde politikaya karşı kontrol eder (`docs/security/k57-global-audit.md` F2).
- **Impersonation (ADM-04):** admin DB'de etkin platform admini ve canlı kendi oturumu olmalı; oturum boyunca da öyle kalmalıdır (her kimlik doğrulamada kontrol: admin yetkisi alınan veya askıya alınan adminin impersonation'ları anında biter) ve adminin tüm oturumlarını iptal eden her işlem (askıya alma, sıfırlama, "her yerden çık") başlattığı impersonation oturumlarını da kapatır; impersonation kullanıcının diğer oturumlarını kapatamaz, yalnızca kendini bitirir; (`amr`/`acr`/`auth_time` ondan miras); hedef etkin, admin değil, break-glass değil, kendisi değil; süre ≤ `admin.impersonation_max_ttl`, uzatılmaz; gerekçe zorunlu (1–1000 yazdırılabilir karakter); kullanıcıya `ImpersonationStarted` bildirimi ve `admin.impersonation_started` audit'i aynı transaction'da; native token'larda RFC 8693 `act` + `read_only` claim'i; salt-okunur mod ara katmanda tüm modüller için zorlanır; impersonation principal'ı asla platform admini değildir.
- **Eşzamanlı oturum sınırı (SES-14):** kullanıcı başına advisory lock ile serileşir; impersonation oturumları sayılmaz ve tahliye edilmez.
- **Bekleyen girişler:** kullanıcı genelindeki iptaller (şifre sıfırlama, askıya alma, "bu ben değilim", "her yerden çık", diğer oturumları kapat) açık login challenge'larını da kapatır; eski şifreyle başlamış bir giriş sonradan tamamlanamaz (`password_changed` istisnası için yukarıya bakın).
- **Birincil `amr` güveni:** `SessionIssuer` çağıranının bildirdiği `mfa` / `hwk` / `swk` yalnızca passkey girişinde kabul edilir (SOC-09, SES-21).
- **Savunma derinliği:** askıya alınmış/devre dışı/silinmiş/kilitli kullanıcının oturumu (iptal kaçırılsa bile) kimlik doğrulamaz; çakışan çerezler (cookie tossing) principal üretmez; `Principal` yalnızca ara katmanda üretilir.

### Bağımsız güvenlik incelemesi (oturum çekirdeği)

Düzeltilen bulgular (her biri, düzeltme olmadan başarısız olan bir regresyon testiyle):

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| orta | `complete_login` / `SessionIssuer` çağıranın `amr` listesindeki `mfa`/`hwk`/`swk` değerlerine her yöntemde güveniyordu: sosyal giriş MFA'yı ve phishing'e dayanıklı organizasyon politikasını `trust_provider_mfa` kapalıyken atlayabiliyor, oturum sahte `amr` taşıyordu | `primary_amr`: yalnızca passkey yöntemi bu değerleri kanıtlar | `issuer::ses_15_primary_authentication_cannot_claim_mfa_or_passkey_amr` |
| orta | Adminin impersonation oturumları, admin askıya alındığında / yetkisi alındığında / tüm oturumları iptal edildiğinde 60 dakikaya kadar yaşamaya devam ediyordu | Kimlik doğrulama sorguları impersonator'ın etkin platform admini olmasını ister; `Target::User`/`UserExcept` iptali `impersonator_user_id`'yi de kapsar (+ kısmi indeks, migration 2000) | `issuer::ses_15_impersonation_ends_when_the_admin_is_revoked_demoted_or_suspended` |
| orta | Step-up yalnızca aktif organizasyonun politikasına bakıyordu: kişisel bağlamda veya gevşek bir organizasyonda çalınmış çerez + şifre, phishing'e dayanıklı MFA isteyen organizasyonun üyesini yeniden doğrulayıp e-posta/şifre/MFA değişikliğini açabiliyordu | Aktif organizasyon + tüm üyeliklerin en katı MFA politikası | `step_up::ses_13_strictest_membership_policy_applies_outside_the_strict_org` |
| orta | Toplu iptal (şifre sıfırlama, askıya alma, "bu ben değilim", her yerden çık) açık login challenge'larını kapatmıyordu; eski şifreyle başlamış giriş (ör. `change_password` zorunlu adımı) sıfırlamadan sonra tamamlanabilirdi | İptal, `password_changed` dışında kullanıcının açık challenge'larını kapatır (diğer oturumları kapatırken tutulan oturumun step-up challenge'ı kalır) | `revocation::ses_15_user_wide_revocation_closes_pending_logins` |
| düşük | Yazılabilir impersonation, kullanıcının diğer oturumlarını tek tek kapatabiliyordu (toplu karşılıkları yasakken) | Impersonation yalnızca kendi oturumunu kapatır | `issuer::ses_11_impersonation_cannot_end_the_users_other_sessions` |
| düşük | `VerifiedOrg` kullanıcıya bağlı değildi: giriş akışında yanlış kullanıcıya verilen kanıt, üye olmayan birine organizasyonu etkinleştirebilirdi | `VerifiedOrg.user_id`; `establish` uyuşmazlığı reddeder | `org_switch::ses_17_verified_org_is_bound_to_the_user_it_was_verified_for` |
| düşük | `record_challenge_failure`, çağıran `open_challenge` kilidini tutarken sonsuza kadar bekliyordu (havuz tükenmesi) | `SET LOCAL lock_timeout = '5s'` + belgelenmiş çağrı sırası | `web_session::ses_03_challenge_failure_never_waits_forever_on_the_callers_lock` |
| düşük | **Wave 2B denetimi (K-12 gerilemesi):** `x-impersonation-session` başlığıyla doğrulanan yazılabilir web impersonation'ı `POST /v1/session/org` çağırınca yanıt döndürülen yeni token'ı `Set-Cookie` ile veriyordu; tarayıcı adminin oturum çerezini impersonation token'ıyla değiştiriyordu, başlıktaki token da ölüyordu. Ayrıca başlık yolunda eşzamanlı rotasyon kontrolü (sunulan token hâlâ geçerli mi) atlanıyordu | `CurrentSession::is_impersonation_header`; başlıkla gelen oturumun rotasyonu yeni token'ı gövdede (`impersonation_token`, `token_header`) döner, hiç çerez yazmaz; rotasyon kontrolü başlık token'ının hash'iyle de yapılır | `issuer::adm_04_header_impersonation_rotation_never_sets_a_cookie` |
| düşük | Organizasyon değiştirmede izinli giriş yöntemi kontrolü, oturum kontrolü kapalı bearer isteğinde token'dan kurulan sahte kayda (giriş yöntemi yok) bakıyordu | Kontrol kilitli `sessions` satırıyla yapılır | `org_switch::ses_17_login_method_policy_reads_the_stored_session_without_session_check` |

### Kabul edilen riskler / bilinen sınırlamalar

- ~~[low] Native istemcide eşzamanlı iki yetki değişikliği ikinci rotasyonda ilk yanıtın refresh token'ını "kullanılmış" yapar~~ — **kapatıldı (K-58):** her refresh token, birlikte verildiği access token'ın `jti`'siyle eşlenir (`refresh_tokens.access_token_id`, migration `2001`). Bir yetki değişikliği (org değiştirme, step-up), ailenin canlı refresh token'ıyla eşleşmeyen bir access token'la gelirse eşzamanlı bir rotasyonun gerisinde kalmıştır. Bu durumda hiçbir şey döndürülmeden `401` alır ve istemci yeni token'la yeniden dener. Eskiden ikinci rotasyon ilk yanıtın verdiği token'ı emekliye ayırıyordu, istemci onu kullanınca aile iptal ediliyordu. Yeniden kullanım tespiti değişmedi. Refresh ile yetki değişikliği yarışırsa: tolerans penceresi açıksa sunucu tarafı rotasyonun ardılı da mühürlenir ve emekli token aynı ardılı alır; pencere kapalıysa (varsayılan 0) bu yarış yine güvenli tarafta yeniden kullanım sayılır, çünkü çalınmış bir refresh token'dan ayırt edilemez. Testler: `ses_13_k58_overtaken_privilege_change_is_refused_not_a_replay`, `ses_13_k58_concurrent_privilege_changes_keep_the_session`, `ses_17_k58_org_switch_overtaken_by_a_step_up_is_refused`, `ses_05_k58_privilege_change_after_a_refresh_with_the_old_access_token_is_refused`, `ses_05_k58_grace_window_covers_a_refresh_racing_a_privilege_change`.
- ~~[low] Hangi faktörün `mfa` ürettiği oturumda saklanmaz; organizasyon değiştirmede `allowed_mfa_factors` yeniden denetlenmez.~~ Kapatıldı: wave 4B (org değiştirme denetimi) ve K-78 (`sessions.mfa_factors`, aşağıda). Step-up artık tüm üyeliklerin en katı politikasını uygular; kalan boşluk, organizasyon *istenerek* yapılan girişte yalnızca o organizasyonun izinli faktörlerinin uygulanmasıdır (giriş ajanı / `complete_login` ile aynı kural).
- [low] `password_changed` nedenli iptal (PWD-06 kendi kendine şifre değiştirme, SES-22 zorunlu adımları) açık login challenge'larını kapatmaz; eski şifreyle başlamış bekleyen bir giriş challenge ömrü (varsayılan 5 dk) boyunca tamamlanabilir — ikinci faktör ve kalan zorunlu adımlar yine gerekir.
- [low] `SessionIssuer::login_response` challenge token'ını çereze mi gövdeye mi koyacağına `return_to` varlığıyla karar verir (`PendingChallenge` istemci türünü taşımaz); federe web çağıranları `return_to` geçmelidir.
- [info] Kardeş alt alan adı, `Domain=` ile çok sayıda/uzun çerez yazarak (`MAX_COOKIE_PAIRS` 64, başlık 8 KiB) oturum çerezini okunamaz hâle getirebilir: kullanıcı çıkış yapmış görünür (yalnızca DoS; `__Host-` çerezi değiştirilemez).
- [info] Step-up, `must_change_password` bayraklı hesabın doğru şifresini kabul eder (bayrak bir sonraki girişte değişiklik ister; bayrak tek başına ele geçirme anlamına gelmez).
- [info] Step-up ve organizasyon değiştirme token'ı (native'de token çiftini) yeniler; veritabanı oturum kimliği ve JWT `sid` aynı kalır (sabitleme savunması token rotasyonudur, `__Host-` çerezi dışarıdan yazılamaz).
- [info] Native istemci refresh isteğine süresi dolmuş bir `Authorization: Bearer` eklerse ara katman `401` döner; token uç noktasına `Authorization` gönderilmemelidir.
- [info] Impersonation oturumu adminin `amr`'ını devralır; adminin phishing'e dayanıklı oturumla gelmesi (ADM-01) authn-admin'in kontrolüdür — burada eksikse organizasyon politikaları güvenli tarafta reddeder.
- ~~[low] `access_token_session_check = false` iken iptal ve askıya alma en geç 10 dk sonra etkili olur~~ — **kapatıldı (K-58):** üretimde `false` yapılandırma doğrulamasında reddedilir (yukarıda, maliyet ölçümüyle).
- ~~[low] İmza anahtarı önbelleği (30 sn) nedeniyle acil iptal edilen anahtar diğer instance'larda bu süre doğrulanabilir~~ — **kapatıldı (K-58):** `LISTEN/NOTIFY` ile anında boşaltma (yukarıda). Kalan: dinleyici çalışmıyorsa ya da bağlantısı kopmuşsa en fazla 5 sn (kopukken) veya `signing_key_cache_ttl` (dinleyici hiç başlatılmamışsa; sunucu başlatır).
- ~~Bağlantı havuzu kalıbı~~ — **kapatıldı (K-58):** token basımı sırasında süresi dolmuş anahtar önbelleği **çağıranın transaction bağlantısıyla** yeniden yüklenir (`KeyCache::signer_in`). Böylece refresh, sunucu tarafı rotasyon (org değiştirme, step-up), impersonation ve oturum kurma havuzdan ikinci bir bağlantı beklemez. Eskiden refresh transaction'ı açıkken önbellek yenilemesi ikinci bir bağlantı istiyordu. Tek bağlantılı havuzla regresyon testi: `ses_05_k58_native_flows_never_wait_for_a_second_pooled_connection` (düzeltmeden önce `pool timed out`, 500), `ses_03_k58_web_flows_never_wait_for_a_second_pooled_connection` (web akışları; düzeltmeden önce de geçiyordu, kapsam testi). Wave 4B denetimi crate'in tamamını taradı ve bir örnek daha buldu: impersonation başlatırken profil okuması (4B-1, düzeltildi). Kalan havuz kullanımları transaction dışındadır: plan aşaması, `peek`, iptal sonrası işler.
- [info] Kullanıcı başına kullanıcı ajanından türetilen cihaz adı (`authn_protect::risk::useragent::describe`) yalnızca sabit sözlükten oluşur.
- [info] `SessionIssuer::complete_primary_authentication` şimdilik risk değerlendirmesi ve güvenilir cihaz yapmaz; giriş ajanı ekler (yukarıda).
- ~~Break-glass hesabıyla giriş yüksek öncelikli olay üretmiyor~~ — **kapatıldı (wave 2B, K-05):** `is_break_glass` hesabına oturum kuran her giriş (boru hattı ve challenge tamamlama; federe giriş dahil) aynı transaction'da `admin.break_glass_used` (`priority: high`, `surface: login`, `method`, `client`) yazar ve `authn_break_glass_logins_total` metriğini artırır. Test: `passkey_login::adm_05_break_glass_login_emits_high_priority_event`.
- [info] Web impersonation token'ı (K-12) admin konsolunun belleğinde tutulur ve başlıkla gönderilir: native token'larla aynı XSS maruziyeti; `HttpOnly` çerez koruması yoktur (bilinçli: çerez seçeneği adminin oturum çerezini ezerdi).

### K-58 değerlendirmesi: kalan maddeler (2026-11-05)

Proje sahibinin talimatı: bir risk ancak düzeltilmesi imkânsızsa ya da açıkça daha kötüyse kalabilir. Yukarıdaki listelerde üstü çizilmeyen her madde için karar:

| Madde | Karar | Gerekçe |
|-------|-------|---------|
| Challenge adımlarında paralel yanlış denemeler sınırı birkaç adım aşabilir | Gerekçeli kalır | Kapatmak, kanıt doğrulanırken (Argon2/TOTP) challenge satırının kilitli tutulmasını gerektirir. Bu, havuz kalıbını (bir bağlantıyı yavaş iş boyunca tutmak) geri getirir ve eşzamanlı girişlerde havuz tükenir. Aşım en fazla eşzamanlı istek sayısı kadardır; faktör modüllerinin kullanıcı başına sınırları ve kilitleri ayrıca geçerlidir. |
| Passkey girişi `allowed_mfa_factors`'ı atlar | Spesifikasyon gereği | SES-21: passkey tek başına MFA'dır. Kuruluş passkey'i giriş yöntemlerinden kaldırabilir. |
| Yalnızca TOTP'si olan kullanıcı, phishing'e dayanıklı MFA isteyen kuruluşta takılır | Gerekçeli kalır | Güvenli taraf, atlatma yok. Challenge içinde passkey kaydı, kanıtlanmamış bir oturumda kimlik bilgisi eklemek demektir ("Trojan identifier" sınıfı). |
| `verify_email` doğrulanmamış şifreyi silince bekleyen `change_password` başarısız olur | Gerekçeli kalır | ADR 0002'nin güvenlik kuralıdır; yalnızca kullanılabilirlik etkisi var. |
| Federe girişte güvenilir cihaz yok | Gerekçeli kalır | Güvenli taraf (MFA atlanmaz). |
| Şifresiz arka plan kuyruğu 1024'te düşer | Gerekçeli kalır | Sınırsız kuyruk bellek DoS'u olur. Düşen iş yalnızca e-posta gecikmesidir; hesap varlığı sızmaz. |
| ~~Hangi faktörün `mfa` ürettiği oturumda saklanmaz~~ | **Kapatıldı (wave 4B denetimi)** | Faktör, oturumun `amr` değerinde zaten saklıdır (`otp`=TOTP, `sms`, `email`, `kba`=kurtarma kodu, `hwk`/`swk`=passkey). Eksik olan, org değiştirmede bu bilginin kullanılmasıydı. `POST /v1/session/org` artık hedef kuruluş MFA istiyorsa ve `allowed_mfa_factors` tanımlıysa, `amr`'den birincil giriş yönteminin katkısını çıkarır ve kalan referanslardan biri izinli bir faktör olmalıdır. Passkey tek başına MFA'dır (SES-21). Ayırt edilemeyen durum güvenli tarafta reddedilir: e-posta kodu ile giriş + TOTP iken `otp` birincil yöntemindir. Reddedilen kullanıcı izinli bir faktörle step-up yapar (`org_policy_mfa_required`). Test: `ses_17_k58_org_switch_enforces_the_allowed_second_factors` (düzeltmeden önce `200`). Kalan küçük boşluk: risk onayı e-postası (RSK-03) `amr`'ye `email` ekler. Kuruluş `email` faktörüne izin veriyorsa bu onay, izinli faktör gibi sayılabilir. Kolon gerektirmeyen bu çözüm bilinçli seçildi. **Kalan boşluk K-78 ile kapatıldı (wave 5A), aşağıya bakın.** |
| ~~`password_changed` iptali açık login challenge'larını kapatmaz~~ | **Kapatıldı (wave 4B denetimi)** | Kullanıcı genelindeki `password_changed` iptali artık bekleyen girişleri de kapatır. İstisna, bekleyen adımları `change_password` ya da `verify_email` içeren challenge'lardır: bu SES-22 adımları iptali girişin *içinden* yapar. Eski şifreyi bilen kişi bunları başka birinin değişikliğinden sonra bitiremez. Sebepler: `apply_required_password_change` `must_change_password` bayrağını ister ve her değişiklik bu bayrağı siler; `verify_email` ise posta kutusuna gönderilen kodu ister. Testler: `ses_15_k58_password_change_closes_pending_logins_started_before_it` (düzeltmeden önce kırmızıydı), `ses_15_user_wide_revocation_closes_pending_logins` (güncellendi). |
| `login_response`, challenge token'ının yerini `return_to` varlığıyla seçer | Gerekçeli kalır | API sözleşmesi; federe web çağıranları `return_to` geçer (belgeli). |
| Kardeş alt alan adının çerez kavanozunu doldurması (yalnızca DoS) | İmkânsız | Tarayıcının çerez sınırlarından doğar. `__Host-` çerezin üzerine yazılmasını zaten engeller. |
| Diğer `[info]` maddeleri | Risk değil | Bilgi notudur (tasarım açıklaması). |

### Bağımsız denetim (wave 4B, 2026-11-05)

| # | Önem | Bulgu | Test | Durum |
|---|------|-------|------|-------|
| 4B-1 | orta | Impersonation başlatma (`impersonate_in_tx`, admin işlemi), hedefin satırı kilitliyken bildirim için profili `profile_of` ile **havuzdan ikinci bir bağlantıyla** okuyordu (havuz kalıbı; eşzamanlı işlemlerde havuz tükenmesi, 500). | `ses_15_k58_impersonation_never_waits_for_a_second_pooled_connection` (düzeltmeden önce `internal_error`) | Düzeltildi: `AccountService::profile_of_in(conn, …)` |
| 4B-2 | orta | `password_changed` bekleyen girişleri kapatmıyordu (yukarıdaki tablo). | `ses_15_k58_password_change_closes_pending_logins_started_before_it` | Düzeltildi |
| 4B-3 | düşük | Org değiştirme `allowed_mfa_factors`'ı denetlemiyordu (yukarıdaki tablo). | `ses_17_k58_org_switch_enforces_the_allowed_second_factors` | Düzeltildi |
| 4B-4 | düşük | İmza anahtarı dinleyicisi: bağlantı koptuğunda `PgListener` sonraki `try_recv` içinde sessizce yeniden bağlanıyordu. Bu sürede (en çok bağlantı zaman aşımı kadar) durum "bağlı" kalıyor, önbellek ömrü 30 sn oluyordu ve bildirimler kayboluyordu. Artık kopma "bağlı değil" (5 sn) sayılıyor ve dinleyici açıkça yeniden abone oluyor. Önbellek LISTEN geri geldikten sonra yeniden boşaltılıyor. | `ses_09_k58_listener_survives_a_killed_connection` (sağlamlık testi; pencere zamanlamaya bağlı olduğundan düzeltmeden önce kırmızı gösterilemedi) | Düzeltildi |
| 4B-5 | düşük, kabul | Tolerans penceresi açıkken (`refresh_reuse_grace` > 0; varsayılan 0, en çok 10 sn) sunucu tarafı rotasyonun (org değiştirme, step-up) ardılı da artık mühürleniyor. Pencere içinde emekli refresh token'ı sunan **herkes** ardılı alır; çalınmış token bu kısa pencerede yeniden kullanım olarak algılanmaz. Bu, refresh rotasyonunun zaten var olan tolerans semantiğiyle aynıdır. Tespit, iki taraf ayrıştığında yine gerçekleşir: sonraki rotasyonda kaybeden tarafın token'ı yeniden kullanım sayılır ve aile iptal edilir. | — | Kabul: pencere varsayılan olarak kapalı, açıkken de 10 sn ile sınırlı |
| 4B-6 | bilgi | `access_token_id` eşlemesi yeniden kullanım tespitini veya aile iptalini hiçbir yolda zayıflatmıyor. Eşleşmeyen access token'la yetki değişikliği `401` alır ve hiçbir şey döndürülmez. Eskiden çalınmış eski bir access token'la org değiştirmek **yeni bir refresh token** veriyordu; şimdi veremez. Migration öncesi satırlarda (`NULL`) kontrol yapılmaz ve eski davranış geçerlidir; ilk rotasyonla eşleme dolar. Eşleşmeme audit'e yazılmaz, yalnızca `401` döner. | mevcut `ses_*_k58_*` | Bilgi |
| 4B-7 | bilgi | Nesil sayacı (u64, yalnızca artar) ABA'ya açık değil. Tetikleyici INSERT/UPDATE/DELETE/TRUNCATE'i kapsıyor. Dinleyici kimlik bilgilerini havuzun bağlantı seçeneklerinden kopyalıyor ve hatalarda yalnızca `sqlx` hata metnini logluyor (parola içermez). Kapanış bağlantıyı bırakıp havuzu kapatıyor. Kaçan bir NOTIFY, anahtarı en çok `signing_key_cache_ttl` boyunca kabul ettirebilir, "sonsuza dek" değil. | `cry_10_k58_every_signing_key_change_notifies` | Bilgi |


## Server'ın bağlaması gerekenler

```rust,ignore
// 1) MfaService (policy_source = server adaptörü) …
let session_revoker = authn_session::PgSessionRevoker::new(clock.clone(), audit.clone(), events.clone(), mfa.clone());
// 2) AccountService, iç revoker ile; diğer modüllere account dekoratörü:
let account = AccountService::new(AccountServiceDeps { sessions: Arc::new(session_revoker.clone()), … }, …)?;
let revoker: Arc<dyn SessionRevoker> = Arc::new(authn_account::AccountAwareSessionRevoker::new(Arc::new(session_revoker), account.clone()));
// 3) PasswordService / OrgService / … `revoker` ile; sonra:
let sessions = SessionService::new(SessionServiceDeps { pool, clock, keys: crypto.keys.clone(), envelopes: crypto.envelopes.clone(),
    rate_limiter, audit, events, notifier, passwords, mfa, webauthn, orgs, accounts: account }, SessionSettings::from_app_config(&config))?;
// 4) SessionIssuer portu: Arc::new(sessions.clone()) as Arc<dyn SessionIssuer> → authn-oidc-client, authn-admin.
```

- `impl FromRef<AppState> for SessionService`; `.merge(authn_session::router::<AppState>())`; `openapi.rs`'e `authn_session::SessionApi`.
- Katman (8): `axum::middleware::from_fn_with_state(sessions.clone(), authn_session::authenticate)`; `authn_org::api_key_middleware` **kurulmaz**. `/v1/me*`, `/v1/email/change/confirm` ve diğer modüllerin oturum isteyen yolları bu katmanın arkasında.
- Açılış: `SigningKeyRepository::rotate_if_due` (ilk anahtar) — anahtar yoksa token basılamaz (`service_unavailable`); acil rotasyondan sonra aynı süreçte `sessions.invalidate_signing_keys()`.
- Arka plan işi (OPS-06): `sessions.purge_expired(limit)` (biten oturumlar 30 gün sonra, challenge'lar 1 gün sonra, tolerans ardılları).
- Dışa aktarma (ACC-10): `AccountServiceDeps.exporters`'a `Arc::new(authn_session::SessionDataExporter)`.
- Wave 2B: CORS izinli başlıklarına `x-impersonation-session` (admin konsolu ayrı origin'deyse). `AccountAwareSessionRevoker` `revoke_everything_except`'i iletmelidir (wave 2A'da eklendi). authn-oidc-client `SessionLiveness` adaptörü → `authn_session::is_session_active_in(conn, session, user, now)`.
- authn-admin: impersonation için `SessionIssuer::start_impersonation_audited(conn, ctx, request, client, Some(admin_session_id), event_id)` (bildirim ve audit burada, adminin transaction'ında yazılır; admin tekrar göndermez, gerekçeyi aynı transaction'da `event_id`'ye bağlar). Test: `ses_15_audited_impersonation_runs_in_the_callers_transaction`.

## Testler

| Dosya | Kapsam |
|-------|--------|
| `tests/web_session.rs` | SES-03 çerez öznitelikleri, sabitleme, cookie tossing; SES-04 CSRF (eksik/yanlış token, çapraz origin, `Sec-Fetch-Site`, login CSRF, giriş yapmış tarayıcı); SES-06 boşta/mutlak bitiş (FakeClock), touch seyreltme, askıya alınmış sahip; SES-07; SES-14 (eşzamanlı girişler dahil); challenge API'si (tek kullanım, cihaz bağlama, deneme sınırı, çağıranın kilidinde sonsuz bekleme yok) |
| `tests/native_tokens.rs` | SES-05 rotasyon, yeniden kullanım → aile iptali + audit, eşzamanlı refresh yarışı, tolerans penceresi (aynı ardıl, kapanış), oturum kontrolü açık/kapalı; SES-06 mutlak bitiş uzamaz; SES-08 claim'ler, kurcalama / `alg: none` / HS256 / bilinmeyen `kid` / yabancı anahtar / `aud` / `iss` / `typ` / `nbf` / ömür / süre bitimi ara katman üzerinden; SES-09 JWKS ve acil anahtar rotasyonu |
| `tests/revocation.rs` | SES-15 port anlamı (aynı transaction'da güvenilir cihazlar, geri alma), biri hariç, organizasyon bazlı, her şey, tüm `RevocationReason` değerleri, domain olayları, bekleyen girişlerin kapatılması (`password_changed` istisnası); SES-11 liste (maskeli IP, IDOR `404`, CSRF), diğerlerini kapat, dışa aktarma; SES-12 çıkış ve her yerden çıkış; temizlik işi |
| `tests/org_switch.rs` | SES-17 rotasyon, yabancı/askıdaki üyelik `404`, MFA politikası → TOTP step-up, IP izin listesi, izinli giriş yöntemi, ömür üst sınırı, native token rotasyonu ve eski token'ın reddi, `VerifiedOrg`'un kullanıcıya bağlılığı, oturum kontrolü kapalıyken giriş yöntemi kontrolü |
| `tests/step_up.rs` | SES-13 şifre, yanlış şifre (tek tip + audit), TOTP (+ tekrar oynatma), oran sınırı, admin/katı organizasyon için passkey zorunluluğu (kişisel bağlamda ve gevşek organizasyonda da: tüm üyeliklerin en katı politikası), native, passkey seremonisi |
| `tests/introspection.rs` | SES-10 istemci doğrulaması, aktif token, iptal/süresi dolmuş/yabancı/kişisel/refresh → `active:false`, oran sınırı, API anahtarlarının yalnızca organizasyon yollarında principal olması |
| `tests/login.rs` | Giriş akışları HTTP üzerinden: SES-01 (tek tip hata, zamanlama — CAPTCHA öncesi ve sonrası, durum yalnızca doğru şifreden sonra, login CSRF, CAPTCHA tırmanması, eşzamanlı denemeler, bütçe iadesi), SES-02 (TOTP, kurtarma kodu, izinsiz faktör doğrulanmadan reddi, tek kullanım, deneme sınırı, istemci/cihaz bağlama, askıya alma), MFA-09, SES-22, RSK-03/04 (yüksek risk engeli, e-posta onayı, federe girişte risk, yeni cihaz + "bu ben değilim"), SES-18 (aynı/başka cihaz, GET ile tüketilmeme, tek kullanım, süre, pre-hijacking, oran sınırı), SES-19, SES-21, denetim regresyonları |
| `tests/passkey_login.rs` | Yazılımsal authenticator ile passkey girişi (web/native), passkey = MFA ve phishing'e dayanıklı politika, binding token, ikinci faktör olarak passkey |
| `tests/issuer.rs` | SES-16 `/v1/me`; SES-15 `SessionIssuer` (federe giriş: oturum/challenge, passkey UV = MFA, sahte `mfa`/`hwk` iddiası, askıya alınmış hesap, organizasyon yöntem politikası), impersonation (salt-okunur zorlama, audit, bildirim, süre sınırı, uygunsuz hedefler, `act` claim'i, step-up yasağı, admin iptal/yetki kaybı/askıya alma ile bitiş, kullanıcının diğer oturumlarını kapatamama) |

## Komutlar

```bash
cargo test -p authn-session --all-features
cargo clippy -p authn-session --all-targets --all-features -- -D warnings
cargo fmt -p authn-session
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## K-78: MFA'yı üreten faktörler (wave 5A, 2026-11-05)

**Sorun:** risk onayı e-postası (RSK-03) `amr`'ye `email` ekler. Wave 4B'nin org değiştirme denetimi faktörü `amr`'den çıkarıyordu. TOTP ile step-up yapmış ve risk onayı vermiş bir oturum (`["pwd","email","otp","mfa"]`), yalnızca `email` faktörüne izin veren bir kuruluşa geçebiliyordu. Oysa `email` ikinci faktör değil, risk onayıydı.

**Çözüm:** oturum, MFA'yı hangi ikinci faktörlerin ürettiğini saklar.
- **Saklama:** migration `2002`: `sessions.mfa_factors`, `auth_challenges.mfa_factors` (`text[]`, `FactorKind` değerleri). Kaynaklar: giriş challenge'ında doğrulanan faktör, giriş sırasında kaydı onaylanan faktör, step-up'ta doğrulanan TOTP / kurtarma kodu / passkey (`StepUpProof::factor`). Risk onayı e-postası **asla** kaydedilmez. Şifreyle step-up ikinci faktör değildir.
- **`mfa` kararı** (`record_second_factor`): `amr`'deki örtüşmeye değil faktör türüne bakılır. Faktör, birincil yöntemin kendi faktöründen (e-posta link/kodu → `email`, passkey → `webauthn`) farklıysa `mfa` eklenir. Sonuçlar:
  - parola + risk onayı + e-posta faktörü artık `mfa` alır (önceden onayın `email`'i faktörü gizliyordu);
  - e-posta kodu + TOTP artık ayırt edilir ve `mfa` alır (önceden `otp` örtüşmesi yüzünden almıyordu; K-78 satırındaki kullanılabilirlik notu);
  - e-posta kodu + e-posta faktörü (aynı posta kutusu) `mfa` almaz.
- **Uygulama:** `POST /v1/session/org` hedef kuruluş MFA istiyor ve `allowed_mfa_factors` tanımlıysa `mfa_factors` içinde izinli bir tür arar (passkey tek başına MFA, SES-21). Step-up zaten kanıt türünü kuruluşun izinli faktörlerine göre denetliyordu; şimdi doğrulanan faktörü de kaydediyor. Giriş challenge'ı izinli faktörleri `allowed_factors` ile doğrulamadan önce denetliyordu, bu değişmedi.
- **Geçiş:** migration'dan önceki oturumların kaydı boştur. Faktörleri kısıtlayan bir kuruluşa geçerken bir kez step-up istenir (güvenli taraf). Sağlayıcı MFA'sı (SOC-09) bir faktör kaydı üretmez, önceki gibi reddedilir.
- **Testler:**
  - `login::k_78_risk_confirmation_never_counts_as_an_allowed_second_factor` (regresyon: düzeltmeden önce org değiştirme `200` dönüyordu, test kırmızıydı);
  - `login::k_78_verified_login_factor_is_recorded_for_the_session`;
  - `establish::k78_tests::k_78_mfa_is_decided_on_factor_kinds`;
  - `k58::ses_17_k58_org_switch_enforces_the_allowed_second_factors` (güncellendi: kayıtsız `otp` reddedilir, e-posta kodu + kayıtlı TOTP kabul edilir).
