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
| SES-22 | Uygulandı | `login/challenge.rs`, `POST /v1/login/challenge/step` |
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
| `PgSessionRevoker::new(clock, audit, events, mfa)` | `SessionRevoker` port uygulaması (SES-15) |
| `impl SessionIssuer for SessionService` | `complete_primary_authentication`, `login_response`, `start_impersonation`, `start_impersonation_with`, `start_impersonation_audited` (ADM-04, ADM-08; wave 1, K-06: çağıranın transaction'ında, çağıranın verdiği olay kimliğiyle `admin.impersonation_started`; commit çağıranın) |
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
4. **Oturum (SES-03/05/06/07/14):** `establish(&mut conn, &ctx, EstablishSession { user_id, method, amr, acr, auth_time, client, remember_me, shared_device, org, device })` → `EstablishedSession { session, credentials, evicted }`. Her çağrı yeni oturum kimliği ve token'ı üretir (sabitlemeye karşı). Aynı transaction'da `login_succeeded_event(&ctx, &established, method)` ile audit yazılır, `UserRepository::record_login` çağrılır; yanıt `response::credentials_response(&session, credentials, now)` (web: çerez + yeni CSRF token'ı + pre-session çerezinin silinmesi + gerekirse cihaz çerezi; native: token çifti).
5. **Boru hattı:** `complete_login(&ctx, PrimaryAuthentication, ClientChannel)` birincil doğrulamadan sonraki ortak karar noktasıdır (hesap durumu → organizasyon → MFA → zorunlu adımlar → oturum veya challenge). `PrimaryAuthentication.amr` içindeki `mfa` / `hwk` / `swk` yalnızca `LoginMethod::Passkey` için dikkate alınır; diğer yöntemlerde atılır (sağlayıcı MFA'sı yalnızca `provider_asserted_mfa` + `oidc_client.trust_provider_mfa` ile, SOC-09). Giriş ajanı bunu **risk değerlendirmesi (RSK-03, `RiskEvaluator` + `authn_protect::risk::decide` + `RiskAlerts`) ve güvenilir cihaz (MFA-09, `MfaService::is_trusted_device`)** ile genişletir; şifre girişinde `LoginProtection::check_attempt` / `record_success` / `record_failure` ve `verify_login_password` sonucunun enum ile eşlenmesi (`MustChangePassword` ⇒ `RequiredAction::ChangePassword`) contracts §15.7'dedir.
6. **Toplu iptal ve bekleyen girişler:** kullanıcı genelindeki her iptal (`revoke_all_for_user` / `revoke_all_except` / `revoke_everything`) kullanıcının açık challenge'larını da kapatır — **`password_changed` hariç**: SES-22 zorunlu adımları (şifre değiştirme, e-posta doğrulama) iptali tamamladıkları girişin *içinden* bu nedenle yapar. Giriş ajanı başka bir nedenle iptal tetikleyen bir adımı challenge'ın ortasında çalıştırmamalıdır.
7. **NotMeTokenIssuer (RSK-04):** `authn_protect::risk::NotMeTokenIssuer` uygulaması ve `not_me` linkinin tüketimi giriş ajanına kalır (`one_time_tokens` amaçları `magic_link`, `login_code`, `not_me`).

## Giriş akışları (`src/login/`)

**Ortak boru hattı** (`login/pipeline.rs`, `complete_login` ve `SessionIssuer` de bunu kullanır): hesap durumu (yalnızca doğru birincil kimlik bilgisinden sonra açıklanır) → istenen organizasyon (üyelik, IP, izinli yöntem) → MFA gereksinimi (MFA-08) → **risk** (RSK-03: `high` ⇒ engel + kullanıcıya bildirim, `medium` ⇒ kayıtlı faktör ya da e-postayla gönderilen onay kodu) → **güvenilir cihaz** (MFA-09; yalnızca politika kaynaklı MFA'yı karşılar, riskin istediğini asla) → oturum ya da challenge. Oturumdan sonra: cihaz/ağ kaydı, yeni cihazda bildirim + "bu ben değilim" linki (RSK-04, cihaz kimliği oturuma yeni atansa bile), doğrulanmış domain'lere otomatik katılım.

**Challenge adım sırası** (`login/challenge.rs`): `verify_mfa` (kanıt türü `allowed_factors`'ta değilse doğrulamadan **önce** reddedilir) → `enroll_mfa` → `change_password` / `accept_terms` / `verify_email`. Kayıtlı bir faktörü olan kullanıcı yeni faktör kaydetmeden önce mevcut faktörünü doğrular; riskli girişte ve "şifre değiştirmeye zorlanmış" hesapta (PWD-12, RSK-04) e-posta onayı şifre değişikliğinden önce gelir — şifre tek başına ne faktör kaydettirir ne de şifreyi değiştirir.

**İstemci türü:** tarayıcı varsayılan (login CSRF zorunlu, challenge token'ı `__Host-authn_challenge` çerezinde); native `X-Authn-Client: native` gönderir, token'lar gövdede, challenge token'ı `X-Authn-Challenge` başlığında.

| Metot ve yol | Gereksinim |
|--------------|-----------|
| `POST /v1/login/password` | SES-01 |
| `POST /v1/login/passkey/options`, `POST /v1/login/passkey` | SES-20, SES-21 |
| `POST /v1/login/magic-link`, `POST /v1/login/magic-link/verify` | SES-18 (GET ile tüketilmez; başka cihazda `confirm_other_device` gerekir → `409 magic_link_confirmation_required`) |
| `POST /v1/login/email-code`, `POST /v1/login/email-code/verify` | SES-19 (her hata tek tip `invalid_code`, en az 50 ms) |
| `POST /v1/login/challenge/verify` | SES-02 (`totp`, `recovery_code`, `email`, `sms`, `passkey`, `email_confirmation`; `trust_device`) |
| `POST /v1/login/challenge/send-code` | SES-02, RSK-03 |
| `POST /v1/login/challenge/passkey/options` | SES-02 |
| `POST /v1/login/challenge/step` | SES-22 (`change_password`, `accept_terms`, `enroll_totp`/`enroll_email`/`enroll_sms`, `confirm_enrollment`) |
| `POST /v1/login/not-me` | RSK-04 (token gövdede; tüm oturumlar + güvenilir cihazlar + bekleyen girişler kapanır, şifre değişikliği zorunlu, sıfırlama e-postası) |

Yeni bağımlılıklar (`SessionServiceDeps`): `protection: LoginProtection`, `risk: Arc<dyn RiskEvaluator>`, `risk_alerts: RiskAlerts`, `otp: OtpHasher`. Kapanışta `drain_background_jobs()` (şifresiz isteklerin arka plan işi). Yeni hata kodları: `magic_link_confirmation_required` (409), `challenge_step_not_allowed` (403).

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

## Kimlik doğrulama ara katmanı

`authenticate`, OPS-02 sırasındaki (8) yuvasıdır ve `authn_org::api_key_middleware`'in **yerine** kurulur (ikisi birlikte kurulmaz: org ara katmanı principal taşıyan isteği reddeder). Tam olarak bir kimlik bilgisi karar verir:

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
| `issuer` / `audiences` | `public_base_url` / `["rust-authentication"]` | ilk audience bu API'nin kendi doğruladığıdır |
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
- **Oturum kontrolü ödünleşimi:** `access_token_session_check = true` (varsayılan) iptali bir sonraki istekte etkili kılar (istek başına bir sorgu). `false` iken iptal en geç `access_token_ttl` (10 dk) içinde etkili olur ve bearer principal'ı asla platform admini sayılmaz (admin API'si için kontrol açık olmalı).
- **Introspection (SES-10):** API anahtarıyla istemci doğrulaması zorunlu; yalnızca anahtarın organizasyonunu aktif organizasyon olarak taşıyan token'lar `active: true` (kiracı izolasyonu, ARC-10); iptal edilmiş/süresi dolmuş/yabancı/kişisel token'lar ayırt edilemez biçimde `{"active": false}`. Kişisel (organizasyonsuz) token'lar JWKS ile çevrimdışı doğrulanır.
- **Step-up (SES-13):** impersonation ve API anahtarı asla step-up yapamaz; platform adminleri ve phishing'e dayanıklı MFA isteyen organizasyonlar yalnızca passkey ile; izinli faktörler uygulanır — **aktif organizasyon ve kullanıcının tüm üyeliklerinin en katı birleşimi** (step-up hesap genelindeki işlemleri açar: kişisel bağlamda veya gevşek bir organizasyonda katı organizasyonun kuralı atlanamaz); kullanıcı başına oran sınırı; tek tip `reauthentication_failed` ve `step_up.failed` audit'i (şifre/kod asla loglanmaz, gövde ayrıştırma hataları gövdeyi yankılamaz — `SecretJson`).
- **Organizasyon değiştirme (SES-17):** üyelik ve politika authn-org `check_membership` ile (başka kiracı `404`); izinli giriş yöntemi kontrolü (passkey step-up passkey-only politikayı karşılar); oturum ömrü üst sınırı mutlak bitişi yalnızca kısaltır.
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
| düşük | Organizasyon değiştirmede izinli giriş yöntemi kontrolü, oturum kontrolü kapalı bearer isteğinde token'dan kurulan sahte kayda (giriş yöntemi yok) bakıyordu | Kontrol kilitli `sessions` satırıyla yapılır | `org_switch::ses_17_login_method_policy_reads_the_stored_session_without_session_check` |

### Kabul edilen riskler / bilinen sınırlamalar

- [low] Native istemcide eşzamanlı iki yetki değişikliği (org değiştirme + step-up) ikinci rotasyonda ilk yanıtın refresh token'ını "kullanılmış" yapar; istemci onu kullanırsa aile iptal edilir (güvenli tarafta başarısızlık).
- [low] Hangi faktörün `mfa` ürettiği oturumda saklanmaz; organizasyon değiştirmede `allowed_mfa_factors` yeniden denetlenmez. Step-up artık tüm üyeliklerin en katı politikasını uygular; kalan boşluk, organizasyon *istenerek* yapılan girişte yalnızca o organizasyonun izinli faktörlerinin uygulanmasıdır (giriş ajanı / `complete_login` ile aynı kural).
- [low] `password_changed` nedenli iptal (PWD-06 kendi kendine şifre değiştirme, SES-22 zorunlu adımları) açık login challenge'larını kapatmaz; eski şifreyle başlamış bekleyen bir giriş challenge ömrü (varsayılan 5 dk) boyunca tamamlanabilir — ikinci faktör ve kalan zorunlu adımlar yine gerekir.
- [low] `SessionIssuer::login_response` challenge token'ını çereze mi gövdeye mi koyacağına `return_to` varlığıyla karar verir (`PendingChallenge` istemci türünü taşımaz); federe web çağıranları `return_to` geçmelidir.
- [info] Kardeş alt alan adı, `Domain=` ile çok sayıda/uzun çerez yazarak (`MAX_COOKIE_PAIRS` 64, başlık 8 KiB) oturum çerezini okunamaz hâle getirebilir: kullanıcı çıkış yapmış görünür (yalnızca DoS; `__Host-` çerezi değiştirilemez).
- [info] Step-up, `must_change_password` bayraklı hesabın doğru şifresini kabul eder (bayrak bir sonraki girişte değişiklik ister; bayrak tek başına ele geçirme anlamına gelmez).
- [info] Step-up ve organizasyon değiştirme token'ı (native'de token çiftini) yeniler; veritabanı oturum kimliği ve JWT `sid` aynı kalır (sabitleme savunması token rotasyonudur, `__Host-` çerezi dışarıdan yazılamaz).
- [info] Native istemci refresh isteğine süresi dolmuş bir `Authorization: Bearer` eklerse ara katman `401` döner; token uç noktasına `Authorization` gönderilmemelidir.
- [info] Impersonation oturumu adminin `amr`'ını devralır; adminin phishing'e dayanıklı oturumla gelmesi (ADM-01) authn-admin'in kontrolüdür — burada eksikse organizasyon politikaları güvenli tarafta reddeder.
- [low] `access_token_session_check = false` iken iptal ve hesap askıya alma en geç 10 dk sonra etkili olur (belgelenmiş ödünleşim).
- [low] İmza anahtarı önbelleği (`signing_key_cache_ttl`, 30 sn) nedeniyle acil iptal edilen anahtarın token'ları diğer instance'larda en fazla bu süre doğrulanabilir (oturum kontrolü açıkken iptal edilmiş oturumlar yine reddedilir).
- [info] Kullanıcı başına kullanıcı ajanından türetilen cihaz adı (`authn_protect::risk::useragent::describe`) yalnızca sabit sözlükten oluşur.
- [info] `SessionIssuer::complete_primary_authentication` şimdilik risk değerlendirmesi ve güvenilir cihaz yapmaz; giriş ajanı ekler (yukarıda).

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
