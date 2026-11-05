# Kimlik doğrulama: başlıklar, çerezler ve CSRF (DOC-04)

Bu belge istemcinin kendini nasıl tanıttığını ve sunucunun hangi başlık ve çerezleri okuduğunu/yazdığını anlatır. Kaynaklar: `crates/authn-session/src/{middleware,cookies,csrf}.rs`, `crates/authn-session/src/login/{mod,routes}.rs`, `crates/authn-org/src/middleware.rs`, `crates/authn-core/src/http/context.rs`, `crates/authn-protect/src/web/{headers,cors,host}.rs`. Akışların sıra diyagramları: [`docs/architecture/flows.md`](../architecture/flows.md). İstemci rehberleri: [`docs/integration/`](../integration/README.md).

## 1. İki istemci türü

| | Web (tarayıcı) | Native (mobil / masaüstü / sunucu) |
|-|----------------|------------------------------------|
| Seçim | varsayılan | giriş isteklerinde `X-Authn-Client: native` |
| Kimlik bilgisi | opak oturum token'ı, `__Host-authn_session` çerezinde | JWT access token (`Authorization: Bearer …`) + dönen refresh token |
| Bekleyen giriş (MFA / zorunlu adım) | `__Host-authn_challenge` çerezi | yanıt gövdesindeki `challenge_token`, sonraki adımlarda `X-Authn-Challenge` başlığı |
| CSRF | zorunlu (durum değiştiren her istek) | yok (çerez kullanılmaz) |
| Ömür | `session.web` (2s boşta / 12s mutlak), `remember_me`, `shared_device` | access `session.access_token_ttl` (10 dk), refresh ailesi `session.refresh_token` (30g boşta / 90g mutlak) |

`X-Authn-Client` `native` veya `web` değerini alır (başlık yoksa `web`); başka değer veya tekrarlanan başlık `400 bad_request`. Web giriş isteklerinin (`/v1/login/*`, `POST /v1/login/not-me` hariç) login-CSRF kanıtı taşıması zorunludur (§3). Giriş yanıtı (`CredentialsBody`) web'de `csrf_token` ve `Set-Cookie`, native'de `access_token`, `token_type: "Bearer"`, `expires_in`, `refresh_token`, `refresh_token_expires_at` taşır. Her iki türde `status: "authenticated"`, `session_id`, `user_id`, `amr`, `auth_time`, `expires_at`, `active_org_id`. Ek adım gerekiyorsa `status: "challenge_required"` + `challenge_id`, `allowed_factors`, `required_actions`, `expires_at` (`ChallengeBody`).

## 2. Kimlik doğrulama ara katmanı (karar sırası)

`authn_session::authenticate` her modül rotasında çalışır (OPS-02 yuva 8, `crates/authn-server/src/app.rs`); yalnızca oturumsuz break-glass passkey kayıt rotaları (`/v1/admin/enrollment/*`) bu katmanın dışındadır. Kimlik istemeyen uçlar da bu katmandan geçer: kimlik bilgisi yoksa principal üretilmez, istek devam eder. **Tam olarak bir** kimlik bilgisi karar verir:

1. **`x-impersonation-session`** (admin konsolu, K-12): yalnızca canlı bir impersonation web oturumunun token'ı kabul edilir; `Authorization` ile birlikte gönderilemez; geçersizse `401` ve adminin çerezine geri düşülmez. CSRF token'ı gerekmez.
2. **API anahtarı** — `Authorization: Bearer ak_…` veya `X-API-Key: ak_…`. Yalnızca `/v1/orgs/{org_id}[/…]` yollarında `Principal` olur (anahtarın organizasyonu ve kapsamları içinde); başka yollarda principal üretmez (`POST /v1/token/introspect` anahtarı kendisi doğrular). İki başlık birlikte veya tekrarlı başlık `401`. Biçim: `ak_<env>_<43 base62>_<6 base62 CRC>`; başka ortamın (`org.api_keys.environment`) anahtarı veritabanına gitmeden reddedilir.
3. **Bearer access token** — imza ve claim doğrulaması (bkz. §5) + varsayılan olarak oturumun hâlâ etkin olması (`session.access_token_session_check`, üretimde zorunlu `true`) ve token'daki aktif organizasyonun oturumunkiyle eşleşmesi. Hata: `401 unauthenticated` + `WWW-Authenticate: Bearer error="invalid_token"`. `Authorization` başlığı varsa çerez yok sayılır.
4. **Oturum çerezi** `__Host-authn_session` — durum değiştiren yöntemlerde (GET/HEAD/OPTIONS/TRACE dışındaki her şey) CSRF denetimi burada yapılır; başarısızsa `403 csrf_failed` ve handler çalışmaz. Aynı ada farklı değerli birden fazla çerez (cookie tossing) principal üretmez.

Salt-okunur impersonation altında `POST /v1/logout` dışındaki her durum değiştiren istek `403 forbidden` alır. Kimliği doğrulanmamış istek kimlik isteyen bir uca gelirse `401 unauthenticated`.

## 3. CSRF

`crates/authn-session/src/csrf.rs` (SES-04). Oturum çereziyle gelen durum değiştiren her istekte **iki bağımsız denetim**:

1. **Origin:** `Origin` başlığı izinli origin'lerden biri olmalı: `server.public_base_url`'in origin'i + `session.csrf_allowed_origins` (tam eşleşme). `Origin` yoksa yalnızca `Sec-Fetch-Site: same-origin` kabul edilir; ikisi de yoksa veya `Origin: null` ise ret.
2. **Senkronize token:** `X-CSRF-Token` = `base64url(HMAC(K_csrf, "session" ‖ oturum kimliği ‖ SHA-256(oturum token'ı)))`. Token oturuma **ve** güncel oturum token'ına bağlıdır: oturum döndüğünde (giriş, MFA tamamlama, `POST /v1/session/org`, `POST /v1/reauth`) eski CSRF token'ı geçersizleşir; yeni değer o yanıtın `csrf_token` alanındadır. Tekrarlanan başlık reddedilir; karşılaştırma sabit zamanlıdır.

Güncel token'ı her zaman `GET /v1/csrf` verir (`{"csrf_token": "…", "kind": "session" | "pre_session"}`).

**Giriş formu CSRF'i (login CSRF):** henüz oturum yokken `GET /v1/csrf` rastgele bir sırrı `__Host-authn_csrf` çerezine (`SameSite=Strict`, tarayıcı oturumu çerezi) yazar ve `kind: "pre_session"` token'ı döner. Web giriş istekleri (`/v1/login/*`) `Origin` + bu token'ı taşımalıdır; oturum kurulunca pre-session çerezi silinir. Federe (sosyal) geri dönüşler bunun yerine OAuth `state` + tarayıcı bağlama çereziyle korunur.

## 4. Çerezler

Tüm çerezler `__Host-` önekli, `Path=/`, `Secure`, `HttpOnly`'dir ve `Domain` taşımaz: kardeş bir alt alan adı bunları yazamaz/ezemez (`crates/authn-session/src/cookies.rs::build`). Yalnızca HTTPS'te çalışırlar (tarayıcılar `localhost`'ta `Secure` çerezi kabul eder).

| Çerez | SameSite | Ömür | Ne için | Kaynak |
|-------|----------|------|---------|--------|
| `__Host-authn_session` | `Lax` | tarayıcı oturumu; "beni hatırla"da `Max-Age` = kalan mutlak ömür | Web oturum token'ı (256 bit, DB'de yalnızca SHA-256) | authn-session `cookies.rs` |
| `__Host-authn_csrf` | `Strict` | tarayıcı oturumu | Login CSRF pre-session sırrı | authn-session `cookies.rs` |
| `__Host-authn_challenge` | `Strict` | challenge ömrü (`session.mfa_challenge_ttl`) | Bekleyen girişin (MFA / zorunlu adım) token'ı | authn-session `cookies.rs` |
| `__Host-authn_passkey` | `Strict` | seremoni ömrü | Passkey girişi / step-up seremonisi ve giriş challenge'ı içindeki passkey kaydı (K-112) bağlama token'ı | authn-session `cookies.rs` |
| `__Host-authn_trusted_device` | `Strict` | `mfa.trusted_device.ttl` | "Bu cihazda tekrar sorma" (MFA-09) token'ı | authn-session `cookies.rs`, authn-mfa |
| `__Host-authn_device` | `Lax` | 365 gün | Cihaz kimliği (risk değerlendirmesi, bilinen cihaz); `[A-Za-z0-9_-]{16,128}` | authn-core `http/context.rs` |
| `__Host-authn_magic` | `Lax` | magic link ömrü | Magic link isteğini yapan tarayıcıya bağlar (SES-18) | authn-session `login/mod.rs` |
| `__Host-authn_registration` | `Strict` | `account.unverified_purge_after` | Kayıt tutamacı (ADR 0002) | authn-account `service/registration.rs` |
| `__Host-authn_oauth` | `None` | 600 sn | Sosyal giriş tarayıcı bağlaması; Apple `form_post` geri dönüşü siteler arası `POST` olduğu için `None` | authn-oidc-client `cookies.rs` |

`POST /v1/logout` web'de oturum çerezini siler ve `Clear-Site-Data: "cookies"` gönderir (impersonation başlığıyla çağrıldığında göndermez).

## 5. Access token (JWT)

`crates/authn-session/src/claims.rs`, `crates/authn-crypto/src/jwt.rs` (CRY-09, SES-08, RFC 9068).

- Başlık: tam olarak `{"alg":"EdDSA","typ":"at+jwt","kid":"…"}`. Başka parametre (`crit`, `jku`, `jwk`, `x5u`, `x5c`, `b64`) veya tekrarlanan ad reddedilir. Tek algoritma Ed25519'dur; `none`/`HS*`/`RS*`/`ES*` asla kabul edilmez.
- Claim'ler: `iss` (`session.issuer`, varsayılan `server.public_base_url` sondaki `/` olmadan), `sub` (opak kullanıcı kimliği), `aud` (dizi: `session.audiences`), `exp`, `iat`, `nbf`, `jti`, `sid` (oturum = refresh ailesi), `auth_time`, `amr` (RFC 8176 + `email`, `fed`), isteğe bağlı `acr`, `org_id` (aktif organizasyon), `scope` (boşlukla ayrılmış, `session.default_scopes`), `client_id` (`first-party`), impersonation'da `act: {"sub": "<admin>"}` ve `read_only`.
- Kişisel veri yoktur (e-posta, ad taşınmaz).
- Doğrulama anahtarları: `GET /.well-known/jwks.json` (OKP / Ed25519, `alg: EdDSA`, `use: sig`). Kaynak sunucusu örneği: [`docs/integration/resource-server.md`](../integration/resource-server.md).

## 6. Diğer istek başlıkları

| Başlık | Yön | Anlam |
|--------|-----|-------|
| `X-Authn-Challenge` | istek | Native: bekleyen girişin `challenge_token`'ı |
| `x-trusted-device` | istek | Native: güvenilir cihaz token'ı (challenge doğrulama yanıtındaki `trusted_device_token`) |
| `x-device-id` | istek | Native: kalıcı cihaz kimliği, `[A-Za-z0-9_-]{16,128}` (geçersizse yok sayılır); web'de `__Host-authn_device` çerezi |
| `x-request-id` | yanıt | Sunucunun ürettiği UUIDv7. **İstemcinin gönderdiği değer yok sayılır** ve değiştirilir |
| `Accept-Language` | istek | Hata mesajlarının dili (`tr` / `en`; eşleşmezse `server.default_locale`) |
| `Retry-After` | yanıt | `429` ve bazı `503`'lerde saniye |
| `WWW-Authenticate` | yanıt | Bearer reddinde `Bearer error="invalid_token"` |
| `Cache-Control: no-store` | yanıt | Varsayılan olarak **her** yanıtta (JWKS ve well-known belgeleri kendi `public, max-age` değerini koyar) |

## 7. Güvenlik başlıkları, Host ve CORS

- Her yanıtta (`crates/authn-protect/src/web/headers.rs`): `Strict-Transport-Security: max-age=63072000; includeSubDomains` (ayarlanabilir), `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-site`, `Permissions-Policy` (`protect.security_headers.permissions_policy`).
- **Host:** yalnızca `protect.allowed_hosts` (varsayılan: `public_base_url`'in host'u); aksi `421 host_not_allowed`. `/health/` muaf.
- **CORS** (`protect.cors.allowed_origins`, varsayılan kapalı): yalnızca tam eşleşen origin'ler, kimlik bilgisiyle (`Access-Control-Allow-Credentials`). İzinli yöntemler `GET, HEAD, POST, PUT, PATCH, DELETE`; izinli istek başlıkları yalnızca `accept`, `accept-language`, `authorization`, `content-language`, `content-type`, `x-csrf-token`, `x-device-id`; okunabilir yanıt başlıkları `x-request-id`, `retry-after`. Liste dışı preflight `403 cors_origin_not_allowed`. Sonuç: başka bir origin'deki tarayıcı kodu `X-Authn-Client`, `X-Authn-Challenge`, `X-API-Key` veya `x-trusted-device` gönderemez — yani native token akışını tarayıcıdan **kullanamaz**. Tarayıcılar çerez akışını kullanır ([web rehberi](../integration/web.md)). `x-impersonation-session` yalnızca `server.admin_console_origins` için ayrı bir katmanda izinlidir (K-67).
