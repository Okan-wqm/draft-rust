# Web istemcileri: aynı site çerez, SPA ve BFF (DOC-05)

Tarayıcılar `rust-authentication`'a **çerez oturumuyla** bağlanır: opak oturum token'ı `HttpOnly` bir `__Host-` çerezindedir, JavaScript onu hiç görmez. Access/refresh token'ları tarayıcıya verilmez (native akış CORS ile tarayıcıya kapalıdır, bkz. [authentication.md §7](../api/authentication.md#7-güvenlik-başlıkları-host-ve-cors)). Başlık, çerez ve CSRF ayrıntıları: [`docs/api/authentication.md`](../api/authentication.md). Akış diyagramları: [`docs/architecture/flows.md`](../architecture/flows.md).

## 1. Topoloji seçimi

`server.public_base_url` üç şeyin tek kaynağıdır: API'nin kendi adresi (JWT `iss`, OAuth `redirect_uri`, CSRF'in varsayılan izinli origin'i) **ve** e-postalardaki linklerin tabanı (`{public_base_url}{notify.links.*}#token=…`, ör. `/verify-email`, `/reset-password`, `/magic-link`). Bu yüzden ön yüzün e-posta link sayfaları da bu origin'de açılmalıdır.

| Topoloji | Nasıl | Ayarlar | Not |
|----------|-------|---------|-----|
| **A. Aynı origin (önerilen)** | Ters vekil `https://app.example.com` altında `/v1/*`, `/.well-known/*`, `/health/*` yollarını kimlik sunucusuna, kalanını ön yüze yönlendirir | `public_base_url = "https://app.example.com"`; CORS gerekmez | En basit; tüm çerezler tek host'a ait, `Origin` her zaman izinli |
| **B. Aynı site, ayrı alt alan** | SPA `https://app.example.com`, API `https://auth.example.com` | `protect.cors.allowed_origins = ["https://app.example.com"]`, `session.csrf_allowed_origins = ["https://app.example.com"]`; e-posta linklerinin açılacağı sayfalar `auth.example.com`'da olmalı (veya oradan app'e yönlendirin) | `SameSite` "site"e (kayıtlı domain) bakar: `Lax`/`Strict` çerezler `app` → `auth` `fetch`'lerinde gider. `fetch(…, {credentials: 'include'})` zorunlu |
| **C. Siteler arası** | SPA `https://shop.example`, API `https://auth.example.com` | — | **Desteklenmez:** `SameSite=Lax/Strict` çerezler siteler arası `fetch`'te gönderilmez. BFF kullanın (§5) |

Passkey için `webauthn.rp_id` her iki host'u kapsayan kayıtlı domain olmalıdır (ör. `example.com`) ve web origin'leri `webauthn.allowed_origins`'ta listelenmelidir; farklı bir kayıtlı domain ancak `webauthn.related_origins` ile eklenebilir (tarayıcı desteğine bağlı Related Origin Requests, `/.well-known/webauthn`).

## 2. Giriş (şifre + MFA)

```js
const api = (path, opts = {}) => fetch(`https://auth.example.com${path}`, {
  credentials: 'include',
  ...opts,
  headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
});

// 1) Oturumsuz: pre-session CSRF token'ı (ayrıca __Host-authn_csrf çerezini yazar)
const { csrf_token } = await (await api('/v1/csrf')).json();

// 2) Şifre girişi
let res = await api('/v1/login/password', {
  method: 'POST',
  headers: { 'X-CSRF-Token': csrf_token },
  body: JSON.stringify({ email, password, remember_me: false }),
});
let body = await res.json();

// 3) MFA gerekiyorsa: challenge token'ı __Host-authn_challenge çerezinde, gövdede değil
if (body.status === 'challenge_required') {
  // body.allowed_factors: ["totp","recovery_code","email","sms","webauthn", …]
  res = await api('/v1/login/challenge/verify', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrf_token },
    body: JSON.stringify({ method: 'totp', code: '123456', trust_device: true }),
  });
  body = await res.json();
}

// 4) body.status === 'authenticated': oturum çerezi yazıldı; YENİ CSRF token'ı body.csrf_token'da
let sessionCsrf = body.csrf_token;
```

- Hata akışı: `401 invalid_credentials` (tek tip), `403 captcha_required` (→ `GET /v1/captcha/challenge?action=…`, sonra `captcha` alanıyla tekrar), `429 rate_limited` / `login_temporarily_blocked` (`Retry-After`), `403 login_method_not_allowed` / `org_policy_mfa_required` (`org_id` ile organizasyona giriş).
- Zorunlu adımlar (`required_actions`): şifre değiştirme, şartları kabul, MFA kaydı, e-posta doğrulama — her biri `POST /v1/login/challenge/step`.
- `remember_me: true` kalıcı çerez (varsayılan 14 g boşta / 30 g mutlak); `shared_device: true` her zaman tarayıcı oturumu çerezi + kısa ömür.

## 3. Oturum açıkken

- Durum değiştiren her istek (`POST`, `PUT`, `PATCH`, `DELETE`) `X-CSRF-Token: <session token>` taşımalı; tarayıcı `Origin`'i kendisi ekler. Eksik/yanlışsa `403 csrf_failed`.
- **Token dönünce CSRF token'ı da değişir:** `POST /v1/reauth` (step-up), `POST /v1/session/org` (organizasyon değiştirme) ve giriş tamamlama yanıtındaki `csrf_token`'ı kullanın. Emin değilseniz `GET /v1/csrf` güncel değeri verir. CSRF token'ını yalnızca bellekte tutun (`localStorage` değil).
- `401 step_up_required` → kullanıcıdan şifre/TOTP/passkey alıp `POST /v1/reauth` (`{"method":"password","password":"…"}` vb.), ardından isteği tekrarlayın.
- Çıkış: `POST /v1/logout` (çerez silinir + `Clear-Site-Data: "cookies"`), her yerden: `POST /v1/logout/all`.
- Veri dışa aktarma `POST /v1/me/export` (gövdesiz, CSRF başlığıyla; yanıtı `Blob` olarak indirin — [api-changelog K-79](../api-changelog.md)).

## 4. Diğer giriş yöntemleri

- **Passkey (otomatik doldurma dahil):** `POST /v1/login/passkey/options` (`{"conditional_ui": true}` isteğe bağlı) → `navigator.credentials.get(options)` → `POST /v1/login/passkey` (`ceremony_id`, `credential`). Bağlama token'ı `__Host-authn_passkey` çerezindedir. İkili alanlar base64url'dir; `PublicKeyCredential.parseRequestOptionsFromJSON` / `toJSON()` destekleyen tarayıcılarda doğrudan kullanılabilir.
- **Magic link:** `POST /v1/login/magic-link {email}` her adres için `202`. E-postadaki link `{public_base_url}/magic-link#token=…` açar; sayfanız parçadaki token'ı `POST /v1/login/magic-link/verify {token}` ile gönderir (CSRF başlığıyla). Link isteği yapan tarayıcı `__Host-authn_magic` çerezine sahiptir; başka bir tarayıcıda açılırsa `409 magic_link_confirmation_required` → kullanıcı onaylarsa `confirm_other_device: true` ile tekrar.
- **E-posta kodu:** `POST /v1/login/email-code {email}` → `POST /v1/login/email-code/verify {code}` (challenge çerezine bağlı).
- **Sosyal giriş:** tarayıcıyı `GET /v1/oauth/{provider}/start?return_to=/dashboard&remember_me=false` adresine **gezdirin** (fetch değil). Sunucu sağlayıcıya `303` ile yönlendirir ve `__Host-authn_oauth` (`SameSite=None`) bağlama çerezini yazar; geri dönüşte oturum çerezini yazıp `return_to`'ya `303` yapar. `return_to` göreli güvenli bir yol veya `protect.redirect_allow_list` / `oidc_client.allowed_return_to`'da birebir bulunan mutlak URL olmalıdır. Hata durumunda `oidc_client.error_redirect` ayarlıysa oraya `?error=<kod>` ile döner. MFA gerekiyorsa `return_to`'ya challenge çereziyle dönülür; sayfanız `POST /v1/login/challenge/verify` ile devam eder. Etkin sağlayıcılar: `GET /v1/oauth/providers`.

## 5. BFF (Backend-for-Frontend)

Topoloji C'de ya da tarayıcının kimlik sunucusuyla hiç konuşmaması istendiğinde ön yüzün kendi sunucusu aracı olur. İki desen:

1. **Ters vekil BFF (önerilen):** BFF, `/v1/*` isteklerini olduğu gibi kimlik sunucusuna iletir ve tarayıcıya kendi origin'inden sunar — bu, topoloji A'nın aynısıdır (`public_base_url` = BFF'in origin'i). Çerezler, CSRF ve e-posta linkleri değişmeden çalışır.
2. **Token tutan BFF:** BFF girişi **native** akışla yapar (`X-Authn-Client: native`), access/refresh token'ları sunucu tarafında saklar ve tarayıcıya kendi oturum çerezini verir. Bu durumda:
   - Kimlik sunucusu istemci IP'sini görmez: BFF'in adresini `server.trusted_proxies`'e ekleyip gerçek IP'yi `X-Forwarded-For` ile iletin; aksi hâlde IP oran sınırları ve risk değerlendirmesi tüm kullanıcıları tek istemci sayar.
   - Kullanıcı başına kararlı bir `x-device-id` (16–128 karakter `[A-Za-z0-9_-]`) iletin (risk, bilinen cihaz).
   - Refresh token'ı rotasyonda **atomik** değiştirin: aynı refresh token'ı iki kez kullanmak tüm aileyi (oturumu) iptal eder (`invalid_refresh_token`). Eşzamanlı yenilemeleri BFF içinde tek uçuşa indirin; `session.refresh_reuse_grace` (≤ 10 sn) yalnızca yarışlar için bir emniyet payıdır.
   - Kendi çerezinizi en az `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax` ile ve CSRF korumasıyla verin.

## 6. Kayıt ve e-posta doğrulama

`POST /v1/signup` her adres için aynı yanıtı verir ve **kayıt tutamacını** hem gövdede (`registration`) hem `__Host-authn_registration` (`SameSite=Strict`) çerezinde döner. Doğrulama sayfanız (`/verify-email#token=…`) önce yalnızca `{token}` ile `POST /v1/email/verify` çağırır: aynı tarayıcıda çerez yeter. `403 registration_confirmation_required` dönerse kullanıcıya "kayıtta seçtiğiniz şifre" (`password`) veya "kaydı ben yapmadım, yeni şifre belirle" (`new_password`) seçeneklerini sunun (ADR 0002). Doğrulama oturum açmaz; ardından normal giriş yapılır.
