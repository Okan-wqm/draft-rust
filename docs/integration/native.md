# Native istemciler: ortak kurallar (DOC-05)

iOS, Android, masaüstü ve sunucudan sunucuya (kullanıcı adına) istemciler için ortak sözleşme. Platforma özel adımlar: [`ios.md`](ios.md), [`android.md`](android.md). Kaynaklar: `crates/authn-session/src/login/routes.rs`, `crates/authn-session/src/service/refresh.rs`, `crates/authn-session/src/response.rs`.

## 1. İstek başlıkları

| Başlık | Ne zaman | Değer |
|--------|----------|-------|
| `X-Authn-Client: native` | Her giriş isteği (`/v1/login/*`). Sosyal native giriş (`/v1/oauth/{provider}/native`) ve `POST /v1/token/refresh` zaten native'dir | `native` |
| `X-Authn-Challenge` | Bekleyen girişin sonraki adımları (`/v1/login/challenge/*`) | yanıttaki `challenge_token` |
| `Authorization: Bearer <access_token>` | Oturum isteyen her uç | — |
| `x-device-id` | Her istek (önerilir) | Uygulama kurulumuna özgü kararlı, rastgele 16–128 karakter `[A-Za-z0-9_-]`. Risk değerlendirmesi ve "yeni cihazdan giriş" bildirimi bunu kullanır; geçersiz değer yok sayılır |
| `x-trusted-device` | Giriş istekleri | Daha önce verilen `trusted_device_token` (MFA-09) |
| `Accept-Language` | Her istek | `tr` / `en` hata mesajları |

Native istemciler CSRF başlığı göndermez ve çerez kullanmaz.

## 2. Giriş yanıtları

- `200 {"status":"authenticated", "access_token", "token_type":"Bearer", "expires_in", "refresh_token", "refresh_token_expires_at", "session_id", "user_id", "amr", "auth_time", "expires_at", "active_org_id"}`.
- `200 {"status":"challenge_required", "challenge_id", "challenge_token", "allowed_factors", "required_actions", "expires_at"}` → `POST /v1/login/challenge/verify` / `send-code` / `step` (`X-Authn-Challenge` ile). `enroll_mfa` + `allowed_factors: ["webauthn"]` ise passkey platform API'siyle kaydedilir (K-112): `POST /v1/login/challenge/passkey/register/options` → yanıttaki `options` + `binding_token` → `POST /v1/login/challenge/passkey/register/verify {ceremony_id, binding_token, credential}`. Challenge süresi `session.mfa_challenge_ttl` (5 dk), deneme hakkı `session.challenge_max_attempts` (5); geçersiz/süresi dolmuş/başka cihaz → tek tip `401 challenge_invalid`.
- MFA'yı `trust_device: true` ile geçerseniz başarı yanıtında ek alan `trusted_device_token` gelir; sonraki girişlerde `x-trusted-device` ile gönderin (yalnızca politika kaynaklı MFA'yı atlatır, risk kaynaklı doğrulamayı asla).

## 3. Refresh token rotasyonu

```http
POST /v1/token/refresh
Content-Type: application/json

{"refresh_token": "…"}
```

- Yanıt: `{access_token, token_type: "Bearer", expires_in, refresh_token, refresh_token_expires_at}`. **Gönderdiğiniz refresh token artık geçersizdir**; yenisini atomik olarak saklayın.
- Kullanılmış bir refresh token yeniden gelirse sunucu bunu çalınma sayar: **tüm aile (oturum) iptal edilir**, kullanıcı yeniden giriş yapmalıdır. Bu yüzden:
  - Aynı anda iki yenileme göndermeyin (uygulama içinde tek uçuş / kilit).
  - Ağ hatasında yanıt gelmediyse aynı token'la **hemen** bir kez tekrar deneyebilirsiniz yalnızca `session.refresh_reuse_grace` > 0 ise (varsayılan `0s`: kapalı; açıkken pencere içinde aynı ardıl döner).
- Bu uca `Authorization` başlığı **göndermeyin**: süresi dolmuş bir bearer eklenirse ara katman `401` döner.
- Tüm hatalar tek tip `401 invalid_refresh_token`; IP başına sınır `session.refresh_per_ip` (300 / dk).
- Mutlak ömür (`session.refresh_token.absolute_timeout`, 90 g) rotasyonla uzamaz; boşta ömür 30 g.

## 4. Oturum yönetimi

- Access token ömrü `expires_in` saniye (varsayılan 600). `401` + `WWW-Authenticate: Bearer error="invalid_token"` görürseniz bir kez yenileyip isteği tekrarlayın.
- İptal (şifre sıfırlama, "her yerden çık", admin askıya alma) bir sonraki istekte etkili olur (`session.access_token_session_check`).
- Step-up: `401 step_up_required` → `POST /v1/reauth` (`password` / `totp` / `recovery_code` / `passkey`). Başarılı step-up ve `POST /v1/session/org` **yeni token çifti döner**; eskileri bırakın.
- Çıkış: `POST /v1/logout` (Bearer) oturumu ve refresh token'larını kapatır (`204`).

## 5. Şifresiz ve kod akışları (mobil uyumlu)

| Akış | İstek | Doğrulama |
|------|-------|-----------|
| Magic link | `POST /v1/login/magic-link {email}` → `202 {status:"sent", expires_in, token}` (`token` = bağlama token'ı) | `POST /v1/login/magic-link/verify {token: <linkteki>, binding_token}` |
| E-posta kodu | `POST /v1/login/email-code {email}` → `202 {…, token}` (`token` = challenge token'ı) | `POST /v1/login/email-code/verify {code}` + `X-Authn-Challenge` |
| Şifre sıfırlama | `POST /v1/password/forgot {email}` → `202` (link + 6 haneli kod e-postayla) | `POST /v1/password/reset {email, code, new_password}`; oturum açılmaz, tüm oturumlar kapanır |
| E-posta doğrulama | `POST /v1/signup` → `202 {status, registration}` | `POST /v1/email/verify {code, registration}` |

Her istek ucu hesap var olsun olmasın aynı yanıtı verir; arayüzünüz "bu adres kayıtlı değil" dememelidir.
