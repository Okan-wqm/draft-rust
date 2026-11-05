# iOS / macOS istemcileri (DOC-05)

Bu rehber yalnızca sunucunun **gerçekten desteklediği** mobil özellikleri anlatır: native token akışı, passkey (AASA `webcredentials`), Sign in with Apple (ve diğer sağlayıcılar) ID token girişi, universal link'ler ve Keychain'de token saklama önerileri. Ortak native kurallar (başlıklar, refresh rotasyonu): [`native.md`](native.md). Android: [`android.md`](android.md).

## 1. Sunucu yapılandırması

```toml
[webauthn]
rp_id = "example.com"                                   # passkey'lerin bağlı olduğu domain
allowed_origins = ["https://example.com", "https://auth.example.com"]
apple_app_ids = ["ABCDE12345.com.example.app"]          # TEAMID.bundle.id
# app_link_paths = ["/verify-email", "/reset-password", "/magic-link"]   # universal link istiyorsanız

[oidc_client.apple]
client_id = "com.example.web"          # Services ID (web akışı)
team_id = "ABCDE12345"
key_id = "XYZ987654"
private_key_ciphertext = "…"           # rust-authentication seal-apple-key --pem-file AuthKey.p8
native_client_ids = ["com.example.app"] # uygulamanın bundle id'si (native ID token aud'u)
```

- Sunucu `GET /.well-known/apple-app-site-association`'ı bu ayarlardan üretir: `{"webcredentials":{"apps":["ABCDE12345.com.example.app"]}}`, `app_link_paths` doluysa ayrıca `applinks.details[].components` (`{"/": "<yol>"}`). `Content-Type: application/json`, yönlendirmesiz, `Cache-Control: public, max-age=<webauthn.well_known_max_age>`. `apple_app_ids` boşsa `404`.
- Apple bu dosyayı entitlement'taki domain'den (`webcredentials:example.com`, `applinks:example.com`) indirir. Dosyanın **o domain'de** sunulması gerekir: `rp_id` kimlik sunucusunun host'u değilse (ör. `rp_id = "example.com"`, sunucu `auth.example.com`) `example.com/.well-known/apple-app-site-association`'ı kimlik sunucusuna vekilleyin veya `rp_id`'yi sunucunun host'u yapın.
- iOS passkey'leri istemci verisinde `https://<rp_id>` origin'ini kullanır; bu origin `webauthn.allowed_origins`'ta olmalıdır (üretimde `https://` zorunlu).

## 2. Native token akışı

Her giriş isteğinde `X-Authn-Client: native` gönderin. Yanıt `status: "authenticated"` ise gövdede `access_token`, `token_type: "Bearer"`, `expires_in`, `refresh_token`, `refresh_token_expires_at`; `challenge_required` ise `challenge_token` gelir ve sonraki adımlar `X-Authn-Challenge: <challenge_token>` ile yapılır. CSRF yoktur. Ayrıntı ve refresh kuralları: [`native.md`](native.md).

## 3. Passkey

**Giriş (kullanıcı adsız):**

1. `POST /v1/login/passkey/options` (`X-Authn-Client: native`, gövde `{}`) → `{ceremony_id, options, binding_token, expires_at}`. `options.publicKey.challenge` ve `rpId` buradadır.
2. `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId).createCredentialAssertionRequest(challenge:)` ile doğrulama.
3. `POST /v1/login/passkey` `{ceremony_id, binding_token, credential}` — `credential` WebAuthn JSON biçimindedir (`{"id","rawId","type":"public-key","response":{"authenticatorData","clientDataJSON","signature","userHandle"}}`, ikili alanlar base64url).

**Kayıt (oturum açıkken, step-up gerekir):** `POST /v1/me/passkeys/registration/options` (`Authorization: Bearer …`, isteğe bağlı `{"name": "iPhone"}`) → `createCredentialRegistrationRequest(challenge:name:userID:)` → `POST /v1/me/passkeys/registration/verify` `{ceremony_id, credential}`. İlk passkey de step-up ister (`webauthn.step_up_for_first_passkey = true`, varsayılan): `401 step_up_required` gelirse `POST /v1/reauth`.

**Step-up için passkey:** `POST /v1/reauth/passkey/options` → doğrulama → `POST /v1/reauth` (`method: "passkey"`). Bağlama token'ı native'de yanıt gövdesindedir.

Passkey tek başına MFA sayılır (`amr` içinde `hwk`/`swk`, SES-21).

## 4. Sign in with Apple (ve diğer sağlayıcılar)

1. `POST /v1/oauth/nonce` `{"provider": "apple"}` → `{nonce, expires_at}` (tek kullanımlık, `oidc_client.native_nonce_ttl` = 10 dk).
2. `ASAuthorizationAppleIDRequest.nonce = nonce` — sunucunun verdiği değeri **olduğu gibi** verin (kendiniz hash'lemeyin); sunucu ID token'daki `nonce` claim'ini kendi kaydıyla karşılaştırır.
3. `POST /v1/oauth/apple/native` `{id_token, authorization_code?, given_name?, family_name?, remember_me?, shared_device?}`:
   - `authorization_code` (SDK'nın tek kullanımlık kodu) gönderirseniz sunucu onu Apple'da bundle id ile takas edip refresh token'ı saklar; hesap silinince veya Apple ayrılınca bu token Apple'da iptal edilir (App Store'un hesap silme şartı; `apple.revoke_tokens_on_deletion`, varsayılan açık). Takas başarısız olsa da giriş başarısız olmaz.
   - `given_name` / `family_name` yalnızca Apple'ın ilk girişte verdiği ad içindir (Apple ID token'ı ad taşımaz); imzasız istemci girdisidir.
4. Yanıt diğer native girişlerle aynıdır: token'lar veya challenge (MFA, zorunlu adımlar).

Hatalar: `400 oauth_nonce_invalid`, `400 oauth_native_not_supported` (`native_client_ids` boş), `401 oauth_token_invalid`, `403 oauth_email_not_verified`, `409 oauth_link_required` (adres başka bir hesaba ait: kullanıcı o hesapla girip `POST /v1/me/identities/link/native` ile bağlar).

Aynı akış Google (`/v1/oauth/google/native`), Microsoft ve `native_client_ids` tanımlı genel OIDC sağlayıcıları için de geçerlidir. **GitHub native girişi desteklenmez** (ID token yok).

## 5. Universal link'ler

`webauthn.app_link_paths` doluysa AASA'da `applinks` yayımlanır. E-posta linkleri `{public_base_url}{notify.links.*}#token=…` biçimindedir; token **URL parçasındadır** (sunucuya gitmez). Uygulama linki yakalayınca parçadan token'ı alıp ilgili uca gönderir:

| Link | Uç |
|------|----|
| `/verify-email#token=…` | `POST /v1/email/verify` `{token, registration}` (kayıtta dönen `registration` tutamacını saklayın) — ya da kodla: `{code, registration}` |
| `/reset-password#token=…` | `POST /v1/password/reset` `{token, new_password}` — mobilde 6 haneli kod da gelir: `{email, code, new_password}` |
| `/magic-link#token=…` | `POST /v1/login/magic-link/verify` `{token, binding_token}` (`binding_token` = isteğin yanıtındaki `token`) |

## 6. Token saklama (Keychain)

- `refresh_token`'ı Keychain'de `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (veya daha katı) ile saklayın; iCloud Keychain eşitlemesine açmayın (`kSecAttrSynchronizable = false`). Access token'ı yalnızca bellekte tutun.
- Güvenilir cihaz token'ı (`trusted_device_token`, MFA'yı "bu cihazda tekrar sorma" ile geçtiğinizde challenge yanıtında gelir) ve kalıcı `x-device-id` değeri de Keychain'de saklanmalıdır.
- Çıkışta `POST /v1/logout` (Bearer) çağırın, sonra Keychain girdilerini silin.
