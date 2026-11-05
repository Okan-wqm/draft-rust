# Android istemcileri (DOC-05)

Sunucunun Android için sağladıkları: native token akışı, Credential Manager ile passkey (Digital Asset Links `get_login_creds` ve `android:apk-key-hash:` origin'i), Google / Microsoft / genel OIDC ID token girişi, App Links. Ortak native kurallar: [`native.md`](native.md).

## 1. Sunucu yapılandırması

```toml
[webauthn]
rp_id = "example.com"
allowed_origins = [
  "https://example.com",
  # Android passkey istemci verisindeki origin: imza sertifikasının
  # SHA-256'sının dolgusuz base64url'i (43 karakter)
  "android:apk-key-hash:Fk3fH0…",
]

[[webauthn.android_apps]]
package_name = "com.example.app"
sha256_cert_fingerprints = ["AB:CD:…:EF"]   # 32 büyük harf hex bayt, ':' ile

# app_link_paths = ["/verify-email", "/reset-password", "/magic-link"]

[oidc_client.google]
client_id = "…apps.googleusercontent.com"   # web istemcisi
client_secret = "…"
native_client_ids = ["…-android.apps.googleusercontent.com"]
```

- `GET /.well-known/assetlinks.json` bu ayarlardan üretilir: her uygulama için `relation: ["delegate_permission/common.get_login_creds"]` (passkey / Credential Manager), `app_link_paths` doluysa ek olarak `delegate_permission/common.handle_all_urls`; `target` = `{namespace: "android_app", package_name, sha256_cert_fingerprints}`. `android_apps` boşsa `404`.
- Android dosyayı `rp_id` domain'inden doğrular; `rp_id` sunucunun host'u değilse dosyayı o domain'de sunun (vekil).
- Aynı sertifika iki biçimde girilir: `sha256_cert_fingerprints` iki nokta üst üste ayrılmış hex, `android:apk-key-hash:` ise aynı 32 baytın dolgusuz base64url'i. Yanlış biçim yapılandırma doğrulamasında reddedilir.
- **Google ID token `aud`'u:** Android'de `GoogleIdOption.setServerClientId(<web client id>)` kullanırsanız token'ın `aud`'u web istemci kimliğidir. Bu durumda o kimliği `native_client_ids`'e **bilinçli olarak** ekleyin (web akışının nonce'ları native akışta geçmediği için güvenlidir; `crates/authn-oidc-client/README.md`).

## 2. Passkey (Credential Manager)

**Giriş:**

1. `POST /v1/login/passkey/options` (`X-Authn-Client: native`, gövde `{}`) → `{ceremony_id, options, binding_token, expires_at}`.
2. `GetPublicKeyCredentialOption(requestJson = options.publicKey JSON)` ile `CredentialManager.getCredential(...)`.
3. Dönen `PublicKeyCredential.authenticationResponseJson`'u `credential` olarak gönderin: `POST /v1/login/passkey` `{ceremony_id, binding_token, credential}`.

**Kayıt:** `POST /v1/me/passkeys/registration/options` (Bearer, step-up gerekebilir) → `CreatePublicKeyCredentialRequest(requestJson = options.publicKey JSON)` → `POST /v1/me/passkeys/registration/verify` `{ceremony_id, credential: <registrationResponseJson>}`.

İstemci verisindeki origin `android:apk-key-hash:…` olacağından bu değer `allowed_origins`'ta yoksa doğrulama `passkey_authentication_failed` / `passkey_registration_failed` ile başarısız olur.

## 3. Google ile giriş (ve diğer sağlayıcılar)

1. `POST /v1/oauth/nonce {"provider": "google"}` → `{nonce}`.
2. Credential Manager `GetGoogleIdOption.Builder().setNonce(nonce)` (değeri olduğu gibi verin).
3. `POST /v1/oauth/google/native {id_token, remember_me?, shared_device?}` → token'lar veya challenge.

Hatalar ve hesap eşleştirme kuralları iOS ile aynıdır ([ios.md §4](ios.md#4-sign-in-with-apple-ve-diğer-sağlayıcılar)): doğrulanmamış e-posta `403 oauth_email_not_verified`, adres başka hesaba aitse `409 oauth_link_required`. GitHub native girişi desteklenmez. Sign in with Apple Android'de native SDK olmadan çalışmaz; tarayıcı akışını (`GET /v1/oauth/apple/start`) bir Custom Tab'da kullanabilirsiniz, ama o zaman oturum **çerez** olarak tarayıcıda kalır, uygulamaya token dönmez — bu sürümde web akışını native token'a çeviren bir uç yoktur.

## 4. App Links

`webauthn.app_link_paths` doluysa `handle_all_urls` yayımlanır ve e-posta linkleri (`{public_base_url}/reset-password#token=…` vb.) uygulamada açılabilir. Token URL parçasındadır; uygulama onu ilgili `POST` ucuna gönderir (tablo: [ios.md §5](ios.md#5-universal-linkler)).

## 5. Token saklama (Keystore)

- `refresh_token`'ı Android Keystore'da üretilmiş, dışa aktarılamayan bir AES-GCM anahtarıyla şifreleyip (ör. Jetpack Security / Tink) uygulamanın özel depolamasında saklayın; yedeklemeden hariç tutun (`android:allowBackup`/`dataExtractionRules`). Access token'ı yalnızca bellekte tutun.
- `x-device-id` ve `trusted_device_token` için de aynısı.
- Çıkışta `POST /v1/logout` (Bearer), sonra yerel kayıtları silin.
