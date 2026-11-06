# OAuth 2.1 / OpenID Connect sağlayıcısı: bağlı taraf (RP) entegrasyonu (K-80)

`rust-authentication` kayıtlı uygulamalara **OpenID Provider** ve OAuth 2.1 yetkilendirme sunucusu olarak hizmet verebilir: kendi ürünlerinizin web uygulamaları, mobil uygulamalar ve üçüncü taraf uygulamalar "rust-authentication ile giriş yap" akışını standart OIDC kütüphaneleriyle kullanır. Bu rehber hem **işletmeciyi** (sağlayıcıyı açan, istemcileri kaydeden, giriş / onay sayfasını sunan) hem **RP geliştiricisini** anlatır. Modül ayrıntıları: [`crates/authn-oidc-provider/README.md`](../../crates/authn-oidc-provider/README.md).

> Birinci taraf web ve mobil uygulamalarınız için çerez oturumu ([web.md](web.md)) ve native token akışı ([native.md](native.md)) daha basittir ve sağlayıcıya ihtiyaç duymaz. Sağlayıcıyı, ayrı bir alan adındaki uygulamalar, üçüncü taraflar veya standart OIDC kütüphanesi kullanmak isteyen ekipler için açın.

## 1. Desteklenenler

| Özellik | Değer |
|---------|-------|
| Akış | Authorization Code + PKCE (`S256` zorunlu); implicit, ROPC, `plain` **yok** |
| Grant türleri | `authorization_code`, `refresh_token` (rotasyonlu) |
| İstemci kimlik doğrulaması | `client_secret_basic`, `client_secret_post`, `none` (açık istemci) |
| Kapsamlar | `openid`, `profile`, `email` + `oidc_provider.custom_scopes` |
| İmza | `EdDSA` (Ed25519) — kütüphanenizin desteklediğinden emin olun (ES256 kalan iş) |
| Token'lar | access token: JWT, RFC 9068 (`typ: at+jwt`); ID token: OIDC Core; refresh token: opak |
| Keşif | `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` (RFC 8414) |
| Diğer | RFC 9207 `iss` yanıt parametresi, RFC 8707 resource indicators, RFC 7009 iptal, RFC 7662 introspection, UserInfo, `prompt` (`none` / `login` / `consent`), `max_age`, `acr_values` |

## 2. İşletmeci: açma ve istemci kaydı

1. Yapılandırma (`[oidc_provider]`, [configuration.md §12a](../operations/configuration.md)):

   ```toml
   [oidc_provider]
   enabled = true
   interaction_url = "https://app.example.com/oauth/consent"
   ```

   Varsayılan **kapalıdır**: kapalıyken hiçbir sağlayıcı yolu yoktur (`404`). Ters vekil `/v1/oauth2/*` ve `/.well-known/*` yollarını kimlik sunucusuna iletmelidir.

2. İstemci kaydı personel API'siyle (`platform_admin` rolü; okuma `security` rolüne de açık, K-93; passkey MFA ve yakın tarihli kimlik doğrulama gerekir):

   ```http
   POST /v1/admin/oauth2/clients
   {
     "name": "Mağaza",
     "client_type": "confidential",          // sunucu tarafı uygulama; tarayıcı/mobil için "public"
     "application_type": "web",              // "native": RFC 8252 kuralları
     "redirect_uris": ["https://shop.example.com/auth/callback"],
     "allowed_scopes": ["openid", "profile", "email"],
     "allowed_resources": ["https://api.example.com"],   // isteğe bağlı, RFC 8707
     "skip_consent": false                   // yalnızca kendi uygulamalarınız için true
   }
   ```

   Yanıttaki `client_secret` **bir kez** gösterilir (sunucu yalnızca SHA-256'sını saklar); kaybolursa `POST /v1/admin/oauth2/clients/{client_id}/secret` ile döndürün (eski sır hemen geçersizleşir). `PATCH` ile `disabled: true` veya izinleri daraltmak istemcinin tüm grant'lerini iptal eder.

   `redirect_uri` kuralları: kayıt **kanonik** biçimde olmalı (`https://shop.example.com/cb` — `https://shop.example.com` değil, sondaki `/` dahil); joker, parça (`#`), kullanıcı bilgisi yasak; `web` istemci yalnızca `https`; `native` istemci ayrıca `http://127.0.0.1/…` / `http://[::1]/…` (port serbest, RFC 8252 §7.3; `localhost` kabul edilmez) ve ters-domain özel şema (`com.example.app:/oauth`). Eşleşme birebirdir.

   **Mobil / masaüstü açık istemciler (RFC 8252 §8.6):** `redirect_uri` loopback veya özel şema ise istemcinin kimliği kanıtlanamaz (aynı portu dinleyen ya da aynı şemayı sahiplenen başka bir uygulama kodu alabilir). Bu yüzden böyle bir istekte onay ekranı **her seferinde** gösterilir — önceki onay, `skip_consent: true` ve `prompt=none` (→ `consent_required`) bunu atlatmaz. Sessiz SSO istiyorsanız doğrulanmış uygulama bağlantısı (iOS Universal Links / Android App Links) ile `https` `redirect_uri` kullanın.

## 3. İşletmeci: giriş / onay sayfası (headless)

Sağlayıcı kendi ekranını sunmaz. Kullanıcının oturumu yoksa, yeniden kimlik doğrulaması veya onayı gerekiyorsa tarayıcıyı `interaction_url?interaction_id=<uuid>` adresine yönlendirir ve `__Host-authn_oidc_browser` bağlama çerezini yazar. Sayfanız (kimlik sunucusuyla **aynı site**, [web.md §1](web.md) topoloji A veya B):

```js
const id = new URLSearchParams(location.search).get('interaction_id');
let view = await (await api(`/v1/oauth2/interactions/${id}`)).json();
// view: { client: {name, first_party}, scopes, resources, authenticated,
//         login_required, login_reasons, consent_required, acr_values, expires_at }

if (!view.authenticated) {
  // Mevcut giriş API'leriyle giriş (şifre, passkey, magic link, sosyal giriş …), web.md §2.
  await login();
} else if (view.login_required) {
  // prompt=login, max_age veya acr_values: step-up (POST /v1/reauth; acr aal2 için TOTP/passkey).
  await reauth();
}
view = await (await api(`/v1/oauth2/interactions/${id}`)).json();
if (view.consent_required && !(await askUser(view.client.name, view.scopes))) {
  const { redirect_to } = await (await api(`/v1/oauth2/interactions/${id}/deny`, { method: 'POST' })).json();
  location.assign(redirect_to);        // istemci access_denied alır
} else {
  const res = await api(`/v1/oauth2/interactions/${id}/accept`, {
    method: 'POST', headers: { 'X-CSRF-Token': sessionCsrf },
  });
  // 401 step_up_required → details.login_reasons; yeniden kimlik doğrulayıp tekrar deneyin.
  location.assign((await res.json()).redirect_to);   // istemciye ?code=…&state=…&iss=…
}
```

- İstek tek kullanımlıktır, varsayılan 10 dk yaşar ve yalnızca onu başlatan tarayıcıda (bağlama çerezi) okunabilir; aksi hâlde `400 oauth_interaction_invalid` — kullanıcıyı uygulamaya geri gönderin.
- Onay ekranında **istemci adını ve istenen kapsamları** açıkça gösterin; ekranınızı çerçeveye (iframe) alınamaz yapın (`Content-Security-Policy: frame-ancestors 'none'` / `X-Frame-Options: DENY`) — onay tıklaması clickjacking'e karşı sizin sayfanızda korunur.
- Impersonation oturumu bir istemciyi kullanıcı adına yetkilendiremez.
- Kullanıcı verdiği erişimleri `GET /v1/me/oauth2/consents` ile görür, `DELETE /v1/me/oauth2/consents/{client_id}` ile geri alır (o uygulamanın tüm token'ları iptal olur).

## 4. RP geliştiricisi: akış

1. Keşif: `GET https://auth.example.com/.well-known/openid-configuration` (`issuer` = `https://auth.example.com`).
2. Her girişte yeni `state`, `nonce` ve PKCE doğrulayıcısı (43–128 karakter) üretin; `code_challenge = BASE64URL(SHA256(verifier))`.
3. Tarayıcıyı gönderin:

   ```
   GET /v1/oauth2/authorize?response_type=code&client_id=oc_…&redirect_uri=https%3A%2F%2Fshop.example.com%2Fauth%2Fcallback
       &scope=openid%20email&state=…&nonce=…&code_challenge=…&code_challenge_method=S256
   ```

4. Geri dönüşte **`iss`'in beklenen issuer olduğunu** (RFC 9207, mix-up saldırısı) ve `state`'i doğrulayın. Hata varsa `error` (`access_denied`, `login_required`, `consent_required`, `interaction_required`, `invalid_scope`, `invalid_target`, `invalid_request` …).
5. Kodu 60 sn içinde takas edin:

   ```http
   POST /v1/oauth2/token
   Authorization: Basic base64(urlencode(client_id) ":" urlencode(client_secret))
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code&code=…&redirect_uri=https%3A%2F%2Fshop.example.com%2Fauth%2Fcallback&code_verifier=…
   ```

   Açık istemci (SPA / mobil) `Authorization` yerine gövdede yalnızca `client_id` gönderir. Yanıt: `access_token`, `token_type: "Bearer"`, `expires_in`, `refresh_token` (istemci `refresh_token` grant'ine izinliyse), `id_token` (`openid` ile), `scope`.

6. **ID token'ı doğrulayın:** imza (JWKS `jwks_uri`, `alg` `EdDSA`, başlıktaki `alg`'e güvenmeyin), `iss`, `aud` = client id, `azp`, `exp`, `iat`, `nonce` = gönderdiğiniz, `at_hash` = `BASE64URL(SHA-512(access_token)[0..32])` (EdDSA/Ed25519 için). `auth_time`, `amr`, `acr` (`urn:rust-authentication:acr:aal1` / `aal2` / `phr`) ve `sid` de vardır. ID token'da e-posta / ad **yoktur**: `userinfo`'yu çağırın.
7. `GET /v1/oauth2/userinfo` (`Authorization: Bearer <access_token>`): `sub`; `profile` → `name`, `locale`, `zoneinfo`; `email` → `email`, `email_verified`.
8. Refresh: `grant_type=refresh_token&refresh_token=…` (isteğe bağlı daha dar `scope`). **Her yanıtta yeni refresh token gelir; eskisini hemen bırakın.** Döndürülmüş bir token'ı tekrar göndermek (eşzamanlı iki yenileme dahil) grant'in tamamını iptal eder — yenilemeleri tek uçuşa indirin.
9. Çıkışta `POST /v1/oauth2/revoke` (`token=<refresh_token>`): grant'in tamamı iptal olur.

**Grant ömrü:** grant, kullanıcının yetkilendirme sırasındaki tarayıcı oturumuna bağlıdır. Kullanıcı çıkış yaparsa, "her yerden çıkış" yaparsa, şifresini sıfırlarsa, hesap askıya alınır / silinirse veya oturum süresi dolarsa refresh `invalid_grant` döner: kullanıcıyı yeniden `/authorize`'a gönderin (oturum varsa ve onay verilmişse ekransız geri döner; `prompt=none` ile sessiz deneme yapılabilir). Oturumdan bağımsız uzun ömürlü erişim (`offline_access`) henüz yoktur.

## 5. Kaynak sunucusu (API) tarafı

- İstemci `allowed_resources`'ta kayıtlı bir API için `resource=https://api.example.com` parametresiyle (RFC 8707) token ister; access token'ın `aud`'u bu değer olur. `resource` yoksa `aud` istemcinin client id'sidir (+ `openid` ile `userinfo` adresi).
- **Yerel doğrulama** ([resource-server.md](resource-server.md) ile aynı JWKS): `typ` `at+jwt`, `alg` `EdDSA`, `iss`, `aud` **kendi kaynak adresiniz**, `exp`. `client_id` ve `scope` claim'leriyle yetkilendirin. Sağlayıcı access token'ı **native token değildir**: `sid` taşımaz ve native `aud`'u (`session.audiences`) asla içermez; birini diğerinin yerine kabul etmeyin.
- Yerel doğrulama iptali en geç `access_token_ttl` (varsayılan 5 dk) sonra görür. Anında iptal gerekiyorsa API'nizi gizli istemci olarak kaydedip **introspection** kullanın: `POST /v1/oauth2/introspect` (`token=…`, istemci kimlik doğrulamasıyla). Token yalnızca kendi istemcisine veya `aud`'unda client id'si geçen istemciye `active: true` görünür.

## 6. Güvenlik kontrol listesi (RP)

- PKCE her istekte, `state` ve `nonce` her istekte yeni ve tek kullanımlık.
- Yetkilendirme yanıtındaki `iss`'i, ID token'daki `iss` / `aud` / `nonce` / `at_hash`'i doğrulayın.
- Sırrı yalnızca sunucuda tutun; tarayıcı / mobil istemci **açık istemci** olarak kaydedilmelidir.
- Tarayıcıdaki SPA token uç noktasını çapraz origin çağıracaksa origin'i `protect.cors.allowed_origins`'a ekleyin ya da BFF kullanın ([web.md §5](web.md)); refresh token'ı tarayıcı deposunda tutmayın.
- Mobil uygulama sistem tarayıcısı (ASWebAuthenticationSession / Custom Tabs) kullanmalı, gömülü WebView değil (RFC 8252).
