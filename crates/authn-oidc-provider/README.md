# authn-oidc-provider

OAuth 2.1 / OpenID Connect **sağlayıcısı** çekirdeği (Faz 2, K-80): sunucu, kayıtlı üçüncü taraf (ve birinci taraf) uygulamalar için yetkilendirme sunucusu ve OpenID Provider olur. Bağlı olan taraf (relying party) entegrasyonu: [`docs/integration/oidc-provider.md`](../../docs/integration/oidc-provider.md).

> **Durum (2026-11-05, wave 11A):** yazıldı ve test edildi (uzman yazar aşaması). Bağımsız denetçi aşaması (HANDOFF §6) henüz yapılmadı; varsayılan **kapalı** (`oidc_provider.enabled = false`).

## Sahip olunan gereksinimler

| Kimlik | Özet | Başlıca testler |
|--------|------|-----------------|
| OIDP-01 | İstemci kaydı (gizli / açık, `web` / `native`, sır SHA-256, personel rolleri) | `oidp_01_client_registry_is_staff_only_and_validated`, `oidp_01_client_registry_follows_staff_roles` (server) |
| OIDP-02 | `redirect_uri` kuralları: kanonik kayıt, birebir eşleşme, RFC 8252 loopback / özel şema, doğrulanamayan istek yönlendirilmez | `oidp_02_registration_rules`, `oidp_02_exact_match_rejects_variants`, `oidp_02_loopback_ignores_only_the_port`, `oidp_02_unregistered_redirects_are_never_followed`, `oidp_02_native_public_client_with_loopback_port_and_no_secret` |
| OIDP-03 | Yalnızca `code` + PKCE `S256`, `state` / `nonce`, RFC 9207 `iss`, tekrarlanan parametre reddi | `oidp_03_*` (birim + akış) |
| OIDP-04 | Headless etkileşim (tarayıcıya bağlı, tek kullanımlık, kısa ömürlü), `prompt`, `max_age`, `acr_values` | `oidp_04_*` |
| OIDP-05 | Onay kayıtları, birinci taraf atlaması, kullanıcının onay listesi / geri alması, dışa aktarma | `oidp_05_*` |
| OIDP-06 | `authorization_code`: tek kullanımlık kod, tekrar → grant iptali, istemci / `redirect_uri` / PKCE bağı, istemci kimlik doğrulaması | `oidp_06_*` |
| OIDP-07 | Refresh rotasyonu, tekrar kullanım tespiti, kapsam daraltma | `oidp_07_refresh_rotation_and_replay_detection` |
| OIDP-08 | RFC 9068 access token, OIDC ID token, RFC 8707 `aud`, native token'larla karışmama | `oidp_06_web_client_code_flow_with_pkce_and_independent_id_token_check`, `oidp_08_*`, `oidp_08_provider_and_native_tokens_are_never_interchangeable` (server) |
| OIDP-09 | Keşif (OIDC Discovery + RFC 8414), ortak JWKS | `oidp_09_discovery_documents`, `oidp_09_discovery_and_shared_jwks_through_the_stack` (server) |
| OIDP-10 | UserInfo (kapsama göre) | `oidp_06_web_client_code_flow_with_pkce_and_independent_id_token_check` |
| OIDP-11 | RFC 7009 iptal, RFC 7662 introspection | `oidp_11_revocation_and_introspection` |
| OIDP-12 | Oturum / hesap yaşam döngüsüne bağlı iptal, rate limit, token'sız audit | `oidp_12_*` (crate + server) |
| OIDP-13 | `[oidc_provider]` yapılandırması, varsayılan kapalı, üretim kuralları, temizlik işi | `oidp_13_*` (authn-core, crate, server) |

## Mimari

- **Katman:** Dalga B kurallarıyla (core, crypto, store ve Dalga A'ya bağımlı olabilir; authn-session ve authn-admin'e bağımlı **değildir**). Onlardan gerekenler kanca trait'leriyle gelir (`hooks.rs`), uygulamaları authn-server'dadır:
  - `SessionLiveness` → `authn_session::is_session_active_in` (aynı bağlantıdan; kullanıcının giriş yapabilir olmasını da denetler).
  - `ClientAdminAuthorizer` → `AdminService::authorize_permission(…, AdminPermission::OAuthClientsRead | OAuthClientsManage)` (K-93 personel rolleri + ADM-01 guard'ı). Varsayılanlar (`NoLiveSessions`, `DenyClientAdmin`) her şeyi reddeder.
- **Tablolar** (migration `3000`, aralık 3000–3099): `oidc_clients`, `oidc_interactions`, `oidc_grants`, `oidc_authorization_codes`, `oidc_refresh_tokens`, `oidc_access_tokens`, `oidc_consents`. Kullanıcıya bağlı her satır hesapla kaskad silinir; her yabancı anahtarın indeksi var (K-70).
- **İmza:** sunucunun anahtar kümesi (CRY-09/10, `signing_keys`) ve sabit algoritmalı EdDSA JWS'i (`authn_crypto::jwt`); sağlayıcı anahtar üretmez. Süreç başına anahtar anlık görüntüsü en çok 5 sn eski (`keys.rs`): acil iptal (ADM-06) birkaç saniyede bu süreçte de etkili olur. İşlem içindeki imza, çağıranın bağlantısıyla yeniden yükler (K-58 havuz kalıbı).
- **Grant = oturum bağı (OIDP-12):** her grant yetkilendirildiği tarayıcı oturumuna bağlıdır. Kod takası, refresh, introspection ve `userinfo` her seferinde grant'in iptal edilmemiş / süresi dolmamış olduğunu **ve** oturumun canlı olduğunu denetler. Böylece çıkış, her yerden çıkış, şifre sıfırlama, askıya alma, silme, admin / acil oturum iptali başka hiçbir modülde değişiklik gerektirmeden sağlayıcı grant'lerini de bitirir. Bedeli: refresh token'ı tarayıcı oturumundan uzun yaşayamaz (Keycloak'un "online" oturum modeli). Oturumdan bağımsız uzun ömürlü erişim (`offline_access`) kalan iş (aşağıda).
- **Router'lar:** `router` (authorize, interaction, onaylar, istemci kaydı) oturum + CSRF katmanının **arkasında**; `protocol_router` (token, iptal, introspection, userinfo, keşif) **dışında**: istemciyi / sağlayıcı token'ını kendileri doğrular, çerez okumaz; native bearer ara katmanı sağlayıcı token'ını native token sanıp reddederdi.

## Endpoint'ler

| Yöntem | Yol | Kimlik | Gereksinim |
|--------|-----|--------|------------|
| `GET` | `/v1/oauth2/authorize` | isteğe bağlı tarayıcı oturumu | OIDP-02 … OIDP-04 |
| `GET` | `/v1/oauth2/interactions/{interaction_id}` | bağlama çerezi (+ oturum) | OIDP-04 |
| `POST` | `/v1/oauth2/interactions/{interaction_id}/accept` | oturum + CSRF + bağlama çerezi | OIDP-04, OIDP-05 |
| `POST` | `/v1/oauth2/interactions/{interaction_id}/deny` | bağlama çerezi | OIDP-04 |
| `GET` | `/v1/me/oauth2/consents` | oturum | OIDP-05 |
| `DELETE` | `/v1/me/oauth2/consents/{client_id}` | oturum + CSRF | OIDP-05 |
| `GET`, `POST` | `/v1/admin/oauth2/clients` | personel (`oauth_clients:read` / `:manage`) | OIDP-01 |
| `GET`, `PATCH`, `DELETE` | `/v1/admin/oauth2/clients/{client_id}` | personel | OIDP-01 |
| `POST` | `/v1/admin/oauth2/clients/{client_id}/secret` | personel (`:manage`) | OIDP-01 |
| `POST` | `/v1/oauth2/token` | istemci (`client_secret_basic` / `client_secret_post` / `none`) | OIDP-06 … OIDP-08 |
| `POST` | `/v1/oauth2/revoke` | istemci | OIDP-11 |
| `POST` | `/v1/oauth2/introspect` | gizli istemci | OIDP-11 |
| `GET`, `POST` | `/v1/oauth2/userinfo` | sağlayıcı access token'ı | OIDP-10 |
| `GET` | `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | — | OIDP-09 |

JWKS: authn-session'ın `/.well-known/jwks.json`'u (SES-09). Protokol uçlarının hataları RFC 6749 §5.2 / RFC 6750 biçimindedir (`{"error": "invalid_grant", "error_description": …}`), diğerleri proje zarfı.

## Akış (özet)

1. RP tarayıcıyı `GET /v1/oauth2/authorize?response_type=code&client_id&redirect_uri&scope&state&nonce&code_challenge&code_challenge_method=S256` adresine gönderir.
2. İstemci veya `redirect_uri` doğrulanamazsa `400 invalid_authorization_request` (yönlendirme yok). Diğer hatalar `redirect_uri?error=…&state=…&iss=…`.
3. Tarayıcı oturumu varsa, `prompt` / `max_age` / `acr_values` karşılanıyorsa ve onay daha önce verilmişse (veya istemci birinci tarafsa) doğrudan `redirect_uri?code&state&iss` (SSO). Kayıtlı onay yalnızca istenen **kapsamların ve kaynakların** (RFC 8707 `resource`, token `aud`'u) tamamını kapsıyorsa sayılır. **İstisna (RFC 8252 §8.6):** `redirect_uri`'si `https` olmayan (loopback, özel şema) **açık** istemci kullanıcısız hiçbir zaman yetkilendirilmez — kayıtlı onay, `skip_consent` ve `prompt=none` fark etmez, onay ekranı her seferinde gösterilir; aynı portu dinleyen veya aynı şemayı sahiplenen başka bir uygulama kendi PKCE çiftiyle kodu sessizce alıp kullanabilirdi. `prompt=none` hiçbir zaman etkileşime gitmez: `login_required`, `interaction_required` veya `consent_required`.
4. Aksi hâlde bekleyen istek saklanır, `__Host-authn_oidc_browser` bağlama çerezi yazılır ve tarayıcı `interaction_url?interaction_id=<id>` adresine gider. Sayfa `GET /v1/oauth2/interactions/{id}` ile isteği okur, gerekirse mevcut giriş API'leriyle girişi / step-up'ı (`POST /v1/reauth`) yaptırır, onay ekranını gösterir ve `POST …/accept` (veya `…/deny`) çağırır; yanıttaki `redirect_to`'ya gider.
5. RP kodu `POST /v1/oauth2/token` ile `code_verifier` göndererek takas eder.

`acr` değerleri (`claims.rs`): `urn:rust-authentication:acr:aal1` (tek faktör), `…:aal2` (`amr` `mfa` içerir), `…:phr` (kullanıcı doğrulamalı passkey). Üstteki alttakini karşılar.

## Konfigürasyon

`[oidc_provider]` (`crates/authn-core/src/config/oidc_provider.rs`), anahtarlar ve sınırlar: [`docs/operations/configuration.md` §12a](../../docs/operations/configuration.md). Derleme bayrağı: authn-server `oidc-provider` (varsayılan derlenir; uçlar yalnızca `enabled = true` iken bağlanır).

## Hata kodları

`codes::oidc_provider`: `invalid_authorization_request` (400, yönlendirilmeyen yetkilendirme isteği), `oauth_interaction_invalid` (400, bilinmeyen / süresi dolmuş / tamamlanmış / başka tarayıcının isteği), `invalid_client_metadata` (422, `details.field`). Ayrıca ortak `step_up_required` (`details.login_reasons`), `unauthenticated`, `forbidden`, `not_found`, `rate_limited`.

## Güvenlik notları

- **PKCE zorunlu ve yalnızca `S256`**; `plain`, implicit, ROPC, `request` / `request_uri` yok. Yanlış doğrulayıcı kodu "yakar" (enjeksiyon denemesi). Kod başka istemciye sunulursa dokunulmadan reddedilir (meşru istemci hâlâ kullanabilir).
- **Kod / refresh tekrarı:** tekrar kullanılan kod veya döndürülmüş refresh token grant'i iptal eder; o grant'in access token'ları introspection / `userinfo`'da hemen pasifleşir (`jti` kaydı). Audit: `oauth.code_replayed`, `oauth.refresh_token_replayed`.
- **Mix-up (RFC 9207):** her yetkilendirme yanıtında `iss`; keşifte `authorization_response_iss_parameter_supported: true`.
- **Open redirect:** yalnızca doğrulanmış `redirect_uri`'ye yönlendirilir; kayıt kanonik formu zorunlu kılar, eşleşme birebirdir (alt yol, büyük/küçük harf, port, sorgu varyantları reddedilir; tek istisna loopback portu).
- **Token türü ayrımı (OIDP-08):** sağlayıcı access token'ında `sid` yoktur ve `aud`'u native `session.audiences`'ı hiçbir zaman içermez (kayıt ve imza anında denetlenir), bu yüzden native bearer doğrulayıcısı onu reddeder; sağlayıcı ise yalnızca kendi `jti` kaydı olan token'ı kabul eder, native token reddedilir. ID token (`typ: JWT`) hiçbir yerde access token değildir.
- **CSRF / clickjacking:** onay (`accept`) oturum + CSRF katmanının arkasındadır; bağlama çerezi `SameSite=Lax`, tarayıcılar arası POST'ta gitmez. Güvenlik başlıkları (PRT-07, `X-Frame-Options` / CSP) tüm yanıtlarda; onay ekranının kendisi işletmecinin önyüzündedir ve kendi çerçeve korumasını taşımalıdır (entegrasyon rehberi).
- **Sırlar:** istemci sırrı, kod ve refresh token 256 bit CSPRNG (`OpaqueToken`), yalnızca SHA-256 saklanır, sabit zamanlı karşılaştırılır; `Debug` çıktılarında yoktur; audit olaylarında token / sır yoktur (test ile).
- **Impersonation:** impersonation oturumu bir istemciyi kullanıcı adına yetkilendiremez (oturum yok sayılır).
- **Rate limit:** `authorize` IP başına, token / iptal / introspection IP başına (kimlik doğrulamadan önce) ve doğrulanmış istemci başına, `userinfo` IP başına.

### Kabul edilen riskler / sınırlamalar

- Yalnızca **EdDSA** (Ed25519) imza: birçok RP kütüphanesi EdDSA'yı desteklemez. ES256 (`p256 0.14`) için authn-crypto ve `signing_keys.alg` kolonu gerekir (kalan iş).
- Kaynak sunucuları JWT'yi yerelde doğrularsa iptali en geç `access_token_ttl` (varsayılan 5 dk) sonra görür; anında iptal için introspection kullanılmalı.
- Grant tarayıcı oturumuna bağlı olduğundan RP'nin refresh token'ı oturumun boşta / mutlak süresini aşamaz (`offline_access` kalan iş).
- Tarayıcıdaki SPA'lar token uç noktasını CORS ile çağırır: `protect.cors.allowed_origins`'a eklenmeli (istemci başına CORS listesi kalan iş) veya BFF kullanılmalı.
- `at_hash` EdDSA/Ed25519 için SHA-512'nin sol yarısıdır (OIDC Core §3.1.3.6'nın `alg`'e göre hash kuralı; Ed25519 SHA-512 üzerine kuruludur, sertifikalı diğer sağlayıcılarla aynı). OIDC Core 1.0 metni `EdDSA` için hash'i adıyla belirtmez; `panva/oidc-provider` / `oidc-token-hash` ve Nimbus (Ed25519 → SHA-512) bu seçimi kullanır, `authlib` gibi `alg[2:]`'den hash türeten kütüphaneler `EdDSA` için `at_hash`'i doğrulamadan geçer. Bu sunucuda ID token yalnızca token uç noktasından (TLS üzerinden, doğrudan) döndüğü için `at_hash` savunma katmanıdır, tek güvence değildir.
- `client_secret_basic` kimlik bilgileri RFC 6749 §2.3.1 / Ek B'ye göre çözülür: `+` boşluk, `%XX` bayt; ham `&` / `=` veridir (alan ayırıcı sayılmaz), bozuk kaçış `invalid_client`.

## Server'ın bağlaması gerekenler (yapıldı, wave 11A)

- `Services.oidc_provider` (`services.rs` adım 9), `FromRef` (`state.rs`), `app.rs::provider_routes` (slot 8 içinde) ve `provider_protocol_routes` (dışında) — yalnızca `oidc_provider.enabled`.
- `hooks.rs`: `ServerSessionLiveness` (`SessionLiveness`), `ServerClientAdmin` (`ClientAdminAuthorizer`).
- `jobs.rs`: bakım turunda `purge_expired` (sağlayıcı kapalıyken de çalışır).
- `ProviderDataExporter` (`oauth_provider` bölümü) `AccountServiceDeps.exporters`'ta.
- OpenAPI: `OidcProviderApi`, güvenlik şemaları `oauth2_client` ve `oauth2_access_token`.

## Kalan işler (K-80'in bu dalgada yapılmayan kısımları)

1. Bağımsız güvenlik denetimi (HANDOFF §6) ve OpenID Foundation uyumluluk test paketi (Basic OP / Config OP) koşusu.
2. **ES256** imza (authn-crypto `p256 0.14` imzalayıcı, `signing_keys.alg` kolonu, istemci başına sabit algoritma); RS256 kararı roadmap §11.
3. **Organizasyon tarafından yönetilen istemciler** (org API'si, `oidc_clients.org_id`, ARC-10 kiracı izolasyon testleri).
4. `offline_access` (oturumdan bağımsız grant; authn-session'da kullanıcı bazlı iptal kancası gerektirir — `SessionRevoker` sarmalayıcısı veya olay).
5. Sır rotasyonunda eski sırrın geçiş süresi; `private_key_jwt` (K-84); istemci başına CORS origin listesi; `claims` parametresi; `ui_locales` / `login_hint` / `id_token_hint` iletimi; pairwise `sub`.
6. Fuzz hedefi `oidc_authorize_request` — `fuzz/fuzz_targets/oidc_authorize_request.rs` (ayrıştırıcı `request::parse_query` + `validate`).

## Testler

```bash
cargo test -p authn-oidc-provider --all-features          # birim + akış testleri (gerçek PostgreSQL)
cargo test -p authn-server --all-features --test oidc_provider_e2e   # tam yığın
```

Akış testleri ID token'ı ve access token'ı **bağımsız** bir Ed25519 doğrulayıcısıyla (`ed25519-dalek`, JWKS'ten) doğrular; `at_hash`'i ayrıca SHA-512 ile hesaplar.

## Komutlar

```bash
cargo fmt -p authn-oidc-provider
cargo clippy -p authn-oidc-provider --all-targets --all-features -- -D warnings
cargo test -p authn-oidc-provider --all-features
```
