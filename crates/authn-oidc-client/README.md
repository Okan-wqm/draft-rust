# authn-oidc-client

OIDC / OAuth 2.0 istemcisi (relying party) olarak sosyal giriş: Google, Apple, Microsoft (çok kiracılı), GitHub ve genel OIDC sağlayıcıları; tarayıcı (web) ve native (mobil SDK) akışları; hesap eşleştirme, bağlama ve ayırma.

## Sahip olunan gereksinimler

SOC-01 … SOC-09 (ayrıntı: [`docs/spec/requirements.md`](../../docs/spec/requirements.md)).

| Gereksinim | Nerede | Özet |
|------------|--------|------|
| SOC-01 | `provider.rs`, `discovery.rs`, `identity.rs` | Google, Apple, Microsoft, GitHub, genel OIDC (discovery, önbellekli, issuer birebir); her biri `[oidc_client]` bölümünden etkinleşir |
| SOC-02 | `service/web.rs`, `cookies.rs`, `store.rs` | Authorization Code + PKCE S256 + `state` + `nonce`; sunucu tarafı durum (10 dk, tek kullanımlık, atomik tüketim); tarayıcı bağlama çerezi; `return_to` doğrulaması |
| SOC-03 | `id_token.rs`, `jwks.rs` | İmza (JWKS önbellekli, bilinmeyen `kid`'de rate limit'li yenileme), `iss` (Microsoft kiracı kuralı), `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce`; `none`/HS* reddi |
| SOC-04 | `service/native.rs` | `POST /v1/oauth/nonce` → `POST /v1/oauth/{provider}/native`; nonce zorunlu, tek kullanımlık, sağlayıcıya bağlı; audience = native client id'leri |
| SOC-05 | `service/accounts.rs` | `(provider, subject)` ile eşleştirme; e-postayla otomatik birleştirme yok (yalnızca konfigürasyonla, doğrulanmış e-posta + güvenilir sağlayıcı); yeni hesap yalnızca doğrulanmış e-postayla |
| SOC-06 | `service/accounts.rs`, `hooks.rs` | Bağlama (step-up), ayırma (step-up, son giriş yöntemi koruması, kullanıcı satırı kilidi) |
| SOC-07 | `apple.rs` | ES256 `client_secret` (yalnızca `p256` 0.14), önbellekli ve süresi dolmadan yenilenir; ilk girişteki ad; özel relay adresleri |
| SOC-08 | `service/accounts.rs` | Sağlayıcı token'ları varsayılan saklanmaz; saklanırsa zarf şifreli, AAD = tablo/kolon/satır |
| SOC-09 | `service/accounts.rs` | Oturum yalnızca `SessionIssuer` portundan; MFA politikası session hattında uygulanır, sağlayıcı MFA'sı yalnızca `trust_provider_mfa` açıksa iletilir |

## Mimari

- **Bağımlılık kuralı:** Dalga B. `authn-core`, `authn-crypto`, `authn-store`, `authn-account`, `authn-protect`'e bağımlıdır; `authn-session` ve `authn-admin`'e **bağımlı olamaz** (`authn-testkit/tests/architecture.rs`). Oturum `SessionIssuer` portuyla açılır.
- **HTTP:** her dış istek `HttpClient` portundan geçer (üretimde `authn_protect::outbound::SsrfSafeHttpClient`). Yerleşik sağlayıcıların sabit uç noktaları operatör tarafından güvenilir hedeftir (`Trusted`); genel sağlayıcının discovery belgesinden gelen token/JWKS uç noktaları **kullanıcı tarafından verilmiş** gibi (`UserSupplied`: yalnızca https, özel/iç adres yok, DNS sabitleme) çağrılır. Yanıtlar 256 KiB ile sınırlı, 10 sn zaman aşımlı.
- **Kriptografi:** sağlayıcı imzaları `openidconnect`'in denetlenmiş JWK uygulamasıyla (`CoreJsonWebKey::verify_signature`, yalnızca açık anahtar) doğrulanır; JWS ayrıştırma ve tüm claim kuralları bu crate'te açıkça yazılıdır. `openidconnect`/`oauth2`'nin HTTP istemcileri ve varsayılan özellikleri kullanılmaz. Apple `client_secret` yalnızca `p256` 0.14 ile imzalanır (RFC 6979, RNG yok). Rastgelelik: `OpaqueToken` (256 bit OS CSPRNG).

| Modül | İçerik |
|-------|--------|
| `service` | `OidcClientService` (tüm kullanım durumları), `OidcClientServiceDeps`, `actions` |
| `routes` | `router`, `OidcClientApi` (OpenAPI) |
| `provider` | `ProviderRegistry`, `Endpoints`, `IssuerRule`, `TenantPolicy` |
| `discovery`, `jwks` | önbellekler |
| `id_token` | JWS ayrıştırma + claim doğrulama |
| `identity` | sağlayıcıdan bağımsız kimlik, GitHub API'si |
| `apple` | `AppleClientSecret`, ilk girişteki ad |
| `hooks` | `LoginMethodInventory`, `AddressReservations` (+ varsayılanlar) |
| `export` | `IdentityDataExporter` (ACC-10 `identities` bölümü) |
| `codes` | bu crate'in hata kodları (bkz. "Açık işler") |
| `settings` | `OidcClientSettings` |

## Endpoint'ler

| Metot | Yol | Kimlik doğrulama | Yanıt |
|-------|-----|------------------|-------|
| `GET` | `/v1/oauth/providers` | — | `{providers: [{id, display_name, native}]}` |
| `GET` | `/v1/oauth/{provider}/start?return_to=` | — (tarayıcı) | `303` sağlayıcıya + `Set-Cookie: __Host-authn_oauth` |
| `GET`, `POST` | `/v1/oauth/{provider}/callback` | bağlama çerezi | `SessionIssuer::login_response` (oturum çerezi veya challenge çerezi + `return_to`'ya `303`); bağlama akışında `303` `return_to` |
| `POST` | `/v1/oauth/nonce` | — | `{nonce, expires_at}` |
| `POST` | `/v1/oauth/{provider}/native` | — | `SessionIssuer::login_response` (token'lar veya challenge, JSON) |
| `GET` | `/v1/me/identities` | oturum | `{identities: [...]}` (token/subject yok) |
| `POST` | `/v1/me/identities/link` | oturum + step-up | `{authorization_url}` + bağlama çerezi |
| `POST` | `/v1/me/identities/link/native` | oturum + step-up | `201` kimlik özeti |
| `DELETE` | `/v1/me/identities/{identity_id}` | oturum + step-up | `204` |

Tüm yanıtlar `Cache-Control: no-store`. Callback `POST`'u Apple'ın `form_post`'u içindir: bu çapraz site POST'unda oturum çerezi gönderilmez, dolayısıyla sunucunun CSRF katmanı devreye girmez; CSRF koruması tarayıcıya bağlı tek kullanımlık `state`'tir.

## Akışlar

### Web (SOC-02)

1. `start`: `state`, `nonce`, PKCE doğrulayıcısı (her biri 256 bit) üretilir. Saklananlar: `SHA-256(state)`, `SHA-256(nonce)`, `SHA-256(bağlama)`, zarf şifreli doğrulayıcı (AAD = `oauth_states`/`pkce_verifier_ciphertext`/satır kimliği), doğrulanmış mutlak `return_to`, `state_ttl` (10 dk). Tarayıcıya `__Host-authn_oauth` bağlama çerezi (`HttpOnly; Secure; Path=/; SameSite=None`) verilir; tarayıcıda geçerli bir bağlama çerezi varsa yeniden kullanılır (eşzamanlı akışlar).
2. `callback`: satır **önce** atomik olarak tüketilir (`UPDATE … WHERE consumed_at IS NULL AND expires_at > now RETURNING`); sonra sağlayıcı yol ile eşleşmeli, bağlama çerezi hash'i sabit zamanlı eşleşmeli; sağlayıcı hata döndüyse `oauth_authorization_denied`; kod PKCE doğrulayıcısıyla takas edilir; ID token doğrulanır ve `nonce`'unun hash'i saklananla eşleşmelidir. GitHub'da ID token yoktur: `/user` ve `/user/emails` access token ile okunur.
3. `return_to`: `authn-protect` `RedirectValidator` (göreli güvenli yol veya `protect.redirect_allow_list` ∪ `oidc_client.allowed_return_to` içinde birebir mutlak URL); göreli yollar `server.public_base_url`'e göre mutlak yapılır. `redirect_uri` her zaman `server.public_base_url`'den kurulur (`Host` başlığı kullanılmaz).

### Native (SOC-04)

İstemci `POST /v1/oauth/nonce {provider}` ile nonce alır ve platform SDK'sına **aynen** verir (Apple: `ASAuthorizationAppleIDRequest.nonce`; Google: Credential Manager `setNonce`). `POST /v1/oauth/{provider}/native {id_token, remember_me?, shared_device?, given_name?, family_name?}` (`given_name`/`family_name` imzasız istemci girdisidir ve **yalnızca Apple** için kullanılır — Apple ID token'ı ad taşımaz; diğer sağlayıcılarda imzalı `name` claim'i geçerlidir): imza ve claim'ler doğrulanır (`aud`/`azp` ∈ yapılandırılmış `native_client_ids`), sonra token'daki nonce'un hash'iyle native nonce satırı atomik tüketilir (yalnızca bu sağlayıcının, süresi geçmemiş, kullanılmamış satırı). Web akışının nonce'u native akışta geçmez. `native_client_ids` boşsa ya da sağlayıcı GitHub ise `oauth_native_not_supported`.

> Google Android'de `requestIdToken(serverClientId)` kullanılırsa token'ın `aud`'u sunucu (web) client id'sidir: bu durumda o kimlik `native_client_ids` listesine **bilinçli olarak** eklenmelidir (web akışının nonce'ları native akışta geçmediği için güvenlidir).

### Hesap eşleştirme (SOC-05) ve pre-hijacking (ADR 0002)

1. `(provider, subject)` bağlıysa o hesap; sağlayıcının bildirdiği e-posta hesabı **değiştirmez**. Genel sağlayıcılarda kimlik ayrıca oluşturulduğu **issuer**'a bağlıdır: bir slug'ın `issuer_url`'i değişirse eski kimlikle eşleşen giriş/bağlama `oauth_token_invalid` ile reddedilir (yeni issuer'ın `sub` ad alanı başka kişilere aittir).
2. Değilse sağlayıcı **doğrulanmış** bir e-posta bildirmelidir; değilse `oauth_email_not_verified` — bu karar **hiçbir hesap sorgusundan önce** verilir (yanıt, durum kodu ve süre var olan hesaplardan bağımsız).
3. Adrese ait hesap ve rezervasyon yoksa: hesap `active` + e-posta doğrulanmış olarak açılır, kimlik bağlanır (tek transaction; `account.registered`, `identity.linked` audit; `user.created` olayı).
4. Adrese ait hesap varsa: **otomatik birleştirme yok** → `oauth_link_required` (409; yalnızca e-postanın sahibi olduğunu sağlayıcıyla kanıtlamış kişiye gösterilir). Yalnızca `auto_link_verified_email = true` **ve** sağlayıcı `auto_link_trusted_providers` içindeyse ve hesap `active`/`pending_verification` ise: kullanıcı satırı kilitlenir; hesap doğrulanmamışsa önce `AccountService::confirm_mailbox_control_in_tx(…, MailboxProof::Passwordless)` (bekleyen kayıtlar ve kanıtlanmamış şifre silinir, tüm oturumlar ve güvenilir cihazlar iptal edilir, adres doğrulanır) — sonra kimlik bağlanır. Kimlik **asla** `pending_verification` bir hesaba eklenmez.
5. Eşzamanlı ilk girişler: benzersizlik ihlalinde karar bir kez yeniden çalıştırılır.

E-postanın "doğrulanmış" sayılması:

| Sağlayıcı | Doğrulanmış sayılır |
|-----------|---------------------|
| Google, genel OIDC | `email_verified` `true` |
| Apple | `email_verified` `true` / `"true"` (özel relay adresleri dahil) |
| Microsoft | kişisel hesap kiracısı (`9188040d-…`) veya isteğe bağlı `xms_edov` claim'i `true`; iş hesaplarının düz `email` claim'i değiştirilebilir olduğundan doğrulanmamış sayılır ("nOAuth") |
| GitHub | yalnızca `/user/emails`'teki **birincil** adres `verified` ise (diğer doğrulanmış adresler yok sayılır) |

### Bağlama / ayırma (SOC-06)

- Bağlama: oturum (API anahtarı değil), yazılabilir principal (salt-okunur impersonation değil), `session.step_up_max_age` içinde kimlik doğrulama; hesap `active` ve e-postası doğrulanmış olmalı (`identity_link_not_allowed`). Kimlik başka hesaba bağlıysa `identity_already_linked`; hesapta aynı sağlayıcıdan başka kimlik varsa `identity_provider_already_linked`. Bağlama transaction'ı kullanıcı satırını kilitler.
- Ayırma: aynı koşullar; transaction'ın **başında** `UserRepository::lock_for_update` (PWD-11 yarışı); son kimlikse `LoginMethodInventory::other_login_methods` aynı bağlantıdan okunur, başka yöntem yoksa `identity_last_login_method`. Başka kullanıcının/bilinmeyen kimlik `not_found`.

### MFA (SOC-09)

Doğrulanmış kimlik `PrimaryAuthentication { method: Social, amr: [fed], provider_asserted_mfa }` olarak `SessionIssuer::complete_primary_authentication`'a verilir; hesap durumu, risk, organizasyon ve MFA politikası authn-session hattında uygulanır ve sonuç **oturum ya da challenge** olur (challenge web'de çerezle, native'de JSON ile döner). `provider_asserted_mfa` yalnızca `oidc_client.trust_provider_mfa = true` ve token'ın `amr`'si `mfa` içeriyorsa `true`'dur; authn-session ayrıca phishing-resistant MFA gereken yerde bunu hiç kabul etmez. Bu crate `amr`'ye asla `mfa`/`hwk`/`swk` koymaz.

## Konfigürasyon

`[oidc_client]` (`crates/authn-core/src/config/oidc_client.rs`): `state_ttl` (10 dk), `native_nonce_ttl` (10 dk), `allowed_return_to`, `google`/`microsoft`/`apple`/`github`/`generic[]`, `auto_link_verified_email` (false), `auto_link_trusted_providers`, `trust_provider_mfa` (false), `store_provider_tokens` (false), `jwks_cache_ttl` (1 sa; discovery de aynı süreyle önbelleklenir).

Wave 1'de eklenen anahtarlar (K-31; `OidcClientSettings::from_app_config` bunları okur, sunucu programatik olarak yine değiştirebilir):

| Anahtar | Varsayılan | Anlam |
|---------|-----------|-------|
| `microsoft.allowed_tenants` | boş | Microsoft `tid` izin listesi (GUID); alan adı biçimli `tenant` için zorunlu (konfigürasyon doğrulaması ve açılış ikisi de reddeder) |
| `microsoft.trust_personal_account_email` | **false** | Microsoft kişisel hesap (MSA) `email`'i doğrulanmış sayılsın mı (K-17). Varsayılan güvenli taraf: Microsoft `email` claim'ini değişebilir/doğrulanmamış olarak belgeler, `xms_edov` yalnızca iş hesaplarında gelir; `false` iken MSA kimliği yeni hesap açmaz ve e-postayla otomatik bağlanmaz (kullanıcı e-postayla kaydolup Microsoft'u giriş yapmışken açıkça bağlar) |
| `generic[].trust_email_verified` | **false** | Genel sağlayıcının `email_verified` claim'ine güvenilsin mi (K-04, ADR 0002 "non-verifying IdP"); `false` iken bu sağlayıcının adresleri doğrulanmamış sayılır (yeni hesap ve otomatik bağlama yok, yalnızca açık bağlama) |
| `apple.private_key_file` | yok | Apple özel anahtarı (PKCS#8 PEM) dosyadan (ör. secret mount); `private_key_pem` ile **tam olarak biri** zorunlu (K-34, SOC-07). Dosya açılışta bir kez okunur, içerik/yol hata mesajına girmez |
| `start_per_ip` | 60 / 10 dk | web başlatma (giriş + bağlama), IP başına |
| `native_per_ip` | 60 / 10 dk | native nonce + native giriş/bağlama, IP başına |
| `callback_per_ip` | 60 / 10 dk | web callback'i, IP başına (state sorgusundan **önce**; kısılan istek audit'e yazılmaz) |
| `jwks_refresh_min_interval` | 60 sn (10 sn–1 sa) | bilinmeyen `kid` ile zorlanan iki JWKS indirmesi arası en kısa süre |

Anahtarı olmayan tek alan: `apple_client_secret_ttl` (1 sa; Apple `client_secret` ömrü, çeyreği kalınca yenilenir).

Microsoft `tenant`: `common` (her kiracı), `organizations` (kişisel hesap kiracısı hariç), `consumers` (yalnızca kişisel), kiracı GUID'i (yalnızca o), alan adı (yalnızca `microsoft.allowed_tenants`; liste boşsa konfigürasyon geçersiz).

## Hata kodları

Kodlar global kayıt defterinde, `authn_core::error::codes::oidc_client` (wave 1, K-30; `codes::all()` ve DOC-04 kataloğunda görünür); `codes.rs` bunları yeniden dışa açar. Tel dizeleri değişmedi (`soc_01_wire_strings_are_unchanged`):

| Kod | Durum | Ne zaman |
|-----|-------|----------|
| `oauth_provider_unknown` | 404 | sağlayıcı yapılandırılmamış |
| `oauth_state_invalid` | 400 | state bilinmiyor/süresi dolmuş/kullanılmış/başka sağlayıcının/başka tarayıcının (bilerek ayırt edilmez) |
| `oauth_nonce_invalid` | 400 | native nonce yok/bilinmiyor/süresi dolmuş/kullanılmış/başka sağlayıcının |
| `oauth_token_invalid` | 401 | ID token veya kod takası doğrulanmadı (neden yalnızca loglanır) |
| `oauth_authorization_denied` | 400 | kullanıcı iptal etti / sağlayıcı reddetti |
| `oauth_email_not_verified` | 403 | sağlayıcı doğrulanmış e-posta bildirmedi (yeni hesap/eşleştirme yok) |
| `oauth_link_required` | 409 | bu adresle hesap var; giriş yapıp bağlayın |
| `oauth_native_not_supported` | 400 | sağlayıcının native akışı yok |
| `identity_already_linked` | 409 | kimlik başka hesaba bağlı |
| `identity_provider_already_linked` | 409 | hesapta bu sağlayıcıdan kimlik var |
| `identity_last_login_method` | 409 | son giriş yöntemi kaldırılamaz |
| `identity_link_not_allowed` | 403 | hesap aktif/doğrulanmış değil |

Ortak kodlar: `step_up_required`, `forbidden`, `unauthenticated`, `not_found`, `rate_limited` (+ `Retry-After`), `invalid_redirect` (authn-protect), `service_unavailable` (sağlayıcıya ulaşılamadı).

## Güvenlik notları

- **Login CSRF / oturum takası:** callback, state'i başlatan tarayıcının bağlama çerezini ister; state tek kullanımlıktır ve her kontrolden önce atomik tüketilir (eşzamanlı tekrar oynatmada tam olarak biri ilerler).
- **Sırlar düz saklanmaz:** state/nonce/bağlama yalnızca SHA-256; PKCE doğrulayıcısı ve sağlayıcı token'ları zarf şifreli, AAD satıra bağlı (kopyala-yapıştır saldırısı çözülemez). `Debug` çıktıları token içermez; sağlayıcı hata gövdeleri loglanmaz.
- **Audience:** `aud`'daki **her** değer kabul edilen bir client id olmalı (OIDC Core 3.1.3.7 kural 3); birden çok audience'ta `azp` zorunlu ve kabul edilen bir client id olmalı.
- **Algoritma karışıklığı:** `none` ve tüm `HS*` anahtar aranmadan reddedilir; JWK'nın `alg`'i varsa başlıkla aynı olmalı; simetrik ve şifreleme anahtarları JWKS'ten atılır; `jku`/`x5u`/`jwk` başlıkları izlenmez; `crit` reddedilir.
- **JWKS DoS:** bilinmeyen `kid` en fazla `jwks_refresh_min_interval`'de bir indirme tetikler; indirme başarısızsa önbellekteki anahtar kullanılmaya devam eder.
- **Microsoft kiracı sahteciliği:** `iss`, token'ın kendi `tid`'i (GUID biçimi zorunlu) ile `…/{tid}/v2.0` olmalı ve kiracı politikası/izin listesi `tid`'i kabul etmeli; subject `<tid>:<oid>`.
- **Hesap varlığı:** doğrulanmamış e-posta yanıtı hesap sorgusundan önce verilir (test: gövde, durum ve süre). `oauth_link_required` yalnızca adresin sahibi olduğunu sağlayıcıyla kanıtlamış kişiye döner (SOC-05'in tasarımı).
- **Audit:** başarısız sosyal girişler `login.failed` (kullanıcısız, `method=social`, sağlayıcı, kod) olarak kaydedilir; bilinmeyen sağlayıcı, native'i olmayan sağlayıcı ve rate limit'e takılan istekler anonim çağıranın audit zincirini büyütememesi için kaydedilmez. Kimliksiz uçların hepsi (başlatma, callback, nonce, native) IP başına sınırlıdır; dolayısıyla anonim bir çağıranın yazdırabileceği `login.failed` sayısı da sınırlıdır.
- **`Debug` çıktıları:** callback parametreleri (`code`, `state`, Apple `user`), doğrulanmamış ID token ve sağlayıcı yanıt gövdeleri `Debug`'da görünmez. Bağlama/ayırma `identity.linked`/`identity.unlinked`; impersonation altında ayırmada `impersonator` yazılır.

### Bağımsız güvenlik denetimi (2026-11-04)

Kodu yazmamış bir denetçi "zafiyetli, kanıtla" varsayımıyla inceledi. Doğrulanan her bulgu önce düzeltme olmadan **başarısız olan** bir regresyon testiyle kanıtlandı, sonra düzeltildi:

| # | Önem | Bulgu | Regresyon testi | Durum |
|---|------|-------|-----------------|-------|
| 1 | Orta | Web callback'i rate limit'siz ve kimliksizdi: rastgele, biçimce geçerli `state` değerleriyle sınırsız DB `UPDATE`'i ve sınırsız anonim `login.failed` audit kaydı (audit zinciri/DB şişirme; crate'in kendi "anonim çağıran audit'i büyütemez" kuralına aykırı) | `soc_02_callback_is_rate_limited_and_cannot_flood_the_audit` | Düzeltildi: `callback_per_ip` (60/10 dk), state sorgusundan önce |
| 2 | Düşük | `aud` dizisinde güvenilmeyen ek audience'lı token, `azp` bizimse kabul ediliyordu (OIDC Core 3.1.3.7 kural 3) | `soc_03_untrusted_extra_audiences_are_rejected`, `soc_03_azp_rules`, `soc_04_native_audience_is_the_native_client_ids` | Düzeltildi: her audience kabul edilen bir client id olmalı; dizi elemanı string değilse red |
| 3 | Orta | Kimlik yalnızca `(provider, subject)` ile eşleşiyordu; genel sağlayıcının `issuer_url`'i değişince (IdP göçü, eski IdP'nin ele geçirilmesi) yeni issuer'ın aynı `sub`'u eski kullanıcının hesabına giriyordu (hesap ele geçirme) | `soc_05_generic_identity_is_bound_to_its_issuer` | Düzeltildi: genel sağlayıcıda saklı issuer token'ınkiyle aynı olmalı (giriş ve bağlama) |
| 4 | Düşük | Native istekteki imzasız `given_name`/`family_name` her sağlayıcıda imzalı `name` claim'inin yerine geçiyor ve her girişte kimliğin görünen adını değiştiriyordu | `soc_07_native_client_name_is_only_used_for_apple` | Düzeltildi: yalnızca Apple |
| 5 | Düşük | `Debug` çıktısında sırlar: `CallbackParams` (`code`, `state`), `UnverifiedToken` (imzalı token'ın tamamı), `ProviderResponse` (token yanıtı gövdesi) | `soc_02_callback_params_debug_redacts_code_and_state`, `soc_03_unverified_token_debug_redacts_the_token`, `soc_08_provider_response_debug_redacts_the_body` | Düzeltildi: elle yazılmış `Debug` |

Ek: rezervasyon yolu hiç test edilmiyordu → `soc_05_reserved_address_gets_no_new_account`; `NoReservations` bağlanırsa servis açılışta uyarı loglar (`AddressReservations::enforced`).

İncelenip **sorun bulunmayan** başlıca alanlar: imza doğrulama (`openidconnect` `check_key_compatibility`: JWK `use`/`kty`/`alg`, EC eğrisi kontrolü), `kid` zorunluluğu, `crit`/`typ`, `exp`/`iat`/`nbf` + leeway, nonce (sabit zamanlı hash karşılaştırması), Microsoft `tid` GUID + `{tenantid}` şablonu + izin listesi + `<tid>:<oid>` + `xms_edov`, GitHub birincil+doğrulanmış e-posta, discovery (birebir issuer, `UserSupplied` uç noktalar, https, SSRF istemcisi yönlendirme izlemez), state tek kullanım (atomik `UPDATE … RETURNING`), sağlayıcıya bağlılık, `__Host-` bağlama çerezi ve çerez fırlatma, PKCE doğrulayıcısı AAD'si, `return_to` (ters bölü, `//`, userinfo, yüzde kodlama katmanları `authn-protect`'te; göreli yol `public_base_url`'e eklenir), sağlayıcı başına `redirect_uri` (mix-up), Apple `form_post` (CSRF koruması `state`+bağlama; `SameSite=None` çerez tek başına bir şey vermez), Apple `client_secret` yalnızca `p256` 0.14 (`cargo tree -i p256@0.14.0` → yalnızca bu crate; 0.13 yalnızca `openidconnect` açık anahtar doğrulamasında), hesap eşleştirme/ön ele geçirme (ADR 0002), bağlama/ayırma (step-up, IDOR, `lock_for_update`), SOC-08 zarf şifreleme (AAD satıra bağlı), SOC-09 (`amr: [fed]` sabit; sağlayıcı MFA'sı yalnızca yapılandırmayla, authn-session phishing-resistant gerekiyorsa yine yok sayar), yanıt boyutu (256 KiB) ve token boyutu (16 KiB) sınırları, panik yok.

### Kabul edilen riskler / sınırlamalar

1. ~~Genel OIDC sağlayıcısının `email_verified` beyanına koşulsuz güvenilir~~ — **kapatıldı (wave 1, K-04):** sağlayıcı başına `trust_email_verified`, varsayılan `false`; güvenilmeyen sağlayıcı yeni hesap açtıramaz ve adres varlığını öğrenemez (`oauth_email_not_verified` hesap aramasından önce döner). Testler: `soc_05_generic_provider_email_is_unverified_unless_trusted`, `soc_05_untrusted_providers_never_create_accounts`. Operatör `true`'yu yalnızca adresleri gerçekten doğrulayan IdP'ler için açmalıdır. Güven ayarını kapatmak zaten bağlı kimlikleri kilitlemez: giriş `(provider, subject)` ile sürer (bağımsız denetim, `soc_05_untrusted_providers_keep_linked_identities_and_reveal_no_accounts`; MSA için de).
2. **Web akışında `remember_me`/`shared_device` yok:** `oauth_states` tablosunda bu seçenekler için kolon yok (migration talebi açık); web sosyal girişi her zaman varsayılan oturum ömrünü kullanır. Native akış gövdedeki değerleri iletir.
3. **Adres rezervasyonu (ACC-07)** `AddressReservations` kancasına bağlıdır; `NoReservations` hiçbir adresi ayrılmış saymaz (fail-open). Denetçi değerlendirmesi: bu bir "varsayılan" değil, `OidcClientServiceDeps`'te **zorunlu ve açık** bir seçimdir; fail-closed bir varsayılan (her yeni sosyal kaydı reddetmek) sosyal kaydı tamamen kapatırdı ve rezervasyon verisi authn-account'un tablosunda olduğundan bu crate onu doğrudan okuyamaz (contracts §5). Etkisi: geri alma süresinde eski adresle sosyal girişte yeni hesap açılırsa, eski sahibin "geri al" işlemi benzersizlik ihlaliyle **başarısız olur** — rezervasyonun koruduğu kurtarma yolu kapanır. Bunu yapabilen yalnızca o adresi sağlayıcıda doğrulamış kişidir (pratikte kurtarmaya çalışan eski sahibin kendisi, ya da doğrulamayan bir genel IdP; bkz. madde 1). Önlem: `NoReservations` bağlıysa servis açılışta `warn` loglar; üretimde authn-account adaptörü zorunludur (talep açık).
4. **Bağlama/ayırma bildirimi yok:** `NotificationKind`'da kimlik bağlandı/ayrıldı türü yok; yalnızca audit olayı yazılır (talep açık).
5. **Yeni sosyal hesapta profil satırı yok:** görünen ad yalnızca `identities.display_name`'de tutulur (`user_profiles` authn-account'a ait; sağlama API'si talebi açık). Şartların kabulü (ACC-11) giriş hattında zorunlu adım olarak istenir.
6. **Apple özel anahtarı:** satır içi PEM veya `private_key_file` (wave 1, K-34 kısmen; `soc_07_private_key_is_read_from_a_file_or_inline`). Zarf şifreli değer seçeneği **yok**: konfigürasyon sisteminde zarf şifreli değer deseni bulunmuyor (KEK `[crypto]`'da, çözme authn-crypto'da); eklenmesi wave 2'ye bırakıldı.
7. **Apple native yetkilendirme kodu takas edilmez:** native akış yalnızca ID token'ı doğrular; Apple refresh token'ı alınmaz/saklanmaz (hesap silmede Apple token iptali kapsam dışı).
8. **Hata yanıtı tarayıcıya JSON olarak döner:** callback hataları (`oauth_state_invalid` vb.) standart hata zarfıdır; ön yüz kendi hata sayfasına yönlendirmek isterse bunu bir ters vekil/ön yüz katmanında yapmalıdır. Güvenlik etkisi yok (hata gövdesi kararlı kod ve genel mesajdır; ayrıntı yalnızca log'da).
9. **Bağlama akışı callback'inde oturum yeniden doğrulanmaz:** step-up başlatmada (`POST /v1/me/identities/link`) kontrol edilir; `oauth_states` satırı oturum kimliğini değil yalnızca `user_id`'yi taşır ve Apple'ın çapraz site `form_post`'unda oturum çerezi gelmez. Başlatan oturum en çok `state_ttl` (10 dk) içinde iptal edilse (çıkış, şifre sıfırlama) bile, akışı başlatan **aynı tarayıcı** (bağlama çerezi) callback'i tamamlayıp kimliği bağlayabilir. Saldırganın zaten taze step-up'lı bir oturuma sahip olmasını gerektirir ve o anda doğrudan da bağlayabilirdi; pencere 10 dk ile sınırlı, `identity.linked` audit'i yazılır. Kalıcı çözüm için talep açıldı (`oauth_states.session_id` + callback'te oturumun hâlâ geçerli olduğunun bir port ile kontrolü).
10. ~~Microsoft kişisel hesap e-postası koşulsuz doğrulanmış sayılır~~ — **kapatıldı (wave 1, K-17):** `microsoft.trust_personal_account_email`, varsayılan `false` (güvenli taraf; gerekçe rustdoc'ta ve yukarıdaki tabloda). İş/okul hesaplarında yine yalnızca `xms_edov`. Test: `soc_05_microsoft_personal_account_email_is_unverified_unless_trusted`.
11. **JWKS indirmesi başarısızken yenileme sınırı yok:** bilinmeyen `kid` ile yenileme yalnızca başarılı indirmeden sonra `jwks_refresh_min_interval` ile sınırlıdır; sağlayıcıya ulaşılamazken her doğrulama bir indirme dener (URL başına kilitle seri, 10 sn zaman aşımı). Bu istekler zaten IP başına sınırlı uçlardan (native, callback) gelir; etki sağlayıcı kesintisi sırasında gecikmeyle sınırlıdır.
12. **Kullanılmayan bağımlılıklar:** `Cargo.toml`'da `oauth2`, `subtle`, `axum-extra`, `reqwest`, `uuid`, `thiserror` bu crate'in kodunda kullanılmıyor (hepsi zaten workspace grafiğinde; `oauth2` `openidconnect` üzerinden). Kaldırmak kök `Cargo.lock`'u değiştirir; paralel çalışma nedeniyle bu denetimde yapılmadı.

## Server'ın bağlaması gerekenler

1. **Servis:**
   ```rust
   let settings = authn_oidc_client::OidcClientSettings::from_app_config(&config);
   // isteğe bağlı: settings.microsoft_allowed_tenants = …;
   let oidc = authn_oidc_client::OidcClientService::new(
       authn_oidc_client::OidcClientServiceDeps {
           pool, clock, http /* SsrfSafeHttpClient */, envelopes: crypto.envelopes.clone(),
           rate_limiter, audit, events,
           sessions: session_service.clone() /* Arc<dyn SessionIssuer> */,
           accounts: account_service.clone(),
           login_methods: Arc::new(ServerLoginMethods { … }),
           reservations: Arc::new(ServerReservations { … }) /* veya NoReservations */,
       },
       settings,
   )?; // Apple anahtarı ve Microsoft kiracı ayarı açılışta doğrulanır (fail fast)
   ```
   `impl FromRef<AppState> for OidcClientService`.
2. **Router ve OpenAPI:** `app.rs::module_routes`'a `.merge(authn_oidc_client::router::<AppState>())`; OpenAPI'ye `authn_oidc_client::OidcClientApi`. `/v1/me/identities*` oturum + CSRF katmanının arkasında (global `authn_session::authenticate` zaten `Principal` ekler); `/v1/oauth/*` kimliksiz.
3. **Kanca uygulamaları:**
   - `authn_oidc_client::LoginMethodInventory` — **yalnızca verilen `conn`'dan**: şifre (`UserRepository::find_password(conn, user)`) → `Password`; `WebauthnService::passkey_count_in(conn, user, true) > 0` → `Passkey`; kurulumda açıksa `MagicLink`/`EmailCode`. `Social` döndürmeyin.
   - `authn_oidc_client::AddressReservations` — authn-account rezervasyon sorgusu dışa açılınca (talep açık) aynı bağlantıyla.
   - Diğer modüllerin kancalarında sosyal kimlik sayısı: `authn_password::LoginMethodInventory` ve `authn_webauthn::AccountMethodsSource` adaptörleri `OidcClientService::linked_identity_count_in(conn, user) > 0` ise `LoginMethod::Social` eklemeli (contracts §15.1).
4. **Veri dışa aktarma:** `AccountServiceDeps.exporters`'a `Arc::new(authn_oidc_client::IdentityDataExporter)` (bölüm adı `identities`).
5. **Arka plan işi (OPS-06):** `OidcClientService::purge_expired_states(limit)` periyodik (ör. 5 dk'da bir, `limit = 1000`, dönen sayı `limit`'e eşitse tekrar); çoklu instance güvenli.
6. **Açılış:** `authn_core::tls::install_crypto_provider()` (servis de çağırır); HTTP istemcisi `SsrfSafeHttpClient::new(&config.protect.outbound)`.
7. **authn-session ayarı:** `SessionSettings::trust_provider_mfa` zaten `oidc_client.trust_provider_mfa`'dan okunuyor; ek iş yok.

## Testler

```bash
cargo test -p authn-oidc-client --all-features
```

Gerçek PostgreSQL (`#[sqlx::test]`), gerçek SSRF korumalı HTTP istemcisi ve `wiremock` sahte sağlayıcılar (Google, Apple, Microsoft, GitHub, genel OIDC tek sunucuda yol önekleriyle). `tests/fixtures/` altındaki anahtarlar **yalnızca test** içindir (README'si orada).

| Gereksinim | Testler (seçme) |
|------------|-----------------|
| SOC-01 | `soc_01_generic_oidc_provider_uses_discovery_and_basic_auth`, `soc_01_generic_discovery_with_foreign_issuer_is_refused`, `soc_01_discovery_issuer_must_match_exactly`, `soc_01_github_login_uses_primary_verified_email`, `soc_01_microsoft_web_login_uses_tenant_issuer_and_tid_oid_subject`, `soc_01_unknown_provider_and_listing`, `soc_01_disabled_providers_are_absent` |
| SOC-02 | `soc_02_google_web_login_creates_verified_account_and_logs_in`, `soc_02_state_replay_is_rejected`, `soc_02_concurrent_callbacks_consume_the_state_once`, `soc_02_callback_from_another_browser_is_rejected`, `soc_02_state_of_another_provider_is_rejected`, `soc_02_state_expires_after_ten_minutes`, `soc_02_nonce_mismatch_is_rejected`, `soc_02_pkce_or_code_rejected_by_provider_fails`, `soc_02_pkce_verifier_is_bound_to_its_state_row`, `soc_02_return_to_open_redirects_are_rejected`, `soc_02_pkce_s256_known_answer`, `soc_02_callback_is_rate_limited_and_cannot_flood_the_audit`, `soc_02_callback_params_debug_redacts_code_and_state` |
| SOC-03 | `soc_03_wrong_issuer_audience_azp_expiry_and_future_iat_are_rejected`, `soc_03_alg_none_hmac_confusion_and_foreign_keys_are_rejected`, `soc_03_jwks_rotation_and_rate_limited_refresh`, `soc_03_microsoft_tenant_spoofing_and_allow_list`, `soc_03_microsoft_tenant_spoofing_is_rejected`, `soc_03_alg_confusion_jwk_algorithm_must_match_header`, `soc_03_untrusted_extra_audiences_are_rejected`, `soc_03_unverified_token_debug_redacts_the_token` |
| SOC-04 | `soc_04_google_native_login_with_server_nonce`, `soc_04_apple_microsoft_and_generic_native_logins`, `soc_04_nonce_is_mandatory_single_use_and_provider_bound`, `soc_04_native_audience_is_the_native_client_ids`, `soc_04_github_has_no_native_flow` |
| SOC-05 | `soc_05_identity_is_matched_by_subject_not_by_email`, `soc_05_existing_account_is_never_merged_automatically_by_default`, `soc_05_auto_link_only_for_trusted_providers_and_verified_email`, `soc_05_pending_account_never_receives_an_identity_without_auto_link`, `soc_05_pre_hijacked_pending_account_is_reclaimed_by_the_mailbox_owner`, `soc_05_unverified_email_answer_does_not_reveal_accounts`, `soc_05_github_unverified_primary_email_cannot_create_an_account`, `soc_05_microsoft_work_account_email_is_unverified_without_xms_edov`, `soc_05_generic_identity_is_bound_to_its_issuer`, `soc_05_reserved_address_gets_no_new_account` |
| SOC-06 / PWD-11 | `soc_06_web_link_requires_step_up_and_links_on_callback`, `soc_06_native_link_rules`, `soc_06_unlink_never_removes_the_last_login_method`, `soc_06_foreign_and_unknown_identities_answer_not_found`, `soc_06_identity_routes_require_a_user_session`, `pwd_11_concurrent_unlinks_cannot_strand_the_account`, `pwd_11_unlink_and_password_removal_serialize_on_the_user_row` |
| SOC-07 | `soc_07_apple_form_post_login_with_es256_client_secret_and_first_name`, `soc_07_client_secret_is_es256_signed_with_apple_claims`, `soc_07_client_secret_is_cached_and_renewed_before_expiry`, `soc_07_native_client_name_is_only_used_for_apple` |
| SOC-08 | `soc_08_provider_tokens_are_not_stored_by_default`, `soc_08_stored_provider_tokens_are_envelope_encrypted_with_row_aad`, `soc_08_turning_storage_off_clears_tokens_on_next_login`, `soc_08_provider_response_debug_redacts_the_body` |
| SOC-09 | `soc_09_provider_mfa_is_not_trusted_by_default`, `soc_09_provider_mfa_is_forwarded_only_when_trusted`, `soc_09_mfa_challenge_is_returned_instead_of_a_session` |

## Açık işler (sözleşme değişikliği talepleri)

Bu crate dışındaki kod, konfigürasyon ve migration dosyaları bu görevde değiştirilmedi; aşağıdakiler [`docs/architecture/contract-change-requests.md`](../../docs/architecture/contract-change-requests.md) `## authn-oidc-client` başlığı altında talep edildi:

1. Hata kodlarının `codes.rs`'ten `crates/authn-core/src/error/codes/oidc_client.rs`'e birebir taşınması (`ALL` kayıt defterine; şu an global katalogda görünmüyorlar).
2. `[oidc_client]`'e alanlar: `microsoft.allowed_tenants`, `start_per_ip`, `native_per_ip`, `callback_per_ip`, `apple.private_key_file` (SOC-07 "dosya"), isteğe bağlı `jwks_refresh_min_interval` (+ `config/example.toml` yorumları).
3. Migration `2100`: `oauth_states.remember_me`, `oauth_states.shared_device` (web akışında SES-06/07).
4. authn-account: rezervasyon sorgusu (`is_address_reserved_in(conn, email)`) ve doğrulanmış sosyal hesap sağlama API'si (profil + görünen ad + dil).
5. authn-notify: `NotificationKind::IdentityLinked` / `IdentityUnlinked`.
6. (Denetimden) Bağlama akışında oturum bağlılığı: migration `2101` `oauth_states.session_id` + callback'te oturumun hâlâ geçerli olduğunun kontrolü (kabul edilen risk 9).
7. (Denetimden) Genel sağlayıcı başına `trust_email_verified` (varsayılan `true`, geriye uyumlu): `false` ise sağlayıcı e-postası hiçbir zaman doğrulanmış sayılmaz (kabul edilen risk 1).

## Komutlar

```bash
cargo fmt -p authn-oidc-client
cargo clippy -p authn-oidc-client --all-targets --all-features -- -D warnings
cargo test -p authn-oidc-client --all-features
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
