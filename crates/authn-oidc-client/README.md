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
| SOC-07 | `apple.rs`, `service/native.rs`, `service/revocation.rs` | ES256 `client_secret` (yalnızca `p256` 0.14; client id başına), önbellekli ve süresi dolmadan yenilenir; özel anahtar satır içi PEM, dosya veya zarf şifreli değer; ilk girişteki ad; özel relay adresleri; native yetkilendirme kodu takası; hesap silmede/ayırmada Apple token iptali |
| SOC-08 | `service/accounts.rs` | Sağlayıcı token'ları varsayılan saklanmaz (iptal için gereken Apple refresh token'ı hariç); saklananlar zarf şifreli, AAD = tablo/kolon/satır |
| ACC-09 / ADM-03 (çapraz) | `acc_09_account_deletion_revokes_the_apple_token`, `acc_09_revocation_failures_are_retried_then_audited_never_blocking`, `adm_03_admin_verification_shows_no_staff_identity_in_the_users_view` (K-14; gerçek authn-audit sink'i ve kullanıcı görünümüyle) |
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
| `hooks` | `LoginMethodInventory` (+ `PasswordOnlyInventory`), `SessionLiveness` (varsayılanı yok) |
| `export` | `IdentityDataExporter` (ACC-10 `identities` bölümü) |
| `codes` | bu crate'in hata kodları (bkz. "Açık işler") |
| `settings` | `OidcClientSettings` |

## Endpoint'ler

| Metot | Yol | Kimlik doğrulama | Yanıt |
|-------|-----|------------------|-------|
| `GET` | `/v1/oauth/providers` | — | `{providers: [{id, display_name, native}]}` |
| `GET` | `/v1/oauth/{provider}/start?return_to=&remember_me=&shared_device=` | — (tarayıcı) | `303` sağlayıcıya + `Set-Cookie: __Host-authn_oauth` |
| `GET`, `POST` | `/v1/oauth/{provider}/callback` | bağlama çerezi | `SessionIssuer::login_response` (oturum çerezi veya challenge çerezi + `return_to`'ya `303`); bağlama akışında `303` `return_to`; hata: JSON zarf ya da (yapılandırılmışsa) `oidc_client.error_redirect`'e `303` |
| `POST` | `/v1/oauth/nonce` | — | `{nonce, expires_at}` |
| `POST` | `/v1/oauth/{provider}/native` | — | `SessionIssuer::login_response` (token'lar veya challenge, JSON) |
| `GET` | `/v1/me/identities` | oturum | `{identities: [...]}` (token/subject yok) |
| `POST` | `/v1/me/identities/link` | oturum + step-up | `{authorization_url}` + bağlama çerezi |
| `POST` | `/v1/me/identities/link/native` (`{provider, id_token, authorization_code?}`) | oturum + step-up | `201` kimlik özeti |
| `DELETE` | `/v1/me/identities/{identity_id}` | oturum + step-up | `204` |

Tüm yanıtlar `Cache-Control: no-store`. Callback `POST`'u Apple'ın `form_post`'u içindir: bu çapraz site POST'unda oturum çerezi gönderilmez, dolayısıyla sunucunun CSRF katmanı devreye girmez; CSRF koruması tarayıcıya bağlı tek kullanımlık `state`'tir.

## Akışlar

### Web (SOC-02)

1. `start`: `state`, `nonce`, PKCE doğrulayıcısı (her biri 256 bit) üretilir. Saklananlar: `SHA-256(state)`, `SHA-256(nonce)`, `SHA-256(bağlama)`, zarf şifreli doğrulayıcı (AAD = `oauth_states`/`pkce_verifier_ciphertext`/satır kimliği), doğrulanmış mutlak `return_to`, `state_ttl` (10 dk); giriş akışında giriş sayfasının `remember_me` / `shared_device` seçimi (K-32, migration `2100`), bağlama akışında akışı başlatan oturumun kimliği (K-03, migration `2101`). Tarayıcıya `__Host-authn_oauth` bağlama çerezi (`HttpOnly; Secure; Path=/; SameSite=None`) verilir; tarayıcıda geçerli bir bağlama çerezi varsa yeniden kullanılır (eşzamanlı akışlar).
2. `callback`: satır **önce** atomik olarak tüketilir; giriş akışında saklanan `remember_me` / `shared_device` `PrimaryAuthentication`'a aynen geçer (SES-06/07, K-32) (`UPDATE … WHERE consumed_at IS NULL AND expires_at > now RETURNING`); sonra sağlayıcı yol ile eşleşmeli, bağlama çerezi hash'i sabit zamanlı eşleşmeli; sağlayıcı hata döndüyse `oauth_authorization_denied`; kod PKCE doğrulayıcısıyla takas edilir; ID token doğrulanır ve `nonce`'unun hash'i saklananla eşleşmelidir. GitHub'da ID token yoktur: `/user` ve `/user/emails` access token ile okunur.
3. **Hata sayfası (K-36):** `oidc_client.error_redirect` ayarlıysa callback hataları JSON yerine bu adrese `303` ile döner ve yalnızca kararlı kod eklenir (`?error=oauth_state_invalid`). Adres açılışta `return_to` ile aynı doğrulayıcıdan geçer (göreli güvenli yol veya izin listesinde birebir mutlak URL; `//`, ters bölü, userinfo, `http`, `javascript:` reddedilir — açılış başarısız olur); state'in kendi `return_to`'su hatada **asla** kullanılmaz (state sahte olabilir). Ayarlı değilse varsayılan JSON hata zarfıdır.
4. `return_to`: `authn-protect` `RedirectValidator` (göreli güvenli yol veya `protect.redirect_allow_list` ∪ `oidc_client.allowed_return_to` içinde birebir mutlak URL); göreli yollar `server.public_base_url`'e göre mutlak yapılır. `redirect_uri` her zaman `server.public_base_url`'den kurulur (`Host` başlığı kullanılmaz).

### Native (SOC-04)

İstemci `POST /v1/oauth/nonce {provider}` ile nonce alır ve platform SDK'sına **aynen** verir (Apple: `ASAuthorizationAppleIDRequest.nonce`; Google: Credential Manager `setNonce`). `POST /v1/oauth/{provider}/native {id_token, remember_me?, shared_device?, given_name?, family_name?, authorization_code?}` (`given_name`/`family_name` imzasız istemci girdisidir ve **yalnızca Apple** için kullanılır — Apple ID token'ı ad taşımaz; diğer sağlayıcılarda imzalı `name` claim'i geçerlidir): imza ve claim'ler doğrulanır (`aud`/`azp` ∈ yapılandırılmış `native_client_ids`), sonra token'daki nonce'un hash'iyle native nonce satırı atomik tüketilir (yalnızca bu sağlayıcının, süresi geçmemiş, kullanılmamış satırı). Web akışının nonce'u native akışta geçmez. `native_client_ids` boşsa ya da sağlayıcı GitHub ise `oauth_native_not_supported`.

**Apple yetkilendirme kodu (K-35):** iOS SDK'nın tek kullanımlık `authorizationCode`'u `authorization_code` olarak gönderilebilir (yalnızca Apple; diğer sağlayıcılarda yok sayılır, sağlayıcıya istek gitmez). ID token doğrulandıktan sonra kod Apple'ın token uç noktasında, ID token'ın `aud`'u olan **bundle id** ile (ES256 `client_secret`'in `sub`'u da bundle id; `redirect_uri`/PKCE yok) takas edilir; yanıttaki ID token doğrulanmalı ve **aynı `sub`'u** taşımalıdır (başka bir Apple hesabının kodu reddedilir). Yalnızca refresh token, `apple.revoke_tokens_on_deletion` (varsayılan açık) veya `store_provider_tokens` açıksa saklanır. Kod takası başarısız olursa giriş **başarısız olmaz** (kullanıcı zaten ID token ile doğrulandı); yalnızca loglanır ve o giriş için iptal edilecek token olmaz. Boyutu/biçimi geçersiz kod sağlayıcıya gönderilmez.

> Google Android'de `requestIdToken(serverClientId)` kullanılırsa token'ın `aud`'u sunucu (web) client id'sidir: bu durumda o kimlik `native_client_ids` listesine **bilinçli olarak** eklenmelidir (web akışının nonce'ları native akışta geçmediği için güvenlidir).

### Hesap eşleştirme (SOC-05) ve pre-hijacking (ADR 0002)

1. `(provider, subject)` bağlıysa o hesap; sağlayıcının bildirdiği e-posta hesabı **değiştirmez**. Genel sağlayıcılarda kimlik ayrıca oluşturulduğu **issuer**'a bağlıdır: bir slug'ın `issuer_url`'i değişirse eski kimlikle eşleşen giriş/bağlama `oauth_token_invalid` ile reddedilir (yeni issuer'ın `sub` ad alanı başka kişilere aittir).
2. Değilse sağlayıcı **doğrulanmış** bir e-posta bildirmelidir; değilse `oauth_email_not_verified` — bu karar **hiçbir hesap sorgusundan önce** verilir (yanıt, durum kodu ve süre var olan hesaplardan bağımsız).
3. Hesap açma authn-account'a aittir (K-02, K-33): `AccountService::provision_verified_user_in_tx` aynı transaction'da, adres kilidi (kayıt ve e-posta değişikliğiyle aynı advisory lock) altında karar verir — adrese ait hesap varsa `Existing` (aşağıdaki madde 4), adres e-posta değişikliğinin geri alma süresinde **rezerve** ise `Reserved` → `oauth_link_required` (hesap açılmaz; eski sahibin geri alması bozulmaz), alan adı tek kullanımlık e-posta listesindeyse `email_domain_not_allowed` (ACC-12), aksi hâlde hesap `active` + e-posta doğrulanmış açılır, **`user_profiles` satırı** (sağlayıcının görünen adı ACC-03 kurallarıyla normalize edilir — geçmezse ad saklanmaz —, isteğin dili, `UTC`) yazılır ve kimlik bağlanır (tek transaction; `account.registered`, `identity.linked` audit; `user.created` olayı). Rezervasyon için **kanca yoktur**: üretimde yanlışlıkla "rezervasyon yok" (fail-open) bağlanamaz.
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

- Bağlama: oturum (API anahtarı değil), yazılabilir principal (salt-okunur impersonation değil), `session.step_up_max_age` içinde kimlik doğrulama; hesap `active` ve e-postası doğrulanmış olmalı (`identity_link_not_allowed`). Tarayıcı bağlama akışı başlatan oturumun kimliğini `oauth_states.session_id`'de taşır; callback, kullanıcı satırı kilitliyken aynı bağlantıyla `SessionLiveness::is_active(conn, session, user, now)` sorar; oturum iptal edilmiş, süresi dolmuş veya başka kullanıcıya aitse `oauth_state_invalid` (K-03). Native bağlamada istek zaten oturumla gelir.
- Bildirimler (K-18): açık bağlama, otomatik bağlama ve ayırma, hesabın adresine `identity_linked` / `identity_unlinked` bildirimini (sağlayıcının görünen adı, dil profil dilinden) **aynı transaction'da** outbox'a yazar; reddedilen işlem bildirim üretmez. Sosyal kayıtla yeni açılan hesap bildirim almaz (var olan hesaba bir şey eklenmedi). Kimlik başka hesaba bağlıysa `identity_already_linked`; hesapta aynı sağlayıcıdan başka kimlik varsa `identity_provider_already_linked`. Bağlama transaction'ı kullanıcı satırını kilitler.
- Ayırma: aynı koşullar; transaction'ın **başında** `UserRepository::lock_for_update` (PWD-11 yarışı); son kimlikse `LoginMethodInventory::other_login_methods` aynı bağlantıdan okunur, başka yöntem yoksa `identity_last_login_method`. Başka kullanıcının/bilinmeyen kimlik `not_found`. Apple kimliği ayrılırken saklı refresh token'ı aynı transaction'da iptal kuyruğuna alınır (K-35).

### Apple token'ları ve iptal (SOC-07, SOC-08, K-35)

- **Saklama:** `store_provider_tokens` kapalıyken de Apple **refresh** token'ı (yalnızca o; access token değil), `apple.revoke_tokens_on_deletion = true` (varsayılan) ise saklanır — Apple, hesap silmeyi sunan uygulamalardan token iptali ister. Zarf şifreli, AAD = `identities`/`refresh_token_ciphertext`/satır; verildiği client id `identities.token_client_id`'de (migration `2102`). Web akışında services id, native kod takasında bundle id.
- **Kuyruk:** kimlik ortadan kalkarken (hesap silme — `AccountErasureHook`, silme transaction'ında kaskaddan **önce**; kimlik ayırma) token çözülür, yeni satıra bağlı AAD ile (`oauth_token_revocations`/`token_ciphertext`/satır) yeniden mühürlenir ve `oauth_token_revocations`'a yazılır. Kuyruk satırında kullanıcı kimliği yoktur. Çözülemeyen token (KEK kaldırılmış, bozuk satır) `identity.provider_token_revoked` başarısız (`provider_token_unreadable`) olarak audit'lenir ve atlanır; silmeyi ya da ayırmayı **engellemez** (ayırma tek bir başarılı `identity.unlinked` olarak kalır, K-60).
- **Yeniden giriş (K-59):** bir giriş saklı refresh token'ı yenisiyle değiştirdiğinde (ya da yapılandırma gereği sildiğinde) eski token Apple tarafında hâlâ geçerlidir. Bu yüzden aynı transaction'da aynı kuyruğa alınır. Kimlik satırı önce `FOR UPDATE` kilitlenir; eşzamanlı iki giriş, her biri gerçekten değiştirdiği token'ı kuyruğa alır. Sağlayıcı **aynı** token'ı yeniden verirse (sabit zamanlı karşılaştırma) iptal edilmez. Test: `soc_07_k59_relogin_queues_the_replaced_apple_token` (düzeltme olmadan kırmızı olduğu görüldü).
- **E-posta değişikliğinin geri alınması (K-20):** `remove_all_identities_in_tx(conn, ctx, user)` geri alma transaction'ında hesabın **tüm** kimliklerini kaldırır. Son giriş yöntemi kontrolü yapılmaz (sahip, geri yüklenen posta kutusu üzerinden şifre sıfırlamayla girer). Apple token'ı kuyruğa alınır, her kaldırma `identity.unlinked` (`Actor::System`, `reason = email_change_reverted`) olarak audit'lenir. Ayrı bildirim yoktur, geri alma bildirimi bunu kapsar. Server bunu `authn_account::EmailChangeRevertHook` olarak kaydeder. Test: `acc_07_k20_revert_removes_every_linked_identity_in_the_transaction`.
- **İş:** `OidcClientService::process_token_revocations(limit)` satırı tek `UPDATE … FOR UPDATE SKIP LOCKED` ile kiralar (çoklu instance güvenli; HTTP sırasında bağlantı/kilit tutulmaz), Apple `POST /auth/revoke`'u (`client_id`, ES256 `client_secret` — `sub` = token'ın client id'si —, `token`, `token_type_hint=refresh_token`) çağırır. `200` veya `400 invalid_grant` (zaten geçersiz) → satır silinir, `identity.provider_token_revoked` (`Actor::System`, `outcome`, `attempts`; K-60) audit'lenir. Diğer hatalar → üstel geri çekilmeyle yeniden denenir (1 dk'dan başlayıp ikiye katlanır, en çok 6 sa; `MAX_REVOCATION_ATTEMPTS` = 14 deneme ≈ 32 sa); son denemeden sonra satır silinir ve `provider_token_revocation_failed` olarak audit'lenir, `error` logu ve `authn_social_token_revocations_total{outcome="abandoned"}` metriği. Silme hiçbir durumda iptali beklemez.

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
| `jwks_max_staleness` | 24 sa (`jwks_cache_ttl` – 7 gün) | K-61: JWKS indirmesi başarısızken önbellekteki anahtarlar en fazla bu yaşa kadar kullanılır; sonrasında doğrulama kapalı başarısız olur (`service_unavailable`) |

Wave 2A'da eklenen anahtarlar:

| Anahtar | Varsayılan | Anlam |
|---------|-----------|-------|
| `error_redirect` | yok | Callback hatalarında tarayıcının gönderileceği sayfa (`?error=<kod>` eklenir); göreli güvenli yol veya izin listesinde mutlak https URL, açılışta doğrulanır (K-36). Yoksa JSON hata |
| `apple.private_key_ciphertext` | yok | Apple anahtarı zarf şifreli (base64; `[crypto]` KEK, sabit bağlam); `private_key_pem` / `private_key_file` ile **tam olarak biri** (K-34) |
| `apple.revoke_tokens_on_deletion` | **true** | Apple refresh token'ını (şifreli) hesap silme/ayırmada iptal için sakla (K-35) |

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
- **JWKS DoS:** bilinmeyen `kid` en fazla `jwks_refresh_min_interval`'de bir indirme tetikler; indirme başarısızsa önbellekteki anahtar en çok `jwks_max_staleness` (24 sa) yaşına kadar kullanılmaya devam eder (K-61). Başarısız indirmeler URL başına üstel geri çekilir (K-16): n. ardışık hatadan sonra `min(5 sn · 2^(n-1), 5 dk)` boyunca hiç istek yapılmaz — bayat anahtar varsa onunla doğrulanır, yoksa hemen `service_unavailable`; ilk başarılı indirme sayacı sıfırlar (`authn_social_jwks_failures_total{outcome=failed|backoff}`).
- **Microsoft kiracı sahteciliği:** `iss`, token'ın kendi `tid`'i (GUID biçimi zorunlu) ile `…/{tid}/v2.0` olmalı ve kiracı politikası/izin listesi `tid`'i kabul etmeli; subject `<tid>:<oid>`.
- **Hesap varlığı:** doğrulanmamış e-posta yanıtı hesap sorgusundan önce verilir (test: gövde, durum ve süre). `oauth_link_required` yalnızca adresin sahibi olduğunu sağlayıcıyla kanıtlamış kişiye döner (SOC-05'in tasarımı).
- **Audit:** başarısız sosyal girişler `login.failed` (kullanıcısız, `method=social`, sağlayıcı, kod) olarak kaydedilir; bilinmeyen sağlayıcı, native'i olmayan sağlayıcı ve rate limit'e takılan istekler anonim çağıranın audit zincirini büyütememesi için kaydedilmez. Kimliksiz uçların hepsi (başlatma, callback, nonce, native) IP başına sınırlıdır; dolayısıyla anonim bir çağıranın yazdırabileceği `login.failed` sayısı da sınırlıdır.
- **`Debug` çıktıları:** callback parametreleri (`code`, `state`, Apple `user`), native `authorization_code`, doğrulanmamış ID token, sağlayıcı yanıt gövdeleri, Apple özel anahtarı (PEM/şifreli değer) ve kuyruktaki token'lar `Debug`'da görünmez; Apple anahtarıyla ilgili hatalar yalnızca ayar adını söyler. Bağlama/ayırma `identity.linked`/`identity.unlinked`; impersonation altında ayırmada `impersonator` yazılır.

### Bağımsız güvenlik denetimi (2026-11-04)

Kodu yazmamış bir denetçi "zafiyetli, kanıtla" varsayımıyla inceledi. Doğrulanan her bulgu önce düzeltme olmadan **başarısız olan** bir regresyon testiyle kanıtlandı, sonra düzeltildi:

| # | Önem | Bulgu | Regresyon testi | Durum |
|---|------|-------|-----------------|-------|
| 1 | Orta | Web callback'i rate limit'siz ve kimliksizdi: rastgele, biçimce geçerli `state` değerleriyle sınırsız DB `UPDATE`'i ve sınırsız anonim `login.failed` audit kaydı (audit zinciri/DB şişirme; crate'in kendi "anonim çağıran audit'i büyütemez" kuralına aykırı) | `soc_02_callback_is_rate_limited_and_cannot_flood_the_audit` | Düzeltildi: `callback_per_ip` (60/10 dk), state sorgusundan önce |
| 2 | Düşük | `aud` dizisinde güvenilmeyen ek audience'lı token, `azp` bizimse kabul ediliyordu (OIDC Core 3.1.3.7 kural 3) | `soc_03_untrusted_extra_audiences_are_rejected`, `soc_03_azp_rules`, `soc_04_native_audience_is_the_native_client_ids` | Düzeltildi: her audience kabul edilen bir client id olmalı; dizi elemanı string değilse red |
| 3 | Orta | Kimlik yalnızca `(provider, subject)` ile eşleşiyordu; genel sağlayıcının `issuer_url`'i değişince (IdP göçü, eski IdP'nin ele geçirilmesi) yeni issuer'ın aynı `sub`'u eski kullanıcının hesabına giriyordu (hesap ele geçirme) | `soc_05_generic_identity_is_bound_to_its_issuer` | Düzeltildi: genel sağlayıcıda saklı issuer token'ınkiyle aynı olmalı (giriş ve bağlama) |
| 4 | Düşük | Native istekteki imzasız `given_name`/`family_name` her sağlayıcıda imzalı `name` claim'inin yerine geçiyor ve her girişte kimliğin görünen adını değiştiriyordu | `soc_07_native_client_name_is_only_used_for_apple` | Düzeltildi: yalnızca Apple |
| 5 | Düşük | `Debug` çıktısında sırlar: `CallbackParams` (`code`, `state`), `UnverifiedToken` (imzalı token'ın tamamı), `ProviderResponse` (token yanıtı gövdesi) | `soc_02_callback_params_debug_redacts_code_and_state`, `soc_03_unverified_token_debug_redacts_the_token`, `soc_08_provider_response_debug_redacts_the_body` | Düzeltildi: elle yazılmış `Debug` |

Ek: rezervasyon yolu hiç test edilmiyordu → `soc_05_reserved_address_gets_no_new_account` (wave 2A'da gerçek authn-account e-posta değişikliği rezervasyonuyla yeniden yazıldı; `AddressReservations`/`NoReservations` kaldırıldı, K-02).

İncelenip **sorun bulunmayan** başlıca alanlar: imza doğrulama (`openidconnect` `check_key_compatibility`: JWK `use`/`kty`/`alg`, EC eğrisi kontrolü), `kid` zorunluluğu, `crit`/`typ`, `exp`/`iat`/`nbf` + leeway, nonce (sabit zamanlı hash karşılaştırması), Microsoft `tid` GUID + `{tenantid}` şablonu + izin listesi + `<tid>:<oid>` + `xms_edov`, GitHub birincil+doğrulanmış e-posta, discovery (birebir issuer, `UserSupplied` uç noktalar, https, SSRF istemcisi yönlendirme izlemez), state tek kullanım (atomik `UPDATE … RETURNING`), sağlayıcıya bağlılık, `__Host-` bağlama çerezi ve çerez fırlatma, PKCE doğrulayıcısı AAD'si, `return_to` (ters bölü, `//`, userinfo, yüzde kodlama katmanları `authn-protect`'te; göreli yol `public_base_url`'e eklenir), sağlayıcı başına `redirect_uri` (mix-up), Apple `form_post` (CSRF koruması `state`+bağlama; `SameSite=None` çerez tek başına bir şey vermez), Apple `client_secret` yalnızca `p256` 0.14 (`cargo tree -i p256@0.14.0` → yalnızca bu crate; 0.13 yalnızca `openidconnect` açık anahtar doğrulamasında), hesap eşleştirme/ön ele geçirme (ADR 0002), bağlama/ayırma (step-up, IDOR, `lock_for_update`), SOC-08 zarf şifreleme (AAD satıra bağlı), SOC-09 (`amr: [fed]` sabit; sağlayıcı MFA'sı yalnızca yapılandırmayla, authn-session phishing-resistant gerekiyorsa yine yok sayar), yanıt boyutu (256 KiB) ve token boyutu (16 KiB) sınırları, panik yok.

### Wave 2A bağımsız denetimi (2026-11-04)

Wave 2A'yı yazmamış bir denetçi inceledi. Önce yazarın güvenlik açısından kritik testlerinin **eski davranışta gerçekten başarısız olduğu** düzeltme satırları geçici olarak geri alınarak doğrulandı (sonra geri yüklendi):

| Kalem | Geri alınan satır | Başarısız olan test(ler) |
|-------|-------------------|--------------------------|
| K-02 | `provision_verified_user_in_tx` içindeki rezervasyon kontrolü | `soc_05_reserved_address_gets_no_new_account`, authn-account `acc_07_provisioning_never_takes_an_existing_or_reserved_address` |
| K-03 | `link_identity` içindeki `SessionLiveness` kontrolü | `soc_06_link_callback_rejects_revoked_session`, `soc_06_link_callback_rejects_a_session_of_another_user` |
| K-36 | `error_redirect`'in açılışta redirect doğrulayıcısından geçmesi | `soc_02_error_redirect_cannot_be_an_open_redirect` |
| K-14 | `MailboxProof::Administrator` → `Actor::System` + istemci bağlamı yok | `adm_03_admin_verification_shows_no_staff_identity_in_the_users_view`, authn-account `adm_08_admin_mailbox_proof_shows_no_staff_identity_to_the_user` |
| K-35 | native kod takasında `sub` eşitliği | `soc_07_foreign_or_refused_apple_codes_store_nothing` |
| K-35 | refresh token'ın satır AAD'si (sabit bağlamla mühürlendi) | `soc_08_apple_refresh_token_is_kept_sealed_for_revocation`, `soc_08_stored_provider_tokens_are_envelope_encrypted_with_row_aad` |

Bulgular:

| # | Önem | Bulgu | Regresyon testi | Durum |
|---|------|-------|-----------------|-------|
| 2A-1 | Orta | **K-14 eksik kalmıştı:** yalnızca admin e-posta doğrulaması düzeltilmişti; admin askıya alma / askıdan çıkarma / kilit açma (`change_status_in_tx`, `Actor::System`) adminin IP'si ve user-agent'ını kullanıcının kendi `account.status_changed` olayına yazıyordu — audit sink bunu kullanıcının kişisel verisi olarak saklıyor, kullanıcının olay listesi maskeli gösteriyordu | authn-account `adm_08_staff_status_change_shows_no_staff_network_to_the_user` | Düzeltildi (authn-account `lifecycle::transition_event`): istemci IP/UA yalnızca aktör bir kullanıcı veya anonim ise eklenir; personel/sistem, servis hesabı ve API anahtarı işlemlerinde yalnızca istek kimliği kalır |
| 2A-2 | Düşük (işlevsel, fail-closed) | Adres kilidi (K-02/K-33) yüzünden aynı kimliğin eşzamanlı **ilk** girişinde (çift gönderim, uygulama yeniden denemesi) kilidi kaybeden istek, kazananın hesabını "var olan hesap" görüp kullanıcının kendi kimliğini `oauth_link_required` ile reddediyordu (eski kodda unique ihlali → yeniden deneme → giriş) | `soc_05_concurrent_first_sign_in_of_the_same_identity_signs_in` (deterministik: "kazanan" adres kilidini giriş bekleyene kadar tutar) | Düzeltildi: `Existing` dalında kimlik kilit altında yeniden aranır; bağlıysa karar yeniden çalışır |

Ek sertleştirme testi (bulgu yok, mevcut kodda geçer): `soc_02_error_redirect_variants_stay_on_allowed_origins` — `%2F%2F`, `%5C`, `/\/`, sekme/boşluk, CRLF ve `%0d%0a`, `..//`, `https:evil`, IDN/kiril homograf, büyük harfli host, userinfo (`@`), port, parça (`#@`) varyantları: açılışta kabul edilen her hedefin `Location`'ı bu sunucunun origin'inde veya tam izin listesi girdisinde kalır, kontrol karakteri içermez, yalnızca `error=<kod>` eklenir.

İncelenip sorun bulunmayan alanlar: adres kilidi + rezervasyon + ACC-12 sırası (kayıt, e-posta değişikliği ve sosyal kayıt aynı kilit sırasını kullanır: önce adres kilidi(leri), sonra kullanıcı satırı — kilitlenme yok); ADR 0002 ile etkileşim (bekleyen kayıt `pending_verification` hesap olarak `Existing` döner, otomatik bağlamada `confirm_mailbox_control_in_tx`); `Reserved` ve her `Existing` durumu aynı kodu döner; K-03 kontrolü kullanıcı satırı kilidi altında **aynı bağlantıda** (ikinci havuz bağlantısı yok), gerçek uygulayıcı `authn_session::is_session_active_in` kullanıcıyı, iptali, süreleri ve impersonation'ı kontrol eder; migration `2101` yalnızca yarıda kalmış bağlama state'lerini siler, CHECK kısıtları (`2100`, `2101`, `2102`) doğru; K-32'de bağlama akışı daima `false/false` yazar (CHECK ile de zorlanır), seçenekler oturum hattına yalnızca tarayıcının kendi girişi için gider (bağlama çerezi login CSRF'i engeller); K-34 zarfının bağlamı sabit ve tekil, hata/`Debug`'da anahtar yok, `build` hatada açılmaz; K-35 takasında `aud` = yapılandırılmış bundle id, `sub` eşitliği, hata girişi bozmaz ve hiçbir şey yazmaz; kuyruk satırında kullanıcı kimliği yok, `UPDATE … SKIP LOCKED` kiralama, HTTP sırasında bağlantı tutulmaz, deneme sayısı sınırlı, iptal SSRF-güvenli istemciyle, silme asla engellenmez, silme kancası silme transaction'ında; K-41 sorguları birebir aynı (koşullar, `SKIP LOCKED`, sıralama); üretim kodunda `unwrap/expect/panic` yok; SQL statik + bind.

### Kabul edilen riskler / sınırlamalar

Wave 1 ve wave 2A'dan sonra kapatılan maddeler (1–12) ve wave 2A denetiminin bilinçle kabul ettiği, gerekçeli kalan sınırlar (13–16):

1. ~~Genel OIDC sağlayıcısının `email_verified` beyanına koşulsuz güvenilir~~ — **kapatıldı (wave 1, K-04):** `generic[].trust_email_verified`, varsayılan `false`. Testler: `soc_05_generic_provider_email_is_unverified_unless_trusted`, `soc_05_untrusted_providers_never_create_accounts`, `soc_05_untrusted_providers_keep_linked_identities_and_reveal_no_accounts`.
2. ~~Web akışında `remember_me`/`shared_device` yok~~ — **kapatıldı (wave 2A, K-32):** migration `2100`, `start?remember_me=&shared_device=`; test `ses_06_web_social_login_carries_remember_me_and_shared_device`.
3. ~~Adres rezervasyonu `NoReservations` ile fail-open bağlanabilir~~ — **kapatıldı (wave 2A, K-02):** kanca kaldırıldı; rezervasyon authn-account'un `provision_verified_user_in_tx`'i içinde, adres kilidi altında okunur (yapılandırmayla kapatılamaz). Gerekçe: rezervasyon verisi authn-account'un tablosunda ve bu crate zaten authn-account'a bağımlı — ayrı bir kanca yalnızca yanlış bağlama imkânı ekliyordu. Testler: `soc_05_reserved_address_gets_no_new_account`, `soc_05_expired_reservation_no_longer_blocks_sign_up`.
4. ~~Bağlama/ayırma bildirimi yok~~ — **kapatıldı (wave 2A, K-18):** test `soc_06_link_and_unlink_notify_the_account_owner`, `soc_06_auto_link_is_announced_but_sign_up_is_not`.
5. ~~Yeni sosyal hesapta profil satırı yok~~ — **kapatıldı (wave 2A, K-33):** test `soc_05_new_social_account_gets_a_profile` (+ authn-account `acc_08_provisioned_social_account_gets_a_profile`).
6. ~~Apple özel anahtarı yalnızca PEM/dosya~~ — **kapatıldı (wave 1 + 2A, K-34):** `apple.private_key_ciphertext` (zarf şifreli, sabit bağlam `oidc_client`/`apple_private_key`/`apple`, `[crypto]` KEK), açılışta `OidcClientService::build` çözer; üretmek için `apple::seal_private_key`. Testler: `soc_07_envelope_encrypted_private_key_round_trip`, `soc_07_tampered_or_foreign_ciphertext_is_refused_without_detail`, `soc_07_service_build_decrypts_an_envelope_encrypted_apple_key`.
7. ~~Apple native kodu takas edilmez; silmede token iptali yok~~ — **kapatıldı (wave 2A, K-35):** yukarıdaki "Apple token'ları ve iptal". Kalan bilinçli sınır: native girişte istemci `authorization_code` göndermezse (ya da takas başarısız olursa) o giriş için iptal edilecek token yoktur; web akışında her zaman vardır. Yalnızca Apple token'ları iptal edilir (diğer sağlayıcılar silmede iptal şartı koymuyor; `store_provider_tokens` ile saklanan Google/Microsoft token'ları satırla birlikte silinir).
8. ~~Callback hataları yalnızca JSON~~ — **kapatıldı (wave 2A, K-36):** `oidc_client.error_redirect`; testler `soc_02_callback_errors_redirect_to_the_configured_error_page`, `soc_02_error_redirect_cannot_be_an_open_redirect`.
9. ~~Bağlama callback'inde oturum yeniden doğrulanmaz~~ — **kapatıldı (wave 2A, K-03):** migration `2101` + `SessionLiveness`; testler `soc_06_link_callback_rejects_revoked_session`, `soc_06_link_callback_rejects_a_session_of_another_user`, `soc_06_link_callback_with_live_session_links`. Migration, çalıştığı anda yarıda kalan bağlama akışlarını (en çok `state_ttl`) siler; kullanıcı bağlamayı yeniden başlatır.
10. ~~Microsoft kişisel hesap e-postası koşulsuz doğrulanmış~~ — **kapatıldı (wave 1, K-17).**
11. ~~JWKS indirmesi başarısızken geri çekilme yok~~ — **kapatıldı (wave 2A, K-16):** testler `soc_03_jwks_outage_backs_off_exponentially`, `soc_03_jwks_backoff_is_bounded_and_keeps_stale_keys`, `soc_03_jwks_backoff_is_exponential_and_bounded`.
12. ~~Kullanılmayan bağımlılıklar~~ — **kapatıldı (wave 2A, K-37):** `oauth2`, `subtle`, `axum-extra`, `reqwest`, `uuid`, `thiserror` kaldırıldı (hepsi workspace'te başka crate'lerce kullanıldığı için `Cargo.lock`'ta yalnızca iç kenarlar değişti).
13. ~~Tek kullanımlık alan adı yanıtı hesap varlığına bağlı~~: **kapatıldı (wave 3B, K-63).** `provision_verified_user_in_tx` (authn-account) alan adını artık her aramadan **önce**, yalnızca adrese bakarak karar verir. Engelli bir alan adındaki adresle gelen yeni kimlik, hesap ya da rezervasyon olsun olmasın aynı `422 email_domain_not_allowed`'ı alır: gövde, durum kodu ve süre aynıdır. Bedeli: liste güncellendikten sonra o alan adındaki mevcut bir hesap **yeni** bir sağlayıcıyı otomatik bağlamayla ekleyemez. Zaten bağlı kimlikle giriş ve oturum açıkken açık bağlama etkilenmez. Testler: `acc_12_k63_blocked_domain_answer_does_not_depend_on_accounts` (gövde, durum, `compare_timings`; düzeltme olmadan kırmızı olduğu görüldü, 409 ≠ 422), authn-account `acc_12_k63_blocked_domain_is_decided_before_the_account_lookup`.
14. ~~JWKS kesintisinde bayat anahtar süre sınırı olmadan kullanılır~~: **kapatıldı (wave 3B, K-61).** `oidc_client.jwks_max_staleness` (varsayılan 24 sa, `jwks_cache_ttl` ile 7 gün arası) aşılınca önbellekteki anahtar kullanılmaz. Hem başarısız indirmede hem geri çekilme sırasında doğrulama kapalı başarısız olur ve kararlı `service_unavailable` kodu döner (`authn_social_jwks_failures_total{outcome="stale_expired"}`, `warn` logu). Sağlayıcı yeniden yanıt verince ilk başarılı indirme düzeltir. Testler: `soc_03_k61_stale_keys_expire_after_the_max_staleness`, `soc_03_k61_default_max_staleness_is_a_day`, authn-core `soc_03_k61_jwks_max_staleness_default_and_bounds`. Kalan sınır: 24 saatten uzun bir sağlayıcı kesintisinde o sağlayıcıyla giriş durur (bilinçli, kapalı başarısızlık). Discovery belgesinin önbelleği bu kalemin kapsamı dışında; anahtarlar yine JWKS'ten bu sınırla gelir.
15. ~~Yeniden girişte önceki Apple refresh token'ı iptal edilmeden değiştirilir~~: **kapatıldı (wave 3B, K-59).** Yukarıdaki "Yeniden giriş".
16. ~~Kuyruk olayları `identity.unlinked` türünü yeniden kullanır~~: **kapatıldı (wave 3B, K-60).** Ayrı tür `identity.provider_token_revoked` (authn-core `SecurityEventKind::IdentityProviderTokenRevoked`): başarılı iptal, vazgeçilen iptal (`provider_token_revocation_failed`) ve çözülemeyen token (`provider_token_unreadable`). Ayırma anında token çözülemezse kullanıcı listesinde tek bir **başarılı** `identity.unlinked` ve doğru metinli ayrı bir başarısız token iptali kaydı görür, başarısız bir "ayırma" görmez. Test: `soc_06_k60_unreadable_token_is_not_shown_as_a_failed_unlink`.

Davranış notu: sosyal kayıt ACC-12 tek kullanımlık alan adı listesine de uyar (`email_domain_not_allowed`). K-63'ten beri bu kod hesap ve rezervasyon durumundan bağımsız döner.

## Server'ın bağlaması gerekenler

1. **Servis (async, açılışta):**
   ```rust
   let settings = authn_oidc_client::OidcClientSettings::from_app_config(&config);
   let oidc = authn_oidc_client::OidcClientService::build(
       authn_oidc_client::OidcClientServiceDeps {
           pool, clock, http /* SsrfSafeHttpClient */, envelopes: crypto.envelopes.clone(),
           rate_limiter, audit, events,
           sessions: session_service.clone() /* Arc<dyn SessionIssuer> */,
           accounts: account_service.clone(),
           login_methods: Arc::new(ServerLoginMethods { … }),
           session_liveness: Arc::new(ServerSessionLiveness { … }),
           notifier: notify.notifier_port(),
       },
       settings,
   ).await?; // Apple anahtarı (şifreliyse çözülür), Microsoft kiracı ayarı ve error_redirect açılışta doğrulanır (fail fast)
   account_service.register_erasure_hook(Arc::new(oidc.erasure_hook())); // K-35
   ```
   `impl FromRef<AppState> for OidcClientService`.
2. **Router ve OpenAPI:** `app.rs::module_routes`'a `.merge(authn_oidc_client::router::<AppState>())`; OpenAPI'ye `authn_oidc_client::OidcClientApi`. `/v1/me/identities*` oturum + CSRF katmanının arkasında; `/v1/oauth/*` kimliksiz.
3. **Kanca uygulamaları:**
   - `authn_oidc_client::LoginMethodInventory` — **yalnızca verilen `conn`'dan**: şifre (`UserRepository::find_password(conn, user)`) → `Password`; `WebauthnService::passkey_count_in(conn, user, true) > 0` → `Passkey`; kurulumda açıksa `MagicLink`/`EmailCode`. `Social` döndürmeyin.
   - `authn_oidc_client::SessionLiveness` (K-03) — authn-session üzerinden, **yalnızca verilen `conn`'dan**: oturum var, `user_id == user`, iptal edilmemiş, boşta/mutlak süresi `now`'da dolmamış ve impersonation oturumu değil → `true`. Varsayılan uygulama **yoktur** (bilinçli). Wave 2B ile kararlaştırılan authn-session fonksiyonu: `authn_session::is_session_active_in(conn, session, user, now) -> Result<bool, AuthError>` (yalnızca verilen bağlantı; sahibi askıya alınmış/kilitli ise de `false`); adaptör bunu birebir çağırır.
   - Adres rezervasyonu için kanca **yok** (K-02): authn-account servisi yeterli.
   - Diğer modüllerin kancalarında sosyal kimlik sayısı: `authn_password::LoginMethodInventory` ve `authn_webauthn::AccountMethodsSource` adaptörleri `OidcClientService::linked_identity_count_in(conn, user) > 0` ise `LoginMethod::Social` eklemeli (contracts §15.1).
4. **Veri dışa aktarma:** `AccountServiceDeps.exporters`'a `Arc::new(authn_oidc_client::IdentityDataExporter)` (bölüm adı `identities`).
5. **Arka plan işleri (OPS-06):** `OidcClientService::purge_expired_states(limit)` (ör. 5 dk) ve `OidcClientService::process_token_revocations(limit)` (K-35; ör. 1 dk, `limit = 100`); ikisi de çoklu instance güvenli.
6. **Açılış:** `authn_core::tls::install_crypto_provider()` (servis de çağırır); HTTP istemcisi `SsrfSafeHttpClient::new(&config.protect.outbound)`.
7. **CLI (K-34):** operatörün `apple.private_key_ciphertext` üretmesi için bir komut (ör. `seal-apple-key --pem-file …`) `authn_oidc_client::apple::seal_private_key(&crypto.envelopes, &pem)` çağırıp base64 değeri yazdırmalı. `rotate-kek`/`reencrypt` bu değeri ve `identities.refresh_token_ciphertext`, `oauth_token_revocations.token_ciphertext` kolonlarını da kapsamalı (bağlamlar yukarıda).
8. **authn-session ayarı:** `SessionSettings::trust_provider_mfa` zaten `oidc_client.trust_provider_mfa`'dan okunuyor; ek iş yok.

## Testler

```bash
cargo test -p authn-oidc-client --all-features
```

Gerçek PostgreSQL (`#[sqlx::test]`), gerçek SSRF korumalı HTTP istemcisi ve `wiremock` sahte sağlayıcılar (Google, Apple, Microsoft, GitHub, genel OIDC tek sunucuda yol önekleriyle). `tests/fixtures/` altındaki anahtarlar **yalnızca test** içindir (README'si orada).

| Gereksinim | Testler (seçme) |
|------------|-----------------|
| SOC-01 | `soc_01_generic_oidc_provider_uses_discovery_and_basic_auth`, `soc_01_generic_discovery_with_foreign_issuer_is_refused`, `soc_01_discovery_issuer_must_match_exactly`, `soc_01_github_login_uses_primary_verified_email`, `soc_01_microsoft_web_login_uses_tenant_issuer_and_tid_oid_subject`, `soc_01_unknown_provider_and_listing`, `soc_01_disabled_providers_are_absent` |
| SOC-02 | `soc_02_callback_errors_redirect_to_the_configured_error_page`, `soc_02_error_redirect_cannot_be_an_open_redirect`, `soc_02_error_redirect_variants_stay_on_allowed_origins`, `ses_06_web_social_login_carries_remember_me_and_shared_device`, `soc_02_google_web_login_creates_verified_account_and_logs_in`, `soc_02_state_replay_is_rejected`, `soc_02_concurrent_callbacks_consume_the_state_once`, `soc_02_callback_from_another_browser_is_rejected`, `soc_02_state_of_another_provider_is_rejected`, `soc_02_state_expires_after_ten_minutes`, `soc_02_nonce_mismatch_is_rejected`, `soc_02_pkce_or_code_rejected_by_provider_fails`, `soc_02_pkce_verifier_is_bound_to_its_state_row`, `soc_02_return_to_open_redirects_are_rejected`, `soc_02_pkce_s256_known_answer`, `soc_02_callback_is_rate_limited_and_cannot_flood_the_audit`, `soc_02_callback_params_debug_redacts_code_and_state` |
| SOC-03 | `soc_03_jwks_outage_backs_off_exponentially`, `soc_03_jwks_backoff_is_bounded_and_keeps_stale_keys`, `soc_03_wrong_issuer_audience_azp_expiry_and_future_iat_are_rejected`, `soc_03_alg_none_hmac_confusion_and_foreign_keys_are_rejected`, `soc_03_jwks_rotation_and_rate_limited_refresh`, `soc_03_microsoft_tenant_spoofing_and_allow_list`, `soc_03_microsoft_tenant_spoofing_is_rejected`, `soc_03_alg_confusion_jwk_algorithm_must_match_header`, `soc_03_untrusted_extra_audiences_are_rejected`, `soc_03_unverified_token_debug_redacts_the_token` |
| SOC-04 | `soc_04_google_native_login_with_server_nonce`, `soc_04_apple_microsoft_and_generic_native_logins`, `soc_04_nonce_is_mandatory_single_use_and_provider_bound`, `soc_04_native_audience_is_the_native_client_ids`, `soc_04_github_has_no_native_flow` |
| SOC-05 | `soc_05_identity_is_matched_by_subject_not_by_email`, `soc_05_concurrent_first_sign_in_of_the_same_identity_signs_in`, `soc_05_existing_account_is_never_merged_automatically_by_default`, `soc_05_auto_link_only_for_trusted_providers_and_verified_email`, `soc_05_pending_account_never_receives_an_identity_without_auto_link`, `soc_05_pre_hijacked_pending_account_is_reclaimed_by_the_mailbox_owner`, `soc_05_unverified_email_answer_does_not_reveal_accounts`, `soc_05_github_unverified_primary_email_cannot_create_an_account`, `soc_05_microsoft_work_account_email_is_unverified_without_xms_edov`, `soc_05_generic_identity_is_bound_to_its_issuer`, `soc_05_reserved_address_gets_no_new_account`, `soc_05_expired_reservation_no_longer_blocks_sign_up`, `soc_05_new_social_account_gets_a_profile` |
| SOC-06 / PWD-11 | `soc_06_link_callback_rejects_revoked_session`, `soc_06_link_callback_rejects_a_session_of_another_user`, `soc_06_link_callback_with_live_session_links`, `soc_06_link_and_unlink_notify_the_account_owner`, `soc_06_auto_link_is_announced_but_sign_up_is_not`, `soc_06_unlinking_apple_queues_the_token_revocation`, `soc_06_web_link_requires_step_up_and_links_on_callback`, `soc_06_native_link_rules`, `soc_06_unlink_never_removes_the_last_login_method`, `soc_06_foreign_and_unknown_identities_answer_not_found`, `soc_06_identity_routes_require_a_user_session`, `pwd_11_concurrent_unlinks_cannot_strand_the_account`, `pwd_11_unlink_and_password_removal_serialize_on_the_user_row` |
| SOC-07 | `soc_07_native_apple_code_is_exchanged_as_the_bundle_id`, `soc_07_foreign_or_refused_apple_codes_store_nothing`, `soc_07_client_secret_is_signed_per_configured_client_id`, `soc_07_envelope_encrypted_private_key_round_trip`, `soc_07_tampered_or_foreign_ciphertext_is_refused_without_detail`, `soc_07_service_build_decrypts_an_envelope_encrypted_apple_key`, `soc_07_revocation_backoff_is_exponential_and_bounded`, `soc_07_apple_form_post_login_with_es256_client_secret_and_first_name`, `soc_07_client_secret_is_es256_signed_with_apple_claims`, `soc_07_client_secret_is_cached_and_renewed_before_expiry`, `soc_07_native_client_name_is_only_used_for_apple` |
| SOC-08 | `soc_08_apple_refresh_token_is_kept_sealed_for_revocation`, `soc_08_apple_token_is_not_kept_when_revocation_is_off`, `soc_08_provider_tokens_are_not_stored_by_default`, `soc_08_stored_provider_tokens_are_envelope_encrypted_with_row_aad`, `soc_08_turning_storage_off_clears_tokens_on_next_login`, `soc_08_provider_response_debug_redacts_the_body` |
| ACC-09 / ADM-03 (çapraz) | `acc_09_account_deletion_revokes_the_apple_token`, `acc_09_revocation_failures_are_retried_then_audited_never_blocking`, `adm_03_admin_verification_shows_no_staff_identity_in_the_users_view` (K-14; gerçek authn-audit sink'i ve kullanıcı görünümüyle) |
| SOC-09 | `soc_09_provider_mfa_is_not_trusted_by_default`, `soc_09_provider_mfa_is_forwarded_only_when_trusted`, `soc_09_mfa_challenge_is_returned_instead_of_a_session` |

## Açık işler (sözleşme değişikliği talepleri)

İlk sürümdeki yedi talebin hepsi uygulandı (wave 1: hata kodları, `[oidc_client]` alanları, `trust_email_verified`; wave 2A: migration `2100`/`2101`/`2102`, authn-account rezervasyon + sağlama API'si, bağlama/ayırma bildirimleri, oturum bağlılığı). Kalan tek dış bağımlılık sunucu bağlamasıdır (K-51): `SessionLiveness` adaptörü `authn_session::is_session_active_in`'i (wave 2B) çağırır. Ayrıntı: [`docs/architecture/contract-change-requests.md`](../../docs/architecture/contract-change-requests.md) `## authn-oidc-client`.

## Komutlar

```bash
cargo fmt -p authn-oidc-client
cargo clippy -p authn-oidc-client --all-targets --all-features -- -D warnings
cargo test -p authn-oidc-client --all-features
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
