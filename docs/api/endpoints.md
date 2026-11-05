# Endpoint referansı (DOC-04)

> **Üretilmiş dosya — elle düzenlemeyin.** Kaynak: [`openapi.json`](openapi.json) (sunucunun birleşik OpenAPI belgesi) ve `generate_reference.py` içindeki Türkçe açıklamalar. Yeniden üretmek için [README](README.md#openapi-belgesini-yenilemek).

Toplam **163** işlem. İstek/yanıt şemalarının tamamı, alan açıklamaları ve her yanıt kodunun İngilizce açıklaması `openapi.json`'dadır.

**Kimlik sütunu** (her işlemin OpenAPI `security` bildiriminden üretilir; K-129): `—` kimlik doğrulaması yok · `oturum` web oturum çerezi (+ durum değiştiren yöntemlerde CSRF) veya `Authorization: Bearer <access token>` · `oturum / API anahtarı` ek olarak organizasyon API anahtarı (`Authorization: Bearer ak_…` / `X-API-Key`) · `admin` platform admini, passkey oturumu + step-up (+ `admin.ip_allow_list`) · `API anahtarı` yalnızca organizasyon API anahtarı · `challenge token'ı` bekleyen girişin token'ı (web: `__Host-authn_challenge` çerezi, native: `X-Authn-Challenge` başlığı). Ayrıntı: [authentication.md](authentication.md). "step-up" = son `session.step_up_max_age` içinde yeniden doğrulama, yoksa `401 step_up_required`.

`GET /openapi.json` (yalnızca `server.openapi_enabled = true` iken) belgenin kendisidir ve listede yoktur.

## Oturum ve token'lar (`session`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /.well-known/jwks.json` | — | Access token doğrulaması için Ed25519 açık anahtarları (`pending`, `active` ve yayım süresi dolmamış `retired`). `Cache-Control: public, max-age=<crypto.signing_keys.jwks_cache_ttl>`. | — | `200` |
| `GET /v1/csrf` | — | Oturum varsa oturumun CSRF token'ını, yoksa giriş formları için pre-session token'ını verir (gerekirse `__Host-authn_csrf` çerezini yazar). | — | `200` |
| `POST /v1/logout` | oturum | Oturumu ve refresh token'larını kapatır; web'de çerez silinir ve `Clear-Site-Data: "cookies"` gönderilir. | — | `204` `401` `403` |
| `POST /v1/logout/all` | oturum | Her yerden çıkış: kullanıcının tüm oturumları ve güvenilir cihazları. | — | `204` `401` `403` |
| `GET /v1/me` | oturum | Oturumdaki kullanıcı (SES-16). | — | `200` `401` |
| `GET /v1/me/sessions` | oturum | Canlı oturumlar (SES-11). | — | `200` `401` |
| `POST /v1/me/sessions/revoke-others` | oturum | Diğer tüm oturumları ve güvenilir cihazları kapatır. | — | `200` `401` `403` |
| `DELETE /v1/me/sessions/{session_id}` | oturum | Kendi oturumlarından birini kapatır; başkasınınki `404`. | — | `204` `401` `403` `404` |
| `POST /v1/reauth` | oturum | Step-up yeniden kimlik doğrulama (SES-13: `password`, `totp`, `recovery_code`, `passkey`); oturumu döndürür. | `StepUpProof` | `200` `401` `403` `429` |
| `POST /v1/reauth/passkey/options` | oturum | Oturuma bağlı passkey step-up seremonisi başlatır. | — | `200` `400` `401` `403` |
| `POST /v1/session/org` | oturum | Aktif organizasyonu değiştirir (SES-17); oturumu döndürür. | `OrgSwitch` | `200` `401` `403` `404` |
| `POST /v1/token/introspect` | API anahtarı | Token introspection (RFC 7662): istemci org API anahtarıyla doğrulanır, yalnızca kendi organizasyonunun token'larını görür. | `IntrospectionRequest` (application/x-www-form-urlencoded) | `200` `401` `429` |
| `POST /v1/token/refresh` | — | Refresh token rotasyonu (SES-05); tekrar kullanılan token tüm aileyi iptal eder; her hata `invalid_refresh_token`. | `RefreshRequest` | `200` `401` `429` |

## Giriş akışları (`login`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `POST /v1/login/challenge/passkey/options` | challenge token'ı | Bekleyen girişin ikinci faktör adımı için passkey seremonisi başlatır. | — | `200` `401` `403` |
| `POST /v1/login/challenge/passkey/register/options` | challenge token'ı | Bekleyen girişin `enroll_mfa` adımında (izinli faktörler `webauthn` içeriyorsa, `verify_mfa` bittikten sonra) passkey kayıt seremonisi başlatır; seremoni bu challenge'a, kullanıcıya ve bağlama token'ına bağlıdır, kuruluşların en katı AAGUID politikası uygulanır (K-112). | — | `200` `401` `403` `409` `429` |
| `POST /v1/login/challenge/passkey/register/verify` | challenge token'ı | Passkey kaydını bitirir; passkey challenge ilerlemesiyle aynı transaction'da saklanır ve bu girişin ikinci faktörü sayılır (`mfa_factors`: `webauthn`). Tek kullanımlık; başka challenge'ın seremonisi reddedilir (K-112). | `PasskeyEnrollmentVerify` | `200` `400` `401` `403` `409` |
| `POST /v1/login/challenge/send-code` | challenge token'ı | Bekleyen girişte geçerli faktör adımı için kod gönderir (`email`, `sms`, `email_confirmation`). | `SendCodeChannel` | `202` `401` `403` `429` |
| `POST /v1/login/challenge/step` | challenge token'ı | Bekleyen girişin zorunlu adımını yapar (SES-22): `change_password`, `accept_terms`, `enroll_totp`/`enroll_email`/`enroll_sms`, `confirm_enrollment`. | `ChallengeStep` | `200` `401` `403` `422` |
| `POST /v1/login/challenge/verify` | challenge token'ı | Bekleyen girişin ikinci faktörünü doğrular (`totp`, `recovery_code`, `email`, `sms`, `passkey`, `email_confirmation`; isteğe bağlı `trust_device`). | `FactorSubmission` | `200` `400` `401` `403` `429` |
| `POST /v1/login/email-code` | — | E-posta ile giriş kodu ister (SES-19); her adres için aynı yanıt (`202`). | `MagicLinkRequest` | `202` `403` `429` |
| `POST /v1/login/email-code/verify` | — | E-postadaki kodla giriş yapar; tüm hatalar tek tip `invalid_code`. | `EmailCodeVerify` | `200` `400` |
| `POST /v1/login/magic-link` | — | Magic link ister (SES-18); her adres için aynı yanıt (`202`). | `MagicLinkRequest` | `202` `403` `422` `429` |
| `POST /v1/login/magic-link/verify` | — | Magic link token'ıyla giriş yapar (yalnızca POST); başka cihazda açılırsa `409 magic_link_confirmation_required`. | `MagicLinkVerify` | `200` `400` `409` |
| `POST /v1/login/not-me` | — | "Bu ben değilim" (RSK-04): tüm oturumlar ve güvenilir cihazlar kapanır, şifre değişikliği zorunlu olur. | `NotMeRequest` | `200` `400` |
| `POST /v1/login/passkey` | — | Passkey girişini tamamlar (SES-20, SES-21). | `PasskeyLogin` | `200` `401` `403` |
| `POST /v1/login/passkey/options` | — | Kullanıcı adsız passkey girişi başlatır (`conditional_ui` ile otomatik doldurma). | `PasskeyLoginOptions` | `200` `403` `429` |
| `POST /v1/login/password` | — | E-posta + şifre ile giriş (SES-01): `authenticated` (oturum/token) veya `challenge_required`. | `PasswordLogin` | `200` `401` `403` `429` |

## Şifre (`password`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `POST /v1/me/password` | oturum | Şifresiz hesaba şifre ekler (PWD-10; step-up). | `AddPasswordRequest` | `204` `401` `409` `422` |
| `DELETE /v1/me/password` | oturum | Şifreyi kaldırır (PWD-11; step-up + başka güçlü yöntem: passkey veya bağlı kimlik). | — | `204` `401` `409` |
| `POST /v1/me/password/change` | oturum | Şifre değiştirir (PWD-06): mevcut şifre veya yakın step-up; diğer oturumlar kapanır. | `ChangePasswordRequest` | `204` `401` `403` `409` `422` `429` |
| `POST /v1/password/check` | — | Kayıt/değişiklik formları için canlı şifre politikası denetimi (IP başına sınırlı; şifre loglanmaz). | `CheckPasswordRequest` | `200` `422` `429` `503` |
| `POST /v1/password/forgot` | — | Şifre sıfırlama ister; hesap olsun olmasın aynı yanıt, durum ve süre (`202`). | `ForgotPasswordRequest` | `202` `422` `429` |
| `POST /v1/password/reset` | — | Link token'ı veya e-posta + kodla sıfırlamayı tamamlar; tüm oturumlar, refresh token'lar ve güvenilir cihazlar kapanır, oturum açılmaz. | `ResetPasswordRequest` | `200` `400` `422` `429` |

## Hesap (`account`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `POST /v1/account/deletion/cancel` | — | E-postadaki linkin token'ıyla planlanmış hesap silmesini iptal eder (ACC-09). | `TokenRequest` | `200` `400` `429` |
| `POST /v1/email/change/confirm` | oturum | Yeni adrese giden linkle e-posta değişikliğini onaylar (ACC-07); hesap sahibinin oturumu gerekir. | `TokenRequest` | `200` `400` `401` `403` `429` |
| `POST /v1/email/change/revert` | — | Eski adrese giden linkle değişikliği geri alır: adres geri gelir, her yerden çıkış, şifre sıfırlama zorunlu. | `TokenRequest` | `200` `400` `409` `429` |
| `POST /v1/email/verification/resend` | — | Doğrulama e-postasını yeniden gönderir; her adres için aynı yanıt (`202`). | `EmailRequest` | `202` `422` `429` |
| `POST /v1/email/verify` | — | Adresi link veya kodla doğrular ve kaydı tamamlar (ADR 0002): link + kayıt tutamacı/çerez, + kayıttaki şifre (`password`) veya + yeni şifre (`new_password`). Oturum açmaz. | `VerifyEmailRequest` | `200` `400` `403` `409` `422` `429` |
| `DELETE /v1/me` | oturum | Hesap silmeyi planlar (ACC-09; step-up). Bekleme süresi `account.deletion_grace_period`. | — | `202` `401` `403` `409` |
| `GET /v1/me/consents` | oturum | Kullanıcının kayıtlı şart/gizlilik politikası onayları (ACC-11). | — | `200` |
| `POST /v1/me/consents` | oturum | Güncel belge sürümlerini kabul eder; IP ve user agent kaydedilir. | `ConsentRequest` | `204` `409` `422` |
| `GET /v1/me/deletion` | oturum | Planlanmış hesap silmesi (yoksa `404`). | — | `200` `404` |
| `POST /v1/me/deletion/cancel` | oturum | Planlanmış silmeyi oturumdan iptal eder. | — | `200` `409` |
| `POST /v1/me/email` | oturum | E-posta değişikliği ister (ACC-07; step-up); yeni adres uygun olsun olmasın aynı yanıt. | `EmailChangeRequest` | `202` `401` `422` `429` |
| `POST /v1/me/email/confirm` | oturum | Yeni adrese giden kodla e-posta değişikliğini onaylar. | `CodeRequest` | `200` `400` `429` |
| `POST /v1/me/email/verification` | oturum | Oturumdaki kullanıcıya doğrulama e-postasını yeniden gönderir. | — | `202` `409` `429` |
| `POST /v1/me/email/verify` | oturum | Oturumdaki kullanıcının adresini kodla doğrular (ACC-04, ACC-05 `limited` modu). | `CodeRequest` | `200` `400` `409` `429` |
| `POST /v1/me/export` | oturum | Tüm kişisel verinin makinece okunur dışa aktarımı (ACC-10; step-up; gövdesiz `POST`, `GET` → `405`). | — | `200` `401` `403` `405` `429` |
| `GET /v1/me/profile` | oturum | Profil (ACC-08). | — | `200` `401` |
| `PATCH /v1/me/profile` | oturum | Görünen ad, dil ve saat dilimini günceller. | `ProfileUpdate` | `200` `422` |
| `POST /v1/signup` | — | Hesap kaydı (ACC-01): adres kayıtlı olsun olmasın aynı yanıt; kayıt tutamacı gövdede ve `__Host-authn_registration` çerezinde. | `SignupInput` | `202` `400` `403` `409` `422` `429` `503` |
| `GET /v1/terms` | — | Güncel kullanım şartları / gizlilik politikası sürümleri. | — | `200` |

## MFA (`mfa`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/me/mfa` | oturum | MFA durumu: faktörler (sırsız, maskeli iletişim), kurtarma kodu sayaçları, güvenilir cihaz sayısı. | — | `200` `401` |
| `POST /v1/me/mfa/email` | oturum | Hesap adresinde e-posta OTP faktörünü başlatır ve onay kodu gönderir (step-up). | — | `202` `401` `403` `409` `429` |
| `DELETE /v1/me/mfa/factors/{factor_id}` | oturum | Faktörü kaldırır (step-up); politika MFA isterken son kullanılabilir faktör kaldırılamaz. | — | `204` `401` `404` `409` |
| `POST /v1/me/mfa/factors/{factor_id}/confirm` | oturum | Bekleyen faktörü kodla onaylar; ilk faktörde kurtarma kodları bir kez döner (step-up). | `ConfirmFactorRequest` | `200` `400` `401` `404` `409` `429` |
| `POST /v1/me/mfa/factors/{factor_id}/resend` | oturum | Bekleyen e-posta/SMS faktörü için yeni onay kodu gönderir (step-up). | — | `202` `401` `404` `409` `429` |
| `GET /v1/me/mfa/recovery-codes` | oturum | Kurtarma kodu sayaçları (MFA-04). | — | `200` `401` |
| `POST /v1/me/mfa/recovery-codes` | oturum | Yeni kurtarma kodları üretir, eskileri geçersiz (step-up; bir kez gösterilir). | — | `201` `401` `403` |
| `POST /v1/me/mfa/sms` | oturum | SMS faktörü başlatır (E.164, izinli ülke; step-up). | `BeginSmsRequest` | `202` `401` `403` `409` `422` `429` |
| `POST /v1/me/mfa/totp` | oturum | TOTP kaydı başlatır: sır, `otpauth://` URI ve QR bir kez döner (step-up). | `BeginTotpRequest` | `201` `401` `409` `422` |
| `GET /v1/me/mfa/trusted-devices` | oturum | Güvenilir cihazlar (MFA-09). | — | `200` `401` |
| `DELETE /v1/me/mfa/trusted-devices` | oturum | Tüm güvenilir cihazları iptal eder. | — | `200` `401` |
| `DELETE /v1/me/mfa/trusted-devices/{device_id}` | oturum | Tek bir güvenilir cihazı iptal eder. | — | `204` `401` `404` |

## Passkey yönetimi (`passkeys`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/me/passkeys` | oturum | Passkey listesi (PKY-04). | — | `200` `401` |
| `POST /v1/me/passkeys/registration/options` | oturum | Passkey kaydı başlatır: `navigator.credentials.create()` / platform API'leri için `CredentialCreationOptions`. | `RegistrationOptionsRequest` | `200` `401` `403` `409` `422` `429` |
| `POST /v1/me/passkeys/registration/verify` | oturum | Doğrulayıcı yanıtını doğrular ve passkey'i kaydeder. | `RegistrationVerifyRequest` | `201` `400` `403` `409` |
| `PATCH /v1/me/passkeys/{passkey_id}` | oturum | Passkey'i yeniden adlandırır. | `RenamePasskeyRequest` | `200` `404` `422` |
| `DELETE /v1/me/passkeys/{passkey_id}` | oturum | Passkey'i siler (step-up). | — | `204` `401` `404` `409` |

## Well-known belgeleri (`well-known`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /.well-known/apple-app-site-association` | — | iOS/macOS ilişkilendirme dosyası: `webcredentials` (passkey) ve `app_link_paths` varsa `applinks`. `webauthn.apple_app_ids` boşsa `404`. | — | `200` `404` |
| `GET /.well-known/assetlinks.json` | — | Android Digital Asset Links: `get_login_creds` (passkey / Credential Manager), `app_link_paths` varsa `handle_all_urls`. `webauthn.android_apps` boşsa `404`. | — | `200` `404` |
| `GET /.well-known/webauthn` | — | WebAuthn Related Origin Requests belgesi (`{"origins": [...]}`). `webauthn.related_origins` boşsa `404`. | — | `200` `404` |

## Organizasyonlar (B2B) (`organizations`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `POST /v1/invitations/accept` | oturum | Daveti kabul eder (ORG-05); hesabın doğrulanmış adresi davet adresiyle eşleşmeli. | `InvitationToken` | `200` `400` `403` `409` `429` |
| `POST /v1/invitations/preview` | oturum | Davetin neyi verdiğini gösterir (organizasyon adı, rol, maskeli adres, adres eşleşiyor mu). | `InvitationToken` | `200` `400` `429` |
| `GET /v1/org-permissions` | oturum | İzin kataloğu (ORG-03). | — | `200` `401` |
| `GET /v1/orgs` | oturum | Kullanıcının organizasyonları (sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `401` `403` |
| `POST /v1/orgs` | oturum | Organizasyon kurar; çağıran `owner` olur. | `CreateOrganization` | `201` `401` `403` `409` `422` `429` |
| `GET /v1/orgs/{org_id}` | oturum / API anahtarı | Organizasyonu okur (`org:read`). | — | `200` `401` `403` `404` |
| `PATCH /v1/orgs/{org_id}` | oturum / API anahtarı | Ad / slug değiştirir (`org:update`). | `UpdateOrganization` | `200` `403` `404` `409` `422` |
| `DELETE /v1/orgs/{org_id}` | oturum / API anahtarı | Organizasyon silmeyi planlar (sahip + step-up, ORG-12). | — | `202` `401` `403` `404` `409` |
| `GET /v1/orgs/{org_id}/api-keys` | oturum / API anahtarı | API anahtarlarını listeler (`api_keys:read`; sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `404` |
| `POST /v1/orgs/{org_id}/api-keys` | oturum / API anahtarı | API anahtarı oluşturur (`api_keys:manage` + step-up); anahtar bir kez gösterilir. | `CreateApiKey` | `201` `401` `403` `404` `409` `422` |
| `GET /v1/orgs/{org_id}/api-keys/{key_id}` | oturum / API anahtarı | API anahtarı üst verisi (`api_keys:read`). | — | `200` `404` |
| `DELETE /v1/orgs/{org_id}/api-keys/{key_id}` | oturum / API anahtarı | API anahtarını iptal eder (`api_keys:manage`). | — | `200` `404` |
| `POST /v1/orgs/{org_id}/api-keys/{key_id}/rotate` | oturum / API anahtarı | API anahtarını döndürür (`api_keys:manage` + step-up); eskisi `org.api_keys.rotation_grace` boyunca çalışır. | `RotateApiKey` | `201` `401` `403` `404` `409` |
| `POST /v1/orgs/{org_id}/deletion/cancel` | oturum / API anahtarı | Planlanmış organizasyon silmesini iptal eder (sahip + step-up). | — | `200` `401` `403` `404` `409` |
| `GET /v1/orgs/{org_id}/domains` | oturum / API anahtarı | Domain'leri listeler (`domains:read`). | — | `200` `404` |
| `POST /v1/orgs/{org_id}/domains` | oturum / API anahtarı | Domain ekler (`domains:manage`); yanıt yayımlanacak TXT kaydını söyler. | `AddDomain` | `201` `404` `409` `422` |
| `PATCH /v1/orgs/{org_id}/domains/{domain_id}` | oturum / API anahtarı | Otomatik katılımı açar/kapatır (`domains:manage`). | `UpdateDomain` | `200` `404` `409` |
| `DELETE /v1/orgs/{org_id}/domains/{domain_id}` | oturum / API anahtarı | Domain'i kaldırır (`domains:manage`). | — | `204` `404` |
| `POST /v1/orgs/{org_id}/domains/{domain_id}/verify` | oturum / API anahtarı | DNS TXT kaydını denetler (`domains:manage`, ORG-06). | — | `200` `404` `409` `422` `429` `503` |
| `GET /v1/orgs/{org_id}/invitations` | oturum / API anahtarı | Davetleri listeler (`members:invite`; sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `404` |
| `POST /v1/orgs/{org_id}/invitations` | oturum / API anahtarı | Adres davet eder (`members:invite`; `owner` daveti step-up ister). | `CreateInvitation` | `201` `403` `404` `409` `422` `429` |
| `DELETE /v1/orgs/{org_id}/invitations/{invitation_id}` | oturum / API anahtarı | Bekleyen daveti iptal eder. | — | `204` `404` `409` |
| `POST /v1/orgs/{org_id}/invitations/{invitation_id}/resend` | oturum / API anahtarı | Daveti yeni token'la yeniden gönderir (eskisi geçersiz). | — | `200` `404` `409` `429` |
| `POST /v1/orgs/{org_id}/leave` | oturum / API anahtarı | Organizasyondan ayrılır (son sahip ayrılamaz). | — | `204` `404` `409` |
| `GET /v1/orgs/{org_id}/members` | oturum / API anahtarı | Üyeleri listeler (`members:read`; sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `403` `404` |
| `GET /v1/orgs/{org_id}/members/{member_id}` | oturum / API anahtarı | Üyeyi okur (`members:read`). | — | `200` `404` |
| `PATCH /v1/orgs/{org_id}/members/{member_id}` | oturum / API anahtarı | Üyenin rolünü/durumunu değiştirir (`members:update`; yükseltme koruması, son sahip koruması; `owner` vermek step-up ister). | `UpdateMember` | `200` `401` `403` `404` `409` |
| `DELETE /v1/orgs/{org_id}/members/{member_id}` | oturum / API anahtarı | Üyeyi çıkarır (`members:remove`). | — | `204` `403` `404` `409` |
| `POST /v1/orgs/{org_id}/ownership-transfer` | oturum / API anahtarı | Sahiplik devri başlatır (sahip + step-up, ORG-11). | `RequestOwnershipTransfer` | `202` `401` `403` `404` `422` `429` |
| `DELETE /v1/orgs/{org_id}/ownership-transfer` | oturum / API anahtarı | Bekleyen sahiplik devirlerini iptal eder (sahip). | — | `204` `403` `404` |
| `GET /v1/orgs/{org_id}/policy` | oturum / API anahtarı | Güvenlik politikasını okur (`policies:read`). | — | `200` `404` |
| `PUT /v1/orgs/{org_id}/policy` | oturum / API anahtarı | Güvenlik politikasını tamamen değiştirir (`policies:manage` + step-up); çağıranı kilitleyecek politika `422 org_policy_lockout`. | `OrgPolicyInput` | `200` `401` `404` `422` |
| `GET /v1/orgs/{org_id}/roles` | oturum / API anahtarı | Yerleşik ve özel roller (`roles:read`). | — | `200` `404` |
| `POST /v1/orgs/{org_id}/roles` | oturum / API anahtarı | Özel rol oluşturur (`roles:manage`). | `CreateRole` | `201` `403` `404` `409` `422` |
| `PATCH /v1/orgs/{org_id}/roles/{role_id}` | oturum / API anahtarı | Özel rolü değiştirir. | `UpdateRole` | `200` `403` `404` `409` |
| `DELETE /v1/orgs/{org_id}/roles/{role_id}` | oturum / API anahtarı | Kullanılmayan özel rolü siler. | — | `204` `404` `409` |
| `GET /v1/orgs/{org_id}/service-accounts` | oturum / API anahtarı | Servis hesaplarını listeler (`service_accounts:read`; sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `404` |
| `POST /v1/orgs/{org_id}/service-accounts` | oturum / API anahtarı | Servis hesabı oluşturur (`service_accounts:manage`). | `CreateServiceAccount` | `201` `403` `404` `409` `422` |
| `GET /v1/orgs/{org_id}/service-accounts/{service_account_id}` | oturum / API anahtarı | Servis hesabını okur. | — | `200` `404` |
| `PATCH /v1/orgs/{org_id}/service-accounts/{service_account_id}` | oturum / API anahtarı | Servis hesabını değiştirir. | `UpdateServiceAccount` | `200` `403` `404` `409` |
| `DELETE /v1/orgs/{org_id}/service-accounts/{service_account_id}` | oturum / API anahtarı | Servis hesabını ve anahtarlarını siler. | — | `204` `403` `404` |
| `POST /v1/ownership-transfers/accept` | oturum | Sahiplik devrini kabul eder (hedef kullanıcı + step-up). | `AcceptOwnershipTransfer` | `200` `400` `401` `429` |

## Kötüye kullanım koruması (`protect`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/captcha/challenge` | — | Bir eylem (`?action=`) için CAPTCHA challenge'ı verir (PoW sağlayıcısında bulmaca; diğerlerinde site anahtarı).<br>Sorgu: `action` | — | `200` `422` `429` `5XX` |

## Audit (`audit`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/me/security-events` | oturum | Kullanıcının son 90 günlük güvenlik olayları (AUD-04; sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `401` `403` `422` `429` |
| `GET /v1/orgs/{org_id}/audit-events` | oturum / API anahtarı | Organizasyonun audit log'u, filtreli (AUD-04; sayfalı).<br>Sorgu: `limit`, `cursor`, `kind`, `category`, `outcome`, `actor_user_id`, `resource_type`, `since`, `until` | — | `200` `401` `404` `422` `429` |

## Webhook'lar (`webhooks`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/orgs/{org_id}/webhooks` | oturum / API anahtarı | Webhook uç noktalarını listeler (AUD-07). | — | `200` `404` |
| `POST /v1/orgs/{org_id}/webhooks` | oturum / API anahtarı | Webhook uç noktası oluşturur; imza sırrı (`whsec_…`) bir kez döner (step-up). | `CreateWebhookEndpoint` | `201` `401` `403` `404` `409` `422` `429` |
| `GET /v1/orgs/{org_id}/webhooks/{endpoint_id}` | oturum / API anahtarı | Tek webhook uç noktası. | — | `200` `404` |
| `PATCH /v1/orgs/{org_id}/webhooks/{endpoint_id}` | oturum / API anahtarı | Uç noktayı değiştirir (URL, abonelik, etkinleştirme step-up ister). | `UpdateWebhookEndpoint` | `200` `401` `403` `404` `422` |
| `DELETE /v1/orgs/{org_id}/webhooks/{endpoint_id}` | oturum / API anahtarı | Uç noktayı ve teslim geçmişini siler (step-up). | — | `204` `401` `404` |
| `GET /v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` | oturum / API anahtarı | Teslim geçmişi (sayfalı).<br>Sorgu: `limit`, `cursor` | — | `200` `404` |
| `POST /v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver` | oturum / API anahtarı | Bitmiş bir teslimi yeniden kuyruğa alır. | — | `202` `404` `409` `429` |
| `POST /v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret` | oturum / API anahtarı | İmza sırrını döndürür; yeni sır bir kez döner. `?immediate=true` değilse eski sır `audit.webhooks.secret_rotation_overlap` boyunca da imzalar (step-up).<br>Sorgu: `immediate` | — | `200` `401` `404` |

## Sosyal giriş (`social-login`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/me/identities` | oturum | Bağlı sosyal kimlikler (SOC-06). | — | `200` `401` |
| `POST /v1/me/identities/link` | oturum | Tarayıcıda sağlayıcı bağlamayı başlatır (step-up). | `LinkStartRequest` | `200` `401` `403` `404` |
| `POST /v1/me/identities/link/native` | oturum | Native ID token ile sağlayıcı bağlar (step-up). | `LinkNativeRequest` | `201` `401` `409` |
| `DELETE /v1/me/identities/{identity_id}` | oturum | Kimliği ayırır (step-up); son giriş yöntemi asla ayrılamaz. | — | `204` `401` `404` `409` |
| `POST /v1/oauth/nonce` | — | Native ID token için tek kullanımlık nonce verir (SOC-04). | `NativeNonceRequest` | `200` `400` `404` `429` |
| `GET /v1/oauth/providers` | — | Etkin sosyal giriş sağlayıcıları. | — | `200` |
| `GET /v1/oauth/{provider}/callback` | — | Sağlayıcı geri dönüşü (sorgu parametreleri); oturum + `303`.<br>Sorgu: `code`, `state`, `error`, `user` | — | `303` `400` `401` `403` `409` |
| `POST /v1/oauth/{provider}/callback` | — | Sağlayıcı geri dönüşü (`response_mode=form_post`, Sign in with Apple). | `CallbackParams` (application/x-www-form-urlencoded) | `303` `400` `401` |
| `POST /v1/oauth/{provider}/native` | — | Platform SDK ID token'ıyla native giriş: token'lar veya challenge (SOC-04, SOC-09). | `NativeLoginRequest` | `200` `400` `401` `403` `409` |
| `GET /v1/oauth/{provider}/start` | — | Tarayıcı girişini başlatır: sağlayıcıya `303` ve `__Host-authn_oauth` bağlama çerezi.<br>Sorgu: `return_to`, `remember_me`, `shared_device` | — | `303` `400` `404` `429` |

## Platform admin (`admin`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/admin/approvals` | admin | Son 7 günün dört göz onay istekleri (en yeni önce). | — | `200` `401` `403` |
| `POST /v1/admin/approvals` | admin | Kritik bir işlem için ikinci bir platform admininin onayını ister (K-66); `admin.four_eyes_approval_ttl` sonra düşer. | `ApprovalRequest` | `200` `401` `403` `404` `422` `429` |
| `POST /v1/admin/approvals/{approval_id}/approve` | admin | Başka bir adminin bekleyen isteğini onaylar; onaylayan istekte bulunan veya hedef olamaz. | `DecisionRequest` | `200` `401` `403` `404` `422` |
| `POST /v1/admin/approvals/{approval_id}/deny` | admin | Başka bir adminin bekleyen isteğini reddeder (kesin). | `DecisionRequest` | `200` `401` `403` `404` `422` |
| `GET /v1/admin/audit-events` | admin | Platform genelinde audit olayları, admin işlemlerinin gerekçeleriyle (ADM-07); sayfalı.<br>Sorgu: `limit`, `cursor`, `kind`, `category`, `outcome`, `actor_user_id`, `subject_user_id`, `org_id`, `resource_type`, `since`, `until` | — | `200` `401` `403` `422` |
| `POST /v1/admin/audit-events/export` | admin | Filtreye uyan audit olaylarını dışa aktarır (sınırlı; `next_cursor` ile devam). Gerekçe zorunlu, dışa aktarma audit'lenir. | `ExportRequest` | `200` `401` `403` `422` |
| `POST /v1/admin/audit-events/verify` | admin | Audit hash zincirini doğrular (AUD-02, ADM-07); yanıtta `legacy_events`, `keyed_from_seq`, `head_key_version`. | `VerifyChainRequest` | `200` `401` `403` `422` |
| `POST /v1/admin/audit-events/{event_id}/restrict` | admin | Bir admin işlem gerekçesini yasal kısıtlamayla kullanıcının veri dışa aktarımından `review_at`'e kadar gizler (K-39, K-62). | `RestrictRequest` | `200` `401` `403` `404` `422` |
| `POST /v1/admin/audit-events/{event_id}/restrict/extend` | admin | Etkin bir kısıtlamayı daha sonraki bir gözden geçirme tarihine uzatır (K-62). | `RestrictRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/emergency/force-password-change` | admin | Şifresi `changed_before`'dan önce değişmiş her hesaba sonraki girişte şifre değişikliği zorunlu kılar; `"confirm": "force_password_change"`. | `ForcePasswordChangeRequest` | `200` `401` `403` `422` |
| `POST /v1/admin/emergency/revoke-all-sessions` | admin | Tüm kullanıcıların tüm oturumlarını kapatır (çağıranınki hariç, `include_own_session` değilse); `"confirm": "revoke_all_sessions"`. | `RevokeAllRequest` | `200` `401` `403` `422` `429` |
| `POST /v1/admin/emergency/rotate-signing-key` | admin | Acil imza anahtarı rotasyonu: etkin anahtar iptal edilir, yenisi etkinleşir; `"confirm": "rotate_signing_key"`. | `EmergencyRequest` | `200` `401` `403` `422` |
| `POST /v1/admin/enrollment/options` | kayıt bağlantısı | Break-glass kayıt bağlantısının hesabı için passkey kayıt seçenekleri (K-11). Oturumsuz; bağlantı token'ı gövdede. | `EnrollmentOptionsRequest` | `200` `400` `403` `429` |
| `POST /v1/admin/enrollment/verify` | kayıt bağlantısı | Passkey'i kaydeder ve kayıt bağlantısını tüketir (K-11). Oturumsuz. | `EnrollmentVerifyRequest` | `200` `400` `403` `429` |
| `GET /v1/admin/users` | admin | Hesap arama (ADM-02): keyset sayfalı, en yeni önce, sır yok.<br>Sorgu: `limit`, `cursor`, `email`, `status`, `platform_admin`, `email_verified`, `created_after`, `created_before` | — | `200` `401` `403` `422` |
| `GET /v1/admin/users/{user_id}` | admin | Tek hesabın ayrıntıları (ADM-02); erişim audit'lenir. | — | `200` `401` `403` `404` |
| `POST /v1/admin/users/{user_id}/force-password-reset` | admin | Şifre sıfırlamayı zorlar: şifre çalışmaz, oturumlar kapanır, sıfırlama linki gönderilir (yalnızca normal kullanıcılar). | `ForcePasswordResetRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/impersonate` | admin | Kullanıcıyı taklit etmeye başlar (ADM-04): varsayılan salt-okunur, 15 dk (en çok 60). Web: gövdedeki `impersonation_token` `x-impersonation-session` başlığıyla gönderilir; adminin çerezi değişmez. | `ImpersonateRequest` | `200` `401` `403` `404` `422` |
| `POST /v1/admin/users/{user_id}/mark-email-verified` | admin | Adresi doğrulanmış işaretler (yalnızca normal kullanıcılar). | `ReasonRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/must-change-password` | admin | `must_change_password` bayrağını koyar veya kaldırır (yalnızca normal kullanıcılar). | `MustChangePasswordRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/reset-mfa` | admin | Hesabın MFA'sını (passkey'ler dahil) sıfırlar ve kullanıcıya bildirir (yalnızca normal kullanıcılar). | `ReasonRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/revoke-sessions` | admin | Hesabın tüm oturumlarını ve güvenilir cihazlarını kapatır. | `ReasonRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/suspend` | admin | Hesabı askıya alır; oturumlar ve güvenilir cihazlar kapanır. | `ReasonRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/unlock` | admin | Geçici kilidi ve giriş yumuşak kilidini kaldırır. | `ReasonRequest` | `200` `401` `403` `404` `409` `422` |
| `POST /v1/admin/users/{user_id}/unsuspend` | admin | Askıyı kaldırır (yalnızca normal kullanıcılar). | `ReasonRequest` | `200` `401` `403` `404` `409` `422` |

## Sağlık (`health`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /health/live` | — | Canlılık: süreç HTTP'ye yanıt veriyor (`{"status":"ok"}`). | — | `200` |
| `GET /health/ready` | — | Hazır olma: veritabanı erişilebilir ve şema bu ikiliyle güncel; değilse `503` + `not_ready`. | — | `200` `503` |

## Örnek / meta (`meta`)

| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |
|---------------|--------|----------|---------------|----------|
| `GET /v1/time` | — | Sunucu saati: ARC-03 modül yönlendirici deseninin örnek ucu (`crates/authn-server/src/routes/example.rs`); kimlik doğrulaması istemez. | — | `200` `5XX` |
