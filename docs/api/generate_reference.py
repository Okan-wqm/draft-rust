#!/usr/bin/env python3
"""Generates docs/api/endpoints.md and docs/api/errors.md (DOC-04).

Inputs (nothing is invented here):
  * docs/api/openapi.json  -- the server's merged OpenAPI document
    (`authn_server::openapi::document()`, served at GET /openapi.json);
  * crates/authn-core/src/error/codes/*.rs -- the stable error codes.

Turkish one-line descriptions live in DESCRIPTIONS / NOTES below; the
script fails when an operation or an error code has none, so a new
endpoint or code cannot silently stay undocumented.

Usage (from the repository root):
    python3 -I docs/api/generate_reference.py
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OPENAPI = ROOT / "docs/api/openapi.json"
CODES_DIR = ROOT / "crates/authn-core/src/error/codes"
METHODS = ("get", "post", "put", "patch", "delete")

TAG_TITLES = {
    "health": "Sağlık",
    "meta": "Örnek / meta",
    "session": "Oturum ve token'lar",
    "login": "Giriş akışları",
    "password": "Şifre",
    "account": "Hesap",
    "mfa": "MFA",
    "passkeys": "Passkey yönetimi",
    "well-known": "Well-known belgeleri",
    "organizations": "Organizasyonlar (B2B)",
    "protect": "Kötüye kullanım koruması",
    "audit": "Audit",
    "webhooks": "Webhook'lar",
    "social-login": "Sosyal giriş",
    "admin": "Platform admin",
}

# Turkish descriptions, keyed by "METHOD path" (verified against the
# handler and its #[utoipa::path] annotation).
DESCRIPTIONS = {
    "GET /.well-known/apple-app-site-association": "iOS/macOS ilişkilendirme dosyası: `webcredentials` (passkey) ve `app_link_paths` varsa `applinks`. `webauthn.apple_app_ids` boşsa `404`.",
    "GET /.well-known/assetlinks.json": "Android Digital Asset Links: `get_login_creds` (passkey / Credential Manager), `app_link_paths` varsa `handle_all_urls`. `webauthn.android_apps` boşsa `404`.",
    "GET /.well-known/jwks.json": "Access token doğrulaması için Ed25519 açık anahtarları (`pending`, `active` ve yayım süresi dolmamış `retired`). `Cache-Control: public, max-age=<crypto.signing_keys.jwks_cache_ttl>`.",
    "GET /.well-known/webauthn": "WebAuthn Related Origin Requests belgesi (`{\"origins\": [...]}`). `webauthn.related_origins` boşsa `404`.",
    "GET /health/live": "Canlılık: süreç HTTP'ye yanıt veriyor (`{\"status\":\"ok\"}`).",
    "GET /health/ready": "Hazır olma: veritabanı erişilebilir ve şema bu ikiliyle güncel; değilse `503` + `not_ready`.",
    "POST /v1/account/deletion/cancel": "E-postadaki linkin token'ıyla planlanmış hesap silmesini iptal eder (ACC-09).",
    "GET /v1/admin/approvals": "Son 7 günün dört göz onay istekleri (en yeni önce).",
    "POST /v1/admin/approvals": "Kritik bir işlem için ikinci bir platform admininin onayını ister (K-66); `admin.four_eyes_approval_ttl` sonra düşer.",
    "POST /v1/admin/approvals/{approval_id}/approve": "Başka bir adminin bekleyen isteğini onaylar; onaylayan istekte bulunan veya hedef olamaz.",
    "POST /v1/admin/approvals/{approval_id}/deny": "Başka bir adminin bekleyen isteğini reddeder (kesin).",
    "GET /v1/admin/audit-events": "Platform genelinde audit olayları, admin işlemlerinin gerekçeleriyle (ADM-07); sayfalı.",
    "POST /v1/admin/audit-events/export": "Filtreye uyan audit olaylarını dışa aktarır (sınırlı; `next_cursor` ile devam). Gerekçe zorunlu, dışa aktarma audit'lenir.",
    "POST /v1/admin/audit-events/verify": "Audit hash zincirini doğrular (AUD-02, ADM-07); yanıtta `legacy_events`, `keyed_from_seq`, `head_key_version`.",
    "POST /v1/admin/audit-events/{event_id}/restrict": "Bir admin işlem gerekçesini yasal kısıtlamayla kullanıcının veri dışa aktarımından `review_at`'e kadar gizler (K-39, K-62).",
    "POST /v1/admin/audit-events/{event_id}/restrict/extend": "Etkin bir kısıtlamayı daha sonraki bir gözden geçirme tarihine uzatır (K-62).",
    "POST /v1/admin/emergency/force-password-change": "Şifresi `changed_before`'dan önce değişmiş her hesaba sonraki girişte şifre değişikliği zorunlu kılar; `\"confirm\": \"force_password_change\"`.",
    "POST /v1/admin/emergency/revoke-all-sessions": "Tüm kullanıcıların tüm oturumlarını kapatır (çağıranınki hariç, `include_own_session` değilse); `\"confirm\": \"revoke_all_sessions\"`.",
    "POST /v1/admin/emergency/rotate-signing-key": "Acil imza anahtarı rotasyonu: etkin anahtar iptal edilir, yenisi etkinleşir; `\"confirm\": \"rotate_signing_key\"`.",
    "POST /v1/admin/enrollment/options": "Break-glass kayıt bağlantısının hesabı için passkey kayıt seçenekleri (K-11). Oturumsuz; bağlantı token'ı gövdede.",
    "POST /v1/admin/enrollment/verify": "Passkey'i kaydeder ve kayıt bağlantısını tüketir (K-11). Oturumsuz.",
    "GET /v1/admin/users": "Hesap arama (ADM-02): keyset sayfalı, en yeni önce, sır yok.",
    "GET /v1/admin/users/{user_id}": "Tek hesabın ayrıntıları (ADM-02); erişim audit'lenir.",
    "POST /v1/admin/users/{user_id}/force-password-reset": "Şifre sıfırlamayı zorlar: şifre çalışmaz, oturumlar kapanır, sıfırlama linki gönderilir (yalnızca normal kullanıcılar).",
    "POST /v1/admin/users/{user_id}/impersonate": "Kullanıcıyı taklit etmeye başlar (ADM-04): varsayılan salt-okunur, 15 dk (en çok 60). Web: gövdedeki `impersonation_token` `x-impersonation-session` başlığıyla gönderilir; adminin çerezi değişmez.",
    "POST /v1/admin/users/{user_id}/mark-email-verified": "Adresi doğrulanmış işaretler (yalnızca normal kullanıcılar).",
    "POST /v1/admin/users/{user_id}/must-change-password": "`must_change_password` bayrağını koyar veya kaldırır (yalnızca normal kullanıcılar).",
    "POST /v1/admin/users/{user_id}/reset-mfa": "Hesabın MFA'sını (passkey'ler dahil) sıfırlar ve kullanıcıya bildirir (yalnızca normal kullanıcılar).",
    "POST /v1/admin/users/{user_id}/revoke-sessions": "Hesabın tüm oturumlarını ve güvenilir cihazlarını kapatır.",
    "POST /v1/admin/users/{user_id}/suspend": "Hesabı askıya alır; oturumlar ve güvenilir cihazlar kapanır.",
    "POST /v1/admin/users/{user_id}/unlock": "Geçici kilidi ve giriş yumuşak kilidini kaldırır.",
    "POST /v1/admin/users/{user_id}/unsuspend": "Askıyı kaldırır (yalnızca normal kullanıcılar).",
    "GET /v1/captcha/challenge": "Bir eylem (`?action=`) için CAPTCHA challenge'ı verir (PoW sağlayıcısında bulmaca; diğerlerinde site anahtarı).",
    "GET /v1/csrf": "Oturum varsa oturumun CSRF token'ını, yoksa giriş formları için pre-session token'ını verir (gerekirse `__Host-authn_csrf` çerezini yazar).",
    "POST /v1/email/change/confirm": "Yeni adrese giden linkle e-posta değişikliğini onaylar (ACC-07); hesap sahibinin oturumu gerekir.",
    "POST /v1/email/change/revert": "Eski adrese giden linkle değişikliği geri alır: adres geri gelir, her yerden çıkış, şifre sıfırlama zorunlu.",
    "POST /v1/email/verification/resend": "Doğrulama e-postasını yeniden gönderir; her adres için aynı yanıt (`202`).",
    "POST /v1/email/verify": "Adresi link veya kodla doğrular ve kaydı tamamlar (ADR 0002): link + kayıt tutamacı/çerez, + kayıttaki şifre (`password`) veya + yeni şifre (`new_password`). Oturum açmaz.",
    "POST /v1/invitations/accept": "Daveti kabul eder (ORG-05); hesabın doğrulanmış adresi davet adresiyle eşleşmeli.",
    "POST /v1/invitations/preview": "Davetin neyi verdiğini gösterir (organizasyon adı, rol, maskeli adres, adres eşleşiyor mu).",
    "POST /v1/login/challenge/passkey/options": "Bekleyen girişin ikinci faktör adımı için passkey seremonisi başlatır.",
    "POST /v1/login/challenge/send-code": "Bekleyen girişte geçerli faktör adımı için kod gönderir (`email`, `sms`, `email_confirmation`).",
    "POST /v1/login/challenge/step": "Bekleyen girişin zorunlu adımını yapar (SES-22): `change_password`, `accept_terms`, `enroll_totp`/`enroll_email`/`enroll_sms`, `confirm_enrollment`.",
    "POST /v1/login/challenge/verify": "Bekleyen girişin ikinci faktörünü doğrular (`totp`, `recovery_code`, `email`, `sms`, `passkey`, `email_confirmation`; isteğe bağlı `trust_device`).",
    "POST /v1/login/email-code": "E-posta ile giriş kodu ister (SES-19); her adres için aynı yanıt (`202`).",
    "POST /v1/login/email-code/verify": "E-postadaki kodla giriş yapar; tüm hatalar tek tip `invalid_code`.",
    "POST /v1/login/magic-link": "Magic link ister (SES-18); her adres için aynı yanıt (`202`).",
    "POST /v1/login/magic-link/verify": "Magic link token'ıyla giriş yapar (yalnızca POST); başka cihazda açılırsa `409 magic_link_confirmation_required`.",
    "POST /v1/login/not-me": "\"Bu ben değilim\" (RSK-04): tüm oturumlar ve güvenilir cihazlar kapanır, şifre değişikliği zorunlu olur.",
    "POST /v1/login/passkey": "Passkey girişini tamamlar (SES-20, SES-21).",
    "POST /v1/login/passkey/options": "Kullanıcı adsız passkey girişi başlatır (`conditional_ui` ile otomatik doldurma).",
    "POST /v1/login/password": "E-posta + şifre ile giriş (SES-01): `authenticated` (oturum/token) veya `challenge_required`.",
    "POST /v1/logout": "Oturumu ve refresh token'larını kapatır; web'de çerez silinir ve `Clear-Site-Data: \"cookies\"` gönderilir.",
    "POST /v1/logout/all": "Her yerden çıkış: kullanıcının tüm oturumları ve güvenilir cihazları.",
    "DELETE /v1/me": "Hesap silmeyi planlar (ACC-09; step-up). Bekleme süresi `account.deletion_grace_period`.",
    "GET /v1/me": "Oturumdaki kullanıcı (SES-16).",
    "GET /v1/me/consents": "Kullanıcının kayıtlı şart/gizlilik politikası onayları (ACC-11).",
    "POST /v1/me/consents": "Güncel belge sürümlerini kabul eder; IP ve user agent kaydedilir.",
    "GET /v1/me/deletion": "Planlanmış hesap silmesi (yoksa `404`).",
    "POST /v1/me/deletion/cancel": "Planlanmış silmeyi oturumdan iptal eder.",
    "POST /v1/me/email": "E-posta değişikliği ister (ACC-07; step-up); yeni adres uygun olsun olmasın aynı yanıt.",
    "POST /v1/me/email/confirm": "Yeni adrese giden kodla e-posta değişikliğini onaylar.",
    "POST /v1/me/email/verification": "Oturumdaki kullanıcıya doğrulama e-postasını yeniden gönderir.",
    "POST /v1/me/email/verify": "Oturumdaki kullanıcının adresini kodla doğrular (ACC-04, ACC-05 `limited` modu).",
    "POST /v1/me/export": "Tüm kişisel verinin makinece okunur dışa aktarımı (ACC-10; step-up; gövdesiz `POST`, `GET` → `405`).",
    "GET /v1/me/identities": "Bağlı sosyal kimlikler (SOC-06).",
    "POST /v1/me/identities/link": "Tarayıcıda sağlayıcı bağlamayı başlatır (step-up).",
    "POST /v1/me/identities/link/native": "Native ID token ile sağlayıcı bağlar (step-up).",
    "DELETE /v1/me/identities/{identity_id}": "Kimliği ayırır (step-up); son giriş yöntemi asla ayrılamaz.",
    "GET /v1/me/mfa": "MFA durumu: faktörler (sırsız, maskeli iletişim), kurtarma kodu sayaçları, güvenilir cihaz sayısı.",
    "POST /v1/me/mfa/email": "Hesap adresinde e-posta OTP faktörünü başlatır ve onay kodu gönderir (step-up).",
    "DELETE /v1/me/mfa/factors/{factor_id}": "Faktörü kaldırır (step-up); politika MFA isterken son kullanılabilir faktör kaldırılamaz.",
    "POST /v1/me/mfa/factors/{factor_id}/confirm": "Bekleyen faktörü kodla onaylar; ilk faktörde kurtarma kodları bir kez döner (step-up).",
    "POST /v1/me/mfa/factors/{factor_id}/resend": "Bekleyen e-posta/SMS faktörü için yeni onay kodu gönderir (step-up).",
    "GET /v1/me/mfa/recovery-codes": "Kurtarma kodu sayaçları (MFA-04).",
    "POST /v1/me/mfa/recovery-codes": "Yeni kurtarma kodları üretir, eskileri geçersiz (step-up; bir kez gösterilir).",
    "POST /v1/me/mfa/sms": "SMS faktörü başlatır (E.164, izinli ülke; step-up).",
    "POST /v1/me/mfa/totp": "TOTP kaydı başlatır: sır, `otpauth://` URI ve QR bir kez döner (step-up).",
    "DELETE /v1/me/mfa/trusted-devices": "Tüm güvenilir cihazları iptal eder.",
    "GET /v1/me/mfa/trusted-devices": "Güvenilir cihazlar (MFA-09).",
    "DELETE /v1/me/mfa/trusted-devices/{device_id}": "Tek bir güvenilir cihazı iptal eder.",
    "GET /v1/me/passkeys": "Passkey listesi (PKY-04).",
    "POST /v1/me/passkeys/registration/options": "Passkey kaydı başlatır: `navigator.credentials.create()` / platform API'leri için `CredentialCreationOptions`.",
    "POST /v1/me/passkeys/registration/verify": "Doğrulayıcı yanıtını doğrular ve passkey'i kaydeder.",
    "DELETE /v1/me/passkeys/{passkey_id}": "Passkey'i siler (step-up).",
    "PATCH /v1/me/passkeys/{passkey_id}": "Passkey'i yeniden adlandırır.",
    "DELETE /v1/me/password": "Şifreyi kaldırır (PWD-11; step-up + başka güçlü yöntem: passkey veya bağlı kimlik).",
    "POST /v1/me/password": "Şifresiz hesaba şifre ekler (PWD-10; step-up).",
    "POST /v1/me/password/change": "Şifre değiştirir (PWD-06): mevcut şifre veya yakın step-up; diğer oturumlar kapanır.",
    "GET /v1/me/profile": "Profil (ACC-08).",
    "PATCH /v1/me/profile": "Görünen ad, dil ve saat dilimini günceller.",
    "GET /v1/me/security-events": "Kullanıcının son 90 günlük güvenlik olayları (AUD-04; sayfalı).",
    "GET /v1/me/sessions": "Canlı oturumlar (SES-11).",
    "POST /v1/me/sessions/revoke-others": "Diğer tüm oturumları ve güvenilir cihazları kapatır.",
    "DELETE /v1/me/sessions/{session_id}": "Kendi oturumlarından birini kapatır; başkasınınki `404`.",
    "POST /v1/oauth/nonce": "Native ID token için tek kullanımlık nonce verir (SOC-04).",
    "GET /v1/oauth/providers": "Etkin sosyal giriş sağlayıcıları.",
    "GET /v1/oauth/{provider}/callback": "Sağlayıcı geri dönüşü (sorgu parametreleri); oturum + `303`.",
    "POST /v1/oauth/{provider}/callback": "Sağlayıcı geri dönüşü (`response_mode=form_post`, Sign in with Apple).",
    "POST /v1/oauth/{provider}/native": "Platform SDK ID token'ıyla native giriş: token'lar veya challenge (SOC-04, SOC-09).",
    "GET /v1/oauth/{provider}/start": "Tarayıcı girişini başlatır: sağlayıcıya `303` ve `__Host-authn_oauth` bağlama çerezi.",
    "GET /v1/org-permissions": "İzin kataloğu (ORG-03).",
    "GET /v1/orgs": "Kullanıcının organizasyonları (sayfalı).",
    "POST /v1/orgs": "Organizasyon kurar; çağıran `owner` olur.",
    "DELETE /v1/orgs/{org_id}": "Organizasyon silmeyi planlar (sahip + step-up, ORG-12).",
    "GET /v1/orgs/{org_id}": "Organizasyonu okur (`org:read`).",
    "PATCH /v1/orgs/{org_id}": "Ad / slug değiştirir (`org:update`).",
    "GET /v1/orgs/{org_id}/api-keys": "API anahtarlarını listeler (`api_keys:read`; sayfalı).",
    "POST /v1/orgs/{org_id}/api-keys": "API anahtarı oluşturur (`api_keys:manage` + step-up); anahtar bir kez gösterilir.",
    "DELETE /v1/orgs/{org_id}/api-keys/{key_id}": "API anahtarını iptal eder (`api_keys:manage`).",
    "GET /v1/orgs/{org_id}/api-keys/{key_id}": "API anahtarı üst verisi (`api_keys:read`).",
    "POST /v1/orgs/{org_id}/api-keys/{key_id}/rotate": "API anahtarını döndürür (`api_keys:manage` + step-up); eskisi `org.api_keys.rotation_grace` boyunca çalışır.",
    "GET /v1/orgs/{org_id}/audit-events": "Organizasyonun audit log'u, filtreli (AUD-04; sayfalı).",
    "POST /v1/orgs/{org_id}/deletion/cancel": "Planlanmış organizasyon silmesini iptal eder (sahip + step-up).",
    "GET /v1/orgs/{org_id}/domains": "Domain'leri listeler (`domains:read`).",
    "POST /v1/orgs/{org_id}/domains": "Domain ekler (`domains:manage`); yanıt yayımlanacak TXT kaydını söyler.",
    "DELETE /v1/orgs/{org_id}/domains/{domain_id}": "Domain'i kaldırır (`domains:manage`).",
    "PATCH /v1/orgs/{org_id}/domains/{domain_id}": "Otomatik katılımı açar/kapatır (`domains:manage`).",
    "POST /v1/orgs/{org_id}/domains/{domain_id}/verify": "DNS TXT kaydını denetler (`domains:manage`, ORG-06).",
    "GET /v1/orgs/{org_id}/invitations": "Davetleri listeler (`members:invite`; sayfalı).",
    "POST /v1/orgs/{org_id}/invitations": "Adres davet eder (`members:invite`; `owner` daveti step-up ister).",
    "DELETE /v1/orgs/{org_id}/invitations/{invitation_id}": "Bekleyen daveti iptal eder.",
    "POST /v1/orgs/{org_id}/invitations/{invitation_id}/resend": "Daveti yeni token'la yeniden gönderir (eskisi geçersiz).",
    "POST /v1/orgs/{org_id}/leave": "Organizasyondan ayrılır (son sahip ayrılamaz).",
    "GET /v1/orgs/{org_id}/members": "Üyeleri listeler (`members:read`; sayfalı).",
    "DELETE /v1/orgs/{org_id}/members/{member_id}": "Üyeyi çıkarır (`members:remove`).",
    "GET /v1/orgs/{org_id}/members/{member_id}": "Üyeyi okur (`members:read`).",
    "PATCH /v1/orgs/{org_id}/members/{member_id}": "Üyenin rolünü/durumunu değiştirir (`members:update`; yükseltme koruması, son sahip koruması; `owner` vermek step-up ister).",
    "DELETE /v1/orgs/{org_id}/ownership-transfer": "Bekleyen sahiplik devirlerini iptal eder (sahip).",
    "POST /v1/orgs/{org_id}/ownership-transfer": "Sahiplik devri başlatır (sahip + step-up, ORG-11).",
    "GET /v1/orgs/{org_id}/policy": "Güvenlik politikasını okur (`policies:read`).",
    "PUT /v1/orgs/{org_id}/policy": "Güvenlik politikasını tamamen değiştirir (`policies:manage` + step-up); çağıranı kilitleyecek politika `422 org_policy_lockout`.",
    "GET /v1/orgs/{org_id}/roles": "Yerleşik ve özel roller (`roles:read`).",
    "POST /v1/orgs/{org_id}/roles": "Özel rol oluşturur (`roles:manage`).",
    "DELETE /v1/orgs/{org_id}/roles/{role_id}": "Kullanılmayan özel rolü siler.",
    "PATCH /v1/orgs/{org_id}/roles/{role_id}": "Özel rolü değiştirir.",
    "GET /v1/orgs/{org_id}/service-accounts": "Servis hesaplarını listeler (`service_accounts:read`; sayfalı).",
    "POST /v1/orgs/{org_id}/service-accounts": "Servis hesabı oluşturur (`service_accounts:manage`).",
    "DELETE /v1/orgs/{org_id}/service-accounts/{service_account_id}": "Servis hesabını ve anahtarlarını siler.",
    "GET /v1/orgs/{org_id}/service-accounts/{service_account_id}": "Servis hesabını okur.",
    "PATCH /v1/orgs/{org_id}/service-accounts/{service_account_id}": "Servis hesabını değiştirir.",
    "GET /v1/orgs/{org_id}/webhooks": "Webhook uç noktalarını listeler (AUD-07).",
    "POST /v1/orgs/{org_id}/webhooks": "Webhook uç noktası oluşturur; imza sırrı (`whsec_…`) bir kez döner (step-up).",
    "DELETE /v1/orgs/{org_id}/webhooks/{endpoint_id}": "Uç noktayı ve teslim geçmişini siler (step-up).",
    "GET /v1/orgs/{org_id}/webhooks/{endpoint_id}": "Tek webhook uç noktası.",
    "PATCH /v1/orgs/{org_id}/webhooks/{endpoint_id}": "Uç noktayı değiştirir (URL, abonelik, etkinleştirme step-up ister).",
    "GET /v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries": "Teslim geçmişi (sayfalı).",
    "POST /v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver": "Bitmiş bir teslimi yeniden kuyruğa alır.",
    "POST /v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret": "İmza sırrını döndürür; yeni sır bir kez döner. `?immediate=true` değilse eski sır `audit.webhooks.secret_rotation_overlap` boyunca da imzalar (step-up).",
    "POST /v1/ownership-transfers/accept": "Sahiplik devrini kabul eder (hedef kullanıcı + step-up).",
    "POST /v1/password/check": "Kayıt/değişiklik formları için canlı şifre politikası denetimi (IP başına sınırlı; şifre loglanmaz).",
    "POST /v1/password/forgot": "Şifre sıfırlama ister; hesap olsun olmasın aynı yanıt, durum ve süre (`202`).",
    "POST /v1/password/reset": "Link token'ı veya e-posta + kodla sıfırlamayı tamamlar; tüm oturumlar, refresh token'lar ve güvenilir cihazlar kapanır, oturum açılmaz.",
    "POST /v1/reauth": "Step-up yeniden kimlik doğrulama (SES-13: `password`, `totp`, `recovery_code`, `passkey`); oturumu döndürür.",
    "POST /v1/reauth/passkey/options": "Oturuma bağlı passkey step-up seremonisi başlatır.",
    "POST /v1/session/org": "Aktif organizasyonu değiştirir (SES-17); oturumu döndürür.",
    "POST /v1/signup": "Hesap kaydı (ACC-01): adres kayıtlı olsun olmasın aynı yanıt; kayıt tutamacı gövdede ve `__Host-authn_registration` çerezinde.",
    "GET /v1/terms": "Güncel kullanım şartları / gizlilik politikası sürümleri.",
    "GET /v1/time": "Sunucu saati: ARC-03 modül yönlendirici deseninin örnek ucu (`crates/authn-server/src/routes/example.rs`); kimlik doğrulaması istemez.",
    "POST /v1/token/introspect": "Token introspection (RFC 7662): istemci org API anahtarıyla doğrulanır, yalnızca kendi organizasyonunun token'larını görür.",
    "POST /v1/token/refresh": "Refresh token rotasyonu (SES-05); tekrar kullanılan token tüm aileyi iptal eder; her hata `invalid_refresh_token`.",
}

# Turkish notes for error codes whose meaning needs more than the localized
# message (the message itself comes from the code).
NOTES = {
    "internal_error": "İç ayrıntı yalnızca loglanır (`request_id` ile eşleştirin).",
    "bad_request": "Bozuk JSON, yol parametresi, tekrarlanan başlık vb. Gövde içeriği yankılanmaz.",
    "validation_failed": "`details` alan adlarını taşıyabilir. Bozuk sayfalama `cursor`'ı da bu koddur.",
    "unauthenticated": "Kimlik bilgisi yok/geçersiz. Bearer hatasında ayrıca `WWW-Authenticate: Bearer error=\"invalid_token\"`.",
    "forbidden": "Yetki yok (eksik organizasyon izni, salt-okunur impersonation altında yazma vb.).",
    "not_found": "Başka kiracının kaynağı da `404` (ORG-10).",
    "method_not_allowed": "Yalnızca yönlendirici tarafından üretilir (`for_status`).",
    "payload_too_large": "`server.limits.body_limit_bytes` aşımı; katman tarafından üretilir.",
    "request_timeout": "`server.limits.request_timeout` aşımı.",
    "rate_limited": "`Retry-After` başlığıyla. Bkz. [rate-limiting.md](rate-limiting.md).",
    "too_many_attempts": "Bir kod/faktör için deneme hakkı bitti veya MFA geçici kilidi (`mfa.lockout_duration`; `Retry-After` ile).",
    "service_unavailable": "Havuz zaman aşımı, bağımlılık kesintisi.",
    "step_up_required": "`POST /v1/reauth` ile yeniden doğrulayıp isteği tekrarlayın. Organizasyonun oturum ömrü üst sınırı aşıldığında da döner.",
    "invalid_or_expired_token": "Bilinmeyen/kullanılmış/iptal/süresi dolmuş link token'ı — ayırt edilmez.",
    "invalid_code": "Yanlış/süresi dolmuş kod — ayırt edilmez.",
    "invalid_credentials": "Tek tip: hesap yok, şifre yanlış, şifre yok.",
    "csrf_failed": "Origin/`Sec-Fetch-Site` veya `X-CSRF-Token` denetimi başarısız. Bkz. [authentication.md](authentication.md#3-csrf).",
    "invalid_refresh_token": "Bilinmeyen, süresi dolmuş, iptal edilmiş veya tekrar kullanılmış — hepsi aynı; tekrar kullanım aileyi iptal eder.",
    "challenge_invalid": "Kullanılmış, süresi dolmuş, deneme hakkı bitmiş veya başka cihaz/istemci türü — tek tip.",
    "login_method_not_allowed": "Organizasyon politikası bu giriş yöntemine izin vermiyor. K-57'den beri organizasyonu etkinleştirmemiş oturumlarda da **her** `/v1/orgs/{org_id}/…` isteğinde denetlenir.",
    "org_policy_mfa_required": "Organizasyon MFA / phishing'e dayanıklı MFA istiyor ya da oturumun ikinci faktörü `allowed_mfa_factors`'ta değil (K-57, K-78). İzinli faktörle step-up yapın.",
    "org_policy_ip_denied": "İstemci IP'si organizasyonun izin listesinde değil.",
    "org_policy_lockout": "Yeni politika çağıranı dışarıda bırakırdı; `details.reason` ∈ `ip_allowlist`, `mfa`, `login_method`.",
    "magic_link_confirmation_required": "Link başka bir cihazda açıldı; `confirm_other_device` ile yeniden gönderin.",
    "registration_confirmation_required": "Link kaydı yapan istemci dışında açıldı: `password` (kayıttaki şifre) veya `new_password` isteyin (ADR 0002).",
    "host_not_allowed": "`Host` `protect.allowed_hosts`'ta değil (`/health/` muaf).",
    "cors_origin_not_allowed": "İzin listesi dışı origin'den veya izinsiz yöntem/başlıkla preflight.",
    "captcha_required": "İsteği CAPTCHA yanıtıyla (`captcha` alanı) tekrarlayın.",
    "login_temporarily_blocked": "Hesap yumuşak kilitli (PRT-03); `Retry-After` taşıyabilir.",
    "oauth_link_required": "Adres başka bir hesaba ait; oturum açıp kimliği açıkça bağlayın.",
    "password_breach_check_unavailable": "HIBP erişilemedi ve `password.breach_check.fail_open = false`.",
    "sms_unavailable": "SMS sağlayıcısı yok veya `sms` özelliği derlenmedi.",
    "delivery_rejected": "Sağlayıcı teslimi reddetti.",
    "outbound_destination_not_allowed": "Kullanıcının verdiği URL özel/loopback adrese veya düz http'ye gidiyor (SSRF koruması).",
}

STATUS_NUM = {
    "BAD_REQUEST": 400, "UNAUTHORIZED": 401, "FORBIDDEN": 403, "NOT_FOUND": 404,
    "METHOD_NOT_ALLOWED": 405, "REQUEST_TIMEOUT": 408, "CONFLICT": 409,
    "PAYLOAD_TOO_LARGE": 413, "UNSUPPORTED_MEDIA_TYPE": 415, "MISDIRECTED_REQUEST": 421,
    "UNPROCESSABLE_ENTITY": 422, "TOO_MANY_REQUESTS": 429, "INTERNAL_SERVER_ERROR": 500,
    "BAD_GATEWAY": 502, "SERVICE_UNAVAILABLE": 503,
}

MODULE_TITLES = {
    "common": "Ortak (`codes::common`)", "account": "Hesap (`codes::account`)",
    "admin": "Platform admin (`codes::admin`)", "audit": "Audit ve webhook (`codes::audit`)",
    "mfa": "MFA (`codes::mfa`)", "notify": "Bildirim (`codes::notify`)",
    "oidc_client": "Sosyal giriş (`codes::oidc_client`)", "org": "Organizasyon (`codes::org`)",
    "password": "Şifre (`codes::password`)", "protect": "Koruma (`codes::protect`)",
    "session": "Oturum ve giriş (`codes::session`)", "webauthn": "Passkey (`codes::webauthn`)",
    "crypto": "Kripto", "server": "Sunucu", "store": "Depo",
}
MODULE_ORDER = ["common", "session", "account", "password", "mfa", "webauthn", "org",
                "oidc_client", "protect", "audit", "notify", "admin"]

CODE_RE = re.compile(
    r'pub const (\w+): ErrorCode = ErrorCode::new\(\s*"([^"]+)",\s*StatusCode::(\w+),'
    r'\s*"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)",?\s*\);')


def auth_of(method, path):
    if path.startswith(("/.well-known/", "/health/")):
        return "—"
    if path.startswith("/v1/admin/enrollment/"):
        return "kayıt bağlantısı"
    if path.startswith("/v1/admin/"):
        return "admin"
    if path == "/v1/token/introspect":
        return "API anahtarı"
    if path.startswith("/v1/login/challenge/"):
        return "challenge token'ı"
    if path.startswith("/v1/orgs/"):
        return "oturum / API anahtarı"
    public = {
        "/v1/signup", "/v1/csrf", "/v1/terms", "/v1/password/check", "/v1/password/forgot",
        "/v1/password/reset", "/v1/email/verify", "/v1/email/verification/resend",
        "/v1/email/change/revert", "/v1/account/deletion/cancel", "/v1/token/refresh",
        "/v1/captcha/challenge", "/v1/oauth/providers", "/v1/oauth/nonce", "/v1/time",
    }
    if path in public or path.startswith("/v1/login/") or (
            path.startswith("/v1/oauth/") and not path.startswith("/v1/oauth/nonce")):
        return "—"
    return "oturum"


def schema_name(ref_holder):
    if not ref_holder:
        return ""
    content = ref_holder.get("content", {})
    out = []
    for ctype, media in content.items():
        ref = media.get("schema", {}).get("$ref", "")
        name = ref.rsplit("/", 1)[-1] if ref else media.get("schema", {}).get("type", "")
        out.append(f"`{name}`" + ("" if ctype == "application/json" else f" ({ctype})"))
    return ", ".join(out)


def endpoints(doc):
    by_tag = {}
    missing = []
    for path, item in doc["paths"].items():
        for method in METHODS:
            op = item.get(method)
            if not op:
                continue
            key = f"{method.upper()} {path}"
            if key not in DESCRIPTIONS:
                missing.append(key)
            tag = (op.get("tags") or ["?"])[0]
            by_tag.setdefault(tag, []).append((path, method, op, key))
    if missing:
        sys.exit("no Turkish description for: " + ", ".join(sorted(missing)))
    stale = set(DESCRIPTIONS) - {k for ops in by_tag.values() for (_, _, _, k) in ops}
    if stale:
        sys.exit("descriptions of removed operations: " + ", ".join(sorted(stale)))
    count = sum(len(v) for v in by_tag.values())
    lines = [
        "# Endpoint referansı (DOC-04)",
        "",
        "> **Üretilmiş dosya — elle düzenlemeyin.** Kaynak: [`openapi.json`](openapi.json) "
        "(sunucunun birleşik OpenAPI belgesi) ve `generate_reference.py` içindeki Türkçe açıklamalar. "
        "Yeniden üretmek için [README](README.md#openapi-belgesini-yenilemek).",
        "",
        f"Toplam **{count}** işlem. İstek/yanıt şemalarının tamamı, alan açıklamaları ve "
        "her yanıt kodunun İngilizce açıklaması `openapi.json`'dadır.",
        "",
        "**Kimlik sütunu:** `—` kimlik doğrulaması yok · `oturum` web oturum çerezi (+ durum değiştiren "
        "yöntemlerde CSRF) veya `Authorization: Bearer <access token>` · `oturum / API anahtarı` ek olarak "
        "organizasyon API anahtarı (`Authorization: Bearer ak_…` / `X-API-Key`) · `admin` platform admini, "
        "passkey oturumu + step-up (+ `admin.ip_allow_list`) · `API anahtarı` yalnızca organizasyon API anahtarı · "
        "`challenge token'ı` bekleyen girişin token'ı (web: `__Host-authn_challenge` çerezi, native: "
        "`X-Authn-Challenge` başlığı). "
        "Ayrıntı: [authentication.md](authentication.md). \"step-up\" = son `session.step_up_max_age` "
        "içinde yeniden doğrulama, yoksa `401 step_up_required`.",
        "",
        "`GET /openapi.json` (yalnızca `server.openapi_enabled = true` iken) belgenin kendisidir ve listede yoktur.",
        "",
    ]
    order = [t["name"] for t in doc.get("tags", [])]
    tags = sorted(by_tag, key=lambda t: (order.index(t) if t in order else len(order), t))
    for tag in tags:
        lines += [f"## {TAG_TITLES.get(tag, tag)} (`{tag}`)", ""]
        lines += ["| Yöntem ve yol | Kimlik | Açıklama | İstek gövdesi | Yanıtlar |",
                  "|---------------|--------|----------|---------------|----------|"]
        for path, method, op, key in sorted(by_tag[tag], key=lambda x: (x[0], METHODS.index(x[1]))):
            params = [p["name"] for p in op.get("parameters", []) if p.get("in") == "query"]
            q = ("<br>Sorgu: " + ", ".join(f"`{p}`" for p in params)) if params else ""
            responses = " ".join(f"`{c}`" for c in op.get("responses", {}))
            lines.append(
                f"| `{method.upper()} {path}` | {auth_of(method, path)} | {DESCRIPTIONS[key]}{q} "
                f"| {schema_name(op.get('requestBody')) or '—'} | {responses} |")
        lines.append("")
    return "\n".join(lines)


def errors():
    codes = []
    for f in sorted(CODES_DIR.glob("*.rs")):
        text = f.read_text(encoding="utf-8")
        for m in CODE_RE.finditer(text):
            codes.append((f.stem, m.group(2), m.group(3), m.group(4), m.group(5)))
    declared = sum(len(re.findall(r"^pub const \w+: ErrorCode = ", f.read_text(encoding="utf-8"),
                                  re.MULTILINE))
                   for f in CODES_DIR.glob("*.rs"))
    if declared != len(codes):
        sys.exit(f"parsed {len(codes)} of {declared} error codes; fix CODE_RE")
    unknown_notes = set(NOTES) - {c[1] for c in codes}
    if unknown_notes:
        sys.exit("notes for unknown codes: " + ", ".join(sorted(unknown_notes)))
    lines = [
        "# Hata kodu kataloğu (DOC-04)",
        "",
        "> **Üretilmiş tablo — elle düzenlemeyin.** Kaynak: `crates/authn-core/src/error/codes/*.rs` "
        "(her kod `ErrorCode::new(kod, durum, İngilizce, Türkçe)`), açıklama sütunu kodun kendi Türkçe "
        "mesajıdır; notlar `generate_reference.py` içindedir.",
        "",
        f"Toplam **{len(codes)}** kararlı kod. Yayımlanmış bir kod asla yeniden adlandırılmaz ve anlamı "
        "değişmez (contracts §8). İstemciler `message`'a değil `code`'a göre dallanmalıdır.",
        "",
        "## Hata zarfı",
        "",
        "Her 4xx/5xx yanıt (yönlendirici ve katmanlardan gelen JSON olmayan hatalar dahil) aynı zarfı taşır:",
        "",
        "```json",
        '{"error": {"code": "rate_limited", "message": "…", "request_id": "0190…", "details": {}}}',
        "```",
        "",
        "- `message`: `Accept-Language`'e göre (`tr` / `en`, yoksa `server.default_locale`) yerelleştirilmiş, "
        "kullanıcıya gösterilebilir metin. İç ayrıntı içermez; 5xx'te daima genel mesaj.",
        "- `request_id`: sunucunun her istek için ürettiği UUIDv7; yanıtın `x-request-id` başlığıyla aynıdır. "
        "İstemcinin gönderdiği `x-request-id` yok sayılır.",
        "- `details`: yalnızca bazı kodlarda, kimliği doğrulanmamış birine gösterilmesi güvenli yapılandırılmış "
        "bilgi (ör. `validation_failed` → alan adı, `password_policy_violation` → kural).",
        "- `429` ve bazı `503` yanıtları `Retry-After` (saniye, yukarı yuvarlanmış, en az 1) taşır.",
        "- Bearer token reddinde ayrıca `WWW-Authenticate: Bearer error=\"invalid_token\"`.",
        "",
        "Kodu doğrudan üreten bir handler yoksa (`method_not_allowed`, `payload_too_large` gibi) zarf, "
        "`authn_core::error::codes::common::for_status` ile durum kodundan türetilir "
        "(`crates/authn-core/src/http/context.rs`).",
        "",
        "**Hesap varlığını sızdırmama:** kayıt, şifre sıfırlama, magic link, e-posta kodu ve giriş akışları var olan "
        "ve olmayan hesaplar için aynı durum, gövde ve benzer süreyle yanıt verir; bu akışlarda `conflict` "
        "veya \"hesap bulunamadı\" türünde bir kod görmezsiniz.",
        "",
    ]
    by_mod = {}
    for c in codes:
        by_mod.setdefault(c[0], []).append(c)
    for mod in MODULE_ORDER + sorted(set(by_mod) - set(MODULE_ORDER)):
        if mod not in by_mod:
            continue
        lines += [f"## {MODULE_TITLES.get(mod, mod)}", "",
                  "| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |",
                  "|-----|------|----------------------------------|-----|"]
        for _, code, status, _en, tr in by_mod[mod]:
            num = STATUS_NUM.get(status)
            if num is None:
                sys.exit(f"unknown status {status}")
            tr = tr.replace("\\\"", "\"").replace("|", "\\|")
            lines.append(f"| `{code}` | {num} | {tr} | {NOTES.get(code, '')} |")
        lines.append("")
    return "\n".join(lines)


def main():
    doc = json.loads(OPENAPI.read_text(encoding="utf-8"))
    (ROOT / "docs/api/endpoints.md").write_text(endpoints(doc), encoding="utf-8")
    (ROOT / "docs/api/errors.md").write_text(errors(), encoding="utf-8")


if __name__ == "__main__":
    main()
