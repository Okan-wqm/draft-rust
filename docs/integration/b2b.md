# B2B SaaS entegrasyonu: organizasyonlar, davetler, roller, API anahtarları, politikalar (DOC-05)

Kaynaklar: `crates/authn-org/` (README: yetkilendirme sırası, yükseltme koruması, API anahtarları, davetler, domain doğrulama, politikalar), `crates/authn-org/src/{authz,policy,permission,api_key,middleware}.rs`, `crates/authn-session/src/service/org_switch.rs`. Uçların tam listesi: [`docs/api/endpoints.md` § Organizasyonlar](../api/endpoints.md).

## 1. Kavramlar

- **Organizasyon** = kiracı. Bir kullanıcı birden fazla organizasyonun üyesi olabilir; oturumun bir **aktif organizasyonu** olur (JWT `org_id`, yanıtlarda `active_org_id`).
- **Kiracı izolasyonu:** başka organizasyonun her kaynağı `404 not_found` döner (var olmayanla aynı yanıt, ORG-10). `/v1/orgs/{org_id}/…` uçları her istekte yetkilendirmeyi yeniden yapar (`OrgService::authorize`): principal → salt-okunur kontrolü → organizasyon durumu (`org_suspended`, `org_pending_deletion`) → **politika** → izin.
- **Organizasyon kurma:** `POST /v1/orgs {name, slug}` → çağıran `owner` olur (kullanıcı başına `org.creates_per_user`).
- **Aktif organizasyonu seçme:**
  - Girişte: `POST /v1/login/password` (ve diğer giriş uçları) gövdesinde `org_id` → üyelik, IP izin listesi, izinli giriş yöntemi ve MFA politikası girişte uygulanır.
  - Oturum açıkken: `POST /v1/session/org {"org_id": "…"}` → oturum (web'de çerez + yeni CSRF token'ı, native'de yeni token çifti) döner. Politika ömür üst sınırı oturumun mutlak bitişini yalnızca kısaltır.

## 2. Roller ve izinler (RBAC)

İzin kataloğu (`GET /v1/org-permissions`): `org:read`, `org:update`, `org:delete`, `org:transfer_ownership`, `members:read`, `members:invite`, `members:update`, `members:remove`, `roles:read`, `roles:manage`, `policies:read`, `policies:manage`, `domains:read`, `domains:manage`, `api_keys:read`, `api_keys:manage`, `service_accounts:read`, `service_accounts:manage`, `webhooks:read`, `webhooks:manage`, `audit:read`, `billing:read`, `billing:manage`.

| Yerleşik rol | İzinler |
|--------------|---------|
| `owner` | hepsi (`org:delete` ve `org:transfer_ownership` yalnızca sahibe aittir) |
| `admin` | `org:read/update`, `members:*`, `roles:*`, `policies:*`, `domains:*`, `api_keys:*`, `service_accounts:*`, `webhooks:*`, `audit:read`, `billing:read` |
| `member` | `org:read`, `members:read` |
| `billing` | `org:read`, `billing:read`, `billing:manage` |
| `viewer` | `org:read`, `members:read`, `roles:read`, `policies:read`, `domains:read` |

- Özel roller: `POST /v1/orgs/{org_id}/roles` (`roles:manage`), organizasyon başına `org.limits.custom_roles`.
- **Yükseltme koruması:** rol atama, davet, servis hesabı ve API anahtarı kapsamında aktör verdiği tüm izinlere kendisi sahip olmalıdır (`403 org_role_escalation`). `owner` rolünü yalnızca `owner` verir ve her yolda step-up ister. Son sahip çıkarılamaz/düşürülemez (`409 org_last_owner`).
- Rol düşürme / izin çıkarma, etkilenen üyenin oturumlarını kapatır (`membership_changed`) ve gönderdiği bekleyen davetleri iptal eder.

## 3. Davetler

1. Davet: `POST /v1/orgs/{org_id}/invitations {email, role_id}` (`members:invite`; `owner` daveti step-up ister). Davetliye `{public_base_url}/invitations/accept#token=…` linki gider (256 bit, varsayılan 7 gün, `org.invitation_ttl`).
2. Ön yüz linki açan kullanıcıya önce giriş yaptırır, sonra `POST /v1/invitations/preview {token}` ile organizasyon adını, rolü, maskeli adresi ve `email_matches`'i gösterir.
3. Kabul: `POST /v1/invitations/accept {token}` (oturum). Kabul eden hesabın **doğrulanmış** e-posta adresi davet adresiyle (normalize) eşleşmelidir: değilse `403 org_invitation_email_mismatch`, doğrulanmamışsa `403 org_email_verification_required`. Bilinmeyen/kullanılmış/iptal/süresi dolmuş token ayırt edilemez: `400 invalid_or_expired_token`. Zaten üyeyse `409 org_already_member`.
4. Kabul atomiktir; davetle gelen üye domain otomatik katılımındaki "çıkarıldı/ayrıldı" istisnasını da siler.

Yeniden gönderim (`…/resend`) yeni token üretir, eskisi ölür; gönderimler organizasyon ve organizasyon + alıcı başına sınırlıdır.

## 4. Domain doğrulama ve otomatik katılım

`POST /v1/orgs/{org_id}/domains {domain}` yanıtındaki TXT kaydını yayımlayın: `<org.domain_verification_label>.<domain>` (varsayılan `_authn-verification.example.com`), değer `authn-verification=<43 karakter>`. Sonra `POST …/domains/{domain_id}/verify`. Bir domain'i yalnızca bir organizasyon doğrulayabilir. Doğrulanmış domain'de otomatik katılım açılabilir (`PATCH …/domains/{domain_id}`): doğrulanmış e-posta adresi **tam olarak** o domain'de olan kullanıcılar girişte / e-posta doğrulamasında `member` olarak eklenir (alt domain'ler eşleşmez; çıkarılan veya ayrılan kullanıcılar geri eklenmez).

## 5. Güvenlik politikası

`PUT /v1/orgs/{org_id}/policy` (`policies:manage` + step-up; tam değiştirme):

```json
{
  "mfa_required": true,
  "phishing_resistant_mfa_required": false,
  "allowed_login_methods": ["password", "passkey", "social"],
  "allowed_mfa_factors": ["totp", "webauthn"],
  "max_session_lifetime_seconds": 43200,
  "ip_allowlist": ["203.0.113.0/24"],
  "trusted_devices_allowed": true,
  "allowed_passkey_aaguids": null
}
```

Giriş yöntemleri: `password`, `passkey`, `magic_link`, `email_code`, `social`. Faktörler: `totp`, `webauthn`, `recovery_code`, `email`, `sms`. Alan verilmezse kısıt yoktur.

**Uygulama noktaları ve istemcinin göreceği hatalar:**

| Ne zaman | Denetim | Hata |
|----------|---------|------|
| `org_id` ile giriş, `POST /v1/session/org` | üyelik, IP, izinli giriş yöntemi, MFA / phishing'e dayanıklı MFA, izinli ikinci faktörler | `404` (üye değil), `403 org_policy_ip_denied`, `403 login_method_not_allowed`, `403 org_policy_mfa_required` |
| **Her** `/v1/orgs/{org_id}/…` isteği (K-57, oturum organizasyonu etkinleştirmemiş olsa bile) | IP izin listesi; üyeler için oturumun MFA gücü, oturum ömrü üst sınırı, oturumun birincil giriş yöntemi ve ikinci faktörü (K-78: `sessions.mfa_factors`) | `403 org_policy_ip_denied`, `403 org_policy_mfa_required`, `401 step_up_required` (ömür sınırı aşıldı), `403 login_method_not_allowed` |
| Politika değişikliği | yeni politika **çağıranı** dışarıda bırakırsa reddedilir | `422 org_policy_lockout` (`details.reason` ∈ `ip_allowlist`, `mfa`, `login_method`) |

Notlar:

- **`403 login_method_not_allowed`** (K-57): oturum, organizasyonun izin vermediği bir yöntemle (ör. `magic_link`) açılmışsa organizasyon uçları reddedilir. İstisna: oturum bir passkey içeriyorsa (`amr`'de `hwk`/`swk`) ve politika `passkey`'e izin veriyorsa kabul edilir — passkey ile step-up yapmak bu durumu çözer. İstemci, kullanıcıyı izinli bir yöntemle yeniden giriş yapmaya yönlendirmelidir.
- **`403 org_policy_mfa_required`**: organizasyon MFA istiyor ve oturumda MFA yok, ya da `allowed_mfa_factors` tanımlı ve oturumun MFA'sını üreten faktör listede değil (passkey tek başına yeter). Çözüm: izinli bir faktörle `POST /v1/reauth`. K-78 öncesi oluşturulmuş oturumların kayıtlı faktörü yoktur; faktör kısıtlayan bir organizasyonda bir kez step-up isterler.
- Impersonation oturumları giriş yöntemi/faktör denetiminden muaftır (adminin kimlik doğrulamasını taşırlar).
- API anahtarlarına oturum MFA'sı uygulanmaz; IP izin listesi uygulanır.
- Politika sıkılaştırıldığında organizasyonun oturumları kapatılır.

## 6. API anahtarları ve servis hesapları

- **Oluşturma:** `POST /v1/orgs/{org_id}/api-keys {name, scopes, expires_at?, service_account_id?}` (`api_keys:manage` + step-up; bir API anahtarı anahtar üretemez). Yanıt `{key, api_key}`; `key` **bir kez** gösterilir, yalnızca SHA-256'sı saklanır. Bitiş zorunludur (varsayılan `org.api_keys.default_lifetime` = 90 g, en fazla `max_lifetime` = 365 g).
- **Biçim:** `ak_<ortam>_<43 base62>_<6 base62 sağlama>` (ör. `ak_live_…`). Önek gizli tarama araçlarının (secret scanning) yakalaması içindir.
- **Kullanım:** `Authorization: Bearer ak_…` **veya** `X-API-Key: ak_…` (ikisi birden `401`). Anahtar **yalnızca** `/v1/orgs/{org_id}[/…]` yollarında ve yalnızca kendi organizasyonunda kimlik doğrular; `/v1/me/…` gibi hesap uçlarında hiçbir şey yapmaz. Ayrıca `POST /v1/token/introspect` istemci kimliğidir ([resource-server.md §5](resource-server.md#5-introspection-rfc-7662)).
- **Yetki:** kişisel anahtar (servis hesabı yok) sahibinin rolündeki izinlerle **kesişen** `scopes` kadar; servis hesabı anahtarı servis hesabının rolüyle kesişen `scopes` kadar. Servis hesapları `POST /v1/orgs/{org_id}/service-accounts` ile kurulur ve organizasyon sahibi olamaz.
- **Rotasyon:** `POST …/api-keys/{key_id}/rotate` (step-up) yeni anahtarı bir kez döner; eski anahtar `org.api_keys.rotation_grace` (24 sa) boyunca çalışır. İptal (`DELETE`) rotasyon zincirindeki tüm öncülleri de iptal eder.
- **Hatalar:** tüm geçersiz anahtarlar aynı `401 unauthenticated`; IP başına iyi biçimli geçersiz anahtar sınırı (`org.api_keys.auth_failures_per_ip`) aşılınca `429`. Hesap/üyelik askısı, servis hesabının devre dışı kalması, organizasyon silme planı ve IP izin listesi anahtarı anında durdurur.

## 7. Sahiplik devri, silme, audit, webhook

- Sahiplik devri: `POST /v1/orgs/{org_id}/ownership-transfer` (sahip + step-up) → hedefe link → `POST /v1/ownership-transfers/accept {token}` (hedef + step-up); eski sahip `admin` olur.
- Silme: `DELETE /v1/orgs/{org_id}` (sahip + step-up) → `org.deletion_grace_period` (30 g) sonra kalıcı; bu sürede `POST …/deletion/cancel`. Planlanınca davetler/devirler iptal, organizasyonun oturumları kapanır, API anahtarları durur.
- Audit log: `GET /v1/orgs/{org_id}/audit-events` (`audit:read`; filtreler [pagination.md](../api/pagination.md)).
- Webhook'lar: [webhooks.md](webhooks.md).
