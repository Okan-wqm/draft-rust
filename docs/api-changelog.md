# API değişiklik günlüğü ve geçiş notları

İstemcileri, SDK'ları (K-85) ve operatörleri etkileyen değişiklikler. En yeni en üstte. Her madde neyin değiştiğini, kimin ne yapması gerektiğini ve geriye uyumluluğu söyler.

## Wave 8A (2026-11-05)

### K-120 … K-124 — OpenAPI belgesi düzeltmeleri (yalnızca belge; kablo biçimi değişmedi)

- **Ne değişti:** sunucunun davranışı ve JSON gövdeleri aynı; yalnızca `GET /openapi.json` / `docs/api/openapi.json` artık kodu doğru anlatıyor. OpenAPI'den istemci üretenler istemcilerini yeniden üretmeli:
  - **Enum değerleri** (K-120): `text_enum!` / `org_text_enum!` ile tanımlı 15 enum şeması (`AuthMethodRef`, `ClientKind`, `FactorKind`, `LoginMethod`, `Permission`, `RequiredAction`, `AccountStatus`, `Locale`, `TermsDocument`, `ApiKeyState`, `DomainStatus`, `InvitationStatus`, `MemberStatus`, `OrgStatus`, `ServiceAccountStatus`) Rust varyant adları yerine kablodaki değerleri listeliyor (`"Pwd"` → `"pwd"`, `"OrgRead"` → `"org:read"`). Önceki belgeden üretilmiş istemciler bu alanları yanlış değerlerle (de)serileştiriyordu; elle düzeltme yaptıysanız kaldırabilirsiniz.
  - **`operationId` yeniden adlandırmaları** (K-121, üretilen metot adlarını değiştirir): `POST /v1/login/passkey/options` → `login_passkey_options`, `POST /v1/reauth/passkey/options` → `reauth_passkey_options`, `POST /v1/me/deletion/cancel` → `cancel_account_deletion`, `POST /v1/orgs/{org_id}/deletion/cancel` → `cancel_org_deletion` (önceden ikişer işlem `passkey_options` / `cancel_deletion` adını paylaşıyordu).
  - **Güvenlik şemaları** (K-122): `components.securitySchemes` eklendi (`session_cookie`, `bearer_jwt`, `api_key`, `api_key_bearer`); `POST /v1/token/introspect` `api_key` veya `api_key_bearer` ister.
  - **`POST /v1/login/password` hata kodları** (K-123): `captcha_required` / `captcha_failed` `403` altında listeleniyor (gerçek durum buydu); `429` yalnızca `rate_limited` / `login_temporarily_blocked`.
  - **Giriş yanıt şemaları** (K-124): girişi başlatan uçların `200` gövdesi `LoginResponse` (`CredentialsBody` | `ChallengeBody`), challenge adımlarınınki `ChallengeStepResponse` (`ChallengeCompletedBody` | `ChallengeStatusBody`); `status` alanı ayırır. `ChallengeCompletedBody` native yanıttaki `trusted_device_token`'ı ve son adımın `data`'sını belgeliyor.
- **Kalıcı koruma:** `crates/authn-server/tests/openapi.rs` bu dört sınıf hatayı ve `docs/api/openapi.json`'un kodla farkını CI'da yakalar. Yenileme: [`docs/api/README.md`](api/README.md#openapi-belgesini-yenilemek).

## Wave 5A (2026-11-05)

### K-79 — Kişisel veri dışa aktarma artık `POST /v1/me/export` (kırıcı değişiklik)

- **Ne değişti:** uç, wave 4B denetiminde (K-58) güvenli yöntemden `POST`'a taşındı. Eski yöntemle gelen istek **`405 Method Not Allowed`** alır. Yanıt gövdesi, biçimi (`rust-authentication/personal-data-export/v1`), başlıkları (`Content-Disposition: attachment; filename="personal-data-export.json"`, `Cache-Control: no-store`), step-up ve oran sınırı (`account.export_per_user`, varsayılan günde 2) değişmedi.
- **Neden:** güvenli bir yöntem CSRF denetimlerinden geçmez ve siteler arası üst düzey gezinmede (SameSite=Lax) oturum çereziyle gönderilir. Herhangi bir site kurbanın günlük dışa aktarma hakkını tüketebiliyordu. `POST` CSRF korumasındadır.
- **Web istemcileri:** düz bağlantı (`<a href="/v1/me/export">`) yerine
  `fetch('/v1/me/export', { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': csrfToken } })`
  kullanın ve yanıtı `Blob` olarak indirin. Gövde gönderilmez. `Origin` tarayıcı tarafından aynı köken olarak eklenir. CSRF başlığı eksikse `403 csrf_failed`.
- **Native / mobil istemciler ve SDK'lar:** `Authorization: Bearer <access token>` ile `POST`, gövdesiz. CSRF başlığı gerekmez.
- **Hata akışı (değişmedi):** `401 step_up_required` → `POST /v1/reauth` ile yeniden doğrulayıp tekrar deneyin; impersonation altında `403 forbidden`; sınır aşımında `429` + `Retry-After`.
- **Belge:** OpenAPI açıklaması (`authn_account::routes::export_data`: yalnızca `post`, `401/403/405/429` yanıtları), `crates/authn-account/README.md` ("İstemciler için: kişisel veri dışa aktarma"), `docs/compliance/kvkk-gdpr.md`. Test: `acc_10_k58_export_is_a_post_never_a_get`, `acc_10_k79_openapi_documents_the_export_as_post_only`.

### K-78 — `amr` ve kuruluşun izinli ikinci faktörleri

- **Ne değişti:** oturum artık MFA'yı hangi ikinci faktörlerin ürettiğini kaydeder (`sessions.mfa_factors`, migration `2002`). Kuruluş politikasındaki izinli faktörler (`allowed_mfa_factors`, MFA-08) kuruluş değiştirmede (`POST /v1/session/org`) bu listeye göre denetlenir, `amr`'den çıkarılmaz.
- **Etkisi:**
  - Riskli girişin e-posta onayı (RSK-03) `amr`'ye `email` eklemeye devam eder, ama hiçbir zaman ikinci faktör sayılmaz. Bir kuruluş yalnızca `email` faktörüne izin veriyorsa, `mfa`'sı TOTP'den gelen oturum artık o kuruluşa geçemez (`403 org_policy_mfa_required`; izinli faktörle step-up yapılır).
  - E-posta kodu ile giriş + TOTP artık ayırt edilir: `amr` `["email", "otp", "mfa"]` olur (önceden `mfa` eklenmiyordu) ve kayıtlı faktör `totp`'dir. Parola + risk onayı + e-posta faktörü de artık `mfa` üretir (önceden risk onayının `email`'i faktörü gizliyordu).
  - Migration'dan önce oluşturulmuş oturumların kayıtlı faktörü yoktur. Faktörleri kısıtlayan bir kuruluşa geçerken bir kez step-up istenir.
- **İstemci tarafı:** yanıt şekli değişmedi. `amr`'yi kendi politikası için okuyan istemciler, e-posta kodu + TOTP oturumlarında artık `mfa` göreceklerini bilmelidir.

### K-77 — Anahtarlı audit zinciri (operatörler, admin API)

- **Ne değişti:** yeni audit olayları `HMAC-SHA-256(K_v, prev_hash ‖ kayıt)` ile zincirlenir. `K_v`, `crypto.hmac_root_key`'den türetilen zincir anahtarının `v` sürümüdür (`[audit.chain] key_version`). Eski olaylar SHA-256 ile kalır ve öyle doğrulanır. Yeni güvenlik olayı türü: `audit.chain_key_rotated`.
- **Admin API (`POST /v1/admin/audit-events/verify`, ekleme, geriye uyumlu):** yanıta `legacy_events`, `keyed_from_seq`, `head_key_version` alanları eklendi. Yeni `problem` değerleri: `key_downgrade`, `unkeyed_event`, `key_switch_unrecorded`.
- **CLI:** `verify-audit-chain [--anchor <seq>:<hash>] [--legacy-until-seq <seq>]`, yeni `rotate-audit-chain-key`. Sunucu açılışta zinciri yapılandırılmış anahtar sürümüne geçirir.
- **Operatörün yapması gereken:** yükseltmeden sonra loglanan `chain_key_switch` kontrol noktasını (`seq`, `hash`) dışarıda saklayın ve `audit.chain.legacy_until_seq = seq - 1` ayarlayın. Ayrıntı: `crates/authn-audit/README.md` ("K-77: anahtarlı zincir").
- **Geri dönüş:** yükseltmeden sonra eski bir sürüme dönmek, eski sürümün anahtarsız satır yazmasına yol açar. Doğrulayıcı bunu `key_downgrade` olarak raporlar. Geri dönmeyin; gerekirse ileri düzeltin.
