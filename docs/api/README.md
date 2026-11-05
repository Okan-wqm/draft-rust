# API dokümantasyonu (DOC-04)

`rust-authentication`'ın HTTP API'si: B2C web, B2B SaaS ve mobil istemcilerin ortak kullandığı tek bir JSON API'si. Tüm kimlik doğrulamalı uçlar `/v1` altındadır; sağlık uçları `/health/*`, açık anahtar ve uygulama ilişkilendirme belgeleri `/.well-known/*` altındadır.

| Belge | İçerik |
|-------|--------|
| [`openapi.json`](openapi.json) | Sunucunun **gerçek** OpenAPI 3.1 belgesi (`authn_server::openapi::document()`, `GET /openapi.json` ile sunulanın aynısı). Şemaların ve yanıt açıklamalarının tek kaynağı |
| [`endpoints.md`](endpoints.md) | 161 işlemin Türkçe referansı (yöntem, yol, kimlik türü, açıklama, istek şeması, yanıt kodları) — `openapi.json`'dan üretilir |
| [`errors.md`](errors.md) | 128 kararlı hata kodunun kataloğu (HTTP durumu, anlamı, notlar) ve hata zarfı — kaynak koddan üretilir |
| [`authentication.md`](authentication.md) | Web oturumu ve native token'lar, ara katmanın karar sırası, CSRF, tüm çerezler (SameSite/Secure/HttpOnly/`__Host-`), JWT claim'leri, istek/yanıt başlıkları, CORS |
| [`rate-limiting.md`](rate-limiting.md) | GCRA, arka uçlar, `429` + `Retry-After` semantiği, eylem sınırları tablosu |
| [`pagination.md`](pagination.md) | Keyset sayfalaması (`limit`, `cursor`, `next_cursor`), sayfalı uçlar ve filtreleri |

İlgili: istemci entegrasyon rehberleri [`docs/integration/`](../integration/README.md), akış diyagramları [`docs/architecture/flows.md`](../architecture/flows.md), değişiklik günlüğü [`docs/api-changelog.md`](../api-changelog.md).

## Temel kurallar

- **İçerik türü:** istek ve yanıt gövdeleri `application/json` (UTF-8). İstisnalar: `POST /v1/token/introspect` (`application/x-www-form-urlencoded` veya JSON), `POST /v1/oauth/{provider}/callback` (form; Apple `form_post`), `POST /v1/me/export` (gövdesiz istek, `attachment` yanıt). Gövde sınırı `server.limits.body_limit_bytes` (varsayılan 64 KiB).
- **Hatalar:** her hata `{"error": {"code", "message", "request_id", "details"?}}` zarfındadır; istemciler `code`'a göre dallanır ([errors.md](errors.md)).
- **Dil:** `Accept-Language: tr` veya `en` hata mesajlarını yerelleştirir.
- **Önbellek:** yanıtlar varsayılan olarak `Cache-Control: no-store`'dur; yalnızca JWKS ve well-known belgeleri `public, max-age` taşır.
- **İstek kimliği:** her yanıtta sunucunun ürettiği `x-request-id` (UUIDv7) vardır; destek taleplerinde bunu verin.
- **Hesap varlığı:** kayıt, şifre sıfırlama, magic link, e-posta kodu ve giriş, hesap var olsun olmasın aynı durum, gövde ve süreyle yanıt verir. İstemci arayüzü de "bu adres kayıtlı değil" gibi bir mesaj göstermemelidir.
- **Step-up:** hassas işlemler son `session.step_up_max_age` (varsayılan 10 dk) içinde yeniden doğrulama ister; yoksa `401 step_up_required` → `POST /v1/reauth` → isteği tekrarla.
- **Kiracı izolasyonu:** başka organizasyonun kaynağı her zaman `404 not_found` döner (var olmayanla aynı).

## OpenAPI belgesini yenilemek

`openapi.json` bu belgenin yazıldığı commit'teki (`47c84a7`) koddan alındı. Kod değişince yenileyin ve iki Markdown dosyasını yeniden üretin:

```bash
# 1. Çalışan bir geliştirme sunucusundan (server.openapi_enabled = true, varsayılan):
curl -sf http://localhost:8080/openapi.json | python3 -m json.tool --indent 2 --no-ensure-ascii > docs/api/openapi.json
# 2. Referansları üret (yeni/silinmiş bir uç veya hata kodu için Türkçe açıklama eksikse betik hata verir):
python3 -I docs/api/generate_reference.py
```

Üretimde `/openapi.json`'u açık bırakmak istemiyorsanız `server.openapi_enabled = false` (uç `404` olur). `GET /openapi.json` kimlik doğrulaması istemez; Host doğrulaması ve oran sınırı uygulanır.

## OpenAPI belgesinin bilinen eksikleri

Belge kodla birlikte üretilir ama birkaç noktada kodun davranışını tam yansıtmaz. İstemci üretecekseniz bunları bilin (raporlandı; düzeltmesi kod sahiplerinindir):

- **Metin enum'larının değerleri yanlış.** `text_enum!` / `org_text_enum!` makrolarıyla tanımlanan 17 enum şemasında (`AuthMethodRef`, `ClientKind`, `FactorKind`, `LoginMethod`, `Permission`, `RequiredAction`, `AccountStatus`, `ApiKeyState`, `DomainStatus`, `InvitationStatus`, `Locale`, `MemberStatus`, `OrgStatus`, `ServiceAccountStatus`, `TermsDocument`, …) OpenAPI Rust varyant adlarını listeler (`"Password"`, `"Pwd"`, `"RecoveryCode"`, `"OrgRead"`), oysa kablodaki gerçek değerler serde `rename` değerleridir (`"password"`, `"pwd"`, `"recovery_code"`, `"org:read"`). utoipa, makro içinden gelen `#[serde(rename = $text)]`'i okumuyor. Bu belgelerdeki değerler (gerçek olanlar) kaynak koddan alınmıştır (`crates/authn-core/src/domain/amr.rs`, `crates/authn-org/src/permission.rs`); OpenAPI'den istemci üretirken bu enum'ları elle düzeltin.
- **Güvenlik şemaları tanımlı değil.** `components.securitySchemes` yok; yalnızca `POST /v1/token/introspect` tanımsız `api_key` şemasına başvuruyor. Hangi ucun hangi kimliği istediği [endpoints.md](endpoints.md)'deki "Kimlik" sütunundadır.
- **Yinelenen `operationId`:** `passkey_options` (`POST /v1/login/passkey/options` ve `POST /v1/reauth/passkey/options`) ve `cancel_deletion` (`POST /v1/me/deletion/cancel` ve `POST /v1/orgs/{org_id}/deletion/cancel`). OpenAPI `operationId`'nin benzersiz olmasını ister; bazı kod üreteçleri bu belgeyle çakışan metot adları üretir.
- **Yanıtta belgelenmemiş alanlar:** `POST /v1/login/challenge/verify` / `step` başarılı olduğunda native yanıtı `trusted_device_token` (güvenilir cihaz seçildiyse) ve bazı adımlarda `data` alanı taşıyabilir; `CredentialsBody` şeması bunları listelemez (`crates/authn-session/src/login/routes.rs`).
- **`POST /v1/login/password` için `429` açıklaması** `captcha_required`'ı da sayar; bu kodun gerçek durumu `403`'tür ([errors.md](errors.md)).
- `GET /v1/time` ARC-03 deseninin örnek ucudur (`crates/authn-server/src/routes/example.rs`) ve kimlik doğrulaması istemez.
