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

`openapi.json`, `authn_server::openapi::document()`'in varsayılan özelliklerle (`passkey`, `sms`) üretilmiş çıktısıdır. `crates/authn-server/tests/openapi.rs` içindeki `doc_04_committed_openapi_json_is_current` testi dosyanın üretilen belgeyle birebir aynı olduğunu denetler; bir `#[utoipa::path]` veya şema değişip dosya yenilenmezse CI kırılır. Yenilemek ve iki Markdown dosyasını yeniden üretmek için:

```bash
# 1. openapi.json'u koddan yeniden yaz (sunucu çalıştırmak gerekmez):
UPDATE_OPENAPI=1 cargo test -p authn-server --all-features --test openapi
# 2. Referansları üret (yeni/silinmiş bir uç veya hata kodu için Türkçe açıklama eksikse betik hata verir):
python3 -I docs/api/generate_reference.py
```

Aynı test dosyası belgenin istemci üretimine uygunluğunu da denetler (ARC-09):

- her `operationId` benzersizdir;
- işlemlerin `security` gereksinimleri yalnızca `components.securitySchemes`'te tanımlı şemalara başvurur;
- **her** işlem `security` bildirir ve bildirim, birleşik router'ın gerçekte uyguladığı korumanın aynısıdır (K-129, aşağıda);
- her `$ref` çözülür;
- her enum şemasının değerleri, serde'nin o tür için gerçekte yazdığı ve kabul ettiği değerlerin aynısıdır. Belgeye yeni bir enum şeması girerse test, tür listeye eklenene kadar kırmızıdır.

Üretimde `/openapi.json`'u açık bırakmak istemiyorsanız `server.openapi_enabled = false` (uç `404` olur). `GET /openapi.json` kimlik doğrulaması istemez; Host doğrulaması ve oran sınırı uygulanır.

## Güvenlik şemaları

`components.securitySchemes` dört kimlik türünü tanımlar ([authentication.md](authentication.md)):

| Şema | Tür | Anlamı |
|------|-----|--------|
| `session_cookie` | `apiKey`, çerez `__Host-authn_session` | Web oturumu; durum değiştiren isteklerde ayrıca `X-CSRF-Token` |
| `bearer_jwt` | `http` bearer, `JWT` | Native istemcinin access token'ı |
| `api_key` | `apiKey`, başlık `X-API-Key` | Organizasyon API anahtarı (`ak_…`) |
| `api_key_bearer` | `http` bearer, `ak_…` | Aynı API anahtarı, `Authorization: Bearer ak_…` olarak |

Her işlem kabul ettiği kimliği `security` ile bildirir (K-129). Her gereksinim nesnesi tek bir şema içerir; birden fazla nesne **alternatiftir** (biri yeterli):

| Bildirim | Hangi işlemler | "Kimlik" sütunu ([endpoints.md](endpoints.md)) |
|----------|----------------|-----------------------------------------------|
| `[]` | Kimlik doğrulaması istemeyenler: giriş/kayıt/şifre sıfırlama, sağlık, well-known, sosyal giriş başlat/geri dönüş, `token/refresh`, kayıt bağlantısı (`/v1/admin/enrollment/*`, gövdedeki token), bekleyen giriş adımları (`/v1/login/challenge/*`, challenge token'ı çerezde/başlıkta) | `—`, `challenge token'ı`, `kayıt bağlantısı` |
| `session_cookie` \| `bearer_jwt` | `/v1/me/**`, oturum uçları (`/v1/logout*`, `/v1/reauth*`, `/v1/session/org`), `/v1/orgs` (liste/oluşturma), davet/sahiplik kabulü, `/v1/admin/**` (ek olarak passkey + step-up; [admin](../operations/admin-recovery.md)) | `oturum`, `admin` |
| `session_cookie` \| `bearer_jwt` \| `api_key` \| `api_key_bearer` | `/v1/orgs/{org_id}/**` (API anahtarı kendi organizasyonunda, kapsamlarıyla) | `oturum / API anahtarı` |
| `api_key` \| `api_key_bearer` | `POST /v1/token/introspect` | `API anahtarı` |

Bildirimler kaynakta, her uç `#[utoipa::path(security(...))]` ile yazılır; bildirimsiz işlem birleşik belgede açıkça `security: []` (kimlik gerekmez) olur. Bu yüzden bir bildirimi unutmak korumalı bir ucu açık gösterebilirdi; `arc_09_k129_declared_security_matches_the_router` testi bunu yakalar: birleşik router'daki **her** işlemi kimliksiz, oturum çereziyle (+ CSRF), native access token'la ve organizasyon API anahtarıyla (iki başlık biçimiyle) çağırır, istek gövdesini işlemin şemasından üretir ve kimlik katmanının `401 unauthenticated` reddine göre bulunan kümeyi bildirimle karşılaştırır. "Kimlik" sütunu da bu bildirimden üretilir.

## OpenAPI belgesi hakkında notlar

- **Giriş yanıtları `oneOf`'tur.** Girişi başlatan uçların (`/v1/login/password`, `/passkey`, `/magic-link/verify`, `/email-code/verify`) `200` gövdesi `LoginResponse` (`CredentialsBody` veya `ChallengeBody`), challenge adımlarının (`/v1/login/challenge/verify`, `/step`) gövdesi `ChallengeStepResponse`'tur (`ChallengeCompletedBody` veya `ChallengeStatusBody`). İkisini `status` alanı ayırır (`authenticated` / `challenge_required`). `ChallengeCompletedBody`, native istemcide "bu cihaza güven" seçildiyse `trusted_device_token`'ı (web'de `__Host-authn_trusted_device` çerezi) ve son adımın bir kez gösterilen `data`'sını (ör. kurtarma kodları) taşır.
- `GET /v1/time` ARC-03 deseninin örnek ucudur (`crates/authn-server/src/routes/example.rs`) ve kimlik doğrulaması istemez.
