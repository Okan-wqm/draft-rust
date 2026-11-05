# Webhook alıcısı (DOC-05)

Organizasyonlar, kendi sistemlerinin olaylardan (üye eklendi, API anahtarı iptal edildi…) haberdar olması için imzalı webhook'lar alabilir (AUD-07). İmza şeması **Standard Webhooks**'tur (<https://www.standardwebhooks.com>). Kaynaklar: `crates/authn-crypto/src/webhook.rs` (imza), `crates/authn-audit/src/webhooks/{delivery,fanout,endpoints}.rs` (teslim, gövde, abonelik), `crates/authn-core/src/ports/event_publisher.rs` (olay türleri).

## 1. Uç nokta kaydı

```bash
# webhooks:manage izni + step-up gerekir
curl -s https://auth.example.com/v1/orgs/$ORG/webhooks \
  -H "Authorization: Bearer $AT" -H "Content-Type: application/json" \
  -d '{"url":"https://hooks.example.com/authn","event_types":["member.added","member.removed"],"description":"CRM senkronu"}'
# → 201 {"endpoint": {...}, "secret": "whsec_…"}   (sır yalnızca bir kez gösterilir)
```

- URL: herkese açık `https` (kimlik bilgisi ve parça yok). Her teslimde SSRF koruması uygulanır: özel/loopback adreslere giden URL'ler teslim edilmez (yalnızca geliştirmede `protect.outbound.allow_private_networks`).
- Organizasyon başına en fazla `audit.webhooks.max_endpoints_per_org` (10) uç nokta.
- Abone olunabilen olay türleri (`DomainEventKind`): `user.created`, `user.updated`, `user.email_changed`, `user.deleted`, `session.created`, `session.revoked`, `organization.created`, `organization.updated`, `organization.deleted`, `member.added`, `member.removed`, `member.role_changed`, `invitation.created`, `invitation.accepted`, `invitation.revoked`, `api_key.created`, `api_key.revoked`. Yalnızca **organizasyon kapsamlı** olaylar (olayın organizasyonu varsa) o organizasyonun uç noktalarına gider.

## 2. İstek biçimi

```http
POST /authn HTTP/1.1
Content-Type: application/json
User-Agent: rust-authentication-webhooks/1
webhook-id: 0190f3c1-7b2e-7d40-9a51-3c0f0e6d2a11
webhook-timestamp: 1793000000
webhook-signature: v1,J6pCiCkk3wTc+tdvsChrYjPY32Vzr5nK1hLINLMF9h4=

{"id":"0190f3c1-…","type":"member.added","timestamp":"2026-11-05T10:00:00Z","organization_id":"0190…","user_id":"0190…","data":{…}}
```

| Öğe | Anlam |
|-----|-------|
| `webhook-id` | Olay kimliği; **yeniden denemelerde aynı kalır**. Tekilleştirme (idempotency) anahtarınız budur |
| `webhook-timestamp` | Bu teslim denemesinin Unix saniyesi |
| `webhook-signature` | Boşlukla ayrılmış bir veya daha fazla `v1,<base64(HMAC-SHA256)>` girdisi |
| Gövde | `id`, `type`, `timestamp` (RFC 3339), `organization_id`, `user_id`, `data` (sır içermez). Hesabı silinmiş kullanıcının henüz bitmemiş teslimleri bitince karartılır (`redacted`) |

## 3. İmza doğrulama

- Anahtar: `whsec_` önekinden sonraki kısmın **standart base64** (dolgulu) çözülmüş baytları (sunucu 32 bayt üretir).
- İmzalanan içerik: `{webhook-id}.{webhook-timestamp}.{ham gövde}` — gövdeyi JSON olarak ayrıştırıp yeniden serileştirmeyin, **ham baytları** kullanın.
- `HMAC-SHA256(anahtar, içerik)` → standart base64 → `v1,` girdilerinden **herhangi biriyle** sabit zamanlı karşılaştırın. Sır rotasyonunda (`POST …/rotate-secret`) `audit.webhooks.secret_rotation_overlap` (varsayılan 24 sa) boyunca her teslim eski ve yeni sırla iki kez imzalanır; `?immediate=true` ile rotasyonda eski sır hemen bırakılır.
- Tekrar penceresi: zaman damgası şimdiye göre ±5 dakika dışındaysa reddedin (sunucunun kendi doğrulayıcısı da `DEFAULT_TOLERANCE_SECS = 300` kullanır).
- `webhook-id`'yi `[A-Za-z0-9_-]{1,256}` ile sınırlayın (sunucu da öyle): `.` içeren kimlik imzalanan içeriği belirsiz yapardı.

### Rust örneği

Bağımlılıklar: `hmac = "0.12"`, `sha2 = "0.10"`, `base64 = "0.22"`, `subtle = "2.6"`. Bu kod, bu belge yazılırken `authn_crypto::webhook::sign` ile üretilen iki sırlı (rotasyon) imzalarla denenmiştir (iki sırla da kabul; değişmiş gövde ve 301 sn kayma ret).

```rust
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

const TOLERANCE_SECS: i64 = 300;

pub fn verify_webhook(
    secret: &str,            // "whsec_…"
    webhook_id: &str,        // webhook-id başlığı
    webhook_timestamp: &str, // webhook-timestamp başlığı
    webhook_signature: &str, // webhook-signature başlığı
    body: &[u8],             // ham gövde
    now_unix: i64,
) -> Result<(), &'static str> {
    let key = STANDARD
        .decode(secret.strip_prefix("whsec_").ok_or("bad secret")?)
        .map_err(|_| "bad secret")?;
    if webhook_id.is_empty()
        || webhook_id.len() > 256
        || !webhook_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("bad webhook-id");
    }
    let ts: i64 = webhook_timestamp.parse().map_err(|_| "bad webhook-timestamp")?;
    if (now_unix - ts).abs() > TOLERANCE_SECS {
        return Err("timestamp outside tolerance");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| "bad secret")?;
    mac.update(webhook_id.as_bytes());
    mac.update(b".");
    mac.update(webhook_timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    let mut ok = false;
    for entry in webhook_signature.split(' ') {
        let Some(sig) = entry.strip_prefix("v1,") else { continue };
        let Ok(sig) = STANDARD.decode(sig) else { continue };
        ok |= bool::from(sig.as_slice().ct_eq(expected.as_slice()));
    }
    if ok { Ok(()) } else { Err("no matching signature") }
}
```

Doğrulama başarısızsa `401`/`400` dönün; ayrıntı vermeyin. Diğer dillerde Standard Webhooks'un resmi kütüphaneleri aynı şemayı uygular.

## 4. Yanıt, yeniden deneme ve devre dışı kalma

- **Başarı = herhangi bir `2xx`.** Diğer her yanıt veya zaman aşımı (`audit.webhooks.timeout`, 10 sn) başarısız denemedir.
- Yeniden deneme: üstel geri çekilme + jitter, `audit.webhooks.backoff_base` (1 dk) → `backoff_max` (6 sa), en fazla `audit.webhooks.max_attempts` (8) deneme. Yanıtınızdaki `Retry-After` (saniye) `backoff_max`'a kadar dikkate alınır.
- Kesintisiz `disable_after_failures` (20) başarısız deneme **ve** en az `disable_after` (24 sa) süren hata durumunda uç nokta otomatik devre dışı kalır; `PATCH …/webhooks/{endpoint_id}` ile yeniden etkinleştirin (step-up).
- **En az bir kez teslim:** aynı olay birden fazla gelebilir; `webhook-id` ile tekilleştirin. Sıra garanti değildir; `timestamp`'e göre sıralayın.
- Teslim geçmişi: `GET /v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` (sayfalı, `audit.webhooks.delivery_retention` = 30 gün); bitmiş bir teslimi yeniden kuyruğa almak: `POST …/deliveries/{delivery_id}/redeliver`.
- Hızlı yanıt verin (işi kuyruğa alıp `2xx`); uzun işlem zaman aşımına düşer.
