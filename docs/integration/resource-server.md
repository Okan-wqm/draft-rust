# Kaynak sunucusu: access token doğrulama (DOC-05)

Kendi API'niz (sipariş servisi, B2B arka ucu…) `rust-authentication`'ın verdiği access token'ları kabul edecekse iki yol var:

| Yol | Ne zaman | Gecikme | İptali görme |
|-----|----------|---------|--------------|
| **Yerel JWT doğrulama** (JWKS) | Her istekte; varsayılan | ağ yok (JWKS önbellekte) | En geç token'ın `exp`'inde (≤ `session.access_token_ttl`, varsayılan 10 dk) |
| **Introspection** (`POST /v1/token/introspect`) | Yüksek riskli işlemlerde; iptalin anında görülmesi gerektiğinde | istek başına bir HTTP çağrısı | Anında (oturumun canlılığı sorgulanır) |

Kaynaklar: `crates/authn-session/src/claims.rs` (claim'ler), `crates/authn-crypto/src/jwt.rs` (doğrulama kuralları), `crates/authn-session/src/service/introspect.rs`, `crates/authn-store/src/signing_keys.rs` (anahtar yaşam döngüsü).

## 1. Token biçimi

- **Başlık:** tam olarak `{"alg":"EdDSA","typ":"at+jwt","kid":"<anahtar kimliği>"}`. Tek algoritma Ed25519'dur. Başlığa göre algoritma **seçmeyin**; `EdDSA` dışındaki her şeyi (`none`, `HS256`, `RS256`, `ES256`…) reddedin. Başka başlık parametresi (`jku`, `jwk`, `x5u`, `crit`…) gelirse reddedin.
- **Claim'ler:**

| Claim | Tür | Anlam |
|-------|-----|-------|
| `iss` | string | `session.issuer`; varsayılan `server.public_base_url` **sondaki `/` olmadan** (ör. `https://auth.example.com`) |
| `sub` | string | Opak kullanıcı kimliği (UUIDv7). E-posta/ad taşınmaz |
| `aud` | string dizisi | `session.audiences` (varsayılan `["rust-authentication"]`). Kendi API'niz için ayrı bir audience ekleyip yalnızca onu kabul edin |
| `exp`, `iat`, `nbf` | tamsayı (Unix sn) | `exp − iat` ≤ `session.access_token_ttl`; `exp` oturumun mutlak bitişini aşmaz |
| `jti` | string | Token kimliği |
| `sid` | string | Oturum kimliği (refresh ailesi) |
| `auth_time` | tamsayı | Son (yeniden) kimlik doğrulama; step-up kararlarında kullanın |
| `amr` | string dizisi | RFC 8176 değerleri (`pwd`, `otp`, `sms`, `hwk`, `swk`, `mfa`, `kba`, `user`, `pin`, `fpt`, `face`, `rba`, `mca`) ve uzantılar `email`, `fed` |
| `acr` | string (opsiyonel) | Kimlik doğrulama bağlam sınıfı |
| `org_id` | string (opsiyonel) | Aktif organizasyon (B2B kiracı) |
| `scope` | string | Boşlukla ayrılmış kapsamlar (`session.default_scopes`, varsayılan `api`) |
| `client_id` | string | Faz 1'de her zaman `first-party` |
| `act` | nesne (opsiyonel) | Impersonation: `{"sub": "<admin kullanıcı kimliği>"}` (RFC 8693) |
| `read_only` | bool (opsiyonel) | `true` ise impersonation salt-okunurdur: **durum değiştiren her isteği reddedin** |

## 2. JWKS ve anahtar rotasyonu

- Uç: `GET {public_base_url}/.well-known/jwks.json` — kimlik doğrulama yok, `Cache-Control: public, max-age=<crypto.signing_keys.jwks_cache_ttl>` (varsayılan 3600).
- Girdi biçimi: `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"<base64url>","kid":"…","alg":"EdDSA","use":"sig"}]}`.
- JWKS üç durumdaki anahtarları içerir: `pending` (henüz imzalamıyor, en az `pending_period` ≥ `jwks_cache_ttl` önce yayımlanır), `active` ve `publish_until` süresi dolmamış `retired` anahtarlar. Bu sayede `max-age`'e uyan bir önbellek rotasyonda hiçbir zaman eksik kalmaz.
- **İptal edilen anahtar (acil rotasyon) JWKS'ten hemen düşer.** Önbelleğinizi `max-age`'den uzun tutmayın.
- Bilinmeyen `kid` görürseniz JWKS'i **bir kez** yenileyin, ama bunu sınırlayın (ör. en fazla 30–60 sn'de bir); aksi hâlde rastgele `kid`'li token'lar JWKS uç noktasına sel olur. Sunucunun kendisi aynı korumayı uygular.

## 3. Doğrulama sırası (sunucunun kendi kuralları)

1. Uzunluk (≤ 8 KiB), üç parça, katı base64url (dolgusuz).
2. Başlık: yalnızca `alg`, `typ`, `kid`; `alg == "EdDSA"`; `typ == "at+jwt"` (veya `application/at+jwt`).
3. `kid` JWKS'te olmalı.
4. İmza: 64 bayt Ed25519, **katı** doğrulama (`verify_strict`) — imzalanan girdi `base64url(başlık) "." base64url(gövde)`.
5. Ancak bundan sonra gövdeyi yorumlayın: `iss` tam eşleşme, `aud` sizin audience'ınızı içermeli, `exp`/`iat` zorunlu tamsayı, `nbf` varsa, saat kayması toleransı (sunucu `crypto.jwt_leeway` = 30 sn kullanır), `iat ≤ exp`, `exp − iat` ≤ beklenen azami ömür.
6. Yetkilendirme: `org_id` istenen kiracıyla eşleşmeli, `scope` gereken kapsamı içermeli, `read_only == true` ise yazma yok, `act` varsa işlemi "admin X, kullanıcı Y adına" olarak loglayın.

## 4. Rust örneği

Bağımlılıklar (izin verici lisanslı): `ed25519-dalek = "2.2"`, `base64 = "0.22"`, `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`. Bu kod, bu belge yazılırken `authn-crypto`'nun ürettiği gerçek token'lar ve JWKS ile denenmiştir (geçerli token kabul, imzası bozulmuş veya yanlış audience'lı token ret).

```rust
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Jwk { kty: String, crv: String, kid: String, x: String }
#[derive(Deserialize)]
struct JwkSet { keys: Vec<Jwk> }

/// `GET /.well-known/jwks.json` gövdesini `kid -> anahtar` haritasına çevirir.
pub fn parse_jwks(json: &str) -> Result<HashMap<String, VerifyingKey>, String> {
    let set: JwkSet = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let mut keys = HashMap::new();
    for jwk in set.keys {
        if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
            continue;
        }
        let raw = URL_SAFE_NO_PAD.decode(&jwk.x).map_err(|e| e.to_string())?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| "bad key length".to_owned())?;
        keys.insert(jwk.kid, VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())?);
    }
    Ok(keys)
}

/// Başlıkta yalnızca bu üç üye olabilir.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header { alg: String, typ: String, kid: String }

#[derive(Debug, Deserialize)]
pub struct Actor { pub sub: String }

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub jti: String,
    pub sid: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub acr: Option<String>,
    pub org_id: Option<String>,
    pub scope: String,
    pub client_id: String,
    pub act: Option<Actor>,
    pub read_only: Option<bool>,
}

pub struct Expected<'a> {
    pub issuer: &'a str,          // ör. "https://auth.example.com" (sondaki / yok)
    pub audience: &'a str,        // session.audiences içindeki sizin değeriniz
    pub leeway_secs: i64,         // 30
    pub max_lifetime_secs: i64,   // session.access_token_ttl, varsayılan 600
}

pub fn verify(token: &str, keys: &HashMap<String, VerifyingKey>, expected: &Expected<'_>)
    -> Result<Claims, String>
{
    if token.len() > 8 * 1024 {
        return Err("token too long".into());
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a compact JWS".into());
    };
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if header.alg != "EdDSA" {
        return Err("unexpected alg".into()); // algoritma sabit; başlık seçemez
    }
    if header.typ != "at+jwt" && header.typ != "application/at+jwt" {
        return Err("unexpected typ".into());
    }
    let key = keys.get(&header.kid).ok_or("unknown kid")?; // → JWKS'i (sınırlı) yenile, bir kez tekrar dene
    let sig: [u8; 64] = URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())?
        .try_into().map_err(|_| "bad signature length".to_owned())?;
    let signing_input = &token[..h.len() + 1 + p.len()];
    key.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| "bad signature".to_owned())?;

    // Gövde yalnızca imza doğrulandıktan sonra yorumlanır.
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs() as i64;
    let l = expected.leeway_secs;
    if claims.iss != expected.issuer {
        return Err("wrong iss".into());
    }
    if !claims.aud.iter().any(|a| a == expected.audience) {
        return Err("wrong aud".into());
    }
    if claims.exp + l <= now {
        return Err("expired".into());
    }
    if claims.nbf.is_some_and(|nbf| nbf > now + l) || claims.iat > now + l || claims.iat > claims.exp {
        return Err("not yet valid".into());
    }
    if claims.exp - claims.iat > expected.max_lifetime_secs {
        return Err("lifetime too long".into());
    }
    Ok(claims)
}
```

İstek işleyicisinde: `Authorization: Bearer <token>` başlığını alın, `verify` başarısızsa `401` + `WWW-Authenticate: Bearer error="invalid_token"` dönün; sonra `org_id`, `scope` ve `read_only` ile yetkilendirin.

**Bu workspace içindeki Rust servisleri** aynı mantığı kopyalamak yerine `authn_crypto::jwt::{JwtVerifier, JwtValidation}` kullanabilir: `JwtValidation::access_token(issuer, audience).with_leeway(..).with_max_lifetime(..)` ve `JwtVerifier::new([(kid, Ed25519PublicKey)])` (`crates/authn-crypto/src/jwt.rs`); bu, sunucunun kullandığı doğrulayıcının kendisidir.

## 5. Introspection (RFC 7662)

```bash
curl -s https://auth.example.com/v1/token/introspect \
  -H "Authorization: Bearer ak_live_…" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS_TOKEN"
```

- **İstemci kimliği:** bir **organizasyon API anahtarı** (`Authorization: Bearer ak_…` veya `X-API-Key: ak_…`). Geçersizse `401 unauthenticated`. Gövde `application/x-www-form-urlencoded` veya `application/json` (`{"token": "…"}`); başka içerik türü `415`. Parametreler `token` ve isteğe bağlı `token_type_hint`.
- **`active: true` yalnızca** token geçerliyse, oturumu hâlâ canlıysa, oturumun aktif organizasyonu token'daki `org_id` ile aynıysa **ve** bu `org_id` API anahtarının organizasyonuysa. Diğer her durum (iptal edilmiş, süresi dolmuş, başka organizasyonun veya kişisel — `org_id`'siz — token, `token_type_hint=refresh_token`, refresh token'ın kendisi) ayırt edilemez biçimde yalnızca `{"active": false}` döner (ARC-10 kiracı izolasyonu).
- Aktif yanıt alanları: `active`, `scope`, `client_id`, `token_type` (`Bearer`), `exp`, `iat`, `nbf`, `sub`, `aud`, `iss`, `jti`, `sid`, `auth_time`, `amr`, `acr`, `org_id`, `act`, `read_only`.
- Oran sınırı: API anahtarı başına `session.introspection_per_client` (varsayılan 600 / dk), aşımda `429` + `Retry-After`. Yanıtlar `Cache-Control: no-store`.
- Kişisel (organizasyonsuz) token'lar introspection ile **görülemez**; onları JWKS ile yerel doğrulayın.
