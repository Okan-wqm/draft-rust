# ADR 0001 — JWT/JWS uygulaması: `ed25519-dalek` üzerinde minimal, algoritması sabit JWS

- **Durum:** Kabul edildi (2026-10-31)
- **Sahip:** `authn-crypto`
- **İlgili gereksinimler:** CRY-09, CRY-10, CRY-12, CRY-14, SES-08, SES-09, SES-10, TST-02, TST-04
- **Kod:** `crates/authn-crypto/src/jwt.rs`, `crates/authn-crypto/src/signing.rs`, `crates/authn-store/src/signing_keys.rs`, `fuzz/fuzz_targets/jwt_parse.rs`

## Bağlam

Sistem, mobil/native istemciler ve kaynak sunucuları için access token'ları JWT olarak imzalar (SES-05, SES-08) ve JWKS ile yayınlar (SES-09). Spesifikasyon iki seçeneğe izin verir (requirements §1):

1. `jsonwebtoken` crate'i (`rust_crypto` arka ucu ile EdDSA),
2. `ed25519-dalek` üzerine minimal, algoritması sabit bir JWS uygulaması.

JWT kütüphanelerindeki tarihsel açıkların büyük çoğunluğu **algoritma seçiminin token'a bırakılmasından** doğar: `alg: none`, RS256 açık anahtarının HS256 sırrı olarak kullanılması (algorithm confusion), `jku`/`jwk`/`x5u` ile saldırgan anahtarının içeri alınması, `crit` ile tanınmayan uzantılar, `b64: false` gibi beklenmedik biçimler. TST-02 bu sınıfların tamamı için regresyon testi ister.

## Değerlendirilen seçenekler

| Ölçüt | `jsonwebtoken` (`rust_crypto`) | Minimal sabit-algoritmalı JWS |
|-------|-------------------------------|-------------------------------|
| Desteklenen algoritmalar | HS*, RS*, PS*, ES*, EdDSA — doğru `Validation::algorithms` ve doğru `DecodingKey` tipiyle sınırlanmalı; yanlış yapılandırma tek satırlık hata | Yalnızca EdDSA; başka algoritma kod yolu **yok** |
| Ek bağımlılıklar | `rsa 0.9` (RUSTSEC-2023-0071, Marvin), `p256`/`p384 0.13` → `crypto-bigint 0.5` (RUSTSEC-2026-0387), `simple_asn1`, `pem` | Yok (`ed25519-dalek` zaten iş akışında) |
| Header işleme | Bilinmeyen parametreler sessizce kabul edilir | Yalnızca `alg`, `typ`, `kid`; diğer her şey (`crit`, `jku`, `jwk`, `x5u`, `x5c`, `b64`…) ve yinelenen adlar reddedilir |
| `typ` (RFC 9068 `at+jwt`) | Elle kontrol edilmeli | Zorunlu, doğrulamanın parçası |
| Yinelenen claim adları | Son değer kazanır | Reddedilir (RFC 7519 §4) |
| İmza doğrulaması | `verify` | `verify_strict` (kanonik olmayan `S`, küçük mertebeli noktalar reddedilir) |
| Kod büyüklüğü / denetlenebilirlik | Büyük, genel amaçlı | ~550 satır (belgeler dahil), tek dosya, fuzz edilir |
| Lisans | MIT | Bağımlılıklar MIT/Apache-2.0/BSD-3 (LIC-01) |

## Karar

**Seçenek 2** uygulanır: `authn_crypto::jwt` içinde kompakt JWS serileştirmesi, yalnızca EdDSA (Ed25519). Algoritma kodda sabittir; header'daki `alg` değeri bir algoritma *seçmek* için değil, yalnızca sabit değerle (`EdDSA`) karşılaştırmak için okunur.

Doğrulama sırası (her adım kapalı başarısız olur; imza doğrulanmadan payload yorumlanmaz):

1. Boyut (≤ 8 KiB), yalnızca ASCII, tam olarak üç boş olmayan bölüm (JWE ve imzasız JWS biçimleri reddedilir).
2. Katı base64url (dolgu yok, kanonik son bitler); header bir JSON **nesnesi** olmalı (dizi kabul edilmez), yinelenen ad yok, yalnızca `alg`/`typ`/`kid`.
3. `alg == "EdDSA"` (büyük/küçük harf dahil tam eşitlik); `none`, `HS*`, `RS*`, `ES*`, `PS*` vb. → `UnsupportedAlgorithm`.
4. `typ` beklenen tür (`at+jwt`; RFC 7515 §4.1.9 gereği `application/` öneki ve harf büyüklüğü farkı kabul edilir).
5. `kid` doğrulayıcının anahtar kümesinde olmalı (iptal edilmiş anahtar kümede yoktur → `UnknownKey`).
6. 64 baytlık imza, alınan imzalama girdisi üzerinde bayt bayt `verify_strict`.
7. Payload: katı base64url, yinelenen adı olmayan JSON nesnesi; `iss` (tam eşitlik), `aud` (dize veya dizi, beklenen kitleyi içermeli), `exp` ve `iat` zorunlu tamsayı, `nbf` isteğe bağlı tamsayı; saat kayması toleransı `crypto.jwt_leeway` (varsayılan 30 sn); `iat ≤ exp`; isteğe bağlı azami ömür.

İstemciye dönen hata her durumda `unauthenticated`'dır; ayrıntılı neden (`JwtError`) yalnızca loglanır.

JWKS (`JwkSet`) yalnızca `kty=OKP`, `crv=Ed25519`, `x`, `kid`, `alg=EdDSA`, `use=sig` alanlarını içerir; özel anahtar alanı (`d`) tipte bulunmaz. `kid`, `signing_keys.id` (UUIDv7) değeridir.

## Sonuçlar

**Olumlu**

- Algoritma karışıklığı saldırıları yapısal olarak imkânsız; `rsa`/eski `p256` zinciri ve ilgili RustSec istisnaları JWT yolu için gerekmez.
- Header ve claim ayrıştırıcısı küçük, tamamen bizim testlerimizle (`jwt/tests.rs`: `none`, HS256-açık-anahtar karışıklığı, bilinmeyen header parametreleri, yinelenen adlar, yanlış `kid`, süresi dolmuş, yanlış `aud`/`iss`, `nbf`/`iat` gelecekte, bölüm manipülasyonları) ve fuzz hedefiyle (`jwt_parse`, iki mod: ham token ve imzalı rastgele header/payload) güvence altında.
- Ed25519 deterministik imzalar: imzalama sırasında rastgelelik hatası yok; RFC 8032 test vektörleri `signing.rs`'te.

**Olumsuz / riskler**

- JOSE ayrıştırma kodunun bakımı bizde. Azaltım: kapsam bilinçli olarak dar, fuzz + birim testleri, bu ADR'deki doğrulama sırası değişmez kuraldır.
- RFC 9864 "tam belirtilmiş" `Ed25519` algoritma adını tanımlar; uyumluluk için yalnızca `EdDSA` üretilir ve kabul edilir. Ekosistem geçtiğinde yeni bir ADR ile `Ed25519` adı **ek** sabit değer olarak eklenebilir (yine tek eğri, tek algoritma).
- Faz 2 OIDC sağlayıcısında RS256 bekleyen istemciler olursa ayrı bir ADR gerekir; o durumda bile algoritma anahtar kaydına bağlı olmalı, header'dan seçilmemelidir.
- Üçüncü taraf kimlik sağlayıcılarının ID token'larının (SOC-03; RS256/ES256) doğrulanması bu modülün işi değildir; `authn-oidc-client` `openidconnect` ile yapar.

## Reddedilen alternatif

`jsonwebtoken`: işlevsel olarak yeterli, ancak yukarıdaki tablo nedeniyle saldırı yüzeyi ve bağımlılık riski daha büyük. Yalnızca EdDSA kullanacağımız için genelliğinin bir faydası yok.
