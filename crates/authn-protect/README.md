# authn-protect

Kötüye kullanım koruması ve web güvenliği: rate limit (bellek/PostgreSQL/Redis), CAPTCHA (Turnstile, hCaptcha, proof-of-work), yumuşak kilit, risk değerlendirmesi, güvenlik başlıkları, CORS, host ve yönlendirme doğrulama, SSRF korumalı giden HTTP.

## Sahip olunan gereksinimler

PRT-01 … PRT-05, PRT-07 … PRT-10, PRT-12, RSK-01 … RSK-04, DOC-03

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı olamaz. Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-protect/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/protect.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/protect.rs` |
| Uygulanan portlar | `RateLimiter`, `CaptchaVerifier`, `RiskEvaluator`, `GeoIpLookup` (opsiyonel), `HttpClient` |
| Sahip olunan tablolar | `rate_limit_buckets` (UNLOGGED), `login_soft_locks`, `captcha_pow_challenges`, `known_devices`, `known_networks` |
| `one_time_tokens.purpose` değerleri | — |
| Migration aralığı | `1600–1699` (`migrations/<sürüm>_<açıklama>.sql`) |

## Notlar

- PRT-06 (istemci IP tespiti) `authn-core` içinde uygulandı (`authn_core::http::client_ip`); PRT-11 (gövde/zaman aşımı/eşzamanlılık sınırları) `authn-server` katman yığınındadır.
- Redis arka ucu `redis` feature'ı ile `fred` crate'i üzerinden (redis-rs'in async yığını BSL-1.0 lisanslı `xxhash-rust` çektiği için reddedildi).
- `reqwest` istemcisi oluşturmadan önce `authn_core::tls::install_crypto_provider()` çağrılmalıdır (aksi halde reqwest panikler).

## Komutlar

```bash
cargo test -p authn-protect
cargo clippy -p authn-protect --all-targets -- -D warnings
cargo fmt -p authn-protect
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.

## Durum

İskelet: crate derleniyor, bağımlılıkları tanımlı; modül agent'ı tarafından doldurulacak. Uygulanamayan SHOULD/MAY maddeleri gerekçesiyle bu dosyaya eklenmelidir.
