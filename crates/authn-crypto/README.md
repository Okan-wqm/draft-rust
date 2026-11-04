# authn-crypto

Sistemin kriptografik yapı taşları. Bu crate **hiçbir algoritmayı kendisi icat etmez**: tüm primitifler denetlenmiş crate'lerden gelir (RustCrypto, dalek-cryptography); crate yalnızca bunları güvenli varsayılanlar, tipli sırlar ve kapalı başarısız olan (fail-closed) ayrıştırıcılarla birleştirir.

## Sahip olunan gereksinimler

CRY-01 … CRY-14, ARC-12, TST-05 (ve kendi bağımlılıkları için LIC-01 uyumu). Ayrıca `authn-store` içindeki iki modül bu crate'in agent'ına aittir: `one_time_tokens` (ARC-06 atomik tüketim, CRY-06/07) ve `signing_keys` (CRY-10).

## Bağımlılık kuralı

Katman 1: yalnızca `authn-core`'a bağımlıdır. Tüm harici bağımlılıklar kök `Cargo.toml` `[workspace.dependencies]` içindedir ve MIT / Apache-2.0 / BSD-3-Clause lisanslıdır (LIC-01; `cargo deny check` yeşil). Bu crate için **yeni** bir workspace bağımlılığı eklenmedi; kullanılmayan `sqlx`, `rand`, `rand_core`, `p256`, `crc32fast` bağımlılıkları kaldırıldı (`unicode-normalization` eklendi, zaten workspace'teydi).

## Genel API

| Modül | Gereksinim | Öne çıkan öğeler |
|-------|-----------|------------------|
| `password` | CRY-01 … 05, ARC-12, PWD-02 | `PasswordHasher` (`hash`, `verify`, `verify_dummy`, `needs_rehash`, `wrap_legacy_digest`), `VerifyOutcome`, `RehashReason`, `HashAlgorithm`, `StoredPasswordHash`, `PasswordHashRecord`, `canonicalize_password`, `Peppers`, `Argon2Settings` |
| `token` | CRY-06 | `OpaqueToken` (`generate`, `parse`, `hash`, `matches`), `TokenHash` |
| `otp` | CRY-07 | `OtpCode` (`generate`, `parse`), `OtpHasher` (`hash`, `verify`) |
| `envelope` | CRY-08 | `KeyProvider` trait, `EnvKeyProvider`, `EnvelopeCipher` (`seal`, `open`, `needs_rewrap`, `rewrap`), `EnvelopeContext`, `Envelope::parse` |
| `jwt` | CRY-09, SES-09 | `JwtSigner`, `JwtVerifier`, `JwtValidation`, `VerifiedJwt`, `RegisteredClaims`, `JwtError`, `JwkSet`/`Jwk` |
| `signing` | CRY-10 | `Ed25519SigningKey`, `Ed25519PublicKey`, `SigningKeyStatus`, `seal_private_key`, `open_private_key` |
| `kdf` | CRY-11 | `KeyPurpose` (enum), `KeyRing`, `HmacKey` (`sign`, `verify`, `sign_fields`), `hmac_sha256`, `hkdf_sha256` |
| `ct` | CRY-12 | `constant_time_eq`, `eq_array`, `position_of` |
| `secret` | CRY-13 | `SecretKey<N>`, `SecretBytes` (sıfırlanan, `Debug` redakte) |
| `totp` | MFA-01/02 çekirdeği | `Totp` (`generate`, `verify` → eşleşen zaman adımı, `provisioning_uri`), `TotpSecret`, `TotpParams`, `hotp` |
| `webhook` | AUD-07 çekirdeği | `WebhookSecret`, `sign`, `verify`, `parse_signature_header`, `SignedHeaders` |
| `random` | — | `fill`, `secret_bytes`, `uniform_below`, `string_from_alphabet` (yalnızca işletim sistemi CSPRNG'si) |
| `services` | ARC-07 | `CryptoServices::from_config` — `[crypto]` bölümünden tüm servisler, geçersiz anahtarda hızlı başarısızlık |

Hatalar `CryptoError`'dır (statik mesajlar, sır içermez); `AuthError`'a dönüşümde istemci yalnızca `internal_error` (iş havuzu kapalıysa `service_unavailable`) görür. JWT doğrulama hataları `unauthenticated` olur.

### Kullanım örneği (giriş akışı)

```rust,ignore
let services = CryptoServices::from_config(&config.crypto).await?;
let stored = credential.map(|c| StoredPasswordHash::new(&c.password_hash, &c.algorithm, c.pepper_version));
// Kullanıcı yoksa `None`: sahte hash'e karşı eşit maliyetli doğrulama (CRY-05).
match services.passwords.verify(&password, stored.as_ref()).await? {
    VerifyOutcome::Valid { rehash: Some(_) } => { /* hash(password) → rehash_password */ }
    VerifyOutcome::Valid { rehash: None } => {}
    VerifyOutcome::Invalid => return Err(invalid_credentials()),
}
```

## Kararlar

| Konu | Karar ve gerekçe |
|------|------------------|
| Şifre hash'i (CRY-01) | Argon2id v1.3, varsayılan m=19456 KiB, t=2, p=1; 16 bayt tuz, 32 bayt çıktı. Tek PHC biçimi üretilir ve kabul edilir (`$argon2id$v=19$m=…,t=…,p=…$tuz$hash`). Ayrıştırıcı el yazımı ve katıdır: başka varyant/sürüm, `keyid`/`data`, baştaki sıfırlar ve sınır dışı parametreler (m ≤ 4 GiB, t ≤ 16, p ≤ 16) reddedilir — veritabanına yerleştirilmiş bir hash girişi DoS'a çeviremez. |
| Pepper (CRY-02) | Argon2 girdisi `HMAC-SHA256(pepper[v], NFKC(şifre))`. Sürüm hash ile birlikte döner ve `password_credentials.pepper_version`'a yazılır; birden çok sürüm aynı anda yapılandırılabilir. Yapılandırmadan kaldırılmış bir sürümün hash'i `Invalid` olur (hata değil; hesap varlığı sızmaz) ve loglanır. |
| Normalizasyon (PWD-02) | Tek kanonik fonksiyon: `canonicalize_password` (Unicode NFKC). Çıktı tamponu ilk geçişte tam boyutlandırılır; yeniden ayırma olmaz, bu yüzden sıfırlanmamış kopya kalmaz. Politika (uzunluk, güç) `authn-password`'dadır; hashing katmanında yalnızca 4096 baytlık DoS sınırı vardır. |
| Rehash (CRY-03) | `VerifyOutcome::Valid { rehash }`: parametre/tuz/çıktı uzunluğu güncel değilse `OutdatedParameters`, pepper sürümü eskiyse `OutdatedPepper`, eski şema ise `LegacyAlgorithm`. `needs_rehash` hash hesaplamadan aynı kararı verir. |
| Eski hash'ler (CRY-04) | `bcrypt` (`$2a$`/`$2b$`/`$2y$`, maliyet 4–15), `pbkdf2_sha256` (PHC, passlib ve Django biçimleri, ≤ 5 000 000 iterasyon), `argon2id_wrapped_md5` / `argon2id_wrapped_sha1` (`argon2id(HMAC(pepper, hex(md5/sha1(şifre))))`). Eski sistemler aldıkları baytları hash'lediği için eski şemalar **ham** (normalize edilmemiş) şifreyle doğrulanır; başarıdan sonra kanonik şifre düz Argon2id ile yeniden hash'lenir. Düz MD5/SHA-1 asla doğrudan doğrulanmaz: `wrap_legacy_digest` (`migrate-legacy-hashes` CLI'ı için) onları içe aktarırken Argon2id ile sarar. |
| Sahte doğrulama (CRY-05) | Başlangıçta güncel parametre ve güncel pepper ile rastgele bir şifrenin hash'i hesaplanır. `verify(…, None)` kanonikleştirme + HMAC + Argon2 işini aynen yapar. Bozuk hash, bilinmeyen algoritma, bilinmeyen pepper sürümü ve aşırı uzun girdi de aynı sahte işi yapıp `Invalid` döner. Test: `cry_05_unknown_account_does_equal_work_and_fails` (`authn_testkit::timing`). |
| Eşzamanlılık (ARC-12) | Argon2, bcrypt ve PBKDF2 `spawn_blocking` üzerinde, `crypto.max_concurrent_hashes` izinli bir semafor altında çalışır. İzin bloklayan göreve taşınır: istek iptal edilse bile sınır korunur. |
| Token'lar (CRY-06) | 32 bayt CSPRNG, base64url (dolgusuz) = 43 karakter. Saklanan: metnin SHA-256'sı. `parse` kanonik olmayan biçimleri SQL'e ulaşmadan reddeder. Hash ile veritabanı araması zamanlama açısından güvenlidir (saldırgan SHA-256 çıktısının baytlarını seçemez); Rust tarafındaki karşılaştırmalar sabit zamanlıdır. |
| OTP (CRY-07) | 6 hane, reddetme örneklemesiyle tekdüze (modulo yanlılığı yok; χ² testi `tests/properties.rs`). Saklanan: `HMAC(K_otp, len‖purpose‖len‖kod)`; amaç MAC'e bağlıdır, bir amacın hash'i başka amaçta kullanılamaz. Deneme sayımı `authn-store::one_time_tokens`'ta. |
| Zarf şifreleme (CRY-08) | Her değer için **ayrı** rastgele 256 bit DEK; veri XChaCha20-Poly1305 ile, DEK `KeyProvider` ile KEK altında sarılır. Biçim: `sürüm(1) ‖ len(kek_id)(1) ‖ kek_id ‖ len(sarılı DEK)(2, BE) ‖ sarılı DEK ‖ nonce(24) ‖ şifreli metin+etiket`. AAD zorunludur: tablo/kolon/satır kimliği (uzunluk önekli) ve sürüm hem veriye hem DEK sarmasına bağlanır; başka satıra kopyalanan şifreli metin açılmaz. KEK rotasyonu (`rewrap`) yalnızca DEK'i yeniden sarar, önce zarfın tamamını doğrular. **Neden XChaCha20-Poly1305:** 192 bit rastgele nonce'ta pratik çakışma sınırı yok (AES-GCM'in 96 bit rastgele nonce'u anahtar başına ~2^32 mesajla sınırlı), AES-NI'ya bağlı olmadan her CPU'da sabit zamanlı yazılım uygulaması, zaten workspace'te. Değer başına DEK ile nonce yeniden kullanımı teorik olarak da imkânsız. |
| JWT (CRY-09) | `ed25519-dalek` üzerinde algoritması sabit (EdDSA) kompakt JWS; bkz. [ADR 0001](../../docs/architecture/adr/0001-jwt-implementation.md). |
| İmza anahtarları (CRY-10) | Ed25519; tohum zarf şifreli (`signing_keys.private_key_ciphertext`, AAD = tablo/kolon/anahtar kimliği); açılan anahtar saklanan açık anahtarla sabit zamanlı karşılaştırılır. Yaşam döngüsü `authn_store::signing_keys`'te. |
| Alt anahtarlar (CRY-11) | HKDF-SHA256, sabit tuz `rust-authentication/hkdf-sha256/v1`, kök `crypto.hmac_root_key`. Amaçlar bir enum'dur (`OtpCode`, `RecoveryCode`, `CsrfToken`, `TrustedDevice`, `DeviceBinding`, `ProofOfWork`, `AuditPseudonym`, `RateLimitKey`, `OAuthState`, `WebhookSecret`, `KnownDevice`); her biri ayrı `info` etiketi (`authn/v1/…`) alır. `KnownDevice` (`authn/v1/known-device`, wave 1, K-21) authn-protect'in `known_devices.device_hash`'i içindir (eskiden `RateLimitKey` anahtarını ayrı etiketle paylaşıyordu). Etiketler asla değiştirilmez. |
| Sabit zaman (CRY-12) | Tüm sır karşılaştırmaları `subtle` üzerinden; TOTP penceresi ve webhook imzaları erken çıkışsız taranır. |
| Bellek (CRY-13) | Anahtarlar `SecretKey`/`SecretBytes`/`Zeroizing` içinde; `Debug` çıktıları redakte (testlerle doğrulanır); token/kod tiplerinde `Display` ve `Serialize` yok. |
| TOTP | RFC 6238/4226; varsayılan SHA-1, 6 hane, 30 sn, ±1 adım; `verify` tüm pencereyi tarar, `last_used_step` ve öncesini reddeder (MFA-02) ve eşleşen adımı döner. Sır 160 bit (en az 128 bit kabul edilir). |
| Webhook | Standard Webhooks (`webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<base64>`). Ek sertleştirme: `webhook-id` `[A-Za-z0-9_-]{1,256}` ile sınırlı (`.` içeren kimlik, imzalı içeriği belirsizleştirip imzanın başka gövdeye taşınmasına izin verirdi), zaman damgası kanonik ondalık ve tolerans her iki yönde. |

## Konfigürasyon (`[crypto]`, `crates/authn-core/src/config/crypto.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `argon2.memory_kib` / `iterations` / `parallelism` | 19456 / 2 / 1 | CRY-01 |
| `peppers[] {version, key}` | **zorunlu** | base64, ≥ 32 bayt |
| `current_pepper_version` | **zorunlu** | |
| `keks[] {id, key}` | **zorunlu** | id `[A-Za-z0-9_-]{1,32}`, key tam 32 bayt |
| `current_kek_id` | **zorunlu** | |
| `hmac_root_key` | **zorunlu** | ≥ 32 bayt |
| `jwt_leeway` | `30s` | 0–5 dk |
| `max_concurrent_hashes` | 4 | 1–256 (ARC-12) |
| `signing_keys.jwks_cache_ttl` | `1h` | 1 dk – 1 gün |
| `signing_keys.pending_period` | `2h` | ≥ `jwks_cache_ttl`, 1 dk – 30 gün, `rotation_interval`'dan kısa |
| `signing_keys.rotation_interval` | `30d` | 1–365 gün |
| `signing_keys.retired_retention` | `1d` | 1 dk – 90 gün, ≥ `session.access_token_ttl` |

Bu görevde `pending_period` ve `retired_retention` için üst/alt sınırlar eklendi (yeni alan yok, `config/example.toml` değişmedi).

## `authn-store` tarafı

- `one_time_tokens::OneTimeTokenRepository`: `create` (isteğe bağlı olarak aynı özne + amaçtaki etkin token'ları iptal eder; eşzamanlı istekler işlem kapsamlı advisory lock ile sıralanır), `find_active_link` (tüketmeden bakma, SES-18), `consume_link` (tek atomik `UPDATE … WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $now RETURNING`, grup kardeşlerini iptal eder, çağıranın transaction'ında), `verify_code` (**kendi** transaction'ında: `FOR UPDATE` satır kilidi, Rust'ta sabit zamanlı karşılaştırma, deneme sayacı, sınırda kilit/iptal — başarısız deneme çağıranın işlemi geri alınsa bile kalıcıdır), `revoke_active`, `revoke_for_user`, `revoke_group`, `delete_expired`. `TokenPurpose` enum'u sözleşmedeki (contracts §5) amaç tablosunun birebir karşılığıdır.
- `signing_keys::SigningKeyRepository`: `create_pending`, `activate_due`, `activate`, `revoke`, `emergency_rotate`, `rotate_if_due` (zamanlayıcı giriş noktası; ilk açılışta anahtar üretir), `load_active_signer`, `publishable`, `jwks`, `verifier`, `list`, `rewrap_private_keys` (KEK rotasyonu). Her durum değişikliği advisory lock altında transaction'dadır; `signing_keys_single_active_idx` tek aktif anahtarı ayrıca garanti eder.

Şema değişikliği gerekmedi (migration eklenmedi).

## Bilinen sınırlamalar / SHOULD notları

- **Eski hash zamanlaması:** bcrypt/PBKDF2 hash'li hesapların doğrulama süresi Argon2'den farklıdır; bu hesaplar için zamanlama hesap varlığını kısmen sızdırabilir. Azaltım: girişte otomatik yükseltme ve göç penceresinin kısa tutulması; MD5/SHA-1 sarmalı Argon2 maliyetindedir.
- **Kod yeniden gönderme:** `verify_code` deneme sayımını kod başınadır; yeni kod istemek yeni deneme hakkı demektir. Yeniden gönderme bekleme süresi ve saatlik limit (ACC-04, MFA-05) ile kullanıcı/faktör başına toplam deneme sınırı (MFA-03) çağıran modülün ve `RateLimiter`'ın sorumluluğundadır.
- **bcrypt 72 bayt:** tarihsel bcrypt gibi yalnızca ilk 72 bayt dikkate alınır; ilk başarılı girişte Argon2id'ye geçilir.
- **`data_encryption_keys` tablosu kullanılmıyor:** değer başına DEK tasarımında DEK zarfın içindedir; tablo ileride KMS önbelleği için ayrılmış kalır (bkz. `docs/architecture/contract-change-requests.md`).
- **Eski parametreli kullanıcılar:** Argon2 parametreleri artırıldığında, henüz yükseltilmemiş hash'lerin doğrulama süresi sahte doğrulamadan kısa olabilir; kullanıcılar giriş yaptıkça kapanır.
- Uygulanmayan SHOULD/MAY maddesi yoktur.

## Testler

- **Bilinen test vektörleri (CRY-14, TST-05):** RFC 4231 (HMAC-SHA256), RFC 5869 (HKDF), RFC 4226 (HOTP), RFC 6238 (TOTP; SHA-1/256/512), RFC 8032 (Ed25519 TEST 1–3), Argon2id referans uygulaması (`password`/`somesalt`) ve RFC 9106 vektörü, RFC 7914 (PBKDF2-HMAC-SHA256), OpenWall bcrypt vektörü, Standard Webhooks referans vektörü, FIPS 180-2 SHA-256.
- **Property testleri (TST-03):** zarf gidiş-dönüşü ve ayrıştırıcının toplamlığı (`envelope/tests.rs`), token/kod biçimleri ve OTP tekdüzeliği (`tests/properties.rs`).
- **Güvenlik regresyonları (TST-02):** JWT `alg` karışıklığı/`none`/yanlış `kid`/süresi dolmuş/yanlış `aud`; zarf kopyala-yapıştır ve bayt değişimi; tek kullanımlık token'ların eşzamanlı tüketimi (tam olarak biri başarılı) ve eşzamanlı kod tahmininde deneme sınırının aşılmaması (`crates/authn-store/tests/one_time_tokens.rs`); eşzamanlı rotasyonda tek aktif anahtar (`crates/authn-store/tests/signing_keys.rs`).
- **Fuzz hedefleri (TST-04, `fuzz/fuzz_targets/`):** `jwt_parse`, `envelope_parse`, `password_hash_parse`, `token_parse`, `webhook_verify`.

## Komutlar

```bash
cargo test -p authn-crypto
cargo test -p authn-store --test one_time_tokens --test signing_keys
cargo clippy -p authn-crypto --all-targets -- -D warnings
cargo fmt -p authn-crypto

# Fuzz (nightly, depo kökünden)
cargo +nightly fuzz build
cargo +nightly fuzz run jwt_parse -- -max_total_time=30
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
