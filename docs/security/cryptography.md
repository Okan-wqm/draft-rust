# Kriptografi kararları (DOC-03)

> **Durum:** `claude/compassionate-darwin-aa1tiy` dalı, `47c84a7` üzerindeki kod (2026-11-05). Her satır kodla karşılaştırıldı. Belge ile kod ayrışırsa **kod doğrudur**; bu belgeyi düzeltin.
>
> İlgili belgeler: [ADR 0001 — JWT uygulaması](../architecture/adr/0001-jwt-implementation.md), [`crates/authn-crypto/README.md`](../../crates/authn-crypto/README.md), [tehdit modeli](threat-model.md), [bilinen sınırlamalar](known-limitations.md). Anahtar rotasyonu runbook'ları DOC-06 kapsamında [`docs/operations/`](../operations/) altındadır.

## 1. İlkeler

| İlke | Uygulanışı | Kanıt |
|------|------------|-------|
| Kendi algoritmamızı yazmıyoruz | Tüm primitifler denetlenmiş crate'lerden gelir: RustCrypto (`argon2`, `hmac`, `sha1`, `sha2`, `hkdf`, `chacha20poly1305`, `p256` 0.14, `bcrypt`, `pbkdf2`), dalek (`ed25519-dalek`), `subtle`, `zeroize`, `secrecy`, `getrandom`. `authn-crypto` yalnızca bunları birleştirir | `Cargo.toml` `[workspace.dependencies]`, [`crates/authn-crypto/README.md`](../../crates/authn-crypto/README.md) |
| Tek yerden kriptografi | Uygulama kodu primitiflere doğrudan değil `authn-crypto` üzerinden erişir (istisnalar aşağıda adıyla anılır: audit zincirinin SHA-256'sı, Apple `client_secret` için `p256`, OIDC JWK doğrulaması için `openidconnect`) | — |
| Yalnızca işletim sistemi CSPRNG'si | `authn_crypto::random` her rastgele değeri `getrandom::fill` ile üretir; kullanıcı alanında RNG yoktur | `crates/authn-crypto/src/random.rs`, `cry_06_random_bytes_differ`, `cry_07_uniform_below_is_roughly_uniform` |
| Sabit zamanlı karşılaştırma | Sır karşılaştırmaları `subtle` ile (`ct::constant_time_eq`, `eq_array`, `position_of`, `TokenHash` eşitliği, `SecretKey` eşitliği, `HmacKey::verify`) | `crates/authn-crypto/src/ct.rs`, `cry_12_eq_array`, `cry_12_position_of_scans_all_candidates`, `cry_12_secret_key_equality`, `cry_12_hmac_key_sign_and_verify`, `cry_06_hash_is_sha256_of_text_and_compares_in_constant_time` |
| Bellekte sır | `SecretKey<N>`, `SecretBytes`, `Zeroizing`, `SecretString`; `Debug` redakte eder, token/kod tiplerinde `Display`/`Serialize` yoktur | `crates/authn-crypto/src/secret.rs`, `cry_13_*` testleri (ör. `cry_13_secret_key_debug_is_redacted`, `cry_13_tokens_are_redacted`, `cry_13_totp_secret_is_redacted`) |
| Bilinen test vektörleri | RFC 4231, RFC 5869, RFC 4226, RFC 6238, RFC 8032, Argon2 referans + RFC 9106, FIPS 180-2 SHA-256, Standard Webhooks referans vektörü | `cry_14_hmac_sha256_rfc4231_vectors`, `cry_14_hkdf_sha256_rfc5869_vectors`, `cry_14_hotp_rfc4226_vectors`, `cry_14_totp_rfc6238_vectors`, `cry_14_ed25519_rfc8032_vectors`, `cry_14_argon2id_reference_phc_vector`, `cry_14_argon2id_rfc9106_vector`, `cry_14_sha256_known_answer`, `aud_07_standard_webhooks_reference_vector` |
| Ayrıştırıcılar fuzz edilir | `fuzz/fuzz_targets/`: `jwt_parse`, `envelope_parse`, `password_hash_parse`, `token_parse`, `webhook_verify`, `webhook_signature`, `api_key_parse` (ve diğerleri, toplam 13 hedef) | `fuzz/Cargo.toml` |
| TLS | `rustls` + `ring`; OpenSSL, `native-tls` ve `aws-lc-sys` `deny.toml` ile yasak | `deny.toml` `[bans]` |
| `unsafe` yok | `[workspace.lints.rust] unsafe_code = "forbid"`, her crate `[lints] workspace = true` | `Cargo.toml` |

## 2. Anahtar envanteri

Yapılandırmadaki üç kök sır (`[crypto]`, `crates/authn-core/src/config/crypto.rs`) ve onlardan türeyen her şey:

| Kök sır | Yapılandırma | Biçim / sınır | Ne korur | Rotasyon |
|---------|--------------|---------------|----------|----------|
| Pepper | `[[crypto.peppers]] {version, key}`, `crypto.current_pepper_version` | base64, ≥ 32 bayt; birden çok sürüm aynı anda | Şifre hash'leri (§3) | Yeni sürüm eklenir, `current_pepper_version` değişir; kullanıcılar giriş yaptıkça yeni sürüme geçer (CRY-03). Eski sürüm kaldırılırsa o sürümdeki hash `Invalid` olur |
| KEK | `[[crypto.keks]] {id, key}`, `crypto.current_kek_id` | id `[A-Za-z0-9_-]{1,32}`, anahtar tam 32 bayt; birden çok KEK | Zarf şifrelenmiş her değer (§4) | `rust-authentication rotate-kek` (§4.3) |
| HMAC kökü | `crypto.hmac_root_key` | ≥ 32 bayt; **tek değer** | HKDF ile türetilen tüm amaç anahtarları (§5) | Çok sürümlü değil; değiştirmek türetilen her şeyi geçersiz kılar (bkz. [bilinen sınırlamalar](known-limitations.md)) |

Üç kök sır için ortak kurallar:

- Zorunludur. Eksik ya da kısa anahtarla servis açılmaz (`arc_07_missing_secrets_fail_fast`, `arc_07_short_keys_are_rejected`, `arc_07_invalid_key_material_fails_fast`).
- `config/example.toml` ve `authn-testkit` içindeki **yayımlanmış** anahtarlar `production` ve `staging` ortamında reddedilir (`cry_02_published_keys_are_refused_in_production`, `ops_08_example_keys_are_refused_in_production`).
- Hata mesajları ve `Debug` çıktısı anahtar materyali içermez (`cry_02_secrets_are_redacted_in_debug`, `cry_08_kek_rules_never_echo_key_material`, `arc_07_invalid_values_are_all_reported_without_secrets`).
- Sırlar ortam değişkeniyle de verilebilir (`AUTHN__CRYPTO__…`, ARC-07). KMS/HSM uygulaması **yoktur**: `KeyProvider` trait'inin tek uygulaması `EnvKeyProvider`'dır (Faz 2, K-96).

## 3. Şifre saklama (CRY-01 … CRY-05, PWD-02)

**Kod:** `crates/authn-crypto/src/password/` (`argon.rs`, `pepper.rs`, `canonical.rs`, `legacy.rs`, `mod.rs`).

```text
kanonik   = NFKC(şifre)                                  (canonicalize_password; ≤ 4096 bayt DoS sınırı)
girdi     = HMAC-SHA256(pepper[v], kanonik)              (v = current_pepper_version)
saklanan  = Argon2id v1.3 (m, t, p; 16 bayt rastgele tuz; 32 bayt çıktı) → PHC dizesi
            + password_credentials.pepper_version = v
```

| Karar | Değer | Gerekçe / not | Test |
|-------|-------|---------------|------|
| Algoritma | Argon2id v1.3 | OWASP ve RFC 9106 önerisi | `cry_01_hash_is_argon2id_phc_with_configured_parameters` |
| Varsayılan parametre | m = 19456 KiB, t = 2, p = 1 (`[crypto.argon2]`) | OWASP'ın asgari Argon2id seti; ölçüm ve alternatif setler [`docs/operations/performance.md`](../operations/performance.md) | `cry_01_production_defaults_from_config`, `cry_01_defaults_are_valid` |
| Parametre sınırları | Ayrıştırıcı m ≤ 4 GiB, t ≤ 16, p ≤ 16 dışını, başka varyant/sürümü, `keyid`/`data` alanlarını, baştaki sıfırları reddeder | Veritabanına yerleştirilmiş bir hash, doğrulamayı DoS'a çeviremez | `cry_01_parser_is_strict`, `cry_01_settings_bounds` |
| Pepper | `HMAC-SHA256(pepper[v], NFKC(şifre))` Argon2'ye girer; sürüm hash'le birlikte saklanır | Yalnızca veritabanı sızarsa çevrimdışı kırma pepper olmadan mümkün değildir | `cry_02_the_pepper_is_part_of_the_hash`, `cry_02_versions_produce_different_outputs`, `cry_02_argon2id_hash_requires_pepper_version` |
| Rehash | Parametre/tuz/çıktı uzunluğu güncel değilse, pepper sürümü eskiyse ya da eski şema ise başarılı doğrulamadan sonra yeniden hash'lenir | CRY-03 | `cry_02_cry_03_pepper_rotation_upgrades_on_login`, `cry_03_outdated_parameters_trigger_rehash`, `cry_03_outdated_argon2_parameters_are_upgraded_after_login` |
| Eski hash'ler (yalnızca doğrulama) | `bcrypt` (`$2a$`/`$2b$`/`$2y$`, maliyet 4–15), `pbkdf2_sha256` (≤ 5 000 000 iterasyon), `argon2id_wrapped_md5` / `argon2id_wrapped_sha1` | Yeni hash hep Argon2id'dir. Düz MD5/SHA-1 asla doğrudan doğrulanmaz, `migrate-legacy-hashes` onları içe aktarırken Argon2id ile sarar | `cry_04_bcrypt_verifies_and_must_be_upgraded`, `cry_04_pbkdf2_verifies_and_must_be_upgraded`, `cry_04_wrapped_md5_and_sha1_hashes`, `cry_04_bcrypt_rejects_variants_and_dos_costs`, `cry_04_legacy_wrapped_sha1_hash_is_migrated_to_argon2id` |
| Sahte doğrulama | Kullanıcı yoksa ya da hash kullanılamıyorsa (bozuk, bilinmeyen pepper sürümü) açılışta hesaplanan sahte hash'e karşı aynı iş yapılır | Hesap varlığı süreden sızmaz (CRY-05) | `cry_05_unknown_account_does_equal_work_and_fails`, `cry_05_unusable_stored_hashes_fail_closed`, `cry_05_unknown_and_passwordless_accounts_fail_uniformly` |
| Eşzamanlılık | Argon2/bcrypt/PBKDF2 `spawn_blocking` üzerinde, `crypto.max_concurrent_hashes` (varsayılan 4) izinli semafor altında | Kimlik doğrulama öncesi pahalı iş CPU'yu tüketemez (ARC-12) | `arc_12_hashing_concurrency_is_bounded_by_the_semaphore`, `arc_12_closed_semaphore_is_reported` |
| Normalizasyon | Unicode NFKC, çıktı tamponu tek seferde boyutlandırılır | PWD-02; sıfırlanmamış kopya kalmaz | `pwd_02_nfkc_normalization_is_applied`, `pwd_02_capacity_is_exact`, `pwd_02_verification_uses_the_canonical_form` |

Bilinen sınırlar (ayrıntı [known-limitations.md](known-limitations.md)): eski bcrypt/PBKDF2 hash'li hesaplarda doğrulama süresi Argon2id'den farklıdır; bcrypt yalnızca ilk 72 baytı kullanır. İkisi de ilk başarılı girişte Argon2id'ye geçişle kapanır.

## 4. Zarf şifreleme (CRY-08)

**Kod:** `crates/authn-crypto/src/envelope/` (`mod.rs`, `provider.rs`).

### 4.1 Biçim

Her değer için **ayrı**, rastgele 256 bit bir DEK üretilir. Veri XChaCha20-Poly1305 ile DEK altında şifrelenir. DEK, `KeyProvider` aracılığıyla KEK altında sarılır.

```text
sürüm(1) ‖ len(kek_id)(1) ‖ kek_id ‖ len(sarılı DEK)(2, BE) ‖ sarılı DEK ‖ nonce(24) ‖ şifreli metin+etiket
```

- **AAD zorunludur:** `EnvelopeContext::new(tablo, kolon, satır)`. Tablo/kolon/satır kimliği (uzunluk önekli) ve sürüm hem veriye hem DEK sarmasına bağlanır. Başka satıra kopyalanan şifreli metin açılmaz (`cry_08_aad_binds_table_column_and_row`).
- Zarfın her baytı doğrulanır (`cry_08_every_byte_is_authenticated`). Ayrıştırıcı toplamdır ve kanonik olmayan girdiyi reddeder (`cry_08_parser_rejects_malformed_envelopes`, `cry_08_prop_parser_total`, `cry_08_limits`).
- **Neden XChaCha20-Poly1305:** 192 bit rastgele nonce'ta pratik çakışma sınırı yoktur (AES-GCM'in 96 bit rastgele nonce'u anahtar başına ~2^32 mesajla sınırlıdır). AES-NI olmadan da her CPU'da sabit zamanlı yazılım uygulaması vardır. Değer başına DEK kullanıldığı için aynı anahtarla nonce tekrarı da olmaz.
- `data_encryption_keys` tablosu **kullanılmıyor**: DEK zarfın içindedir. Tablo ileride bir KMS önbelleği için ayrılmıştır (`cry_08_data_encryption_keys_is_documented_as_reserved`).

### 4.2 Zarfla saklanan değerler

| Değer | Tablo.kolon (AAD bağlamı) | Kod |
|-------|---------------------------|-----|
| JWT imza anahtarı tohumu | `signing_keys.private_key_ciphertext` | `crates/authn-crypto/src/signing.rs` |
| TOTP sırrı | `mfa` faktör tablosunun sır kolonu (`SECRET_TABLE`/`SECRET_COLUMN`) | `crates/authn-mfa/src/service/enroll.rs` |
| Webhook imza sırrı (güncel + rotasyondaki önceki) | `webhook_endpoints.secret_ciphertext`, `previous_secret_ciphertext` | `crates/authn-audit/src/webhooks/endpoints.rs` |
| Bildirim yükü (outbox) | `outbox.sealed_payload` | `crates/authn-notify/src/outbox.rs` |
| Refresh tolerans ardılı | `refresh_tokens.successor_ciphertext` | `crates/authn-session/src/service/refresh.rs` |
| Sağlayıcı token'ları (`store_provider_tokens` veya Apple iptali için) | `identities.access_token_ciphertext`, `identities.refresh_token_ciphertext` | `crates/authn-oidc-client/src/service/mod.rs`, `apple.rs` |
| Apple iptal kuyruğu | `oauth_token_revocations.token_ciphertext` | `crates/authn-oidc-client/src/service/revocation.rs` |
| PKCE doğrulayıcısı | `oauth_states` | `crates/authn-oidc-client/src/service/` |
| Apple özel anahtarı (yapılandırmada) | sabit bağlam `oidc_client` / `apple_private_key` / `apple` | `crates/authn-oidc-client/src/apple.rs`, CLI `seal-apple-key` |

Testler: `mfa_01_secret_is_envelope_encrypted_and_bound_to_its_row`, `cry_08_private_keys_are_encrypted_and_bound_to_the_kek`, `cry_10_private_keys_are_sealed_and_bound_to_their_row`, `aud_07_create_returns_the_secret_once_and_stores_only_ciphertext`, `ses_05_rotation_keeps_only_the_latest_sealed_successor`, `aud_06_sealed_payload_debug_is_redacted`.

### 4.3 KEK rotasyonu

`rust-authentication rotate-kek` (takma ad `reencrypt`, `crates/authn-server/src/operations.rs`):

- Yalnızca DEK'i yeniden sarar. Önce zarfın tamamını doğrular, veriye dokunmaz (`cry_08_kek_rotation_rewraps_without_touching_data`).
- Satır başına karşılaştır-ve-yaz yapar, 500 satırlık anahtar-sıralı sayfalarla ilerler. Yarıda kalırsa yeniden çalıştırmak güvenlidir (`cry_08_rotate_kek_rewraps_every_row_across_pages`).
- Şemadaki **her** `*_ciphertext` kolonunun kapsandığını bir test zorlar (`cry_08_rotate_kek_covers_every_sealed_column_of_the_schema`). Sosyal giriş şifreli metinleri ve yapılandırmadaki Apple anahtarı da kapsanır (`cry_08_rotate_kek_rewraps_social_login_ciphertexts_and_the_apple_key`).
- Yapılandırmadaki Apple anahtarı eski KEK'le mühürlüyse komut yeniden sarılmış değeri yazdırır. Eski KEK yapılandırmadan kaldırılmadan önce bu değer yapılandırmaya konmalıdır.

## 5. HKDF alt anahtarları (CRY-11)

**Kod:** `crates/authn-crypto/src/kdf.rs`.

```text
K_amaç = HKDF-SHA256(salt = "rust-authentication/hkdf-sha256/v1", ikm = crypto.hmac_root_key, info = etiket)
```

Etiketler kodda sabittir ve **asla değiştirilmez** (değişirse saklanan her MAC geçersiz olur). Amaçların birbirinden bağımsız ve deterministik olduğu test edilir (`cry_11_purpose_keys_are_distinct_and_deterministic`).

| `KeyPurpose` | `info` etiketi | Kullanan kod | Ne için |
|--------------|----------------|--------------|---------|
| `OtpCode` | `authn/v1/otp-code` | `crates/authn-crypto/src/otp.rs` | Kısa kodların saklama hash'i (e-posta/SMS kodları, sıfırlama kodu, giriş kodu, kayıt kodu) |
| `RecoveryCode` | `authn/v1/recovery-code` | `crates/authn-mfa/src/recovery.rs` | Kurtarma kodu hash'i |
| `CsrfToken` | `authn/v1/csrf-token` | `crates/authn-session/src/csrf.rs` | Senkronize CSRF token'ı ve giriş öncesi (login CSRF) token'ı |
| `TrustedDevice` | `authn/v1/trusted-device` | `crates/authn-mfa/src/device_token.rs` | Güvenilir cihaz token'ı etiketi |
| `ProofOfWork` | `authn/v1/proof-of-work` | `crates/authn-protect/src/captcha/pow.rs` | Kendi barındırılan PoW CAPTCHA görevinin HMAC'i |
| `RateLimitKey` | `authn/v1/rate-limit-key` | `crates/authn-protect/src/keys.rs` | Kişisel veri içeren hız sınırı anahtarlarının anahtarlı hash'i |
| `KnownDevice` | `authn/v1/known-device` | `crates/authn-protect/src/keys.rs` | `known_devices.device_hash` ("yeni cihaz" sinyali, K-21) |
| `AuditChain` | `authn/v1/audit-chain` | `crates/authn-audit/src/keys.rs` | Anahtarlı audit zincirinin taban anahtarı (§9) |
| `ErasureLedger` | `authn/v1/erasure-ledger` | `crates/authn-account/src/service/erasure_ledger.rs` | `export-erasures` satırlarının MAC'i; `reapply-erasures` imzasız/yanlış imzalı satırı reddeder (K-108) |
| `DeviceBinding` | `authn/v1/device-binding` | **kullanılmıyor** | Ayrılmış etiket. Magic link cihaz bağlama değeri bugün 256 bit `OpaqueToken`'dır, yalnızca SHA-256'sı saklanır (`crates/authn-session/src/login/passwordless.rs`) |
| `AuditPseudonym` | `authn/v1/audit-pseudonym` | **kullanılmıyor** | Ayrılmış etiket. Audit takma adları bugün rastgele UUID'dir (`audit_subjects`, `crates/authn-audit/src/sink.rs`) |
| `OAuthState` | `authn/v1/oauth-state` | **kullanılmıyor** | Ayrılmış etiket. OAuth durumu sunucu tarafında saklanır, PKCE doğrulayıcısı zarfla şifrelenir |
| `WebhookSecret` | `authn/v1/webhook-secret` | **kullanılmıyor** | Ayrılmış etiket. Webhook sırları rastgele üretilir ve zarfla saklanır (§10) |

"Kullanılmıyor" satırları `crates/` altında `KeyPurpose::<ad>` araması ile doğrulandı. Bu amaçlar enum'da durur, çünkü etiketler kalıcıdır.

## 6. Token'lar, kodlar ve entropi (CRY-06, CRY-07)

| Değer | Üretim | Entropi | Saklanan | Kod / test |
|-------|--------|---------|----------|------------|
| Opak token (`OpaqueToken`) | 32 bayt CSPRNG, base64url dolgusuz (43 karakter) | 256 bit | Metnin SHA-256'sı (`TokenHash`, eşitlik sabit zamanlı) | `crates/authn-crypto/src/token.rs`; `cry_06_tokens_have_256_bits_and_canonical_form`, `cry_06_parse_rejects_malformed_tokens` |
| — kullanıldığı yerler | Web oturum token'ı (`sessions.token_hash`), refresh token, sıfırlama/doğrulama/magic link/e-posta değişikliği bağlantıları, kayıt tutamacı, davet ve sahiplik devri token'ları, challenge token'ları, break-glass kayıt bağlantısı, break-glass başlangıç şifresi | 256 bit | SHA-256 | `pwd_07_reset_token_is_256_bit_single_use_and_only_its_hash_is_stored`, `ses_03_session_cookie_is_host_prefixed_http_only_secure_lax` |
| 6 haneli kod (`OtpCode`) | Reddetme örneklemesiyle tekdüze (`random::uniform_below`), modulo yanlılığı yok | ≈ 19,9 bit | `HMAC(K_otp, len‖amaç‖len‖kod)`: amaç MAC'e bağlıdır | `crates/authn-crypto/src/otp.rs`; `cry_07_generated_codes_are_uniform`, `cry_07_hash_is_keyed_and_purpose_bound`, `cry_07_code_attempts_are_counted_and_lock_out` |
| Kurtarma kodu | Crockford base32 alfabesinden 10 karakter (`XXXXX-XXXXX`) | 50 bit | `HMAC-SHA256(K_recovery, len‖user_id‖len‖kod)` | `crates/authn-mfa/src/recovery.rs`; `mfa_04_alphabet_has_32_unambiguous_symbols_and_50_bits`, `mfa_04_hash_is_keyed_and_bound_to_the_user` |
| Güvenilir cihaz token'ı | `td1.<cihaz id>.<bitiş>.<nonce 256 bit>.<etiket>`; etiket `HMAC-SHA256(K_trusted_device, …user…id…exp…nonce)` | 256 bit nonce | Token'ın SHA-256'sı (`trusted_devices.token_hash`) | `crates/authn-mfa/src/device_token.rs`; `mfa_09_round_trip_and_binding`, `mfa_09_tampering_is_rejected` |
| CSRF token'ı | `base64url(HMAC(K_csrf, "session" ‖ oturum id ‖ SHA-256(oturum token'ı)))`; giriş öncesi: `HMAC(K_csrf, "pre-session" ‖ SHA-256(sır))` | HMAC çıktısı | Saklanmaz (her istekte yeniden hesaplanır) | `crates/authn-session/src/csrf.rs`; `ses_04_session_token_is_bound_to_session_and_token`, `ses_04_login_csrf_needs_pre_session_cookie_and_token` |
| API anahtarı | `ak_<env>_<32 bayt CSPRNG, 43 base62 hane>_<CRC-32, 6 base62 hane>` | 256 bit | Metnin SHA-256'sı; gösterim yalnızca oluşturmada | `crates/authn-org/src/api_key.rs`; `org_08_checksum_rejects_typos_without_database_work`, `org_08_debug_never_contains_the_key` |
| Webhook sırrı | `whsec_` + 32 bayt CSPRNG (base64) | 256 bit | Zarf şifreli | `crates/authn-crypto/src/webhook.rs`; `aud_07_secret_format` |
| WebAuthn kullanıcı tanıtıcısı | Rastgele, e-postadan bağımsız | 128 bit | Açık | `pky_03_user_handle_is_random_stable_and_email_independent` |
| WebAuthn challenge'ı | `webauthn-rs` üretir (32 bayt, `rand::rng()`) | 256 bit | Seremoni durumu sunucuda (tek kullanımlık, varsayılan 5 dk) | `webauthn-rs-core` 0.6.2 `CHALLENGE_SIZE_BYTES`; `pky_01_registration_ceremony_is_single_use` |
| Kimlikler | UUIDv7 (ARC-05) | ~74 bit rastgele kısım | — | `crates/authn-core/src/id.rs`. **Sır değildir**; yetkilendirme tahmin edilemezliğe dayanmaz |

Tek kullanımlık tüketim veritabanında atomiktir (`UPDATE … WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $now RETURNING`, `crates/authn-store/src/one_time_tokens.rs`): `arc_06_link_token_is_single_use`, `tst_02_concurrent_link_consumers_exactly_one_succeeds`, `tst_02_concurrent_code_verification_exactly_one_succeeds`.

Hash ile veritabanı araması bilinçli olarak SQL'de yapılır, sabit zamanlı değildir. Karşılaştırılan değer 256 bit rastgele token'ın SHA-256'sı olduğundan, saldırgan SHA-256 çıktısının baytlarını seçemez; zamanlamadan önek öğrenmek token hakkında bilgi vermez.

E-postayla giden bağlantılarda token URL **parçasındadır** (`#token=…`): tarayıcı onu sunucuya, proxy loglarına ya da `Referer`'a göndermez (`crates/authn-notify/src/links.rs`, `ntf_02_links_use_only_the_public_base_url_and_configured_path`).

## 7. JWT access token'ları ve imza anahtarları (CRY-09, CRY-10, SES-08, SES-09)

**Karar:** [ADR 0001](../architecture/adr/0001-jwt-implementation.md). `jsonwebtoken` kullanılmaz; `ed25519-dalek` üzerinde algoritması sabit (EdDSA) minimal bir JWS uygulanır (`crates/authn-crypto/src/jwt.rs`).

| Konu | Karar | Test |
|------|-------|------|
| Algoritma | Yalnızca `EdDSA` (Ed25519). Header'daki `alg` bir algoritma *seçmez*, yalnızca sabit değerle karşılaştırılır. `none`, `HS*`, `RS*`, `ES*`, `PS*` reddedilir | `cry_09_alg_none_and_symmetric_algorithms_are_rejected` |
| Header | Yalnızca `alg`, `typ`, `kid`. `crit`, `jku`, `jwk`, `x5u`, `x5c`, `b64` ve yinelenen adlar reddedilir | `cry_09_unknown_header_parameters_and_duplicates_are_rejected` |
| `typ` | `at+jwt` (RFC 9068) zorunlu | `cry_09_kid_and_typ_are_enforced` |
| İmza | `verify_strict` (kanonik olmayan `S`, küçük mertebeli noktalar reddedilir) | `cry_09_any_modification_breaks_the_signature`, `cry_10_weak_and_malformed_public_keys_are_rejected` |
| Yapı | ≤ 8 KiB, ASCII, tam üç bölüm, katı base64url, JSON nesnesi, yinelenen claim yok | `cry_09_structural_attacks_are_rejected`, `cry_09_duplicate_claims_are_rejected` |
| Claim'ler | `iss` tam eşitlik, `aud` içermeli, `exp`/`iat` zorunlu, `nbf` isteğe bağlı; saat kayması `crypto.jwt_leeway` (varsayılan 30 sn, en çok 5 dk) | `cry_09_registered_claims_are_validated`, `cry_09_leeway_and_max_lifetime_are_configurable` |
| İçerik | `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid`, `auth_time`, `amr`, `acr`, `org_id`, `scope`; kişisel veri yok. Impersonation token'larında `act` | `ses_08_access_token_claims_follow_rfc_9068_without_personal_data`, `ses_08_native_impersonation_tokens_carry_the_act_claim` |
| Ömür | `session.access_token_ttl`, varsayılan 10 dk | `ses_06_defaults_follow_the_specification_and_validate` |
| İptal | Bearer isteklerinde oturum canlılığı her istekte kontrol edilir (`session.access_token_session_check`); üretimde kapatılamaz | `ses_05_revoked_session_rejects_its_access_tokens_at_once`, `ses_08_k58_session_check_cannot_be_switched_off_in_production_or_staging` |
| İstemciye hata | Her doğrulama hatası `unauthenticated`; ayrıntılı `JwtError` yalnızca loga | `ses_08_tampered_and_foreign_tokens_are_rejected_by_the_middleware`, `cry_09_forged_tokens_are_refused_through_the_stack` |

**İmza anahtarı yaşam döngüsü** (`crates/authn-store/src/signing_keys.rs`):

- Durumlar `pending → active → retired → revoked`. Tek aktif anahtarı hem advisory lock hem `signing_keys_single_active_idx` garanti eder (`cry_10_at_most_one_active_signing_key`, `cry_10_concurrent_rotation_keeps_a_single_active_key`).
- Yeni anahtar `pending_period` (varsayılan 2 sa, ≥ `jwks_cache_ttl`) boyunca JWKS'te yayımlanır, sonra etkinleşir. Emekli anahtar `retired_retention` (varsayılan 1 gün, ≥ `access_token_ttl`) boyunca yayımlanmaya devam eder. Varsayılan rotasyon aralığı 30 gündür (`[crypto.signing_keys]`).
- Testler: `cry_10_full_rotation_lifecycle`, `cry_10_pending_keys_cannot_sign_before_their_period`, `cry_10_first_start_bootstraps_an_active_key`, `cry_10_signing_key_periods_are_bounded`.
- Rotasyon kendiliğinden saatlik işle yapılır. Elle: `rotate-signing-key`. Acil durumda `rotate-signing-key --emergency` (veya ADM-06 admin ucu) etkin anahtarı `revoked` yapar ve yenisini hemen etkinleştirir.
- **Önbellek:** imzalayıcı/doğrulayıcı/JWKS önbelleği süreç başınadır (`session.signing_key_cache_ttl`, varsayılan 30 sn, 1 sn–5 dk). `signing_keys` tablosundaki her değişiklik bir tetikleyiciyle `NOTIFY` üretir. `serve` içindeki dinleyici önbelleği anında boşaltır (migration `2001`; `cry_10_k58_every_signing_key_change_notifies`, `ses_09_k58_serving_instance_drops_a_key_revoked_elsewhere`, `ses_09_k58_listener_survives_a_killed_connection`). Dinleyici kopuksa önbellek ömrü 5 sn'ye iner.
- **JWKS:** `GET /.well-known/jwks.json` yalnızca `kty=OKP`, `crv=Ed25519`, `x`, `kid`, `alg=EdDSA`, `use=sig` içerir; özel anahtar alanı tipte yoktur (`ses_09_jwks_contains_only_public_okp_keys`, `ses_09_jwks_publishes_public_keys_with_cache_headers`).

Birlikte çalışabilirlik sınırı: yalnızca EdDSA desteklenir; RS256/ES256 bekleyen kaynak sunucusu kütüphaneleri doğrulayamayabilir ([roadmap](../roadmap.md) C19).

### 7.1 OAuth 2.1 / OIDC sağlayıcısının token'ları (K-80, OIDP-06 … OIDP-08)

- **İmza:** native token'larla aynı anahtar kümesi ve aynı sabit algoritmalı EdDSA JWS'i (`authn_crypto::jwt`); sağlayıcı anahtar üretmez, süreç başına anlık görüntüsü en çok 5 sn eskidir. Access token `typ: at+jwt` (RFC 9068), ID token `typ: JWT`; ikisi birbirinin yerine doğrulanamaz.
- **Ayrım:** sağlayıcı access token'ı `sid` taşımaz ve `aud`'u native `session.audiences`'ı asla içermez; native doğrulayıcı onu reddeder. Sağlayıcı her access token'ı `jti` kaydıyla (`oidc_access_tokens`) eşleştirir; kaydı olmayan (native) token kabul edilmez.
- **`at_hash`:** OIDC Core §3.1.3.6 hash'i ID token'ın `alg`'ine göre seçer; EdDSA/Ed25519 için SHA-512'nin sol 32 baytı, base64url (Ed25519 SHA-512 üzerine kuruludur; sertifikalı diğer sağlayıcılarla aynı seçim).
- **Opak değerler:** istemci sırrı, yetkilendirme kodu ve refresh token 256 bit `OpaqueToken`; yalnızca SHA-256 saklanır (§6), istemci sırrı sabit zamanlı karşılaştırılır. Tarayıcı bağlama çerezi de 256 bit, yalnızca SHA-256'sı saklanır.
- **PKCE:** yalnızca `S256` (`BASE64URL(SHA-256(verifier))`), sabit zamanlı karşılaştırma, RFC 7636 Ek B test vektörüyle test edilir.

## 8. Üçüncü taraf ID token'ları ve Apple istemci sırrı (SOC-02, SOC-03, SOC-07)

**ID token doğrulaması** (`crates/authn-oidc-client/src/id_token.rs`):

- JWS burada ayrıştırılır. İmza, `openidconnect`'in JWK uygulamasıyla (`CoreJsonWebKey::verify_signature`, yalnızca açık anahtar) doğrulanır.
- İzin listesindeki algoritmalar: RS256/384/512, PS256/384/512, ES256, ES384. `none` ve `HS*` anahtar aranmadan reddedilir. Algoritma adı taşıyan bir JWK, header'daki algoritmayla aynı olmalıdır. `crit` reddedilir, `jku`/`x5u`/`jwk` asla izlenmez (`soc_03_alg_none_and_hmac_are_rejected_before_key_lookup`, `soc_03_alg_confusion_jwk_algorithm_must_match_header`).
- `kid` zorunludur. `iss` tam eşleşmeli (Microsoft için kiracı kuralı geçerli). Her `aud` kabul edilen bir istemci kimliği olmalıdır; birden çok `aud` varsa `azp` zorunludur. `exp`/`iat`/`nbf` `jwt_leeway` ile denetlenir. `nonce` saklanan nonce'un hash'iyle sabit zamanlı karşılaştırılır (`soc_03_wrong_issuer_audience_azp_expiry_and_future_iat_are_rejected`, `soc_03_microsoft_tenant_spoofing_is_rejected`, `soc_04_nonce_is_mandatory_single_use_and_provider_bound`).
- JWKS önbelleklenir. Bilinmeyen `kid` hız sınırlı yenileme tetikler. İndirme başarısızsa üstel geri çekilme uygulanır, bayat anahtarlar en çok `jwks_max_staleness` (varsayılan 24 sa) kullanılır, sonra kapalı başarısız olunur (`soc_03_jwks_rotation_and_rate_limited_refresh`, `soc_03_k61_stale_keys_expire_after_the_max_staleness`).
- Web akışı PKCE S256 + `state` + `nonce` kullanır (`soc_02_pkce_s256_known_answer`, `soc_02_nonce_mismatch_is_rejected`, `soc_02_state_replay_is_rejected`).

**Apple `client_secret`** (`crates/authn-oidc-client/src/apple.rs`): ES256 imzalı JWT'dir ve **yalnızca `p256` 0.14** ile imzalanır (RFC 6979 deterministik ECDSA). `openidconnect`'in çektiği eski `p256`/`p384` 0.13 zinciri (`crypto-bigint` 0.5, RUSTSEC-2026-0387) ve `rsa` 0.9 (RUSTSEC-2023-0071) yalnızca **açık anahtarla** imza doğrulamasında kullanılır. Bu iki uyarının bilinçli olarak yok sayılmasının gerekçesi `deny.toml` ve `.cargo/audit.toml` içindedir. Kural: gizli anahtarlı her EC işlemi `p256` 0.14 ile yapılır.

## 9. Audit hash zinciri (AUD-02, K-77)

**Kod:** `crates/authn-audit/src/chain.rs`, `keys.rs`, `sink.rs`, `verify.rs`; `crates/authn-crypto/src/kdf.rs` (`AuditChainKeys`); migration `1703_audit_keyed_chain.sql`.

```text
K_AuditChain = HKDF(hmac_root_key, info = "authn/v1/audit-chain")
K_v          = HKDF-SHA256(salt = "authn/v1/audit-chain/versions", ikm = K_AuditChain, info = "v<v>")
hash         = HMAC-SHA-256(K_v, prev_hash ‖ canonical_json(kayıt))        (chain_key_version = v)
eski satır   = SHA-256(prev_hash ‖ canonical_json(kayıt))                  (chain_key_version IS NULL, K-77 öncesi)
pii_digest   = SHA-256(rastgele 32 bayt tuz ‖ canonical_json({ip, user_agent}))
```

- `prev_hash` sabit 32 bayttır, bu yüzden birleştirme belirsiz değildir. İlk olayın `prev_hash` değeri 32 sıfır bayttır.
- Kişisel veri zincirde yoktur. Kullanıcılar rastgele takma adlarla görünür. IP ve user-agent `audit_event_pii` tablosunda tutulur, zincirde yalnızca tuzlu özetleri bulunur. Silmede (AUD-05) bu tablo silinir, zincir bozulmaz.
- Sürümler yeniden türetilebilir: eski anahtarlar için ayrı saklama gerekmez. Bir sürüm anahtarının sızması tabanı ve diğer sürümleri açığa çıkarmaz. Sürüm hiç azalmaz (`max(baş, yapılandırma)`).
- Rotasyon: `[audit.chain] key_version` bir artırılıp sunucu yeniden başlatılır ya da `rotate-audit-chain-key` çalıştırılır. Sürüm değişiminde `SECURITY DEFINER` bir tetikleyici `chain_key_switch` kontrol noktası yazar.
- Doğrulayıcı (CLI `verify-audit-chain`, admin API) geri düşüşleri reddeder: `key_downgrade`, `unkeyed_event`, `key_switch_unrecorded`, baş sürümü uyuşmazlığı.
- Testler: `k_77_keyed_hash_is_hmac_sha256_of_prev_hash_and_canonical_json`, `k_77_forger_without_the_key_cannot_recompute_the_chain`, `k_77_forger_with_a_wrong_key_cannot_recompute_the_chain`, `k_77_downgrading_keyed_events_to_the_unkeyed_rule_is_detected`, `k_77_key_rotation_applies_to_new_events_and_old_ones_still_verify`, `k_77_audit_chain_version_keys_are_independent_and_deterministic`, `k_77_chain_key_never_appears_in_logs_or_debug`, `k_77_production_code_never_builds_an_unkeyed_audit_sink`, `aud_05_pii_digest_depends_on_salt_and_content`.

Sınırlar (dış çıpa gerektiren durumlar, kök anahtarın tek olması): [known-limitations.md](known-limitations.md) §3.

## 10. Webhook imzaları (AUD-07)

**Kod:** `crates/authn-crypto/src/webhook.rs`, `crates/authn-audit/src/webhooks/`.

- Standard Webhooks biçimi kullanılır: `webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<base64(HMAC-SHA256(sır, id.timestamp.gövde))>`.
- Sır `whsec_` + 32 rastgele bayttır, kabul edilen uzunluk 24–64 bayttır. Sır oluşturmada bir kez gösterilir ve zarfla saklanır. Rotasyonda örtüşme süresi boyunca (`audit.webhooks.secret_rotation_overlap`, varsayılan 24 sa) her iki sırla imzalanır.
- Ek sertleştirme: `webhook-id` `[A-Za-z0-9_-]{1,256}` ile sınırlıdır (`.` içeren bir kimlik imzalı içeriği belirsizleştirirdi). Zaman damgası kanonik ondalıktır ve tolerans her iki yönde uygulanır (varsayılan 300 sn). İmza listesi taranırken erken çıkış yapılmaz.
- Testler: `aud_07_standard_webhooks_reference_vector`, `aud_07_sign_verify_rotation_and_tampering`, `aud_07_ids_with_dots_are_refused`, `aud_07_timestamp_tolerance_both_directions`, `aud_07_secret_rotation_signs_with_both_secrets_during_the_overlap`, `aud_07_kek_rotation_rewraps_secrets_without_changing_them`.

## 11. TOTP (MFA-01, MFA-02)

**Kod:** `crates/authn-crypto/src/totp.rs`, `crates/authn-mfa/src/totp.rs`.

- RFC 6238/4226. Varsayılan: HMAC-SHA-1, 6 hane, 30 sn, ±1 adım (`[mfa] totp`). SHA-1, RFC 6238 ve doğrulayıcı uygulamalarla uyumluluk için kullanılır; HMAC-SHA-1'in bilinen çakışma zayıflığı HMAC kullanımını etkilemez.
- Sır 160 bittir (en az 128 bit kabul edilir) ve zarfla saklanır (§4.2). Sır, `otpauth://` URI'si ve QR (SVG) yalnızca kayıt yanıtında bir kez döner.
- `verify` tüm pencereyi erken çıkışsız tarar ve eşleşen adımı döner. Son kullanılan adım ve öncesi reddedilir (MFA-02). Doğrulama kullanıcının satır kilidi altındadır, böylece aynı adım eşzamanlı isteklerde bile en fazla bir kez kabul edilir.
- Testler: `cry_14_totp_rfc6238_vectors`, `mfa_01_window_and_replay_protection`, `mfa_02_totp_code_cannot_be_replayed`, `mfa_02_concurrent_duplicate_submissions_only_one_succeeds`, `mfa_01_secret_is_envelope_encrypted_and_bound_to_its_row`.

## 12. WebAuthn / passkey (PKY-01 … PKY-08)

**Kod:** `crates/authn-webauthn/` (`webauthn-rs` 0.6.2; lisans MPL-2.0, `deny.toml`'da crate bazında istisna).

- Kriptografik doğrulama (attestation, assertion imzası, origin, RP ID hash'i, UV/UP bayrakları) `webauthn-rs`'indir. Bu crate seremoni durumunu, bağlamayı ve politikayı yönetir.
- Challenge durumu sunucu tarafındadır, tek kullanımlıktır ve en çok `webauthn.ceremony_ttl` (varsayılan 5 dk) yaşar. Tüketim doğrulamadan önce commit edilir: başarısız yanıt challenge'ı yakar. Kimlik doğrulama seremonileri ayrıca 256 bit bir bağlama token'ı taşır (yalnızca SHA-256'sı saklanır): ikinci faktör giriş challenge'ına, step-up oturuma bağlıdır (`pky_01_authentication_ceremony_is_single_use`, `pky_01_swapped_or_unbound_ceremonies_are_rejected`, `pky_01_concurrent_finishes_authenticate_exactly_once`).
- Şifresiz giriş ve step-up'ta kullanıcı doğrulaması (UV) zorunludur. UV'siz kaydedilmiş anahtar yalnızca ikinci faktör olabilir (`pky_02_passwordless_login_requires_user_verification`, `pky_02_second_factor_only_keys_cannot_log_in_passwordless`).
- Origin'ler tam eşleşir; alt alan adı veya port joker karakteri yoktur. Android origin'leri yalnızca yapılandırılmış imza sertifikası hash'iyle kabul edilir (`pky_01_assertion_from_wrong_origin_is_rejected`, `pky_06_origins_must_belong_to_the_rp_id_or_be_related`).
- Attestation varsayılan olarak `none`'dır. AAGUID kısıtı (PKY-08) yalnızca yapılandırmadaki güvenilir köklerle doğrulanmış attestation'a dayanır; FIDO MDS3 entegrasyonu yoktur (Faz 2, K-95). Testler: `pky_08_org_policy_rejects_unattested_and_other_models`, `pky_08_policy_applies_to_existing_passkeys`.
- İmza sayacı gerilemesi yalnızca imzası doğrulanmış bir onayda klon işareti üretir (`pky_05_counter_regression_flags_a_cloned_passkey`).
- Saklanan veri yalnızca açık anahtar ve meta veridir. Liste, dışa aktarma ve audit açık anahtar veya ham credential id içermez (`pky_04_list_shows_metadata_without_key_material`).

## 13. Diğer HMAC/hash kullanımları

| Kullanım | Yapı | Kod |
|----------|------|-----|
| Kendi barındırılan PoW CAPTCHA | Görev = `base64url(yük) "." base64url(HMAC(K_pow, yük))`; çözüm `SHA-256(görev ":" çözüm)` için baştaki sıfır bitleri; tek kullanım `INSERT … ON CONFLICT DO NOTHING` | `crates/authn-protect/src/captcha/pow.rs`; `prt_05_pow_rejects_forgery_wrong_action_expiry_and_lazy_work`, `prt_05_pow_concurrent_double_spend_passes_once` |
| Hız sınırı anahtarları | Kişisel veri içeren anahtarlar `HMAC(K_rate_limit, …)` olarak saklanır | `crates/authn-protect/src/keys.rs`; `prt_02_rate_limit_keys_are_keyed_hashes_without_personal_data`, `prt_02_postgres_stores_only_keyed_hashes` |
| Bilinen cihaz | `HMAC(K_known_device, user ‖ cihaz id)` | `crates/authn-protect/src/keys.rs`; `cry_11_device_hashes_use_the_known_device_purpose_key`, `rsk_02_device_hashes_are_bound_to_the_user` |
| HIBP sızıntı kontrolü | SHA-1(şifre); yalnızca ilk 5 hex karakter `Add-Padding: true` ile gönderilir (k-anonymity). SHA-1 burada HIBP API'sinin biçimi olduğu için kullanılır | `crates/authn-password/src/breach.rs`; `pwd_03_only_the_five_character_prefix_is_sent_with_padding` |
| API anahtarı sağlama toplamı | CRC-32 (IEEE): yalnızca yazım hatası/sızıntı taraması içindir, güvenlik özelliği **değildir** | `crates/authn-org/src/api_key.rs` |

## 14. Değerlendirilip seçilmeyenler

| Seçenek | Neden seçilmedi |
|---------|-----------------|
| `jsonwebtoken` crate'i | Algoritma seçimini yapılandırmaya bırakır ve RUSTSEC uyarılı `rsa`/eski `p256` zincirini çeker ([ADR 0001](../architecture/adr/0001-jwt-implementation.md)) |
| AES-256-GCM (zarf için) | 96 bit rastgele nonce anahtar başına ~2^32 mesajla sınırlı; donanım hızlandırması olmadan yazılım uygulamasının sabit zamanlılığı platforma bağlı (§4.1) |
| Webhook/CSRF/PoW için ayrı rastgele anahtarlar | Tek kök + HKDF amaç ayrımı yapılandırmayı tek sırda tutar. Bedeli: kök anahtar rotasyonu tüm türevleri etkiler ([known-limitations.md](known-limitations.md)) |
| RS256/ES256 access token | Faz 2 OIDC sağlayıcısında (K-80) ES256 eklenmesi planlı. Algoritma anahtar kaydına bağlanacak, header'dan seçilmeyecek ([ADR 0001](../architecture/adr/0001-jwt-implementation.md)) |
| FIPS 140 doğrulanmış modül | RustCrypto crate'leri FIPS doğrulamalı değildir ([roadmap](../roadmap.md) G18) |
