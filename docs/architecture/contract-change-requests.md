# Sözleşme değişikliği talepleri

Kurallar: [`contracts.md` §13](contracts.md#13-sözleşme-değişikliği-talebi). Her crate **yalnızca kendi başlığı altına** ekleme yapar; başka bölümleri düzenlemez. Uygulanan talepler silinmez, durumu güncellenir.

Kayıt şablonu:

```markdown
### <YYYY-AA-GG> — <kısa başlık>
- **Talep eden:** authn-<crate>
- **Etkilenen dosya / sahip:** `crates/authn-core/src/ports/…` / authn-<sahip>
- **Gereksinim:** <ID>
- **Gerekçe:** …
- **Önerilen değişiklik:** …
- **Geriye uyumluluk:** …
- **Durum:** Açık | Uygulandı (<tarih>, <commit/özet>) | Reddedildi (<gerekçe>)
```

## authn-crypto

### 2026-10-31 — `authn-store` bağımlılığı ve yeni store modülleri
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `crates/authn-store/Cargo.toml`, `crates/authn-store/src/lib.rs`, `crates/authn-store/README.md` / authn-store
- **Gereksinim:** ARC-06, CRY-06, CRY-07, CRY-10
- **Gerekçe:** Görev ataması gereği `one_time_tokens` ve `signing_keys` modülleri `authn-store` içinde authn-crypto agent'ı tarafından yazıldı. Modüller `TokenHash`, `EnvelopeCipher`, `JwtSigner` tiplerini kullandığından `authn-store` → `authn-crypto` bağımlılığı eklendi (contracts §2'de zaten izinli; `architecture.rs` testi geçiyor). `lib.rs`'e yalnızca `pub mod` ve yeniden dışa aktarma satırları, README'ye iki API satırı eklendi.
- **Önerilen değişiklik:** Uygulandı; store sahibinin bilgisine.
- **Geriye uyumluluk:** Ekleme; mevcut API değişmedi.
- **Durum:** Uygulandı (2026-10-31, authn-crypto görevi)

### 2026-10-31 — `data_encryption_keys` tablosu kullanılmıyor
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `migrations/0011_keys.sql` (`data_encryption_keys`) / authn-crypto (tablo), mimar (migration)
- **Gereksinim:** CRY-08
- **Gerekçe:** Zarf şifreleme değer başına DEK kullanır; DEK, KEK ile sarılmış olarak zarfın içinde taşınır (`version ‖ kek_id ‖ wrapped_dek ‖ nonce ‖ ciphertext`). Bu, şifre çözme yolunda veritabanı araması/önbellek gerektirmez, nonce yeniden kullanımını imkânsız kılar ve KEK rotasyonunu `EnvelopeCipher::rewrap` ile satır bazında yapar. `0011` yorumundaki "zarf başlığı DEK kimliğini taşır" modeli uygulanmadı.
- **Önerilen değişiklik:** Tablo şimdilik olduğu gibi kalsın (ileride KMS sağlayıcısı için sarılmış-DEK önbelleği olarak kullanılabilir); `0011_keys.sql` yorumu ve `overview.md` bir sonraki mimar düzenlemesinde "kullanılmıyor / ayrılmış" olarak güncellensin. Tablo silinmesi istenirse authn-crypto aralığında (`1000–1099`) bir `DROP TABLE` migration'ı yazılabilir.
- **Geriye uyumluluk:** Etkisi yok (tabloya yazan/okuyan kod yok).
- **Durum:** Açık

### 2026-10-31 — Sarmalanmış eski hash'ler için pepper zorunluluğu (şema kısıtı)
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `password_credentials` tablosu / authn-store (yeni migration mimar aralığında)
- **Gereksinim:** CRY-02, CRY-04
- **Gerekçe:** `argon2id_wrapped_md5` ve `argon2id_wrapped_sha1` hash'leri de pepper ile üretilir; `pepper_version` olmadan doğrulanamazlar (kod `Invalid` döner ve loglar). Mevcut kısıt yalnızca `algorithm = 'argon2id'` için `pepper_version`'ı zorunlu kılıyor.
- **Önerilen değişiklik:** `ALTER TABLE password_credentials ADD CONSTRAINT password_credentials_wrapped_pepper_check CHECK (algorithm NOT LIKE 'argon2id%' OR pepper_version IS NOT NULL);`
- **Geriye uyumluluk:** Mevcut veride bu biçimde satır yok; ekleme.
- **Durum:** Açık

### 2026-10-31 — Fuzz harness'ine authn-crypto hedefleri eklendi
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `fuzz/Cargo.toml` / mimar
- **Gereksinim:** TST-04, CRY-14
- **Gerekçe:** Görev kapsamı `fuzz/**`'i içerdiğinden üç yeni hedef (`password_hash_parse`, `token_parse`, `webhook_verify`) ve harness yardımcı bağımlılıkları (`base64 0.23.1`, `serde_json 1.0.154`, `time 0.3.55`; workspace ile aynı sürümler, MIT/Apache-2.0) eklendi. `webhook_signature` hedefi authn-audit'e ait olarak bırakıldı; `webhook_verify` yalnızca `authn_crypto::webhook` ayrıştırıcısını kapsar. CI'daki `cargo +nightly fuzz build` adımı yeni hedefleri otomatik derler.
- **Önerilen değişiklik:** Uygulandı.
- **Geriye uyumluluk:** Ekleme.
- **Durum:** Uygulandı (2026-10-31)

### 2026-10-31 — Yeni `one_time_tokens.purpose` değerleri artık bir enum'a eklenir
- **Talep eden:** authn-crypto
- **Etkilenen dosya / sahip:** `crates/authn-store/src/one_time_tokens.rs` (`TokenPurpose`) / authn-crypto agent'ı
- **Gereksinim:** ARC-06
- **Gerekçe:** Amaçlar dize değil, contracts §5 tablosunun birebir karşılığı olan `TokenPurpose` enum'udur (link/kod türü enum'dan türetilir, yazım hatası yeni bir amaç yaratamaz). Yeni amaç isteyen modül §13 kaydıyla birlikte enum'a varyant eklenmesini talep eder.
- **Önerilen değişiklik:** contracts §5'e "Yeni purpose = `TokenPurpose` varyantı" notu eklensin.
- **Geriye uyumluluk:** Etkisi yok.
- **Durum:** Açık

## authn-store

## authn-password

## authn-account

## authn-mfa

## authn-webauthn

## authn-org

## authn-protect

## authn-audit

## authn-notify

## authn-session

## authn-oidc-client

## authn-admin

## authn-server
