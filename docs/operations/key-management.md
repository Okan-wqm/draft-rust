# Anahtar yönetimi ve rotasyon runbook'ları (DOC-06)

Sistemdeki her sır, nerede tutulduğu, rotasyonu ve sızıntıda ne yapılacağı. Kaynaklar: `crates/authn-core/src/config/crypto.rs`, `crates/authn-crypto/src/{password,envelope,kdf}/…`, `crates/authn-store/src/signing_keys.rs`, `crates/authn-server/src/{cli,operations}.rs`, `crates/authn-audit/README.md` ("K-77: anahtarlı zincir"). Sızıntı senaryoları: [incident-response.md](incident-response.md). Admin hesapları ve break-glass: [admin-recovery.md](admin-recovery.md).

## 0. Envanter

| Sır | Yapılandırma | Ne korur | Rotasyon | Kesinti |
|-----|--------------|----------|----------|---------|
| **Pepper** | `crypto.peppers[]`, `crypto.current_pepper_version` | Argon2id girdisi `HMAC-SHA256(pepper_v, NFKC(şifre))` (CRY-02) | Yeni sürüm ekle; hash'ler **başarılı girişte** yeni sürüme taşınır (§1) | Yok |
| **KEK** | `crypto.keks[]`, `crypto.current_kek_id` | Zarf şifreleme: her değerin kendi DEK'i KEK ile sarılır (CRY-08) | Yeni KEK ekle + `rotate-kek` (§2) | Yok |
| **JWT imza anahtarları** | veritabanında (`signing_keys`, özel anahtar KEK ile şifreli) | Access token imzası (Ed25519) | Otomatik (`crypto.signing_keys.rotation_interval`, 30 g) veya `rotate-signing-key` (§3) | Yok (acil rotasyonda eski token'lar düşer) |
| **HMAC kök anahtarı** | `crypto.hmac_root_key` | HKDF amaç anahtarları (§4) | **Fiilen rotasyonsuz** — yıkıcı (§4) | Var |
| **Audit zinciri anahtarı** | kökten türetilir; sürüm `audit.chain.key_version` | Audit olaylarının HMAC zinciri (K-77) | Sürüm artır + `rotate-audit-chain-key` (§5) | Yok |
| Webhook imza sırları | veritabanında, KEK ile şifreli | Organizasyon webhook'ları | Organizasyon `POST …/rotate-secret` | Yok (örtüşme penceresi) |
| Apple özel anahtarı | `oidc_client.apple.private_key_*` | Sign in with Apple `client_secret` | Apple'da yeni anahtar + `seal-apple-key` | Yok |
| Veritabanı/SMTP/SMS/CAPTCHA/Redis kimlik bilgileri | `database.url`, `notify.*`, `protect.*` | Bağımlılıklar | Sağlayıcıda değiştir, yapılandırmayı güncelle, yeniden başlat | Kısa |

Genel kurallar:

- Anahtar materyali: `openssl rand -base64 32` (KEK **tam** 32 bayt; diğerleri ≥ 32 bayt). Depoda yayımlanmış örnek/test anahtarları production/staging'de reddedilir.
- Sırları ortam değişkeni veya salt-okunur secret mount ile verin; yapılandırma hataları anahtar adını söyler, değeri asla.
- Her rotasyon adımından sonra `rust-authentication check-config` çalıştırın ve **tüm örnekleri** aynı yapılandırmaya getirin: çok örnekli kurulumda bir örneğin bilmediği bir anahtar/sürümle yazılmış veri o örnekte okunamaz.

## 1. Pepper rotasyonu (CRY-02, CRY-03)

1. Yeni sürüm ekleyin, eskisini **silmeyin**:
   ```toml
   current_pepper_version = 2
   [[crypto.peppers]]
   version = 1
   key = "<eski>"
   [[crypto.peppers]]
   version = 2
   key = "<openssl rand -base64 32>"
   ```
2. Tüm örneklere dağıtın. Yeni hash'ler sürüm 2 ile yazılır; sürüm 1'li bir şifreyle **başarılı her girişte** şifre yeni sürümle yeniden hash'lenir (`authn-password/src/service/login.rs`, audit'te `rehashed`, metrik `authn_password_updates_total{kind="rehashed"}`).
3. İlerlemeyi izleyin:
   ```sql
   SELECT pepper_version, count(*) FROM password_credentials GROUP BY 1 ORDER BY 1;
   ```
   (`NULL` = henüz sarılmamış içe aktarılmış eski hash; bkz. `migrate-legacy-hashes`.)
4. Eski sürümü kaldırma: kaldırılan sürümle hash'lenmiş şifreler **artık doğrulanmaz** (sahte doğrulamaya düşer, kullanıcı `invalid_credentials` görür; hesap varlığı sızmaz). Bu kullanıcıları önce şifre sıfırlamaya yönlendirin (ör. admin `POST /v1/admin/emergency/force-password-change` ile `changed_before`) veya kalan sayı kabul edilebilir olana kadar bekleyin. Şifreyi önceden toplu yeniden hash'lemek mümkün değildir (düz metin gerekir).

## 2. KEK rotasyonu (CRY-08) — `rotate-kek`

Zarfın biçimi `sürüm ‖ kek_id ‖ sarılmış DEK ‖ nonce ‖ şifreli metin`; KEK yalnızca DEK'i sarar, rotasyon veriyi yeniden şifrelemez, **DEK'i yeni KEK ile yeniden sarar**.

1. Yeni KEK ekleyin ve geçerli yapın, eskisini tutun:
   ```toml
   current_kek_id = "kek-2026-12"
   [[crypto.keks]]
   id = "kek-2026-11"
   key = "<eski>"
   [[crypto.keks]]
   id = "kek-2026-12"
   key = "<openssl rand -base64 32>"
   ```
2. Tüm örneklere dağıtın (yeni değerler yeni KEK ile yazılır; eski KEK'li değerler okunmaya devam eder).
3. Yeniden sarın (uygulama rolüyle, herhangi bir makineden):
   ```bash
   rust-authentication --config prod.toml rotate-kek
   # re-wrapped: <n> signing keys, <n> webhook secrets, <n> other values
   ```
   Kapsam: imza anahtarlarının özel anahtarları, webhook sırları ve şemadaki her zarf şifreli kolon (`mfa_factors.secret_ciphertext`, `refresh_tokens.successor_ciphertext`, `outbox.sealed_payload`, `identities.access_token_ciphertext` / `refresh_token_ciphertext`, `oauth_states.pkce_verifier_ciphertext`, `oauth_token_revocations.token_ciphertext`; test `cry_08_rotate_kek_covers_every_sealed_column_of_the_schema` yeni kolonların atlanmasını engeller). Satır başına karşılaştır-ve-değiştir yapılır; yarıda kalırsa yeniden çalıştırın (idempotent: güncel KEK'li değerler atlanır). Her zarf önce tam doğrulanır; bozuk bir zarf komutu durdurur (`69`).
4. `oidc_client.apple.private_key_ciphertext` kullanıyorsanız komut yeni değeri yazdırır (`replace oidc_client.apple.private_key_ciphertext with …`): yapılandırmayı güncelleyip dağıtın (dosyayı komut değiştiremez).
5. Komutu bir kez daha çalıştırın: `0` yeniden sarma bekleyin (rotasyon sırasında eski örneklerin yazdığı değerler de yakalanır).
6. Ancak bundan sonra eski KEK'i yapılandırmadan kaldırın. Yedekler eski KEK'le sarılmış DEK'ler içerir: eski KEK'i yedek saklama süresi boyunca güvenli bir kasada tutun ([backup.md](backup.md)).

> `data_encryption_keys` tablosu ayrılmış ve kullanılmıyor (DEK değer başına zarfın içindedir). KMS/HSM sağlayıcısı yol haritasındadır (K-96).

## 3. JWT imza anahtarı rotasyonu (CRY-10) — `rotate-signing-key`

**Otomatik:** sunucu saatte bir kontrol eder; etkin anahtar `rotation_interval`'dan (30 g) eskiyse yeni anahtar `pending` olarak oluşturulur, JWKS'te en az `pending_period` (2 sa, ≥ `jwks_cache_ttl`) yayımlanır, sonra etkinleşir; önceki anahtar `retired` olur ve `retired_retention` (1 g, ≥ `access_token_ttl`) boyunca JWKS'te kalır. Kaynak sunucuları kesintisiz geçer.

**Planlı (elle):**
```bash
rust-authentication --config prod.toml rotate-signing-key
# pending key <kid> created; it activates after crypto.signing_keys.pending_period
```

**Acil (anahtar sızıntısı):**
```bash
rust-authentication --config prod.toml rotate-signing-key --emergency
# emergency rotation done; active key <kid>; serving instances drop the revoked key at once …
```
Etkin anahtar **iptal edilir** (JWKS'ten hemen düşer) ve yenisi bekleme süresi olmadan etkinleşir. Sunucu örnekleri `LISTEN authn_signing_keys` ile milisaniyeler içinde önbelleklerini boşaltır (dinleyici kopuksa en geç 5 sn, hiç çalışmıyorsa `session.signing_key_cache_ttl`). Eski anahtarla imzalanmış **tüm** access token'lar geçersizleşir; native istemciler refresh token'larıyla yeni token alır (refresh token'lar etkilenmez). Kaynak sunucularınız JWKS önbelleğini en geç `max-age` sonunda yeniler; daha hızlı yayılım için onların önbelleğini de boşaltın. Admin API karşılığı: `POST /v1/admin/emergency/rotate-signing-key` (`"confirm": "rotate_signing_key"`; dört göz onayı açıksa ikinci bir admin onaylar).

## 4. HMAC kök anahtarı (`crypto.hmac_root_key`)

Kök anahtardan HKDF ile türetilen amaç anahtarları (`crates/authn-crypto/src/kdf.rs`, `KeyPurpose`): kısa OTP kodlarının saklama hash'i, **kurtarma kodlarının saklama hash'i**, CSRF token'ları, güvenilir cihaz token'ları, magic link cihaz bağlaması, PoW CAPTCHA, audit takma adları / PII özetleri, oran sınırı anahtar hash'leri, OAuth state bütünlüğü, webhook sırrı türetme girdileri, bilinen cihaz hash'leri ve **audit zinciri taban anahtarı**.

Kök anahtarın sürümü yoktur; değiştirmek bunların hepsini aynı anda değiştirir:

- Tüm kullanıcıların **kurtarma kodları çalışmaz** hâle gelir (yeniden üretmeleri gerekir); bekleyen e-posta/SMS/sıfırlama kodları, güvenilir cihazlar, açık CSRF token'ları ve bekleyen OAuth akışları geçersizleşir.
- Her cihaz "yeni cihaz" sayılır (bildirim e-postaları), oran sınırı sayaçları sıfırlanır.
- Audit takma adları değişir: yeni olaylar eski olaylarla aynı kişiye bağlanamaz.
- **Anahtarlı audit zinciri, eski anahtarla yazılmış olaylar için doğrulanamaz olur** (zincir sürüm anahtarları kökten türetilir).

Bu yüzden rutin rotasyon önerilmez; yalnızca sızıntıda yapılır ([incident-response.md §4](incident-response.md#4-pepper-kek-veya-hmac-kök-anahtarı-sızıntısı)). Rotasyondan **önce** `verify-audit-chain` çıktısındaki baş `seq:hash`'ini ve tam bir veritabanı yedeğini dışarıda saklayın; eski olayların bütünlüğü bundan sonra yalnızca o dış çıpayla ve eski kök anahtarla (kasada saklanan) kanıtlanabilir. Sürümlü/KMS'li kök anahtar yol haritasındadır (K-96).

## 5. Audit zinciri anahtarı (K-77)

Yeni audit olayları `HMAC-SHA-256(K_v, prev_hash ‖ kayıt)` ile zincirlenir; `K_v` = kökten türetilen zincir anahtarının `audit.chain.key_version` sürümü. Eski sürümler her zaman yeniden türetilebilir, bu yüzden rotasyon eski olayların doğrulanmasını bozmaz.

**İlk kurulum / K-77'ye yükseltme (bir kez):**

1. Sunucu açılışta zinciri yapılandırılmış sürüme geçirir ve `chain_key_switch` kontrol noktasını `WARN` düzeyinde `(seq, hash)` ile loglar. Aynısını elle yapmak ve değeri görmek için:
   ```bash
   rust-authentication --config prod.toml rotate-audit-chain-key
   # audit chain switched from unkeyed to key version 1; keep this checkpoint outside the database: <seq>:<hash>
   ```
2. `<seq>:<hash>`'i veritabanı dışında, değiştirilemez bir depoda (WORM) saklayın.
3. `audit.chain.legacy_until_seq = <seq - 1>` ayarlayın ve dağıtın. Bu sabitleme olmadan, zincirin tamamını anahtarsız biçime çeviren bir saldırgan yalnızca raporda `legacy_events > 0` olarak görünür.

**Rotasyon (ör. yıllık, veya sürüm anahtarının sızdığı şüphesinde):**

1. `audit.chain.key_version`'ı bir artırın (`1..=32767`; sürüm hiç azalmaz).
2. Tüm örneklere dağıtın; ilk açılan örnek (veya `rotate-audit-chain-key`) geçişi yapar, yeni anahtarla imzalanan ilk olay `audit.chain_key_rotated` olur. Eski ve yeni yapılandırmalı örnekler yan yana güvenle çalışır (her ikisi de en yüksek sürümle yazar).
3. Yazdırılan / loglanan `chain_key_switch` `seq:hash`'ini WORM depoya ekleyin.

**Doğrulama:**

```bash
rust-authentication --config prod.toml verify-audit-chain
# audit chain intact; <n> events verified; head <seq>:<hash> (key version <v>)
rust-authentication --config prod.toml verify-audit-chain --anchor <seq>:<64 hex>
rust-authentication --config prod.toml verify-audit-chain --legacy-until-seq <seq>
```

- `--anchor` doğrulamayı saklama başlangıcı yerine dışarıda saklanan bir kontrol noktasından başlatır (kesme / geri sarma tespiti); `--legacy-until-seq` yapılandırmadaki değeri geçersiz kılar.
- Bozulmada çıkış kodu `1` ve `audit chain broken after <n> verified events: …`; sorun türleri `key_downgrade`, `unkeyed_event`, `key_switch_unrecorded`, `head_mismatch` ve hash uyuşmazlıkları. Admin API karşılığı: `POST /v1/admin/audit-events/verify`.
- **Dış çıpaları düzenli toplayın:** günlük bakım işi yalnızca saklama temizliği yaptığında (`audit.retention`, varsayılan 400 gün dolunca) kontrol noktası yazar; ayrı bir periyodik kontrol noktası işi yoktur. Bu yüzden `verify-audit-chain`'i zamanlanmış olarak (ör. günlük) çalıştırıp yazdırdığı `head <seq>:<hash>` değerini WORM depoya ekleyin; sonraki doğrulamalarda en yeni çıpayı `--anchor` ile kullanın.

## 6. Diğer sırlar

- **Webhook sırları:** organizasyon yöneticisi `POST /v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret` (step-up) çağırır; eski sır `audit.webhooks.secret_rotation_overlap` (24 sa) boyunca da imzalar, `?immediate=true` ile hemen bırakılır. Platform tarafında bir eylem gerekmez (sırlar KEK ile şifreli, `rotate-kek` kapsar).
- **Apple özel anahtarı:** Apple Developer'da yeni Sign in with Apple anahtarı oluşturun → `rust-authentication --config prod.toml seal-apple-key --pem-file AuthKey_NEW.p8` (veya `--pem-file -` ile stdin; anahtar asla yazdırılmaz) → çıktıyı `oidc_client.apple.private_key_ciphertext` ve yeni `key_id` olarak ayarlayın → dağıtın → Apple'da eski anahtarı iptal edin.
- **Eski şifre hash'lerinin içe aktarımı:** `rust-authentication --config prod.toml migrate-legacy-hashes --input hashes.csv` (`user_id,algorithm,hash` satırları; `algorithm` yalnızca `md5` veya `sha1` — bu zayıf özetler Argon2id ile sarılır (`argon2id_wrapped_md5/sha1`) ve ilk başarılı girişte düz Argon2id'ye taşınır, CRY-04. bcrypt ve PBKDF2-SHA256 hash'leri sarmadan doğrulanabilir; bu komut onları kabul etmez).
- **Veritabanı rol parolaları:** PostgreSQL'de `ALTER ROLE … PASSWORD`, sonra `database.url` / `maintenance_url`'i güncelleyip örnekleri sırayla yeniden başlatın (`database.max_lifetime` = 30 dk sonunda eski bağlantılar kendiliğinden yenilenir).
