# rust-authentication

Rust ile yazılmış, kendi barındırılan bir **kimlik doğrulama sunucusu**. B2C web uygulamaları, B2B SaaS ürünleri (organizasyonlar, roller, davetler, API anahtarları) ve native mobil uygulamalar (token akışı, passkey) aynı sunucuyu kullanır. Tek binary (`rust-authentication`) olarak çalışır; PostgreSQL 16 zorunludur, Redis isteğe bağlıdır. Yalnızca ticari kullanıma engel olmayan, izin verici lisanslı bağımlılıklar kullanılır.

> **Durum (2026-11-05):** Faz 1 geliştirme aşamasında, ilk sürüm etiketlenmedi (workspace sürümü `0.1.0`). Kod iç güvenlik denetimlerinden geçti ([K-57](docs/security/k57-global-audit.md)), ancak **bağımsız bir dış güvenlik denetimi (pentest) yapılmadı** (K-72) ve **Docker imajı hiç derlenip çalıştırılmadı** (K-55). Üretime çıkmadan önce [bilinen sınırlamalar](docs/security/known-limitations.md) belgesini okuyun.

Depo adı `draft-rust`, ürün ve binary adı `rust-authentication`'dır.

## İçindekiler

1. [Özellikler](#özellikler)
2. [Henüz olmayanlar](#henüz-olmayanlar)
3. [Hızlı başlangıç](#hızlı-başlangıç)
4. [Mimari özet](#mimari-özet)
5. [Operasyon komutları](#operasyon-komutları)
6. [Geliştirme ve kalite kapıları](#geliştirme-ve-kalite-kapıları)
7. [Lisans politikası](#lisans-politikası)
8. [Belgeler](#belgeler)

## Özellikler

Bu liste [özellik matrisindeki](docs/roadmap.md#3-özellik-matrisi) ✅ satırlarıyla aynıdır. Her satırın gereksinim kimliği [`docs/spec/requirements.md`](docs/spec/requirements.md)'dedir ve test adlarında geçer.

**Kimlik doğrulama**

- E-posta + şifre: Argon2id + versiyonlu pepper, eski bcrypt/PBKDF2/MD5/SHA-1 hash'lerinin doğrulanıp Argon2id'ye taşınması, HIBP k-anonymity ile sızıntı kontrolü, zxcvbn güç tahmini, NIST 800-63B'ye uygun politika (karakter sınıfı zorunluluğu yok) (CRY-01…05, PWD-01…12).
- Passkey / WebAuthn: birincil (şifresiz, kullanıcı adısız, conditional UI) ve ikinci faktör, AAGUID politikası, imza sayacıyla klon tespiti, iOS/Android ilişkilendirme dosyaları (`apple-app-site-association`, `assetlinks.json`, `/.well-known/webauthn`) (PKY-01…08, SES-20/21).
- MFA: TOTP (tekrar kullanım korumalı), kurtarma kodları, e-posta OTP, SMS OTP (SMS pumping korumasıyla, varsayılan kapalı), güvenilir cihaz (MFA-01…10).
- Şifresiz giriş: magic link (GET ile tüketilmez, başka cihazda onay ister) ve e-posta kodu (SES-18/19).
- Sosyal giriş (OIDC istemcisi): Google, Apple, Microsoft (Entra ID, kiracı izin listesi), GitHub ve discovery destekli genel OIDC; web (PKCE + state + nonce) ve native (SDK'dan gelen ID token) akışları; `(provider, subject)` ile eşleştirme, e-postayla otomatik birleştirme varsayılan kapalı (SOC-01…09).
- Risk tabanlı doğrulama: yeni cihaz/ağ, hata hızı, anonimleştirici ağ listesi; `medium` → MFA veya e-posta onayı, `high` → engel + bildirim; yeni cihaz bildirimi ve "bu ben değilim" bağlantısı (RSK-01…04).

**Oturumlar ve token'lar**

- Web: sunucu tarafı opak oturum, `__Host-` çerezi (`HttpOnly`, `Secure`, `SameSite=Lax`), her girişte/MFA'da/org değişiminde/step-up'ta yeni token, çift CSRF koruması (Origin + oturuma bağlı token) ve login CSRF (SES-03/04).
- Native: EdDSA imzalı JWT access token (RFC 9068, 10 dk), rotasyonlu opak refresh token, yeniden kullanımda tüm token ailesinin iptali (SES-05/08).
- JWKS (`/.well-known/jwks.json`), imza anahtarı rotasyonu (`pending → active → retired → revoked`), acil iptal ve tüm instance'lara anında yayılması; kaynak sunucuları için introspection (RFC 7662, org API anahtarıyla) (SES-09/10, CRY-09/10).
- Boşta/mutlak ömürler, "beni hatırla", paylaşılan cihaz modu, eşzamanlı oturum sınırı, oturum listesi ve uzaktan kapatma, her Bearer isteğinde canlı oturum kontrolü (SES-06/07/11/12/14).
- Step-up (son N dakikada yeniden doğrulama), `amr`/`acr`/`auth_time` (SES-13).

**Hesap yaşam döngüsü ve gizlilik**

- Hesap varlığını gövdeden, durum kodundan ve **süreden** sızdırmayan kayıt, şifre sıfırlama, magic link ve giriş (ACC-02, PWD-07, SES-01/18).
- Hesap ön-ele geçirmeye (pre-hijacking) karşı tasarlanmış kayıt akışı ([ADR 0002](docs/architecture/adr/0002-registration-pre-hijacking.md)).
- E-posta doğrulama (link + kod), e-posta değişikliği ve geri alma, durum makinesi, bekleme süreli hesap silme, KVKK/GDPR veri dışa aktarma, kullanım şartı onay kayıtları (ACC-01…13).

**B2B**

- Organizasyonlar, çoklu üyelik, RBAC (yerleşik + org'a özel roller, `resource:action` izinleri, ayrıcalık yükseltme koruması), davetler, DNS TXT ile domain doğrulama ve otomatik katılım (ORG-01…06).
- Org politikaları: MFA / phishing'e dayanıklı MFA zorunluluğu, izinli giriş yöntemleri ve faktörler, oturum ömrü üst sınırı, IP izin listesi; her org isteğinde uygulanır (ORG-07).
- API anahtarları (`ak_<env>_…_<crc32>`, kapsam, zorunlu son kullanma, rotasyon), servis hesapları, kiracı izolasyonu (başka kiracının kaynağı `404`), sahiplik devri, org silme (ORG-08…12).

**Yönetim, audit, bildirimler**

- Admin API (`/v1/admin/...`): passkey + step-up zorunlu, kullanıcı arama/işlemler, gerekçe zorunlu, süreli ve varsayılan salt-okunur impersonation (`act` claim'i), break-glass hesabı, acil durum işlemleri, kritik işlemlerde **çift onay (four-eyes)** (ADM-01…08, K-66).
- Ekleme-yalnızca, **anahtarlı HMAC zincirli** audit log'u; kişisel veri zincir dışında, silmede takma adlaştırma; kullanıcının kendi olayları ve org audit log'u (AUD-01…05, K-77).
- Transactional outbox, Standard Webhooks biçiminde imzalı ve SSRF korumalı org webhook'ları (AUD-06/07).
- TR/EN e-posta şablonları, SMTP (TLS zorunlu), genel HTTP SMS sağlayıcısı (NTF-01…04).

**Güvenlik altyapısı ve operasyon**

- Dağıtık hız sınırı (PostgreSQL varsayılan, Redis opsiyonel, GCRA), CAPTCHA (Turnstile, hCaptcha, kendi barındırılan proof-of-work), hesabı kapatmayan yumuşak kilit (PRT-01…05).
- Güvenlik başlıkları, sıkı CORS, Host doğrulama, open redirect koruması, istek sınırları, DNS sabitlemeli SSRF-güvenli giden HTTP (PRT-06…12).
- AAD'li zarf şifreleme (XChaCha20-Poly1305) ve KEK rotasyonu; HKDF ile amaç başına alt anahtarlar ([kriptografi kararları](docs/security/cryptography.md)).
- Yapılandırılmış JSON log ve kişisel veri maskeleme, Prometheus metrikleri (ayrı port), sağlık uçları, OpenAPI şeması (`/openapi.json`), çoklu instance'ta güvenli arka plan işleri, zarif kapanış (OPS-01…10).
- En az yetkili veritabanı rolleri: uygulama rolünün audit tablosunda `UPDATE`/`DELETE` yetkisi yoktur ([runbook](docs/operations/least-privilege.md)).

## Henüz olmayanlar

Dürüst liste; ayrıntı ve öncelik [`docs/roadmap.md`](docs/roadmap.md)'te, kabul edilen riskler [`docs/security/known-limitations.md`](docs/security/known-limitations.md)'de.

- **OAuth 2.1 / OIDC sağlayıcısı değildir.** Başka uygulamalara "X ile giriş yap" sunamaz, üçüncü taraf istemci barındıramaz, uygulamalar arası SSO veremez (Faz 2, K-80).
- Kurumsal SSO (org başına OIDC IdP), SCIM 2.0, DPoP, Single Logout, `client_credentials`, device flow, token exchange (Faz 2). SAML 2.0 (Faz 3).
- SDK'lar (TypeScript, iOS, Android), barındırılan giriş arayüzü, yönetim konsolu UI'ı. Sistem API-önceliklidir.
- KMS/HSM anahtar sağlayıcısı (yalnızca ortam/yapılandırma), GeoIP uygulaması, FIDO MDS3.
- Access token için yalnızca EdDSA (RS256/ES256 yok).
- Helm chart / HA referans dağıtımı.

## Hızlı başlangıç

Aşağıdaki adımlar geliştirme ortamı içindir. `config/example.toml` içindeki anahtarlar **herkese açık örnek değerlerdir** ve `production` / `staging` ortamında reddedilir.

### Gereksinimler

- Rust: `rust-toolchain.toml` 1.97 sürümünü sabitler (`rustup` otomatik kurar).
- PostgreSQL 16.
- İsteğe bağlı: Redis 7 (yalnızca `redis` cargo özelliği ve Redis hız sınırı arka ucu için), Mailpit (e-postaları görmek için).

### 1. Bağımlılık servisleri

**Seçenek A: yerel kurulum** (bu depoda doğrulanan yol)

```bash
# Debian/Ubuntu örneği
service postgresql start
su postgres -c "psql -c \"ALTER USER postgres PASSWORD 'postgres';\""
su postgres -c "psql -c 'CREATE DATABASE authn;'"
```

Bağlantı dizesi `config/example.toml`'daki ve `.cargo/config.toml`'daki varsayılanla aynıdır: `postgres://postgres:postgres@localhost:5432/authn`.

**Seçenek B: `docker compose`**

Depodaki [`docker-compose.yml`](docker-compose.yml) yalnızca **bağımlılıkları** başlatır (PostgreSQL 16, Redis 7, Mailpit; portlar yalnızca `127.0.0.1`'e bağlanır). Sunucunun kendisi bu dosyada yoktur.

```bash
docker compose up -d
```

> **Not:** Bu compose dosyası ve `Dockerfile`, proje geliştirilirken ortamda Docker daemon'u olmadığı için **hiç çalıştırılmadı** (K-55). Sorun yaşarsanız Seçenek A'yı kullanın ve sorunu bildirin.

### 2. Derleme, migration ve çalıştırma

```bash
# Yapılandırmayı doğrula (geçersizse çıkış kodu 78)
cargo run -p authn-server -- --config config/example.toml check-config

# Migration'ları uygula
cargo run -p authn-server -- --config config/example.toml migrate

# Sunucuyu başlat (varsayılan 0.0.0.0:8080; metrikler 127.0.0.1:9090)
cargo run -p authn-server -- --config config/example.toml serve
```

İlk derleme uzun sürer (16 crate ve bağımlılıkları). `config/example.toml` `database.migrate_on_start = true` ayarlıdır, yani `serve` bekleyen migration'ları kendisi de uygular.

Başka bir terminalde:

```bash
curl -s http://localhost:8080/health/ready
# {"status":"ready","database":"ok","migrations":"up_to_date"}

curl -s http://localhost:8080/.well-known/jwks.json   # açık imza anahtarları
curl -s http://localhost:8080/openapi.json            # tüm uçların OpenAPI şeması
curl -s http://127.0.0.1:9090/metrics                 # Prometheus metrikleri
```

`/v1/...` uçları `Host` başlığını doğrular: yalnızca `server.public_base_url`'in host'u (örnekte `localhost:8080`) ve `protect.allowed_hosts` kabul edilir, diğerleri `421` alır. Bu yüzden istekleri `http://localhost:8080` üzerinden yapın.

Bu adımlar (check-config, migrate, serve, `/health/ready`, JWKS, OpenAPI, metrikler) 2026-11-05'te yerel PostgreSQL ile çalıştırılarak doğrulandı.

### 3. Sonraki adımlar

- **Yapılandırma:** her ayar [`config/example.toml`](config/example.toml)'da yorumlu olarak durur. Her anahtar ortam değişkeniyle ezilebilir: `AUTHN__<BÖLÜM>__<ANAHTAR>=değer` (ör. `AUTHN__SESSION__ACCESS_TOKEN_TTL=5m`). Ayrıntılı referans: [`docs/operations/`](docs/operations/).
- **Kendi anahtarlarınız:** `crypto.peppers`, `crypto.keks`, `crypto.hmac_root_key` için `openssl rand -base64 32` ile yeni değerler üretin.
- **E-postaları görmek:** Mailpit'i başlattıysanız `config/example.toml`'da `notify.email.smtp.extra_ca_file = "config/dev-certs/mailpit.pem"` satırının yorumunu kaldırın (sunucu TLS'i zorunlu tutar ve sertifikayı doğrular). Mailpit arayüzü: `http://127.0.0.1:8025`. Sertifika yalnızca geliştirme içindir ([`config/dev-certs/README.md`](config/dev-certs/README.md)).
- **İlk admin:** `cargo run -p authn-server -- --config config/example.toml create-admin --email admin@example.com --passkey-link` tek kullanımlık bir passkey kayıt bağlantısı yazdırır (bağlantı yalnızca bir kez gösterilir).
- **Üretim:** `server.environment = "production"` (varsayılan budur) iken `https`, PostgreSQL/Redis hız sınırı arka ucu, four-eyes, oturum kontrolü gibi kurallar zorunludur; aksi hâlde servis açılmaz. En az yetkili veritabanı rolleri: [`docs/operations/least-privilege.md`](docs/operations/least-privilege.md).

## Mimari özet

Bir Cargo workspace'i: **16 crate**, katmanlı ve hexagonal. Dış dünya (e-posta, SMS, CAPTCHA, saat, risk, DNS, HTTP) `authn-core::ports` içindeki trait'lerin arkasındadır. Aynı dalgadaki crate'ler birbirini derleme zamanında görmez; bu kural `authn-testkit/tests/architecture.rs` ile her test koşusunda zorlanır. Ayrıntı: [`docs/architecture/overview.md`](docs/architecture/overview.md), bağlayıcı kurallar: [`docs/architecture/contracts.md`](docs/architecture/contracts.md).

```text
authn-server  (binary: rust-authentication; AppState, router, ara katman, CLI, işler)
   │
   ├── Dalga B:  authn-session · authn-oidc-client · authn-admin
   │
   ├── Dalga A:  authn-password · authn-account · authn-mfa · authn-webauthn
   │             authn-org · authn-protect · authn-audit · authn-notify
   │
   └── Temel:    authn-store → authn-crypto → authn-core      (authn-testkit: yalnızca testler)
```

| Crate | Sorumluluk |
|-------|------------|
| [`authn-core`](crates/authn-core/README.md) | Tipli kimlikler (UUIDv7), hata modeli ve kararlı hata kodları (TR/EN), yapılandırma ve doğrulaması, portlar (trait'ler), istek bağlamı ve istemci IP çözümü, `Principal` |
| [`authn-crypto`](crates/authn-crypto/README.md) | Argon2id + pepper, eski hash göçü, token/OTP, zarf şifreleme, HKDF, EdDSA JWT/JWKS, TOTP, webhook imzası |
| [`authn-store`](crates/authn-store/README.md) | Bağlantı havuzu, gömülü migration'lar, transaction yardımcıları, tek kullanımlık token deposu, imza anahtarı deposu, `users` repository'si |
| [`authn-testkit`](crates/authn-testkit/README.md) | Her port için sahte uygulama, `FakeClock`, HTTP ve zamanlama yardımcıları, mimari bağımlılık testi (yalnızca `dev-dependency`) |
| [`authn-protect`](crates/authn-protect/README.md) | Hız sınırı, giriş koruması ve yumuşak kilit, CAPTCHA, risk değerlendirmesi, güvenlik başlıkları/CORS/Host/yönlendirme doğrulaması, SSRF-güvenli HTTP istemcisi |
| [`authn-audit`](crates/authn-audit/README.md) | Anahtarlı hash zincirli audit log, outbox işçisi, imzalı webhook'lar |
| [`authn-notify`](crates/authn-notify/README.md) | Outbox üzerinden bildirim, TR/EN şablonlar, SMTP, HTTP SMS |
| [`authn-password`](crates/authn-password/README.md) | Şifre politikası, HIBP, değiştirme/ekleme/kaldırma, sıfırlama |
| [`authn-account`](crates/authn-account/README.md) | Kayıt (ADR 0002), e-posta doğrulama, durum makinesi, e-posta değişikliği, silme, dışa aktarma, onaylar |
| [`authn-mfa`](crates/authn-mfa/README.md) | TOTP, kurtarma kodları, e-posta/SMS OTP, MFA politikası, güvenilir cihaz |
| [`authn-webauthn`](crates/authn-webauthn/README.md) | Passkey seremonileri ve yönetimi, mobil ilişkilendirme dosyaları |
| [`authn-org`](crates/authn-org/README.md) | Organizasyonlar, üyelik, RBAC, davetler, domain doğrulama, politikalar, API anahtarları, servis hesapları |
| [`authn-session`](crates/authn-session/README.md) | Giriş akışları, web/native oturumlar, token'lar, step-up, org değiştirme, kimlik doğrulama ara katmanı ve CSRF |
| [`authn-oidc-client`](crates/authn-oidc-client/README.md) | Sosyal giriş (web ve native), kimlik bağlama/ayırma, Apple token iptali |
| [`authn-admin`](crates/authn-admin/README.md) | Admin API, impersonation, break-glass, acil durum işlemleri, four-eyes onayı, audit doğrulama |
| [`authn-server`](crates/authn-server/README.md) | `rust-authentication` binary'si: servis inşası ve kancalar, router ve ara katman yığını, OpenAPI, sağlık uçları, arka plan işleri, CLI |

**İstek yolu (OPS-02, dıştan içe):** istek bağlamı (istek kimliği, istemci IP'si, dil, hata zarfı) → tracing → panik yakalama → zaman aşımı → eşzamanlılık sınırı → gövde sınırı → Host doğrulama → güvenlik başlıkları → admin konsolu CORS'u → CORS → IP başına hız sınırı → kimlik doğrulama + CSRF → handler ([`crates/authn-server/src/app.rs`](crates/authn-server/src/app.rs)).

## Operasyon komutları

Tüm komutlar aynı binary'dedir: `rust-authentication [--config <dosya>] <komut>` (`AUTHN_CONFIG` ortam değişkeni de kabul edilir). Tam liste `--help` ile ve [`crates/authn-server/README.md`](crates/authn-server/README.md)'de.

| Komut | Ne yapar |
|-------|----------|
| `serve` | HTTP sunucusunu ve arka plan işlerini çalıştırır |
| `migrate` | Bekleyen migration'ları uygular |
| `check-config` | Yapılandırmayı, `serve`'ün açılışta reddedeceği her şey dahil doğrular |
| `create-admin --email … [--passkey-link]` | Break-glass platform admini oluşturur |
| `admin-enrollment-link`, `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions`, `grant-admin`, `revoke-admin` | Çevrimdışı admin yönetimi (gerekçe ve operatör zorunlu, audit'li); prosedür: [`docs/operations/admin-recovery.md`](docs/operations/admin-recovery.md) |
| `rotate-signing-key [--emergency]` | JWT imza anahtarı rotasyonu / acil iptal |
| `rotate-kek` (`reencrypt`) | Zarf şifreli tüm değerleri güncel KEK ile yeniden sarar |
| `verify-audit-chain [--anchor <seq>:<hash>]`, `rotate-audit-chain-key` | Audit zinciri doğrulama ve zincir anahtarı rotasyonu |
| `seal-apple-key --pem-file …` | Sign in with Apple özel anahtarını KEK ile mühürler |
| `migrate-legacy-hashes --input …` | Eski MD5/SHA-1 hash'lerini toplu olarak Argon2id ile sarar |

## Geliştirme ve kalite kapıları

Testler gerçek PostgreSQL kullanır; her `#[sqlx::test]` kendi geçici veritabanını oluşturur (`DATABASE_URL`, varsayılanı `.cargo/config.toml`'da; `authn` veritabanı var olmalıdır). Redis testleri Redis yoksa atlanır.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cargo audit
```

Fuzz hedefleri ayrı bir workspace'tedir: `cd fuzz && cargo +nightly fuzz build`. Çalışma kuralları (dil, güvenlik, sahiplik, paralel çalışma) [`CLAUDE.md`](CLAUDE.md) ve [`docs/HANDOFF.md`](docs/HANDOFF.md)'dedir. Kodda `unsafe` yasaktır (`unsafe_code = "forbid"`); üretim kodunda `unwrap`/`expect`/`panic!` clippy ile reddedilir.

## Lisans politikası

**Bağımlılıklar (LIC-01):** yalnızca ticari kullanıma engel olmayan, izin verici lisanslar. `deny.toml` bunu zorlar ve CI'da `cargo deny check` kırmızıysa birleştirme yapılmaz.

- **İzinli:** MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, Unicode-DFS-2016, CC0-1.0, CDLA-Permissive-2.0, 0BSD.
- **Yasak:** GPL, AGPL, LGPL, SSPL, BUSL, ticari ve kaynağı-görünür lisanslar. OpenSSL/`native-tls`/`aws-lc-sys` de `deny.toml`'da yasaktır (TLS yalnızca `rustls` + `ring`).
- **Onaylı istisnalar (crate bazında):**
  - Passkey için `webauthn-rs` ailesi ve zorunlu bağımlılıkları **MPL-2.0** (`webauthn-rs`, `webauthn-rs-core`, `webauthn-rs-proto`, `webauthn-attestation-ca`, `webauthn-authenticator-rs`, `base64urlsafedata`, `crypto-glue`, `compact_jwt`).
  - `libfuzzer-sys` (**NCSA**, BSD benzeri): yalnızca dağıtılmayan `fuzz/` workspace'inde, `fuzz/deny.toml` ile. Kök `deny.toml` bu crate'i ürün workspace'inde açıkça yasaklar; ürün binary'sine giremez.
- **Üçüncü taraf bildirimleri:** [`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt) binary'ye giren her crate'in lisans metnini, telif bildirimlerini ve `NOTICE` dosyalarını içerir; Docker imajına `/usr/share/doc/rust-authentication/` altında kopyalanır. Bağımlılık eklediğinizde veya güncellediğinizde `python3 -I licenses/generate_notices.py` ile yeniden üretip commit edin; CI'daki `licence-notices` işi farkı yakalar. Ayrıntı: [`licenses/README.md`](licenses/README.md).

**Projenin kendi lisansı:** depoda henüz bir `LICENSE` dosyası ve `Cargo.toml`'da `license` alanı **yoktur**; bu proje sahibinin kararıdır.

## Belgeler

| Belge | İçerik |
|-------|--------|
| [`docs/spec/requirements.md`](docs/spec/requirements.md) | Bağlayıcı spesifikasyon (gereksinim kimlikleri) |
| [`docs/architecture/overview.md`](docs/architecture/overview.md), [`contracts.md`](docs/architecture/contracts.md), [`adr/`](docs/architecture/adr/) | Mimari, modül sözleşmeleri, mimari karar kayıtları |
| [`docs/security/`](docs/security/) | [Tehdit modeli](docs/security/threat-model.md), [ASVS eşlemesi](docs/security/asvs-mapping.md), [kriptografi](docs/security/cryptography.md), [bilinen sınırlamalar](docs/security/known-limitations.md), [K-57 denetimi](docs/security/k57-global-audit.md) |
| [`SECURITY.md`](SECURITY.md) | Güvenlik açığı bildirimi |
| [`docs/api/`](docs/api/) | API referansı ve OpenAPI belgesi (DOC-04) |
| [`docs/integration/`](docs/integration/) | Web, iOS, Android, kaynak sunucusu, B2B ve webhook entegrasyon rehberleri (DOC-05) |
| [`docs/operations/`](docs/operations/) | Yapılandırma, en az yetki, admin kurtarma, performans ve runbook'lar (DOC-06) |
| [`docs/compliance/kvkk-gdpr.md`](docs/compliance/kvkk-gdpr.md) | KVKK/GDPR veri envanteri, saklama, silme ve dışa aktarma, NIST 800-63B notları |
| [`docs/roadmap.md`](docs/roadmap.md) | Özellik karşılaştırması, Faz 2/3 yol haritası |
| [`docs/api-changelog.md`](docs/api-changelog.md) | İstemcileri etkileyen API değişiklikleri |
| [`docs/HANDOFF.md`](docs/HANDOFF.md), [`docs/handoff/`](docs/handoff/) | Projeyi devralanlar için durum, kalan işler, modül API'leri |
| `crates/*/README.md` | Her crate'in sorumluluğu, API'si, yapılandırması ve güvenlik notları |
