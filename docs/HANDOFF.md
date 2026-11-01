# Devir belgesi — rust-authentication

> **Bu belgeyi başka bir LLM'e / geliştiriciye devretmek için yazdım. "Sen" diye hitap ediyorsam bu işi devralan sensin.**
> Önce bu dosyayı baştan sona oku, sonra [`docs/handoff/remaining-work.md`](handoff/remaining-work.md) (kalan işlerin ayrıntılı tarifi) ve [`CLAUDE.md`](../CLAUDE.md) (değişmez kurallar) dosyalarına geç.
> Bu dosya yazıldığı andaki durum: `main` dalı, son kod commit'i `4aa87d7`, CI yeşil.

---

## 1. Tek paragrafta proje

Rust ile yazılmış, **ticari lisans gerektirmeyen** (yalnızca izin verici açık kaynak lisanslı) bir **kimlik doğrulama sistemi**. Üç tür istemciye hizmet edecek: **B2C web**, **B2B SaaS** (organizasyonlar, roller, davetler, API anahtarları) ve **mobil uygulamalar** (native token akışı + passkey). Kullanıcı (proje sahibi) bunu daha sonra kendi ürünlerinde **taslak/şablon olarak** kullanacak; bu yüzden eksiksiz, test edilmiş, belgeli ve "güvenlik takıntılı" kalitede olması istendi. Bir Cargo workspace'i: 16 crate, tek bir binary (`rust-authentication`), PostgreSQL 16 zorunlu, Redis opsiyonel.

Depo: `github.com/Okan-wqm/draft-rust` (dal: `main`). Proje sahibi ileride adını `rust-authentication` yapmak istiyor; depo adını değiştirmek onun kararı, sen değiştirme.

## 2. Önce bu üç şeyi yap

1. **Ortamı ayağa kaldır** (§4) ve şunun yeşil çıktığını gör: `cargo test --workspace --all-features` (bu belgenin yazıldığı an: **1181 geçti, 0 başarısız, 8 ignored** — ignored olanlar `ignore` işaretli doc-test örnekleri).
2. [`docs/handoff/remaining-work.md`](handoff/remaining-work.md)'yi oku. Kalan işin sırası: **login akışları → (sosyal giriş ∥ admin) → sunucu entegrasyonu + uçtan uca testler → genel güvenlik denetimi → QA sertleştirme → dokümantasyon.**
3. Kod yazmaya başlamadan [`docs/architecture/contracts.md`](architecture/contracts.md)'yi oku — özellikle §3 (dosya sahipliği), §4 (portlar), §11 (güvenlik kuralları), §15 (sunucu bağlama tablosu). Mimari kararlar orada; onlara uymadan yazılan kod entegrasyonda kırılır.

## 3. Mevcut durum

### 3.1 Genel resim

Spesifikasyonda (`docs/spec/requirements.md`) 175 gereksinim kimliği var (ör. `PWD-07`, `SES-01`). Her biri `contracts.md` §1'deki tabloda **tam bir crate'e** atanmış.

| Durum | Gereksinim sayısı (yaklaşık) |
|-------|-----------------------------|
| Yazıldı, test edildi, denetlendi, GitHub'da | ~128 |
| Kalan | ~47 (çoğu login akışları, sosyal giriş, admin, sunucu entegrasyonu, dokümantasyon) |

Sayıya göre ~%73, efora göre ~%65 bitti: kalan iş (entegrasyon, uçtan uca testler, genel denetim) sayıdan daha ağır.

### 3.2 Crate'ler

| Crate | Durum | Not |
|-------|-------|-----|
| `authn-core` | ✅ bitti | Tipli ID'ler, hata modeli (TR/EN), konfigürasyon, 17 port, `RequestContext`/IP çözümü, `Principal`. (~13K satır) |
| `authn-crypto` | ✅ bitti | Argon2id+pepper, eski hash göçü, token/OTP, zarf şifreleme, TOTP, EdDSA JWT/JWKS, HKDF, Standard Webhooks imzası. Fuzz hedefleri var. |
| `authn-store` | ✅ bitti | Pool, migration'lar, tek kullanımlık token deposu (atomik tüketim), imza anahtarı deposu, `UserRepository`. |
| `authn-testkit` | ✅ bitti | Her port için sahte, `FakeClock`, HTTP/zamanlama yardımcıları, mimari bağımlılık testi. |
| `authn-protect` | ✅ bitti | Rate limit (Postgres/Redis/bellek), CAPTCHA (Turnstile/hCaptcha/PoW), yumuşak kilit, risk, güvenlik başlıkları/CORS/host/redirect, SSRF-güvenli `HttpClient`. |
| `authn-audit` | ✅ bitti | Hash zincirli audit log, outbox işçisi, imzalı webhook'lar. |
| `authn-notify` | ✅ bitti | Outbox bildirimci, TR/EN şablonlar, SMTP (TLS zorunlu), HTTP SMS. |
| `authn-password` | ✅ bitti | Politika, HIBP, değiştirme/ekleme/kaldırma, sıfırlama. |
| `authn-account` | ✅ bitti | Kayıt (pre-hijacking'e karşı yeniden tasarlandı, ADR 0002), doğrulama, durum makinesi, e-posta değişikliği, silme, dışa aktarma, onaylar. |
| `authn-mfa` | ✅ bitti | TOTP, kurtarma kodları, e-posta/SMS OTP, MFA politikası, güvenilir cihaz. |
| `authn-webauthn` | ✅ bitti | Passkey seremonileri, yönetim, mobil ilişkilendirme dosyaları. |
| `authn-org` | ✅ bitti | Organizasyon, üyelik, RBAC, davet, domain doğrulama, politika, API anahtarı, servis hesabı. |
| `authn-session` | 🟡 **yarım** | **Çekirdek bitti** (SES-03…17: oturumlar, CSRF, token rotasyonu, JWKS, introspection, middleware, step-up, org değiştirme, `SessionRevoker`/`SessionIssuer`). **`src/login/` yok**: SES-01, 02, 18, 19, 20, 21, 22 yazılmadı. |
| `authn-oidc-client` | 🔴 iskelet | Boş (14 satır). SOC-01…09 yazılacak. |
| `authn-admin` | 🔴 iskelet | Boş (14 satır). ADM-01…08 yazılacak. |
| `authn-server` | 🟠 iskelet | Yalnızca sağlık uçları, örnek route, CLI iskeleti, katman yığını. Hiçbir modül bağlı değil. OPS-*, DOC-01/04/06, TST-02/06 bu crate'in. |

### 3.3 Doğrulama sonuçları (yazıldığı an)

- `cargo fmt --all -- --check` ✅, `cargo clippy --workspace --all-targets --all-features -- -D warnings` ✅, `cargo test --workspace --all-features` ✅ (1181), `cargo deny check` ✅ (advisories/bans/licenses/sources), `cargo audit` ✅.
- GitHub Actions: son 4 commit yeşil (https://github.com/Okan-wqm/draft-rust/actions).
- Fuzz: 13 hedef derleniyor; kısa süreli (30 sn–2 dk) koşturuldu, çökme yok (bir bulgu düzeltildi: RP id `0x`).
- **Henüz hiç koşulmadı:** uçtan uca testler (modüller henüz birbirine bağlı değil), Mailpit ile gerçek SMTP (ortamda Docker daemon yoktu), `cargo llvm-cov` kapsam raporunun tamamı (CI'da çalışır ama yerelde tamamlanmadı), uzun fuzz koşuları.

### 3.4 Bulunan ve kapatılan güvenlik sorunları (bilgi için)

Her modülü yazan uzmandan **bağımsız** bir denetçi agent inceledi. Toplam **2 yüksek, 15 orta, 25 düşük** önemde gerçek açık bulundu; hepsi, düzeltme olmadan başarısız olan bir regresyon testiyle kapatıldı. Öne çıkanlar:

- **Yüksek:** eşzamanlı giriş denemeleriyle CAPTCHA/kilit eşiğinin aşılması (check-then-act yarışı); hesap ön-ele-geçirme (pre-hijacking) — saldırgan, kurbanın e-postasıyla önce kayıt olup kurban doğrulayınca kendi şifresiyle aktif hesap elde edebiliyordu (ADR 0002 ile baştan tasarlandı).
- **Orta (örnekler):** sosyal/şifre girişinin "MFA yaptım" iddiasını sorgusuz kabul etmesi; admin askıya alınınca impersonation oturumlarının 60 dk daha çalışması; step-up'ın yalnızca aktif organizasyonun politikasına bakması; şifre sıfırlamadan sonra eski şifreyle başlamış girişlerin tamamlanabilmesi.

**Ders:** hatalar neredeyse hep **modüller arası yanlış kullanımda** çıkıyor (doğru API'yi yanlış sırayla / yanlış varsayımla çağırmak). Bu yüzden entegrasyon ve genel denetim aşamaları kritik; atlama.

## 4. Ortamı ayağa kaldırma

Gereksinimler: Rust (repo `rust-toolchain.toml` ile 1.97'yi sabitler), PostgreSQL 16, (opsiyonel) Redis 7, (araçlar) cargo-deny, cargo-audit, cargo-llvm-cov, nightly + cargo-fuzz.

```bash
# PostgreSQL (Debian/Ubuntu): başlat, şifreyi ayarla, test veritabanını oluştur
service postgresql start
su postgres -c "psql -c \"ALTER USER postgres PASSWORD 'postgres';\""
su postgres -c "psql -c 'CREATE DATABASE authn;'"

# Redis (yalnızca Redis arka ucu testleri için; yoksa o testler atlanır)
service redis-server start
```

`DATABASE_URL` varsayılanı `.cargo/config.toml` içinde: `postgres://postgres:postgres@localhost:5432/authn`. Her `#[sqlx::test]` bu sunucuda kendi geçici veritabanını yaratır; `authn` veritabanının **var olması** gerekir. Alternatif: `docker compose up -d` (PostgreSQL 16, Redis 7, Mailpit).

```bash
# Araçlar (bir kere)
cargo install --locked cargo-deny cargo-audit cargo-llvm-cov
rustup toolchain install nightly --profile minimal
cargo +nightly install --locked cargo-fuzz
```

Kalite kapıları (hepsi geçmeden commit yok):

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cargo audit
```

Fuzz: `cd fuzz && cargo +nightly fuzz build` (ayrı workspace; hedef listesi `fuzz/Cargo.toml`'da). **Fuzz çıktı klasörleri (`fuzz/target` ~1,5 GB) işin sonunda silinmeli.**

### Disk tuzağı

Çalışma sırasında `target/` 21 GB'a çıktı ve disk doldu (testler "no space left" ile rastgele kırıldı). Önlemler: dev profilde `incremental = false` ayarlı, **ek `--target-dir` açma**, `--all-features` ile tutarlı çalış (artefakt paylaşılsın), gerekirse `cargo clean`. Disk dolduğunda Postgres testleri tuhaf hatalarla düşer — önce `df -h` bak.

## 5. Çalışma kuralları (özet; asıl kaynak `CLAUDE.md`)

- **Dil:** kod, tanımlayıcı, kod yorumu, commit mesajı, API hata kodu **İngilizce**; tüm Markdown dokümantasyon **Türkçe**.
- **Lisans (LIC-01):** yalnızca MIT, Apache-2.0, BSD-2/3, ISC, Zlib, Unicode, CC0, CDLA-Permissive-2.0, 0BSD. GPL/AGPL/LGPL/SSPL/BUSL/ticari **yasak**. Tek istisna `webauthn-rs` ailesi (MPL-2.0, passkey için; `deny.toml`'da crate bazında). Yeni bağımlılık eklemeden önce lisansını ve **geçişli bağımlılıklarını** kontrol et; `cargo deny check` geçmeli. Kullanıcının sözü: "ticari kullanıma engel olmayan kütüphaneleri kullan, başkasının lisanslı (ticari) şeylerini kullanmayalım."
- **Güvenlik:** `unsafe` yasak; production kodunda `unwrap/expect/panic!/todo!/unimplemented!/dbg!` yok (clippy `deny`; testlerde serbest); sırlar `SecretString`/`Zeroizing` içinde ve `Debug`'da görünmez; sabit zamanlı karşılaştırma; yalnızca CSPRNG; kendi kriptografini yazma; hesap varlığı yanıt gövdesinden, durum kodundan **ve süreden** anlaşılmamalı.
- **Test:** her gereksinim kimliğinin en az bir testi olmalı ve **test adı kimliği içermeli** (`pwd_07_reset_token_is_single_use`). Veritabanı testleri gerçek PostgreSQL'e karşı (`#[sqlx::test]`), mock yok.
- **Sahiplik:** bir crate'in dosyalarını yalnızca o crate'in sahibi değiştirir (`contracts.md` §3). Başka sahibin dosyasında değişiklik gerekirse `docs/architecture/contract-change-requests.md`'ye **kendi başlığın altına** talep yaz (§13). Aynı dalgadaki crate'ler birbirine bağımlı olamaz; `authn-testkit/tests/architecture.rs` bunu her testte zorlar.
- **Her özellik test edildikten sonra, ayrı ve ayrıntılı bir commit'le GitHub'a push edilir** (kullanıcının açık isteği). Commit mesajı: İlk satır `feat(<modül>): <özet>`; gövdede `Implemented:` (gereksinim kimlikleriyle), `Security review:` (bulunan/düzeltilen açıklar), `Tests:` (sayı + önemli güvenlik testleri), `Wiring needed:` (server'ın bağlayacağı şeyler). Sonuna, çalıştığın ortamın zorunlu kıldığı atıf satırlarını ekle (önceki commit'lerde `Co-Authored-By` + `Claude-Session` satırları vardı).
- **Commit yalnızca kendi yollarını içersin** (`git commit -F msg -- <yollar>`); başka birinin yarım işini sürükleme.
- **Test edilmemiş / kapıları geçmemiş kodu push etme.**

### Paralel çalışma kuralları (birden fazla agent aynı ağaçta çalışacaksa)

- **Asla `cargo fmt --all` / `cargo clippy --workspace`** çalıştırma; yalnızca `cargo fmt -p <crate>`, `cargo clippy -p <crate> --all-targets --all-features -- -D warnings`, `cargo test -p <crate> --all-features`.
- "Blocking waiting for file lock" normaldir, bekle.
- Aynı anda en fazla ~2 ağır agent mantıklı: derleme ve Postgres kaynak çekiyor, disk de sınırlı.

## 6. Bu projede işe yarayan çalışma deseni

Her modül için **iki aşama, iki ayrı agent**:

1. **Uzman (yazar):** modülün gereksinimlerini uygular, testleri yazar, README'yi (Türkçe) yazar. Commit **etmez**.
2. **Bağımsız denetçi (saldırgan gözü):** kodu yazmamış biri, "bu kod zafiyetli, kanıtla" varsayımıyla inceler; doğrulanmış her bulguyu önce **düzeltme olmadan başarısız olan bir regresyon testiyle** kanıtlar, sonra düzeltir; kabul edilen riskleri README'deki "Güvenlik notları"na gerekçesiyle yazar; Definition of Done denetimi yapar (her gereksinim kimliği bir test adında geçiyor mu, `unwrap` var mı, rustdoc, README); kapılar geçerse **kendisi** commit + push eder.

Denetçinin baktığı sınıflar: hesap varlığı sızıntısı (gövde/durum/süre), token/OTP tekrar kullanımı, yarışlar/TOCTOU, atlatılabilir rate limit, yetkilendirme açıkları, IDOR/kiracılar arası erişim, step-up atlatma, ayrıcalık yükseltme, loglarda/Debug'da/audit'te sır, sabit zamanlı olmayan karşılaştırma, zayıf rastgelelik, kriptografi yanlış kullanımı (AAD eksik, yanlış anahtar amacı), SQL'in string'den kurulması, SSRF, open redirect, başlık/CRLF enjeksiyonu, Unicode/normalizasyon hileleri, sınırsız girdi ve kimlik doğrulama öncesi pahalı iş (DoS), panikler, yanlış transaction sınırı, enjekte edilmeyen saat, hata ayrıntısı sızıntısı.

## 7. Bilinen tuzaklar (yaşanmış)

- **sqlx 0.9:** SQL metinleri `&'static str` olmalı; dinamik SQL derleme hatası. Değerler daima bind parametresi. Derleme zamanı `query!` makroları kullanılmıyor.
- **reqwest 0.13** `rustls-no-provider` ile derleniyor: bir istemci kurmadan önce `authn_core::tls::install_crypto_provider()` çağrılmazsa **panikler**. Sunucu CLI'ı bunu yapıyor; yeni bir giriş noktası/test yazarsan sen de çağır.
- **`jsonwebtoken` kullanılmıyor** (savunmasız eski RSA/EC crate'lerini çekiyor); JWT kendi küçük, sabit algoritmalı (EdDSA) uygulamamız — bkz. `docs/architecture/adr/0001-jwt-implementation.md`.
- **`redis-rs` yerine `fred`** (redis-rs, BSL-1.0 lisanslı `xxhash-rust` çekiyor). `openidconnect`/`oauth2` varsayılan özellikleri kapalı; HTTP'leri bizim SSRF-güvenli istemcimizden geçmeli.
- **Bilinçle yok sayılan iki RustSec uyarısı** (`RUSTSEC-2023-0071` rsa, `RUSTSEC-2026-0387` crypto-bigint 0.5): yalnızca `openidconnect` içinde **açık anahtarla** imza doğrulamasında kullanılıyor. Kural: gizli anahtarlı her EC işlemi (ör. Apple `client_secret`) yalnızca `p256 0.14` ile yapılmalı. Gerekçe `deny.toml` ve `.cargo/audit.toml`'da.
- **`libfuzzer-sys` NCSA lisanslı** (permissive ama LIC-01 listesinde yok): yalnızca ayrı `fuzz/` workspace'inde, `fuzz/deny.toml` ile o crate için izinli, ürün binary'sine girmiyor. Proje sahibinin bu istisnayı onaylaması beklenen bir konu.
- **`config/dev-certs/mailpit.key` depoda:** yalnızca geliştirme için üretilmiş, Mailpit'in sabit sertifikası. Üretim yapılandırması bunu kabul etmez. `config/dev-certs/README.md`'ye bak.
- **Yarış testlerinde bağlantı havuzu:** bir sorgu hata verirse bağlantı havuza "iptal edilmiş transaction" durumunda dönebilir. Beklenen hata veren sorguları açık transaction içinde çalıştırıp `rollback` et (bir CI hatası böyle çıktı).
- **Zamanlama testleri** (hesap varlığı sızıntısı) yüzdelik toleransla çalışır; çok gürültülü CI makinelerinde nadiren dalgalanabilir. Dalgalanırsa toleransı değil, testin ölçüm yöntemini (örnek sayısı, medyan) gözden geçir.
- **Clippy ve test modülleri:** testler bir varsayılan yapının tek alanını değiştiriyorsa `#[allow(clippy::field_reassign_with_default)]` gerekebilir (test modülüne uygulandı).
- **Eşzamanlı agent'ların `Cargo.lock`/`fuzz/Cargo.lock` değişiklikleri:** birleştirme çakışırsa elle düzenleme; `cargo update --workspace` ile yeniden üret.
- Kullanıcının e-posta adresi dahil hiçbir kişisel veriyi üçüncü taraf servislere (ör. crates.io User-Agent) gönderme. (Bir kez yanlışlıkla bir sürüm sorgusunda gönderildi; tekrarlanmasın.)

## 8. Belge haritası

| Dosya | Ne için |
|-------|---------|
| `CLAUDE.md` | Değişmez kurallar (lisans, güvenlik, kapılar). Yeni LLM oturumları otomatik okur. |
| `docs/spec/requirements.md` | **Bağlayıcı spesifikasyon**, 175 gereksinim kimliği. |
| `docs/architecture/contracts.md` | Sahiplik, bağımlılık grafiği, portlar, tablolar, migration aralıkları, router deseni, hata/konfigürasyon/test kuralları, **§15 sunucu bağlama tablosu**. |
| `docs/architecture/overview.md` | Mermaid diyagramları (bağımlılık, istek akışı, veri modeli). |
| `docs/architecture/contract-change-requests.md` | Modüllerin açtığı sözleşme değişikliği talepleri ve durumları. Açık olanlar için bkz. `remaining-work.md` §9. |
| `docs/architecture/adr/` | 0001 JWT uygulaması, 0002 kayıt akışı / pre-hijacking. |
| `docs/compliance/kvkk-gdpr.md` | Veri envanteri (her tablo), saklama süreleri, silme/dışa aktarma. Bir test, her tablonun burada geçmesini zorlar (`doc_07_…`). |
| `docs/handoff/remaining-work.md` | **Kalan işlerin ayrıntılı tarifi** (her görev için kapsam, kurallar, test listesi). |
| `docs/handoff/module-apis.md` | Biten modüllerin genel API'si, sunucunun bağlaması gerekenler, kabul edilen riskler (agent raporlarından). |
| `crates/*/README.md` | Her crate'in sorumluluğu, API'si, endpoint'leri, konfigürasyonu, "Güvenlik notları", "server'ın bağlaması gerekenler". |
| `config/example.toml` | Tüm ayarların yorumlu örneği (bir test geçerliliğini zorlar). |

## 9. Kullanıcıyla ilgili bilinmesi gerekenler

- Kullanıcı Türkçe konuşuyor; kısa, doğrudan ilerleme raporu bekliyor. İlerlemeyi "yüzde kaç bitti, ne kaldı" gibi sorarak takip ediyor — dürüst ol, bitmemiş şeyi bitmiş gösterme.
- İsteği: "profesyonel kalite, güvenlik takıntılı, her özellik test edilsin, dokümantasyon eksiksiz, her bölüm için uzman agent". Faz 1 bu repoda; Faz 2/3 (OAuth 2.1/OIDC **sağlayıcısı**, kurumsal SSO, SCIM, DPoP, Single Logout, SAML) ayrı bir iş olarak planlandı (`docs/roadmap.md`, DOC-09 yazılacak).
- Üretime çıkmadan önce **bağımsız bir dış güvenlik denetimi (pentest)** önerildi ve bu repo bunun yerine geçmez.
