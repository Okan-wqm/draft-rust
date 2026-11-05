# rust-authentication — Gereksinim Belgesi (Faz 1)

Bu belge tüm geliştirme agent'larının ve geliştiricilerin bağlayıcı sözleşmesidir. Her gereksinimin kalıcı bir kimliği vardır; kod, test adları, dokümantasyon ve OWASP ASVS eşleme tablosu bu kimliklere atıf yapar.

"MUST" = zorunlu, "SHOULD" = güçlü öneri (uygulanmazsa gerekçesi modül README'sinde yazılır), "MAY" = opsiyonel.

---

## 0. Kapsam

**Faz 1 (bu sürüm):** Kayıt ve hesap yaşam döngüsü, şifre yönetimi, oturum ve token yönetimi, MFA (TOTP, passkey, kurtarma kodu, e-posta/SMS OTP), şifresiz giriş, sosyal giriş (OIDC istemcisi), organizasyonlar (B2B temeli), RBAC, API anahtarları, kötüye kullanım koruması, risk tabanlı doğrulama, audit log, webhook'lar, bildirimler, admin API, anahtar yönetimi, gözlemlenebilirlik.

**Faz 2 (sonra, ama mimari şimdiden hazır olmalı):** OAuth 2.1 / OIDC sağlayıcısı (Authorization Code + PKCE, RFC 8252, device flow), kurumsal SSO (organizasyon başına OIDC IdP), SCIM 2.0, DPoP (RFC 9449), Single Logout.
**Faz 3:** SAML 2.0.

Mimari, Faz 2/3 eklenirken mevcut modüllerin yeniden yazılmasını gerektirmemeli: kimlik sağlayıcıları (`identities` tablosu), oturum/AMR modeli, imza anahtarı/JWKS altyapısı ve organizasyon politikaları bu genişlemeyi taşıyacak şekilde tasarlanır.

**Hedef istemciler:**
- Web (B2C ve B2B SaaS): cookie tabanlı oturum (aynı site veya BFF deseni).
- Mobil (iOS/Android native): bearer access token + rotasyonlu refresh token.
- Kaynak sunucuları (sizin diğer servisleriniz): JWKS ile çevrimdışı JWT doğrulama veya introspection.
- Makineler: API anahtarları ve servis hesapları.

---

## 1. Teknoloji ve lisans

- Rust edition 2024, stable toolchain (`rust-toolchain.toml`).
- Çalışma zamanı ve HTTP: `tokio`, `axum` (0.8), `tower`, `tower-http`.
- Veritabanı: PostgreSQL 16+ (zorunlu), `sqlx` (postgres, runtime-tokio, rustls). Redis (opsiyonel, rate limit arka ucu).
- Kriptografi (RustCrypto ve muadilleri): `argon2`, `hmac`, `sha2`, `sha1` (yalnızca TOTP/HIBP uyumluluğu), `chacha20poly1305` veya `aes-gcm`, `ed25519-dalek`, `p256` (Apple client secret), `subtle`, `zeroize`, `secrecy`, `rand`/`getrandom`, `base64`, `data-encoding`.
- JWT: `jsonwebtoken` (EdDSA, `rust_crypto` backend) veya `ed25519-dalek` üzerine minimal, algoritması sabit JWS uygulaması.
- Passkey: `webauthn-rs` (MPL-2.0 — tek onaylı istisna; `passkey` cargo feature'ı arkasında, varsayılan açık).
- HTTP istemcisi: `reqwest` (rustls). OIDC: `openidconnect`/`oauth2` (MIT/Apache).
- E-posta: `lettre` (rustls). Şablon: `minijinja`.
- Diğer: `serde`, `serde_json`, `thiserror`, `uuid` (v7), `time`, `tracing`, `tracing-subscriber`, `metrics` + `metrics-exporter-prometheus`, `utoipa` (OpenAPI), `figment` (konfigürasyon), `zxcvbn`, `unicode-normalization`, `unicode-security`, `hickory-resolver` (DNS TXT), `qrcode` (TOTP QR), `governor` (bellek içi rate limit).
- Test: `proptest`, `wiremock`, `tokio::test`, `#[sqlx::test]`, `cargo-fuzz`.

**Lisans politikası (LIC-01, MUST):** Yalnızca ticari kullanıma engel olmayan açık kaynak lisanslar. İzinli: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, Unicode-DFS-2016, CC0-1.0, CDLA-Permissive-2.0, 0BSD, OpenSSL (yalnızca `openssl` bağımlılığı gerekiyorsa). MPL-2.0 yalnızca `webauthn-rs` ailesi ve onun zorunlu bağımlılıkları için crate bazında istisna. GPL, AGPL, LGPL, SSPL, BUSL, ticari ve kaynağı-görünür (source-available) lisanslar yasak. `deny.toml` bunu zorlar; CI'da `cargo deny check` kırmızıysa merge yok.

---

## 2. Mimari kurallar

- **ARC-01** Cargo workspace; her modül ayrı crate (`crates/authn-*`). Çekirdek crate'ler IO bağımsız ve test edilebilir.
- **ARC-02** Hexagonal yapı: dış dünya (e-posta, SMS, CAPTCHA, saat, risk, DNS, HTTP) `authn-core` içindeki trait'ler (port) arkasında. Testlerde sahte (fake) uygulamalar `authn-testkit` içinde.
- **ARC-03** Her modül crate'i kendi HTTP handler'larını `pub fn router<S>() -> axum::Router<S>` olarak dışa açar; ihtiyaç duyduğu servisleri `FromRef<S>` ile alır. Uygulama durumu (`AppState`) yalnızca `authn-server` içinde tanımlanır.
- **ARC-04** Saat (`Clock`) enjekte edilir; hiçbir iş mantığı doğrudan `OffsetDateTime::now_utc()` çağırmaz (testlerde zamanı ilerletmek için).
- **ARC-05** Tüm kimlikler UUIDv7. Dışa açılan ID'ler tahmin edilemez; sıralı tamsayı ID dışa açılmaz.
- **ARC-06** Tüm durum değiştiren işlemler veritabanı transaction'ı içinde; tek kullanımlık token'lar atomik olarak tüketilir (`UPDATE ... WHERE consumed_at IS NULL AND expires_at > now() RETURNING`).
- **ARC-07** Konfigürasyon: dosya (TOML) + ortam değişkenleri (`AUTHN__` öneki), `figment` ile. Tüm süreler, limitler ve politikalar konfigüre edilebilir; varsayılanlar bu belgedeki değerlerdir. Geçersiz konfigürasyonda servis açılmaz (fail-fast).
- **ARC-08** Hata modeli: `authn-core::error::AuthError`; her varyantın kararlı bir `code` (snake_case), HTTP durumu ve TR/EN mesajı vardır. Yanıt zarfı:
  `{"error": {"code": "invalid_credentials", "message": "...", "request_id": "..."}}`. İç hata detayları yalnızca loglarda.
- **ARC-09** API sürümlü: `/v1/...`. JSON, `snake_case` alanlar. Tüm endpoint'ler OpenAPI (`utoipa`) ile belgelenir.
- **ARC-10** Çok kiracılılık (tenant izolasyonu): organizasyon kapsamlı her sorgu `org_id` filtresi içerir; organizasyonlar arası veri sızıntısını önleyen testler zorunlu.
- **ARC-11** Cargo feature'ları: `passkey` (varsayılan açık), `redis` (opsiyonel), `sms` (varsayılan açık, sağlayıcı konfigüre edilmezse kapalı davranır).
- **ARC-12** Uzun süren / kriptografik ağır işler (`argon2`) `spawn_blocking` ile ve eşzamanlılık sınırı (semafor) altında çalışır.

---

## 3. Kriptografi ve anahtar yönetimi (`authn-crypto`)

- **CRY-01** Şifre hash: Argon2id, varsayılan m=19456 KiB, t=2, p=1 (OWASP); konfigüre edilebilir. PHC string formatında saklanır.
- **CRY-02** Pepper: Şifre Argon2'ye girmeden önce HMAC-SHA256(pepper, şifre) uygulanır. Pepper anahtarı versiyonludur (`pepper_version` hash ile birlikte saklanır), birden fazla aktif sürüm desteklenir, rotasyon sonrası kullanıcı giriş yaptıkça yeni sürüme geçilir. Pepper opsiyonel değil, konfigürasyonda zorunlu.
- **CRY-03** Rehash: Argon2 parametreleri veya pepper sürümü güncel değilse başarılı doğrulamadan sonra şifre yeniden hash'lenir.
- **CRY-04** Eski hash göçü: `bcrypt`, `pbkdf2-sha256`, `md5`/`sha1` (sarmalanmış: `argon2(legacy_hash(şifre))`) formatları doğrulanabilir; başarılı girişte düz Argon2id'ye çevrilir. Göç aracı (CLI) eski hash'leri toplu sarmalar.
- **CRY-05** Sahte doğrulama: kullanıcı yoksa önceden hesaplanmış sahte bir hash'e karşı doğrulama yapılır (zamanlama eşitliği).
- **CRY-06** Token üretimi: en az 256 bit entropi, URL-safe base64 (padding yok). Veritabanında yalnızca SHA-256 hash'i saklanır; karşılaştırma sabit zamanlı.
- **CRY-07** Kısa kodlar (OTP): 6 hane, CSPRNG ile tekdüze (modulo bias yok); HMAC-SHA256(server_key, kod) olarak saklanır; deneme sayısı sınırlı.
- **CRY-08** Zarf şifreleme: Veri anahtarları (DEK) bir ana anahtarla (KEK) şifrelenir. AEAD: XChaCha20-Poly1305 (veya AES-256-GCM). Şifreli veriler `key_id` + nonce + ciphertext formatında, ilişkili veri (AAD) olarak tablo/kolon/satır kimliği kullanılır (kopyala-yapıştır saldırısını önler). KEK kaynağı `KeyProvider` trait'i: ortam değişkeni (base64, 32 byte, birden fazla sürüm) varsayılan; KMS için genişletilebilir.
- **CRY-09** JWT imzalama: EdDSA (Ed25519). Header'da `kid`, `typ: at+jwt` (RFC 9068). Doğrulamada algoritma sabittir (`alg` header'ına güvenilmez), `none` ve simetrik algoritmalar reddedilir. `iss`, `aud`, `exp`, `nbf`, `iat` doğrulanır; saat kayması toleransı varsayılan 30 sn.
- **CRY-10** İmza anahtarı rotasyonu: anahtarlar DB'de zarf şifreli saklanır; durumları `pending` → `active` → `retired` → `revoked`. Yeni anahtar en az bir JWKS önbellek süresi boyunca `pending` olarak JWKS'te yayınlanır, sonra aktif olur; emekli anahtar en uzun token ömrü boyunca JWKS'te kalır. Acil durumda (`revoked`) anında kaldırılır.
- **CRY-11** HMAC yardımcıları ve anahtar ayrımı: sunucunun kendi MAC'lediği her amaç (CSRF token'ları, güvenilir cihaz token'ları, OTP ve kurtarma kodu hash'leri, PoW CAPTCHA, kişisel veri içeren rate limit anahtarları, bilinen cihaz hash'leri, audit zinciri) tek kök sırdan HKDF ile türetilmiş, amaca özel ayrı `info` etiketli bir alt anahtar kullanır; etiketler sabittir ve yeniden kullanılmaz. Webhook imzaları (AUD-07) bu hiyerarşiden türetilmez: her uç noktanın imza sırrı CSPRNG ile üretilir, aboneye bir kez gösterilir ve zarf şifrelemeyle (CRY-08) saklanır; böylece bir sırrın sızması ya da rotasyonu kök anahtara ve diğer uç noktalara dokunmaz.
- **CRY-12** Sabit zamanlı karşılaştırma tüm sır karşılaştırmalarında (`subtle::ConstantTimeEq`).
- **CRY-13** Bellekteki sırlar `Zeroizing`/`SecretBox` içinde; `Debug`/`Display` uygulamaları redakte eder.
- **CRY-14** Tüm kriptografik fonksiyonlar bilinen test vektörleriyle (RFC 6238, RFC 4231, RFC 8032, Argon2 referans vektörleri) test edilir; ayrıştırıcılar fuzz edilir.

---

## 4. Kayıt ve hesap yaşam döngüsü (`authn-account`)

- **ACC-01** E-posta + şifre ile kayıt. Şifre politikası `PasswordValidator` portu ile doğrulanır.
- **ACC-02** Hesap varlığını sızdırmayan kayıt: e-posta zaten kayıtlıysa yanıt başarılı kayıtla aynıdır (aynı durum kodu, gövde, benzer süre); mevcut hesap sahibine "biri bu e-postayla kayıt olmaya çalıştı" e-postası gider.
- **ACC-03** E-posta normalizasyonu: Unicode NFKC, baştaki/sondaki boşluk temizliği, domain IDNA'ya (punycode) çevrilip küçük harf; benzersizlik için ayrıca tamamen küçük harfli `email_normalized` kolonu. Geçersiz e-posta biçimleri reddedilir. Görünen ad (display name) için karıştırılabilir karakter (confusable/mixed-script) kontrolü (`unicode-security`).
- **ACC-04** E-posta doğrulama: hem link (token, varsayılan 24 saat) hem 6 haneli kod (varsayılan 15 dk, 5 deneme). Tek kullanımlık. Tekrar gönderme bekleme süresi (varsayılan 60 sn) ve saatlik limit.
- **ACC-05** Doğrulanmamış hesap politikası konfigüre edilebilir: giriş tamamen engelli / sınırlı erişim. Doğrulanmamış hesaplar varsayılan 7 gün sonra temizlenir.
- **ACC-06** Hesap durum makinesi: `pending_verification`, `active`, `locked` (geçici, zaman aşımlı), `suspended` (admin), `disabled`, `pending_deletion`, `deleted`. Geçişler tek bir fonksiyonda tanımlı, geçersiz geçişler reddedilir, her geçiş audit log'a yazılır.
- **ACC-07** E-posta değişikliği: step-up gerektirir; yeni adrese doğrulama gider; doğrulanınca değişir; eski adrese "geri al" linkli bildirim gider (varsayılan 7 gün geçerli). Geri alma, değişikliği geri çevirir, tüm oturumları kapatır ve şifre sıfırlamaya zorlar.
- **ACC-08** Profil: görünen ad, dil (`tr`, `en`), saat dilimi. Güncelleme endpoint'i.
- **ACC-09** Hesap silme: step-up gerektirir; `pending_deletion` durumuna geçer, bekleme süresi (varsayılan 30 gün) boyunca iptal edilebilir; süre sonunda kişisel veriler kalıcı olarak silinir veya anonimleştirilir (audit log'da kullanıcı kimliği takma ada çevrilir). Organizasyonun son sahibi silinemez (önce devir).
- **ACC-10** Veri dışa aktarma (KVKK/GDPR): kullanıcının tüm verisi makine-okunur JSON. Modüller `DataExporter` portu ile kendi bölümlerini ekler. Step-up gerektirir, rate limit'li.
- **ACC-11** Onay kayıtları: kullanım şartları ve gizlilik politikası sürümünün kabul zamanı, IP ve user-agent ile saklanır; yeni sürüm yayınlanınca girişte yeniden onay istenebilir (konfigüre edilebilir).
- **ACC-12** Tek kullanımlık e-posta domain'i engel listesi (konfigürasyondan dosya; varsayılan kapalı).
- **ACC-13** Kayıtta bot koruması: `CaptchaVerifier` portu; politika ile zorunlu/opsiyonel/risk tabanlı.

---

## 5. Şifre yönetimi (`authn-password`)

- **PWD-01** Politika (NIST SP 800-63B rev.4 / OWASP ASVS): minimum uzunluk varsayılan 12 (konfigüre edilebilir; dokümantasyon tek faktörlü hesaplar için 15'i önerir), maksimum 128 karakter (NFKC sonrası, DoS önlemi). Karakter sınıfı zorunluluğu YOK. Tüm Unicode karakterlere ve boşluklara izin verilir.
- **PWD-02** Şifre hash'lenmeden önce NFKC normalizasyonu.
- **PWD-03** Sızdırılmış şifre kontrolü: HIBP Pwned Passwords k-anonymity API (yalnızca SHA-1 hash'in ilk 5 karakteri gider, `Add-Padding: true` başlığı ile). HIBP erişilemezse davranış konfigüre edilebilir (varsayılan: fail-open + uyarı logu). Opsiyonel çevrimdışı liste (dosya).
- **PWD-04** Güç tahmini: `zxcvbn`; minimum skor varsayılan 3; e-posta, ad ve servis adı kullanıcıya özel girdi olarak verilir. Geri bildirim (neden zayıf) TR/EN döner.
- **PWD-05** Şifre kontrol endpoint'i (kayıt formunda canlı geri bildirim için), rate limit'li, şifreyi loglamaz.
- **PWD-06** Şifre değiştirme: mevcut şifre (veya yakın zamanda step-up) gerekir; yeni şifre politikaya uymalı ve mevcut şifreyle aynı olmamalı; mevcut oturum hariç tüm oturumlar kapanır (`SessionRevoker` portu); bildirim e-postası gider.
- **PWD-07** Şifre sıfırlama isteği: hesap varlığını sızdırmaz (her durumda aynı yanıt ve benzer süre); e-posta başına ve IP başına rate limit; token tek kullanımlık, 256 bit, yalnızca hash'i saklanır, varsayılan 30 dk geçerli; yeni istek önceki token'ları geçersiz kılar.
- **PWD-08** Sıfırlama linki yalnızca konfigürasyondaki `public_base_url` ile oluşturulur (Host header kullanılmaz). Mobil için 6 haneli kod alternatifi (deneme limitli).
- **PWD-09** Sıfırlama tamamlama: token atomik tüketilir; yeni şifre politikaya uyar; tüm oturumlar ve refresh token'lar iptal edilir; güvenilir cihazlar silinir; bildirim e-postası gider; MFA etkinse sıfırlama MFA'yı atlatmaz (sıfırlamadan sonra giriş yine MFA ister).
- **PWD-10** Şifresi olmayan hesaplar (yalnızca passkey/sosyal giriş) şifre ekleyebilir (step-up ile).
- **PWD-11** Kullanıcı şifreyi kaldırabilir (yalnızca en az bir başka güçlü giriş yöntemi varsa).
- **PWD-12** Admin "bir sonraki girişte şifre değiştir" bayrağı (`must_change_password`).

---

## 6. Giriş, oturumlar ve token'lar (`authn-session`)

- **SES-01** Şifreli giriş akışı: rate limit kontrolü → gerekiyorsa CAPTCHA → kullanıcı arama (yoksa sahte hash doğrulama) → şifre doğrulama (gerekirse rehash) → hesap durumu kontrolü → risk değerlendirmesi → MFA gereksinimi → oturum oluşturma. Tüm başarısızlık yanıtları aynıdır (`invalid_credentials`); hesap durumu (askıda, kilitli) yalnızca doğru şifreden SONRA açıklanır.
- **SES-02** MFA gerekiyorsa tam oturum yerine kısa ömürlü (varsayılan 5 dk), tek kullanımlık, deneme limitli bir "MFA challenge" döner; challenge hangi faktörlerin kullanılabildiğini listeler.
- **SES-03** Web oturumu: sunucu tarafı opak oturum token'ı; cookie `__Host-authn_session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. Girişte, MFA tamamlandığında, organizasyon değiştiğinde ve yetki değiştiğinde oturum kimliği yenilenir.
- **SES-04** CSRF: cookie oturumunda durum değiştiren her istek için çift doğrulama: (a) `Origin`/`Sec-Fetch-Site` kontrolü (izinli origin listesi), (b) senkronize CSRF token'ı (`X-CSRF-Token` başlığı, oturuma bağlı HMAC). Login CSRF'e karşı giriş öncesi de geçerlidir.
- **SES-05** Mobil/native token modu: access token = JWT (varsayılan 10 dk); refresh token = opak, 256 bit, yalnızca hash'i saklanır. Her kullanımda rotasyon. Eski (zaten kullanılmış) refresh token tekrar gelirse tüm token ailesi (o oturum) iptal edilir ve güvenlik olayı üretilir. Rotasyon yarış durumuna karşı kısa bir tolerans penceresi (varsayılan 0 — kapalı; konfigüre edilebilir, ağ kesintisi için en fazla 10 sn ve yalnızca aynı yeni token'ı döndürür).
- **SES-06** Ömürler (varsayılan, konfigüre edilebilir): web oturumu boşta 2 saat / mutlak 12 saat; "beni hatırla" ile boşta 14 gün / mutlak 30 gün; refresh token boşta 30 gün / mutlak 90 gün. Mutlak süre rotasyonla uzamaz.
- **SES-07** "Bu benim cihazım değil" (paylaşılan bilgisayar): kalıcı cookie yerine tarayıcı oturumu cookie'si ve kısa ömür.
- **SES-08** Access token içeriği (RFC 9068): `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid`, `auth_time`, `amr` (RFC 8176 değerleri: `pwd`, `otp`, `hwk`, `swk`, `mfa`, `sms`, `email` vb.), `acr`, `org_id` (aktif organizasyon), `scope`. Kişisel veri (e-posta, ad) access token'a konmaz.
- **SES-09** JWKS: `GET /.well-known/jwks.json`, `Cache-Control` ile; yalnızca açık anahtarlar.
- **SES-10** Token introspection (RFC 7662): kaynak sunucuları için, istemci kimlik doğrulaması (API anahtarı) zorunlu; iptal edilmiş oturuma ait token için `active: false`.
- **SES-11** Oturum listesi: cihaz bilgisi (user-agent'tan ayrıştırılmış basit ad), oluşturulma, son görülme, IP (kısmen maskeli), mevcut oturum işareti. Tek tek kapatma, "diğer tüm oturumları kapat", "tümünü kapat".
- **SES-12** Çıkış: oturum sunucu tarafında iptal edilir, cookie temizlenir (`Clear-Site-Data: "cookies"` başlığı web için), refresh token iptal edilir.
- **SES-13** Step-up (yeniden doğrulama): hassas işlemler son N dakika içinde (varsayılan 10) doğrulama gerektirir; step-up şifre, passkey veya TOTP ile yapılabilir; `auth_time` ve `amr` güncellenir. Hassas işlemler listesi: e-posta değiştirme, şifre değiştirme/ekleme/kaldırma, MFA ekleme/kaldırma, kurtarma kodu üretme, hesap silme, veri dışa aktarma, API anahtarı oluşturma, organizasyon sahipliği devri, admin işlemleri.
- **SES-14** Eşzamanlı oturum sınırı (varsayılan sınırsız; konfigüre edilirse en eski oturum kapanır).
- **SES-15** `SessionRevoker` portunu uygular (kullanıcının tüm oturumları, biri hariç tümü, organizasyon bazında).
- **SES-16** `GET /v1/me`: oturum sahibinin temel bilgileri, doğrulanmış yöntemler, aktif organizasyon.
- **SES-17** Aktif organizasyon değiştirme: kullanıcının üyesi olduğu organizasyona geçer; o organizasyonun politikaları (MFA zorunluluğu, izinli yöntemler, oturum süresi, IP izin listesi) uygulanır; gerekirse step-up veya MFA ister.
- **SES-18** Şifresiz giriş — magic link: e-posta ile tek kullanımlık link (varsayılan 15 dk); hesap varlığını sızdırmaz; link açıldığı cihaz isteği başlatan cihazla aynı değilse (cihaz bağlama cookie'si yoksa) onay ekranı gerektirir (link-preview botlarına ve oturum sabitlemeye karşı GET ile tüketilmez, POST ile onaylanır).
- **SES-19** Şifresiz giriş — e-posta kodu: 6 haneli kod (varsayılan 10 dk, 5 deneme), challenge kimliğine bağlı.
- **SES-20** Passkey ile giriş (bkz. PKY): kullanıcı adı olmadan (discoverable credential) ve conditional UI desteği.
- **SES-21** Tüm giriş yöntemleri organizasyon politikası ve kullanıcının MFA gereksinimiyle birlikte değerlendirilir; passkey (UV=true) tek başına MFA sayılır (`amr: ["hwk"|"swk","mfa"]` uygun şekilde).
- **SES-22** Girişte `must_change_password`, yeniden onay gereken kullanım şartları ve zorunlu MFA kaydı gibi "zorunlu adımlar" (required actions) challenge olarak döner; tamamlanmadan tam oturum verilmez.

---

## 7. MFA (`authn-mfa`)

- **MFA-01** TOTP (RFC 6238): SHA-1, 6 hane, 30 sn, ±1 pencere (konfigüre edilebilir). Sır 160 bit, zarf şifreli saklanır. Kurulum: sır + `otpauth://` URI + QR (SVG) döner; kurulum ancak geçerli bir kodla onaylanınca aktif olur.
- **MFA-02** TOTP tekrar kullanım koruması: başarıyla kullanılan son zaman adımı saklanır; aynı veya önceki adım reddedilir.
- **MFA-03** Tüm OTP doğrulamaları deneme sınırlı (faktör başına ve kullanıcı başına); sınır aşılınca geçici kilit ve güvenlik olayı.
- **MFA-04** Kurtarma kodları: 10 adet, her biri en az 50 bit entropi, okunaklı biçim (`xxxxx-xxxxx`, karışıklık yaratan karakterler hariç); yalnızca hash'leri saklanır; tek kullanımlık; yeniden üretme eskileri geçersiz kılar (step-up gerekir); kalan kod sayısı gösterilir; kod kullanıldığında bildirim e-postası gider.
- **MFA-05** E-posta OTP: ikinci faktör (yedek) olarak; 6 hane, 10 dk, 5 deneme, tekrar gönderme bekleme süresi.
- **MFA-06** SMS OTP: opsiyonel (`SmsSender` portu); telefon numarası E.164 formatında doğrulanır ve doğrulanmadan faktör olmaz; SMS pumping koruması: ülke izin listesi (varsayılan: yalnızca konfigürasyonda izin verilen ülke kodları), numara ve IP başına limit, global günlük bütçe; SMS zayıf faktör olarak işaretlenir (organizasyon politikası SMS'i yasaklayabilir).
- **MFA-07** Bir kullanıcı birden fazla faktör kaydedebilir; son faktör kaldırılırken (MFA zorunluysa) engellenir; faktör ekleme/kaldırma step-up ister ve bildirim e-postası gönderir.
- **MFA-08** MFA politikası değerlendirmesi: kullanıcı tercihi, organizasyon politikası (zorunlu MFA, izinli faktörler, phishing'e dayanıklı faktör zorunluluğu), admin rolü (her zaman zorunlu, yalnızca phishing'e dayanıklı). Sonuç: `NotRequired | Required{allowed_factors} | EnrollmentRequired{allowed_factors}`.
- **MFA-09** Güvenilir cihaz (opsiyonel, politika ile kapatılabilir): MFA sonrası "bu cihazda 30 gün sorma"; imzalı cihaz token'ı (cookie veya mobil için başlık) + DB kaydı; şifre sıfırlama, MFA değişikliği ve "tüm oturumları kapat" ile iptal; admin hesaplarında devre dışı.
- **MFA-10** Kullanıcının MFA durumu ve faktör listesi endpoint'i (sırlar asla dönmez).

---

## 8. Passkey / WebAuthn (`authn-webauthn`)

- **PKY-01** `webauthn-rs` ile kayıt ve doğrulama seremonileri; challenge durumu sunucu tarafında, kısa ömürlü (varsayılan 5 dk), tek kullanımlık.
- **PKY-02** Passkey hem ikinci faktör hem birincil (şifresiz) giriş yöntemi. Discoverable credential (resident key) tercih edilir; user verification `required` (birincil giriş için) / `preferred` (ikinci faktör için).
- **PKY-03** Kullanıcı tanıtıcısı (user handle) rastgele ve e-postadan bağımsız.
- **PKY-04** Kimlik bilgisi yönetimi: listeleme (ad, oluşturulma, son kullanım, senkronize/yedeklenmiş durumu), yeniden adlandırma, silme (step-up; son giriş yöntemi silinemez).
- **PKY-05** İmza sayacı ve klon tespiti (`webauthn-rs` sonucu); şüpheli durumda güvenlik olayı.
- **PKY-06** RP konfigürasyonu: `rp_id`, izinli origin'ler (web origin'leri + Android `android:apk-key-hash:` origin'leri).
- **PKY-07** Mobil entegrasyon için `/.well-known/apple-app-site-association` ve `/.well-known/assetlinks.json` konfigürasyondan servis edilir (passkey + universal/app link). Related Origin Requests için `/.well-known/webauthn` (opsiyonel).
- **PKY-08** Attestation varsayılan `none`; organizasyon politikası belirli AAGUID'lere (ör. donanım anahtarı) kısıt koyabilir (opsiyonel).

---

## 9. Sosyal giriş — OIDC istemcisi (`authn-oidc-client`)

- **SOC-01** Sağlayıcılar: Google, Apple, Microsoft (Entra ID, çok kiracılı), GitHub (OAuth2 + `/user/emails` API), genel OIDC (discovery ile). Her biri konfigürasyondan etkinleştirilir.
- **SOC-02** Web akışı: Authorization Code + PKCE (S256) + `state` + `nonce`; durum sunucu tarafında saklanır, tek kullanımlık, 10 dk; dönüş adresi (`return_to`) izin listesiyle doğrulanır (open redirect yok).
- **SOC-03** ID token tam doğrulama: imza (sağlayıcı JWKS, önbellekli ve `kid` değişiminde yenilenen), `iss` (Microsoft için kiracıya özel issuer kuralı), `aud`, `exp`, `iat`, `nonce`, `azp` (varsa).
- **SOC-04** Native mobil akış: mobil SDK'dan (Sign in with Apple, Google Sign-In) gelen ID token sunucuda doğrulanır; nonce zorunlu (istemci önce sunucudan nonce alır).
- **SOC-05** Hesap eşleştirme: kimlik `(provider, subject)` ile eşleştirilir, e-posta ile değil. Yeni kimlik + aynı e-postaya sahip mevcut hesap varsa otomatik birleştirme YAPILMAZ; kullanıcı mevcut hesabıyla giriş yapıp bağlamaya yönlendirilir (konfigürasyonla yalnızca `email_verified=true` ve güvenilir sağlayıcı için otomatik bağlama açılabilir; varsayılan kapalı).
- **SOC-06** Kimlik bağlama/ayırma: giriş yapmış kullanıcı yeni sağlayıcı bağlayabilir (step-up), bağlantıyı kaldırabilir (son giriş yöntemiyse engellenir).
- **SOC-07** Apple özel: `client_secret` ES256 imzalı JWT olarak üretilir (özel anahtar konfigürasyondan, zarf şifreli veya dosya); Apple'ın ilk girişte gönderdiği ad bilgisi alınır; özel e-posta relay adresleri desteklenir.
- **SOC-08** Sağlayıcı token'ları varsayılan saklanmaz; saklanırsa zarf şifreli.
- **SOC-09** Sosyal girişle gelen hesap da MFA politikasına tabidir (sağlayıcı MFA'sına güvenme konfigüre edilebilir; varsayılan kapalı).

---

## 10. Organizasyonlar, RBAC, API anahtarları (`authn-org`)

- **ORG-01** Organizasyon CRUD; benzersiz `slug`; kurucu `owner` olur.
- **ORG-02** Üyelik: bir kullanıcı birden fazla organizasyonda olabilir; üyelik durumu (`active`, `suspended`); son `owner` organizasyondan çıkarılamaz/ayrılamaz.
- **ORG-03** RBAC: yerleşik roller (`owner`, `admin`, `member`, `billing`, `viewer`) + organizasyona özel roller; roller izinlerden (`resource:action`, ör. `members:invite`) oluşur; yetki kontrolü tek bir fonksiyon (`authorize(principal, permission, org)`) üzerinden; varsayılan reddet.
- **ORG-04** Ayrıcalık yükseltme koruması: kullanıcı kendi sahip olmadığı izinleri içeren rol atayamaz; `owner` rolünü yalnızca `owner` atayabilir.
- **ORG-05** Davetler: e-posta adresine bağlı, tek kullanımlık, 256 bit token (hash'i saklanır), varsayılan 7 gün; daveti kabul eden kullanıcının doğrulanmış e-postası davet e-postasıyla eşleşmeli; iptal edilebilir; yeniden gönderilebilir (rate limit).
- **ORG-06** Domain doğrulama: DNS TXT kaydı (`_authn-verification.<domain>`, rastgele değer); doğrulanmış domain için politika: o domain'den kayıt olanları otomatik üye yap (opsiyonel) / SSO zorunlu (Faz 2 hazırlığı).
- **ORG-07** Organizasyon politikaları: MFA zorunlu, phishing'e dayanıklı MFA zorunlu, izinli giriş yöntemleri, izinli MFA faktörleri, oturum ömrü üst sınırı, IP izin listesi (CIDR), güvenilir cihaz izni. Politika değişikliği audit log'a yazılır.
- **ORG-08** API anahtarları: biçim `ak_<env>_<base62 rastgele 32 byte>_<crc32 checksum>` (sızıntı taramasına uygun önek ve sağlama toplamı); yalnızca hash'i saklanır; gösterim yalnızca oluşturma anında; kapsamlar (scope), son kullanma tarihi (zorunlu, varsayılan en fazla 1 yıl), son kullanım zamanı ve IP; iptal ve rotasyon (yeni anahtar + eski anahtar için kısa geçiş süresi).
- **ORG-09** Servis hesapları: organizasyona ait, insan olmayan kimlik; yalnızca API anahtarı ile kimlik doğrular; rol atanabilir.
- **ORG-10** Kiracı izolasyonu: başka organizasyonun kaynağına erişim girişimi `404` döner (varlığı sızdırmaz); tüm organizasyon endpoint'lerinde IDOR testleri zorunlu.
- **ORG-11** Organizasyon sahipliği devri (step-up, hedef kullanıcının onayı).
- **ORG-12** Organizasyon silme (bekleme süreli, yalnızca `owner`, step-up).

---

## 11. Kötüye kullanım koruması ve web güvenliği (`authn-protect`)

- **PRT-01** `RateLimiter` portu ve uygulamaları: bellek içi (tek instance/test), PostgreSQL (dağıtık, varsayılan), Redis (opsiyonel feature). Algoritma: GCRA veya kayan pencere; atomik.
- **PRT-02** Anahtar boyutları: IP, hesap (normalize e-posta veya kullanıcı kimliği), IP+hesap, endpoint, organizasyon, telefon numarası, global. Varsayılan limitler konfigürasyonda; giriş için hesap başına 10/15 dk sonra CAPTCHA, 50/saat sonra geçici yumuşak kilit; IP başına 100/15 dk.
- **PRT-03** Yumuşak kilit: hesap kilitleme saldırganın hesabı kapatmasına (DoS) izin vermez — kilit, bilinmeyen cihaz/IP'den gelen şifre denemelerini engeller; güvenilir cihazdan veya passkey ile giriş ve şifre sıfırlama mümkün kalır. Kilit yanıtı hesap varlığını sızdırmaz.
- **PRT-04** Artan gecikme yerine (thread bloklamamak için) `429` + `Retry-After`.
- **PRT-05** `CaptchaVerifier` uygulamaları: Cloudflare Turnstile, hCaptcha (HTTP doğrulama) ve kendi barındırılan proof-of-work (HMAC imzalı challenge, zorluk ayarlı, tek kullanımlık). Tetikleme: politika (her zaman / risk tabanlı / asla).
- **PRT-06** İstemci IP tespiti: `X-Forwarded-For`/`Forwarded` yalnızca konfigürasyondaki güvenilir proxy CIDR'larından gelirse kullanılır; aksi halde bağlantı IP'si.
- **PRT-07** Güvenlik başlıkları (tower katmanı): `Strict-Transport-Security` (max-age 2 yıl, includeSubDomains, opsiyonel preload), `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` (API yanıtları), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-site`, `Permissions-Policy`, auth yanıtlarında `Cache-Control: no-store`.
- **PRT-08** CORS: açık origin izin listesi; kimlik bilgili isteklerde joker veya yansıtılan origin asla; preflight önbellek süresi sınırlı.
- **PRT-09** Host başlığı doğrulama: yalnızca konfigürasyondaki host'lar; aksi halde `421`/`400`.
- **PRT-10** Yönlendirme (redirect) doğrulama: `return_to`/`redirect_uri` değerleri tam eşleşme izin listesiyle; göreli yollar yalnızca `/` ile başlayıp `//` ile başlamıyorsa.
- **PRT-11** İstek gövdesi boyut sınırı (varsayılan 64 KiB), istek zaman aşımı, eşzamanlı istek sınırı.
- **PRT-12** Giden HTTP istekleri (HIBP, OIDC, webhook, CAPTCHA) için SSRF koruması: webhook gibi kullanıcı tarafından verilen URL'ler özel/yerel/link-local/metadata IP aralıklarına çözümlenemez (DNS rebinding'e karşı çözümlenen IP'ye bağlanılır); zaman aşımı ve yanıt boyutu sınırı.

---

## 12. Risk tabanlı doğrulama (`authn-protect`)

- **RSK-01** `RiskEvaluator` portu: girdi = kullanıcı, IP, user-agent, cihaz kimliği, zaman, giriş yöntemi; çıktı = risk seviyesi (`low`, `medium`, `high`) + nedenler.
- **RSK-02** Varsayılan değerlendirici: yeni cihaz (cihaz cookie'si/kimliği görülmemiş), yeni IP ağı (/24 veya /48), kısa sürede çok sayıda başarısız deneme, TOR/proxy listesi (opsiyonel dosya), imkansız seyahat (GeoIP sağlayıcısı portu takılırsa; GeoIP veritabanı gömülmez).
- **RSK-03** Risk sonucu politikası: `medium` → MFA iste (MFA kayıtlıysa) veya e-posta onayı; `high` → giriş engelle + kullanıcıya bildirim. Konfigüre edilebilir.
- **RSK-04** Yeni cihazdan başarılı girişte kullanıcıya bildirim e-postası (cihaz, yaklaşık konum varsa, zaman, "bu ben değilim" linki → tüm oturumları kapatır ve şifre sıfırlatır).

---

## 13. Audit log, olaylar, webhook'lar ve bildirimler (`authn-audit`, `authn-notify`)

- **AUD-01** `AuditSink` portu; tüm güvenlik olayları kaydedilir: giriş başarılı/başarısız (neden kodu), çıkış, MFA olayları, şifre/e-posta değişikliği, sıfırlama, oturum iptali, token yeniden kullanım tespiti, rol/üyelik değişiklikleri, politika değişiklikleri, admin işlemleri, impersonation, API anahtarı olayları.
- **AUD-02** Kurcalamaya karşı: kayıtlar ekleme-yalnızca (uygulama rolü `UPDATE`/`DELETE` yetkisine sahip değil — migration'da ayrı rol önerisi); anahtarlı hash zinciri (`hash = HMAC-SHA-256(K_v, prev_hash || canonical_json(event))`; `K_v`, `crypto.hmac_root_key`'den HKDF ile türetilen `audit-chain` alt anahtarının `v` sürümüdür — anahtarı olmayan, veritabanına yazabilen bir saldırgan zinciri yeniden hesaplayamaz, K-77); anahtar sürümü rotasyonu ve kontrol noktası; anahtar öncesi eski satırlar `SHA-256(prev_hash || canonical_json(event))` ile doğrulanır, anahtarlı satırdan sonra anahtarsız satıra geri düşüş reddedilir; zincir doğrulama fonksiyonu ve CLI komutu.
- **AUD-03** Olay içeriği: kim (aktör + impersonation durumunda gerçek aktör), ne, hangi kaynak, sonuç, IP, user-agent, request id, organizasyon. Sır, şifre, token, OTP asla yazılmaz.
- **AUD-04** Kullanıcının kendi güvenlik olaylarını görebildiği endpoint (son 90 gün); organizasyon adminleri için organizasyon audit log'u (sayfalama, filtre).
- **AUD-05** Saklama süresi konfigüre edilebilir; hesap silindiğinde kullanıcı kimliği takma ada çevrilir (zincir bozulmadan: kişisel veriler ayrı tabloda tutulur ve silinir, zincirdeki olay takma ad içerir).
- **AUD-06** Outbox deseni: domain olayları aynı transaction içinde `outbox` tablosuna yazılır; arka plan işçisi teslim eder (en az bir kez, üstel geri çekilme, ölü mektup durumu).
- **AUD-07** Webhook'lar: organizasyon başına endpoint'ler; olay türü abonelikleri (`user.created`, `user.deleted`, `session.revoked`, `member.added` vb.); imza Standard Webhooks biçiminde (`webhook-id`, `webhook-timestamp`, `webhook-signature` = HMAC-SHA256); sır rotasyonu; SSRF korumalı (PRT-12); teslim geçmişi; tekrar deneme.
- **NTF-01** `Notifier` portu: bildirim türü + alıcı + dil + parametreler. Türler: e-posta doğrulama, kayıt girişimi (mevcut hesap), şifre sıfırlama, şifre değişti, e-posta değişti (eski/yeni adres), MFA eklendi/kaldırıldı, kurtarma kodu kullanıldı, yeni cihazdan giriş, hesap silme planlandı/iptal edildi, davet, magic link, giriş kodu, organizasyon sahipliği devri.
- **NTF-02** E-posta şablonları TR ve EN, HTML + düz metin; şablonlar dosyadan geçersiz kılınabilir; kullanıcı verisi otomatik escape edilir; linkler yalnızca `public_base_url` ile.
- **NTF-03** `EmailTransport`: SMTP (`lettre`, STARTTLS/TLS zorunlu), log/geliştirme taşıyıcısı (yalnızca dev), test taşıyıcısı. Gönderim outbox üzerinden (istek yolunu bloklamaz, yeniden denenir).
- **NTF-04** `SmsSender`: genel HTTP sağlayıcı arayüzü + log/test uygulaması.

---

## 14. Admin API (`authn-admin`)

- **ADM-01** Ayrı router (`/v1/admin/...`); yalnızca platform admin rolü; admin oturumları phishing'e dayanıklı MFA (passkey) ve her işlem için son 10 dk içinde step-up ister; opsiyonel IP izin listesi.
- **ADM-02** Kullanıcı arama/listeleme (sayfalı, filtreli), detay görüntüleme (sırlar hariç).
- **ADM-03** Kullanıcı işlemleri: askıya alma/geri alma, kilit açma, oturumları kapatma, şifre sıfırlamaya zorlama, `must_change_password`, MFA sıfırlama (gerekçe zorunlu, kullanıcıya bildirim), e-posta doğrulandı işaretleme (gerekçe zorunlu).
- **ADM-04** Impersonation: süreli (varsayılan 15 dk, en fazla 60), gerekçe zorunlu, salt-okunur mod varsayılan, token'da `act` claim'i (RFC 8693), kullanıcıya bildirim ve kullanıcının güvenlik olaylarında görünür, adminlere ve break-glass hesaplarına uygulanamaz.
- **ADM-05** Break-glass: CLI ile oluşturulan acil durum admin hesabı; kullanımı yüksek öncelikli güvenlik olayı üretir.
- **ADM-06** Acil durum işlemleri: tüm kullanıcıların tüm oturumlarını kapatma, imza anahtarını acil iptal ve rotasyon, belirli bir tarihten önce şifresi değişmemiş tüm kullanıcılara şifre sıfırlama zorunluluğu.
- **ADM-07** Audit log sorgulama, dışa aktarma ve zincir doğrulama.
- **ADM-08** Her admin işlemi gerekçe alanı ile audit log'a yazılır.

---

## 15. Sunucu, operasyon ve gözlemlenebilirlik (`authn-server`)

- **OPS-01** Tek binary (`rust-authentication`), alt komutlar: `serve`, `migrate`, `create-admin` (break-glass), `rotate-signing-key`, `rotate-kek`/`reencrypt`, `verify-audit-chain`, `migrate-legacy-hashes`, `check-config`.
- **OPS-02** Middleware sırası belgelenmiş: request id → izleme (tracing) → zaman aşımı → gövde sınırı → host doğrulama → güvenlik başlıkları → CORS → rate limit → kimlik doğrulama → CSRF → handler.
- **OPS-03** Yapılandırılmış JSON loglar; kişisel veri maskeleme (e-posta kısmi, IP kısmi), sır redaksiyonu; her istekte `request_id`.
- **OPS-04** Metrikler (Prometheus, ayrı dinleyici/port): giriş başarı/başarısızlık (neden koduna göre), MFA kullanımı, kayıt, sıfırlama talepleri, rate limit tetiklenmeleri, token yeniden kullanım tespitleri, outbox kuyruk derinliği, gecikme histogramları.
- **OPS-05** `GET /health/live`, `GET /health/ready` (DB bağlantısı ve migration durumu).
- **OPS-06** Arka plan işleri: outbox teslimi, süresi dolmuş token/oturum/challenge temizliği, doğrulanmamış hesap temizliği, hesap silme tamamlama, audit log saklama, imza anahtarı rotasyonu zamanlaması. Çoklu instance'ta güvenli (`FOR UPDATE SKIP LOCKED` veya advisory lock).
- **OPS-07** Zarif kapanış (graceful shutdown).
- **OPS-08** `Dockerfile` (çok aşamalı, root olmayan kullanıcı, minimal imaj), `docker-compose.yml` (PostgreSQL, Redis, Mailpit), örnek konfigürasyon dosyası (`config/example.toml`) — tüm ayarlar yorumlarıyla.
- **OPS-09** OpenAPI şeması `GET /openapi.json` (konfigürasyonla kapatılabilir).
- **OPS-10** Veritabanı migration'ları `sqlx migrate`; uygulama veritabanı rolü için en az yetki önerisi (audit tablosunda `UPDATE`/`DELETE` yok).

---

## 16. Test gereksinimleri

- **TST-01** Her modül: birim testleri, `#[sqlx::test]` ile gerçek PostgreSQL entegrasyon testleri ve HTTP seviyesinde (router + `tower::ServiceExt::oneshot`) testler.
- **TST-02** Güvenlik regresyon testleri (zorunlu): hesap varlığı sızıntısı (yanıt gövdesi, durum kodu ve zamanlama — istatistiksel tolerans ile), token ve OTP tekrar kullanımı, refresh token yeniden kullanım tespiti, TOTP replay, CSRF, login CSRF, open redirect, Host header zehirlenmesi, IDOR/kiracılar arası erişim, ayrıcalık yükseltme, yarış durumu (aynı tek kullanımlık token'ın eşzamanlı tüketimi — tam olarak birinin başarılı olması), rate limit, JWT `alg` karışıklığı/`none`/yanlış `kid`/süresi dolmuş/yanlış `aud`, SSRF.
- **TST-03** Property-based testler (`proptest`): normalizasyon, token/kod biçimleri, şifreleme gidiş-dönüşü, durum makinesi geçişleri.
- **TST-04** Fuzz hedefleri: JWT ayrıştırma, API anahtarı ayrıştırma, şifreli veri zarfı ayrıştırma, e-posta normalizasyonu, webhook imza doğrulama, `return_to` doğrulama.
- **TST-05** Kriptografi bilinen test vektörleri (CRY-14).
- **TST-06** Uçtan uca senaryolar (`authn-server` seviyesinde): kayıt → doğrulama → giriş → TOTP kayıt → çıkış → TOTP ile giriş → kurtarma kodu ile giriş; şifre sıfırlama; passkey kayıt/giriş (`webauthn-rs` yazılımsal authenticator ile); mobil token akışı ve rotasyon; organizasyon oluşturma → davet → kabul → rol değişikliği → politika (MFA zorunlu) etkisi; sosyal giriş (`wiremock` ile sahte sağlayıcı); admin impersonation.
- **TST-07** Kalite kapıları CI'da: `cargo fmt --check`, `cargo clippy -D warnings` (workspace lint'leri), `cargo test`, `cargo deny check` (lisans + RustSec + kaynaklar), `cargo audit`, kapsam raporu (`cargo llvm-cov`), fuzz hedeflerinin derlendiği kontrolü.
- **TST-08** Testler deterministik: sahte saat, sabit tohumlu sahte RNG yalnızca testlerde, ağ bağımlılığı yok (dış servisler `wiremock`).

---

## 17. Dokümantasyon gereksinimleri (Türkçe)

- **DOC-01** `README.md`: ne olduğu, özellik listesi, hızlı başlangıç (docker compose ile 5 dakikada çalıştırma), mimari özet, lisans politikası.
- **DOC-02** `docs/architecture/`: genel mimari, crate'ler ve bağımlılık grafiği, veri modeli (ER diyagramı), akış diyagramları (kayıt, giriş + MFA, token rotasyonu, şifre sıfırlama, sosyal giriş, davet), ADR'ler (her önemli karar).
- **DOC-03** `docs/security/`: tehdit modeli (STRIDE, varlıklar, güven sınırları, saldırgan profilleri), OWASP ASVS eşleme tablosu (gereksinim → kod → test), kriptografi kararları, bilinen sınırlamalar, `SECURITY.md` (zafiyet bildirimi).
- **DOC-04** `docs/api/`: endpoint referansı (OpenAPI'den), hata kodları kataloğu, kimlik doğrulama başlıkları, rate limit davranışı, sayfalama.
- **DOC-05** `docs/integration/`: web (aynı site cookie, BFF, SPA), iOS (passkey, Sign in with Apple, token saklama — Keychain), Android (Credential Manager, passkey, Keystore), kaynak sunucusu (JWKS ile JWT doğrulama örneği), B2B (organizasyon, davet, roller, API anahtarı), webhook alıcısı (imza doğrulama örneği).
- **DOC-06** `docs/operations/`: konfigürasyon referansı (her ayar), dağıtım, anahtar yönetimi ve rotasyon runbook'ları, olay müdahalesi runbook'ları (hesap ele geçirme, toplu oturum kapatma, imza anahtarı sızıntısı, pepper/KEK sızıntısı), yedekleme, izleme ve alarm önerileri, ölçekleme.
- **DOC-07** `docs/compliance/`: KVKK/GDPR notları (veri envanteri, saklama süreleri, silme/dışa aktarma, yurt dışı aktarım notu), NIST 800-63B uyum notları.
- **DOC-08** Her crate'in kendi `README.md`'si (sorumluluk, genel API, konfigürasyon, gereksinim kimlikleri).
- **DOC-09** `docs/roadmap.md`: Faz 2 ve Faz 3 kapsamı ve mevcut mimarideki genişleme noktaları.

---

## 18. Bitti tanımı (her modül için)

1. Bölümündeki tüm MUST gereksinimleri uygulanmış; uygulanamayan SHOULD/MAY maddeleri gerekçesiyle crate README'sinde.
2. `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings` ilgili crate için geçiyor; `cargo fmt` uygulanmış.
3. Production kodunda `todo!`, `unimplemented!`, `unwrap`, `expect`, `panic!`, TODO yorumu yok.
4. Her gereksinim kimliğinin en az bir testi var (test adında kimlik).
5. Tüm public öğeler rustdoc ile belgelenmiş (`#![warn(missing_docs)]`).
6. Crate `README.md` (Türkçe) yazılmış.
