# Özellik karşılaştırması ve yol haritası (DOC-09, K-71)

> **Durum:** 2026-11-05, `main` üzerindeki Faz 1 kodu (16 crate, 175 gereksinim kimliği). Bu belge iki soruyu yanıtlar: (1) önde gelen kimlik sistemlerine göre bugün neredeyiz, (2) eksikleri hangi sırayla kapatacağız. Faz 2 kalemleri [`docs/handoff/remaining-work.md` §10.6](handoff/remaining-work.md)'da K-80 … K-99 olarak izlenir.
>
> Hedef (proje sahibi, HANDOFF §9): "Dünyadaki en güvenli, en hızlı, en özellikli auth sistemi." Bu belge "en özellikli" hedefine bugün **ulaşmadığımızı** açıkça gösterir. Güvenlik derinliğinde güçlüyüz; protokol genişliğinde (OAuth/OIDC sağlayıcısı, kurumsal federasyon, SDK'lar) geride kalıyoruz.

## İçindekiler

1. [Yöntem ve sınırlar](#1-yöntem-ve-sınırlar)
2. [Özet](#2-özet)
3. [Özellik matrisi](#3-özellik-matrisi)
4. [Zaten önde olduğumuz yerler](#4-zaten-önde-olduğumuz-yerler)
5. [Geride olduğumuz yerler](#5-geride-olduğumuz-yerler)
6. [Önceliklendirme ölçütleri](#6-önceliklendirme-ölçütleri)
7. [Faz 2](#7-faz-2)
8. [Faz 3](#8-faz-3)
9. [Daha sonra / izlenecekler](#9-daha-sonra--izlenecekler)
10. [Mevcut mimarideki genişleme noktaları](#10-mevcut-mimarideki-genişleme-noktaları)
11. [Lisans kısıtları](#11-lisans-kısıtları)
12. [Bu belgenin bakımı](#12-bu-belgenin-bakımı)

---

## 1. Yöntem ve sınırlar

- **Bizim sütunumuz kodla doğrulandı.** Her ✅ satırı bir gereksinim kimliğine, crate'e veya test adına bağlanır. Crate README'leri ve testler `grep` ile kontrol edildi. Kodda olmayan hiçbir şey ✅ sayılmadı.
- **Rakip sütunları genel kategorilerdir.** Karşılaştırmayı iki genel kategoriyle yaptık: **önde gelen barındırılan (SaaS) IdP ürünleri** ve **önde gelen açık kaynak kimlik sunucuları**. Ürün adı vermiyoruz. Bu sütunlar yalnızca kamuya açık belgelerde yaygın olarak tanıtılan **özellik kategorilerini** yansıtır. Rakiplerin iç yapısı, güvenlik kalitesi ya da varsayılan ayarları hakkında iddiada bulunmuyoruz.
- Rakip sütunlarındaki ifadeler:
  - **genel olarak sunulur:** kategorideki önde gelen ürünlerin çoğunun belgelerinde var. Emin olmadığımız durumda da bu ifadeyi kullandık, yani aşırı kesin okunmamalı.
  - **bazılarında:** bazı ürünlerde var, bazılarında yok ya da ek ürün/eklentiyle geliyor.
  - **nadiren:** yaygın olarak tanıtılmıyor.
  - **belirsiz:** iç davranışa (ör. zamanlama eşitliği, SSRF savunması) ilişkin, kamuya açık belgelerden çıkarılamayan konular. Bu konularda hiçbir yönde iddiada bulunmuyoruz.
  - **uygulanamaz / —:** kategori için anlamsız (ör. barındırılan bir hizmette "tek binary ile kendi barındırma").
- **Durum simgeleri:** ✅ var · 🟡 kısmi (sınırı notta yazılı) · ❌ yok.
- **Çaba tahminleri** kabadır ve **uzman-hafta** cinsindendir: bir uzman yazar ve bir bağımsız denetçi (HANDOFF §6 deseni), testler, README ve denetim dahil. ±%50 sapma beklenmeli.

## 2. Özet

| Kategori | ✅ | 🟡 | ❌ | Toplam |
|----------|----|----|----|--------|
| A. Kimlik doğrulama faktörleri | 14 | 0 | 5 | 19 |
| B. Sosyal ve kurumsal federasyon | 4 | 2 | 7 | 13 |
| C. OAuth 2.1 / OIDC sağlayıcısı olarak | 2 | 3 | 14 | 19 |
| D. Oturum yönetimi | 9 | 0 | 2 | 11 |
| E. B2B | 11 | 0 | 4 | 15 |
| F. Yönetim | 6 | 1 | 2 | 9 |
| G. Güvenlik | 12 | 3 | 3 | 18 |
| H. Uyumluluk | 7 | 1 | 1 | 9 |
| I. Geliştirici deneyimi | 6 | 2 | 9 | 17 |
| J. Operasyon | 11 | 1 | 3 | 15 |
| **Toplam** | **82** | **13** | **50** | **145** |

Kısaca: B2C ve B2B'nin "uygulama içi" kimlik doğrulama çekirdeği (faktörler, oturumlar, organizasyonlar, yönetim, güvenlik) güçlü. En büyük açık **C kategorisi**: sistem bir OAuth 2.1/OIDC **sağlayıcısı** değil. Bu yüzden başka uygulamalara SSO veremiyor, üçüncü taraf istemci barındıramıyor ve kurumsal federasyonun yarısı (B) da bu eksikliğe bağlı. İkinci büyük açık **I kategorisi**: SDK, barındırılan UI ve bileşenler yok.

## 3. Özellik matrisi

### A. Kimlik doğrulama faktörleri

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| A1 | Şifre (modern hash, sızıntı kontrolü, NIST 800-63B politikası) | genel olarak sunulur | genel olarak sunulur | ✅ | PWD-01…12, CRY-01…05: Argon2id + versiyonlu pepper, HIBP k-anonymity, zxcvbn, karakter sınıfı zorunluluğu yok |
| A2 | Passkey / WebAuthn (birincil giriş ve ikinci faktör, discoverable) | genel olarak sunulur | genel olarak sunulur | ✅ | PKY-01…05, SES-20/21 (`authn-webauthn`, `webauthn-rs`) |
| A3 | Conditional UI (passkey autofill) | genel olarak sunulur | bazılarında | ✅ | SES-20, `AuthenticationTarget::Discoverable { conditional_ui }` |
| A4 | Cihazlar arası passkey (hybrid / QR) | genel olarak sunulur | genel olarak sunulur | ✅ | Protokol platform/tarayıcı tarafında. Sunucu taşıyıcı (transport) kısıtı koymaz. Gerçek cihazla uçtan uca test edilmedi |
| A5 | Mobil passkey ilişkilendirmesi (AASA, assetlinks, Android origin, Related Origins) | genel olarak sunulur | bazılarında | ✅ | PKY-06/07 |
| A6 | WebAuthn Level 3 eklentileri (conditional create / otomatik passkey yükseltme, Signal API) | bazılarında | nadiren | ❌ | Faz 2 K-95. `webauthn-rs` desteği doğrulanmalı |
| A7 | Donanım anahtarı + attestation / AAGUID politikası | genel olarak sunulur | bazılarında | ✅ | PKY-08: org politikası `allowed_passkey_aaguids`, güvenilir kökler yapılandırmadan |
| A8 | FIDO Metadata Service (MDS3) entegrasyonu | bazılarında | bazılarında | ❌ | Kökler elle yapılandırılıyor (`authn-webauthn` README). Faz 2 K-95 |
| A9 | TOTP (replay korumalı) | genel olarak sunulur | genel olarak sunulur | ✅ | MFA-01/02 |
| A10 | Kurtarma kodları | genel olarak sunulur | genel olarak sunulur | ✅ | MFA-04 |
| A11 | E-posta OTP (ikinci faktör) | genel olarak sunulur | genel olarak sunulur | ✅ | MFA-05 |
| A12 | SMS OTP (ikinci faktör, SMS pumping koruması) | genel olarak sunulur | bazılarında | ✅ | MFA-06: ülke izin listesi, numara/IP/global bütçe, "zayıf" işaretli. Sağlayıcı genel HTTP (NTF-04) |
| A13 | Magic link | genel olarak sunulur | bazılarında | ✅ | SES-18: GET ile tüketilmez, cihaz bağlama |
| A14 | E-posta koduyla şifresiz giriş | genel olarak sunulur | bazılarında | ✅ | SES-19 |
| A15 | Telefonla şifresiz giriş / telefon tanımlayıcı | genel olarak sunulur | bazılarında | ❌ | SMS yalnızca ikinci faktör. Bilinçli: SMS zayıf faktör. Faz 3 |
| A16 | Kullanıcı adı tanımlayıcı (e-postasız hesap) | genel olarak sunulur | genel olarak sunulur | ❌ | Tanımlayıcı yalnızca e-posta (ACC-01/03). Faz 3 |
| A17 | Push MFA (doğrulayıcı uygulama onayı, numara eşleştirme) | genel olarak sunulur | nadiren | ❌ | Faz 3 (kendi doğrulayıcı uygulaması + APNs/FCM gerektirir) |
| A18 | Güvenilir cihaz ("bu cihazda sorma") | genel olarak sunulur | bazılarında | ✅ | MFA-09: imzalı token + DB kaydı, şifre sıfırlamada iptal, adminlerde kapalı |
| A19 | Risk tabanlı / uyarlamalı kimlik doğrulama (MFA iste / engelle) | genel olarak sunulur | bazılarında | ✅ | RSK-01…03: kural tabanlı (yeni cihaz/ağ, hata hızı, anonimleştirici ağ, imkânsız seyahat). Sınırları G6 ve G5'te |

### B. Sosyal ve kurumsal federasyon

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| B1 | Sosyal giriş: Google, Apple, Microsoft, GitHub | genel olarak sunulur | genel olarak sunulur | ✅ | SOC-01…03, 07: web akışı PKCE + state + nonce, Apple ES256 `client_secret`, Microsoft kiracı kuralı |
| B2 | Genel OIDC sağlayıcısı (discovery) | genel olarak sunulur | genel olarak sunulur | ✅ | SOC-01, `trust_email_verified` varsayılan kapalı (K-04) |
| B3 | Yalnızca OAuth 2.0 konuşan sağlayıcılar (OIDC olmayan) | genel olarak sunulur | genel olarak sunulur | 🟡 | Yalnızca GitHub özel olarak destekleniyor. Diğerleri için sağlayıcı başına kod gerekir |
| B4 | Native mobil sosyal giriş (SDK'dan gelen ID token) | genel olarak sunulur | bazılarında | ✅ | SOC-04: sunucu nonce'u zorunlu, Apple kod takası (K-35) |
| B5 | Güvenli hesap eşleştirme, bağlama/ayırma | genel olarak sunulur | genel olarak sunulur | ✅ | SOC-05/06: `(provider, subject)` ile eşleşir. E-postayla otomatik birleştirme varsayılan kapalı. Step-up ve son yöntem koruması var |
| B6 | Organizasyon başına kurumsal OIDC SSO (müşterinin IdP'si) | genel olarak sunulur | genel olarak sunulur | ❌ | Faz 2 K-82. `identities` tablosu hazır |
| B7 | Home realm discovery (e-posta alan adı → IdP yönlendirmesi) | genel olarak sunulur | bazılarında | 🟡 | Doğrulanmış domain var (ORG-06), yönlendirme yok. Faz 2 K-82 |
| B8 | SAML 2.0 SP (kurumsal IdP'den giriş) | genel olarak sunulur | genel olarak sunulur | ❌ | Faz 3 (spesifikasyon §0) |
| B9 | SAML 2.0 IdP (başka uygulamalara SAML ile SSO) | bazılarında | genel olarak sunulur | ❌ | Faz 3 |
| B10 | SCIM 2.0 sağlama (provisioning) sunucusu | genel olarak sunulur | bazılarında | ❌ | Faz 2 K-83 |
| B11 | Dizin senkronizasyonu (bulut dizin API'leri) | bazılarında | bazılarında | ❌ | Faz 3. Çoğu müşteri için SCIM yeterli |
| B12 | Kurumsal JIT sağlama (ilk SSO girişinde üye/rol) | genel olarak sunulur | genel olarak sunulur | ❌ | Sosyal girişte hesap sağlama var (K-33). Kurumsal JIT Faz 2 K-82 |
| B13 | LDAP / Active Directory kullanıcı federasyonu | bazılarında | genel olarak sunulur | ❌ | Faz 3. Şifreleri dış dizinde doğrulamak, yerel hash politikamızın dışına çıkar |

### C. OAuth 2.1 / OIDC sağlayıcısı olarak

| # | Özellik (standart) | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|--------------------|----------------------|-----------------------|-----|-------------|
| C1 | Authorization Code + PKCE (OAuth 2.1 taslağı, RFC 7636) | genel olarak sunulur | genel olarak sunulur | ✅ | K-80 çekirdeği (wave 11A, varsayılan kapalı): yalnızca `code` + PKCE `S256` (OIDP-03, OIDP-06), `authn-oidc-provider`. Bağımsız denetim ve uyumluluk paketi koşusu bekliyor |
| C2 | OIDC Core + Discovery: ID token, `userinfo`, `/.well-known/openid-configuration` | genel olarak sunulur | genel olarak sunulur | ✅ | K-80 (OIDP-08 … OIDP-10); RFC 8414 meta verisi de var |
| C3 | Native uygulamalar için OAuth (RFC 8252), üçüncü taraf istemciler | genel olarak sunulur | genel olarak sunulur | ✅ | K-80: loopback (port serbest) ve özel şema `redirect_uri`, açık istemci + PKCE (OIDP-02). Org tarafından yönetilen istemciler kalan iş |
| C4 | Client Credentials (makineden makineye) | genel olarak sunulur | genel olarak sunulur | ❌ | Bugünkü alternatif: org API anahtarları + servis hesapları (ORG-08/09). Faz 2 K-84 |
| C5 | Device Authorization Grant (RFC 8628) | genel olarak sunulur | genel olarak sunulur | ❌ | Faz 2 K-89 (spesifikasyon §0 Faz 2'de sayar) |
| C6 | Token Exchange (RFC 8693) | bazılarında | genel olarak sunulur | ❌ | `act` claim'i impersonation'da kullanılıyor (ADM-04). Uç nokta Faz 2 K-90 |
| C7 | DPoP (RFC 9449) | bazılarında | bazılarında | ❌ | Faz 2 K-81 |
| C8 | PAR (RFC 9126) | bazılarında | bazılarında | ❌ | Faz 2 K-87 |
| C9 | RAR (RFC 9396) | nadiren | bazılarında | ❌ | Faz 3 |
| C10 | CIBA (OpenID Connect Client-Initiated Backchannel Authentication) | nadiren | bazılarında | ❌ | Faz 3 |
| C11 | Dinamik istemci kaydı (RFC 7591/7592) | bazılarında | genel olarak sunulur | ❌ | Faz 2 K-91 |
| C12 | Onay (consent) ekranı ve onay kayıtları | genel olarak sunulur | genel olarak sunulur | ✅ | K-80 (OIDP-05): onay kayıtları, kullanıcının geri alması; ekran işletmecinin önyüzünde (headless). Kullanım şartı onayları (ACC-11) ayrı bir şey |
| C13 | Token introspection (RFC 7662) | genel olarak sunulur | genel olarak sunulur | ✅ | SES-10 (native token'lar, org API anahtarı) + K-80 OIDP-11 (sağlayıcı token'ları, OAuth istemci kimlik doğrulaması) |
| C14 | Token revocation (RFC 7009) | genel olarak sunulur | genel olarak sunulur | ✅ | K-80 OIDP-11: `/v1/oauth2/revoke` (sağlayıcı token'ları); native oturumlar için SES-11/12 |
| C15 | Back-channel / front-channel / RP-initiated logout (OIDC) | genel olarak sunulur | genel olarak sunulur | ❌ | Faz 2 K-86 (spesifikasyondaki "Single Logout") |
| C16 | JWT access token (RFC 9068), JWKS, anahtar rotasyonu | genel olarak sunulur | genel olarak sunulur | ✅ | SES-08/09, CRY-09/10: `pending → active → retired → revoked`, acil iptal (ADM-06) |
| C17 | Birinci taraf native token modu (rotasyonlu refresh, yeniden kullanım tespiti) | genel olarak sunulur | genel olarak sunulur | ✅ | SES-05: aile iptali, eşzamanlı refresh yeniden kullanım sayılır (`ses_05_concurrent_refresh_of_one_token_is_a_replay`) |
| C18 | mTLS istemci kimlik doğrulaması / sertifikaya bağlı token (RFC 8705) | bazılarında | bazılarında | ❌ | Faz 3 |
| C19 | Birlikte çalışabilir imza algoritmaları (RS256 / ES256) | genel olarak sunulur | genel olarak sunulur | 🟡 | Yalnızca EdDSA (ADR 0001); K-80 çekirdeği de EdDSA ile çıktı. Birçok RP kütüphanesi EdDSA'yı desteklemeyebilir. ES256 K-80'in kalan işi, RS256 için bkz. §11 |

### D. Oturum yönetimi

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| D1 | Sunucu tarafı web oturumu, `__Host-` çerez, kimlik rotasyonu | genel olarak sunulur | genel olarak sunulur | ✅ | SES-03 |
| D2 | CSRF (origin + senkronize token), login CSRF | genel olarak sunulur | genel olarak sunulur | ✅ | SES-04. Her durum değiştiren rota numaralandırılarak test edilir (`authn-server/tests/route_protection.rs`) |
| D3 | Boşta/mutlak ömür, "beni hatırla", paylaşılan cihaz modu | genel olarak sunulur | genel olarak sunulur | ✅ | SES-06/07 |
| D4 | Oturum listesi, tekil/toplu uzaktan kapatma | genel olarak sunulur | genel olarak sunulur | ✅ | SES-11/12 |
| D5 | Eşzamanlı oturum sınırı | bazılarında | bazılarında | ✅ | SES-14 |
| D6 | Refresh token rotasyonu + yeniden kullanım tespiti | genel olarak sunulur | genel olarak sunulur | ✅ | SES-05 (C17 ile aynı mekanizma) |
| D7 | Anında iptal: access token'da çevrimiçi oturum kontrolü | bazılarında | bazılarında | ✅ | `session.access_token_session_check` (varsayılan açık). Kapalıysa gecikme ≤ 10 dk (K-58) |
| D8 | Step-up, `auth_time` / `amr` (RFC 8176) / `acr` | genel olarak sunulur | genel olarak sunulur | ✅ | SES-08/13. Step-up tüm üyeliklerin en katı politikasını uygular |
| D9 | Aktif organizasyon değiştirme ve org politikaları | genel olarak sunulur | bazılarında | ✅ | SES-17 |
| D10 | Cihaza bağlı oturum / token (DPoP, Device Bound Session Credentials) | bazılarında | bazılarında | ❌ | DPoP Faz 2 K-81. DBSC taslak, §9 |
| D11 | Uygulamalar arası tek oturum (SSO oturumu) | genel olarak sunulur | genel olarak sunulur | 🟡 | K-80: tarayıcı oturumu ve verilmiş onayla `/authorize` ekransız kod döner; Single Logout (K-86) yok |

### E. B2B

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| E1 | Organizasyonlar, çoklu üyelik | genel olarak sunulur | genel olarak sunulur | ✅ | ORG-01/02 |
| E2 | RBAC: yerleşik + org'a özel roller, `resource:action` izinleri | genel olarak sunulur | genel olarak sunulur | ✅ | ORG-03/04: tek `authorize` kapısı, ayrıcalık yükseltme koruması |
| E3 | ABAC / ilişki tabanlı (ReBAC) / kaynak düzeyinde ince taneli yetkilendirme | bazılarında | bazılarında | ❌ | Faz 3 |
| E4 | Davetler | genel olarak sunulur | genel olarak sunulur | ✅ | ORG-05: doğrulanmış e-postaya bağlı, eşzamanlı kabulde tek üyelik |
| E5 | Domain doğrulama (DNS TXT) + otomatik katılım | genel olarak sunulur | bazılarında | ✅ | ORG-06 |
| E6 | Domain'in periyodik yeniden doğrulanması | bazılarında | nadiren | ✅ | ORG-13 (K-97, wave 11): periyodik TXT kontrolü, yalnızca kesin yokluk sayılır, eşikte doğrulama kalkar, otomatik katılım durur, domain yöneticilerine bildirim |
| E7 | Org başına MFA / phishing'e dayanıklı MFA / yöntem / IP / oturum ömrü politikası | genel olarak sunulur | bazılarında | ✅ | ORG-07, SES-21, MFA-08 |
| E8 | Org başına SSO bağlantısı ve SSO zorunluluğu | genel olarak sunulur | bazılarında | ❌ | `org_domains.sso_required` saklanıyor ama uygulanmıyor. Faz 2 K-82 |
| E9 | API anahtarları (kapsam, son kullanma, rotasyon, tarayıcıya uygun biçim) | genel olarak sunulur | bazılarında | ✅ | ORG-08: `ak_<env>_…_<crc32>`, rotasyon zinciri iptali |
| E10 | Servis hesapları | genel olarak sunulur | genel olarak sunulur | ✅ | ORG-09 (yalnızca API anahtarıyla; OAuth istemcisi olarak K-84) |
| E11 | Kiracı izolasyonu, IDOR testleri | genel olarak sunulur | genel olarak sunulur | ✅ | ORG-10, ARC-10: `arc_10_org_10_every_endpoint_hides_other_tenants_from_a_session_owner` |
| E12 | Sahiplik devri, bekleme süreli org silme | bazılarında | bazılarında | ✅ | ORG-11/12 |
| E13 | Org audit log'u | genel olarak sunulur | bazılarında | ✅ | AUD-04 |
| E14 | Org webhook'ları | genel olarak sunulur | bazılarında | ✅ | AUD-07: Standard Webhooks, sır rotasyonu, SSRF korumalı |
| E15 | Org başına marka / tema (e-posta, giriş ekranı) | genel olarak sunulur | bazılarında | ❌ | Şablon geçersiz kılma yalnızca global (NTF-02). Faz 3 |

### F. Yönetim

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| F1 | Kullanıcı arama/detay/işlemler (askıya alma, kilit açma, MFA sıfırlama…) | genel olarak sunulur | genel olarak sunulur | ✅ | ADM-02/03: gerekçe zorunlu, MFA sıfırlama passkey'leri de siler (K-01) |
| F2 | Impersonation (süreli, salt-okunur varsayılan, `act`, kullanıcıya bildirim) | genel olarak sunulur | bazılarında | ✅ | ADM-04, K-12 |
| F3 | Audit sorgu, dışa aktarma, bütünlük doğrulama | genel olarak sunulur | bazılarında | ✅ | ADM-07, AUD-02 (anahtarlı HMAC-SHA-256 zinciri, K-77) |
| F4 | Kritik admin işlemlerinde çift onay (four-eyes) | nadiren | nadiren | ✅ | K-66: `/v1/admin/approvals`, `crates/authn-admin/tests/four_eyes.rs` |
| F5 | Break-glass hesabı ve acil durum işlemleri | bazılarında | bazılarında | ✅ | ADM-05/06, K-07/K-11 |
| F6 | Her admin işleminde gerekçe kaydı | bazılarında | nadiren | ✅ | ADM-08, K-39/K-62 (gerekçeler kullanıcı dışa aktarımında) |
| F7 | Personel için ayrıntılı roller (destek / güvenlik / salt-okunur) | genel olarak sunulur | genel olarak sunulur | ✅ | ADM-09/ADM-10 (K-93, wave 11): `support_readonly`, `support`, `security`, `platform_admin`; her admin ucu bir izin bildirir, çift onay yetkisi yalnızca `security` + `platform_admin`. Özel personel rolü yok |
| F8 | Yönetim konsolu (UI) | genel olarak sunulur | genel olarak sunulur | ❌ | Yalnızca API. Faz 3 |
| F9 | Audit/olay akışının SIEM'e aktarımı | genel olarak sunulur | bazılarında | 🟡 | Org webhook'ları ve outbox var. Platform geneli SIEM akışı (syslog/OTLP/nesne depolama) yok. Faz 3 |

### G. Güvenlik

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| G1 | Sızdırılmış şifre tespiti | genel olarak sunulur | bazılarında | ✅ | PWD-03: HIBP k-anonymity + `Add-Padding`, çevrimdışı liste |
| G2 | Bot koruması (CAPTCHA) | genel olarak sunulur | bazılarında | ✅ | PRT-05: Turnstile, hCaptcha, kendi barındırılan proof-of-work |
| G3 | Rate limit (dağıtık) | genel olarak sunulur | genel olarak sunulur | ✅ | PRT-01/02/04: GCRA, PostgreSQL/Redis/bellek, atomik |
| G4 | Hesap kilitleme saldırganın DoS aracına dönüşmeden (yumuşak kilit) | genel olarak sunulur | bazılarında | ✅ | PRT-03: passkey, magic link ve bilinen cihaz geçer. Bütçeler atomik olarak önceden tüketilir |
| G5 | Davranışsal / ML tabanlı anomali tespiti | genel olarak sunulur | nadiren | ❌ | Yalnızca kural tabanlı puanlama (RSK-02). Faz 3 |
| G6 | İmkânsız seyahat (GeoIP) | genel olarak sunulur | bazılarında | ✅ | RSK-05 (K-98, wave 11): `MmdbGeoIp` işletmecinin MaxMind DB dosyasını okur (veri gömülmez), periyodik yeniden yükleme, kaba konum (0,1°) |
| G7 | Anonimleştirici ağ (TOR/proxy) sinyali | genel olarak sunulur | nadiren | ✅ | RSK-02: `anonymizing_networks_file`. Otomatik yenileme yok |
| G8 | Yeni cihaz bildirimi + "bu ben değilim" | genel olarak sunulur | bazılarında | ✅ | RSK-04 |
| G9 | Shared Signals Framework: CAEP / RISC (sürekli erişim değerlendirmesi) | bazılarında | nadiren | ❌ | Faz 2 K-88 |
| G10 | Hesap ön ele geçirme (pre-hijacking) savunması | belirsiz | belirsiz | ✅ | ADR 0002, K-02, K-20. Bkz. §4 |
| G11 | Hesap varlığını sızdırmama (gövde, durum kodu, **süre**) | belirsiz | belirsiz | ✅ | ACC-02, PWD-07, SES-01/18, TST-02. İstatistiksel zamanlama testleri. Sınırı: eski bcrypt/PBKDF2 hash'li hesaplar (bkz. §5) |
| G12 | SSRF korumalı giden HTTP (DNS sabitleme) | belirsiz | belirsiz | ✅ | PRT-12, `prt_12_webhook_delivery_refuses_a_name_rebound_to_loopback` |
| G13 | E-posta bombalama ve SMS pumping koruması | genel olarak sunulur | bazılarında | ✅ | MFA-06, `authn-notify` alıcı başına limit |
| G14 | Zarf şifreleme (AAD'li) + KEK rotasyonu | belirsiz | bazılarında | ✅ | CRY-08, `rotate-kek` (şemadaki her `*_ciphertext` kolonu test ile zorlanır) |
| G15 | KMS / HSM ile anahtar saklama | genel olarak sunulur | bazılarında | 🟡 | `KeyProvider` trait'i var, yalnızca ortam değişkeni uygulaması mevcut. Faz 2 K-96 |
| G16 | Sızan API anahtarının otomatik tespiti (secret scanning ortaklığı) | bazılarında | nadiren | 🟡 | Biçim tarayıcılara uygun (ORG-08). Ortaklık ve otomatik iptal uç noktası yok. Faz 3 |
| G17 | Fuzz, bilinen test vektörleri, bağımlılık/advisory kapıları | belirsiz | bazılarında | ✅ | TST-04/05/07: 13 fuzz hedefi, `cargo deny`, `cargo audit` |
| G18 | FIPS 140 doğrulanmış kriptografi modu | bazılarında | bazılarında | ❌ | RustCrypto crate'leri FIPS doğrulamalı değil. §9 |

Step-up G kategorisinde ayrıca sayılmadı (D8).

### H. Uyumluluk

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| H1 | Kişisel veri dışa aktarma (GDPR md. 15/20, KVKK md. 11) | genel olarak sunulur | bazılarında | ✅ | ACC-10: modüller `DataExporter` ile kendi bölümlerini ekler |
| H2 | Silme / anonimleştirme, bekleme süresi | genel olarak sunulur | genel olarak sunulur | ✅ | ACC-09, AUD-05: audit zinciri bozulmadan takma ad |
| H3 | Onay kayıtları (şartlar/gizlilik sürümü) | genel olarak sunulur | bazılarında | ✅ | ACC-11 |
| H4 | Yapılandırılabilir saklama süreleri | genel olarak sunulur | bazılarında | ✅ | AUD-05, OPS-06 |
| H5 | Veri envanteri belgesi (her tablo) | belirsiz | nadiren | ✅ | `docs/compliance/kvkk-gdpr.md` (her tablonun burada geçtiği test ile zorlanır) |
| H6 | İşlemenin kısıtlanması / yasal bekletme | bazılarında | nadiren | ✅ | K-39, K-62: en çok 180 gün, gerekçeli ve audit'li |
| H7 | NIST SP 800-63B uyum notları | bazılarında | bazılarında | ✅ | `docs/compliance/kvkk-gdpr.md` §9 |
| H8 | Veri yerleşimi (data residency) | genel olarak sunulur | — (kendi barındırma) | 🟡 | Kendi barındırmada veri işletmecinin seçtiği bölgedeki PostgreSQL'de kalır. Kiracı başına bölge yok. Faz 3 |
| H9 | Bağımsız sertifikasyonlar (SOC 2, ISO 27001 vb.) | genel olarak sunulur | uygulanamaz | ❌ | Yazılım değil, işletmeci kuruluşun süreci. Dış pentest (K-72) proje sahibinin kararında |

### I. Geliştirici deneyimi

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| I1 | OpenAPI şeması | genel olarak sunulur | bazılarında | ✅ | OPS-09, `GET /openapi.json`. Belgelenen her yolun yönlendirildiği test edilir |
| I2 | Web SDK (TypeScript; SPA, BFF, SSR) | genel olarak sunulur | genel olarak sunulur | ❌ | Faz 2 K-85 |
| I3 | iOS SDK (Swift) | genel olarak sunulur | bazılarında | ❌ | Faz 2 K-85 |
| I4 | Android SDK (Kotlin) | genel olarak sunulur | bazılarında | ❌ | Faz 2 K-85 |
| I5 | React Native / Flutter SDK | genel olarak sunulur | bazılarında | ❌ | Faz 3 (K-85'in native SDK'ları üzerine ince sarmalayıcı) |
| I6 | Kaynak sunucusu doğrulama kütüphaneleri / örnekleri | genel olarak sunulur | genel olarak sunulur | ❌ | Standart JWKS + EdDSA ile her JWT kütüphanesi doğrulayabilir. Hazır paket yok (örnekler DOC-05'te). K-85 |
| I7 | Barındırılan giriş / kayıt arayüzü | genel olarak sunulur | genel olarak sunulur | ❌ | API-öncelikli ("headless"). Faz 3 |
| I8 | Gömülebilir UI bileşenleri | genel olarak sunulur | nadiren | ❌ | Faz 3 |
| I9 | Webhook'lar | genel olarak sunulur | bazılarında | ✅ | AUD-07 |
| I10 | Domain olayları / transactional outbox | bazılarında | bazılarında | ✅ | AUD-06: en az bir kez, ölü mektup, idempotency anahtarı |
| I11 | Operasyon CLI'ı | bazılarında | genel olarak sunulur | ✅ | OPS-01: `migrate`, `check-config`, `create-admin`, `rotate-signing-key`, `rotate-kek`, `verify-audit-chain`, `migrate-legacy-hashes` … |
| I12 | Terraform / IaC sağlayıcısı | genel olarak sunulur | bazılarında | ❌ | Faz 3. Lisans uyarısı §11 |
| I13 | Yerelleştirme (e-posta/SMS şablonları, hata mesajları) | genel olarak sunulur | genel olarak sunulur | 🟡 | Yalnızca TR ve EN (NTF-02, ARC-08). Şablonlar dosyadan geçersiz kılınabilir |
| I14 | Kendi barındırma: tek binary, yalnızca PostgreSQL (+ opsiyonel Redis) | uygulanamaz | genel olarak sunulur | ✅ | OPS-01/08 |
| I15 | Konteyner imajı, Helm chart, yerel geliştirme ortamı | uygulanamaz | genel olarak sunulur | 🟡 | `Dockerfile` ve `docker-compose.yml` var ama **hiç çalıştırılmadı** (K-55). Helm yok. Faz 2 K-99 |
| I16 | Çok bölgeli (multi-region) dağıtım | genel olarak sunulur | bazılarında | ❌ | Tek PostgreSQL birincili varsayılıyor. Faz 3 |
| I17 | Kararlı hata kodları (TR/EN mesaj) | genel olarak sunulur | bazılarında | ✅ | ARC-08: `codes::all()` test ile zorlanır |

### J. Operasyon

| # | Özellik | Barındırılan IdP'ler | Açık kaynak sunucular | Biz | Kanıt / not |
|---|---------|----------------------|-----------------------|-----|-------------|
| J1 | Yatay ölçekleme (durumsuz instance'lar, çoklu instance güvenli işler) | uygulanamaz | genel olarak sunulur | ✅ | OPS-06: `SKIP LOCKED`, advisory lock |
| J2 | HA referans mimarisi (PostgreSQL HA, yük dengeleyici, yedek) | uygulanamaz | bazılarında | ❌ | Faz 2 K-99 |
| J3 | Yapılandırılmış log, kişisel veri maskeleme | uygulanamaz | genel olarak sunulur | ✅ | OPS-03 |
| J4 | Prometheus metrikleri | uygulanamaz | genel olarak sunulur | ✅ | OPS-04 (ayrı port) |
| J5 | Dağıtık izleme (OpenTelemetry) | uygulanamaz | bazılarında | ✅ | OPS-11/OPS-12 (K-92, wave 11): opsiyonel OTLP/HTTP (`otel` özelliği), W3C Trace Context, span'lerde kişisel veri yok (testle zorlanır). Yalnızca HTTP span'i |
| J6 | Sağlık uçları | uygulanamaz | genel olarak sunulur | ✅ | OPS-05 |
| J7 | Zarif kapanış | uygulanamaz | genel olarak sunulur | ✅ | OPS-07 |
| J8 | Şema migration'ları (expand/contract, sürüm aralıkları) | uygulanamaz | genel olarak sunulur | ✅ | OPS-10, contracts §6 |
| J9 | Eski şifre hash'lerinin içe aktarılması (bcrypt, PBKDF2, MD5/SHA-1 sarmalı) | genel olarak sunulur | bazılarında | ✅ | CRY-04, `migrate-legacy-hashes`. İlk girişte Argon2id'ye geçilir |
| J10 | Diğer hash biçimleri (scrypt ve türevleri, vb.) | bazılarında | bazılarında | ❌ | Faz 2 K-94 |
| J11 | Başka bir IdP'den toplu kullanıcı içe aktarma aracı | genel olarak sunulur | genel olarak sunulur | ❌ | `migrate-legacy-hashes` yalnızca var olan kullanıcıların hash'lerini sarar. Faz 2 K-94 |
| J12 | Anahtar rotasyonu (imza anahtarı, KEK, pepper) | uygulanamaz | bazılarında | ✅ | CRY-02/10, OPS-01 |
| J13 | En az yetkili veritabanı rolleri | uygulanamaz | nadiren | ✅ | OPS-10, K-42: `authn_apply_least_privilege` |
| J14 | Runbook'lar (olay müdahalesi, rotasyon, yedekleme) | genel olarak sunulur | bazılarında | ✅ | DOC-06 (wave 7): `docs/operations/` — yapılandırma, dağıtım, anahtar yönetimi, olay müdahalesi, yedekleme, izleme, ölçekleme, admin kurtarma, en az yetki. Helm/HA referansı ayrı (K-99) |
| J15 | Performans bütçeleri ve benchmark'lar | belirsiz | bazılarında | ✅ | K-70 (`72b1527`, wave 5B): `docs/operations/performance.md` (uç başına p50/p99 bütçeleri, Argon2id ölçümü), `authn-server/benches/hot_paths.rs`, yük testi `tests/load.rs` |

---

## 4. Zaten önde olduğumuz yerler

Bu bölümdeki her iddia kod ve testle desteklenir. Rakiplerin bunları yapamadığını **iddia etmiyoruz**. Söylediğimiz şu: bu davranışları, önde gelen ürünlerin kamuya açık belgelerinde varsayılan olarak tanıtıldığını yaygın biçimde görmedik ve bizde varsayılan olarak açıklar.

| # | Güçlü yan | Neden önemli | Kanıt (test) |
|---|-----------|--------------|--------------|
| 1 | **Kritik admin işlemlerinde four-eyes** (K-66). Bir admin istek açar, başka bir admin onaylar. Onay tek kullanımlıktır, parametre hash'ine bağlıdır ve süreli tutulur. Hedef admin onaylayan olamaz. Üretimde kapatılamaz | Ele geçirilmiş tek bir admin hesabı toplu kesinti yaratamaz ve diğer adminleri kaldıramaz | `adm_06_k66_emergency_needs_an_approval_and_uses_it_once`, `adm_03_k66_self_approval_target_approval_and_foreign_use_are_refused`, `adm_06_k66_parameter_tampering_is_refused`, `adm_03_k66_concurrent_uses_of_one_approval_run_once` |
| 2 | **Ekleme-yalnızca, anahtarlı hash zincirli audit log** (AUD-02, K-77). Zincir `HMAC-SHA-256(K_v, prev_hash ‖ kayıt)` ile kurulur: veritabanına yazabilen ama anahtarı olmayan biri zinciri yeniden hesaplayamaz. Uygulama rolünün `UPDATE`/`DELETE` yetkisi yoktur, tetikleyici de korur. Eşzamanlı eklemede zincir çatallanmaz. Kişisel veri zincir dışında tutulur, böylece silme zinciri bozmaz | Kurcalama tespit edilir. Hesap silme ile audit bütünlüğü çatışmaz | `aud_02_concurrent_writers_never_fork_the_chain`, `k_77_forger_without_the_key_cannot_recompute_the_chain`, `aud_04_k62_a_hold_lasts_at_most_180_days` |
| 3 | **Hesap ön ele geçirme (pre-hijacking) savunması tasarımın parçası** (ADR 0002). Doğrulanmamış kayıt hesabı aktive etmez. Sosyal girişte adres rezervasyonu yapılır. E-posta değişikliği geri alınınca saldırganın eklediği tüm giriş yöntemleri silinir | Bilinen bir hesap ele geçirme sınıfı kapatılır | `acc_02_attacker_first_link_alone_never_activates_the_attackers_password`, `soc_05_reserved_address_gets_no_new_account`, `acc_07_k20_revert_removes_every_login_method_the_attacker_added` |
| 4 | **En az yetkili veritabanı rolleri**, çalıştırılabilir bir fonksiyonla kurulur. Fonksiyon tehlikeli rolleri (tablo sahibi, süper kullanıcı, `BYPASSRLS`, `pg_*_all_data` üyesi) reddeder ve çağıranın `search_path`'ine güvenmez | SQL enjeksiyonu ya da uygulama ele geçirilse bile audit silinemez | `ops_10_least_privilege_grants_are_exact`, `ops_10_roles_inheriting_owner_or_peer_privileges_are_refused`, `ops_10_the_application_runs_as_the_restricted_role` |
| 5 | **Hesap varlığı süre üzerinden de sızmaz.** Kayıt, şifre sıfırlama, magic link ve kilit yanıtlarının süreleri istatistiksel testlerle karşılaştırılır | Kullanıcı numaralandırması (enumeration) zorlaşır | `acc_02_signup_timing_does_not_reveal_existing_accounts`, `prt_03_lock_response_does_not_reveal_account_existence`, `ses_18_unknown_addresses_get_the_same_answer_and_no_mail` |
| 6 | **Yarışa dayanıklı giriş bütçeleri.** CAPTCHA ve yumuşak kilit bütçeleri doğrulamadan önce atomik olarak tüketilir. Yumuşak kilit hesabı kapatmaz | Paralel tahminler eşikleri aşamaz. Kilit DoS aracına dönüşmez | `crates/authn-protect/tests/login.rs`, HANDOFF §3.4 (yüksek bulgu) |
| 7 | **Refresh yeniden kullanımında aile iptali**, eşzamanlı refresh dahil | Çalınan refresh token'ı fark edilir | `ses_05_refresh_rotates_and_replay_revokes_the_family`, `ses_05_concurrent_refresh_of_one_token_is_a_replay` |
| 8 | **SSRF'ye dayanıklı giden HTTP.** DNS'i kendimiz çözeriz, adresi sabitleriz, IPv6'yı izin listesiyle sınıflandırırız, bulut metadata adreslerini reddederiz | Webhook ve OIDC çağrıları iç ağa saldırı aracı olamaz | `prt_12_webhook_delivery_refuses_a_name_rebound_to_loopback`, `crates/authn-protect` tablo testleri + proptest |
| 9 | **Kiracı izolasyonu her uçta saldırgan gözüyle test edilir.** Başka kiracının kaynağı, var olmayanla aynı `404`'ü alır | B2B veri sızıntısı riski azalır | `arc_10_org_10_every_endpoint_hides_other_tenants_from_a_session_owner` |
| 10 | **Impersonation sınırları.** Süreli ve varsayılan salt-okunurdur. Kullanıcıya bildirilir. Admin askıya alınınca biter. Passkey ekleyemez. Adminin çerezini ezmez | Destek erişimi kalıcı arka kapıya dönüşmez | `adm_04_header_impersonation_rotation_never_sets_a_cookie`, `crates/authn-server/tests/admin_e2e.rs` |
| 11 | **Lisans ve tedarik zinciri disiplini.** Yalnızca izin verici lisanslar kullanılır (ürün binary'sindeki tek istisna `webauthn-rs`, MPL-2.0; ayrıca yalnızca geliştirme amaçlı, dağıtılmayan `fuzz/` workspace'inde `libfuzzer-sys`, NCSA). `cargo deny` + `cargo audit` CI'da çalışır. Üçüncü taraf bildirimleri otomatik üretilir | Ticari kullanıma engel yok. Kendi barındırmada kaynak kodun tamamı işletmecide | `deny.toml`, `licenses/README.md`, CI `licence-notices` işi |
| 12 | **Kendi barındırma ve veri sahipliği.** Tek binary, veri işletmecinin PostgreSQL'inde kalır | KVKK açısından yurt dışı aktarımı işletmeci kontrol eder | OPS-01, `docs/compliance/kvkk-gdpr.md` §7 |

## 5. Geride olduğumuz yerler

Dürüst liste, etkisi büyükten küçüğe:

1. **OAuth 2.1 / OIDC sağlayıcısı değiliz (C1–C15).** Önde gelen ürünlerin tamamına yakını bir yetkilendirme sunucusudur. Biz bugün yalnızca kendi API'mize oturum ve token veriyoruz. Başka bir uygulamaya "X ile giriş yap" sunamıyoruz, üçüncü taraf istemci barındıramıyoruz, uygulamalar arası SSO veremiyoruz. Faz 2'nin çekirdeği budur (K-80).
2. **Kurumsal federasyon yok (B6–B13, E8).** B2B satışında organizasyon başına SSO ve SCIM sık sık satın alma koşuludur. SAML ise birçok kurumsal IdP'de hâlâ birincil protokoldür ve bizde yok (Faz 3).
3. **SDK, barındırılan UI ve bileşen yok (I2–I8).** Mobil ve web entegrasyonu bugün yalnızca HTTP API ve belgeyle yapılıyor. Rakipler genellikle hazır SDK ve ekran sunar. Güvenli token saklama gibi işler entegratöre kalıyor.
4. **İmza algoritması birlikte çalışabilirliği zayıf (C19).** Yalnızca EdDSA destekliyoruz. Kaynak sunucuları ve RP kütüphanelerinin bir kısmı EdDSA desteklemeyebilir.
5. **Gönderene bağlı token (DPoP/mTLS) yok (C7, C18, D10).** Mobil access/refresh token'ı çalınırsa taşıyıcı (bearer) olarak kullanılabilir. Refresh yeniden kullanım tespiti bunu yalnızca kısmen azaltır.
6. **Risk motoru kural tabanlı (G5).** İmkânsız seyahat artık işletmecinin GeoIP veritabanıyla çalışıyor (K-98); davranışsal/ML sinyali ve paylaşılan sinyal (CAEP/RISC) yok.
7. **Push MFA, telefonla giriş ve kullanıcı adı yok (A15–A17).** B2C'de dönüşüm oranını etkileyebilir. Güvenlik açısından ise bilinçli bir tercih (SMS zayıf faktör).
8. **Yönetim UI'ı yok (F8).** Personel rolleri K-93 ile eklendi (F7); özel (kuruluşa göre tanımlanan) personel rolü yok.
9. **Operasyon olgunluğu doğrulanmadı.** Docker imajı hiç çalıştırılmadı (K-55). Helm/HA referansı (K-99) yok (OpenTelemetry K-92 ile eklendi). Runbook'lar (DOC-06, wave 7) ve performans bütçeleri (K-70, wave 5B) artık var, ama bütçeler paylaşımlı bir geliştirme ortamındaki release ölçümüne dayanır (`performance.md` "Ölçüm ortamı"); üretim benzeri donanımda doğrulanmadı. Bağımsız dış pentest yapılmadı (K-72).
10. **Başka IdP'den göç aracı sınırlı (J10, J11).** bcrypt/PBKDF2/MD5/SHA-1 hash'leri doğrulanıyor, ama toplu kullanıcı içe aktarma ve scrypt türevi biçimler yok. Eski bcrypt/PBKDF2 hash'li hesaplarda giriş süresi farklı olduğu için göç tamamlanana kadar kısmi bir hesap varlığı sinyali kalıyor (`authn-crypto` README).
11. **Yalnızca iki dil (I13), kiracı başına marka yok (E15), çok bölgeli dağıtım yok (I16, H8).**

---

## 6. Önceliklendirme ölçütleri

Her eksik dört ölçütle puanlandı. Sıralamada ağırlık sırası bu tablodaki sıradır:

| Ölçüt | Anlamı |
|-------|--------|
| **Güvenlik değeri** | Bir saldırı sınıfını kapatıyor mu (token hırsızlığı, ele geçirme, yetki sızıntısı)? Yanlış uygulanırsa yeni bir saldırı yüzeyi açıyor mu (eksi puan)? |
| **Müşteri talebi** | B2C web, B2B SaaS ve mobil için ayrı ayrı: satın alma koşulu mu, dönüşümü mü etkiliyor, yoksa "olsa iyi olur" mu? |
| **Bağımlılık** | Başka kalemlerin önünü açıyor mu? (K-80 neredeyse her şeyin önünü açar) |
| **Çaba** | Uzman-hafta. Aynı değerde olanlardan küçük olan öne alınır |

Ayrıca her kalem şu kurallara uyar: kendi kriptografimizi yazmıyoruz (yalnızca denetlenmiş crate'leri birleştiriyoruz), her yeni protokol ayrıştırıcısı fuzz edilir, her kalem "uzman yazar + bağımsız denetçi" deseniyle yapılır (HANDOFF §6).

## 7. Faz 2

Sıra öncelik sırasıdır. Takip [`remaining-work.md` §10.6](handoff/remaining-work.md)'dadır.

### 7.1 Özet tablo

| Sıra | # | Kalem | Standartlar | Güvenlik değeri | Talep (B2C / B2B / mobil) | Çaba (uzman-hafta) | Bağımlılık |
|------|---|-------|-------------|-----------------|---------------------------|--------------------|------------|
| 1 | K-80 | OAuth 2.1 / OIDC sağlayıcısı çekirdeği | OAuth 2.1 taslağı, RFC 6749, 7636, 8252, 8414, 7009, 7662, 9068, 9207, 8707; OIDC Core, Discovery | Yüksek (doğru yapılırsa); yüksek risk yüzeyi | orta / **çok yüksek** / yüksek | 8–12 | — |
| 2 | K-81 | DPoP (kendi native token'larımız + sağlayıcı) | RFC 9449, RFC 7638 | **Çok yüksek** (token hırsızlığı) | düşük / orta / **yüksek** | 4–6 | Native kısmı bağımsız; sağlayıcı kısmı K-80 |
| 3 | K-82 | Kurumsal SSO: org başına OIDC IdP, HRD, `sso_required`, JIT | OIDC Core (RP olarak), RFC 7636 | Yüksek (merkezi deprovisioning) | — / **çok yüksek** / orta | 4–6 | `authn-oidc-client` doğrulama ilkelleri |
| 4 | K-83 | SCIM 2.0 sunucusu | RFC 7643, 7644 | Yüksek (işten ayrılanın anında kapatılması) | — / **çok yüksek** / — | 3–4 | K-82 (önerilir, zorunlu değil) |
| 5 | K-84 | Makineden makineye: client credentials, `private_key_jwt`, servis hesabı istemcileri | RFC 6749 §4.4, RFC 7521/7523 | Orta-yüksek (statik API anahtarı yerine kısa ömürlü token) | — / yüksek / — | 2–3 | K-80 |
| 6 | K-85 | SDK'lar: TypeScript (web/BFF + kaynak sunucusu), iOS, Android | RFC 8252, RFC 9449 istemci tarafı, WebAuthn | Orta (güvenli token saklama varsayılan olur) | yüksek / yüksek / **çok yüksek** | 8–12 | K-80 (OAuth akışları), K-81 (DPoP) |
| 7 | K-86 | Oturum kapatma ailesi (Single Logout) | OIDC RP-Initiated Logout, Back-Channel Logout, Front-Channel Logout | Orta-yüksek | orta / yüksek / orta | 2–3 | K-80, K-82 |
| 8 | K-87 | PAR + JAR + FAPI 2.0 güvenlik profili tabanı | RFC 9126, RFC 9101, FAPI 2.0 Security Profile | Yüksek (istek bütünlüğü) | düşük / orta / orta | 2–3 | K-80, K-81 |
| 9 | K-88 | Shared Signals: CAEP/RISC verici + alıcı | OpenID SSF, CAEP, RISC; RFC 8417 (SET) | Yüksek (oturumun anında kapatılması) | düşük / yüksek / düşük | 3–5 | K-80 (alıcı/verici kayıtları), K-82 |
| 10 | K-89 | Device Authorization Grant | RFC 8628 | Orta (kimlik avı riski: ekranda onay şart) | orta / orta / orta (TV, CLI) | 2–3 | K-80 |
| 11 | K-90 | Token Exchange (delegasyon, servisler arası) | RFC 8693 | Orta | — / orta / — | 2–3 | K-80, K-84 |
| 12 | K-91 | Dinamik istemci kaydı (kapalı varsayılan, ilk erişim token'ı) | RFC 7591, RFC 7592 | Düşük-orta (açık bırakılırsa risk) | — / orta / — | 1–2 | K-80 |
| 13 | K-92 | OpenTelemetry izleme (OTLP) | OpenTelemetry, W3C Trace Context | Düşük (dolaylı: olay müdahalesi) | operasyon | 1 | — |
| 14 | K-93 | Personel rolleri (destek / güvenlik / salt-okunur / tam admin) | — | Yüksek (iç tehdit, en az yetki) | operasyon | 2 | — |
| 15 | K-94 | Toplu kullanıcı içe/dışa aktarma + ek hash biçimleri + göç rehberleri | — | Orta (göç penceresini kısaltır) | yüksek / yüksek / — | 2–3 | — |
| 16 | K-95 | FIDO MDS3 + WebAuthn Level 3 (conditional create, Signal API) | FIDO MDS3, WebAuthn L3 | Orta | yüksek / orta / yüksek | 2 | `webauthn-rs` desteği |
| 17 | K-96 | KMS/HSM `KeyProvider` uygulamaları | — | Yüksek (KEK uygulama belleğinde kalmaz) | operasyon / B2B | 2–3 | — |
| 18 | K-97 | Domain'in periyodik yeniden doğrulanması | — | Orta (el değiştiren domain) | — / orta / — | 0,5–1 | — |
| 19 | K-98 | GeoIP uygulaması (MMDB okuyucu, işletmecinin veritabanı) | — | Orta (imkânsız seyahat) | orta / orta / orta | 1 | — |
| 20 | K-99 | HA referans dağıtımı: Helm chart, PostgreSQL HA ve yedek rehberi | — | Düşük-orta (kullanılabilirlik) | operasyon | 1–2 | K-55 (Docker doğrulaması) |

**Toplam kaba çaba:** ~52–79 uzman-hafta. Paralel iki iş hattıyla (HANDOFF: aynı anda en fazla ~2 ağır iş) yaklaşık 6–9 ay.

**Önerilen iş hatları:**

```
Hat 1 (protokol):   K-80 ──► K-84 ──► K-87 ──► K-86 ──► K-89 ──► K-90 ──► K-91
                      │
Hat 2 (güvenlik/B2B): K-81(native) ──► K-82 ──► K-83 ──► K-88 ──► K-81(sağlayıcı, K-80 sonrası)
                      │
Hat 3 (ince işler, aralara): K-92, K-93, K-97, K-98, K-96, K-94, K-95, K-99
                      │
SDK'lar (K-85): K-80 ve K-81 API'leri dondurulunca başlar (ayrı depolar)
```

### 7.2 Kalem ayrıntıları

**K-80 — OAuth 2.1 / OIDC sağlayıcısı çekirdeği** (yeni crate `authn-oidc-provider`, migration aralığı 3000–3099)
- Kapsam: istemci kaydı (admin API ve org API, gizli/açık istemci, `redirect_uri` tam eşleşme), `/authorize` (yalnızca `code`, PKCE S256 **zorunlu**, `plain` yok, implicit ve ROPC yok), `/token` (kod tek kullanımlık; yeniden kullanılırsa o koddan çıkan token'lar iptal edilir), refresh rotasyonu (SES-05 mekanizmasının yeniden kullanımı), ID token, `userinfo`, discovery ve RFC 8414 meta verisi, RFC 7009 revocation, RFC 7662 introspection'ın OAuth istemci kimlik doğrulamasıyla genişletilmesi, RFC 9207 `iss` yanıt parametresi, RFC 8707 resource indicators (`aud` kısıtı), onay (consent) kayıtları ve kullanıcının onayları geri alması.
- Arayüz: "headless". Giriş ve onay ekranlarını işletmecinin kendi önyüzü sunar. Sağlayıcı yapılandırılmış bir `interaction_url`'e yönlendirir; etkileşim kimliği tek kullanımlık ve tarayıcıya bağlıdır. Giriş, mevcut `authn-session` akışlarıyla yapılır (`SessionIssuer` portu). Barındırılan UI Faz 3'tedir.
- İmza: EdDSA'ya ek olarak **ES256** (`p256 0.14`, gizli anahtar işlemleri yalnızca bu sürümle; HANDOFF §7). Algoritma istemci başına sabitlenir, `alg` başlığına güvenilmez (ADR 0001 ilkesi). RS256 için bkz. §11.
- Doğrulama: OpenID Foundation uyumluluk test paketinin (conformance suite) Basic OP ve Config OP profilleri CI dışı bir iş olarak koşturulur. Sertifika başvurusu proje sahibinin kararıdır.
- Güvenlik testleri (en az): kod yeniden kullanımı, PKCE düşürme, `redirect_uri` varyantları (open redirect, alt yol, büyük/küçük harf), mix-up (RFC 9207), istemciler arası kod enjeksiyonu, `state`/`nonce` tekrar oynatma, onay atlatma, kiracılar arası istemci erişimi (ARC-10), ayrıştırıcı fuzz'ı.

**K-81 — DPoP** (`authn-crypto`: kanıt JWT ayrıştırma/doğrulama + fuzz hedefi; `authn-session`: native token bağlama; K-80 sonrası `authn-oidc-provider`)
- Native modda (SES-05) refresh token'ı ve access token'ı istemci anahtarına bağlanır (`cnf.jkt`, RFC 7638 parmak izi). `jti` tekrar oynatma deposu kullanılır, sunucu `nonce`'u desteklenir. Kanıt algoritmaları: ES256 ve EdDSA (yalnızca açık anahtarla doğrulama).
- Kaynak sunucuları için doğrulama kuralları DOC-05'e eklenir. Mobil SDK'lar (K-85) anahtarı Keychain/Keystore'da, mümkünse donanımda üretir.
- Mevcut native akışın bozulmaması için org/uygulama başına "DPoP zorunlu" politikası ile kademeli geçiş yapılır.

**K-82 — Kurumsal SSO** (yeni crate `authn-sso`; `authn-oidc-client`'ın ID token doğrulama ilkelerini kullanır; `authn-org` `sso_required`'ı uygular)
- Org başına OIDC bağlantıları **veritabanında** tutulur (sosyal sağlayıcılar yapılandırma dosyasında). İstemci sırları zarf şifrelidir (CRY-08, AAD'li).
- Doğrulanmış domain → bağlantı eşlemesi (HRD) kurulur. `sso_required` domain'inde şifre, magic link ve sosyal giriş reddedilir; break-glass için org sahibine tanımlı bir istisna yolu açılır.
- JIT: ilk SSO girişinde üyelik açılır ve IdP grup/claim → rol eşlemesi yapılır (ORG-04 yükseltme kurallarıyla). Kimlik `identities` tablosunda `(provider = sso:<connection_id>, subject)` olarak tutulur.
- Pre-hijacking (ADR 0002) ve K-02 rezervasyon kuralları korunur. IdP'nin `email_verified` beyanına varsayılan olarak güvenilmez, domain doğrulamasına dayanılır.

**K-83 — SCIM 2.0** (yeni crate `authn-scim`)
- `/scim/v2/{org}/Users`, `/Groups`, `ServiceProviderConfig`, `Schemas`, `ResourceTypes`; `PATCH` ve filtre ayrıştırıcısı (kendi ayrıştırıcımız, fuzz hedefi, karmaşıklık sınırı).
- Kimlik doğrulama: org'a bağlı, yalnızca `scim:*` kapsamlı API anahtarı (ORG-08 biçimi).
- Deprovisioning (`active=false` / `DELETE`) üyeliği askıya alır ve aynı transaction'da oturumları `SessionRevoker` ile kapatır. Gruplar → rol eşlemesi ORG-04 kurallarına tabidir.

**K-84 — Makineden makineye** (`authn-oidc-provider`, `authn-org`)
- Servis hesapları OAuth istemcisi olabilir. `client_credentials` ile kısa ömürlü JWT verilir. İstemci kimlik doğrulaması `private_key_jwt` (RFC 7523) ile yapılır, paylaşılan sır yalnızca geçiş için tutulur.
- API anahtarları kalır. Belgede "statik anahtar yerine kısa ömürlü token" önerisi yer alır.

**K-85 — SDK'lar** (ayrı depolar; LIC-01 bu ekosistemlerde de geçerlidir)
- TypeScript: tarayıcı (PKCE, BFF deseni öncelikli, token'lar mümkünse tarayıcıda tutulmaz), Node kaynak sunucusu doğrulayıcısı (JWKS, EdDSA/ES256, DPoP).
- iOS (Swift): ASWebAuthenticationSession, passkey (AuthenticationServices), Keychain, DPoP anahtarı Secure Enclave'de.
- Android (Kotlin): Custom Tabs, Credential Manager, Keystore (StrongBox varsa).
- React Native / Flutter sarmalayıcıları Faz 3'tedir.

**K-86 — Oturum kapatma ailesi:** RP-initiated logout (`post_logout_redirect_uri` tam eşleşme), back-channel logout (imzalı logout token, SSRF korumalı `HttpClient` ile teslim, outbox üzerinden yeniden deneme) ve front-channel logout (iframe; üçüncü taraf çerez kısıtları nedeniyle "en iyi çaba" olarak belgelenir). K-82'de dış IdP'den gelen logout da kabul edilir.

**K-87 — PAR + JAR + FAPI 2.0 tabanı:** PAR (RFC 9126) istemci başına zorunlu kılınabilir. İmzalı istek nesnesi (RFC 9101) desteklenir. Bir "FAPI 2.0 profili" bayrağı PAR + DPoP/mTLS + PKCE + kısa kod ömrü kombinasyonunu zorlar. mTLS (RFC 8705) Faz 3'tedir.

**K-88 — Shared Signals (CAEP/RISC)** (yeni crate `authn-ssf`): Verici rolünde oturum iptali, kimlik bilgisi değişikliği ve hesap devre dışı kalması gibi olaylar SET (RFC 8417) olarak gönderilir; mevcut outbox ve audit olaylarından beslenir. Alıcı rolünde kurumsal IdP'den gelen "oturum iptal edildi" olayı oturumları kapatır. Push/poll teslimi SSRF korumalı istemciyle yapılır.

**K-89 — Device flow:** Kullanıcı kodu kısa, karıştırılabilir karakterlerden arınmış ve deneme sınırlıdır. Onay ekranında istemci adı ve "bu isteği siz mi başlattınız?" uyarısı gösterilir (device code kimlik avına karşı). Polling için `slow_down` ve rate limit uygulanır.

**K-90 — Token Exchange:** `act` claim modeli ADM-04'te zaten var. Bu kalem, izinli `subject_token_type`/`actor_token_type` çiftlerini ve `audience` politikasını istemci başına açıkça tanımlar; varsayılan reddettir.

**K-91 — Dinamik istemci kaydı:** Varsayılan **kapalı**. Açıkken ilk erişim token'ı (initial access token) zorunlu, `redirect_uri` kuralları K-80 ile aynı ve kayıt yönetimi RFC 7592'ye uygun olur. Ajan/araç ekosistemlerindeki (ör. MCP yetkilendirmesi) talep nedeniyle B2B önemi artıyor. İlgili yeni taslaklar (istemci meta veri belgeleri) izlenir.

**K-92 — OpenTelemetry** (✅ wave 11, OPS-11/OPS-12): `tracing-opentelemetry` + OTLP dışa aktarıcı (varsayılan kapalı). Span özniteliklerinde kişisel veri ve sır bulunmaz (OPS-03 maskeleme kuralları). Bir test, bilinen sır alanlarının span'lere girmediğini zorlar.

**K-93 — Personel rolleri** (`authn-admin`): `support_readonly`, `support`, `security`, `platform_admin` rolleri ve her admin ucu için izin tablosu. Four-eyes (K-66) yalnızca `platform_admin` ve `security` için onay yetkisi verir. Break-glass değişmez.

**K-94 — Göç araçları** (`authn-server` CLI + `authn-account` + `authn-crypto`): JSONL içe aktarma (kullanıcı, doğrulanmış e-posta durumu, hash, sosyal kimlikler, TOTP sırları zarf şifreli). Kesintiye uğrarsa yeniden çalıştırılabilir. Kişisel veri yalnızca girdi dosyasında bulunur, loglara yazılmaz. Ek hash biçimleri: scrypt (standart parametreli). Yaygın bir barındırılan hizmetin değiştirilmiş scrypt varyantı ancak denetlenmiş ilkellerin (scrypt + AES) bilinen test vektörleriyle birleşimi olarak eklenir. Kendi algoritmamızı yazmayız; vektör yoksa eklemeyiz. Ayrıca her biçim için ilk başarılı girişte Argon2id'ye geçilir (CRY-04 ile aynı).

**K-95 — FIDO MDS3 + WebAuthn L3** (`authn-webauthn`): MDS BLOB'u indirilip imza zinciri doğrulanır, önbelleğe alınır. Böylece AAGUID → model adı listede gösterilir ve iptal edilmiş (revoked) authenticator'lar reddedilir. Conditional create (şifreyle girişten sonra otomatik passkey önerisi) ve Signal API (silinen passkey'i istemciye bildirme), `webauthn-rs` desteğine bağlıdır. Destek yoksa yalnızca belgelenir.

**K-96 — KMS/HSM:** `KeyProvider` uygulamaları: bulut KMS'leri ve Vault Transit benzeri bir HTTP API. HTTP, `authn-protect`'in güvenilir `HttpClient`'ı üzerinden yapılır. KEK uygulamaya açık metin olarak gelmez; DEK'ler KMS'te sarılır/açılır, kısa süreli önbellekle (gecikme bütçesi K-70).

**K-97 — Domain yeniden doğrulama** (`authn-org`): Periyodik TXT kontrolü yapılır. Ardışık başarısızlıkta domain `unverified` olur, otomatik katılım ve `sso_required` durur, org sahiplerine bildirim gider.

**K-98 — GeoIP** (`authn-protect`; ✅ wave 11, RSK-05): MMDB biçimli bir veritabanını okuyan `GeoIpLookup` uygulaması. Veritabanı **gömülmez** (RSK-02), işletmeci kendi lisansıyla sağlar.

**K-99 — HA referansı:** Helm chart (uygulama durumsuz, işler çoklu instance güvenli), PostgreSQL HA ve yedek/geri yükleme rehberi, Redis'in opsiyonel olduğu yapılandırma. K-55 (Docker'ın gerçekten çalıştırılması) önkoşuldur.

## 8. Faz 3

Sıra öncelik sırasıdır. Çabalar kabadır.

| Sıra | Kalem | Standartlar | Gerekçe | Çaba |
|------|-------|-------------|---------|------|
| 1 | **SAML 2.0 SP** (kurumsal IdP'den giriş) | SAML 2.0 Core/Bindings/Profiles, XML-DSig, Exc-C14N | B2B'de sık satın alma koşulu. Yüksek risk (imza sarmalama/XSW, XXE, kanonikleştirme); yalnızca olgun ve denetlenmiş bir XML-DSig yığınıyla yapılmalı (§11) | 6–8 |
| 2 | **SAML 2.0 IdP** | aynı | Eski kurumsal uygulamalara SSO | 4–6 |
| 3 | Barındırılan giriş UI + gömülebilir bileşenler | WCAG 2.2, CSP | B2C dönüşümü, hızlı entegrasyon. Sıkı CSP ve tema | 8–12 |
| 4 | İnce taneli yetkilendirme (ReBAC/ABAC, politika motoru) | OpenID AuthZEN (taslak, izlenmeli) | B2B'de kaynak düzeyi paylaşım | 6–10 |
| 5 | Push MFA (kendi doğrulayıcı uygulaması, numara eşleştirme) | — | Kullanılabilirlik. Lisans/RSA notu §11 | 6–8 |
| 6 | React Native / Flutter SDK | — | Mobil talebi | 3–4 |
| 7 | Yönetim konsolu UI | — | Operasyon | 6–8 |
| 8 | Org başına marka/tema, daha fazla dil | — | B2B beyaz etiket | 2–3 |
| 9 | Platform audit akışı (SIEM: syslog/OTLP logs/nesne depolama) | RFC 5424, OTLP | Kurumsal uyum | 2 |
| 10 | mTLS istemci kimlik doğrulaması / sertifikaya bağlı token | RFC 8705 | FAPI, finans | 2–3 |
| 11 | RAR | RFC 9396 | Ödeme/açık bankacılık türü onaylar | 2–3 |
| 12 | CIBA | OpenID CIBA | Çağrı merkezi / ayrık cihaz onayı | 3–4 |
| 13 | LDAP/AD federasyonu, dizin senkronizasyonu | RFC 4511 | Şirket içi müşteriler. SCIM çoğu durumu karşılar | 4–6 |
| 14 | Telefonla giriş, kullanıcı adı tanımlayıcı | — | B2C pazarlarında talep. SMS zayıf faktör olarak kalır | 3–4 |
| 15 | Terraform/IaC sağlayıcısı + yönetim CLI'ı | — | Platform ekipleri. Lisans §11 | 3–4 |
| 16 | Çok bölgeli dağıtım ve kiracı başına veri yerleşimi | — | Büyük B2B, düzenlemeler | 8+ |
| 17 | Davranışsal anomali tespiti | — | Gizlilik ve açıklanabilirlik şartıyla | 4–6 |
| 18 | API anahtarı sızıntı tarama ortaklığı + otomatik iptal uç noktası | — | Sızan anahtarın dakikalar içinde ölmesi | 1–2 |

## 9. Daha sonra / izlenecekler

- **Device Bound Session Credentials (DBSC):** Web oturum çerezini cihaza bağlayan taslak. Tarayıcı desteği ve standartlaşma olgunlaşınca değerlendirilir.
- **FIPS 140 modu:** FIPS doğrulanmış bir kripto modülü (ör. bir AWS-LC FIPS yapılandırması) gerektirir. Lisansı ve geçişli bağımlılıkları LIC-01'e göre ayrıca değerlendirilmeli. Yalnızca kamu müşterisi talebi olursa yapılır.
- **OpenID Federation, doğrulanabilir kimlik bilgileri (OpenID4VCI / OpenID4VP), dijital kimlik cüzdanları:** Kamu kimlik cüzdanları yaygınlaştıkça önem kazanabilir. Standart ve düzenleme durumu izlenir.
- **OpenID sertifikasyonu:** K-80 sonrası uyumluluk testleri geçerse sertifika başvurusu (proje sahibinin kararı).
- **Bağımsız dış pentest (K-72):** Her büyük protokol eklemesinden (K-80, K-82, SAML) sonra tekrarlanmalı.

## 10. Mevcut mimarideki genişleme noktaları

Faz 2/3, mevcut modüllerin yeniden yazılmasını gerektirmeyecek şekilde hazırlandı (spesifikasyon §0):

| Genişleme noktası | Nerede | Hangi kalem kullanır |
|-------------------|--------|----------------------|
| `identities` tablosu, `(provider, subject)` eşleştirmesi | `authn-oidc-client`, contracts §5 | K-82 (kurumsal SSO bağlantıları `sso:<id>` sağlayıcısı olarak), SAML |
| `SessionIssuer` portu (federe girişte oturum veya MFA challenge'ı) | `authn-core` port, `authn-session` uygular | K-80 (giriş etkileşimi), K-82, SAML |
| `amr` (RFC 8176) / `acr` / `auth_time` oturumda ve JWT'de | SES-08, `sessions.amr/acr` | K-80 (`acr_values`, `max_age`), K-87, K-88 |
| İmza anahtarı altyapısı ve JWKS (`pending → active → retired → revoked`, acil rotasyon) | CRY-09/10, SES-09, `signing_keys` | K-80 (ID token), K-86 (logout token), K-88 (SET). ES256 için `alg` sütunu eklenecek (yeni migration) |
| Org politikaları (`mfa_required`, `phishing_resistant_mfa_required`, `allowed_login_methods`, `ip_allowlist`, `sso_required`) | ORG-07, `org_domains.sso_required` | K-82, K-87 (istemci/org profilleri) |
| Doğrulanmış domain'ler | ORG-06 | K-82 (HRD), K-97 |
| Servis hesapları ve kapsamlı API anahtarları | ORG-08/09 | K-83 (SCIM kimlik bilgisi), K-84 |
| `act` claim'i (RFC 8693) | ADM-04 | K-90 |
| Transactional outbox + domain olayları + Standard Webhooks | AUD-06/07 | K-86 (back-channel logout teslimi), K-88 (SET teslimi), K-83 (olaylar) |
| SSRF korumalı `HttpClient` (trusted / user-supplied) | PRT-12 | K-82 (müşteri IdP'si = user-supplied hedef), K-86, K-88, K-91, K-96 |
| `one_time_tokens` amaç tablosu (atomik tüketim) | `authn-store`, contracts §5 | K-80 (yetkilendirme kodu, etkileşim kimliği), K-89 (cihaz kodu) |
| Zarf şifreleme + `rotate-kek` (her `*_ciphertext` kolonu test ile zorlanır) | CRY-08 | K-80 (istemci sırları), K-82 (bağlantı sırları), K-96 |
| `RiskEvaluator` / `GeoIpLookup` portları | RSK-01/02 | K-98, Faz 3 anomali |
| `KeyProvider` trait'i | CRY-08 | K-96 |
| Rate limiter (GCRA, anahtar boyutları) | PRT-01/02 | Tüm yeni uçlar (token, device polling, SCIM) |
| Migration aralığı `3000+` | contracts §6 | Önerilen: 3000–3099 `authn-oidc-provider`, 3100–3199 `authn-sso`, 3200–3299 `authn-scim`, 3300–3399 `authn-ssf` (mimar onaylar) |
| `authn-testkit` mimari testi (dalga bağımlılıkları) | `tests/architecture.rs` | Yeni crate'ler dalga kurallarına eklenir |

## 11. Lisans kısıtları

Kural (LIC-01, `CLAUDE.md`): yalnızca izin verici lisanslar. Tek kalıcı istisna `webauthn-rs` ailesi (MPL-2.0, crate bazında `deny.toml`'da). Yeni bağımlılıkla birlikte `cargo deny check` geçmeli ve `THIRD_PARTY_LICENSES.txt` yeniden üretilmeli. Aşağıdaki lisans bilgileri **bilgimize göredir ve eklemeden önce doğrulanmalıdır**:

| Kalem | Kısıt / risk | Öneri |
|-------|--------------|-------|
| K-80 RS256 | RSA özel anahtar işlemleri için `rsa` crate'inin zamanlama açığı var (RUSTSEC-2023-0071; şu an yalnızca `openidconnect` içinde **açık anahtarla** doğrulamada kabul edilmiş, bkz. HANDOFF §7). Bu crate ile imzalama yapılmamalı | Önce EdDSA + ES256 (`p256 0.14`). RS256 gerçekten gerekiyorsa sabit zamanlı, denetlenmiş bir arka uç (ör. `aws-lc-rs`) değerlendirilmeli. Lisans bileşenleri (ISC / Apache-2.0 / OpenSSL türevi kısımlar olabilir) ve C derleme bağımlılığı ayrıca doğrulanıp proje sahibine sunulmalı |
| K-81 DPoP | Kanıtlar yalnızca açık anahtarla doğrulanır | ES256 + EdDSA ile başlanmalı. RS256 kanıtları kabul edilecekse yukarıdaki advisory istisnasının kapsamı yeniden değerlendirilmeli |
| K-83 SCIM | Yeni kriptografi yok | `serde` yeterli. Filtre ayrıştırıcısı kendi kodumuz (fuzz) |
| K-92 OpenTelemetry | `opentelemetry*` crate'leri Apache-2.0. gRPC taşıyıcısı ek geçişli bağımlılık getirir | **Uygulandı (wave 11):** yalnızca OTLP/HTTP (protobuf); tonic/gRPC yok, reqwest 0.12 yok (authn-protect'in mevcut reqwest 0.13 tabanlı `HttpClient` portu). Yeni crate'ler: `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `opentelemetry-http`, `opentelemetry-proto`, `prost`, `prost-derive` (Apache-2.0), `tracing-opentelemetry` (MIT), `web-time` (MIT/Apache-2.0); `cargo deny` geçer |
| K-95 FIDO MDS | X.509 zinciri doğrulaması | `rustls-webpki` / `x509-parser` gibi izin verici crate'ler (lisanslar doğrulanmalı) |
| K-96 KMS | Bulut SDK'ları ağır olabilir | HTTP API'leri mevcut `HttpClient` ile çağırılabilir. İmzalama (ör. SigV4) HMAC birleşimidir, kendi algoritma değildir; varsa denetlenmiş bir izin verici crate tercih edilir |
| K-98 GeoIP | Okuyucu crate'ler izin verici olabilir. **Veritabanlarının** kendi lisansları/EULA'ları var, bazıları izin verici değil (ör. paylaşımlı-benzer lisanslar) | Veritabanı gömülmez, işletmeci sağlar (RSK-02). Belgede bu açıkça yazılır. **Uygulandı (wave 11):** okuyucu `maxminddb` (ISC) + `ipnetwork` (MIT/Apache-2.0), `mmap` kapalı; depoda GeoIP verisi yok, test fikstürleri `authn_testkit::mmdb` ile üretilir |
| SAML (Faz 3) | Olgun XML-DSig yığınları çoğunlukla C kütüphanelerine (libxml2, xmlsec) FFI ile bağlıdır; saf Rust seçenekler daha az olgun. XML kanonikleştirme güvenlik açısından kritik | Lisanslar ve C bağımlılıkları doğrulanmalı. Kanonikleştirme ve imza doğrulamasını kendimiz yazmayız. Denetlenmiş bir yığın yoksa SAML'ı ayrı, izole bir süreç olarak tasarlamak değerlendirilir |
| Push MFA (Faz 3) | Bazı push servislerinin sunucu kimlik doğrulaması RSA özel anahtarla JWT imzalamayı gerektirir (K-80 RS256 notu) | ES256 kullanan servisler doğrudan desteklenir. Diğerleri için RS256 kararı K-80 ile birlikte verilir |
| Terraform sağlayıcısı (Faz 3) | Sağlayıcı geliştirme çerçevesinin MPL-2.0 olduğu biliniyor (doğrulanmalı). MPL yalnızca `webauthn-rs` için onaylı | Proje sahibinin ayrı bir istisna kararı gerekir. Ayrı depoda, ayrı lisans politikasıyla yürütülebilir |
| SDK'lar (K-85) | Her ekosistemde LIC-01 geçerli | Her SDK deposunda eşdeğer bir lisans denetimi (ör. npm/SwiftPM/Gradle lisans tarayıcısı) CI'da çalışmalı |

## 12. Bu belgenin bakımı

- Bir Faz 2 kalemi kapandığında matristeki satırı ✅ yapın, kanıt sütununa gereksinim kimliği veya test adı yazın ve §2'deki sayıları güncelleyin.
- Yeni gereksinim kimlikleri `docs/spec/requirements.md`'ye eklenir. Faz 2 kimlik önekleri için öneri: `OAP-` (OAuth/OIDC sağlayıcısı), `SSO-`, `SCM-` (SCIM), `DPP-` (DPoP), `SSF-`.
- Rakip sütunları yılda bir kez, yalnızca kamuya açık ürün belgelerine bakılarak gözden geçirilir. Doğrulanamayan bir iddia eklenmez.
