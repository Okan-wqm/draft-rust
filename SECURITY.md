# Güvenlik politikası

Bu belge, `rust-authentication` (depo: `draft-rust`) içinde bulduğunuz bir güvenlik açığını nasıl bildireceğinizi ve bildiriminizin nasıl ele alınacağını anlatır.

## Desteklenen sürümler

Proje henüz ilk sürümünü yayımlamadı. Workspace sürümü `0.1.0`'dır (`Cargo.toml`) ve sürüm etiketi yoktur.

| Sürüm | Güvenlik düzeltmesi alır mı? |
|-------|------------------------------|
| `main` dalının en son commit'i | ✅ Evet |
| Diğer dallar (ör. `claude/**` çalışma dalları) | ❌ Hayır: düzeltmeler `main`'e yapılır |
| Etiketli sürümler | — Henüz yok. İlk sürüm etiketlendiğinde bu tablo, hangi sürüm serilerinin desteklendiğini gösterecek biçimde güncellenmelidir |

Bu yazılım tescillidir ve tüm hakları saklıdır ([`LICENSE`](LICENSE)); yazılı izin olmadan kullanılamaz, kopyalanamaz veya dağıtılamaz. Bu politika, kodu izinle inceleyen ya da kodla karşılaşan herkesin açıkları sorumlu biçimde bildirebilmesi içindir ve hiçbir kullanım hakkı vermez.

## Açık nasıl bildirilir

**Güvenlik açıklarını herkese açık issue, pull request, tartışma ya da sohbet kanalında bildirmeyin.**

Bildirimi **özel olarak** e-postayla gönderin: **by-okan@live.com** (konu satırına `[SECURITY]` yazın).

Bildiriminizde mümkünse şunlar olsun:

- Etkilenen bileşen (crate adı, uç nokta, CLI komutu veya yapılandırma anahtarı) ve commit kimliği.
- Açığın türü ve etkisi (ör. hesap ele geçirme, kimlik doğrulama atlatma, kiracılar arası erişim, hesap varlığı sızıntısı).
- Yeniden üretme adımları, mümkünse en küçük bir örnek istek veya test.
- Gerekiyorsa kullanılan yapılandırma (sırları ve kişisel verileri **çıkararak**).
- Açığı başkalarıyla paylaşıp paylaşmadığınız ve yayımlama planınız.

Kişisel veri, gerçek kullanıcı kimlik bilgisi veya üretim sırları **göndermeyin**. Kanıt için kendi test hesaplarınızı ve test anahtarlarınızı kullanın.

## Süreç ve zaman çizelgesi

Aşağıdaki süreler **hedeftir**, garanti değildir.

| Adım | Hedef süre |
|------|-----------|
| Bildirimin alındığının onaylanması | 3 iş günü |
| İlk değerlendirme (geçerli mi, şiddeti ne) | 10 iş günü |
| Kritik / yüksek şiddette düzeltme | Değerlendirmeden sonra 30 gün |
| Orta / düşük şiddette düzeltme | Değerlendirmeden sonra 90 gün |
| Koordineli açıklama | Düzeltme `main`'e girdikten sonra, en geç ilk bildirimden 90 gün sonra (bildirenle birlikte kararlaştırılır) |

Süreç:

1. Bildirim özel kanalda kabul edilir ve bir takip kimliği verilir.
2. Açık yeniden üretilir ve şiddeti değerlendirilir.
3. Düzeltme, projenin mevcut deseniyle yapılır: önce açığı kanıtlayan ve düzeltme olmadan **başarısız olan** bir regresyon testi yazılır, sonra düzeltme yapılır ve test yeşile döner ([`docs/HANDOFF.md`](docs/HANDOFF.md) §6). Test adı ilgili gereksinim kimliğini taşır.
4. Düzeltme `main`'e girer. Açık, ilgili crate README'sinin "Güvenlik notları" bölümüne ve gerekiyorsa [`docs/security/known-limitations.md`](docs/security/known-limitations.md)'ye yazılır.
5. Bildirenle birlikte açıklama yapılır. Bildiren isterse adıyla teşekkür edilir.

Bir açık düzeltilemiyorsa ya da bilinçli olarak kabul edilen bir risk ise gerekçesiyle [`docs/security/known-limitations.md`](docs/security/known-limitations.md)'ye yazılır ve bildirene bildirilir.

## Kapsam

**Kapsamda:**

- Bu depodaki Rust kodu: `crates/` altındaki 16 crate ve `rust-authentication` binary'si (HTTP API, ara katman, CLI, arka plan işleri).
- Veritabanı şeması, migration'lar ve en az yetkili rol fonksiyonu (`migrations/`).
- Yapılandırma doğrulaması: güvensiz bir yapılandırmanın üretimde kabul edilmesi bir açıktır.
- `Dockerfile` ve `docker-compose.yml` (geliştirme ortamı için olduğu belirtilen sabit Mailpit sertifikası hariç, aşağıya bakın).
- Belgelerdeki güvenlik iddialarının kodla çelişmesi.

Özellikle ilgilendiğimiz sınıflar: kimlik doğrulama/MFA/step-up atlatma, oturum veya token sahteciliği ve tekrar kullanımı, hesap ön-ele geçirme ve hesap kurtarma yolları, kiracılar arası erişim (IDOR), ayrıcalık yükseltme, hesap varlığının yanıt gövdesi/durum kodu/**süre** üzerinden sızması, CSRF, open redirect, SSRF, Host başlığı zehirlenmesi, sırların loglara/audit'e/hata mesajlarına sızması, audit zincirinin fark edilmeden kurcalanması, kriptografinin yanlış kullanımı.

**Kapsam dışı:**

- [`docs/security/known-limitations.md`](docs/security/known-limitations.md)'de gerekçesiyle **zaten listelenmiş** sınırlamalar. Bunları atlatmanın yeni bir yolunu bulduysanız kapsamdadır.
- Faz 2/3 özelliklerinin yokluğu (OAuth/OIDC sağlayıcısı, SSO, SCIM, DPoP, SAML vb.; bkz. [`docs/roadmap.md`](docs/roadmap.md)).
- `config/example.toml` içindeki örnek anahtarlar ve `config/dev-certs/` altındaki Mailpit sertifikası/özel anahtarı. Bunlar bilinçli olarak yayımlanmış geliştirme değerleridir ve üretim/staging yapılandırması bunları reddeder.
- Bu sistemi kullanan ön yüz uygulamaları, işletmecinin altyapısı (TLS sonlandırma, PostgreSQL, ağ), üçüncü taraf servisler (OIDC sağlayıcıları, HIBP, CAPTCHA, SMTP/SMS sağlayıcıları).
- Bağımlılıklardaki açıklar: lütfen önce ilgili projeye bildirin. Bu projedeki kullanımın açığı sömürülebilir kılıp kılmadığı kapsamdadır.
- Hizmet engelleme için yalnızca hacimsel trafik (ör. yük testi). Küçük bir istekle orantısız iş yaptıran mantık hataları kapsamdadır.
- Sosyal mühendislik ve fiziksel saldırılar.

## Güvenli test kuralları

- Yalnızca kendi kurduğunuz bir kopya üzerinde test edin. Başkasının çalışan sistemine izinsiz test yapmayın.
- Başka kullanıcıların verisine erişmeyin, veriyi değiştirmeyin ve silmeyin. Bir açığı kanıtlamak için gereken en az işlemi yapın.

## İlgili belgeler

- [Tehdit modeli](docs/security/threat-model.md)
- [OWASP ASVS eşlemesi](docs/security/asvs-mapping.md)
- [Kriptografi kararları](docs/security/cryptography.md)
- [Bilinen sınırlamalar](docs/security/known-limitations.md)
- [K-57 modüller arası güvenlik denetimi](docs/security/k57-global-audit.md)
