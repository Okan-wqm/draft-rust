# Bilinen sınırlamalar ve kabul edilen riskler (DOC-03)

> **Durum:** `claude/compassionate-darwin-aa1tiy` dalı, `47c84a7` (2026-11-05).
>
> Bu belge, şu kaynaklarda dağınık duran ve **bugün hâlâ geçerli** olan riskleri tek yerde toplar:
>
> - [`docs/handoff/module-apis.md`](../handoff/module-apis.md) "Accepted risks" bölümleri,
> - crate README'lerinin "Güvenlik notları / Kabul edilen riskler" bölümleri ve K-58 değerlendirmeleri,
> - [ADR 0002](../architecture/adr/0002-registration-pre-hijacking.md) "Artık riskler",
> - [K-57 denetimi](k57-global-audit.md) §4–§5,
> - [`docs/operations/performance.md`](../operations/performance.md) "izleme adayları",
> - [`docs/handoff/remaining-work.md`](../handoff/remaining-work.md) §10.
>
> Sonradan **kapatılan** maddeler buraya alınmadı. Örnekler: anahtarsız audit zinciri (K-77), `access_token_session_check = false` ile üretimde çalışma (K-58), imza anahtarı önbelleğinin 30 sn gecikmesi (K-58, LISTEN/NOTIFY), MFA sıfırlamanın passkey'leri silmemesi (K-01), "saldırgan ikinci" kayıt (ADR 0002). Kaynak belgelerde bunlar üstü çizili olarak durur.
>
> Her maddede **etki**, **neden kabul edildi / neden kapatılamadı** ve **azaltım** yazılıdır. "Faz 2" maddeleri bir eksik özelliktir, bir hata değildir.

## 1. Doğrulama durumu (ne yapılmadı)

| # | Sınırlama | Ayrıntı | Kalem |
|---|-----------|---------|-------|
| L-1 | **Bağımsız dış güvenlik denetimi (pentest) yapılmadı** | Tüm denetimler iç denetimlerdir (modül başına bağımsız denetçi agent + modüller arası K-57). Bunlar bir dış pentest'in yerini tutmaz. Üretimden önce önerilir | K-72 (proje sahibinin kararı) |
| L-2 | **Docker imajı ve `docker-compose.yml` bu ortamda hiç çalıştırılmadı** | Geliştirme ortamında Docker daemon'u yoktu. Şunlar doğrulanmadı: `Dockerfile`'ın derlenmesi, distroless imajın çalışması, imajda `THIRD_PARTY_LICENSES.txt`'nin bulunması, Mailpit ile gerçek STARTTLS teslimi. Binary'nin yerel PostgreSQL ile `migrate` + `serve` + `/health/ready` akışı çalıştırılarak doğrulandı | K-55 |
| L-3 | Fuzz hedefleri yalnızca kısa süre koşturuldu | 13 hedef derleniyor; 30 sn – 2 dk koşturuldu. Uzun koşu (10–30 dk/hedef) QA sertleştirmesinde | remaining-work §6 |
| L-4 | Kapsam raporu yerelde tamamlanmadı | `cargo llvm-cov` CI'da çalışır; kritik yollardaki kapsanmayan dallar ayrıca incelenmedi | remaining-work §6 |
| L-5 | Zamanlama testleri istatistikseldir | Hesap varlığı süre testleri yüzdelik toleransla çalışır; çok gürültülü makinede dalgalanabilir | HANDOFF §7 |

## 2. Kimlik doğrulama ve hesap

| # | Risk | Etki | Neden kabul edildi | Azaltım |
|---|------|------|---------------------|---------|
| A-1 | **Kayıt kodu oltalaması** (ADR 0002) | Saldırgan kurbanın adresiyle kayıt olup kurbandan e-postadaki 6 haneli kodu "okumasını" isterse kodu kendi tutamacıyla girip **kendi** kaydını etkinleştirir | Kod, başka cihazda elle girilmek üzere tasarlanmıştır (ACC-04). Gönüllü verilen bir sırrı sunucu ayırt edemez. Kodu kaldırmak ACC-04'ü ihlal eder | E-postada "kodu kimseyle paylaşmayın" uyarısı (`acc_04_k58_verification_mail_warns_against_sharing_the_code`). Hesap posta kutusu sahibinindir; şifre sıfırlama her zaman ona döner |
| A-2 | Kayıt kodu tahmini | Hedef adres başına sürekli durumda günde ≈ 5·10⁻⁶, ilk günde en çok 10⁻⁵ başarı olasılığı | 6 hane spesifikasyon gereğidir (ACC-04). 8 haneye geçiş proje sahibinin kararıydı ve 6 hane korundu | Kayıt başına 5 deneme, adres başına saatlik ve günlük sınır (`acc_04_k58_code_guesses_per_address_are_capped_per_day`). Link yolu kod gerektirmez |
| A-3 | Kayıt kodunun adres bütçesi tüketilebilir | Saldırgan sahibin **kod** yolunu günde 5 denemeyle kapatabilir | Bütçe adrese bağlı olmak zorundadır; aksi hâlde tahmin sınırı aşılır | Link yolu etkilenmez; yanıt hesap varlığını sızdırmaz |
| A-4 | Hesap başına 10 canlı kayıt sınırı | Saldırgan kurbanın kaydından **sonra** 10 kayıt açarsa kurbanın kaydı düşer | Satır sayısını sınırlamak gerekir (DoS) | Her kayıt IP sınırına ve CAPTCHA'ya tabidir; sahip yine "herhangi bir link + yeni şifre" ile hesabı alır |
| A-5 | Doğrulama linki 24 saat "yeni şifre" ile hesabı kurabilir | Sızan bir doğrulama linki hesabı sızdığı kişiye verir | Şifre sıfırlama linkiyle aynı sınıftır | Link yalnızca posta kutusuna gider; tek kullanımlıktır |
| A-6 | **Eski bcrypt/PBKDF2 hash'lerinde zamanlama farkı** | Göç edilmiş hesaplarda doğrulama süresi Argon2id'den farklıdır; hesap varlığı kısmen sızabilir. Argon2 parametreleri artırıldığında da yükseltilmemiş hash'ler sahte doğrulamadan kısa sürebilir | Sahte doğrulamayı eski hash'in maliyetine eşitlemek, saklanan hash'i, yani hesabın varlığını bilmeyi gerektirir | Her başarılı girişte Argon2id'ye geçiş; göç penceresini kısa tutun |
| A-7 | Şifre sıfırlama kodu tahmini | Hedef hesap başına saatte ≈ 10⁻⁵ (yılda ≈ %9) | 6 haneli kod spesifikasyon gereğidir (PWD-08) | Kod başına 5 deneme, adres/IP sınırları. Sıkı ortamlarda `password.reset.code_enabled = false` (yalnızca 256 bit link) |
| A-8 | Hedefli sıfırlama DoS'u | Saldırgan kurbanın saatlik sıfırlama bütçesini tüketebilir veya kodu yakabilir | Sınır gönderilen adrese bağlı olmalıdır, yoksa hesap varlığı sızar (PWD-07) | Kod yanınca aynı gruptaki link geçerli kalır |
| A-9 | **Hedefli yumuşak kilit** | CAPTCHA'ları çözen saldırgan kurbanın bilinmeyen cihazlardan şifreli girişini `soft_lock_duration` (1 sa) boyunca engelleyebilir | PRT-03 tasarımı; tanımlayıcıya bağlı olmayan kilit hedefli tahmini durduramaz | Passkey, güvenilir/bilinen cihaz, magic link ve şifre sıfırlama çalışır; yanıt varlık sızdırmaz |
| A-10 | Risk sinyalinin saldırganca yükseltilmesi | Kurbanın adresine başarısız denemeler + kurbanın yeni cihaz ve yeni ağdan girişi → `high` → varsayılan olarak engel | Sinyal olmazsa saldırganın denemeleri görünmez olurdu | `protect.risk.high_action = "step_up"` |
| A-11 | Kullanıcı başına MFA kilidi | Şifreyi bilen saldırgan, kullanıcının MFA'sını 15 dk'lık pencerelerle geciktirebilir | MFA-03'ün doğal sonucu; kilit hiçbir şey vermez | Yumuşak kilit, risk değerlendirmesi, challenge sayacı |
| A-12 | **Step-up şifreyle yapılabilir** | MFA'lı normal bir kullanıcının çalınmış oturum çerezi + şifresiyle yeni faktör eklenebilir, e-posta değiştirilebilir | SES-13 step-up yöntemleri arasında şifreyi sayar | Ekleme ve değişiklikler bildirilir. Platform adminleri ve phishing'e dayanıklı MFA isteyen org'larda step-up passkey ister (`ses_13_platform_admins_and_strict_orgs_need_a_passkey`) |
| A-13 | Challenge adımlarında paralel yanlış denemeler | Aynı challenge'a eşzamanlı yanlış denemeler sınırı en fazla eşzamanlı istek sayısı kadar aşabilir | Kapatmak, Argon2/TOTP doğrulaması süresince satır kilidi tutmayı gerektirir; bu havuz tükenmesine yol açar | Faktör modüllerinin kullanıcı başına sınırları ve kilitleri ayrıca geçerlidir |
| A-14 | E-posta ile birincil giriş | Magic link ve e-posta kodu (SES-18/19) birincil giriş yöntemidir; e-posta hesabını ele geçiren girişin ilk faktörünü geçer | Spesifikasyon gereği şifresiz giriş | MFA politikası yine uygulanır (`ses_18_magic_link_still_requires_the_second_factor`); org'lar yöntemi yasaklayabilir; e-posta girişi "son yöntem" kurallarında güçlü yöntem sayılmaz |
| A-15 | Girişte sızdırılmış şifre kontrolü yok | Yalnızca yeni şifre belirlenirken HIBP'ye bakılır; mevcut sızmış şifreyle giriş yapılabilir | Spesifikasyon (PWD-03) yeni şifreler için ister | — |
| A-16 | HIBP kesintisinde açık başarısızlık (varsayılan) | HIBP erişilemezse sızmış bir şifre kabul edilebilir | Kullanılabilirlik | `password.breach_check.fail_open = false` veya çevrimdışı liste |
| A-17 | `password.min_length` 8'e düşürülebilir | Varsayılan 12; yapılandırma 8–64 aralığına izin verir | İşletmeci esnekliği | Belge, tek faktörlü hesaplar için 15 önerir |
| A-18 | Break-glass şifresi süresizdir | `create-admin` şifresi değişiklik zorunluluğu olmadan geçerlidir | Acil durum hesabı | `create-admin --passkey-link` kullanın; break-glass kullanımı yüksek öncelikli audit olayı üretir |
| A-19 | Kurtarma kodu yeniden üretimi bildirilmez | Kullanıcıya e-posta gitmez | MFA-04 yalnızca kullanımı ister; uygun `NotificationKind` yok | Step-up gerekir, audit'lenir, güvenilir cihazları iptal eder |
| A-20 | TOTP tekrar kullanım denemesi sahibine bildirilmez | Reddedilir ve başarısız doğrulama olarak sayılır; e-posta gitmez | — | `mfa.failed` audit olayı ve deneme sınırı |
| A-21 | Passkey girişi org'un `allowed_mfa_factors` listesini atlar | Passkey tek başına MFA sayılır | SES-21 spesifikasyonu | Org passkey'i izinli giriş yöntemlerinden çıkarabilir |
| A-22 | Yalnızca TOTP'si olan kullanıcı phishing'e dayanıklı MFA isteyen org'da girişte takılır | Kullanılabilirlik | Challenge içinde passkey kaydı, kanıtlanmamış oturumda kimlik bilgisi eklemek olurdu | Kullanıcı passkey'ini başka bir oturumdan kaydeder |
| A-23 | Klon şüpheli passkey kullanılmaya devam eder | Klonlanmış authenticator çalışmaya devam edebilir | Otomatik devre dışı bırakma gerçek authenticator'ı da kilitler; WebAuthn kararı RP'ye bırakır | İşaret, audit olayı, listede gösterim, e-posta bildirimi |
| A-24 | Passkey kayıt bitişinde step-up yeniden denetlenmez | Seremoni başında denetlenir | Seremoni aynı oturuma bağlı ve en çok `ceremony_ttl` (5 dk) ömürlü | — |
| A-25 | "Giriş yapabilen" passkey sayımı keşfedilebilirliğe bakmaz | Resident olmayan bir anahtar son giriş yöntemi sayılabilir | `credProps.rk` imzasız istemci beyanıdır | Kurtarma e-postayla şifre sıfırlamadır |

## 3. Audit log ve zincir (AUD-02, K-77)

| # | Risk | Etki | Azaltım |
|---|------|------|---------|
| AU-1 | **Sondan kesme / geri sarma yalnızca dış çıpayla tespit edilir** | Veritabanına yazabilen biri zincirin son olaylarını silip baş satırını geri sarabilir; zincir kendi içinde tutarlı kalır | Kontrol noktalarını ve `rotate-audit-chain-key` / açılışta loglanan `chain_key_switch` `(seq, hash)` değerlerini veritabanı dışında (WORM) saklayın; `verify-audit-chain --anchor <seq>:<hash>` ile doğrulayın (`aud_02_truncated_tail_is_detected_by_head_and_external_anchor`) |
| AU-2 | **Zincirin tamamını eski (anahtarsız) biçime çevirmek yalnızca sabitlemeyle yakalanır** | Zinciri baştan anahtarsız SHA-256 olarak yeniden yazıp geçiş kontrol noktasını da silen saldırgan; sabitleme yoksa bu durum yalnızca raporda `legacy_events > 0` / `keyed_from_seq = null` olarak görünür | `audit.chain.legacy_until_seq = <ilk anahtarlı seq − 1>` ayarlayın (`k_77_rewriting_the_whole_chain_as_legacy_is_detected`, `k_77_pinned_legacy_prefix_detects_a_truncated_keyed_part`) |
| AU-3 | Sunucu süreci ele geçirilirse | Zincir anahtarını tutan süreç geçerli olaylar yazabilir; anahtarlı zincir onun yazdıklarını ayırt edemez | Anahtar rotasyonu + dış çıpa |
| AU-4 | Takma ad eşlemesinin yeniden bağlanması | Bir eşleme silinip aynı takma ad başka kullanıcıyla eklenirse geçmiş yeniden bağlanabilir (`audit_event_pii.pseudonym` özetin parçası değildir) | En az yetkili rol; dış çıpa |
| AU-5 | **Kök anahtar tek sürümlüdür** | Zincir sürüm anahtarları `crypto.hmac_root_key`'den türetilir. Kök sızarsa tüm sürümler sızar; kök değişirse eski anahtarlı olaylar yeni yapılandırmayla doğrulanamaz | Kök anahtarı KMS/HSM'de tutmak Faz 2'dir (K-96). Kök değişikliğinden önce zinciri doğrulayıp çıpayı dışarıda saklayın |
| AU-6 | Sanitizer sezgileri her sırrı yakalayamaz | Nötr bir anahtar altındaki düz şifre veya 32 karakterden kısa küçük harfli token metadata'da kalabilir | Birincil kural: üretici modüller sır koymaz (AUD-03); log yakalama testleri |
| AU-7 | Başka kullanıcının kimliği olay `data`'sında kalabilir | Olayın öznesi olmayan bir kullanıcı (ör. davet eden) silinirse, kimliği outbox/webhook geçmişinde saklama süresi (7/30 gün) boyunca kalır | Üreticiler özneyi `user_id` ile verir; serbest metin araması her silmede tam tablo taraması olurdu |
| AU-8 | Webhook teslimi en az bir kezdir | Aynı olay iki kez teslim edilebilir | Alıcılar sabit `webhook-id` ile tekilleştirir |
| AU-9 | Genel yetki retleri audit'lenmez | Org ve kullanıcı uçlarındaki `403`/`404`'ler audit olayı üretmez (admin işlemleri ve API anahtarı hataları üretir) | Uygulama logları ve metrikler |
| AU-10 | Webhook otomatik devre dışı bırakılınca org adminlerine e-posta gitmez | Yalnızca `webhook.endpoint_auto_disabled` audit olayı | Uygun `NotificationKind` yok |

## 4. Oturumlar ve token'lar

| # | Risk | Etki | Azaltım |
|---|------|------|---------|
| S-1 | **Token'lar gönderene bağlı değil** (DPoP/mTLS yok) | Çalınan access token `access_token_ttl` (10 dk) boyunca, refresh token yeniden kullanım tespit edilene dek taşıyıcı olarak kullanılabilir | Refresh rotasyonu + aile iptali; her istekte oturum kontrolü. DPoP Faz 2 (K-81) |
| S-2 | Refresh tolerans penceresi | `session.refresh_reuse_grace` > 0 iken pencere içinde emekli refresh token'ı sunan herkes aynı ardılı alır | Varsayılan 0 (kapalı), en çok 10 sn |
| S-3 | `access_token_session_check = false` | Yalnızca `production` dışında mümkündür; iptal ve askıya alma en geç `access_token_ttl` sonra etkili olur | Üretimde yapılandırma doğrulaması reddeder |
| S-4 | İmza anahtarı dinleyicisi çalışmıyorsa | Acil iptal edilen anahtar diğer instance'larda en çok `signing_key_cache_ttl` (30 sn, en çok 5 dk) doğrulanabilir. PgBouncer transaction pooling'de `LISTEN` çalışmaz | `database.url` doğrudan PostgreSQL'e veya session pooling'e gitmelidir |
| S-5 | Uzun native oturum | Refresh token boşta 30 gün / mutlak 90 gün (varsayılan) | Yapılandırılabilir; oturum listesi ve uzaktan kapatma |
| S-6 | Oturum kapatma uçları yeniden kimlik doğrulama istemez | Çalınmış oturum, kullanıcının diğer oturumlarını kapatabilir (yalnızca DoS) | Bilinçli: kapatma güvenli yöndedir |
| S-7 | Kardeş alt alan adının çerez kavanozunu doldurması | Oturum çerezi okunamaz hâle gelir, kullanıcı çıkış yapmış görünür (yalnızca DoS) | `__Host-` çerezinin üzerine yazılamaz |
| S-8 | Web impersonation token'ı konsol belleğinde | Admin konsolunda XSS varsa token çalınabilir (native token'larla aynı maruziyet) | Bilinçli (K-12): çerez seçeneği adminin oturumunu ezerdi; impersonation süreli ve varsayılan salt-okunur |
| S-9 | Organizasyon *istenerek* yapılan girişte yalnızca o org'un izinli faktörleri uygulanır | Diğer üyeliklerin daha katı politikası girişte değil, org değiştirmede ve her org isteğinde uygulanır | K-57 F2 ile her org isteğinde kontrol |

## 5. Kriptografi ve anahtar yönetimi

| # | Sınırlama | Etki | Not |
|---|-----------|------|-----|
| K-1 | **KMS/HSM yok** | KEK, pepper ve HMAC kökü süreç belleğinde ve yapılandırmada; süreç ele geçirilirse hepsi açığa çıkar | `KeyProvider` trait'i hazır; uygulama Faz 2 (K-96) |
| K-2 | **`hmac_root_key` rotasyonu yıkıcıdır** | Kök tek sürümlüdür. Değiştirmek; bekleyen OTP/kodları, kurtarma kodlarını, güvenilir cihaz token'larını, CSRF token'larını, PoW görevlerini, hız sınırı anahtarlarını (bütçeler sıfırlanır), bilinen cihaz kayıtlarını (herkes için bir kez "yeni cihaz") ve eski anahtarlı audit olaylarının doğrulanabilirliğini (AU-5) etkiler | Rotasyon prosedürü DOC-06 runbook'larındadır ([`docs/operations/`](../operations/)) |
| K-3 | Yalnızca EdDSA | RS256/ES256 bekleyen kaynak sunucusu kütüphaneleri access token'ı doğrulayamayabilir | ES256 Faz 2 (K-80); [ADR 0001](../architecture/adr/0001-jwt-implementation.md) |
| K-4 | Bellekte sıfırlanmayan üçüncü taraf kopyaları | zxcvbn şifrenin ilk 100 karakterini, serde/axum gövde tamponları istekleri, lettre/minijinja e-posta gövdelerini ve SMTP parolasını sıfırlamadan tutar | Bellek dökümü tehdidi kapsam dışı |
| K-5 | FIPS 140 doğrulanmış modül yok | RustCrypto crate'leri FIPS doğrulamalı değildir | [roadmap](../roadmap.md) G18 |
| K-6 | Bilinçle yok sayılan iki RustSec uyarısı | `RUSTSEC-2023-0071` (`rsa`), `RUSTSEC-2026-0387` (`crypto-bigint` 0.5) | Yalnızca `openidconnect` içinde açık anahtarla imza doğrulamasında; gizli anahtarlı EC işlemleri `p256` 0.14 ile. Gerekçe `deny.toml`, `.cargo/audit.toml` |
| K-7 | Kişisel veri kolon düzeyinde şifreli değil | E-posta, telefon, görünen ad, IP veritabanında açık | Disk/DB şifrelemesi işletmecinindir; sırlar zarf şifrelidir |

## 6. Yapılandırma ve işletme

| # | Sınırlama | Etki | Azaltım |
|---|-----------|------|---------|
| O-1 | **Üretim kurallarının çoğu yalnızca `production`'da** | `staging` ortamında yalnızca yayımlanmış örnek anahtarlar reddedilir. `https` zorunluluğu, bellek içi hız sınırı yasağı, SSRF muafiyeti yasağı, four-eyes ve oturum kontrolü zorunluluğu, CAPTCHA hostname zorunluluğu `staging`'de uygulanmaz | `staging`'i üretim gibi yapılandırın. Varsayılan ortam `production`'dır |
| O-2 | HTTP katmanı hız sınırlayıcısı açık başarısız | Limiter hatasında kaba taşkın koruması devre dışı kalır | Güvenlikle ilgili eylem limitleri (giriş, CAPTCHA, sıfırlama) kapalı başarısız olur |
| O-3 | `trusted_proxies` yanlış yapılandırması | Gerçekte güvenilmeyen bir ağ güvenilir yazılırsa istemci IP'si sahte olabilir (IP sınırları, org IP listesi, break-glass IP listesi) | Geniş önekler reddedilir (K-57 F1). Liste yalnızca proxy adreslerini içermeli |
| O-4 | Saat senkronu | GCRA, TOTP ve token ömürleri sistem saatine bağlı | NTP |
| O-5 | Anonimleştirici ağ listesi yalnızca açılışta okunur | Liste güncellemesi yeniden başlatma ister | — |
| O-6 | Arka plan kuyrukları sınırlı | Şifresiz giriş (1024) ve sıfırlama (4096) kuyrukları dolunca istek sessizce düşer (yanıt aynı) | Bellek DoS'una karşı bilinçli; metrikler artar |
| O-7 | PostgreSQL bağlantı bütçesi | Her instance havuz dışında bir kalıcı `LISTEN` bağlantısı açar | `max_connections` = instance × (havuz + 1) + bakım + CLI payı |
| O-8 | Docker/HA referansı yok | Helm chart, PostgreSQL HA ve yedek/geri yükleme rehberi yok | Faz 2 (K-99); önkoşul K-55 |

## 7. Organizasyonlar ve yetkilendirme

| # | Risk | Etki | Neden / azaltım |
|---|------|------|-----------------|
| G-1 | Kişisel API anahtarları org MFA ve ömür politikasından muaf | Politika sıkılaştırması oturumları kapatır ama mevcut anahtarları iptal etmez | Makine kimlik bilgileri MFA taşıyamaz; yöneticiler `api_keys:manage` ile iptal eder. IP izin listesi uygulanır |
| G-2 | Introspection org'un herhangi bir API anahtarıyla yapılabilir | Ayrı bir `tokens:introspect` kapsamı yok; anahtar yalnızca kendi org'unun token'larını görür | Davranış değişikliği Faz 2 OAuth sağlayıcısına (K-80) bırakıldı (K-57 §4) |
| G-3 | Passkey kaydı aktif org'un AAGUID politikasına göre | En katı politika girişte ve step-up'ta uygulandığı için izinsiz passkey kullanılamaz; yalnızca kaydedilebilir ve faktör sayısına girer | Kullanılabilirlik etkisi (K-57 §4) |
| G-4 | Doğrulanmış domain'ler yeniden doğrulanmaz | Domain el değiştirirse otomatik katılım sürer | Faz 2 (K-97) |
| G-5 | `org_domains.sso_required` saklanır ama uygulanmaz | Kurumsal SSO yok | Faz 2 (K-82) |
| G-6 | Servis hesabının gönderdiği davetler SA devre dışı kalınca iptal edilmez | `invited_by` boştur | `members:invite` ile elle iptal |
| G-7 | Başlatanı düşürülen bekleyen sahiplik devri iptal edilmez | Kabulde başlatanın hâlâ aktif sahip olması zorunludur | — |
| G-8 | Org adı davet/devir e-postalarında görünür | İçerik (marka taklidi) denetlenmez | Kontrol/bidi/görünmez karakterler reddedilir; davetler hız sınırlıdır |
| G-9 | Tek "platform admin" rolü | Destek ekibine en az yetki verilemez | Faz 2 (K-93) |
| G-10 | Admin yetkisi yalnızca CLI'dan | İki adminli kurulumda adminler birbirine API'den işlem yapamaz | Bilinçli; kurtarma prosedürü [`docs/operations/admin-recovery.md`](../operations/admin-recovery.md) |
| G-11 | Break-glass passkey kayıt bağlantısını ele geçiren ilk kişi passkey'i kaydeder | Bağlantı güvenli kanalla iletilmelidir | Kayıt yüksek öncelikli `break_glass_passkey_enrolled` olayı üretir; şüphede `suspend-admin` + yeni bağlantı |

## 8. Sosyal giriş

| # | Risk | Etki | Neden / azaltım |
|---|------|------|-----------------|
| F-1 | Güvenilir sayılan kötü niyetli IdP hesap varlığını öğrenebilir | `email_verified=true` iddiasıyla: var olan hesapta `oauth_link_required`, yoksa yeni hesap | Sağlayıcıyı işletmeci yapılandırır; otomatik bağlama yalnızca `auto_link_trusted_providers` için. Sağlayıcı başına domain kısıtı Faz 2 (K-82) |
| F-2 | 24 saatten uzun JWKS kesintisi | O sağlayıcıyla giriş durur | Bilinçli kapalı başarısızlık (`jwks_max_staleness`) |
| F-3 | Apple native girişte yetkilendirme kodu gönderilmezse | O giriş için iptal edilecek Apple token'ı yoktur | Web akışında her zaman vardır |

## 9. Bildirimler

| # | Risk | Etki | Neden / azaltım |
|---|------|------|-----------------|
| N-1 | `notify_in_tx` yalnızca gönderen dalda iş yapar | Üretici diğer dalda eşdeğer iş yapmazsa süre farkı hesap varlığını sızdırabilir | Üretici sözleşmesi; ilgili akışlarda zamanlama testleri var |
| N-2 | Alıcı başına bütçe tüketilebilir | Saldırgan kurbanın bir türdeki (ör. sıfırlama) bütçesini tüketebilir | Her alıcı başına sınırın doğası |
| N-3 | User-agent metni uyarı e-postalarında | Sosyal mühendislik metni temizlenir ve kısaltılır, ama tamamen önlenemez | URL'ler etkisizleştirilir |
| N-4 | SMS sağlayıcısına idempotency anahtarı gönderilmez | En az bir kez teslimde aynı kod nadiren iki kez gelebilir | Port alanı yok |
| N-5 | Tarihler UTC yazılır | Kullanıcının saat dilimi bildirim sözleşmesinde yok | — |

## 10. Performans (izleme adayları)

Kaynak: [`docs/operations/performance.md`](../operations/performance.md) (ölçüm ortamı uyarısıyla).

| # | Konu | Etki | Durum |
|---|------|------|-------|
| P-1 | **Şifre girişi 42 SQL ifadesi** | Aynı `users` satırı 6 kez okunur, hız sınırı 9, audit 5 ifade. Ayrı veritabanı sunucusunda (0,5 ms RTT) ~+21 ms | Düzeltme birden çok modülün arayüzünü ve bilinmeyen hesap yolundaki eşit maliyet garantisini (CRY-05, SES-01) etkiler; ayrı bir iş olarak zamanlama testleriyle yapılmalı |
| P-2 | **Audit zinciri başı tek satır kilidi** | Her audit olayı `audit_chain_head`'i çağıranın `COMMIT`'ine kadar kilitler; audit'li yazmalar sistem genelinde sıralanır. Uzak veritabanında kabaca ~400 audit'li olay/sn tavan | Çatallanmasız zincirin bilinçli bedeli; kaldırmak bir port değişikliği ister |
| P-3 | Argon2id CPU tavanı | Giriş hızı Argon2id ile sınırlıdır (ölçüm makinesinde 4 izinle ~75–77 doğrulama/sn) | `max_concurrent_hashes` ve parametreler yapılandırılabilir |

## 11. Faz 2 / Faz 3 eksikleri (özellik)

Bunlar kodda **yoktur**; ayrıntı ve öncelik [roadmap](../roadmap.md)'te.

| Kalem | Eksik |
|-------|-------|
| K-80 | OAuth 2.1 / OIDC sağlayıcısı (Authorization Code + PKCE, discovery, RFC 7009 revocation ucu, consent) |
| K-81 | DPoP (gönderene bağlı token) |
| K-82 | Org başına kurumsal OIDC SSO, `sso_required` uygulaması, JIT üyelik |
| K-83 | SCIM 2.0 |
| K-84 | `client_credentials`, `private_key_jwt` |
| K-85 | SDK'lar (TypeScript, Swift, Kotlin) |
| K-86 | Single Logout (RP-initiated, back/front-channel) |
| K-87 | PAR, JAR, FAPI 2.0 tabanı |
| K-88 | Shared Signals (CAEP/RISC) |
| K-89 | Device Authorization Grant |
| K-90 | Token Exchange |
| K-91 | Dinamik istemci kaydı |
| K-92 | OpenTelemetry dışa aktarıcısı |
| K-93 | Personel rolleri |
| K-94 | Toplu kullanıcı içe aktarma, scrypt |
| K-95 | FIDO MDS3, WebAuthn Level 3 |
| K-96 | KMS/HSM `KeyProvider` |
| K-97 | Domain'in periyodik yeniden doğrulanması |
| K-98 | GeoIP uygulaması (imkânsız seyahat) |
| K-99 | HA referans dağıtımı (Helm, PostgreSQL HA, yedek) |
| Faz 3 | SAML 2.0, push MFA, telefonla giriş, kullanıcı adı tanımlayıcı, yönetim UI'ı, barındırılan giriş arayüzü |

## 12. Bakım

- Bir madde kapatıldığında buradan **silin** ve kapatan commit'i kaynak belgede (crate README, `remaining-work.md` §10) yazın.
- Yeni bir kabul edilen risk önce ilgili crate README'sine gerekçesiyle yazılır, sonra buraya eklenir.
