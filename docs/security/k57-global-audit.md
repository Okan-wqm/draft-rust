# K-57 — Modüller arası genel güvenlik denetimi

> Kapsam: `claude/compassionate-darwin-aa1tiy` dalı, başlangıç `72b1527`. Denetim 2026-11-05'te, Wave 6B ile paralel yapıldı.
> Modül bazlı denetimler önceki dalgalarda yapılmıştı. Bu denetim **modüller arasındaki dikişlere** bakar: bir crate'in, bir kontrolü "öbür taraf zaten yapıyor" varsaydığı yerlere.
> Yöntem: her bulgu önce, düzeltme olmadan **başarısız olan** bir regresyon testiyle kanıtlandı, sonra düzeltildi ve test yeşile döndü. Kanıtlanamayan kuşkular ayrı listede ("doğrulanmadı").

## 1. Tehdit modeli

| Saldırgan | Elinde ne var | Hedefi |
|-----------|---------------|--------|
| Anonim internet | Hiçbir şey; istediği başlığı yazabilir | Hesap varlığı tespiti, kaba kuvvet, IP tabanlı sınırları aşmak, open redirect, CSRF |
| Kimliği doğrulanmış kullanıcı | Kendi oturumu (web veya native) | Ayrıcalık yükseltme, kendi organizasyonunun politikasını atlatmak |
| Başka kiracının org admini | Kendi org'unda `owner`/`admin` rolü | Kiracılar arası IDOR, başka org verisine erişim |
| Kötü niyetli OAuth/OIDC IdP | Yapılandırılmış bir sağlayıcının imza anahtarı | Rastgele adres için "doğrulanmış e-posta" iddiası, hesap birleştirme, MFA iddiası |
| Çalınmış refresh token | Bir native oturumun refresh token'ı | Kalıcı erişim, iptalden sonra kullanım |
| Çalınmış cihaz | Açık bir web oturumu, güvenilir cihaz çerezi | Step-up olmadan hassas işlem, MFA atlatma |
| Anahtarsız ele geçirilmiş uygulama DB rolü | Uygulama rolüyle SQL; KEK/pepper/HMAC kökü yok | Sır okuma, audit zincirini yeniden hesaplama, oturum üretme |
| Kötü niyetli personel admini | Platform admin oturumu | Tek başına yıkıcı işlem, iz bırakmadan impersonation |

## 2. Neye bakıldı: kapsam matrisi

Gösterim: ✅ kontrol edildi ve sağlam. 🔧 bu denetimde bulundu ve düzeltildi. — uygulanmaz.

### 2.1 Oturum oluşturan yollar × kontroller

Oturum açan **her** yol aynı boru hattından geçer: `SessionService::plan_login` + `finish_login_in`, ya da challenge tamamlamada `advance`. Doğrudan `establish` çağrısı yalnızca bu iki yerde var. Impersonation kendi yolunu kullanır (`impersonate_in_tx`).

| Yol | Hesap durumu | Risk (RSK-03) | MFA politikası | Org politikası (istenen org) | Hız sınırı / kilit |
|-----|--------------|---------------|----------------|------------------------------|--------------------|
| Şifre (`/v1/login/password`) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Passkey (`/v1/login/passkey`) | ✅ | ✅ | ✅ (UV ⇒ `mfa`) | ✅ | ✅ |
| Magic link / e-posta kodu | ✅ | ✅ (posta kanıtı) | ✅ | ✅ | ✅ |
| Challenge tamamlama (MFA, kayıt, zorunlu eylemler) | ✅ (kilitli satırdan yeniden) | — (planda) | ✅ | ✅ (yeniden doğrulanır) | ✅ |
| Sosyal giriş (`SessionIssuer`) | ✅ | ✅ | ✅ (`amr` `primary_amr` ile süzülür) | ✅ | ✅ |
| Impersonation | ✅ (hedef + admin) | — | — (adminin `amr`'si) | — | ✅ (four-eyes, bütçe) |
| Şifre sıfırlama / kayıt / davet kabulü | Oturum açmaz (otomatik giriş yok) | — | — | — | — |

### 2.2 Oturum açıldıktan sonra organizasyon politikası × istek yolu

| Politika öğesi (ORG-07) | Giriş (org istenmişse) | Org değiştirme (SES-17) | Her org isteği (`authorize`) |
|-------------------------|------------------------|--------------------------|------------------------------|
| IP izin listesi | ✅ | ✅ | ✅ |
| MFA / phishing'e dayanıklı MFA | ✅ | ✅ | ✅ |
| Oturum ömrü üst sınırı | ✅ | ✅ | ✅ |
| İzinli giriş yöntemleri | ✅ | ✅ | 🔧 **F2** |
| İzinli MFA faktörleri | ✅ | ✅ (K-78) | 🔧 **F2** |

### 2.3 Diğer dikişler

| Alan | Bakılan | Sonuç |
|------|---------|-------|
| Kiracı izolasyonu | `authz::decide_access` (üyelik/servis hesabı, API anahtarı org bağı), audit ve webhook uçları (`ServerAuditAccess` → aynı karar), introspection (org'a bağlı), oturum yönetimi IDOR (`is_live_session_of`) | ✅ |
| Token türü karışıklığı | Tek JWT türü (access, `typ` sabit). Tek kullanımlık token'lar amaca göre (`purpose` + `kind`) tüketiliyor. Oturum, refresh, challenge, davet ve kayıt bağlantısı ayrı tablolarda | ✅ |
| İptalin yayılması | Şifre değişimi/sıfırlama, askıya alma, MFA sıfırlama, org çıkarma, acil iptal: `AccountAwareSessionRevoker` bekleyen e-posta değişikliklerini ve güvenilir cihazları da kapatır. Bearer istekleri canlı oturumu kontrol eder (üretimde zorunlu). `usable_user!` askıya alınmış/silinmiş sahibi ve demote edilmiş impersonation adminini her istekte reddeder | ✅ |
| Hesap varlığı sızıntısı | Kayıt, şifre sıfırlama, magic link, e-posta kodu (arka plan işi + sabit yanıt), e-posta değişikliği (kullanımdaki adres), davet (adres eşleşmesi oturum sahibinde), sosyal giriş (doğrulanmış adres kontrolü aramadan önce, K-63) | ✅ (bkz. §5 kalıntılar) |
| Step-up | Her modül `require_recent_authentication`'ı kullanıyor. Impersonation ve API anahtarı step-up yapamıyor (audit'te API anahtarı webhook yönetimi bilinçli istisna) | ✅ |
| CSRF / CORS / çerez | Kimlik doğrulama katmanı CSRF'yi her modül rotası için ortak uygular. Impersonation başlığı yalnızca yapılandırılmış konsol origin'inden (K-67). Native istemci çerez almaz | ✅ |
| Yönlendirme | `return_to` izin listesi (PRT-10), OIDC hata yönlendirmesi doğrulanıyor (K-73). E-posta bağlantıları yalnızca `public_base_url`'den | ✅ |
| Sırlar | Loglarda, audit metadata'sında, admin/dışa aktarım görünümlerinde hash, TOTP sırrı, kod veya token yok (grep taraması) | ✅ |
| Yapılandırma tuzakları | Üretim doğrulaması: https, SSRF, bellek içi hız sınırı, four-eyes, oturum kontrolü, CAPTCHA hostname'leri, yayımlanmış anahtarlar | 🔧 **F1** (`trusted_proxies`) |
| Eşzamanlılık | Tek kullanımlık token tüketimi atomik `UPDATE … RETURNING`. Davet kabulü org → davet kilit sırasıyla. Challenge ilerlemesi satır kilidi altında | ✅ |
| Sunucu bağlama | Her modül rotası kimlik doğrulama + CSRF katmanının içinde. Yalnızca break-glass kayıt uçları dışarıda (gerekçeli). Gövde sınırı, zaman aşımı, eşzamanlılık sınırı ve IP hız sınırı tüm router'da. Sağlık uçları yalnızca durum döndürür | ✅ |

## 3. Bulgular

| # | Şiddet | Bulgu | Durum |
|---|--------|-------|-------|
| F2 | **Orta** | Org'un izinli giriş yöntemleri ve izinli MFA faktörleri, org'u etkinleştirmemiş oturumlarda atlatılabiliyordu | ✅ Düzeltildi |
| F1 | **Orta (yapılandırma)** | `server.trusted_proxies` içinde `0.0.0.0/0` / `::/0` kabul ediliyordu: istemci IP'si istemcinin seçtiği değer olurdu | ✅ Düzeltildi |

### F2 — Org politikası (giriş yöntemi, MFA faktörü) kişisel bağlamdaki oturumlarda uygulanmıyordu

**Dikiş:** authn-org ↔ authn-session (+ authn-audit).

- `authn-org/src/service/policies.rs` belgesi şunu söylüyordu: "authn-session giriş yöntemlerini girişte ve org değiştirmede uygular."
- authn-session ise yalnızca `verify_login_org` (org istenen girişte) ve `switch_org` içinde kontrol ediyordu.
- Oysa `authz::decide_access`, bir üyenin **her** oturumunu `/v1/orgs/{org_id}/…` uçlarında yetkilendiriyordu. Aktif org şartı yoktu ve yalnızca IP, MFA (`amr`) ve oturum ömrü kontrol ediliyordu.

**Sonuçlar:**

- Yalnızca passkey'e (veya SSO'ya) izin veren bir org'un üyesi, şifreyle **org istemeden** giriş yapıp org'u hiç etkinleştirmeden org uçlarını kullanabiliyordu. Kapsanan uçlar: üyeler, davetler, API anahtarları, politika, audit, webhook'lar.
- Politika sıkılaştırması (`revoke_all_for_org`) yalnızca **aktif org'u bu org olan** oturumları iptal ediyor. Kişisel bağlamdaki oturumlar sıkılaştırmadan sonra da çalışmaya devam ediyordu.
- Aynı durum izinli MFA faktörleri için de geçerliydi. Örnek: `allowed_mfa_factors = [webauthn]` olan bir org'da TOTP ile `mfa` almış bir oturum org uçlarını kullanabiliyordu (K-78 yalnızca org değiştirmeyi kapatmıştı).
- Alan adıyla otomatik katılım girişten **sonra** çalıştığı için, az önce açılmış bir oturum da bu yoldan org'a girebiliyordu.

**Kanıt (düzeltmeden önce kırmızı):** `crates/authn-server/tests/k57_global_audit.rs`

- `org_07_k57_login_method_policy_applies_to_personal_context_sessions`: `/v1/session/org` doğru şekilde `403` döndü, ama `/v1/orgs/{org}/members` **`200`** döndü.
- `org_07_k57_allowed_factor_policy_applies_to_personal_context_sessions`: aynı desen, TOTP faktörüyle.
- `org_07_k57_policy_change_refuses_to_forbid_the_callers_login_method`: owner, kendi oturumunu dışarıda bırakacak politikayı `200` ile kaydedebiliyordu (kilitlenme koruması yoktu).

**Düzeltme:**

- `authn_core::domain::Principal`'a iki alan eklendi: `login_method: Option<LoginMethod>` ve `mfa_factors: Vec<FactorKind>`. İkisi de `#[serde(default)]`. authn-session bunları oturum kaydından doldurur (`SessionRecord::principal`, challenge principal'ı). API anahtarı ve oturum kontrolsüz bearer'da değer `None` / boş olur.
- Yeni `OrgPolicy::check_session_methods` (`authn-org/src/policy.rs`), `switch_org` ile aynı kuralları uygular:
  - bilinmeyen yöntem yalnızca kısıt yoksa geçer;
  - sonradan passkey ile step-up yapılmışsa passkey'e izin veren politika kabul eder;
  - impersonation muaftır;
  - faktör kısıtı yalnızca MFA zorunluysa uygulanır.
- `authz::decide_access` bu kontrolü her üye-oturum isteğinde çalıştırır. Hatalar: `login_method_not_allowed` (403) veya `org_policy_mfa_required` (403).
- `update_policy` kilitlenme korumasına `reason: login_method` / `mfa` eklendi (`org_policy_lockout`, 422).
- `switch_org`: oturum kontrolü kapalı bir bearer principal'ında (`access_token_session_check = false`, yalnızca geliştirme/test) bu alanlar yoktur. Org değiştirme, üyelik kontrolünden önce bunları saklanan oturumdan okur (`ses_17_login_method_policy_reads_the_stored_session_without_session_check` yeşil kalır). Diğer org uçları bu modda giriş yöntemi kısıtlı org'larda kapalı başarısız olur.
- Birim testi: `org_07_k57_login_method_and_second_factor_of_the_session_are_checked`.

### F1 — `trusted_proxies` her adresi kapsayabiliyordu

**Dikiş:** authn-core (IP çözümü) ↔ authn-protect (IP hız sınırı, risk), authn-org (IP izin listesi, API anahtarı IP listesi), authn-admin (break-glass kayıt IP listesi), authn-audit (IP kayıtları).

`resolve_client_ip`, eş (peer) güvenilirse hop listesini sağdan sola yürür. Her hop güvenilirse **en soldaki** hop'u istemci kabul eder. `0.0.0.0/0` (veya `::/0`) her eşi ve her hop'u güvenilir yapar. Bu durumda istemci IP'si `X-Forwarded-For`'a istemcinin yazdığı ilk değer olur. Sonuç olarak:

- IP başına hız sınırları atlatılır;
- org IP izin listesi atlatılır (izinli bir IP yazılır);
- break-glass kayıt IP listesi atlatılır;
- risk ve audit IP'leri sahte olur.

Doğrulama bu değeri **hiçbir ortamda** reddetmiyordu.

**Kanıt (kırmızı):** `authn-core` `config::tests::prt_06_k57_catch_all_trusted_proxies_are_refused`. Üretim yapılandırmasında `0.0.0.0/0` sorun listesinde yoktu.

**Düzeltme:** `ServerConfig::validate` önek uzunluğu 0 olan her girdiyi reddeder: `server.trusted_proxies[i]: must not trust every address`. Bu kural tüm ortamlarda geçerli, çünkü meşru bir kullanımı yok. `config/example.toml` açıklaması da güncellendi.

### Bağımsız yeniden denetim (F1/F2 düzeltmeleri)

Düzeltmeler bağımsız olarak yeniden denetlendi. İki eksik bulundu, ikisi de düzeltmeden önce kırmızıydı:

- **F2a — bearer token sonraki step-up'ın faktörünü devralıyordu (düşük).** Oturum kontrolü açıkken bearer principal'ı `amr`'yi token'dan, `mfa_factors`'u ise canlı oturum satırından alıyordu. Kurtarma koduyla `mfa` almış bir token, aynı oturum daha sonra TOTP ile step-up yapınca `allowed_mfa_factors = [totp]` olan org'un uçlarını kullanabiliyordu. Oysa token'ın kendi `amr`'sinde TOTP kanıtı yoktu ("token, kendisinden sonraki step-up'tan yararlanmaz" ilkesine aykırı). **Düzeltme:** `authenticate_bearer` (ve oturum kontrolsüz `switch_org` dolgusu) kayıtlı faktörleri token'ın `amr`'sinin kanıtladıklarıyla sınırlar (`factors_proven_by`: TOTP → `otp`, SMS → `sms`, e-posta → `email`, kurtarma kodu → `kba`, WebAuthn → `hwk`/`swk`). Bu yalnızca faktör çıkarır, asla eklemez. **Kanıt:** `org_07_k57_bearer_token_does_not_inherit_factors_of_a_later_step_up` (düzeltmeden önce eski token `200` aldı).
- **F1a — catch-all bölünerek kabul ettirilebiliyordu (orta, yapılandırma).** Kontrol yalnızca önek uzunluğu 0'ı reddediyordu. `0.0.0.0/1` + `128.0.0.0/1` (veya `::/1` + `8000::/1`, `2000::/3`) yine her adresi güvenilir yapıyordu. **Düzeltme:** IPv4'te `/8`'den kısa, IPv6'da `/16`'dan kısa önekler reddedilir; özel IPv6 aralıkları (`fc00::/7`, `fe80::/10`) hariç. Gerekçe: hiçbir özel IPv4 aralığı `/8`'den geniş değil; yayımlanmış yük dengeleyici/CDN aralıkları çok daha dar (ör. Cloudflare `104.16.0.0/13`, `2a06:98c0::/29`). **Kanıt:** `prt_06_k57_near_catch_all_trusted_proxies_are_refused`.

Yeniden denetimde sorun bulunmayan noktalar:

- `::ffff:0:0/96` zararsızdır: `resolve_client_ip` IPv4-eşlemeli adresleri IPv4'e dönüştürdükten sonra karşılaştırır, bu yüzden IPv6 biçimli bu girdi hiçbir adresle eşleşmez.
- Impersonation muafiyeti sunucu tarafı bir olguya dayanır: oturum satırındaki `impersonator_user_id` ya da imzalı token'daki `act` iddiası. İstemci bunu üretemez.
- API anahtarları ve servis hesapları oturum yöntemi kontrolüne girmez (`!api_key && Member`).
- `org_policies` tablosuna yazan tek yol `update_policy`'dir (org oluşturma yalnızca varsayılan satırı ekler). Admin API'sinde politika değiştiren bir yol yoktur, kilitlenme koruması atlatılamaz.
- `check_session_methods` ile `switch_org` aynı kararları verir. `switch_org` önce `check_membership` üzerinden aynı kontrolü çalıştırdığı için iki yol birbirinden ayrışamaz.
- `Principal` hiçbir yanıtta, logda veya dışa aktarımda serileştirilmez.

## 4. Doğrulanmadı (makul ama kanıtlanamadı)

| Kuşku | Neden kanıtlanamadı / değerlendirme |
|-------|--------------------------------------|
| Kötü niyetli genel (`oidc:<slug>`) IdP, rastgele bir adres için `email_verified=true` iddia ederek hesap varlığını öğrenebilir: var olan hesapta `oauth_link_required`, yoksa yeni hesap açılır | Sağlayıcıyı işletmeci yapılandırır. Otomatik bağlama yalnızca `auto_link_trusted_providers` için açık. Güvenilir sağlayıcı varsayımının parçası. Sağlayıcı başına "yalnızca kendi domain'leri" kısıtı Faz 2 kurumsal SSO'da (K-82) ele alınmalı |
| Introspection, org'un **herhangi** bir API anahtarıyla yapılabiliyor (kapsam gerekmiyor) | Yalnızca kendi org'unun token'larını görür (ARC-10). Ayrı bir `tokens:introspect` kapsamı en az yetki açısından daha iyi olur. Davranış değişikliği olduğu için Faz 2 OAuth sağlayıcısına (K-80) bırakıldı |
| Passkey kaydı aktif org'un AAGUID politikasına göre yapılıyor, en katı politikaya göre değil (`ServerPasskeyPolicy`) | Girişte ve step-up'ta doğrulama **en katı** politikayla süzüldüğü için izinsiz bir passkey ne giriş ne step-up için kullanılabiliyor. Etki: kullanılamayan bir passkey kaydedilebiliyor ve MFA faktörü sayısına giriyor (kullanılabilirlik, düşük) |
| `access_token_session_check = false` iken bearer principal'ının `login_method`'u bilinmez. Giriş yöntemi kısıtlı org'larda reddedilir | Bilinçli olarak kapalı başarısızlık. Üretimde bu ayar zaten kapatılamıyor (K-58) |

## 5. Kalan riskler

- **Paralel değişiklikler:** Wave 6B aynı ağaçta çalıştı (kayıt yarışı, TEMP yetkisi, webauthn FK indeksleri, risk audit metadata'sı). Bu denetimin testleri onların değişiklikleriyle birlikte koşuldu, ama onların bulgularını yeniden denetlemez.
- **Bilinen kısmi zamanlama sızıntısı:** eski bcrypt/PBKDF2 hash'li hesaplar, göç tamamlanana dek farklı süre alır (`remaining-work.md` §5.6).
- **Dış denetim:** bu iç denetim bağımsız bir pentest'in yerini tutmaz (K-72).
- **Faz 2 yüzeyi** (OAuth sağlayıcısı, SSO, SCIM, DPoP) burada kapsanmadı. Her biri kendi dikiş denetimini gerektirir. Özellikle K-82 `sso_required` uygulaması, F2'deki "her org isteğinde politika" kuralını izlemeli.

## 6. Değiştirilen dosyalar

- **Kod:**
  - `crates/authn-core/src/domain/principal.rs`
  - `crates/authn-core/src/config/server.rs`
  - `crates/authn-session/src/model.rs`
  - `crates/authn-session/src/login/challenge.rs`
  - `crates/authn-session/src/service/authenticate.rs`
  - `crates/authn-session/src/service/org_switch.rs`
  - `crates/authn-org/src/policy.rs`
  - `crates/authn-org/src/authz.rs`
  - `crates/authn-org/src/service/policies.rs`
  - `crates/authn-org/src/service/api_keys.rs`
  - `crates/authn-admin/src/guard.rs` (yalnızca test principal'ı)
- **Testler:**
  - `crates/authn-server/tests/k57_global_audit.rs` (yeni)
  - `crates/authn-core/src/config/mod.rs`
  - `crates/authn-org/src/policy.rs`
  - `Principal` literali olan test yardımcıları (`tests/common/mod.rs`): account, admin, audit, mfa, oidc-client, org, password, session, webauthn
    - org yardımcısının oturum principal'ı artık gerçek bir oturum gibi `login_method = password` taşır; `with_mfa` da `mfa_factors = [totp]` taşır
    - session yardımcısının `set_policy`'si, politikanın izin verdiği bir giriş yöntemi kullanır (kilitlenme koruması)
  - `crates/authn-server/tests/{mfa_factor_race.rs,perf/mod.rs}`
- **Belge:**
  - `config/example.toml`
  - `crates/authn-org/README.md`
  - `crates/authn-session/README.md`
  - bu dosya
  - `docs/handoff/remaining-work.md` (K-57 satırı)
