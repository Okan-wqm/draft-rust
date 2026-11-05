# Platform admin kurtarma rehberi (K-75)

Bu rehber, platform adminlerinin (admin API'si) ele geçirildiği, birbirine ulaşamadığı ya da kilitlendiği durumlarda operatörün ne yapacağını anlatır: iki adminli kurulum, break-glass hesabının kullanımı, çevrimdışı CLI komutları, ele geçirilmiş admin ve ele geçirilmiş break-glass prosedürleri, IP izin listesinin acil değiştirilmesi, çift onay (four-eyes) ve kayıt bağlantıları.

Belgedeki her `rust-authentication` komut satırı, her bayrak, her API yolu (yöntemi ve sorgu parametreleriyle) ve çıkış kodu tablosu bir testle koddan doğrulanır (`crates/authn-server/tests/operations_docs.rs`: `ops_01_k75_documented_cli_commands_parse`, `ops_01_k75_documented_subcommands_and_flags_exist`, `adm_01_k75_documented_admin_paths_exist`, `ops_01_k75_documented_methods_and_exit_codes_match`). Komutun ya da bayrağın adı değişirse test düşer, belge de birlikte güncellenir. Kodun ayrıntılı davranışı: `crates/authn-admin/README.md` (çift onay, hedef kuralları, limitler), `crates/authn-server/README.md` (CLI).

## 1. Kavramlar

| Kavram | Ne demek |
|--------|----------|
| **Platform admini** | `users.is_platform_admin = true` olan hesap. Admin API'si yalnızca passkey ile (UV dahil, `hwk`/`swk` + `mfa`) açılmış, son `admin.step_up_max_age` (varsayılan 10 dk) içinde step-up yapmış bir oturumla ve (ayarlıysa) IP izin listesinden çalışır. Yetki her istekte veritabanından yeniden okunur: askıya alınan admin bir sonraki istekte reddedilir. |
| **Break-glass hesabı** | `is_break_glass = true` olan platform admini; **yalnızca CLI ile** oluşturulur ve yönetilir. Son çare kurtarma yoludur: çift onaya ve paylaşılan (küresel, soğuma) limitlerine takılmaz, API'den askıya alınamaz, oturumları API'den kapatılamaz. Her kullanımı yüksek öncelikli `admin.break_glass_used` olayıdır. IP izin listesini **atlamaz** (K-13). |
| **Çift onay (four-eyes, K-66)** | Acil durum işlemleri ve başka bir platform adminini hedefleyen işlemler ikinci bir platform admininin onayını ister. `production`/`staging`'de varsayılan açık, `production`'da kapatılamaz. |
| **Çevrimdışı CLI komutları (K-07)** | Veritabanına doğrudan bağlanan, sunucu çalışmasa da çalışan komutlar. Onay istemez (veritabanına erişen operatör onayı zaten atlayabilir); `--operator` ve `--reason` zorunludur ve yüksek öncelikli audit'lenir (`surface: cli`). |
| **Kayıt bağlantısı (K-11)** | Break-glass hesabına passkey kaydettiren tek kullanımlık bağlantı: `{server.public_base_url}/admin/enroll#<token>`. Token URL **parçasındadır** (tarayıcı sunucuya göndermez, erişim loglarına düşmez). Varsayılan 30 dk, en çok 24 sa. |

## 2. Önerilen kurulum

- **En az üç normal platform admini** ve **en az bir break-glass hesabı**. Üç adminle, ele geçirilmiş bir admin diğer ikisinden birinin isteği ve üçüncüsünün onayıyla API'den askıya alınabilir. İki adminde bu mümkün değildir (bölüm 3).
- Break-glass hesabını `create-admin --passkey-link` ile **şifresiz** oluşturun ve passkey'i (donanım anahtarı) çevrimdışı, kasada saklayın. Şifreli oluşturulan break-glass hesabı da admin API'sine yalnızca passkey ile girebilir; şifre tek başına bir işe yaramaz ama çalınabilecek bir sırdır.
- Alarmlar (bölüm 9) kurulmadan üretime çıkmayın: break-glass kullanımı ve çift onay istisnaları alarm üretmezse, saldırganın bu yolları kullandığını kimse görmez.
- CLI'ı çalıştıracak operatörlerin listesini ve kimin hangi `--operator` etiketini kullandığını yazılı tutun; etiket yalnızca audit kaydıdır, kimlik doğrulaması değildir.

## 3. İki adminli kurulum

Wave 3B denetiminin 3B-1 düzeltmesinden beri işlemin **hedefi** olan admin de "başka admin" sayılır. Bu nedenle iki normal admin (A ve B) varken:

| İstenen işlem | API ile | Neden |
|---------------|---------|-------|
| A, B'yi askıya alır / B'nin oturumlarını kapatır / B'nin kilidini açar | **Yapılamaz** (`403 admin_approval_required`) | Onaylayabilecek üçüncü bir admin yok; hedef B kendi aleyhine onay veremez (`403 admin_target_not_allowed`). `no_second_admin` istisnası uygulanmaz, çünkü B aktif bir admindir. |
| A acil durum işlemi çalıştırır (tüm oturumları kapatma, imza anahtarı rotasyonu, toplu şifre değişikliği) | B'nin onayıyla | Normal çift onay akışı (bölüm 7) |
| Askıdaki bir admini geri alma | **Yapılamaz** (API hiçbir admini geri almaz) | Yalnızca `unsuspend-admin` (CLI) |

Bu bilinçli bir tasarımdır: saldırgan, ele geçirdiği tek adminle diğerini kaldırıp "tek admin" istisnasına düşemez. Kurtarma yolları:

1. **Break-glass hesabı** API'den askıya alabilir, oturum kapatabilir, kilit açabilir (onaysız; olay `admin.four_eyes_bypassed`, `exception: break_glass`).
2. **Çevrimdışı CLI**: `suspend-admin`, `revoke-admin-sessions`, `unsuspend-admin`, `revoke-admin` (bölüm 5).

Tek bir aktif normal admin kaldıysa (diğeri askıda ya da yok) acil durum işlemleri `no_second_admin` istisnasıyla onaysız çalışır ve yüksek öncelikli audit'lenir. Bu durumu API ile yaratmak mümkün değildir: aktif bir admini kaldırmak, o admin aktif kaldıkça her zaman çift onay ister.

## 4. Break-glass hesabının kullanımı

**Oluşturma** (yeni hesap; var olan bir adres asla sessizce admin yapılmaz, `conflict` döner):

```bash
rust-authentication --config /etc/authn/config.toml create-admin --email breakglass@example.com --passkey-link --ttl 30m
```

Çıktıdaki bağlantı **bir kez** gösterilir; güvenli bir kanalla (yüz yüze, şifreli kasa) iletin. Bağlantıyı açan ilk kişi passkey'i kaydeder. Kayıt yüksek öncelikli bir `admin.action` olayı (`action: break_glass_passkey_enrolled`) üretir; beklenmedik bir kayıt görülürse hemen bölüm 6.2'yi uygulayın.

Şifreli oluşturma (`--passkey-link` olmadan) 256 bitlik rastgele bir şifreyi **bir kez** yazdırır:

```bash
rust-authentication --config /etc/authn/config.toml create-admin --email breakglass@example.com
```

Bu şifre **tek kullanımlık bir başlangıç şifresidir** (K-110):

- `must_change_password` işaretiyle saklanır (PWD-12). İlk giriş hiçbir zaman doğrudan oturum açmaz: önce hesabın adresine e-postayla gelen kod girilir (posta kutusu kanıtı; yalnızca yazdırılmış şifreyi bulan kişi passkey kaydedemez), sonra passkey kaydı ve yeni şifre seçimi (`change_password`) istenir.
- Oluşturulduktan **24 saat** sonra (sabit, `authn_admin::BREAK_GLASS_PASSWORD_TTL`) değiştirilmemişse geçersiz olur. Süresi dolmuş şifre, yanlış şifreyle **aynı** yanıtı alır (`401 invalid_credentials`, aynı doğrulama maliyeti): hesabın varlığı ya da durumu sızmaz. İlk girişte seçilen yeni şifrenin süresi dolmaz. Komut çıktısı son geçerlilik zamanını yazar.
- Oluşturma olayı (`admin.action`, `action: break_glass_admin_created`, `enrollment: password`) son geçerlilik zamanını `initial_login_expires_unix` olarak taşır; süresi dolmuş şifreyle her deneme normal `login.failed` olayıdır.
- Süresi dolan ya da kaybolan şifre için hesabı silmeye gerek yok: `admin-enrollment-link` (bölüm 5) şifreyi siler ve tek kullanımlık passkey bağlantısı üretir.

**İlk giriş adım adım** (K-112; web istemcisinde challenge token'ı `__Host-authn_challenge` çerezinde, native'de `X-Authn-Challenge` başlığında):

1. `POST /v1/login/password` (adres + yazdırılan şifre) → `challenge_required`, `required_actions: ["verify_mfa", "enroll_mfa", "change_password"]`, `allowed_factors: ["email"]`. Bu aşamada passkey kaydı **sunulmaz** (`403 challenge_step_not_allowed`).
2. `POST /v1/login/challenge/send-code` (`{"channel": "email_confirmation"}`), gelen kodla `POST /v1/login/challenge/verify` (`{"method": "email_confirmation", "code": "…"}`) → `required_actions: ["enroll_mfa", "change_password"]`, `allowed_factors: ["webauthn"]`.
3. `POST /v1/login/challenge/passkey/register/options` → donanım anahtarıyla `navigator.credentials.create()` → `POST /v1/login/challenge/passkey/register/verify`. Seremoni bu challenge'a, hesaba ve bir bağlama token'ına bağlıdır (başka bir girişin seremonisi kullanılamaz, tek kullanımlıktır); RP kimliği/origin ve kuruluşların AAGUID politikası uygulanır. Passkey, challenge'ın ilerlemesiyle aynı transaction'da saklanır ve bu girişin ikinci faktörü olur. Olay: `passkey.registered` (`enrollment: login_challenge`).
4. `POST /v1/login/challenge/step` (`{"step": "change_password", "new_password": "…"}`) → oturum. Oturum passkey'le açılmış sayılır (`amr`: `hwk`/`swk` + `mfa`), admin API'si açılır; sonraki girişler doğrudan passkey'ledir.

Uçtan uca test: `crates/authn-server/tests/login_passkey_enrollment.rs` (`ses_22_k112_password_break_glass_admin_completes_login_with_passkey_enrollment`). Yine de yeni kurulumda `--passkey-link` önerilir: kasada şifre gibi çalınabilecek bir sır hiç oluşmaz.

**Kullanma:** break-glass hesabıyla passkey'le giriş yapılır, step-up yine passkey'le yapılır ve konsoldaki her işlem normal admin uçlarından yürür. Farklar:

- Çift onay istemez (`admin.four_eyes_bypassed`, `exception: break_glass`).
- Paylaşılan limitlerden (acil durum küresel bütçesi, soğuma süresi, admin hedefli küresel bütçe) muaftır; admin başına bütçe ona da uygulanır. Saldırganın tükettiği bütçe kurtarmayı engellemez.
- IP izin listesine tabidir (K-13); gerekirse önce bölüm 6.3.
- Break-glass hesabı başka bir break-glass hesabını API'den askıya alamaz; bunun için CLI kullanılır.

İş bitince oturumu kapatın (`POST /v1/logout`) ve kullanımı olay kaydına yazın.

## 5. Çevrimdışı CLI komutları

Hepsi sunucunun yapılandırmasıyla (`--config <dosya>` ya da `AUTHN_CONFIG`, `AUTHN__*` ortam değişkenleri dosyayı ezer) veritabanına bağlanır. Şema güncel değilse çalışmaz (çıkış kodu 69); önce `migrate`. Bildirimler outbox'a yazılır, çalışan sunucu teslim eder.

| Komut | Bayraklar | Ne yapar |
|-------|-----------|----------|
| `create-admin` | `--email <adres>` (zorunlu), `--passkey-link`, `--ttl <süre>` (yalnızca `--passkey-link` ile; varsayılan `30m`, en çok `24h`) | Yeni break-glass hesabı; tek kullanımlık başlangıç şifresini (ilk girişte değiştirilir, kullanılmazsa 24 saatte geçersiz, K-110) ya da kayıt bağlantısını bir kez yazdırır |
| `admin-enrollment-link` | `--target <e-posta\|kullanıcı id>`, `--reason <gerekçe>`, `--operator <ad>` (üçü zorunlu), `--ttl <süre>` | Var olan **break-glass** hesabına yeni bağlantı; aynı transaction'da şifre, tüm passkey'ler, MFA faktörleri (kurtarma kodları, güvenilir cihazlar) ve oturumlar silinir, eski açık bağlantılar geçersiz olur. Askıdaki hesapta da çalışır |
| `suspend-admin` | `--target`, `--reason`, `--operator` | Platform adminini (break-glass dahil) askıya alır; oturumları, güvenilir cihazları ve başlattığı impersonation oturumları biter |
| `unsuspend-admin` | `--target`, `--reason`, `--operator` | Askıyı kaldırır (doğrulanmış adres → `active`) |
| `revoke-admin-sessions` | `--target`, `--reason`, `--operator` | Yalnızca oturumları (ve güvenilir cihazları) kapatır |
| `grant-admin` | `--target`, `--reason`, `--operator` | Var olan, `active` bir hesabı **normal** platform admini yapar (K-76). Hesabın tüm oturumları ve güvenilir cihazları kapanır: yetkiden önce açılmış bir oturum (ya da çalınmış bir çerez) admin oturumuna dönüşmez. Zaten admin olan hesapta `conflict`, aktif olmayan hesapta `admin_target_not_allowed` |
| `revoke-admin` | `--target`, `--reason`, `--operator` | Platform admini (ve break-glass) yetkisini kalıcı olarak alır (K-76). Hesap kalır; askıdaysa askıda kalır. Oturumlar, güvenilir cihazlar, başlattığı impersonation oturumları ve açık kayıt bağlantıları biter. Bekleyen istekleri kullanılamaz olur; verdiği onaylar kullanım anında yeniden denetlendiği için geçersizleşir. Geriye **başka aktif bir platform admini** (break-glass dahil) kalmayacaksa reddedilir (`admin_target_not_allowed`, "last admin"). Eşzamanlı `grant-admin` / `revoke-admin` komutları sıraya girer |
| `rotate-signing-key` | `--emergency` | Etkin JWT imza anahtarını hemen iptal edip yenisini etkinleştirir (anahtar sızıntısı); bayraksız: bekleyen anahtar planlanır |
| `verify-audit-chain` | — | Audit hash zincirini doğrular; bozuksa çıkış kodu 1 |
| `check-config` | — | Yapılandırmayı `serve`'ün açılışta uyguladığı tüm kurallarla doğrular; veritabanına bağlanmaz |

Girdi kuralları: `--operator` 1–64 karakter `[A-Za-z0-9._@-]`, `$USER`'a geri düşülmez; `--reason` 1–1000 yazdırılabilir karakter (kontrol ve görünmez biçim karakterleri reddedilir). Hatalı değer veritabanına dokunmadan önce reddedilir; hata bayrağı adlandırır, değeri yankılamaz. Hedef yalnızca platform admini olabilir (normal kullanıcıya `admin_target_not_allowed`); tek istisna `grant-admin`'dir. `--target` e-posta adresi ya da kullanıcı id'si alır. Olay sırasında **kullanıcı id'sini** tercih edin: ele geçirilmiş bir hesabın adresi saldırgan tarafından değiştirilmiş olabilir.

API platform admini yetkisini bilinçli olarak hiçbir zaman vermez ya da geri almaz (çift onayla bile). Ele geçirilmiş bir konsol oturumu ve ikna edilmiş ikinci bir admin yeni admin yaratamaz. Yetki değişikliği için veritabanına erişimi olan operatör gerekir.

| Çıkış kodu | Anlamı |
|------------|--------|
| 0 | Başarılı |
| 1 | `verify-audit-chain`: zincir bozuk; G/Ç hatası |
| 65 | Girdi hatası (bayrak değeri) |
| 69 | Veritabanı / servis hatası, şema güncel değil, işlem reddedildi |
| 78 | Yapılandırma geçersiz (`check-config`'in reddettiği her değer dahil) |

## 6. Prosedürler

### 6.1 Ele geçirilmiş normal admin

1. **Kanıtı koruyun:** `GET /v1/admin/audit-events?actor_user_id=<id>` ile son işlemleri dışa aktarın (`POST /v1/admin/audit-events/export`). Zincirin sağlamlığını `rust-authentication verify-audit-chain` ile doğrulayın.
2. **Askıya alın.** Üç ya da daha çok aktif admin varsa konsoldan, çift onayla (bölüm 7): bir admin `POST /v1/admin/approvals` ile `{"action": "suspend_user", "target_user_id": "<id>", "reason": "…"}` ister, üçüncü bir admin `POST /v1/admin/approvals/{approval_id}/approve` ile onaylar, isteyen `POST /v1/admin/users/{user_id}/suspend` gövdesine `approval_id` koyarak çalıştırır. İki adminli kurulumda, ya da hızın önemli olduğu her durumda, break-glass hesabıyla aynı uç onaysız çağrılır. API'ye ulaşılamıyorsa:

   ```bash
   rust-authentication --config /etc/authn/config.toml suspend-admin --target suspect-admin@example.com --reason "INC-123 compromised console session" --operator alice.ops
   ```

3. **Etkiyi sınırlayın:** saldırganın imza anahtarına eriştiğinden şüpheleniliyorsa acil anahtar rotasyonu (`POST /v1/admin/emergency/rotate-signing-key` ya da `rust-authentication --config /etc/authn/config.toml rotate-signing-key --emergency`); kullanıcı oturumları etkilendiyse `POST /v1/admin/emergency/revoke-all-sessions`.
4. **Ele geçirilmiş hesabı admin olarak askıdan çıkarmayın.** Saldırgan konsol oturumunda kendi passkey'ini, TOTP'sini ya da şifresini eklemiş olabilir. `unsuspend-admin` bunların hepsini geri getirir. API bir platform admininin faktörlerini sıfırlayamaz, bu yüzden hesabı **önce admin olmaktan çıkarın**, sonra normal kullanıcı olarak temizleyin:

   ```bash
   rust-authentication --config /etc/authn/config.toml revoke-admin --target 0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b --reason "INC-123 admin rights withdrawn" --operator alice.ops
   ```

   Hesap askıda kalır ve artık normal bir kullanıcıdır. Bu yüzden konsoldan başka bir admin, çift onaysız ve normal hedef kurallarıyla, şunları yapabilir: `POST /v1/admin/users/{user_id}/reset-mfa` (tüm MFA faktörleri, kurtarma kodları, güvenilir cihazlar ve **tüm passkey'ler**), `POST /v1/admin/users/{user_id}/force-password-reset`, ardından `POST /v1/admin/users/{user_id}/unsuspend`. Sıfırlama bağlı sosyal kimlikleri **kaldırmaz** (bölüm 10). Kişi kendi kimliğini doğrulayıp yeni passkey'ini kaydettikten sonra, ve yalnızca hâlâ admin olması gerekiyorsa, yetkiyi yeniden verin:

   ```bash
   rust-authentication --config /etc/authn/config.toml grant-admin --target 0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b --reason "INC-123 closed, credentials replaced" --operator alice.ops
   ```

   `revoke-admin`, geride başka aktif bir admin kalmıyorsa reddedilir. Bu durumda önce yeni bir admin yaratın (`create-admin` ya da başka bir hesaba `grant-admin`).

5. **Onayları gözden geçirin:** şüpheli adminin açtığı bekleyen istekleri (`GET /v1/admin/approvals`) reddedin. Askıdaki ya da yetkisi alınmış bir adminin verdiği onaylar kullanım anında geçersizdir (onaylayan hâlâ aktif admin olmalı). Onaylanıp **çalıştırılmış** işlemleri audit kaydından çıkarın.

### 6.2 Ele geçirilmiş break-glass hesabı

API bu hesaba bilinçli olarak dokunamaz. Sıra önemlidir: askıdan çıkarma ile yeni kayıt arasında hesabın bağlantıdan başka kimlik bilgisi kalmamalıdır.

Örneklerde hedef e-postayla yazılmıştır. Gerçek olayda break-glass hesabının **kullanıcı id'sini** kullanın: hesabı ele geçiren kişi adresini değiştirmiş olabilir.

1. Hesabı askıya alın (oturumlar, güvenilir cihazlar, başlattığı impersonation oturumları biter):

   ```bash
   rust-authentication --config /etc/authn/config.toml suspend-admin --target breakglass@example.com --reason "INC-124 break-glass passkey lost" --operator alice.ops
   ```

   Yalnızca oturumları düşürmek yetiyorsa: `rust-authentication --config /etc/authn/config.toml revoke-admin-sessions --target breakglass@example.com --reason "INC-124 unexpected session" --operator alice.ops`.

2. Hesap **askıdayken** yeni bağlantı üretin. Bu adım şifreyi, tüm passkey'leri, MFA faktörlerini ve oturumları aynı transaction'da siler ve eski bağlantıları geçersiz kılar (`create-admin` var olan hesap için kullanılamaz):

   ```bash
   rust-authentication --config /etc/authn/config.toml admin-enrollment-link --target breakglass@example.com --reason "INC-124 replace credentials" --operator alice.ops --ttl 30m
   ```

3. Askıyı kaldırın (bağlantı yalnızca aktif hesapta çalışır):

   ```bash
   rust-authentication --config /etc/authn/config.toml unsuspend-admin --target breakglass@example.com --reason "INC-124 re-enrolment" --operator alice.ops
   ```

4. Bağlantıyı güvenli kanalla açtırıp yeni passkey'i kaydedin. `admin.action` (`action: break_glass_passkey_enrolled`) olayının tam olarak bir kez, beklenen zamanda geldiğini doğrulayın. Bağlantı süresi dolarsa 2. adımı tekrarlayın (önce yeniden `suspend-admin`).
5. Saldırganın break-glass hesabıyla ne yaptığını audit kaydından çıkarın. Askıya aldığı ya da oturumunu kapattığı adminleri gerekirse `unsuspend-admin` ile geri getirin. Saldırganın break-glass hesabıyla impersonation (ADM-04) yoluyla dokunduğu kullanıcı hesaplarını ayrıca inceleyin.
6. Break-glass hesabı artık gerekmiyorsa onu onarmak yerine yetkisini kaldırabilirsiniz: `revoke-admin` (önce `create-admin` ile yenisini oluşturun; son aktif admin yetkisi kaldırılamaz).

### 6.3 IP izin listesinin acil değiştirilmesi

`[admin] ip_allow_list` (CIDR listesi; boş = her yer) sunucu yapılandırmasıdır, çalışırken değişmez. İstemci IP'si PRT-06 kurallarıyla (güvenilir proxy'ler) çözülür; proxy yapılandırması yanlışsa izin listesi yanlış IP'ye bakar.

1. Geçici CIDR'ı **olabildiğince dar** ekleyin (ör. tek bir adres `/32`) ve değişikliği altyapı değişiklik kaydına yazın:

   ```toml
   [admin]
   ip_allow_list = ["10.0.0.0/8", "203.0.113.7/32"]
   ```

2. Yeni yapılandırmayı **yeniden başlatmadan önce** doğrulayın (yanlış bir CIDR sunucunun açılmamasına yol açar):

   ```bash
   rust-authentication --config /etc/authn/config.toml check-config
   ```

3. Sunucuyu (tüm instance'ları) yeniden başlatın, işi yapın, geçici girdiyi kaldırıp aynı adımlarla geri alın.

Break-glass hesabı da izin listesine tabidir (K-13); listeden çıkarılmış bir ağdan kurtarma gerekiyorsa önce bu bölüm uygulanır. İzin listesi dışındaki her admin denemesi `admin.action` (`admin_access`, başarısız) olarak audit'lenir.

### 6.4 Çift onay iş akışı

Kritik işlemler: `POST /v1/admin/emergency/revoke-all-sessions`, `POST /v1/admin/emergency/rotate-signing-key`, `POST /v1/admin/emergency/force-password-change` ve başka bir platform adminini hedefleyen `POST /v1/admin/users/{user_id}/suspend`, `POST /v1/admin/users/{user_id}/unlock`, `POST /v1/admin/users/{user_id}/revoke-sessions`.

1. **İstek:** isteyen admin `POST /v1/admin/approvals` ile işlemi **tam parametreleriyle** bildirir. `action` değerleri: `revoke_all_sessions` (`include_own_session`), `rotate_signing_key`, `force_password_change_before` (`changed_before`, `revoke_sessions`), `suspend_user`, `unlock_user`, `revoke_user_sessions` (son üçü `target_user_id` ister). İstek `admin.four_eyes_approval_ttl` (varsayılan 30 dk, 5 dk – 2 sa) sonunda düşer. Bekleyen istekler: `GET /v1/admin/approvals`.
2. **Karar:** **farklı** bir admin, kendi passkey oturumu ve step-up'ıyla `POST /v1/admin/approvals/{approval_id}/approve` ya da `POST /v1/admin/approvals/{approval_id}/deny` (gerekçe zorunlu). İsteyen kendi isteğini, hedef admin kendisine yönelik isteği onaylayamaz. Onaylamadan önce `params` alanını işlemle tek tek karşılaştırın ve isteyenle başka bir kanaldan (telefon, yüz yüze) konuşun: ele geçirilmiş bir admin de istek açabilir.
3. **Çalıştırma:** isteyen, işlemi **aynı parametrelerle** ve `approval_id` ile çağırır. Onay tek kullanımlıktır; parametre değişirse `403 admin_approval_invalid`.

**Onay yorgunluğu sınırları (K-74):** bir admin aynı anda en çok `admin.four_eyes_max_pending_requests` (varsayılan 3, 1–10) bekleyen ve saatte en çok `admin.four_eyes_max_requests_per_hour` (varsayılan 10, 1–60, bekleyen sınırından küçük olamaz) istek açabilir; reddedilenler saatlik sınıra sayılır. Aşılırsa `429 rate_limited` ve yüksek öncelikli audit (`approvals_pending_per_admin` / `approvals_per_hour_per_admin`). Sınır dışı değerler yapılandırma doğrulamasında reddedilir (sunucu açılmaz).

**Hedefe sızdırmama:** başka bir admini hedefleyen istek ve karar olayları istek süresi dolana kadar hedefin kendi olay listesinde görünmez.

### 6.5 Kayıt bağlantıları

- Yalnızca break-glass hesapları içindir: yeni hesapta `create-admin --passkey-link`, var olan hesapta `admin-enrollment-link` (bölüm 5).
- Token 256 bit rastgeledir, veritabanında yalnızca SHA-256'sı tutulur. Bağlantı passkey'i saklayan transaction'da tüketilir: iki eşzamanlı tamamlama tek passkey üretir.
- Bilinmeyen, kullanılmış ve süresi dolmuş bağlantılar aynı `400 invalid_or_expired_token`'ı alır. Kayıt uçları (`POST /v1/admin/enrollment/options`, `POST /v1/admin/enrollment/verify`) oturum istemez ama IP izin listesine ve IP başına limite (20 / 15 dk) tabidir.
- Bağlantıyı açık kanallardan (sohbet, bilet sistemi, e-posta) göndermeyin. Ele geçirildiğinden şüpheleniyorsanız bölüm 6.2'nin 1–3. adımlarıyla yenisini üretin: eski bağlantı geçersiz olur.

## 7. Konsoldan değil, CLI'dan yapılması gerekenler (özet)

| Durum | Yol |
|-------|-----|
| Break-glass hesabı oluşturma | `create-admin` |
| Break-glass hesabını askıya alma / oturumlarını kapatma | `suspend-admin` / `revoke-admin-sessions` |
| Herhangi bir admini askıdan çıkarma | `unsuspend-admin` |
| Break-glass kimlik bilgilerini değiştirme | `admin-enrollment-link` |
| İki adminli kurulumda diğer admini kaldırma | break-glass (API) ya da `suspend-admin` |
| Normal platform admini yetkisi verme / geri alma | `grant-admin` / `revoke-admin` |
| Ele geçirilmiş bir adminin faktörlerini temizleme | `revoke-admin`, sonra konsoldan normal kullanıcı olarak `reset-mfa` |
| API'ye ulaşılamıyorken anahtar sızıntısı | `rotate-signing-key --emergency` |

## 8. Gerekçe ve operatör alanları

Her CLI işleminin `--reason` metni `admin_action_reasons` tablosuna (hash zinciri dışında, ekleme-yalnızca) yazılır ve kullanıcının veri dışa aktarımında görünebilir; kişisel veri ya da sır koymayın, olay numarasıyla kısa tutun. `--operator` audit olayında olduğu gibi saklanır.

## 9. Alarmlar

Şunlara alarm kurun (hepsi yüksek öncelikli audit olayı ve/veya metriktir):

- `admin.break_glass_used`, metrik `authn_break_glass_logins_total`
- `admin.four_eyes_bypassed` (`exception`: `break_glass` / `no_second_admin`), metrik `authn_admin_four_eyes_bypassed_total{exception}`
- `admin.action` olaylarında `surface: cli` (her çevrimdışı komut) ve `reason`: limit adları
- `authn_admin_throttled_total{limit}`, `authn_admin_four_eyes_refused_total`
- `admin.action` olaylarında `action: break_glass_passkey_enrolled`

## 10. Bilinen sınırlamalar

- Admin yetkisi yalnızca CLI ile verilir ve geri alınır (`grant-admin` / `revoke-admin`, K-76). API'de bilinçli olarak böyle bir uç yoktur. Veritabanını elle değiştirmeyin: elle yapılan değişiklik audit'lenmez, oturumları kapatmaz ve son admin kuralını atlar.
- Admin hesaplarının şifresini ya da MFA'sını doğrudan sıfırlayan bir komut yoktur. Yol, bölüm 6.1'deki gibi `revoke-admin` → konsoldan normal kullanıcı olarak sıfırlama → `grant-admin`'dir.
- `reset-mfa` bağlı sosyal kimlikleri kaldırmaz. Saldırgan kendi sağlayıcı hesabını bağlamış olabilir: kişi `/v1/me/identities` listesini gözden geçirip tanımadığı kimliği ayırmalıdır. Sosyal girişle açılan bir oturum admin API'sine erişemez (passkey zorunlu), ama normal hesaba erişir.
- IP izin listesi değişikliği yeniden başlatma ister.
