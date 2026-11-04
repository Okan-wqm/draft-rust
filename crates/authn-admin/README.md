# authn-admin

`/v1/admin` altındaki platform admin API'si: kullanıcı arama/detay, kullanıcı işlemleri (askıya alma, kilit açma, oturum kapatma, şifre sıfırlama zorunluluğu, MFA sıfırlama, e-postayı doğrulandı işaretleme), impersonation, break-glass hesapları, acil durum işlemleri ve audit sorgulama/dışa aktarma/zincir doğrulama.

## Sahip olunan gereksinimler

| Kimlik | Nerede | Özet | Testler |
|--------|--------|------|---------|
| ADM-01 | `guard.rs`, `service/mod.rs` (`authorize`) | Yalnızca platform admini (her istekte veritabanından yeniden okunur, `active` olmalı), oturum passkey ile phishing'e dayanıklı MFA (`amr`: `hwk`/`swk` **ve** `mfa`), her istek için son 10 dk içinde step-up, isteğe bağlı IP izin listesi; impersonation altındaki (salt-okunur veya yazılabilir) principal'lar, API anahtarları ve servis hesapları reddedilir. | `tests/authorization.rs` (`adm_01_*`), `guard.rs` birim testleri |
| ADM-02 | `service/users.rs` | Keyset sayfalı (`created_at DESC, id DESC`, `OFFSET` yok) arama: e-posta öneki, durum, platform admini, doğrulanmış, oluşturma aralığı. Detay: hesap, şifre durumu (hash yok), MFA durumu (sır yok, telefon maskeli), yumuşak kilit. Detay görüntüleme audit'lenir (`user_viewed`). | `tests/users.rs` (`adm_02_*`) |
| ADM-03 | `service/actions.rs` | Askıya al / geri al, kilit aç, oturumları kapat, şifre sıfırlamaya zorla, `must_change_password`, MFA sıfırla (kullanıcıya bildirim authn-mfa'dan), e-postayı doğrulandı işaretle (`MailboxProof::Administrator`). Her biri tek transaction + audit + gerekçe. | `tests/actions.rs` (`adm_03_*`) |
| ADM-04 | `service/impersonation.rs` | Varsayılan 15 dk, en çok 60 dk (yapılandırma ne derse desin), gerekçe zorunlu, varsayılan salt-okunur, web veya native (`act` claim'i). `SessionIssuer::start_impersonation_with(ctx, req, client, Some(admin_session))`; bildirim ve `admin.impersonation_started` olayını session yazar, burada **tekrarlanmaz**. Adminlere, break-glass hesaplarına, kendine ve `active` olmayan hesaplara uygulanamaz. | `tests/impersonation.rs` (`adm_04_*`) |
| ADM-05 | `break_glass.rs`, `service/mod.rs` | CLI `create-admin` için `create_break_glass_admin`: 256 bit CSPRNG şifre bir kez döner; oluşturma yüksek öncelikli audit olayıdır. Break-glass hesabının admin API'sindeki her isteği yüksek öncelikli `admin.break_glass_used` olayı üretir; işlemleri `break_glass: true` ile işaretlenir. | `adm_05_break_glass_admin_creation`, `adm_05_break_glass_use_emits_high_priority_event` |
| ADM-06 | `service/emergency.rs` | Tüm oturumları kapat (`revoke_everything`), imza anahtarını acil rotasyon (`SigningKeyRepository::emergency_rotate` + `SigningKeyCache` kancası), tarihten önce şifresi değişmemiş herkese şifre değişikliği zorunluluğu (toplu, parti parti). Hepsi `confirm` alanında işlem adının tekrarını ister. | `tests/emergency.rs` (`adm_06_*`) |
| ADM-07 | `service/audit.rs` | Platform geneli audit sorgusu (`authn_audit::list_events`, keyset), sınırlı ve devam ettirilebilir dışa aktarma (gerekçe zorunlu, audit'lenir), zincir doğrulama (baştan veya dışarıda saklanan çapadan). | `tests/audit.rs` (`adm_07_*`) |
| ADM-08 | `reason.rs`, `service/mod.rs` (`record_action`), migration `2200` | Her admin işlemi `admin.action` / `admin.emergency_action` olayıyla (gerçek aktör = admin, `action` kodu) ve gerekçeyle kaydedilir. Gerekçe serbest metin olduğu ve kişisel veri içerebileceği için hash zincirine **girmez** (AUD-03); `admin_action_reasons` tablosunda olay kimliğine bağlı tutulur. | `adm_08_*`, `actions.rs` içindeki `assert_audited` |

## Bağımlılık kuralı

Dalga B. `authn-core`, `authn-crypto`, `authn-store` ve Dalga A (`password`, `account`, `mfa`, `org`, `protect`, `audit`) crate'lerine bağımlıdır; `authn-session` ve `authn-oidc-client`'e bağımlı **değildir** (oturum kapatma `SessionRevoker`, impersonation `SessionIssuer` portu ile; imza anahtarı önbelleği `SigningKeyCache` kancası ile). Yeni harici bağımlılık eklenmedi.

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-admin/**` |
| Konfigürasyon | `crates/authn-core/src/config/admin.rs` (`[admin]`, değiştirilmedi) |
| Hata kodları | `crates/authn-core/src/error/codes/admin.rs` |
| Tablo | `admin_action_reasons` (migration `2200_admin_action_reasons.sql`) |
| Migration aralığı | `2200–2299` |

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `AdminService::new(AdminServiceDeps { … }, AdminSettings::from_app_config(&config))` | Router durumu (`FromRef`) |
| `AdminService::authorize(&principal, &ctx) -> AdminCaller` | ADM-01 kontrolü (extractor bunu çağırır) |
| `AdminCaller` (extractor) | Her handler'ın ilk argümanı; yalnızca `authorize` üretir |
| `search_users`, `user_detail` | ADM-02 |
| `suspend_user`, `unsuspend_user`, `unlock_user`, `revoke_user_sessions`, `force_password_reset`, `set_must_change_password`, `reset_user_mfa`, `mark_email_verified` | ADM-03 |
| `impersonate(caller, ctx, target, &Justification, &ImpersonationOptions)` | ADM-04 |
| `revoke_all_sessions`, `rotate_signing_key`, `force_password_change_before` | ADM-06 |
| `query_audit`, `export_audit`, `verify_audit_chain` | ADM-07 |
| `create_break_glass_admin(pool, hasher, clock, audit, email) -> BreakGlassAdmin { user_id, password }` | ADM-05 (CLI) |
| `Justification::parse(Option<&str>)` | 1–1000 karakter, kontrol/görünmez biçim karakteri yok |
| `SigningKeyCache` trait, `NoSigningKeyCache` | Acil rotasyon sonrası süreç içi anahtar önbelleğini düşürme |
| `router::<S>()`, `AdminApi` (utoipa) | HTTP ve OpenAPI |
| `authorize` (saf fonksiyon), `is_phishing_resistant_mfa`, `Denial` | ADM-01 kararının kendisi |

## Endpoint'ler

Hepsi: platform admini + passkey MFA oturumu + son 10 dk içinde step-up + (varsa) IP izin listesi; impersonation altında asla. Yanıtlar `Cache-Control: no-store`.

| Yöntem | Yol | Gövde | Gereksinim |
|--------|-----|-------|------------|
| GET | `/v1/admin/users?limit&cursor&email&status&platform_admin&email_verified&created_after&created_before` | — | ADM-02 |
| GET | `/v1/admin/users/{user_id}` | — | ADM-02 |
| POST | `/v1/admin/users/{user_id}/suspend` | `{reason}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/unsuspend` | `{reason}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/unlock` | `{reason}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/revoke-sessions` | `{reason}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/force-password-reset` | `{reason, send_reset_email?}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/must-change-password` | `{reason, must_change}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/reset-mfa` | `{reason}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/mark-email-verified` | `{reason}` | ADM-03 |
| POST | `/v1/admin/users/{user_id}/impersonate` | `{reason, ttl_minutes?, read_only?, client?}` | ADM-04 |
| POST | `/v1/admin/emergency/revoke-all-sessions` | `{reason, confirm: "revoke_all_sessions"}` | ADM-06 |
| POST | `/v1/admin/emergency/rotate-signing-key` | `{reason, confirm: "rotate_signing_key"}` | ADM-06 |
| POST | `/v1/admin/emergency/force-password-change` | `{reason, confirm: "force_password_change", changed_before, revoke_sessions?}` | ADM-06 |
| GET | `/v1/admin/audit-events?limit&cursor&kind&category&outcome&actor_user_id&subject_user_id&org_id&resource_type&since&until` | — | ADM-07 |
| POST | `/v1/admin/audit-events/export` | `{reason, filter}` | ADM-07 |
| POST | `/v1/admin/audit-events/verify` | `{anchor?: {seq, hash}}` (boş gövde `{}`) | ADM-07 |

Kontrol sırası: kimlik doğrulama (`401 unauthenticated`) → impersonation / oturum dışı kimlik bilgisi / admin değil / IP izinli değil (hepsi aynı `403 forbidden`; admin olmayan biri admin API'si veya izin listesi hakkında bir şey öğrenmez) → passkey MFA (`403 admin_phishing_resistant_mfa_required`) → step-up (`401 step_up_required`) → gövde doğrulama (`422 admin_reason_required`, `422 admin_confirmation_required`, `422 validation_failed`) → hedef kuralı (`404 not_found`, `403 admin_target_not_allowed`) → iş kuralı (`409 account_status_transition_not_allowed`, `409 password_not_set`, `403 impersonation_not_allowed`).

### Hedef kuralları

| İşlem | Kendi hesabı | Başka platform admini | Break-glass hesabı | Normal kullanıcı |
|-------|--------------|-----------------------|--------------------|------------------|
| kilit aç | ✗ | ✓ | ✓ (yalnızca erişimi geri verir) | ✓ |
| askıya al, oturumları kapat | ✗ | ✓ (ele geçirilmiş admin'e karşı savunma) | ✗ (son çare kurtarma yolu; CLI ile) | ✓ |
| geri al, şifre sıfırla, `must_change_password`, MFA sıfırla, e-postayı doğrulandı işaretle, impersonation | ✗ | ✗ (ele geçirmeye açık; çevrimdışı/CLI ile) | ✗ | ✓ |

### İşlemlerin ayrıntısı

- **Askıya alma:** `AccountService::change_status_in_tx` (`→ suspended`, neden `admin_suspension`) + aynı transaction'da `SessionRevoker::revoke_all_for_user(AccountSuspended, also_trusted_devices)`. Askıya alınan bir adminin başlattığı impersonation oturumları da biter (session çekirdeği).
- **Geri alma:** yalnızca `suspended` hesaplar; doğrulanmış adres → `active`, değilse `pending_verification`.
- **Kilit açma:** `locked → active` ve `LoginProtection::unlock` (yumuşak kilit + başarısızlık sayaçları). Veritabanı değişikliği ve audit önce commit edilir, yumuşak kilit hemen ardından temizlenir (idempotent).
- **Şifre sıfırlamaya zorlama:** mevcut şifre **hemen** çalışmaz hâle gelir (atılan rastgele 256 bitlik bir sırrın hash'i ile değiştirilir, `must_change = true`), tüm oturumlar ve güvenilir cihazlar kapatılır, isteğe bağlı olarak normal akışla (PWD-07, rate limit'li) sıfırlama linki gönderilir. Yalnızca `must_change_password` ayarlamak, şifreyi bilen saldırgana karşı yetmediği için ayrı bir işlemdir.
- **MFA sıfırlama:** `MfaService::reset_user_mfa_in_tx` (faktörler, kurtarma kodları, güvenilir cihazlar, bekleyen kodlar; `mfa_reset` bildirimi aynı transaction'da) + tüm oturumlar (`MfaChanged`). **Passkey'ler (authn-webauthn) silinmez** — ele geçirme şüphesinde askıya alma kullanın (bkz. "Kabul edilen riskler").
- **E-postayı doğrulandı işaretleme:** `confirm_mailbox_control_in_tx(…, MailboxProof::Administrator { admin })`. Doğrulanmamış hesapta ADR 0002 gereği kanıtlanmamış şifre silinir ve oturumlar kapatılır; kullanıcı şifre sıfırlamayla devam eder.

## Konfigürasyon (`[admin]`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `ip_allow_list` | `[]` (her yer) | CIDR listesi; istemci IP'si PRT-06 ile çözülür (güvenilir proxy yapılandırması önemli) |
| `step_up_max_age` | `10m` | Her admin isteği için |
| `impersonation_default_ttl` | `15m` | |
| `impersonation_max_ttl` | `60m` | Kod ayrıca 60 dk sert üst sınır uygular |

Kodda sabit (`AdminSettings`): dışa aktarma başına en çok 5000 olay; toplu şifre işleminde transaction başına 500 hesap.

## server'ın bağlaması gerekenler

1. **Servis:** `AdminService::new(AdminServiceDeps { pool, clock, audit: PgAuditSink, sessions: <AccountAwareSessionRevoker ile sarılmış revoker>, issuer: Arc<SessionService> (SessionIssuer), accounts, mfa, passwords, protection: LoginProtection, hasher: crypto.passwords, envelopes: crypto.envelopes, signing_keys }, AdminSettings::from_app_config(&config))`; `impl FromRef<AppState> for AdminService`.
2. **`SigningKeyCache`:** `SessionService` için küçük bir adaptör: `fn invalidate_signing_keys(&self) { self.0.invalidate_signing_keys() }`. Diğer instance'lar önbelleklerini `session.signing_key_cache_ttl` dolunca yeniler.
3. **Router:** `.merge(authn_admin::router::<AppState>())` — **oturum kimlik doğrulaması (`authn_session::authenticate`) ve CSRF katmanlarının arkasında**. OpenAPI'ye `authn_admin::AdminApi`.
4. **CLI `create-admin`:** `operations::create_break_glass_admin` yerine `authn_admin::create_break_glass_admin(&pool, &crypto.passwords, clock, &audit, email)`; dönen `password.expose()` yalnızca bir kez yazdırılır. Var olan bir adres hiçbir zaman sessizce admin yapılmaz (`conflict`).
5. **Migration `2200`** gömülü migrator ile gelir. En az yetki kurulumunda uygulama rolüne `admin_action_reasons` üzerinde yalnızca `SELECT, INSERT` verilmelidir (trigger ayrıca `UPDATE`/`DELETE`/`TRUNCATE`'i reddeder). Saklama temizliği `audit_events` satırını sildiğinde gerekçe FK kaskadıyla silinir (`adm_08_retention_purge_still_removes_justifications`).
6. **Audit sink gerçek olmalı:** gerekçe satırı `audit_events(id)`'ye FK ile bağlıdır; `AuditSink` olayları `audit_events`'e yazmazsa (ör. sahte sink) her işlem `internal_error` ile geri alınır (güvenli taraf).

## Güvenlik notları

- **Varsayılan ret, her istekte yeniden kontrol:** `Principal.is_platform_admin` tek başına yetmez; hesap her istekte veritabanından okunur (`is_platform_admin AND status = active`). Yetkisi alınan veya askıya alınan admin bir sonraki istekte reddedilir.
- **Passkey zorunluluğu:** yalnızca `hwk`/`swk` **ve** `mfa` birlikte kabul edilir; UV'siz passkey (`hwk`+`user`), TOTP/SMS/e-posta/kurtarma kodu ile MFA reddedilir. Gerçek adminin bu nedenle ve IP izin listesi nedeniyle reddedilmesi `admin.action` (`admin_access`, başarısız) olarak audit'lenir; admin olmayanların denemeleri yalnızca log + metrik (audit log'u şişirmemek için).
- **Impersonation izolasyonu:** impersonation oturumu (salt-okunur olsun olmasın) admin API'sini hiç kullanamaz; bir impersonation başka bir impersonation başlatamaz.
- **Personel kimliği:** işlemleri gerçekleştiren modüllerin kendi olayları (`account.status_changed`) `Actor::System` ile yazılır; gerçek aktör aynı transaction'daki `admin.action` olayındadır (authn-audit, `admin.*` olaylarında personel kimliğini kullanıcıya ve organizasyon adminlerine göstermez).
- **Gerekçe zincir dışında:** serbest metin kişisel veri içerebilir; hash zincirine giremez (AUD-03). `admin_action_reasons` satırı olayla aynı transaction'da yazılır (biri başarısızsa hepsi geri alınır — `adm_08_failed_action_rolls_back_change_audit_and_reason`), konu hesabı silinince kaskadla silinir (`adm_08_justification_follows_subject_erasure`), saklama süresi dolan olayla birlikte gider. Zincirdeki olay `reason_recorded: true` taşır; metin zincirle korunmadığı için tahrifata karşı yalnızca veritabanı yetkileriyle korunur.
- **Gerekçe girdisi:** kırpılır; 1–1000 karakter; kontrol karakterleri, satır/paragraf ayırıcıları (U+2028/2029) ve görünmez biçim/dolgu karakterleri (tüm bidi kontrolleri dahil U+061C, sıfır genişlik, Unicode etiket karakterleri U+E0000–E007F, Hangul dolguları, U+180E, U+FFF9–FFFB, U+034F, U+206A–206F) reddedilir; emoji varyasyon seçicileri serbesttir. `Debug` çıktısında metin yer almaz.
- **Gerekçe tablosu ekleme-yalnızca:** `admin_action_reasons` üzerinde `UPDATE`/`DELETE`/`TRUNCATE`, veritabanı yetkilerinden bağımsız olarak bir trigger ile reddedilir (`audit_events` ile aynı model). Yalnızca yabancı anahtar eylemleri geçer: konu hesabın silinmesi ve saklama temizliği (kaskad), adminin silinmesi (`admin_user_id` → NULL; başka hiçbir sütun değişemez). Bunlar PostgreSQL'in referans bütünlüğü trigger'larından (derinlik > 1) çalışır.
- **Acil durum onayı:** yanlışlıkla tetiklemeye karşı `confirm` alanında işlem adı. Toplu şifre işleminde bir parti başarısız olursa, commit edilmiş partiler gerekçeyle birlikte başarısız (`batch_failed`) bir `admin.emergency_action` olayıyla kaydedilir.
- **CSRF / yöntem güvenliği:** tüm durum değiştiren uçlar `POST` + `application/json` gövde (axum `Json` başka içerik türünü reddeder; çapraz site form gönderimi mümkün değildir); `GET` uçları yalnızca okur. Sunucu router'ı oturum + CSRF katmanlarının arkasına bağlamalıdır.
- **SQL:** tüm sorgular sabit metin + bind parametresi; e-posta araması `LIKE` değil `starts_with(email_normalized, $1)` (joker karakter enjeksiyonu yok); sayfalama imleci `authn_core::domain::Cursor` ile çözülür, değerleri bind edilir.
- **Bağlantı havuzu:** transaction açıkken ikinci bir havuz bağlantısı beklenmez (okumalar transaction'dan önce yapılır).

### Bağımsız güvenlik denetimi (2026-11-04)

Kodu yazmamış bir denetçi "zafiyetli, kanıtla" varsayımıyla inceledi. Doğrulanan her bulgu önce düzeltme olmadan başarısız olan bir testle kanıtlandı, sonra düzeltildi (`tests/security_review.rs`):

| # | Önem | Bulgu | Regresyon testi | Durum |
|---|------|-------|-----------------|-------|
| 1 | Yüksek | Ele geçirilmiş tek bir admin, break-glass hesabını askıya alabiliyor (veya oturumlarını sürekli kapatabiliyordu); admin hesapları API'den geri alınamadığı için son çare kurtarma yolu kayboluyordu. | `adm_05_break_glass_account_cannot_be_suspended_or_revoked_by_another_admin` | Düzeltildi: break-glass hesaplarına askıya alma / oturum kapatma reddedilir (kilit açma serbest); break-glass hesabı ele geçirilmiş admini askıya alabilir. |
| 2 | Düşük | Gerekçe filtresi `char::is_control` olmayan görünmez/satır kıran karakterleri (U+2028/2029, U+061C bidi, etiket karakterleri, Hangul dolguları …) kabul ediyordu; denetçiden metin gizlenebiliyordu. | `adm_08_justification_rejects_hidden_and_line_breaking_characters` | Düzeltildi |
| 3 | Orta | Gerekçeler hash zincirinin dışında ve uygulama rolüyle sessizce değiştirilebilir/silinebilirdi. | `adm_08_justifications_are_append_only`, `adm_08_retention_purge_still_removes_justifications` | Düzeltildi: ekleme-yalnızca trigger (FK eylemleri hariç) |
| 4 | Düşük | Toplu şifre işleminde parti hatası olursa commit edilmiş partilerin başarısızlık olayı gerekçesiz yazılıyordu (ADM-08). | `adm_08_partially_failed_bulk_operation_keeps_its_justification` | Düzeltildi |

Doğrulanıp sorun bulunmayanlar: guard her istekte DB'den yeniden okur (yetkisi alınan/askıya alınan admin hemen reddedilir), adım-yükseltme enjekte saatle; adminler step-up'ı yalnızca passkey ile yapabilir (authn-session); impersonation süresi hem burada hem session'da sınırlı, salt-okunur varsayılan, zincirleme yok, impersonation oturumu admin uçlarına ulaşamaz; admin oluşturma/yükseltme API'si yok (yalnızca CLI break-glass); break-glass şifresi 256 bit CSPRNG, `Debug`'da görünmez, loglanmaz; yanıtlarda/listelerde sır yok, hata ayrıntısı (`context`) istemciye gitmez; her işlem + audit + gerekçe tek transaction.

### Kabul edilen riskler / bilinen sınırlamalar

- **MFA sıfırlama passkey'leri silmez (açık risk, orta).** Karar: bu, "MFA sıfırla"nın beklenen anlamı için gerçek bir açıktır — (a) hesabı ele geçirilmiş bir kullanıcıda saldırganın kaydettiği passkey sıfırlamadan sonra da şifresiz girişe izin verir; (b) passkey'i kaybolan cihazda olan kullanıcı, passkey ikinci faktör olarak kayıtlı kaldığı sürece kilitli kalabilir. authn-webauthn'de admin adına (principal'sız, step-up'sız) kullanıcının tüm passkey'lerini aynı transaction'da silen bir API yok ve bu crate başka crate'i değiştiremez; `contract-change-requests.md`'de `WebauthnService::remove_all_passkeys_in_tx` talebi açıldı. O gelene kadar operatörler ele geçirme şüphesinde MFA sıfırlama yerine **askıya alma** kullanmalı; bu sınırlama rustdoc ve README'de açıkça belirtilir (passkey'ler kullanıcının kendi passkey listesinde, authn-webauthn'de görünür).
- **Break-glass hesabının kendisi ele geçirilirse** API'den askıya alınamaz (bulgu 1'in bilinçli bedeli): CLI/veritabanı ile müdahale edilir; her kullanımı yüksek öncelikli `admin.break_glass_used` olayı üretir (alarm bunun üzerine kurulmalı), acil "tüm oturumları kapat" onun oturumlarını da kapatır.
- **Ele geçirilmiş bir admin diğer normal adminleri askıya alabilir** ve acil durum işlemlerini (tüm oturumları kapatma, anahtar rotasyonu) tekrarlayarak hizmet kesintisi yaratabilir. Bunlar ADM-03/ADM-06'nın gereği; hepsi gerekçe + onay ister, yüksek öncelikli audit'lenir ve break-glass hesabı saldırgan admini askıya alabilir. Askıya alınan adminler CLI ile geri alınır.
- **Gerekçeler kullanıcının veri dışa aktarımında (ACC-10) yok:** personel notlarıdır ve inceleme ayrıntısı içerebilir; konu hesap silinince silinir. Dışa aktarıma eklenip eklenmeyeceği proje sahibinin (KVKK/GDPR) kararıdır.

- **Impersonation gerekçesi:** session portu olay kimliğini döndürmediği için gerekçe, session'ın yazdığı `admin.impersonation_started` olayına sonradan (ayrı transaction'da, `audit_events`'ten olay aranarak) bağlanır. Bu adım başarısız olursa impersonation geri alınmaz; hata loglanır ve gerekçe `sessions.impersonation_reason`'da kalır (oturum temizliğine kadar). Port değişikliği talebi açıldı.
- **Modül olaylarında admin IP'si:** `change_status_in_tx` / `confirm_mailbox_control_in_tx` bağlam (IP, user-agent) ister; bu olaylarda adminin IP'si kullanıcının kendi listesinde maskeli (`/24`–`/48`) görünebilir. Ayrıca `account.email_verified` olayını authn-account `Actor::User(admin)` ile yazar (talep açıldı).
- **Diğer modüllerin metadata anahtarları:** testler sırasında authn-account (`password_removed`) ve authn-password (`code_issued`) metadata'larının audit sink tarafından `[REDACTED]` yapıldığı görüldü (bu crate'in olaylarında redaksiyon yok; testlerle doğrulanıyor).
- **Zincir doğrulama maliyeti:** tam doğrulama büyük log'da pahalıdır; yalnızca adminlere açık, ayrı rate limit yok (sunucu genel rate limit'i geçerli).
- **Kullanıcı listesi indeksi:** `(created_at, id)` indeksi `users` tablosunda yok (store'un tablosu; talep açıldı); büyük kurulumlarda liste sıralaması tablo taraması yapar.
- **Web impersonation** yanıtı oturum çerezini ayarlar: adminin tarayıcısı kullanıcıya geçer, admin oturumu sunucuda yaşamaya devam eder (yeniden giriş gerekir). Ayrı bir tarayıcı profili önerilir.
- **Acil "tüm oturumları kapat"** çağıran adminin oturumunu da kapatır.
- **Break-glass ve IP izin listesi:** break-glass hesapları izin listesini atlamaz (bilinçli; acil durumda izin listesi yapılandırmayla değiştirilmelidir).
- **Break-glass ilk girişi:** platform admini olduğu için session ilk girişte passkey kaydını zorunlu tutar (SES-22, MFA-08); passkey kayıt linki seçeneği uygulanmadı.

## Komutlar

```bash
cargo test -p authn-admin --all-features
cargo clippy -p authn-admin --all-targets --all-features -- -D warnings
cargo fmt -p authn-admin
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
