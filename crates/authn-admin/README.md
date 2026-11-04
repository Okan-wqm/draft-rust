# authn-admin

`/v1/admin` altındaki platform admin API'si: kullanıcı arama/detay, kullanıcı işlemleri (askıya alma, kilit açma, oturum kapatma, şifre sıfırlama zorunluluğu, MFA sıfırlama, e-postayı doğrulandı işaretleme), impersonation, break-glass hesapları, acil durum işlemleri ve audit sorgulama/dışa aktarma/zincir doğrulama.

## Sahip olunan gereksinimler

| Kimlik | Nerede | Özet | Testler |
|--------|--------|------|---------|
| ADM-01 | `guard.rs`, `service/mod.rs` (`authorize`) | Yalnızca platform admini (her istekte veritabanından yeniden okunur, `active` olmalı), oturum passkey ile phishing'e dayanıklı MFA (`amr`: `hwk`/`swk` **ve** `mfa`), her istek için son 10 dk içinde step-up, isteğe bağlı IP izin listesi; impersonation altındaki (salt-okunur veya yazılabilir) principal'lar, API anahtarları ve servis hesapları reddedilir. | `tests/authorization.rs` (`adm_01_*`), `guard.rs` birim testleri |
| ADM-02 | `service/users.rs` | Keyset sayfalı (`created_at DESC, id DESC`, `OFFSET` yok) arama: e-posta öneki, durum, platform admini, doğrulanmış, oluşturma aralığı. Detay: hesap, şifre durumu (hash yok), MFA durumu (sır yok, telefon maskeli), yumuşak kilit. Detay görüntüleme audit'lenir (`user_viewed`). | `tests/users.rs` (`adm_02_*`) |
| ADM-03 | `service/actions.rs` | Askıya al / geri al, kilit aç, oturumları kapat, şifre sıfırlamaya zorla, `must_change_password`, MFA sıfırla (faktörler + passkey'ler aynı transaction'da; kullanıcıya bildirim authn-mfa ve authn-webauthn'den), e-postayı doğrulandı işaretle (`MailboxProof::Administrator`). Her biri tek transaction + audit + gerekçe. | `tests/actions.rs` (`adm_03_*`, `adm_03_reset_mfa_removes_passkeys_and_they_no_longer_authenticate`) |
| ADM-04 | `service/impersonation.rs` | Varsayılan 15 dk, en çok 60 dk (yapılandırma ne derse desin), gerekçe zorunlu, varsayılan salt-okunur, web veya native (`act` claim'i). `SessionIssuer::start_impersonation_audited(conn, ctx, req, client, Some(admin_session), event_id)` (wave 1, K-06): bildirim ve `admin.impersonation_started` olayını session bu crate'in transaction'ında ve bu crate'in seçtiği olay kimliğiyle yazar (burada **tekrarlanmaz**); gerekçe aynı transaction'da o kimliğe bağlanır, hepsi birlikte commit edilir. Adminlere, break-glass hesaplarına, kendine ve `active` olmayan hesaplara uygulanamaz. | `tests/impersonation.rs` (`adm_04_*`, `adm_08_impersonation_reason_and_event_commit_atomically`) |
| ADM-05 | `break_glass.rs`, `operations.rs`, `service/enrollment.rs`, `service/mod.rs` | CLI `create-admin` için `create_break_glass_admin`: 256 bit CSPRNG şifre bir kez döner; `create-admin --passkey-link` için `create_break_glass_admin_with_passkey_link`: şifresiz hesap + tek kullanımlık, kısa ömürlü passkey kayıt bağlantısı (K-11). Oluşturma yüksek öncelikli audit olayıdır. Break-glass hesabının admin API'sindeki her isteği ve (authn-session) her girişi yüksek öncelikli `admin.break_glass_used` olayı üretir; işlemleri `break_glass: true` ile işaretlenir. Çevrimdışı olay müdahalesi (K-07): `suspend_admin_offline`, `unsuspend_admin_offline`, `revoke_admin_sessions_offline`, `issue_break_glass_enrollment_link_offline`. | `adm_05_break_glass_admin_creation`, `adm_05_break_glass_use_emits_high_priority_event`, `tests/hardening.rs` (`adm_05_k07_*`, `adm_05_k11_*`) |
| ADM-06 | `service/emergency.rs`, `service/limits.rs` | Tüm oturumları kapat (varsayılan: çağıranın kendi oturumu hariç — `revoke_everything_except`, K-10; `include_own_session: true` ile o da), ele geçirilmiş admine karşı sıkı limitler ve soğuma süresi (K-08), imza anahtarını acil rotasyon (`SigningKeyRepository::emergency_rotate` + `SigningKeyCache` kancası), tarihten önce şifresi değişmemiş herkese şifre değişikliği zorunluluğu (toplu, parti parti). Hepsi `confirm` alanında işlem adının tekrarını ister. | `tests/emergency.rs` (`adm_06_*`), `tests/hardening.rs` (`adm_06_k08_*`, `adm_06_revoke_all_keeps_caller_session_by_default`) |
| ADM-07 | `service/audit.rs` | Platform geneli audit sorgusu (`authn_audit::list_events`, keyset), sınırlı ve devam ettirilebilir dışa aktarma (gerekçe zorunlu, audit'lenir), zincir doğrulama (baştan veya dışarıda saklanan çapadan; admin başına limit ve küme genelinde tek eşzamanlı doğrulama, K-09). | `tests/audit.rs` (`adm_07_*`), `adm_07_k09_chain_verification_is_rate_limited_and_single_flight` |
| ADM-08 | `reason.rs`, `service/mod.rs` (`record_action`), migration `2200` | Her admin işlemi `admin.action` / `admin.emergency_action` olayıyla (gerçek aktör = admin, `action` kodu) ve gerekçeyle kaydedilir. Gerekçe serbest metin olduğu ve kişisel veri içerebileceği için hash zincirine **girmez** (AUD-03); `admin_action_reasons` tablosunda olay kimliğine bağlı tutulur. Gerekçeler ilgili kullanıcının veri dışa aktarımına girer (personel kimliği olmadan); yasal kısıtlama mümkündür (K-39, aşağıda). | `adm_08_*`, `actions.rs` içindeki `assert_audited`, `acc_10_admin_justifications_are_exported_without_staff_identity` |

## Bağımlılık kuralı

Dalga B. `authn-core`, `authn-crypto`, `authn-store` ve Dalga A (`password`, `account`, `mfa`, `org`, `protect`, `audit`) crate'lerine bağımlıdır; `authn-session` ve `authn-oidc-client`'e bağımlı **değildir** (oturum kapatma `SessionRevoker`, impersonation `SessionIssuer` portu ile; imza anahtarı önbelleği `SigningKeyCache` kancası ile). Yeni harici bağımlılık eklenmedi.

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-admin/**` |
| Konfigürasyon | `crates/authn-core/src/config/admin.rs` (`[admin]`, değiştirilmedi) |
| Hata kodları | `crates/authn-core/src/error/codes/admin.rs` |
| Tablolar | `admin_action_reasons` (migration `2200`); `admin_passkey_enrollments`, `admin_operation_leases`, `admin_reason_restrictions` (migration `2201_admin_hardening.sql`, wave 2B) |
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
| `create_break_glass_admin_with_passkey_link(pool, clock, audit, email, ttl) -> BreakGlassEnrollmentLink { user_id, token, expires_at }` | ADM-05, K-11 (CLI `create-admin --passkey-link`); `ttl` 1 sn – 24 sa (önerilen 30 dk = `AdminSettings::enrollment_link_ttl`) |
| `start_break_glass_enrollment(ctx, token)`, `finish_break_glass_enrollment(ctx, token, RegistrationVerifyRequest)`, `enrollment_router::<S>()`, `AdminEnrollmentApi` | K-11, `passkey` özelliği (varsayılan açık) |
| `OfflineOperator::parse`, `OfflineTarget::{Id, Email, parse}`; `suspend_admin_offline`, `unsuspend_admin_offline`, `revoke_admin_sessions_offline`, `issue_break_glass_enrollment_link_offline` | K-07 (CLI) |
| `restrict_justification(caller, ctx, event_id, &note)` | K-39 |
| `AdminActionsDataExporter` (`DataExporter`, bölüm `admin_actions`) | ACC-10, K-39 |
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
| POST | `/v1/admin/emergency/revoke-all-sessions` | `{reason, confirm: "revoke_all_sessions", include_own_session?: false}` | ADM-06, K-10 |
| POST | `/v1/admin/emergency/rotate-signing-key` | `{reason, confirm: "rotate_signing_key"}` | ADM-06 |
| POST | `/v1/admin/emergency/force-password-change` | `{reason, confirm: "force_password_change", changed_before, revoke_sessions?}` | ADM-06 |
| GET | `/v1/admin/audit-events?limit&cursor&kind&category&outcome&actor_user_id&subject_user_id&org_id&resource_type&since&until` | — | ADM-07 |
| POST | `/v1/admin/audit-events/export` | `{reason, filter}` | ADM-07 |
| POST | `/v1/admin/audit-events/verify` | `{anchor?: {seq, hash}}` (boş gövde `{}`) | ADM-07, K-09 |
| POST | `/v1/admin/audit-events/{event_id}/restrict` | `{reason}` (kısıtlama notu) | ADM-08, K-39 |

Oturumsuz uçlar (`enrollment_router`, K-11; IP izin listesi ve IP başına limit geçerli, admin oturumu gerekmez):

| Yöntem | Yol | Gövde | Gereksinim |
|--------|-----|-------|------------|
| POST | `/v1/admin/enrollment/options` | `{token}` | ADM-05, K-11 |
| POST | `/v1/admin/enrollment/verify` | `{token, ceremony_id, credential}` | ADM-05, K-11 |

Kontrol sırası: kimlik doğrulama (`401 unauthenticated`) → impersonation / oturum dışı kimlik bilgisi / admin değil / IP izinli değil (hepsi aynı `403 forbidden`; admin olmayan biri admin API'si veya izin listesi hakkında bir şey öğrenmez) → passkey MFA (`403 admin_phishing_resistant_mfa_required`) → step-up (`401 step_up_required`) → gövde doğrulama (`422 admin_reason_required`, `422 admin_confirmation_required`, `422 validation_failed`) → hız/soğuma limitleri (`429 rate_limited` + `Retry-After`, K-08/K-09) → hedef kuralı (`404 not_found`, `403 admin_target_not_allowed`) → iş kuralı (`409 account_status_transition_not_allowed`, `409 password_not_set`, `403 impersonation_not_allowed`).

### Hedef kuralları

| İşlem | Kendi hesabı | Başka platform admini | Break-glass hesabı | Normal kullanıcı |
|-------|--------------|-----------------------|--------------------|------------------|
| kilit aç | ✗ | ✓ | ✓ (yalnızca erişimi geri verir) | ✓ |
| askıya al, oturumları kapat | ✗ | ✓ (ele geçirilmiş admin'e karşı savunma; ayrı sıkı limit, K-08) | ✗ (son çare kurtarma yolu; CLI ile, K-07) | ✓ |
| geri al, şifre sıfırla, `must_change_password`, MFA sıfırla, e-postayı doğrulandı işaretle, impersonation | ✗ | ✗ (ele geçirmeye açık; çevrimdışı/CLI ile) | ✗ | ✓ |

### İşlemlerin ayrıntısı

- **Askıya alma:** `AccountService::change_status_in_tx` (`→ suspended`, neden `admin_suspension`) + aynı transaction'da `SessionRevoker::revoke_all_for_user(AccountSuspended, also_trusted_devices)`. Askıya alınan bir adminin başlattığı impersonation oturumları da biter (session çekirdeği).
- **Geri alma:** yalnızca `suspended` hesaplar; doğrulanmış adres → `active`, değilse `pending_verification`.
- **Kilit açma:** `locked → active` ve `LoginProtection::unlock` (yumuşak kilit + başarısızlık sayaçları). Veritabanı değişikliği ve audit önce commit edilir, yumuşak kilit hemen ardından temizlenir (idempotent).
- **Şifre sıfırlamaya zorlama:** mevcut şifre **hemen** çalışmaz hâle gelir (atılan rastgele 256 bitlik bir sırrın hash'i ile değiştirilir, `must_change = true`), tüm oturumlar ve güvenilir cihazlar kapatılır, isteğe bağlı olarak normal akışla (PWD-07, rate limit'li) sıfırlama linki gönderilir. Yalnızca `must_change_password` ayarlamak, şifreyi bilen saldırgana karşı yetmediği için ayrı bir işlemdir.
- **MFA sıfırlama:** `MfaService::reset_user_mfa_in_tx` (faktörler, kurtarma kodları, güvenilir cihazlar, bekleyen kodlar; `mfa_reset` bildirimi aynı transaction'da) + `WebauthnService::remove_all_passkeys_in_tx` (kullanıcının **tüm passkey'leri**, son giriş yöntemi kuralı uygulanmadan; her biri için `passkey.removed` olayı `Actor::System` + `reason: admin_reset`, `mfa_factor_removed` bildirimi; wave 1, K-01) + tüm oturumlar (`MfaChanged`). `admin.action` olayında `passkeys_removed` sayısı. Devam eden passkey seremonileri sıfırlamadan sonra tamamlanamaz (kimlik bilgileri silinir, açık seremoniler — kayıt dahil — aynı transaction'da yakılır). Yalnızca passkey'le giren bir hesapta sıfırlamadan sonra giriş yolu e-posta (magic link / e-posta kodu) kalır; ayrıntı ve kabul edilen riskler authn-webauthn README'sinde.
- **E-postayı doğrulandı işaretleme:** `confirm_mailbox_control_in_tx(…, MailboxProof::Administrator { admin })`. Doğrulanmamış hesapta ADR 0002 gereği kanıtlanmamış şifre silinir ve oturumlar kapatılır; kullanıcı şifre sıfırlamayla devam eder.

## Konfigürasyon (`[admin]`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `ip_allow_list` | `[]` (her yer) | CIDR listesi; istemci IP'si PRT-06 ile çözülür (güvenilir proxy yapılandırması önemli) |
| `step_up_max_age` | `10m` | Her admin isteği için |
| `impersonation_default_ttl` | `15m` | |
| `impersonation_max_ttl` | `60m` | Kod ayrıca 60 dk sert üst sınır uygular |

Kodda sabit (`AdminSettings`, testlerde değiştirilebilir): dışa aktarma başına en çok 5000 olay; toplu şifre işleminde transaction başına 500 hesap; ve wave 2B limitleri:

| Alan | Varsayılan | Kalem |
|------|-----------|-------|
| `emergency_per_admin` | 3 / saat (admin başına) | K-08 |
| `emergency_global` | 6 / saat (tüm adminler; break-glass hariç) | K-08 |
| `emergency_cooldown` | 5 dk (aynı acil işlemin iki çalıştırması arası; break-glass hariç) | K-08 |
| `admin_target_per_admin` | 3 / saat (başka bir platform adminini hedefleyen askıya alma / oturum kapatma / kilit açma) | K-08 |
| `admin_target_global` | 10 / saat (break-glass hariç) | K-08 |
| `audit_verify_per_admin` | 5 / saat | K-09 |
| `audit_verify_lease` | 15 dk (tek eşzamanlı doğrulama kiralamasının en uzun ömrü) | K-09 |
| `enrollment_link_ttl` | 30 dk (sert üst sınır 24 sa) | K-11 |
| `enrollment_per_ip` | 20 / 15 dk | K-11 |

## server'ın bağlaması gerekenler

1. **Servis:** `AdminService::new(AdminServiceDeps { pool, clock, audit: PgAuditSink, sessions: <AccountAwareSessionRevoker ile sarılmış revoker>, issuer: Arc<SessionService> (SessionIssuer; `start_impersonation_audited`'ı uygulamalı — varsayılan gövde reddeder), accounts, mfa, webauthn: WebauthnService (wave 1, K-01), passwords, protection: LoginProtection, hasher: crypto.passwords, envelopes: crypto.envelopes, signing_keys }, AdminSettings::from_app_config(&config))`; `impl FromRef<AppState> for AdminService`.
2. **`SigningKeyCache`:** `SessionService` için küçük bir adaptör: `fn invalidate_signing_keys(&self) { self.0.invalidate_signing_keys() }`. Diğer instance'lar önbelleklerini `session.signing_key_cache_ttl` dolunca yeniler.
3. **Router:** `.merge(authn_admin::router::<AppState>())` — **oturum kimlik doğrulaması (`authn_session::authenticate`) ve CSRF katmanlarının arkasında**. OpenAPI'ye `authn_admin::AdminApi`.
4. **Rate limiter (wave 2B):** `AdminServiceDeps.rate_limiter` = yapılandırılmış `RateLimiter` (authn-protect; çoklu instance'ta PostgreSQL/Redis arka ucu — limitler küme geneli olmalı).
5. **`revoke_everything_except`:** `sessions` olarak verilen revoker zinciri bu port metodunu uygulamalı (`PgSessionRevoker` ve wave 2A'dan sonra `AccountAwareSessionRevoker` uygular; varsayılan gövde reddeder → acil "tüm oturumları kapat" `internal_error`).
6. **Impersonation başlığı (K-12):** CORS izinli başlıklarına `x-impersonation-session` eklenmeli (admin konsolu farklı origin'deyse).
7. **Kayıt bağlantısı (K-11):** `.merge(authn_admin::enrollment_router::<AppState>())` (oturum gerektirmez; CSRF katmanı oturumsuz isteği engellememeli) + OpenAPI `AdminEnrollmentApi`; `authn-admin`'i `passkey` özelliğiyle al (varsayılan). CLI `create-admin --passkey-link [--ttl]` → `create_break_glass_admin_with_passkey_link(&pool, clock, &audit, email, ttl)`; bağlantıyı `{server.public_base_url}/admin/enroll#<token>` biçiminde (token URL **parçasında**, sunucu loglarına gitmez) **bir kez** yazdır. Var olan break-glass için `issue_break_glass_enrollment_link_offline`.
8. **Çevrimdışı CLI komutları (K-07):** `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions` → `AdminService::{suspend_admin_offline, unsuspend_admin_offline, revoke_admin_sessions_offline}(&OfflineOperator::parse(<--operator veya $USER>)?, &OfflineTarget::parse(<e-posta|id>), &Justification::parse(Some(<--reason>))?)`.
9. **Dışa aktarma (K-39):** `AccountServiceDeps.exporters`'a `Arc::new(authn_admin::AdminActionsDataExporter)`.
10. **CLI `create-admin`:** `operations::create_break_glass_admin` yerine `authn_admin::create_break_glass_admin(&pool, &crypto.passwords, clock, &audit, email)`; dönen `password.expose()` yalnızca bir kez yazdırılır. Var olan bir adres hiçbir zaman sessizce admin yapılmaz (`conflict`).
11. **Migration `2200`, `2201`** gömülü migrator ile gelir. En az yetki kurulumunda uygulama rolüne `admin_action_reasons` ve `admin_reason_restrictions` üzerinde yalnızca `SELECT, INSERT`, `admin_passkey_enrollments` ve `admin_operation_leases` üzerinde `SELECT, INSERT, UPDATE, DELETE` verilmelidir (trigger ayrıca `UPDATE`/`DELETE`/`TRUNCATE`'i reddeder). Saklama temizliği `audit_events` satırını sildiğinde gerekçe FK kaskadıyla silinir (`adm_08_retention_purge_still_removes_justifications`).
12. **Audit sink gerçek olmalı:** gerekçe satırı `audit_events(id)`'ye FK ile bağlıdır; `AuditSink` olayları `audit_events`'e yazmazsa (ör. sahte sink) her işlem `internal_error` ile geri alınır (güvenli taraf).

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
- **SQL:** bu crate yalnızca kendi tablosuna (`admin_action_reasons`) SQL yazar; `users`/`password_credentials` erişimi authn-store `UserRepository::{search, stale_passwords, set_admin_flags}` üzerinden (wave 1, K-38), impersonation olay kimliği port üzerinden. Tüm sorgular sabit metin + bind parametresi; e-posta araması `LIKE` değil `starts_with(email_normalized, $1)` (joker karakter enjeksiyonu yok); sayfalama imleci `authn_core::domain::Cursor` ile çözülür, değerleri bind edilir.
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

### Bağımsız güvenlik denetimi — wave 2B (2026-11-04)

Wave 2B'yi (K-05, K-07 … K-13, K-19, K-39, K-41) yazmamış bir denetçi inceledi. Doğrulanan her bulgu düzeltme olmadan başarısız olan bir testle kanıtlandı (test çalıştırıldı ve kırmızıydı), sonra düzeltildi:

| # | Önem | Bulgu | Regresyon testi | Durum |
|---|------|-------|-----------------|-------|
| 2B-1 | Orta | **Ele geçirilmiş break-glass hesabının kurtarma prosedürü saldırganın kimlik bilgilerini kaldırmıyordu.** Belgelenen sıra (`suspend-admin` → yeni bağlantı → `unsuspend-admin` → kayıt) passkey'leri, şifreyi ve MFA faktörlerini olduğu gibi bırakıyordu; hesap askıdan çıkar çıkmaz saldırganın passkey'i/şifresi yeniden çalışıyordu (bağlantı askıdaki hesapta kullanılamadığından askıdan çıkarmak zorunluydu). | `tests/hardening.rs::adm_05_k07_replacement_link_removes_the_compromised_credentials` | Düzeltildi: `issue_break_glass_enrollment_link_offline` aynı transaction'da şifreyi, tüm passkey'leri, MFA faktörlerini (kurtarma kodları, güvenilir cihazlar) siler ve tüm oturumları kapatır; olay `passkeys_removed`, `password_removed`, `factors_removed`, `sessions_revoked` taşır. Askıdaki hesapta da çalışır. |
| 2B-2 | Düşük | **K-12 gerilemesi (authn-session):** yazılabilir web impersonation'ı `x-impersonation-session` başlığıyla `POST /v1/session/org` çağırınca yanıt yeni token'ı `Set-Cookie` ile döndürüyordu; tarayıcı adminin oturum çerezini impersonation token'ıyla değiştiriyordu (K-12'nin kapattığı durum) ve başlıktaki token geçersiz kalıyordu. | `authn-session/tests/issuer.rs::adm_04_header_impersonation_rotation_never_sets_a_cookie` | Düzeltildi (authn-session README) |

Doğrulanıp sorun bulunmayanlar: K-11 bağlantı token'ı 256 bit CSPRNG, yalnızca SHA-256'sı saklanır, `Debug`/log/hata çıktısında yok; bilinmeyen/kullanılmış/süresi dolmuş/aktif olmayan hesap aynı `invalid_or_expired_token`; seremoni (kullanıcı, token hash'i) ikilisine bağlı, tüketim `binding_hash IS NOT DISTINCT FROM` ile birebir; eşzamanlı iki tamamlama tek passkey üretir (bağlantı satırı `UPDATE … consumed_at IS NULL` ile tek kez tüketilir); migration `1401` kısıtı mevcut satırlarla uyumlu (eski kod kayıt seremonisinde `binding_hash` hiç yazmıyordu); normal oturumla kayıt davranışı aynı (tüm webauthn testleri yeşil). K-10: `revoke_everything_except` yenileme token'larını, impersonation oturumlarını ve bekleyen girişleri `revoke_everything` ile aynı biçimde kapatır; varsayılan port uygulaması hiçbir şey iptal etmeden hata döner (sessizce yanlış davranmaz). K-08: break-glass muafiyeti DB'deki `is_break_glass`'tan gelir (istemci kontrol edemez); muafiyet yalnızca paylaşılan bütçeleri atlar, admin başına bütçe break-glass'a da uygulanır. K-09: kiralama tek `INSERT … ON CONFLICT … WHERE expires_at <= …` ifadesi, yarışta tek kazanan. K-39: dışa aktarımda personel kimliği/IP yok, kısıtlanan satır ve kısıtlama notu verilmez, tablo ekleme-yalnızca, yalnızca admin guard'ından geçen (passkey + step-up) çağıran kısıtlayabilir, kendi hakkındaki kaydı kısıtlayamaz. K-07 fonksiyonları HTTP'ye bağlı değil, yalnızca platform adminlerini hedefler. Yeni kodda `unwrap`/`expect`/`panic!` yok (yalnızca test modüllerinde).

Kabul edilen / açık kalan (denetçi notu):

- **`guard_admin_target` TOCTOU (çok düşük):** hedefin admin olup olmadığı transaction'dan önce okunur; arada hedef admine yükseltilirse o tek işlem admin-hedef bütçesini tüketmez. Yükseltme yalnızca CLI ile yapılabildiğinden saldırgan bunu tetikleyemez; olay metadata'sı kilitli satırdan (`target.is_platform_admin`) yine `target_is_admin` alır.
- **Zincir doğrulama kiralaması uygulama saatini kullanır:** doğrulama `audit_verify_lease`'ten (15 dk) uzun sürerse veya instance saatleri kaymışsa ikinci bir doğrulama başlayabilir; yine admin başına bütçeyle sınırlıdır.
- **`restrict_justification` olayı kullanıcının kendi olay listesinde görünür** (konusu kullanıcıdır; metadata'da `restricted_event_id`, not yok). Dışa aktarım zaten `withheld_under_legal_restriction` sayısını bildirdiğinden (proje sahibi adına verilen K-39 kararı) kısıtlamanın varlığı kullanıcıdan gizlenmiyor; soruşturmanın varlığının da gizlenmesi gerekiyorsa bu bir **proje sahibi kararıdır** (olay görünürlüğü authn-audit'te).
- **Çapraz köken konsol:** `x-impersonation-session` başlığı authn-protect CORS izin listesinde (`ALLOWED_HEADERS`) yok; bu güvenli taraftır (başlık yalnızca aynı kökenden gönderilebilir, CSRF gerekçesi bu yüzden sağlam). Admin konsolu API'den farklı bir kökende çalışacaksa başlık authn-protect'e eklenmelidir (sahibi authn-protect).

### Kabul edilen riskler / bilinen sınırlamalar

- ~~MFA sıfırlama passkey'leri silmez~~ — **kapatıldı (wave 1, K-01):** sıfırlama artık passkey'leri aynı transaction'da siler; regresyon testi `adm_03_reset_mfa_removes_passkeys_and_they_no_longer_authenticate` (sıfırlamadan sonra ne bekleyen ne yeni passkey seremonisi tamamlanır).
- ~~Ele geçirilmiş break-glass hesabı için araç yok~~ — **kapatıldı (wave 2B, K-07):** API'den askıya alınamaz (bulgu 1'in bilinçli bedeli), ama çevrimdışı CLI komutları (`suspend-admin`, `revoke-admin-sessions`, `unsuspend-admin`, yeni passkey bağlantısı) gerekçe zorunlu ve yüksek öncelikli audit'le bunu yapar. Prosedür aşağıda.
- ~~Ele geçirilmiş bir admin diğer adminleri askıya alabilir / acil işlemleri tekrarlayabilir~~ — **sınırlandı (wave 2B, K-08):** admin hedefli işlemler ve acil durum işlemleri ayrı, sıkı limitlere ve soğuma süresine tabidir; her ret `429` + yüksek öncelikli başarısız `admin.action` (`reason` = limit adı) + `authn_admin_throttled_total{limit}` metriği üretir (alarm bunlara kurulmalı). Break-glass hesabı paylaşılan limitlerden muaftır, saldırganın tükettiği bütçe kurtarmayı engellemez. Kalan risk: limit içinde (ör. saatte 3 admin) zarar mümkündür; tam önleme için çok kişili onay (Faz 2) gerekir.
- ~~Gerekçeler kullanıcının veri dışa aktarımında yok~~ — **kapatıldı (wave 2B, K-39; proje sahibi adına koordinatör kararı):** `AdminActionsDataExporter` (`admin_actions` bölümü) kullanıcı hakkındaki gerekçeleri işlem kodu, zaman ve metinle verir; personel kimliği ve IP'si verilmez (aktör `platform_staff`, GDPR md. 15(4)). Dolandırıcılık / yasal soruşturma kapsamındaki bir gerekçe `POST /v1/admin/audit-events/{event_id}/restrict` ile (zorunlu kısıtlama notu, kendisi audit'li `admin.action` `restrict_justification`) kısıtlanabilir (KVKK md. 28, GDPR md. 23): dışa aktarımda içerik verilmez, yalnızca `withheld_under_legal_restriction` sayısı bildirilir; kısıtlama notu da kısıtlıdır. Kısıtlamalar ekleme-yalnızca tablodadır (`admin_reason_restrictions`), API'den kaldırılamaz; kaldırmak gerekirse veritabanı yöneticisi işidir (bilinçli).

- ~~Impersonation gerekçesinin sonradan bağlanması~~ — **kapatıldı (wave 1, K-06):** gerekçe, impersonation oturumu ve `admin.impersonation_started` olayıyla aynı transaction'da, önceden seçilen olay kimliğiyle yazılır; gerekçe yazılamazsa hiçbiri commit edilmez (`adm_08_impersonation_reason_and_event_commit_atomically`).
- **Modül olaylarında admin IP'si:** `change_status_in_tx` / `confirm_mailbox_control_in_tx` bağlam (IP, user-agent) ister; bu olaylarda adminin IP'si kullanıcının kendi listesinde maskeli (`/24`–`/48`) görünebilir. Ayrıca `account.email_verified` olayını authn-account `Actor::User(admin)` ile yazar (talep açıldı).
- ~~Diğer modüllerin metadata anahtarlarının redakte edilmesi~~ — **kapatıldı (wave 1, K-15):** authn-audit sanitizer'ı yasaklı kelime içeren anahtarlarda **boolean** değerleri artık korur (`must_change_password`, `code_issued`, `password_removed`); boolean olmayan her değer yine redakte edilir.
- ~~Zincir doğrulamanın ayrı rate limit'i yok~~ — **kapatıldı (wave 2B, K-09):** admin başına limit (`audit_verify_per_admin`) ve küme genelinde tek eşzamanlı doğrulama (`admin_operation_leases` kiralaması; tek ifadeyle alınır/bırakılır, doğrulama sürerken bağlantı tutulmaz; ölen instance'ın kiralaması `audit_verify_lease` sonunda devralınır).
- ~~Kullanıcı listesi indeksi yok~~ — **kapatıldı (wave 1, K-38):** migration `0015` `users_created_id_idx (created_at DESC, id DESC)`.
- ~~Web impersonation adminin oturum çerezini değiştiriyor~~ — **kapatıldı (wave 2B, K-12):** yanıt hiçbir `Set-Cookie` taşımaz (`SessionIssuer::impersonation_response`); impersonation token'ı gövdede (`impersonation_token`) döner, konsol onu `x-impersonation-session` başlığıyla gönderir (authn-session ara katmanı yalnızca canlı **impersonation** web oturumlarını bu başlıkla kabul eder; özel başlık tarayıcıca siteler arası eklenmediğinden CSRF token'ı gerekmez). Adminin kendi oturumu bozulmaz; impersonation'ı bitirmek (`POST /v1/logout` başlıkla) çerez silmez. Token konsolun belleğinde tutulur (native token'larla aynı XSS riski).
- ~~Acil "tüm oturumları kapat" çağıranın oturumunu da kapatıyor~~ — **kapatıldı (wave 2B, K-10):** varsayılan olarak çağıranın oturumu korunur (adminin başlattığı impersonation oturumları dahil diğer her şey kapanır); `include_own_session: true` ile o da kapanır. Olayda `own_session_kept`.
- **Break-glass ve IP izin listesi (K-13, karar: uygulanmaya devam):** break-glass hesapları izin listesini **atlamaz**. Gerekçe: break-glass kimlik bilgisi en güçlü hesaptır; çalınırsa "her yerden çalışan" bir hesap izin listesinin amacını boşa çıkarır, ve izin listesi zaten sunucu yapılandırmasıdır — erişimi olan operatör onu değiştirebilir. Test: `adm_01_k13_break_glass_obeys_the_ip_allow_list` (kayıt bağlantısı uçları için de: `adm_05_k11_enrollment_endpoints_obey_allow_list_and_rate_limit`).
- ~~Break-glass passkey kayıt linki yok~~ — **kapatıldı (wave 2B, K-11):** `create-admin --passkey-link`; şifresiz hesap, tek kullanımlık bağlantı (token yalnızca SHA-256'sıyla saklanır, varsayılan 30 dk, en çok 24 sa), WebAuthn kaydı token hash'ine bağlı oturumsuz seremoniyle (authn-webauthn migration `1401`), bağlantı passkey'i saklayan transaction'da tüketilir. Bilinmeyen, kullanılmış ve süresi dolmuş token'lar aynı `400 invalid_or_expired_token`'ı alır. Kalan risk: bağlantıyı ele geçiren ilk kişi passkey'i kaydeder — bağlantı yalnızca güvenli kanalla iletilmeli; kayıt yüksek öncelikli `break_glass_passkey_enrolled` olayı üretir (alarm), şüphede `suspend-admin` + yeni bağlantı (yeni bağlantı hesabın tüm kimlik bilgilerini siler; denetim bulgusu 2B-1).

### Acil durum prosedürü (operatör, K-07 / K-13)

1. **Ele geçirilmiş admin (normal):** break-glass hesabıyla konsoldan askıya al (`POST /v1/admin/users/{id}/suspend`) — veya API'ye ulaşılamıyorsa `rust-authentication suspend-admin --target <e-posta|id> --reason "<gerekçe>" [--operator <ad>]`.
2. **Ele geçirilmiş break-glass hesabı:** API bunu bilinçli olarak yapamaz; `suspend-admin` (oturumlar, güvenilir cihazlar ve başlattığı impersonation'lar da kapanır) veya yalnızca `revoke-admin-sessions`. Sonra hesap askıdayken yeni bağlantı üret (`create-admin --passkey-link`, var olan hesap için `issue_break_glass_enrollment_link_offline`): bu, aynı transaction'da hesabın şifresini, tüm passkey'lerini, MFA faktörlerini ve oturumlarını siler, eski açık bağlantıları geçersiz kılar. Ardından `unsuspend-admin` ve bağlantıyla yeni passkey'i kaydet (bağlantı yalnızca aktif hesapta çalışır; askıdan çıkarma ile kayıt arasında hesabın bağlantıdan başka kimlik bilgisi yoktur).
3. **İzin listesi dışından erişim gerekiyorsa:** `[admin] ip_allow_list`'e geçici CIDR ekleyip yeniden başlat (yapılandırma değişikliği altyapı denetiminden geçer), iş bitince geri al. Break-glass için izin listesi atlanmaz (K-13).
4. **Limit / soğuma süresine takılındıysa (K-08):** `Retry-After` kadar bekle; acil durumda break-glass hesabı paylaşılan limitlerden muaftır.
5. Her adımın audit'i yüksek önceliklidir (`priority: high`); alarm `admin.break_glass_used`, `admin.action` (`surface: cli`, `limit`) ve `authn_admin_throttled_total` / `authn_break_glass_logins_total` metriklerine kurulmalı.

## Komutlar

```bash
cargo test -p authn-admin --all-features
cargo clippy -p authn-admin --all-targets --all-features -- -D warnings
cargo fmt -p authn-admin
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
