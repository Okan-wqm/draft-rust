# authn-org

B2B kiracı (tenant) katmanı: organizasyonlar, üyelikler, RBAC, davetler, DNS ile domain doğrulama, organizasyon güvenlik politikaları, API anahtarları ve servis hesapları. Tek bir varsayılan-reddet yetkilendirme fonksiyonu (`OrgService::authorize`) bu crate'in tüm uç noktalarında kullanılır ve diğer modüllere (server üzerinden) açılır.

## Sahip olunan gereksinimler

ARC-10, ORG-01 … ORG-12. Uygulanan port: `DnsTxtResolver` (`HickoryDnsTxtResolver`, `hickory-resolver`).

| Gereksinim | Nerede | Test (örnek) |
|------------|--------|--------------|
| ORG-01 Organizasyon CRUD, benzersiz `slug`, kurucu `owner` | `service/orgs.rs` | `org_01_creator_becomes_owner_and_slug_is_unique` |
| ORG-02 Üyelik, durum, son `owner` koruması | `service/members.rs`, migration `1500` | `org_02_concurrent_demotions_never_leave_an_org_without_owner` |
| ORG-03 RBAC, yerleşik + özel roller, tek `authorize` | `authz.rs`, `permission.rs`, `service/roles.rs` | `org_03_custom_roles_drive_authorization` |
| ORG-04 Ayrıcalık yükseltme koruması | `Authorization::ensure_can_grant`, migration `1500` | `org_04_admins_cannot_grant_owner_or_manage_owners` |
| ORG-05 Davetler | `service/invitations.rs` | `org_05_concurrent_acceptance_creates_exactly_one_membership` |
| ORG-06 Domain doğrulama, otomatik katılım | `service/domains.rs`, `dns.rs`, migration `1501` | `org_06_auto_join_requires_verification_and_matches_exact_verified_addresses` |
| ORG-07 Organizasyon politikaları | `policy.rs`, `service/policies.rs`, `authz.rs` | `org_07_policy_is_enforced_on_every_org_request` |
| ORG-08 API anahtarları | `api_key.rs`, `service/api_keys.rs`, `middleware.rs` | `org_08_every_failure_is_the_same_401_and_failures_are_limited` |
| ORG-09 Servis hesapları | `service/service_accounts.rs` | `org_09_disabling_and_deleting_stop_its_keys` |
| ORG-10 / ARC-10 Kiracı izolasyonu, IDOR | `authz.rs`, tüm sorgular `org_id` filtreli | `arc_10_org_10_every_endpoint_hides_other_tenants_from_a_session_owner` |
| ORG-11 Sahiplik devri (hedef onayı) | `service/transfer.rs` | `org_11_transfer_needs_owner_step_up_and_target_acceptance` |
| ORG-12 Bekleme süreli silme | `service/orgs.rs` | `org_12_purge_deletes_everything_after_the_grace_period` |

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. Diğer Dalga A modüllerinin verisi gerekiyorsa portlar (`AuditSink`, `EventPublisher`, `Notifier`, `RateLimiter`, `SessionRevoker`, `DnsTxtResolver`) veya server'ın dolduracağı girdi yapıları kullanılır. Yeni harici bağımlılık eklenmedi; crate `Cargo.toml`'una workspace'te zaten bulunan `unicode-normalization`, `zeroize` ve `http` eklendi, kullanılmayan `secrecy` ve `url` çıkarıldı.

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `OrgService::new(OrgServiceDeps, OrgServiceSettings)` | Servis; `OrgServiceSettings::from_app_config(&config)` |
| `OrgService::authorize(&ctx, &principal, Permission, OrgId) -> Result<Authorization>` | **Tek** yetkilendirme kapısı (varsayılan reddet, başka kiracı → `404`) |
| `OrgService::authorize_from(&principal, Permission, OrgId, Option<IpAddr>)` | Request context'i olmayan çağıranlar için (IP yoksa IP izin listeli organizasyon reddeder) |
| `OrgService::authorize_in(&mut PgConnection, …)` | Çağıranın transaction'ında |
| `OrgService::check_membership(&principal, OrgId, Option<IpAddr>)` | İzin gerektirmeyen üyelik + politika kontrolü (SES-17 organizasyon değiştirme) |
| `OrgService::authenticate_api_key(&ctx, &str) -> Result<Principal>` | API anahtarı doğrulama (server / session) |
| `api_key_middleware` | `Authorization: Bearer ak_…` / `X-API-Key` → `Principal` extension (yalnızca `/v1/orgs/{org_id}[/…]` yollarında; bkz. `middleware::is_api_key_path`) |
| `OrgService::policy(OrgId)`, `policies_for_user(&mut conn, UserId)`, `policy_of(&mut conn, OrgId)` | Politika okuma API'si (session, mfa için server eşlemesi) |
| `OrgService::auto_join_verified_domains(UserId) -> Vec<OrgId>` | Doğrulanmış domain ile otomatik katılım (ORG-06) |
| `sole_owner_organizations(&mut conn, UserId)` | ACC-09: tek sahibi olunan organizasyonlar |
| `OrgService::purge_due_deletions(limit)`, `OrgService::expire_invitations()` | Arka plan işleri (OPS-06) |
| `OrgDataExporter` | `DataExporter`, bölüm `organizations` |
| `HickoryDnsTxtResolver::{from_system_conf, with_name_servers}` | `DnsTxtResolver` uygulaması |
| `router::<S>()`, `OrgApi` | HTTP uç noktaları ve OpenAPI belgesi |
| `Permission`, `PermissionSet`, `BuiltinRole`, `Authorization` | İzin kataloğu, yerleşik roller, yetkilendirme sonucu |
| `parse_api_key`, `GeneratedApiKey` | Anahtar biçimi (fuzz hedefi `api_key_parse`) |

## İzin kataloğu (ORG-03)

`org:read`, `org:update`, `org:delete`*, `org:transfer_ownership`*, `members:read|invite|update|remove`, `roles:read|manage`, `policies:read|manage`, `domains:read|manage`, `api_keys:read|manage`, `service_accounts:read|manage`, `webhooks:read|manage`, `audit:read`, `billing:read|manage`.

\* Yalnızca yerleşik `owner` rolünde bulunur; özel rollere ve API anahtarı kapsamlarına asla eklenemez (kod + `role_permissions_owner_only` tetikleyicisi). Katalog kapalıdır: veritabanında katalog dışı bir değer hiçbir yetki vermez. Yerleşik roller `0012` ile sabit kimliklerle gelir; `BuiltinRole::permissions()` bu tohumu yansıtır ve `org_03_builtin_role_seed_matches_the_catalog` testi ikisini senkron tutar.

## Yetkilendirme (`authorize`) sırası

1. **Kiracı izolasyonu:** aktif üyelik / aynı organizasyonun servis hesabı / aynı organizasyona bağlı API anahtarı yoksa `404 not_found` (bilinmeyen organizasyonla aynı yanıt). Askıdaki üye de dışarıdan biri gibi görünür.
2. Salt-okunur impersonation yalnızca `*:read` izinlerini kullanabilir.
3. Organizasyon durumu: `suspended` → `403 org_suspended`; `pending_deletion` → yalnızca okuma ve `org:delete` (iptal).
4. **Politika her istekte:** IP izin listesi (tüm principal'lar, API anahtarları dahil; istemci IP'si yoksa reddeder), MFA / phishing'e dayanıklı MFA (oturumun `amr`'ı), oturum ömrü üst sınırı (`auth_time`'dan beri geçen süre → `step_up_required`).
5. İzin: rolün izinleri; API anahtarı / servis hesabı için rol ∩ kapsamlar. Yoksa `403 forbidden`.

Platform admin'i örtük yetki almaz (ADM-07 kendi API'sini kullanır).

**Yazma eşzamanlılığı:** Her durum değiştiren işlem tek transaction'da: yetkilendir → organizasyon satırını kilitle (`FOR UPDATE`) → taze anlık görüntüyle yeniden yetkilendir. Bir organizasyonun yazmaları sıralanır; "son sahip", kaynak sınırları ve yükseltme kontrolleri yarışla atlatılamaz (TOCTOU yok); rolü az önce düşürülen bir aktör eski rolüyle işlemi bitiremez. Kilit yalnızca üyeler için alınır (dışarıdakiler kiracıyı bloklayamaz).

## Ayrıcalık yükseltme koruması (ORG-04)

- Rol atama / davet / servis hesabı / API anahtarı kapsamı: aktör verilen tüm izinlere kendisi sahip olmalı; `owner` rolünü yalnızca `owner` verir ve **her yolda step-up** ister (doğrudan rol değişikliği, `owner` daveti ve bu davetin yeniden gönderimi).
- Başka bir üyeyi / servis hesabını / özel rolü yönetmek için aktör hedefin **mevcut** tüm izinlerine sahip olmalı (kimse kendinden yetkili birini yönetemez; yalnızca sahipler sahiplere dokunur).
- Kişisel API anahtarlarını yalnızca sahibi döndürebilir (aksi hâlde bir yönetici başka kullanıcı adına kimlik bilgisi üretebilirdi).
- Servis hesapları asla `owner` olamaz (kod + `service_accounts_not_owner_check`).

## API anahtarları (ORG-08)

- Biçim: `ak_<env>_<32 rastgele baytın 43 haneli base62'si>_<"ak_<env>_<sır>" için CRC-32, 6 haneli base62>`. Önek ve sağlama toplamı sızıntı tarayıcıları ve yazım hatalarını veritabanına gitmeden reddetmek içindir; güvenlik 256 bitlik sırdadır.
- Yalnızca anahtar metninin SHA-256'sı saklanır; anahtar yalnızca oluşturma / rotasyon yanıtında bir kez görünür (`Cache-Control: no-store`), `Debug`'da ve audit'te yoktur.
- Doğrulama: biçim + sağlama + ortam veritabanı olmadan; tek indeksli arama; saklanan hash sabit zamanlı tekrar karşılaştırılır; tüm hatalar aynı `401 unauthenticated`. İyi biçimli ama geçersiz anahtarlar IP başına sınırlanır (`429`) ve audit'e yazılır (sınırla sınırlı). Hesap askıya alınması, üyelik askısı, servis hesabının devre dışı kalması, organizasyon silme planı ve IP izin listesi anahtarı anında durdurur.
- `last_used_at` / `last_used_ip` anahtar başına en fazla `last_used_update_interval`'da bir yazılır (tek koşullu `UPDATE`).
- Son kullanma zorunlu (en fazla `max_lifetime`); oluşturma ve rotasyon step-up ister (API anahtarı anahtar üretemez); rotasyonda eski anahtar kısa bir süre geçerli kalır; bir anahtarın iptali rotasyon zincirindeki **tüm** öncüllerini de iptal eder (A → B → C, C iptal → A ve B de); üyelik silinince kişisel anahtarlar FK kaskadıyla silinir.
- **Yalnızca organizasyon uç noktaları:** `api_key_middleware` bir anahtarı yalnızca `/v1/orgs/{org_id}` ve `/v1/orgs/{org_id}/…` yollarında `Principal`'a çevirir (nokta segmentleri, yüzde kodlanmışları dahil, reddedilir). Diğer yollarda istek dokunulmadan geçer ve anahtar kimseyi doğrulamaz: kişisel anahtar kullanıcısı adına yalnızca kendi organizasyonunda ve kapsamları içinde davranır; kapsam denetlemeyen `/v1/me/…` hesap uç noktalarında (profil, passkey listesi, kişisel güvenlik olayları …) kullanılamaz. API anahtarıyla istemci doğrulaması yapan uç noktalar (SES-10) `authenticate_api_key`'i doğrudan çağırır.

## Davetler (ORG-05)

256 bit token (yalnızca SHA-256), varsayılan 7 gün, e-postaya bağlı: kabul eden hesabın **doğrulanmış** adresi davet adresiyle (normalize) eşleşmeli. Bilinmeyen / kullanılmış / iptal / süresi dolmuş token ayırt edilemez (`invalid_or_expired_token`). Kabul atomik (aynı token'ın eşzamanlı kabulünde tam olarak biri başarılı). Yeniden gönderim yeni token üretir (eskisi ölür); organizasyon başına bütçe, organizasyon + alıcı adresi başına bütçe (`invitation_sends_per_recipient`: daveti iptal edip aynı adrese yeniden davet göndererek davet başına bekleme süresi aşılamaz) ve davet başına bekleme süresi; bekleyen davet sayısı sınırlı; önizleme / kabul kullanıcı başına sınırlı. Token içeren gövdeler `SecretJson` ile okunur (reddedilme mesajları değeri asla loglamaz). Var olan ama üye olmayan bir hesabın daveti, hiç olmayan bir adresinkiyle aynı yanıtı alır. Davet eden üye çıkarılır, askıya alınır, yetkisi düşürülürse **veya rolünden izin çıkarılırsa** gönderdiği bekleyen davetler iptal edilir (artık veremeyeceği bir rol bayat bir davetle verilemez). `owner` daveti ve yeniden gönderimi step-up ister.

## Domain doğrulama (ORG-06)

TXT kaydı `<domain_verification_label>.<domain>` (tam nitelikli sorgu, arama domain'i eklenmez), değer `authn-verification=<43 karakter>`. DNS sorgusu transaction dışında, `dns_timeout` ile sınırlı ve organizasyon başına sınırlıdır. Domain'ler e-posta domain'leri gibi normalize edilir (IDNA, homograf reddi). Bir domain'i yalnızca bir organizasyon doğrulayabilir (ilk doğrulayan kazanır). Otomatik katılım yalnızca doğrulanmış domain'lerde açılabilir ve yalnızca **doğrulanmış** e-posta adresi tam olarak o domain'de olan kullanıcıları (`member` rolüyle) ekler; alt domain'ler ve benzer görünenler eşleşmez. Organizasyondan **çıkarılan veya ayrılan** kullanıcılar otomatik katılımla geri eklenmez (`org_auto_join_exclusions`, migration `1501`); kaydı yalnızca kabul edilen bir davet siler ve kayıt kişisel veri dışa aktarımında (`auto_join_exclusions`) yer alır. `sso_required` Faz 2 için saklanır, henüz uygulanmaz.

## Politikalar (ORG-07)

Alanlar: `mfa_required`, `phishing_resistant_mfa_required` (MFA'yı ima eder), `allowed_login_methods`, `allowed_mfa_factors`, `max_session_lifetime_seconds`, `ip_allowlist` (CIDR, en fazla 100), `trusted_devices_allowed`, `allowed_passkey_aaguids` (PKY-08). Değişiklik `policies:manage` + step-up ister, eski ve yeni değerlerle audit'e yazılır, çağıranı dışarıda bırakacak değişikliği reddeder (`org_policy_lockout`) ve sıkılaştırmada organizasyonun tüm oturumlarını kapatır.

## Sahiplik devri ve silme (ORG-11, ORG-12)

Devir: sahip + step-up; hedef aktif üye olmalı; `one_time_tokens` (purpose `org_ownership_transfer`, `group_id` = organizasyon kimliği: yeni istek / iptal / silme / tamamlanma diğer bekleyen devirleri iptal eder). Yalnızca hedef kullanıcı step-up ile kabul edebilir; başkası sunarsa token tüketilmez. Kabulde başlatan hâlâ aktif sahip ve hedef aynı (yeniden oluşturulmamış) aktif üyelik olmalı; hedef `owner`, başlatan `admin` olur ve başlatanın oturumları kapanır. İptal `org.ownership_transfer_cancelled` olarak audit'e yazılır.

Silme: sahip + step-up; `pending_deletion` + `deletion_scheduled_for`; bekleyen davetler ve devirler iptal, organizasyonun tüm oturumları kapanır, API anahtarları durur; iptal edilebilir (`org.deletion_cancelled`); süre dolunca `purge_due_deletions` organizasyonu siler (tüm kapsamlı satırlar kaskadla).

## Konfigürasyon (`[org]`, `crates/authn-core/src/config/org.rs`)

| Anahtar | Varsayılan |
|---------|-----------|
| `invitation_ttl` | `7d` |
| `invitation_sends_per_org` | 50 / 1 saat |
| `invitation_resend_cooldown` | `1m` |
| `invitation_sends_per_recipient` | 5 / 1 gün (organizasyon + alıcı adresi) |
| `creates_per_user` | 10 / 1 gün |
| `token_attempts_per_user` | 30 / 1 saat |
| `domain_verification_label` | `_authn-verification` |
| `domain_checks_per_org` | 30 / 1 saat |
| `dns_timeout` | `5s` |
| `ownership_transfer_ttl` | `7d` |
| `ownership_transfers_per_org` | 10 / 1 saat |
| `deletion_grace_period` | `30d` |
| `limits.{custom_roles, domains, service_accounts, api_keys, pending_invitations}` | 50, 20, 100, 500, 1000 |
| `api_keys.environment` | `live` |
| `api_keys.max_lifetime` / `default_lifetime` | `365d` / `90d` |
| `api_keys.rotation_grace` | `24h` |
| `api_keys.last_used_update_interval` | `1m` |
| `api_keys.auth_failures_per_ip` | 30 / 15 dk |

Step-up penceresi `session.step_up_max_age`'dir.

## Uç noktalar

Tablo: `src/routes.rs` modül belgesi. Tüm yollar `/v1/orgs/{org_id}/…` adlandırmasını kullanır (authn-audit ile çakışmasız birleşme). Tüm başarılı yanıtlar `Cache-Control: no-store` taşır; her handler `#[utoipa::path]` ile belgelenir (`OrgApi`).

## Hata kodları (`crates/authn-core/src/error/codes/org.rs`)

`org_slug_taken`, `org_last_owner`, `org_role_escalation`, `org_already_member`, `org_invitation_pending`, `org_invitation_email_mismatch`, `org_email_verification_required`, `org_role_key_taken`, `org_builtin_role_immutable`, `org_role_in_use`, `org_limit_reached`, `org_domain_exists`, `org_domain_claimed`, `org_domain_verification_failed`, `org_domain_not_verified`, `org_policy_lockout`, `org_policy_ip_denied`, `org_policy_mfa_required`, `org_pending_deletion`, `org_deletion_not_scheduled`, `org_suspended`, `org_owner_required`, `org_transfer_target_invalid`, `api_key_expiry_invalid`, `api_key_scope_invalid`, `api_key_inactive`, `service_account_disabled`, `service_account_name_taken`. Ortak kodlar: `not_found` (başka kiracı dahil), `forbidden`, `step_up_required`, `rate_limited`, `validation_failed`, `invalid_or_expired_token`, `unauthenticated`.

## Migration `1500_org_tenant_hardening.sql`

- `api_keys_single_owner_check` (anahtarın tam bir sahibi), `api_keys_member_fk` (kişisel anahtar üyeliğe bağlı, üyelikle silinir).
- `service_accounts_not_owner_check`, `role_permissions_owner_only` tetikleyicisi.
- `memberships_last_owner` **ertelenmiş kısıt tetikleyicisi**: var olan bir organizasyon commit anında en az bir aktif sahibe sahip olmalı (organizasyonun kendisinin silinmesi hariç). Bu, son sahibin `users` satırının silinmesini de reddeder (ACC-09'un ikinci savunma hattı).
- Silme, sahip sayımı, sayfalama ve davet süresi indeksleri.

## Migration `1501_org_auto_join_exclusions.sql`

- `org_auto_join_exclusions (org_id, user_id, reason ∈ {removed, left}, created_at)`: çıkarılan / ayrılan kullanıcıyı domain otomatik katılımından hariç tutar (ORG-02, ORG-06). Organizasyon veya kullanıcı silinince kaskadla temizlenir; davet kabulü kaydı siler.

## Server / Dalga B'nin bağlaması gerekenler

1. `OrgService::new(OrgServiceDeps { pool, clock, audit, events, notifier, rate_limiter, session_revoker, dns: Arc::new(HickoryDnsTxtResolver::from_system_conf(config.org.dns_timeout)?) }, OrgServiceSettings::from_app_config(&config))`, `impl FromRef<AppState> for OrgService`, `.merge(authn_org::router::<AppState>())` (kimlik doğrulama katmanının arkasında), `openapi.rs`'e `authn_org::OrgApi`.
2. `api_key_middleware`'i request-context'ten sonra, session kimlik doğrulama katmanıyla aynı yere (`from_fn_with_state(org_service, api_key_middleware)`), modül router'ları mutlak `/v1/...` yollarıyla birleştirildikten sonra (ara katman tam yolu görmeli); başka bir katman zaten `Principal` koyduysa ve anahtar da sunulmuşsa istek reddedilir. Anahtar yalnızca `/v1/orgs/{org_id}[/…]` yollarında `Principal` olur; API anahtarıyla istemci doğrulaması yapan diğer uç noktalar (SES-10) `authenticate_api_key`'i doğrudan çağırmalıdır.
3. Arka plan işleri: `purge_due_deletions(limit)`, `expire_invitations()`.
4. `authn_account::OrganizationOwnership` → `authn_org::sole_owner_organizations(conn, user)`.
5. `authn_mfa::MfaPolicySource::org_policy_for_user` → `authn_org::policies_for_user(conn, user)` sonucunu `OrgMfaPolicy { mfa_required, phishing_resistant_required, allowed_factors, trusted_devices_allowed }`'e eşleyip `strictest` ile birleştirmek.
6. `authn_audit::AuditAccessPolicy::check` → `org_service.authorize_from(principal, Permission::{AuditRead, WebhooksRead, WebhooksManage}, org, client_ip)`; `Ok` → `Allow`, `Err(not_found/forbidden/…)` → `Deny`.
7. `OrgDataExporter`'ı dışa aktarma listesine ekleme.
8. authn-session: API anahtarlı istemci kimlik doğrulaması (SES-10) için `authenticate_api_key`; organizasyon değiştirmede (SES-17) `check_membership` + `Authorization::policy` (`allows_login_method`, `session_lifetime_cap`, `allows_ip`); giriş ve e-posta doğrulamasından sonra `auto_join_verified_domains(user)`.

## Güvenlik notları

### Güvenlik incelemesinde düzeltilenler (2026-11-01)

| Önem | Bulgu | Düzeltme | Regresyon testi |
|------|-------|----------|-----------------|
| Orta | Kişisel API anahtarı, `api_key_middleware` tarafından **her** yolda kullanıcının `Principal`'ına çevriliyordu; kapsam denetlemeyen diğer modüllerin `/v1/me/…` uç noktaları (profil, passkey listesi, kişisel güvenlik olayları) organizasyona ve kapsamlara bağlı bir anahtarla okunabiliyordu | Anahtar yalnızca `/v1/orgs/{org_id}[/…]` yollarında `Principal` olur (`is_api_key_path`, nokta segmentleri reddedilir); diğer yollarda istek dokunulmadan geçer | `org_08_api_keys_are_not_accepted_outside_organization_endpoints`, `org_08_api_keys_only_authenticate_organization_paths` |
| Orta | Domain otomatik katılımı, organizasyondan çıkarılan (veya ayrılan) kullanıcıyı bir sonraki girişte sessizce yeniden üye yapıyordu: doğrulanmış domain'li kullanıcılar için çıkarma kalıcı değildi | `org_auto_join_exclusions` (migration `1501`): çıkarma / ayrılma kaydedilir, otomatik katılım atlar, yalnızca kabul edilen davet kaydı siler | `org_02_org_06_auto_join_never_undoes_a_removal_or_a_departure` |
| Orta | `owner` rolünü doğrudan vermek step-up isterken `owner` daveti (ve yeniden gönderimi) istemiyordu; bayat bir sahip oturumu yeni sahip üretebiliyordu | `owner` daveti ve yeniden gönderimi step-up ister | `org_04_org_05_owner_invitations_require_step_up` |
| Düşük | Rotasyon zincirinde (A → B → C) C'nin iptali yalnızca B'yi iptal ediyordu; geçiş süresindeki A çalışmaya devam ediyordu | Özyinelemeli CTE ile tüm öncül zincir iptal edilir | `org_08_revoking_a_key_revokes_its_whole_rotation_chain` |
| Düşük | Özel rolden izin çıkarmak, rolü taşıyanların gönderdiği bekleyen davetleri iptal etmiyordu (üye düşürmede ediyordu); bekleyen davet artık veremeyecekleri bir rolü veriyordu | Rol izni azaltıldığında taşıyıcıların bekleyen davetleri iptal edilir | `org_04_org_05_role_reduction_revokes_invitations_of_its_holders` |
| Düşük | Davet başına bekleme süresi, daveti iptal edip aynı adrese yeniden davet göndererek aşılabiliyordu (bir organizasyon bir adrese saatlik bütçesinin tamamını gönderebiliyordu) | Organizasyon + alıcı adresi başına gönderim bütçesi (`invitation_sends_per_recipient`, yeni + yeniden gönderim) | `org_05_revoke_and_reinvite_cannot_bomb_one_address` |
| Bilgi | Domain ekleme, silme iptali ve devir iptali `org.updated` + `metadata.action` olarak yazılıyordu | authn-audit'in eklediği `org.domain_added`, `org.deletion_cancelled`, `org.ownership_transfer_cancelled` türleri kullanılıyor | `org_02_org_06_auto_join_never_undoes_a_removal_or_a_departure` |

### Kabul edilen riskler ve bilinen sınırlamalar

- `Principal::active_org` kullanıcı oturumlarında erişimi sınırlamaz; kullanıcı üyesi olduğu her organizasyona URL ile erişebilir, ancak o organizasyonun politikası (IP, MFA, ömür) her istekte uygulanır. API anahtarları ve servis hesapları yalnızca kendi organizasyonlarına erişir.
- Oturum ömrü üst sınırı `auth_time`'a göre uygulanır (son kimlik doğrulamadan beri geçen süre); mutlak oturum ömrünü authn-session uygular.
- İzin verilen giriş yöntemleri ve MFA faktörleri `amr`'dan güvenilir biçimde çıkarılamadığı için authn-session / authn-mfa'da (giriş / organizasyon değiştirme) uygulanmalıdır.
- API anahtarlarına MFA / oturum ömrü politikası uygulanmaz (yalnızca IP izin listesi); politika sıkılaştırması oturumları kapatır ama mevcut kişisel anahtarları iptal etmez. Gerekirse yöneticiler anahtarları `api_keys:manage` ile iptal eder. Bilinçli tercih: makine kimlik bilgileri MFA taşıyamaz.
- Servis hesabının (API anahtarıyla) gönderdiği davetlerde `invited_by` boştur; servis hesabı devre dışı bırakılır veya rolü düşürülürse bu davetler kendiliğinden iptal edilmez (davet oluşturulurken yükseltme koruması uygulanmıştır). Gerekirse `members:invite` ile iptal edilir.
- Bekleyen bir sahiplik devri, başlatan sahiplikten düşürüldüğünde iptal edilmez; kabul anında başlatanın hâlâ aktif sahip olması zorunlu olduğundan devir ancak başlatan yeniden sahip olursa (token süresi içinde) tamamlanabilir.
- Organizasyon adı, davet ve devir e-postalarında görünür ve organizasyonu kuran kullanıcı tarafından seçilir (kontrol / bidi / görünmez karakterler reddedilir, ≤ 200 karakter). Organizasyon kurma kullanıcı başına, davetler organizasyon ve organizasyon + alıcı başına sınırlıdır; içerik (ör. marka taklidi) denetlenmez.
- Domain otomatik katılımını açmak / kapatmak `domains:manage` ister, step-up istemez (audit'e `org.policy_changed` olarak yazılır).
- `org_domain_claimed` hatası, TXT kaydını yayımlayabilen (domain'i kontrol eden) çağırana domain'in başka bir organizasyonda doğrulandığını söyler; domain'i kontrol etmeyen biri bunu öğrenemez.
- Doğrulanmış domain'ler periyodik olarak yeniden doğrulanmaz (Faz 2); domain el değiştirirse eski doğrulama ve otomatik katılım sürer.
- ~~Üye listesi satır başına okuma~~ — **kapatıldı (wave 2B, K-41):** üye listesi sayfanın adreslerini tek sorguyla `UserRepository::find_many` ile okur.
- ~~Rol değişikliğinde `MembershipRemoved`~~ — **kapatıldı (wave 2B, K-41):** rol düşürme, özel rolden izin çıkarma ve devirde eski sahibin düşürülmesi oturumları `RevocationReason::MembershipChanged` (`membership_changed`) ile kapatır; üyelik askıya alma / çıkarma / ayrılma `MembershipRemoved` kalır (testler `changed_in_org` / `revoked_in_org` ile ayırır).
- IP izin listesi değişikliği (genişletme dahil) sıkılaştırma sayılır ve oturumları kapatır (bilinçli olarak temkinli).
- `GET /v1/org-permissions` (statik katalog) da bir organizasyon yolu olmadığından API anahtarıyla çağrılamaz.
- Uygulanmayan SHOULD/MAY maddesi yoktur; ORG-06 `sso_required` Faz 2'dir.

## Testler

`tests/` altında gerçek PostgreSQL ile: `orgs`, `members`, `roles`, `invitations`, `domains`, `policies`, `api_keys`, `service_accounts`, `transfer`, `idor` (iki kiracı; saldırgan A'nın sahibi, step-up + MFA taze, tüm kapsamlı API anahtarı ve servis hesabı ile B'nin kimlikleriyle **her** organizasyon uç noktasını dener; yanıtlar `404` ve var olmayan kimliklere verilen yanıtla aynı olmalı; B'nin durumu değişmemeli), `http` (OpenAPI kapsamı, kimlik doğrulama zorunluluğu, salt-okunur impersonation). Birim testleri: izin kataloğu, karar fonksiyonu, anahtar biçimi (proptest), politika, doğrulama, API anahtarı yol kuralı. Fuzz: `fuzz/fuzz_targets/api_key_parse.rs`.

## Komutlar

```bash
cargo test -p authn-org
cargo clippy -p authn-org --all-targets --all-features -- -D warnings
cargo fmt -p authn-org
cargo +nightly fuzz run api_key_parse -- -max_total_time=60
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
