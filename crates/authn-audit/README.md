# authn-audit

Kurcalamaya dayanıklı (hash zincirli) audit log, transactional outbox işçisi ve imzalı organizasyon webhook'ları (Standard Webhooks).

## Sahip olunan gereksinimler

| Kimlik | Nerede | Özet |
|--------|--------|------|
| AUD-01 | `sink.rs` (`PgAuditSink`) | `AuditSink` portu; tüm `SecurityEventKind` türleri kaydedilir. `record` kendi kısa transaction'ında (iş işlemi başarısız olsa bile), `record_in_tx` çağıranın transaction'ında. |
| AUD-02 | `chain.rs`, `canonical.rs`, `verify.rs`, migration `1700` | `hash = SHA-256(prev_hash ‖ canonical_json(kayıt))`; zincir başı satır kilidiyle (`FOR UPDATE`) sıralı ekleme — eşzamanlı yazarlarda çatallanma yok; tam ve kontrol noktasından doğrulama; en az yetki rol fonksiyonu. |
| AUD-03 | `sanitize.rs`, `sink.rs` | Olay içeriği (aktör, gerçek aktör, ne, kaynak, sonuç, IP, user-agent, request id, organizasyon). Sır/şifre/token/OTP/kişisel veri **yapısal olarak** engellenir. |
| AUD-04 | `query.rs`, `api.rs` | `GET /v1/me/security-events` (son 90 gün), `GET /v1/orgs/{org_id}/audit-events` (filtreli, keyset sayfalama). |
| AUD-05 | `sink.rs`, `retention.rs` | Takma adlar + zincir dışı silinebilir kişisel veri; `pseudonymize_subject`; kontrol noktalı saklama temizliği. |
| AUD-06 | `outbox/` | `EventPublisher` (çağıranın transaction'ında outbox), işçi: `FOR UPDATE SKIP LOCKED`, en az bir kez, üstel geri çekilme + jitter, ölü mektup, idempotency anahtarı, konu öneki → handler kaydı, mühürlü yükün silinmesi. |
| AUD-07 | `webhooks/`, `api.rs` | Organizasyon başına endpoint'ler, olay türü abonelikleri, zarf şifreli imza sırları + rotasyon (çakışma süresince iki imza), Standard Webhooks başlıkları, SSRF korumalı teslim (`OutboundTarget::UserSupplied`), teslim geçmişi, elle yeniden teslim, sürekli hatada otomatik devre dışı bırakma. |

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. Organizasyon yetkilendirmesi `AuditAccessPolicy` trait'i üzerinden **sunucuya** devredilir (authn-org'a derleme zamanı bağımlılığı yoktur). Yeni harici bağımlılık eklenmedi; `http` ve `zeroize` workspace bağımlılıkları crate'e eklendi.

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `PgAuditSink::new(pool, clock)` | `AuditSink` uygulaması (`record`, `record_in_tx`, `pseudonymize_subject`); `append(conn, event) -> AppendedEvent { seq, hash, duplicate }` |
| `verify_chain(&pool) -> ChainReport` / `verify_chain_from(&pool, ChainAnchor)` | Zincir doğrulama (CLI `verify-audit-chain`, ADM-07) |
| `create_checkpoint(&pool, &clock) -> ChainAnchor` | Elle kontrol noktası; logdaki `(seq, hash)` veritabanı dışında saklanmalı |
| `purge_expired(&pool, &clock, retention)` / `purge_before(...)` | Saklama temizliği (AUD-05) |
| `OutboxEventPublisher::new(clock, max_attempts)` | `EventPublisher` uygulaması (outbox kimliği = olay kimliği → idempotent) |
| `OutboxRepository::{enqueue, requeue_dead, depth, purge}` | Genel outbox erişimi |
| `OutboxHandler` trait, `OutboxHandlers` (önek → handler), `HandlerError::{retry, retry_after, permanent}` | Konu bazlı teslim çerçevesi |
| `OutboxWorker::new(pool, clock, handlers, OutboxConfig)` · `run_once()` · `run(shutdown)` | Arka plan işçisi |
| `AuditAccessPolicy` trait (`check(principal, org, permission, client_ip)`), `AuditPermission`, `AccessDecision`, `DenyAllAuditAccess` | Organizasyon yetkilendirmesi (sunucu uygular; `client_ip` organizasyon IP izin listesi, ORG-07, içindir) |
| `AuditService::new(AuditServiceParts { pool, clock, cipher, policy, rate_limiter, config, step_up_max_age })` | Router durumu; `sink()`, `event_publisher()`, `webhooks()`, `outbox_handlers(http)`, `outbox_worker(handlers)`, `run_maintenance(&maintenance_pool)` |
| `router::<S>()`, `AuditApi` (utoipa) | HTTP endpoint'leri ve OpenAPI |
| `list_events(&pool, &AuditEventFilter, &PageRequest)` → `Page<AuditEventDetail>` | Platform geneli sorgu (admin, ADM-07) |
| `hide_from_subject_in_tx(conn, event_id, until, now)` | K-62: olayı ilgili kişinin kendi listesinden (`GET /v1/me/security-events`, `list_user_security_events`) `until`'e kadar gizler. Çağıranın transaction'ında çalışır. Tablo `audit_subject_view_holds` (migration `1701`) ekleme-yalnızcadır (trigger), daha geç bir kayıt süreyi uzatır, olay saklama süresiyle silinince kaskadla gider. Personel görünümleri (`list_events`, organizasyon günlüğü) etkilenmez. Kullanıcı: authn-admin yasal kısıtlaması. Migration `1701` `authn_audit_apply_least_privilege`'i yeni tabloyla günceller (uygulama: `SELECT, INSERT`; bakım: `SELECT`). |
| `webhooks::{WebhookManager, WebhookFanout, WebhookDeliverer, build_signed_request, signed_delivery_headers, validate_webhook_url, rewrap_webhook_secrets}` | Webhook bileşenleri; `rewrap_webhook_secrets` KEK rotasyonu (`rotate-kek`/`reencrypt`) içindir |

## Endpoint'ler

| Yöntem | Yol | Yetki |
|--------|-----|-------|
| GET | `/v1/me/security-events` | kimliği doğrulanmış kullanıcı |
| GET | `/v1/orgs/{org_id}/audit-events` | `audit:read` |
| GET / POST | `/v1/orgs/{org_id}/webhooks` | `webhooks:read` / `webhooks:manage` + step-up |
| GET / PATCH / DELETE | `/v1/orgs/{org_id}/webhooks/{endpoint_id}` | `webhooks:read` / `webhooks:manage` (+ URL, abonelik, etkinleştirme ve silmede step-up) |
| POST | `/v1/orgs/{org_id}/webhooks/{endpoint_id}/rotate-secret[?immediate=true]` | `webhooks:manage` + step-up |
| GET | `/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries` | `webhooks:read` |
| POST | `/v1/orgs/{org_id}/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver` | `webhooks:manage` |

Kontrol sırası: kimlik doğrulama → yetkilendirme (başarısızlık **her zaman** `404 not_found`: başka kiracı, üye değil, izin yok ve bilinmeyen organizasyon ayırt edilemez) → salt-okunur impersonation (`403`) → step-up (`401 step_up_required`; API anahtarı kimlik bilgileri muaf, impersonation asla geçemez) → rate limit (`429` + `Retry-After`). Sır içeren yanıtlar (`201` oluşturma, rotasyon) `Cache-Control: no-store` taşır; sır yalnızca bir kez gösterilir.

Hata kodları (`authn_core::error::codes::audit`): `webhook_url_invalid` (422), `webhook_endpoint_limit_reached` (409), `webhook_delivery_in_progress` (409), `webhook_endpoint_disabled` (409).

## Konfigürasyon (`[audit]`, `crates/authn-core/src/config/audit.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `retention` | `400d` | Saklama (AUD-05), 30 gün – 10 yıl |
| `user_visible_window` | `90d` | Kendi güvenlik olayları penceresi (AUD-04) |
| `outbox.poll_interval` / `batch_size` / `max_attempts` | `1s` / 100 / 10 | |
| `outbox.backoff_base` / `backoff_max` | `2s` / `1h` | `base·2^(n-1)`, `[d/2, d]` jitter |
| `outbox.lease` | `60s` | Handler zaman aşımı = `lease·0.8` |
| `outbox.concurrency` | 16 | Yeni |
| `outbox.delivered_retention` / `dead_retention` | `7d` / `30d` | Yeni (OPS-06 temizliği) |
| `webhooks.timeout` / `max_attempts` | `10s` / 8 | `timeout < outbox.lease` zorunlu |
| `webhooks.secret_rotation_overlap` | `24h` | `0` = rotasyon hep anında |
| `webhooks.max_endpoints_per_org` | 10 | Eşzamanlı oluşturmada da (advisory lock) |
| `webhooks.backoff_base` / `backoff_max` | `1m` / `6h` | Yeni; alıcının `Retry-After`'ı `backoff_max`'a kadar uygulanır |
| `webhooks.disable_after_failures` / `disable_after` | 20 / `24h` | Yeni; ikisi birlikte sağlanınca otomatik devre dışı |
| `webhooks.delivery_retention` | `30d` | Yeni; biten teslim geçmişi |
| `rate_limits.events_read` / `webhook_write` / `webhook_redeliver` | 60/dk · 60/saat · 30/saat | Yeni |

Step-up süresi sunucu tarafından `session.step_up_max_age` ile verilir (`AuditServiceParts::step_up_max_age`).

## Tasarım ve güvenlik notları

- **Zincir kaydı:** `audit_events`'in `seq`, `prev_hash`, `hash` dışındaki tüm kolonları (zaman damgaları mikro saniyeye kesilmiş UTC, metadata kanonik JSON — RFC 8785, yalnızca tamsayı). `pii_digest = SHA-256(tuz ‖ kanonik {ip, user_agent})`; tuz silinince özet geri çözülemez.
- **Çatallanmasız ekleme:** her ekleme `audit_chain_head` satırını kilitler; kilit transaction sonuna kadar tutulur. `record_in_tx`'i transaction'ın **son** adımı olarak ve bir kez çağırın (kilit süresi + kilitlenme riski); `SERIALIZABLE`/`REPEATABLE READ` transaction'larında eşzamanlı eklemeler yeniden denenebilir bir serileştirme hatası (`40001`) üretebilir. `record` kendi transaction'ında `lock_timeout = 10s` ile çalışır ve serileştirme/kilitlenme hatasında bir kez yeniden dener. 48 eşzamanlı yazar testi (`aud_02_concurrent_writers_never_fork_the_chain`).
- **Takma adlar:** rastgele UUIDv4 (UUIDv7 zaman sızdırırdı); `audit_subjects` eşlemesi silinince (hesap silme kaskadı veya `pseudonymize_subject`) bağlantı kopar. Silinmiş (`status = deleted` — geride eşleme kalmış olsa bile), var olmayan veya aynı transaction'da unutulmuş kullanıcılar için tek kullanımlık takma ad üretilir ve kişisel veri **saklanmaz**. Kaynak ve metadata içindeki kullanıcı kimlikleri de takma ada çevrilir; kullanıcı referansı adını taşıyan anahtarlardaki (`user`, `owner`, `…_user_id(s)`, `…_owner_id(s)`) ve `user` türündeki kaynaklardaki kimlikler, hesap artık yoksa bile takma ada çevrilir. Olay başına en fazla 128 farklı UUID denetlenir; fazlası `[REDACTED]` olur (kapalı başarısızlık). Daha uzun bir metnin içine gömülü kimlikler (`UserId(…)`, `urn:uuid:…`, `{…}`, ≥ 32 onaltılık rakam) güvenilir biçimde takma ada çevrilemeyeceği için reddedilir — zincirde kullanıcı kimliği bulunmaz.
- **Kişisel verinin sahibi:** impersonation'da gerçek aktör (admin), aksi hâlde kullanıcı aktör, yoksa olayın öznesi (ör. hesaba yapılan başarısız giriş denemeleri). Kullanıcı kendi listesinde yalnızca kendisine ait IP'yi görür (kendi istekleri tam, diğerleri `/24`–`/48`); organizasyon log'u yalnızca ağ maskeli IP gösterir; platform personeli işlemlerinde (impersonation, `admin.*`) ne IP/user-agent ne de personelin kullanıcı kimliği gösterilir.
- **AUD-03 yapısal zorlama:** `reason` yalnızca snake_case kod (aksi `invalid_reason`); metadata anahtarları snake_case ve sır/kişisel veri adları (`password`, `token`, `otp`, `code`, `email`, `ip`, `phone`, `name`, son segment `key` …; ayrıca bu sözcüklerden birini *içeren* bitişik adlar: `newpassword`, `clientsecret`, `accesstoken` …) değer yerine `[REDACTED]` — **boolean değerler hariç** (wave 1, K-15): tek bit bir sır hakkında olgu bildirir (`must_change_password`, `code_issued`, `password_removed`) ama kendisi sır veya kişisel veri olamaz; bu anahtarlarda dize, sayı, dizi, nesne ve `null` yine redakte edilir (`aud_03_boolean_flags_under_secret_words_are_kept`, `aud_03_non_boolean_values_under_secret_words_stay_redacted`); değerler yalnızca ≤128 yazdırılabilir ASCII (boşluksuz), tamsayı, bool, null; e-posta, IP, telefon, ≥4 haneli sayısal kod, JWT, `whsec_`, yüksek entropili token görünümlü değerler `[REDACTED]`. Logda yalnızca anahtar yolu ve kural adı görünür, değer asla.
- **Tahrifat tespiti:** değişiklik (`hash_mismatch`), silme/ekleme/sıralama (`prev_hash_mismatch`), sondan kesme (`head_mismatch`, kontrol noktası), kişisel veri değişikliği (`pii_digest_mismatch`). Zincirin tamamen yeniden yazılması yalnızca **veritabanı dışında saklanan** bir çıpa ile (`verify_chain_from`) tespit edilebilir: temizlik ve elle kontrol noktaları `(seq, hash)`'i loglar.
- **Saklama temizliği:** yalnızca `seq` önekini siler (geriye tarihli bir olay temizliği durdurur, zincirde delik oluşmaz), silmeden önce segmenti yeniden doğrular (tahrif edilmiş kanıtı silmeyi reddeder), `SET LOCAL authn.audit_purge_before` kaçış kapısını kullanır ve `retention_purge` kontrol noktası yazar. En az yetki: `SELECT authn_audit_apply_least_privilege('authn_app', 'authn_maintenance')` sonrası temizlik bakım rolünün havuzuyla çalışmalıdır.
- **Outbox:** talep etme `FOR UPDATE SKIP LOCKED` + kiralama (`locked_until`, `locked_by`); her mesajın kiralaması handler çağrılmadan hemen önce (hâlâ bu işçideyse ve süresi dolmamışsa) yenilenir — partide sıra beklerken kiralaması dolan mesaj işlenmez, yeniden talep edilmek üzere bırakılır; deneme sayacı talep anında artar (çökme döngüsü sonsuz değildir); son denemede kiralaması dolan mesaj handler çağrılmadan ölü mektuba gider; durum güncellemeleri kiralama sahibine koşulludur; teslimde ve ölü mektupta `sealed_payload` silinir; handler panikleri ve zaman aşımları yeniden denemeye dönüşür; hata metinleri kontrol karakterlerinden arındırılır ve 1000 karakterle sınırlanır.
- **Webhook URL'leri:** yalnızca `https`, kimlik bilgisi/fragment yok, `localhost`/`.local`/`.internal`/tek etiketli adlar ve özel/loopback/link-local/CGNAT/metadata (genel adres alanındaki Azure WireServer dahil)/dokümantasyon IP'leri reddedilir; IPv6'da yalnızca küresel unicast `2000::/3` (Teredo/`2001::/23`, `2001:db8::/32`, `2002::/16`, `3fff::/20` hariç) kabul edilir — IPv4 uyumlu `::/96`, NAT64 ve `100::/64` reddedilir. Asıl SSRF savunması teslimdeki `HttpClient` (`UserSupplied`: DNS çözümü, IP sabitleme, yönlendirme yok, boyut sınırı). URL bir yetenek (ör. gizli yol) taşıyabileceği için audit'e ve loglara yazılmaz.
- **Webhook sırları:** `whsec_` + 32 bayt CSPRNG; AAD = `webhook_endpoints/secret_ciphertext|previous_secret_ciphertext/<id>` ile zarf şifreli; rotasyonda eski sır yeni AAD ile yeniden mühürlenir. Yanıt gövdesi asla saklanmaz/loglanmaz; teslim hatası yalnızca `http_status_<n>` veya `transport_error:<kod>`.
- **Webhook gövdesi:** `{"id","type","timestamp","organization_id","user_id","data"}` kanonik JSON, ≤ 256 KiB; `webhook-id` = olay kimliği (yeniden denemeler ve elle yeniden teslimlerde sabit — alıcılar tekilleştirir).

## Güvenlik notları

### Bağımsız güvenlik incelemesi (2026-11-01) — düzeltilen bulgular

Her bulgu için düzeltme olmadan başarısız olan bir regresyon testi vardır.

| Önem | Bulgu | Düzeltme | Regresyon testi |
|------|-------|----------|-----------------|
| Orta | Metin içine gömülü kullanıcı kimlikleri (`format!("{user:?}")` → `UserId(…)`, `urn:uuid:…`, `{…}`, basit biçim) takma ada çevrilmeden değişmez zincire yazılıyordu; hesap silme (AUD-05) onları asla kaldıramaz. | Gömülü UUID / ≥ 32 onaltılık rakam içeren değerler, kaynak kimlikleri, neden kodları ve anahtarlar reddedilir (`embedded_identifier`). | `aud_05_embedded_user_ids_never_reach_the_chain`, `aud_05_embedded_identifiers_are_refused` |
| Orta | Outbox işçisi, partide eşzamanlılık yuvası beklerken talep anındaki kiralaması dolmuş (başka işçinin yeniden talep edebildiği) mesajları yine de işliyordu — eşzamanlı çift işleme. | Handler'dan önce koşullu kiralama yenileme; dolmuş/devralınmış kiralamada mesaj işlenmez (`lost_lease`). | `aud_06_message_whose_lease_expired_in_the_batch_is_not_handled` |
| Düşük | Silinmiş hesapların kimlikleri metadata'da (`removed_user_id`, `previous_owner` …) veya `user` kaynağında açık metin kalıyordu (yalnızca var olan kullanıcılar tanınıyordu). | Kullanıcı referansı anahtarları ve `user` kaynakları, hesap yoksa da tek kullanımlık takma ad alır. | `aud_05_references_to_deleted_accounts_are_pseudonymised` |
| Düşük | Olay başına 128 UUID sınırının ötesindeki UUID'ler denetlenmeden saklanıyordu (aralarındaki kullanıcı kimliği açık kalıyordu). | Sınır ötesi UUID'ler `[REDACTED]` (kapalı başarısızlık); açık referanslar her zaman önce denetlenir. | `aud_05_identifiers_beyond_the_per_event_limit_are_redacted` |
| Düşük | `status = deleted` olan ama eşlemesi kalmış kullanıcı yeniden bağlanıyor ve yeni kişisel verisi saklanıyordu (belgelenen davranışın tersi). | Silinmiş/unutulmuş durum, mevcut eşlemeden önce değerlendirilir. | `aud_05_deleted_status_account_is_never_linked_again` |
| Düşük | En az yetki fonksiyonu yalnızca `audit_events`/`audit_chain_checkpoints` üzerindeki yetkileri geri alıyordu; daha önce geniş yetki almış uygulama rolü `audit_subjects` üzerinde `UPDATE` (geçmişi başka kullanıcıya bağlama) ve `audit_chain_head` üzerinde `TRUNCATE` yetkisini koruyordu. | Tüm audit/outbox/webhook tablolarında önce `REVOKE ALL`, sonra yalnızca gereken yetkiler. | `aud_02_least_privilege_helper_revokes_previous_broad_grants` |
| Düşük | Bitişik sır adları (`newpassword`, `clientsecret`, `accesstoken`, `useremail` …) anahtar yasak listesini atlatıyordu. | Kesin sır sözcükleri anahtarın herhangi bir yerinde aranır. | `aud_03_concatenated_secret_key_names_are_redacted` |
| Düşük | Kayıt anındaki URL denetimi küresel olmayan IPv6 adreslerini (`::7f00:1` gibi IPv4 uyumlu, Teredo, `3fff::/20`, `100::/64`, `64:ff9b:1::/48`) ve genel alandaki metadata adresini (`168.63.129.16`) kabul ediyordu. | IPv6 için yalnızca `2000::/3` küresel unicast (özel bloklar hariç); ek IPv4 blokları. Asıl SSRF savunması teslimdeki `HttpClient`'tır. | `prt_12_aud_07_unsafe_urls_are_rejected` |
| Düşük | Kullanıcıya ve organizasyon adminine gösterilen user-agent, görünümü sahteleyebilen bidi/sıfır genişlikli karakterleri taşıyabiliyordu. | Bu karakterler saklanmadan önce çıkarılır. | `aud_04_user_agent_spoofing_characters_are_removed` |
| Düşük | `AuditAccessPolicy` istemci IP'sini almadığından organizasyon IP izin listesi (ORG-07) audit/webhook uç noktalarında uygulanamıyordu (authn-org talebi). | `check(…, client_ip: Option<IpAddr>)`; handler'lar çözülmüş istemci IP'sini iletir. | `aud_04_access_policy_receives_the_client_ip` |

Ayrıca authn-org'un talep ettiği `SecurityEventKind` türleri eklendi: `org.domain_added`, `org.deletion_cancelled`, `org.ownership_transfer_cancelled`.

### Bağımsız güvenlik denetimi — wave 3B (2026-11-05)

| Önem | Bulgu | Düzeltme | Regresyon testi |
|------|-------|----------|-----------------|
| Düşük | `audit_subject_view_holds` (K-62) bir olayı tek bir satırla süresiz olarak öznenin görünümünden gizleyebiliyordu (üst sınır yoktu). | `hide_from_subject_in_tx` en çok 180 gün kabul eder (`holds::MAX_HOLD`, aşılırsa `validation_failed`); tablo CHECK'i aynı sınırı uygular. Uzatma yeni, audit'li bir satırdır. | `aud_04_k62_a_hold_lasts_at_most_180_days` |

Bekletmeyi kullananlar: authn-admin'in kısıtlama ve uzatma notları (K-62) ve başka bir admini hedefleyen four-eyes istek ve karar olayları; bunlar istek süresi dolana kadar hedeften gizlenir (K-66).

### Kabul edilen riskler (gerekçeli)

- **Değer sezgileri her sırrı yakalayamaz.** Nötr bir anahtar altındaki sıradan bir şifre (`"detail": "hunter2"`) veya 32 karakterden kısa, küçük harf + rakamlı token'lar tespit edilemez. Anahtar yasak listesi ve değer kuralları üretici hatalarına karşı derinlemesine savunmadır; birincil kural üreticilerin `reason`/`metadata`'ya sır koymamasıdır (port belgesi). Daha agresif sezgiler meşru tanımlayıcıları (alan adları, sürüm etiketleri) bozardı.
- **Nötr anahtar altındaki silinmiş hesap kimliği.** Kayıt anında var olmayan bir kullanıcının kimliği kullanıcı referansı adı taşımayan bir anahtardaysa (ör. `"items": [<uuid>]`), oturum/organizasyon kimliklerinden ayırt edilemez ve açık kalır. Üreticiler kullanıcı kimliklerini `…user_id` adlı anahtarlarla veya `with_subject` ile vermelidir.
- **Organizasyon log'unda platform personeli** yalnızca impersonation ve `admin.*` türlerinde gizlenir. authn-admin, platform personelinin yaptığı her işlemi `admin.*` türüyle (ADM-08) veya impersonator ile kaydetmelidir; aksi hâlde (ör. admin API'sinden `mfa.reset`) personelin kullanıcı kimliği ve maskeli IP'si organizasyon adminlerine görünür.
- **Anahtarsız hash zinciri.** Uygulama rolü ekleme yapabildiği için (`INSERT` + zincir başı `UPDATE`), veritabanı erişimi ele geçirilmiş bir saldırgan zincirin sonuna geçerli hash'li sahte olay ekleyebilir veya bir eşlemeyi silip aynı takma adı başka kullanıcıyla yeniden ekleyerek geçmişi yeniden bağlayabilir; `audit_event_pii.pseudonym` (kişisel verinin sahibi) özetin parçası değildir. Bunlar ve zincirin tamamen yeniden yazılması yalnızca **veritabanı dışında** saklanan çıpalarla (`verify_chain_from`, logdaki kontrol noktaları) tespit edilebilir. Anahtarlı (HMAC) zincir, anahtar yönetimi gerektirdiği için Faz 1 kapsamı dışında bırakıldı.
- **API anahtarı kimlik bilgileri step-up'tan muaftır** (insan yeniden kimlik doğrulaması yapamaz); kapsam denetimi `AuditAccessPolicy` uygulamasının sorumluluğundadır. Impersonation hiçbir zaman step-up'ı geçemez.
- **Step-up gerektirmeyen webhook işlemleri:** endpoint'i devre dışı bırakma, açıklama değişikliği ve elle yeniden teslim geri alınabilir/zararsızdır ve kuruluş başına hız sınırlıdır; yeni hedefe yönlendiren veya kapsamı genişleten işlemler (URL, abonelik, etkinleştirme, oluşturma, silme, sır rotasyonu) step-up ister.
- **Webhook URL'si `webhooks:read` sahiplerine görünür** (alıcılar URL'de yetenek token'ı taşıyabilir); bu, endpoint yönetimi için gereklidir. URL audit'e ve loglara yazılmaz.
- **En az bir kez teslim:** durum güncellemesi başarısız olursa (ör. veritabanı kesintisi) aynı webhook yeniden gönderilebilir; alıcılar sabit `webhook-id` ile tekilleştirir.
- **Endpoint silme ile eşzamanlı teslim kaydı** nadiren PostgreSQL kilitlenme tespitine (`40P01`) düşebilir; silme isteği `500` alır ve yeniden denenebilir, teslim tarafı yeniden dener ve silinmiş endpoint'i atlar.
- **Kayıt anındaki URL denetimi tavsiye niteliğindedir;** DNS adları kayıtta çözülmez. Yetkili SSRF savunması her teslimde `HttpClient` (`OutboundTarget::UserSupplied`, authn-protect) tarafından yapılır.

### K-58 değerlendirmesi (2026-11-05)

Yukarıdaki "Kabul edilen riskler" maddeleri yeniden değerlendirildi. Hiçbiri bu dalgada kod değişikliğiyle kapatılmadı. Her biri için gerekçe:

| Madde | Karar | Gerekçe |
|-------|-------|---------|
| Değer sezgileri her sırrı yakalayamaz | İmkânsız (tam olarak) | Rastgele bir metnin sır olup olmadığı bilinemez. Daha agresif kurallar meşru tanımlayıcıları bozar. Birincil kural üreticinin sır koymamasıdır. |
| Nötr anahtar altındaki silinmiş hesap kimliği | Gerekçeli kalır | Anahtar adı olmayan bir UUID'nin kullanıcı mı, oturum mu olduğu bilinemez. Üretici kuralı (`…user_id` / `with_subject`) belgelidir. |
| Organizasyon log'unda platform personeli | Üretici kuralı | authn-admin her personel işlemini `admin.*` veya impersonator ile kaydeder (ADM-08 testleri). |
| Anahtarsız hash zinciri | **Açık, K-77 (tasarım aşağıda)** | Wave 4B denetimi bu dalgada uygulamadı. Gerekçe: zincir biçimini değiştirmek mevcut satırların doğrulanmasını, CLI'ı (authn-server), admin doğrulamasını (authn-admin) ve en az yetki rollerini birlikte etkiler. Yarım bir uygulama, zinciri doğrulanamaz hâle getirme riski taşır. Bugün tespit veritabanı dışı çıpalarla sağlanır (`verify_chain_from`, kontrol noktaları): veritabanına yazabilen biri zinciri baştan hesaplayabilir, ama dışarıda saklanan bir çıpayla bu fark edilir. |
| API anahtarı step-up'tan muaf | Spesifikasyon gereği | İnsan olmayan kimlik bilgisi yeniden doğrulama yapamaz; kapsamı RBAC sınırlar. |
| Step-up istemeyen webhook işlemleri | Gerekçeli kalır | Geri alınabilir ve hız sınırlı. Yönlendiren ya da genişleten her işlem step-up ister. |
| Webhook URL'si `webhooks:read` sahiplerine görünür | Gerekçeli kalır | Endpoint yönetimi için gerekli; audit'e ve loglara yazılmaz. |
| En az bir kez teslim | Gerekçeli kalır | Tam olarak bir kez teslim dağıtık sistemde imkânsızdır. Sabit `webhook-id` ile tekilleştirilir. |
| Endpoint silme ile eşzamanlı teslimde nadir `40P01` | Gerekçeli kalır | PostgreSQL kilitlenmeyi tespit eder. Her iki taraf da güvenle yeniden dener; tutarsız durum yoktur. |
| Kayıt anındaki URL denetimi tavsiye niteliğinde | Gerekçeli kalır | DNS kaydı değişebilir; yetkili denetim her teslimde (`HttpClient`) yapılır. |

### Bağımsız denetim (wave 4B, 2026-11-05)

| # | Önem | Bulgu / kontrol | Durum |
|---|------|-----------------|-------|
| 4B-A1 | bilgi | **Silmenin kapsamı.** Kullanıcı kimliği şu yerlerde bulunur: outbox `payload.user_id` (domain olayları ve bildirimler); `data` içinde (org, oturum ve hesap olayları `data.user_id`'yi yalnızca `event.user_id` ile birlikte yazar; bütün `DomainEvent` üreticileri tarandı); webhook teslimlerinde `payload.user_id`/`data` ve `subject_user_id`. Silme bunların hepsini işaretler ya da karartır. `user.deleted` olayı `pseudonymize_subject`'ten önce aynı transaction'da yayımlanır, dolayısıyla işaretlenir. Kalan: henüz bitmemiş teslimler işaretlidir ve **bitince** karartılır. Alıcılar `user.deleted`'i yine alır (bilinçli). | Doğrulandı |
| 4B-A2 | bilgi | **`FOR SHARE` kilitlenmesi.** Fan-out yalnızca tek bir outbox satırında paylaşımlı kilit tutar, sonra yeni teslim satırları ekler; silme tarafının tuttuğu hiçbir kilidi beklemez. Silme ise outbox satırlarını, ardından teslim satırlarını günceller. Teslimatçı yalnızca kendi teslim satırını ve endpoint'ini kilitler. Döngü yoktur. READ COMMITTED altında güncelleme satır kilidini bekledikten sonra `subject_erased_at`'i yeniden değerlendirir (EvalPlanQual), bu yüzden yarışan teslim de karartılır. | Doğrulandı |
| 4B-A3 | bilgi | Karartılmış bir teslimin yeniden gönderimi, bilinmeyen teslimle aynı `404`'ü döner. Liste uçları yalnızca karartılmış gövdeyi gösterir (`id`, `type`, `timestamp`, `organization_id`, `redacted`). | Doğrulandı |
| 4B-A4 | orta (tasarım) | Anahtarsız hash zinciri. | Açık, K-77 |

**K-77 tasarımı: anahtarlı zincir.**

1. **Anahtar:** `authn-crypto` `KeyPurpose::AuditChain` alt anahtarı (HKDF, mevcut KeyRing; KMS/HSM sağlayıcısı K-96 ile gelir). Uygulama rolü hesaplar. Doğrulama aracı (`verify-audit-chain` CLI) anahtarı aynı yapılandırmadan alır.
2. **Biçim:** `hash = HMAC-SHA-256(K_v, prev_hash ‖ canonical_json(record))`. `audit_events`'e `chain_key_version smallint NULL` eklenir. `NULL`, eski SHA-256 satırlarıdır ve doğrulayıcı onları eski kuralla doğrular. Geçiş noktası, ilk anahtarlı satırın bir kontrol noktasıyla (`audit_chain_checkpoints`) işaretlenmesidir.
3. **Rotasyon:** yeni sürüm `v+1` yalnızca **yeni** satırlar için kullanılır; eski satırlar yeniden hesaplanmaz, çünkü değişmezlik bunu gerektirir. Eski anahtarlar doğrulama için salt-okunur tutulur. Rotasyon kendisi bir audit olayıdır (`audit.chain_key_rotated`) ve yeni anahtarla imzalanan ilk satırdır. Anahtar sızarsa: rotasyon + dış çıpa. Sızmadan önceki satırların bütünlüğünü yalnızca dış çıpalar kanıtlar.
4. **Kontrol noktaları:** `create_checkpoint` HMAC'li başı dışa (operatörün WORM depolamasına) yazmaya devam eder. Anahtar olmadan zincirin yeniden hesaplanamaması tespiti güçlendirir, dış çıpanın yerini tutmaz.
5. **Sahipler:** authn-crypto (amaç), authn-audit (zincir, doğrulayıcı, migration `17xx`), authn-server (CLI), authn-admin (doğrulama ucu). Testler: anahtarsız yeniden hesaplanan zincirin reddi, karma sürüm doğrulaması, rotasyon sonrası doğrulama, yanlış anahtar.

## Sunucunun (authn-server) ve Dalga B'nin bağlaması gerekenler

1. `impl AuditAccessPolicy` — authn-org RBAC ile (`OrgService::authorize_from(principal, permission, org, client_ip)`): `audit:read`, `webhooks:read`, `webhooks:manage`; varsayılan reddet; servis hesapları yalnızca kendi organizasyonu; platform admini örtük yetkili **değil**; `client_ip` ile organizasyon IP izin listesi (ORG-07).
2. `AuditService::new(AuditServiceParts { … })` + `impl FromRef<AppState> for AuditService` + `.merge(authn_audit::router::<AppState>())`; OpenAPI'ye `AuditApi`.
3. `Arc<dyn AuditSink> = Arc::new(service.sink())`, `Arc<dyn EventPublisher> = Arc::new(service.event_publisher())` tüm modüllere.
4. Outbox işçisi: `service.outbox_handlers(protect_http_client)?` + authn-notify için `notification` önekli bir `OutboxHandler` köprüsü (`.register("notification", …)` veya `.merge(…)`), `service.outbox_worker(handlers).run(shutdown)`; birden fazla instance güvenlidir.
5. Günlük bakım: `service.run_maintenance(&maintenance_pool)` (OPS-06); CLI `verify-audit-chain` → `verify_chain` / `verify_chain_from`; `rotate-kek`/`reencrypt` → `rewrap_webhook_secrets`.
6. authn-account (ACC-09): silme transaction'ında `pseudonymize_subject` (bkz. sözleşme değişikliği kaydı).
7. authn-admin (ADM-07): `list_events`, `verify_chain`, `create_checkpoint`. En az yetki uygulandıysa `create_checkpoint` ve `purge_*` bakım rolünün havuzuyla çağrılmalıdır (uygulama rolünün `audit_chain_checkpoints`'e `INSERT` yetkisi yoktur).

## Bilinen sınırlamalar / SHOULD notları

- `record_in_tx` zincir başı kilidini çağıranın commit'ine kadar tutar: çok yazan transaction'lar audit eklemelerini serileştirir. Bu, çatallanmasız zincirin bilinçli bedelidir.
- Webhook otomatik devre dışı bırakıldığında organizasyon adminlerine e-posta gönderilmez (`NotificationKind`'de uygun tür yok); olay audit log'a `webhook.endpoint_auto_disabled` olarak düşer.
- Domain olayı `data` alanı üretici tarafından "sırsız" olarak garanti edilir; webhook gövdesi ayrıca temizlenmez (audit metadata'sından farklı olarak).
- ~~Teslim edilmiş outbox ve webhook teslim kayıtları saklama süresi boyunca kullanıcı kimliği içerebilir~~ — **kapatıldı (K-58, AUD-05/ACC-09, migration `1702`):**
  - Teslim edilen her outbox mesajının açık yükünden teslim anında `user_id`, `recipient` ve `data` silinir (teslim edilmiş yükü okuyan yoktur): `aud_06_k58_delivered_outbox_messages_keep_no_personal_data`.
  - Hesap silinince (`PgAuditSink::pseudonymize_subject`, silme transaction'ında) kullanıcının ölü mektup mesajları hemen temizlenir; bekleyen ve işlenmekte olanlar işaretlenir ve bitince (teslim ya da ölü) temizlenir.
  - Webhook teslimlerinde olayın `user_id`'si `subject_user_id` kolonunda tutulur. Silmede bitmiş teslimler (`succeeded`, `dead`) hemen **karartılır**: yükte yalnızca `id`, `type`, `timestamp`, `organization_id` ve `"redacted": true` kalır, `redacted_at` yazılır. Bitmemiş olanlar işaretlenir ve bitince karartılır. Böylece alıcılar `user.deleted` dahil her olayı yine alır. İşaretli outbox mesajından fan-out ile oluşan teslimler de işaretlenir; fan-out outbox satırını `FOR SHARE` ile okuduğundan silme transaction'ıyla sıralanır ve yarışta kaçak kalmaz.
  - Karartılmış teslim yeniden gönderilemez (`404`).
  - Testler: `aud_05_k58_erasure_scrubs_the_outbox_and_redacts_the_webhook_history`, `aud_05_k58_deliveries_that_die_after_the_erasure_are_redacted`. Üçü de kaynak değişikliği olmadan başarısız oluyordu.
  - Yaşayan kullanıcıların teslim geçmişi değişmez (alıcı operatörleri ve elle yeniden teslim için gerekli). Kalan: olayın `data` alanında **başka** bir kullanıcının kimliği (ör. davet eden) varsa, o kullanıcı silindiğinde bu alan saklama süresi dolana dek (varsayılan 7/30 gün) kalır. Bunun için yükte serbest metin araması gerekir, bu da her silmede tüm tablo taraması demektir. Üreticiler olayın öznesini `user_id` ile vermelidir.

## Testler

- Birim: kanonik JSON (proptest sabit nokta), zincir hash'i, temizleme kuralları (gömülü kimlikler, bitişik sır adları, user-agent sahteleme karakterleri), URL kuralları, geri çekilme/jitter, imzalı istek, sorgu doğrulama.
- Entegrasyon (`#[sqlx::test]`): `tests/audit_chain.rs` (AUD-01/02/03/05), `tests/audit_api.rs` (AUD-04), `tests/outbox.rs` (AUD-06), `tests/webhooks.rs` (AUD-07).
- Fuzz: `fuzz/fuzz_targets/webhook_signature.rs` — kanonik gövde sabit noktası, imza başlıklarının her sırla doğrulanması, değiştirilmiş gövde/kimlik/sırla reddedilmesi, `.` içeren kimliklerin reddi.

## Komutlar

```bash
cargo test -p authn-audit --all-features
cargo clippy -p authn-audit --all-targets --all-features -- -D warnings
cargo fmt -p authn-audit
cargo +nightly fuzz run webhook_signature -- -max_total_time=60
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
