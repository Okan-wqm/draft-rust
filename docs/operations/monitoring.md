# İzleme ve alarm önerileri (DOC-06)

## 1. Kaynaklar

| Kaynak | Nerede | Not |
|--------|--------|-----|
| **Prometheus metrikleri** | `server.metrics_bind_addr` (varsayılan `127.0.0.1:9090`; Docker imajında `0.0.0.0:9090`; `"off"` kapatır, K-109), ayrı ve kimlik doğrulamasız dinleyici (`metrics-exporter-prometheus`) | Yalnızca iç ağdan kazıyın, internete asla açmayın; konteynerde bkz. [deployment.md §5](deployment.md#5-ağ-ve-vekil) |
| **Yapılandırılmış loglar** | stdout, JSON satırları (`server.log_format = "json"`, varsayılan) | Her HTTP isteği `request_id` (UUIDv7, yanıttaki `x-request-id` ile aynı), `http.request.method`, `http.route` (eşleşen rota **şablonu**, ör. `/v1/orgs/{org_id}/members`; eşleşmeyenler `unmatched` — ham yol ve sorgu dizesi **yok**: OAuth kodları ve yola yazılmış kişisel veri loglanmaz), `http.response.status_code` ve OpenTelemetry açıkken `trace_id` taşıyan `http` span'i içinde loglanır (K-92 öncesi alan adları `method`/`path` idi). Filtre `server.log_filter` / `RUST_LOG`. Sırlar loglanmaz; e-posta/IP maskelenir |
| **Dağıtık izleme (opsiyonel)** | OTLP/HTTP toplayıcı (`[telemetry]`, cargo özelliği `otel`; varsayılan kapalı) | §5; span'lerde kişisel veri/sır yok (OPS-12) |
| **Sağlık** | `GET /health/live`, `GET /health/ready` | [deployment.md §4](deployment.md#4-sağlık-uçları) |
| **Audit log** | PostgreSQL `audit_events`; admin API `GET /v1/admin/audit-events` | Güvenlik olaylarının kalıcı kaydı; SIEM'e aktarım için `POST /v1/admin/audit-events/export` |

> **HTTP metrikleri:** `authn_http_request_duration_seconds` histogramı (OPS-04; `crates/authn-server/src/metrics.rs`) her isteğin süresini `method`, `route` (eşleşen rota **şablonu**, ör. `/v1/orgs/{org_id}/members`; eşleşmeyenler `unmatched`) ve `status` (`1xx`…`5xx`) etiketleriyle kaydeder; kovalar 1 ms – 10 sn. İstek sayısı ve hata oranı bu histogramın `_count`'undan türetilir. Veritabanı havuzu doluluğu metrik olarak yayınlanmaz (havuz zaman aşımı `503 service_unavailable` ve log olarak görünür).

## 2. Yayınlanan metrikler

Histogram ve `authn_outbox_queue_depth` (gauge) dışındakiler sayaçtır (`_total`). Etiket değerleri sabit kümelerdendir (kullanıcı verisi içermez).

| Metrik | Etiketler | Anlam |
|--------|-----------|-------|
| `authn_http_request_duration_seconds` (histogram) | `method`, `route`, `status` | İstek süresi; `_count` istek sayısı |
| `authn_logins_total` | `outcome` | Giriş sonuçları |
| `authn_login_failures_total` | `method`, `reason` | Başarısız girişler |
| `authn_login_factor_total` | `factor`, `outcome` | Giriş challenge'ında ikinci faktör doğrulamaları |
| `authn_sessions_created_total` | `client` (`web`/`native`) | Kurulan oturumlar |
| `authn_sessions_revoked_total` | `reason` | İptaller (`RevocationReason`: `logout`, `user_request`, `password_changed`, `password_reset`, `email_change_reverted`, `not_me`, `mfa_changed`, `refresh_token_reuse`, `account_suspended`, `account_deleted`, `membership_removed`, `membership_changed`, `org_policy_changed`, `admin_action`, `emergency`, `concurrent_limit`, `expired`, `impersonation_ended`) |
| `authn_token_refresh_total` | `outcome` | Refresh sonuçları (`grace` dahil) |
| `authn_refresh_token_reuse_total` | — | **Refresh token yeniden kullanımı → aile iptali** (çalınma göstergesi) |
| `authn_bearer_rejected_total` | `reason` | Reddedilen access token'lar |
| `authn_csrf_rejected_total` | — | CSRF reddi |
| `authn_step_up_total` | `method`, `outcome` | Step-up |
| `authn_introspection_total` | `result` (`active`/`inactive`) | Introspection |
| `authn_signing_keys_invalidated_total` | `cause` | İmza anahtarı önbelleği boşaltmaları (LISTEN/NOTIFY) |
| `authn_break_glass_logins_total` | — | Break-glass hesabıyla giriş |
| `authn_rate_limit_triggered_total` | `action` (`http`, `login`) | Genel IP sınırı ve giriş IP sınırı redleri |
| `authn_soft_lock_engaged_total` | — | Hesap yumuşak kilitlendi |
| `authn_password_breach_checks_total` | `source`, `result` | HIBP / çevrimdışı liste kontrolleri |
| `authn_password_breach_check_unavailable_total` | `mode` | HIBP erişilemedi (`fail_open`'a göre) |
| `authn_password_reset_requests_total` / `_dropped_total` | — | Sıfırlama istekleri / kuyruk dolu diye düşenler |
| `authn_password_resets_completed_total` | `method` | Tamamlanan sıfırlamalar |
| `authn_password_updates_total` | `kind` | Şifre değişiklikleri (`rehashed` dahil) |
| `authn_account_registrations_total` | `outcome` | Kayıt istekleri (`created`, `existing`, `additional_registration`, `provisioned`) |
| `authn_account_registrations_completed_total` | `method` | Tamamlanan kayıtlar |
| `authn_account_email_verifications_total` | — | Doğrulanan adresler |
| `authn_account_deletions_total` | `reason` | Tamamlanan silmeler |
| `authn_account_data_exports_total` | — | Veri dışa aktarımları |
| `authn_mfa_verifications_total` | `factor`, `outcome` | MFA doğrulamaları |
| `authn_mfa_codes_sent_total` | `channel`, `purpose` | E-posta/SMS kodları |
| `authn_mfa_enrollments_total` / `authn_mfa_removals_total` | `factor` | Faktör kaydı / kaldırma |
| `authn_mfa_sms_blocked_total` | `limit` | SMS sınırlarına takılanlar (pompalama) |
| `authn_passkey_ceremonies_started_total` | `kind` | Passkey seremonileri |
| `authn_passkey_registrations_total` | `outcome` | Passkey kayıtları |
| `authn_passkey_authentications_total` | `purpose`, `outcome` | Passkey doğrulamaları |
| `authn_passkey_clone_suspected_total` | `reason` | Klon şüphesi |
| `authn_passkey_removed_total` | — | Kaldırılan passkey'ler |
| `authn_social_logins_total` | `provider`, `outcome` | Sosyal girişler |
| `authn_social_accounts_created_total` | `provider` | Sosyal girişle açılan hesaplar |
| `authn_social_jwks_failures_total` | `outcome` | Sağlayıcı JWKS indirme hataları |
| `authn_social_token_revocations_total` | `provider`, `outcome` | Apple token iptalleri (`abandoned` dahil) |
| `authn_org_created_total`, `authn_api_keys_created_total` | — | Organizasyon / API anahtarı oluşturma |
| `authn_api_key_auth_total` | `result` | API anahtarıyla kimlik doğrulama |
| `authn_org_domain_checks_total` | `result` | DNS TXT kontrolleri |
| `authn_org_domain_reverifications_total` | `outcome` (`present`, `absent`, `inconclusive`) | Periyodik domain yeniden doğrulama kontrolleri (ORG-13). `inconclusive` oranı yükselirse çözücüyü kontrol edin |
| `authn_org_domains_unverified_total` | `reason` (`absent`, `inconclusive`) | Doğrulaması kalkan domain'ler (ORG-13); `reason="inconclusive"` artışına alarm kurun (çözücü arızası tüm domain'leri düşürebilir) |
| `authn_admin_actions_total` | `action` | Admin işlemleri |
| `authn_admin_denied_total` | `reason` | Reddedilen admin istekleri (`permission_denied`: personel rolü izni taşımıyor, K-93; tekrarlayan artış yetki yükseltme denemesi olabilir) |
| `authn_admin_throttled_total` | `limit` | Admin limitlerine takılma |
| `authn_admin_break_glass_used_total` | — | Break-glass kullanımı |
| `authn_admin_four_eyes_bypassed_total` | `exception` | Dört göz istisnası (tek admin / break-glass) |
| `authn_admin_four_eyes_refused_total` | `reason` | Onaysız reddedilen kritik işlemler |
| `authn_audit_events_total` | `kind`, `outcome` | Yazılan audit olayları |
| `authn_outbox_messages_total` | `prefix`, `outcome` (`delivered`/`retried`/`dead`/`lost_lease`) | Outbox işlemleri |
| `authn_outbox_queue_depth` (gauge) | `status` (`pending`/`processing`/`dead`) | Outbox kuyruk derinliği |
| `authn_notifications_enqueued_total` | `channel` | Kuyruğa giren e-posta/SMS |
| `authn_notifications_delivered_total` | `channel` | Teslim edilen |
| `authn_notification_failures_total` | `channel`, `class` (`retry`/`permanent`) | Teslim hataları |
| `authn_notifications_dropped_total` | `channel`, `reason` (`recipient_limit`) | Alıcı bütçesi nedeniyle sessizce düşenler |

## 3. Önerilen alarmlar

Eşikler başlangıç önerisidir; trafiğinize göre ayarlayın (PromQL).

| Öncelik | Alarm | İfade (örnek) | Neden / runbook |
|---------|-------|---------------|-----------------|
| **P1** | Break-glass kullanıldı | `increase(authn_break_glass_logins_total[5m]) > 0 or increase(authn_admin_break_glass_used_total[5m]) > 0` | Her kullanım planlı olmalı; [admin-recovery.md §9](admin-recovery.md#9-alarmlar) |
| **P1** | Hazır değil | yük dengeleyicide `/health/ready` ≠ 200 (2 dk) | Veritabanı veya şema ([deployment.md](deployment.md)) |
| **P2** | 5xx oranı / gecikme | `sum(rate(authn_http_request_duration_seconds_count{status="5xx"}[5m])) / sum(rate(authn_http_request_duration_seconds_count[5m])) > 0.01`; `histogram_quantile(0.99, sum by (le, route) (rate(authn_http_request_duration_seconds_bucket[5m]))) > 0.25` (giriş uçları hariç; bütçeler [performance.md](performance.md#gecikme-bütçeleri)) | Veritabanı, havuz veya bağımlılık sorunu |
| **P1** | Audit zinciri | zamanlanmış `verify-audit-chain` çıkış kodu ≠ 0 veya log `audit retention purge refused` | [incident-response.md §5](incident-response.md#5-audit-kurcalama-tespiti) |
| **P2** | Dış audit çıpası yok (K-107) | log hattında son `audit chain scheduled checkpoint` satırı `audit.checkpoint_interval` + 2 saatten eski, veya log `audit chain checkpoint failed` | Bakım rolü (`database.maintenance_url`) eksik ya da yetkisiz; çıpa üretilmezse kesme/geri sarma tespit edilemez ([key-management.md §5](key-management.md#5-audit-zinciri-anahtarı-k-77)) |
| **P2** | Silme defteri dışa aktarılmıyor (K-108) | zamanlanmış `export-erasures` işinin çıkış kodu ≠ 0 veya son başarılı çalışma 2 saatten eski | Geri yüklemeden sonra silmeler yeniden uygulanamaz ([backup.md §5](backup.md#5-geri-yükleme-sonrası-güvenlik-etkileri)) |
| **P2** | Refresh token yeniden kullanımı | `increase(authn_refresh_token_reuse_total[15m]) > 5` | Token hırsızlığı veya hatalı istemci (eşzamanlı yenileme); [native.md §3](../integration/native.md#3-refresh-token-rotasyonu) |
| **P2** | Outbox birikiyor | `authn_outbox_queue_depth{status="pending"} > 1000` (10 dk) veya `increase(authn_outbox_messages_total{outcome="dead"}[1h]) > 0` | E-posta/SMS/webhook teslimi durdu: SMTP, sağlayıcı |
| **P2** | Bildirim hataları | `rate(authn_notification_failures_total{class="permanent"}[15m]) > 0` | Doğrulama/sıfırlama e-postaları gitmiyor |
| **P2** | Admin baskısı | `increase(authn_admin_throttled_total[15m]) > 0 or increase(authn_admin_four_eyes_refused_total[15m]) > 3` | Ele geçirilmiş admin şüphesi ([admin-recovery.md](admin-recovery.md)) |
| **P2** | Klonlanmış passkey | `increase(authn_passkey_clone_suspected_total[1h]) > 0` | Kullanıcıyı inceleyin |
| **P2** | SMS pompalama | `increase(authn_mfa_sms_blocked_total{limit="global"}[1h]) > 0` (diğer değerler: `country`, `cooldown`, `per_user`, `per_number`, `per_ip`) | Küresel SMS bütçesi doldu |
| **P3** | Kimlik bilgisi doldurma | `rate(authn_rate_limit_triggered_total{action="login"}[5m])` veya `rate(authn_soft_lock_engaged_total[15m])` olağandışı | CAPTCHA'yı sıkılaştırın |
| **P3** | CSRF redleri | `rate(authn_csrf_rejected_total[15m])` ani artış | Saldırı ya da ön yüz hatası (eski CSRF token'ı) |
| **P3** | HIBP erişilemiyor | `increase(authn_password_breach_check_unavailable_total[15m]) > 10` | `fail_open = true` iken sızmış şifre kontrolü atlanıyor |
| **P3** | Sosyal sağlayıcı JWKS | `increase(authn_social_jwks_failures_total[15m]) > 0` | Sağlayıcı kesintisi; `oidc_client.jwks_max_staleness` sonrası girişler `503` |
| **P3** | Apple token iptali bırakıldı | `increase(authn_social_token_revocations_total{outcome="abandoned"}[1d]) > 0` | App Store hesap silme şartı |
| **P3** | Notification drop | `increase(authn_notifications_dropped_total[1h])` olağandışı | Bir adrese yönelik mesaj bombardımanı denemesi |

Diğer `reason`/`outcome` değerlerini ilk haftalarda gözlemleyip eşikleri kesinleştirin; kesin değer kümeleri ilgili crate'lerin `metrics.rs` dosyalarındadır.

## 4. Log uyarıları

`level = ERROR` veya `WARN` satırları arasında izlenmeye değer olanlar: `signing key rotation failed`, `audit maintenance failed`, `audit chain checkpoint failed`, `database schema is ahead of this binary` (WARN, kademeli dağıtım sırasında beklenir; sürerse eski örnek değiştirilmemiş demektir), `provider token revocation run failed`, `password reset backlog full`, `HTTP rate limiter unavailable; failing open`, `database.maintenance_url is not set` (açılışta), `no active JWT signing key`, `grace period elapsed; aborting in-flight requests`.

## 5. OpenTelemetry izleme (OPS-11, K-92)

Varsayılan **kapalı**. Açmak için binary'yi `otel` özelliğiyle derleyin (`cargo build --release -p authn-server --features otel`; Dockerfile'da `--features` ekleyin) ve `[telemetry]`'yi ayarlayın ([configuration.md §16](configuration.md#16-telemetry--configtelemetryrs-sahip-authn-server)):

```toml
[telemetry]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"   # OTLP/HTTP; yan konteynerdeki OpenTelemetry Collector
sampling_ratio = 0.1
```

Toplayıcı bir API anahtarı istiyorsa onu yapılandırma dosyasına değil ortam değişkenine koyun: `OTEL_EXPORTER_OTLP_TRACES_HEADERS="x-api-key=..."` (standart OTLP değişkeni; `OTEL_EXPORTER_OTLP_HEADERS` da okunur). Ağ üzerinden giden izler için `https` kullanın ya da toplayıcıyı aynı pod/ana makinede çalıştırın.

**Ne dışa aktarılır.** Her HTTP isteği için tek bir `SERVER` span'i: ad `"POST /v1/login/password"` biçiminde (yöntem + rota şablonu), öznitelikler `request_id`, `http.request.method`, `http.route`, `http.response.status_code`, `trace_id`; 5xx'te durum `error`. Kaynak özniteliği `service.name` (`telemetry.service_name`). Log satırları span'e **aktarılmaz**; log ve iz `request_id` / `trace_id` ile birleştirilir.

**Ne asla dışa aktarılmaz (OPS-12).** E-posta, şifre, token, cookie/CSRF değeri, kullanıcı kimliği, ham yol, sorgu dizesi, istek/yanıt gövdesi, başlıklar ve **istemci IP'si** (kısaltılmış biçimi dahil). IP kararı: iz arka uçları çoğunlukla logdan daha geniş erişimli ve üçüncü taraf hizmetlerdir; IP'ye ihtiyaç duyulursa `request_id` ile maskeli IP içeren log satırına gidilir. Bunu `crates/authn-server/tests/telemetry.rs` kayıt, giriş, refresh ve şifre sıfırlama akışlarıyla zorlar (öznitelik anahtarları bir izin listesiyle sınırlı; yeni bir öznitelik bilinçli olarak eklenmeli).

**W3C Trace Context.** `traceparent` sürdürülür (`propagate_incoming`); çağıranın `tracestate`'i atılır. Çağıranın "sampled" bayrağı varsayılan olarak yok sayılır (`respect_remote_sampling = false`) — aksi hâlde internetteki herhangi bir istemci her isteğini dışa aktarıcıya sokabilir. Uzak üst span'li izler bu durumda bağımsız bir CSPRNG çekilişiyle `sampling_ratio` oranında örneklenir (çağıran trace kimliğini de seçtiği için trace kimliğine dayalı örnekleme kandırılabilirdi). `respect_remote_sampling = true` yalnızca `traceparent`'i kendisi üreten/temizleyen güvenilir bir ağ geçidinin arkasında açılmalıdır.

**Toplayıcı kesintisi.** Dışa aktarma ayrı bir iş parçacığında, sınırlı kuyrukla (`max_queue_size`, dolunca yeni span'ler atılır) ve `export_timeout` ile yapılır: toplayıcı kapalı ya da yanıtsızsa istekler beklemez ve başarısız olmaz, yalnızca izler kaybolur. Kapanışta kuyruk en fazla `export_timeout + 1 sn` boşaltılmaya çalışılır. Kayıp izler için ayrı bir metrik yoktur; toplayıcının kendi alım metriklerini (`otelcol_receiver_accepted_spans`) izleyin ve beklenen hızın altına düşerse uyarın (P3).
