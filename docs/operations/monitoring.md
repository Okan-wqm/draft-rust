# İzleme ve alarm önerileri (DOC-06)

## 1. Kaynaklar

| Kaynak | Nerede | Not |
|--------|--------|-----|
| **Prometheus metrikleri** | `server.metrics_bind_addr` (varsayılan `127.0.0.1:9090`), ayrı dinleyici (`metrics-exporter-prometheus`) | Yalnızca iç ağdan kazıyın; konteynerde bkz. [deployment.md §5](deployment.md#5-ağ-ve-vekil) |
| **Yapılandırılmış loglar** | stdout, JSON satırları (`server.log_format = "json"`, varsayılan) | Her HTTP isteği `request_id` (UUIDv7, yanıttaki `x-request-id` ile aynı), `method`, `path` (sorgu dizesi **yok** — OAuth kodları loglanmaz) taşıyan bir span içinde loglanır. Filtre `server.log_filter` / `RUST_LOG`. Sırlar loglanmaz; e-posta/IP maskelenir |
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
| `authn_admin_actions_total` | `action` | Admin işlemleri |
| `authn_admin_denied_total` | `reason` | Reddedilen admin istekleri |
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

`level = ERROR` veya `WARN` satırları arasında izlenmeye değer olanlar: `signing key rotation failed`, `audit maintenance failed`, `provider token revocation run failed`, `password reset backlog full`, `HTTP rate limiter unavailable; failing open`, `database.maintenance_url is not set` (açılışta), `no active JWT signing key`, `grace period elapsed; aborting in-flight requests`.
