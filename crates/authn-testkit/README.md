# authn-testkit

Tüm crate'lerin `dev-dependency` olarak kullandığı test altyapısı.

## Sahip olunan gereksinimler

TST-01 (altyapı), TST-08

## İçerik

| Öğe | Açıklama |
|-----|----------|
| `MIGRATOR` | `#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]` için tüm migration'lar |
| `FakeClock` | `advance()` / `set()` ile kontrol edilen saat |
| `TestPorts` | Her port için bir sahte uygulama, ortak `FakeClock` ile |
| `fakes::*` | `RecordingAuditSink` (`pseudonymized()` ile `pseudonymize_subject` çağrıları), `RecordingEventPublisher`, `RecordingNotifier` (e-posta: `recorded`/`with_template`/`take`; SMS: `notify_sms_in_tx` → `recorded_sms`/`sms_with_template`/`last_sms`/`take_sms`, `set_sms_available(false)` ile `sms_unavailable`), `RecordingEmailTransport`, `RecordingSmsSender`, `AllowAllRateLimiter`, `DenyAllRateLimiter`, `InMemoryRateLimiter`, `FakeCaptcha`, `FakeRiskEvaluator`, `FakeBreachedPasswordChecker`, `FakePasswordValidator`, `RecordingSessionRevoker`, `FakeSessionIssuer`, `FakeDnsTxtResolver`, `FakeGeoIp`, `FakeHttpClient`, `StaticDataExporter` |
| `config::test_config()`, `TestConfigBuilder` | Geçerli, deterministik `AppConfig` (herkesçe bilinen test anahtarları; yalnızca testlerde) |
| `http::TestRequest` / `TestResponse` | İstek oluşturma, `tower::ServiceExt::oneshot` ile gönderme, hata zarfını ayrıştırma (`assert_error`) |
| `http::with_request_context` | Router'ı `RequestContext` middleware'i ile sarar |
| `timing::compare_timings` | Hesap varlığı sızıntısı testleri için istatistiksel zamanlama karşılaştırması |
| `bench::{Stats, bench_sync, bench_async, BenchMode}` | K-70 performans ölçümü: gecikme örnekleri → ortalama / p50 / p95 / p99; `harness = false` bench hedeflerinin bağımlılıksız ölçüm döngüsü (`cargo bench` ölçer, `cargo test --benches` her durumu iki kez çalıştıran duman testidir) |
| `bench::count_queries` | Bir future'ın kendi görevinde çalıştırdığı SQL ifadelerini sayar (sqlx'in `sqlx::query` tracing olayları); uç başına sorgu bütçesi testleri için gürültüsüz, yapısal gerileme kontrolü |

## Örnek

```rust
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn pwd_07_reset_request_does_not_leak_account_existence(pool: sqlx::PgPool) {
    let ports = authn_testkit::TestPorts::new();
    let app = authn_testkit::http::with_request_context(/* router().with_state(state) */);
    let res = authn_testkit::http::TestRequest::post("/v1/password/reset")
        .json(&serde_json::json!({"email": "yok@example.com"}))
        .send(&app)
        .await;
    res.assert_status(http::StatusCode::ACCEPTED);
}
```

Testler gerçek PostgreSQL kullanır (`DATABASE_URL`, varsayılanı `.cargo/config.toml`; `authn` veritabanı mevcut olmalıdır — `docker compose up -d` bunu oluşturur).
