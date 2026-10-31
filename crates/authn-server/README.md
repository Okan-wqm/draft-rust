# authn-server

`rust-authentication` binary'si: konfigürasyon yükleme, izleme (JSON log), `AppState`, router ve middleware yığını, sağlık kontrolleri, CLI alt komutları, zarif kapanış.

## Sahip olunan gereksinimler

ARC-03, ARC-09, ARC-11, PRT-11, OPS-01 … OPS-09, TST-02, TST-06, DOC-01, DOC-04, DOC-06

## Alt komutlar (OPS-01)

| Komut | Durum |
|-------|-------|
| `serve` | Uygulandı (migration durumu güncel değilse başlamaz; `database.migrate_on_start` ile otomatik) |
| `migrate` | Uygulandı |
| `check-config` | Uygulandı |
| `create-admin`, `rotate-signing-key`, `rotate-kek` (`reencrypt`), `verify-audit-chain`, `migrate-legacy-hashes` | Tanımlı; ilgili modüller bağlanana kadar açık bir "henüz uygulanmadı" hatası ve çıkış kodu 2 döner (panik yok) |

## Middleware sırası (OPS-02)

Dıştan içe: request context (istek kimliği, IP, dil, hata zarfı) → tracing → panik yakalama → zaman aşımı → eşzamanlılık sınırı → gövde sınırı → *(authn-protect: host doğrulama → güvenlik başlıkları → CORS → rate limit)* → *(authn-session: kimlik doğrulama → CSRF)* → handler. Bkz. `src/app.rs`.

## Modül router deseni (ARC-03)

Referans: `src/routes/example.rs` (`GET /v1/time`). Modül crate'i `pub fn router<S>() -> Router<S>` sağlar ve servisini `FromRef<S>` ile ister; bu crate `impl FromRef<AppState> for ModülServisi` ekler ve `build_router` içinde `.merge(modül::router::<AppState>())` yapar.

## Çalıştırma

```bash
docker compose up -d
cargo run -p authn-server -- --config config/example.toml migrate
cargo run -p authn-server -- --config config/example.toml serve
curl localhost:8080/health/ready
```
