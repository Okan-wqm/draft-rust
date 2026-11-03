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
| `create-admin --email` | Uygulandı (ADM-05): etkin, doğrulanmış, break-glass platform admini; 256 bit rastgele şifre **bir kez** yazdırılır; `admin.action` audit olayı (`priority=high`) |
| `rotate-signing-key [--emergency]` | Uygulandı (CRY-10, ADM-06): bekleyen anahtar (`pending_period` sonra etkin) ya da acil durumda etkin anahtarı iptal edip yenisini hemen etkinleştirme |
| `rotate-kek` (`reencrypt`) | Uygulandı (CRY-08): imza anahtarları, webhook sırları, MFA sırları, refresh tolerans ardılları ve outbox mühürlü yükleri güncel KEK ile yeniden sarılır (karşılaştır-ve-yaz; tekrar çalıştırmak güvenli) |
| `verify-audit-chain` | Uygulandı (AUD-02): zincir bozuksa çıkış kodu 1 |
| `migrate-legacy-hashes --input` | Uygulandı (CRY-04): `user_id,md5|sha1,hex` satırları Argon2id ile sarılır; hatalı satır yalnızca numarasıyla raporlanır (içerik yankılanmaz) |

## Servis inşası ve kancalar (contracts §15)

`src/services.rs` her modül servisini bağımlılık sırasıyla kurar: kripto, rate limiter, SSRF-güvenli HTTP istemcisi, bildirimler → audit sink + domain olayları → `MfaService` → `PgSessionRevoker` → `AccountService` (düz revoker) → `AccountAwareSessionRevoker` (diğer tüm modüllere) → password, passkey, organizasyon, audit (RBAC politikası) → giriş koruması, risk → `SessionService`. `SessionIssuer` portu `SessionService`'tir.

`src/hooks.rs` §15.1 kanca trait'lerini uygular: `LoginMethodInventory`, `ProfileLookup`, `OrganizationOwnership`, `MfaPolicySource`, `AccountMethodsSource`, `PasskeyPolicySource`, `AuditAccessPolicy`. MFA ↔ passkey döngüsü "geç bağlanan" hücrelerle (`Late<T>`) kırılır; bağlanmadan çağrılırsa (yalnızca açılışta mümkün) iç hata döner, tahmin yapılmaz.

## Middleware sırası (OPS-02)

Dıştan içe: request context (istek kimliği, IP, dil, hata zarfı) → tracing → panik yakalama → zaman aşımı → eşzamanlılık sınırı → gövde sınırı → host doğrulama → güvenlik başlıkları → CORS → IP başına rate limit → `authn_session::authenticate` (çerez/bearer/API anahtarı + CSRF + salt-okunur impersonation) → handler. `authn_org::api_key_middleware` **kurulmaz** (ikisi birlikte istekleri bozar). Bkz. `src/app.rs`.

## Arka plan işleri (OPS-06)

`src/jobs.rs`: outbox teslimi (webhook, domain olayları, `notification` köprüsüyle bildirimler), dakikalık temizlik (oturum/challenge, doğrulanmamış hesaplar, hesap/organizasyon silme, kilitler, rezervasyonlar, davetler, MFA, passkey seremonileri, yumuşak kilitler, Postgres rate limit kovaları, PoW CAPTCHA, tek kullanımlık token'lar, imza anahtarı kontrolü), saatlik imza anahtarı rotasyonu, günlük audit saklama/kontrol noktası. Hepsi çoklu instance'ta güvenli (`SKIP LOCKED` / advisory lock / idempotent silme). Açılışta `rotate_if_due` ilk token'dan **önce** çalışır; kapanışta işler durdurulur ve password/account/session arka plan işleri boşaltılır (OPS-07).

## Docker

`Dockerfile`: çok aşamalı; derleme `rust:1.97-bookworm`, çalışma imajı `gcr.io/distroless/cc-debian12:nonroot` (kabuk ve paket yöneticisi yok, root olmayan kullanıcı). **Not:** bu depo geliştirilirken ortamda Docker daemon yoktu; imaj derlenip çalıştırılarak doğrulanmadı.

## Testler

| Dosya | Kapsam |
|-------|--------|
| `tests/http_stack.rs` | Sağlık uçları, hata zarfı, gövde sınırı, birleşik OpenAPI (her modülün yolları; belgelenen her yolun gerçekten yönlendirilmesi), Host zehirlenmesi, güvenlik başlıkları, diğer modüllerin uçlarında CSRF, sahte JWT'ler, tek kullanımlık token'ın eşzamanlı tüketimi (TST-02) |
| `tests/e2e.rs` | TST-06 senaryoları: kayıt → doğrulama → giriş → TOTP kaydı → çıkış → TOTP ile giriş → kurtarma kodu; şifre sıfırlamanın tüm oturumları düşürmesi; native refresh rotasyonu ve yeniden kullanım tespiti; organizasyon → davet → kabul → RBAC → kiracılar arası erişim → politika (MFA zorunlu) → API anahtarı |

## Modül router deseni (ARC-03)

Referans: `src/routes/example.rs` (`GET /v1/time`). Modül crate'i `pub fn router<S>() -> Router<S>` sağlar ve servisini `FromRef<S>` ile ister; bu crate `impl FromRef<AppState> for ModülServisi` ekler ve `build_router` içinde `.merge(modül::router::<AppState>())` yapar.

## Çalıştırma

```bash
docker compose up -d
cargo run -p authn-server -- --config config/example.toml migrate
cargo run -p authn-server -- --config config/example.toml serve
curl localhost:8080/health/ready
```
