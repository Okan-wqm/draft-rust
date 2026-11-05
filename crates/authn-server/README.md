# authn-server

`rust-authentication` binary'si: konfigürasyon yükleme, izleme (JSON log), `AppState`, router ve middleware yığını, sağlık kontrolleri, CLI alt komutları, zarif kapanış.

## Sahip olunan gereksinimler

ARC-03, ARC-09, ARC-11, PRT-11, OPS-01 … OPS-09, TST-02, TST-06, DOC-01, DOC-04, DOC-06

## Alt komutlar (OPS-01)

| Komut | Durum |
|-------|-------|
| `serve` | Uygulandı (migration durumu güncel değilse başlamaz; `database.migrate_on_start` ile otomatik) |
| `migrate` | Uygulandı |
| `check-config` | Uygulandı (ARC-07): yapılandırma + şablonlar + `serve`'ün yalnızca router/servis kurarken doğruladığı her ayar (host doğrulama, güvenlik başlıkları, CORS, admin konsolu CORS'u, KEK/pepper/HMAC anahtarları, sosyal giriş sağlayıcıları ve şifreli Apple anahtarının açılabilmesi); `serve`'ün reddedeceği bir yapılandırmayı "geçerli" saymaz |
| `create-admin --email [--passkey-link [--ttl 30m]]` | Uygulandı (ADM-05, K-11): `authn_admin::create_break_glass_admin` — etkin, doğrulanmış, break-glass platform admini; 256 bit rastgele şifre **bir kez** yazdırılır. `--passkey-link`: şifresiz hesap + tek kullanımlık passkey kayıt bağlantısı `{server.public_base_url}/admin/enroll#<token>` (token URL **parçasında**, sunucu loglarına gitmez; varsayılan 30 dk, en çok 24 sa). Var olan adres asla sessizce admin yapılmaz (`conflict`). Yüksek öncelikli `admin.action` audit olayı |
| `admin-enrollment-link --target --reason --operator [--ttl]` | Uygulandı (K-07): var olan break-glass hesabı için yeni bağlantı; aynı transaction'da hesabın şifresi, passkey'leri, MFA faktörleri ve oturumları silinir |
| `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions` (`--target <e-posta|id> --reason <gerekçe> --operator <ad>`, üçü de zorunlu) | Uygulandı (K-07): çevrimdışı olay müdahalesi (`AdminService::*_offline`); gerekçe ve operatör audit'lenir (`surface: cli`, `priority: high`); bildirimler outbox'a yazılır, çalışan sunucu teslim eder. `--operator` / `--reason` veritabanına bağlanmadan **önce** doğrulanır; hatalı değer bayrağı adlandıran, değeri yankılamayan bir girdi hatasıdır (çıkış kodu 65) |
| `seal-apple-key --pem-file <yol|->` | Uygulandı (SOC-07, K-34): PKCS#8 P-256 PEM'i (dosya ya da stdin) doğrular ve `[crypto]` KEK'iyle mühürler; çıktı `oidc_client.apple.private_key_ciphertext` değeridir. 16 KiB'tan büyük girdi kesilmez, reddedilir; anahtar olmayan girdi de girdi hatasıdır (çıkış kodu 65). Okuma tamponu bir kez ayrılır ve bırakılırken sıfırlanır; anahtar hiçbir çıktıya / hata mesajına girmez |
| `rotate-signing-key [--emergency]` | Uygulandı (CRY-10, ADM-06): bekleyen anahtar (`pending_period` sonra etkin) ya da acil durumda etkin anahtarı iptal edip yenisini hemen etkinleştirme |
| `rotate-kek` (`reencrypt`) | Uygulandı (CRY-08): imza anahtarları, webhook sırları, MFA sırları, refresh tolerans ardılları, outbox mühürlü yükleri, sağlayıcı token'ları (`identities.access_token_ciphertext` / `refresh_token_ciphertext`), PKCE doğrulayıcıları (`oauth_states`) ve iptal kuyruğu (`oauth_token_revocations`) güncel KEK ile yeniden sarılır (satır başına karşılaştır-ve-yaz, 500 satırlık anahtar-sıralı sayfalar: bellek sınırlı, uzun transaction yok; yarıda kalırsa yeniden çalıştırmak güvenli). Yapılandırmadaki `oidc_client.apple.private_key_ciphertext` eski KEK'le mühürlüyse yeniden sarılmış değer yazdırılır (eski KEK kaldırılmadan önce yapılandırmaya konmalı). Şemadaki her `*_ciphertext` kolonunun kapsandığını bir test zorlar |
| `verify-audit-chain` | Uygulandı (AUD-02): zincir bozuksa çıkış kodu 1 |
| `migrate-legacy-hashes --input` | Uygulandı (CRY-04): `user_id,md5|sha1,hex` satırları Argon2id ile sarılır; hatalı satır yalnızca numarasıyla raporlanır (içerik yankılanmaz) |

## Servis inşası ve kancalar (contracts §15)

`src/services.rs` her modül servisini bağımlılık sırasıyla kurar: kripto, rate limiter, SSRF-güvenli HTTP istemcisi, bildirimler → audit sink + domain olayları → `MfaService` → `PgSessionRevoker` → `AccountService` (düz revoker) → `AccountAwareSessionRevoker` (diğer tüm modüllere) → password, passkey, organizasyon, audit (RBAC politikası) → giriş koruması, risk → `SessionService` → sosyal giriş (`OidcClientService::build`, async; Apple anahtarı açılışta çözülür) + hesap kancaları (silme: Apple token iptali kuyruğu; e-posta değişikliği geri alma: eklenen tüm giriş yöntemleri silinir, K-20) → `AdminService`. `SessionIssuer` portu `SessionService`'tir. Bakım rolü havuzu (OPS-10) `Services::build_with_maintenance_pool` ile ayrıca verilir.

`src/hooks.rs` §15.1 kanca trait'lerini uygular: `LoginMethodInventory` (password ve oidc-client), `ProfileLookup`, `OrganizationOwnership`, `MfaPolicySource`, `AccountMethodsSource`, `PasskeyPolicySource`, `AuditAccessPolicy`, `SessionLiveness`, `SigningKeyCache`, `EmailChangeRevertHook`. Bağlı sosyal kimlik `OidcClientService::linked_identity_count_in` ile `LoginMethod::Social` sayılır; parolasız e-posta girişi üç "son yöntem" kuralının hiçbirinde güçlü yöntem sayılmaz. MFA ↔ passkey ve hesap → geri alma kancası → sosyal giriş → hesap döngüleri "geç bağlanan" hücrelerle (`Late<T>`) kırılır. Hücreler yalnızca **zayıf** referans tutar; güçlü referanslar `Services` içindeki `HookAnchors`'tadır. Böylece son `Services` tutamacı bırakılınca tüm servisler ve veritabanı havuzu serbest kalır. Önceden güçlü referanslar bir döngü oluşturuyordu ve havuz hiç bırakılmıyordu (test `ops_07_dropped_services_release_their_pool`). Kanca, servislerin ömrü dışında çağrılırsa (yalnızca açılış/kapanışta mümkün) iç hata döner, tahmin yapılmaz.

## Middleware sırası (OPS-02)

Dıştan içe: request context (istek kimliği, IP, dil, hata zarfı) → tracing → panik yakalama → zaman aşımı → eşzamanlılık sınırı → gövde sınırı → host doğrulama → güvenlik başlıkları → admin konsolu CORS'u (K-67) → CORS → IP başına rate limit → `authn_session::authenticate` (çerez/bearer/API anahtarı/impersonation başlığı + CSRF + salt-okunur impersonation) → handler. `authn_org::api_key_middleware` **kurulmaz** (ikisi birlikte istekleri bozar). Break-glass kayıt uçları (`/v1/admin/enrollment/*`, K-11) kimlik doğrulama katmanının **dışında** birleştirilir (`session_less_routes`): kimlik bilgisi gövdedeki tek kullanımlık bağlantı token'ıdır; ilgisiz bir oturum çerezi taşıyan tarayıcıda CSRF katmanı onları reddetmemeli. Diğer tüm `/v1/admin` uçları oturum + CSRF arkasında. Bkz. `src/app.rs`.

**Admin konsolu başka origin'den (K-67):** `[server] admin_console_origins` (her biri `protect.cors.allowed_origins`'ta da olmalı; aksi hâlde açılış başarısız). Yalnızca bu origin'lerden gelen ve `x-impersonation-session` isteyen preflight'lar bu başlığa izin alır (`src/cors.rs`); varsayılan boş — başlık hiçbir origin'den siteler arası gönderilemez (aynı origin'deki konsol için gerekmez).

**Veritabanı rolleri (OPS-10, K-42):** `[database] maintenance_url` audit saklama temizliğini ayrı, en az yetkili bakım rolüyle çalıştırır; yetkiler migration `2900`'deki `authn_apply_least_privilege` ile verilir. Runbook: [`docs/operations/least-privilege.md`](../../docs/operations/least-privilege.md).

## Arka plan işleri (OPS-06)

`src/jobs.rs`: outbox teslimi (webhook, domain olayları, `notification` köprüsüyle bildirimler), dakikalık temizlik (oturum/challenge, doğrulanmamış hesaplar, hesap/organizasyon silme, kilitler, rezervasyonlar, davetler, MFA, passkey seremonileri, yumuşak kilitler, Postgres rate limit kovaları, PoW CAPTCHA, tek kullanımlık token'lar, imza anahtarı kontrolü, OAuth state'leri / native nonce'lar), dakikalık sağlayıcı token iptali (K-35, ayrı görev: yavaş sağlayıcı temizlikleri geciktirmez), saatlik imza anahtarı rotasyonu, günlük audit saklama/kontrol noktası (bakım rolü havuzuyla). Hepsi çoklu instance'ta güvenli (`SKIP LOCKED` / advisory lock / idempotent silme). Açılışta `rotate_if_due` ilk token'dan **önce** çalışır; kapanışta işler durdurulur ve password/account/session arka plan işleri boşaltılır (OPS-07).

## Docker

`Dockerfile`: çok aşamalı; derleme `rust:1.97-bookworm`, çalışma imajı `gcr.io/distroless/cc-debian12:nonroot` (kabuk ve paket yöneticisi yok, root olmayan kullanıcı). **Not:** bu depo geliştirilirken ortamda Docker daemon yoktu; imaj derlenip çalıştırılarak doğrulanmadı.

## Testler

| Dosya | Kapsam |
|-------|--------|
| `tests/route_protection.rs` | Denetim (wave 3A): birleşik router'ın **her** durum değiştiren rotası numaralandırılır — geçerli oturum çerezi + CSRF token'ı yok ⇒ `403 csrf_failed`; tek istisna gözden geçirilmiş `SESSION_LESS` listesi (`POST /v1/admin/enrollment/{options,verify}`). `/v1/me*`, `/v1/admin/*` (kayıt hariç), `/v1/orgs*` anonim çağrıya `401`. Kaynakta `.route(` ile tanımlı her `/v1/…` / `/.well-known/…` yolu OpenAPI belgesinde |
| `tests/cli.rs` | Denetim (wave 3A): **gerçek binary** ile `create-admin` (tek seferlik şifre ve kayıt bağlantısı token'ı `RUST_LOG=trace` altında bile çıktıda tam **bir kez**), `--operator` doğrulaması (65, veritabanına dokunmadan), `admin-enrollment-link`, `suspend-admin`, `seal-apple-key` (anahtar olmayan / büyük girdi), `check-config`'in `serve`'ün reddedeceğini reddetmesi |
| `tests/ssrf_rebinding.rs` | Denetim (wave 3A): webhook adı teslimde loopback'e çözülür (DNS rebinding); sunucunun outbox işçisi ve SSRF-güvenli istemcisi bağlanmayı reddeder (çözücü enjekte edilir: ortamda test kontrolünde DNS sunucusu yok) |
| `tests/http_stack.rs` | Sağlık uçları, hata zarfı, gövde sınırı, birleşik OpenAPI (her modülün yolları; belgelenen her yolun gerçekten yönlendirilmesi), Host zehirlenmesi, güvenlik başlıkları, diğer modüllerin uçlarında CSRF, sahte JWT'ler, tek kullanımlık token'ın eşzamanlı tüketimi, webhook URL'siyle SSRF (TST-02) |
| `tests/social_e2e.rs` | K-51/K-52: Google web + native, Apple `form_post` (yabancı Origin ile CSRF katmanından geçer), Microsoft kiracı izin listesi, GitHub, genel OIDC; bağlama/ayırma step-up ile, PWD-11/SOC-06 son yöntem kuralları modüller arası; pre-hijacking (varsayılan ve otomatik bağlama); ACC-07 rezervasyonu; silme → Apple token iptal işi; K-20 bağlanan kimliğin geri almada silinmesi; `return_to` open redirect regresyonları (TST-02); Apple (yetkilendirme kodu değişimiyle), Microsoft (kiracı kuralı) ve genel OIDC **native** girişleri, web istemcisi / yabancı kiracı token'larının native'de reddi |
| `tests/admin_e2e.rs` | K-50/K-52 (`passkey` özelliği): gerçek oturumlarla yetki matrisi (anonim, normal kullanıcı, şifreli oturumlu admin, passkey'li admin, step-up penceresi, CSRF), impersonation (başlık yolu, salt-okunur, admin çerezi korunur, askıya almayla gerçek revoker üzerinden biter), acil "tümünü kapat" çağıranı korur, break-glass kayıt bağlantısı uçtan uca, K-20 geri almada saldırganın passkey/TOTP'sinin silinmesi; yazılabilir web ve native (bearer) impersonation; acil imza anahtarı rotasyonu (eski token anında reddedilir, JWKS'ten çıkar) ve toplu zorunlu şifre değişikliği |
| `tests/console_cors.rs` | K-67 |
| `tests/least_privilege.rs` | OPS-10/K-42: yetkiler tek tek; uygulama en az yetkili rolle (giriş, bakım işleri, çevrimdışı admin işlemi, tam hesap silme), audit bakımı bakım rolüyle çalışır; tablo sahibine / diğer role üye, süper kullanıcı veya `pg_*_all_data` üyesi roller reddedilir; çağıranın `search_path`'ine yerleştirilmiş nesne kullanılmaz |
| `tests/lifecycle.rs` | OPS-07: bırakılan `Services` havuzunu serbest bırakır (kanca döngüsü regresyonu); servisler bırakıldıktan sonra kancalar hata verir (kapalı kalır) |
| `tests/operations.rs` | `rotate-kek` her `*_ciphertext` kolonunu ve Apple anahtarını kapsar, sayfa sınırlarını aşan tablolarda her satırı sarar; `seal-apple-key` |
| `tests/e2e.rs` | TST-06 senaryoları: kayıt → doğrulama → giriş → TOTP kaydı → çıkış → TOTP ile giriş → kurtarma kodu; şifre sıfırlamanın tüm oturumları düşürmesi; native refresh rotasyonu ve yeniden kullanım tespiti; organizasyon → davet → kabul → RBAC → kiracılar arası erişim → politika (MFA zorunlu) → API anahtarı |

## Güvenlik denetimi (wave 3A, 2026-11-05)

Bağımsız denetçi entegrasyon katmanını "yanlış bağlanmış" varsayımıyla inceledi. Doğrulanan her bulgu önce düzeltme olmadan **başarısız olduğu gösterilen** bir regresyon testiyle kanıtlandı, sonra düzeltildi.

| # | Önem | Bulgu | Test | Durum |
|---|------|-------|------|-------|
| 1 | Orta | `authn_apply_least_privilege` yalnızca rol adını tablo sahibiyle karşılaştırıyordu: tablo sahibi rolüne (veya bakım rolüne, `pg_write_all_data`'ya) **üye** olan ya da süper kullanıcı olan bir uygulama rolü yetkileri miras alır (`audit_events` üzerinde `DELETE` dahil), fonksiyon yine de başarı bildiriyordu | `ops_10_roles_inheriting_owner_or_peer_privileges_are_refused` | Düzeltildi: üyelik (`pg_has_role … MEMBER`), süper kullanıcı / `BYPASSRLS`, `pg_read_all_data` / `pg_write_all_data` ve iki rolün birbirine üyeliği reddedilir |
| 2 | Düşük | Aynı fonksiyon `authn_audit_apply_least_privilege`'i ve tabloları çağıranın `search_path`'i üzerinden çözüyordu: önceki bir şemaya yerleştirilmiş aynı adlı fonksiyon şema sahibinin yetkisiyle çalışırdı | `ops_10_least_privilege_helper_ignores_the_callers_search_path` | Düzeltildi: `SET search_path FROM CURRENT`, şema nitelikli adlar, açıkça `SECURITY INVOKER` |
| 3 | Düşük | `check-config`, `serve`'ün açılışta reddettiği yapılandırmayı (ör. açılamayan şifreli Apple anahtarı, host/güvenlik başlığı ayarları) "geçerli" sayıyordu | `arc_07_check_config_refuses_what_serve_would_refuse` | Düzeltildi (`check_startup_settings`) |
| 4 | Düşük | Çevrimdışı admin komutları `--operator`/`--reason`'ı tüm servisleri kurup veritabanına bağlandıktan **sonra** doğruluyordu; hata bayrağı adlandırmayan `validation_failed` ve "hizmet yok" çıkış kodu (69) idi | `adm_05_k11_cli_enrollment_link_token_is_printed_once_in_the_fragment` | Düzeltildi: önce doğrulama, girdi hatası (65) |
| 5 | Düşük | `seal-apple-key` 16 KiB'tan büyük girdiyi sessizce kesiyordu; PEM sıfırlanmayan, yeniden ayrılabilen bir `String`'de tutuluyordu; anahtar olmayan girdi `internal_error` / 69 idi | `soc_07_cli_seal_apple_key_refuses_non_keys_without_echo` | Düzeltildi: `Zeroizing`, tek ayırma, büyük girdi ve anahtar olmayan girdi = 65 |
| 6 | Sağlamlaştırma | `rotate-kek` her tabloyu tek seferde belleğe okuyordu (`outbox` büyük olabilir) | `cry_08_rotate_kek_rewraps_every_row_across_pages` | Anahtar-sıralı 500 satırlık sayfalar |
| 7 | Sağlamlaştırma | E-posta geri alma kancası geç bağlanan sosyal giriş servisini, passkey/MFA silindikten **sonra** çözüyordu (hata olsa da transaction geri alınıyordu) | `ops_07_late_hooks_fail_closed_outside_the_services_lifetime` | Önce çözülür; hata hiçbir şeye dokunmadan döner |

Doğrulanan ve bulgu çıkmayan alanlar (kalıcı testlerle): her durum değiştiren rota kimlik doğrulama + CSRF arkasında, oturumsuz rotalar tam olarak iki kayıt ucu (`tests/route_protection.rs`; bir modül router'ını dışarı taşımak testi düşürür); `Late<T>` yükseltmesi başarısız olursa her güvenlik kancası hata döner, tüketiciler `?` ile iletir (yalnızca `ProfileLookup` varsayılan ipuçlarına düşer: güvenlik kontrolü değil); K-20 kancası oturumlar kapatıldıktan sonra aynı transaction'da çalışır, tek geri alma yolu vardır; K-67 CORS joker/`null`/benzer origin kabul etmez; outbox webhook teslimi sunucu bağlantısıyla DNS rebinding'e karşı kapalıdır; Apple/Microsoft/genel native, yazılabilir ve native impersonation, acil anahtar rotasyonu ve zorunlu şifre değişikliği uçtan uca.

Kabul edilen / kapsam dışı:

- `ServerAccountMethods::mfa_facts` (wave 2 kodu) `MfaService::policy_input`'u **havuzdan** okur (sözleşme §4: kancalar yalnızca verilen bağlantıdan okumalı). Sonuç: aynı kullanıcının eşzamanlı "son TOTP'yi sil" + "son passkey'i sil" istekleri (ikisi de step-up ister) MFA zorunlu bir hesabı faktörsüz bırakabilir; bir sonraki girişte MFA kaydı zorlanır. authn-mfa'nın `policy_input_in`'i `pub(super)`; düzeltme authn-mfa'ya bağlantı alan herkese açık bir varyant gerektirir (sahibi: authn-mfa, bu dalgada denetlenmiyor).
- DNS rebinding testi gerçek bir DNS sunucusu yerine enjekte edilmiş çözücü kullanır (ortamda test kontrolünde DNS yok); çözümleme sonrası kod yolu aynıdır.

## Modül router deseni (ARC-03)

Referans: `src/routes/example.rs` (`GET /v1/time`). Modül crate'i `pub fn router<S>() -> Router<S>` sağlar ve servisini `FromRef<S>` ile ister; bu crate `impl FromRef<AppState> for ModülServisi` ekler ve `build_router` içinde `.merge(modül::router::<AppState>())` yapar.

## Çalıştırma

```bash
docker compose up -d
cargo run -p authn-server -- --config config/example.toml migrate
cargo run -p authn-server -- --config config/example.toml serve
curl localhost:8080/health/ready
```
