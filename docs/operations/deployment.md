# Dağıtım (DOC-06)

Kaynaklar: `Dockerfile`, `docker-compose.yml`, `crates/authn-server/src/{main,cli,serve,app,jobs}.rs`, `crates/authn-store/src/migrate.rs`. Konfigürasyon: [configuration.md](configuration.md). Veritabanı rolleri: [least-privilege.md](least-privilege.md). Kapasite: [scaling.md](scaling.md).

> **Docker bu belge yazılırken bu ortamda çalıştırılmadı** (Docker daemon yoktu). `Dockerfile` ve aşağıdaki imaj notları dosyanın okunmasına dayanır; imajı kendi CI'nızda derleyip `check-config` ve `/health/ready` ile doğrulayın. İkili (`cargo build --release -p authn-server`) ve `check-config` / `migrate` komutları bu ortamda denenmiştir.

## 1. İkili ve komutlar

Tek ikili: `rust-authentication` (crate `authn-server`). Yapılandırma `--config <yol>` / `-c` veya `AUTHN_CONFIG` ortam değişkeniyle verilir; `AUTHN__…` değişkenleri dosyayı ezer.

| Komut | Ne yapar |
|-------|----------|
| `serve` | HTTP sunucusu + arka plan işleri (Docker imajının varsayılan komutu) |
| `migrate` | Bekleyen migration'ları uygular, şemanın güncel olup olmadığını yazdırır |
| `check-config` | Yapılandırmayı ve `serve`'ün açılışta reddedeceği her şeyi doğrular; veritabanına bağlanmaz |
| `rotate-signing-key [--emergency]`, `rotate-kek` (`reencrypt`), `verify-audit-chain`, `rotate-audit-chain-key`, `audit-checkpoint`, `migrate-legacy-hashes --input <dosya>`, `seal-apple-key --pem-file <yol\|->` | Bakım; bkz. [key-management.md](key-management.md) |
| `export-erasures --output <dosya\|-> [--since <zaman>]`, `reapply-erasures --from <dosya\|->` | Silme defteri: dışa aktarma ve yedekten geri yüklemeden sonra silmeleri yeniden uygulama (K-108); bkz. [backup.md](backup.md#5-geri-yükleme-sonrası-güvenlik-etkileri) |
| `create-admin`, `admin-enrollment-link`, `suspend-admin`, `unsuspend-admin`, `revoke-admin-sessions`, `grant-admin`, `revoke-admin` | Platform admin kurtarma; bkz. [admin-recovery.md](admin-recovery.md) |

Çıkış kodları (`crates/authn-server/src/error.rs`): `0` başarı, `78` geçersiz yapılandırma, `69` veritabanı/şema/servis hatası, `65` geçersiz komut girdisi, `1` G/Ç, telemetri veya bütünlük (audit zinciri) hatası. Hata mesajları sır içermez.

Derleme özellikleri (`crates/authn-server/Cargo.toml`): varsayılan `passkey`, `sms`. **`redis` cargo varsayılanında yoktur**: kendiniz derlerken `protect.rate_limit.backend = "redis"` için `cargo build --release -p authn-server --features redis` gerekir; özellik yoksa sunucu açılışta reddeder. **Docker imajı `--features redis` ile derlenir** (K-109, §6).

## 2. Açılış sırası (`serve`)

1. Yapılandırma yüklenir ve doğrulanır (hata → `78`).
2. Veritabanı havuzu açılır; `database.migrate_on_start = true` ise migration'lar uygulanır.
3. **Şema bu ikiliyle uyumlu değilse sunucu başlamaz** (`database schema is not up to date … run rust-authentication migrate`, çıkış `69`): ikilinin bir migration'ı uygulanmamış, başarısız ya da uygulandıktan sonra değiştirilmişse (checksum). **Daha yeni bir sürümün** uygulamış olduğu, bu ikilinin tanımadığı migration'lar engel değildir (K-106, §3): `WARN` loglanır, sunucu açılır.
4. Metrik dinleyicisi (`server.metrics_bind_addr`) açılır.
5. Servisler kurulur; bakım rolü havuzu (`database.maintenance_url` yoksa uyarı loglanır).
6. Audit zinciri yapılandırılmış anahtar sürümüne geçirilir (K-77).
7. İmza anahtarı yoksa/rotasyon zamanıysa oluşturulur (ilk token'dan önce).
8. Şart sürümleri (`account.terms`) eşitlenir; arka plan işleri başlar; dinleyici açılır.

**Kapanış (SIGTERM/SIGINT):** yeni bağlantı kabulü durur, uçuştaki istekler en fazla `server.shutdown_grace_period` (30 sn) beklenir, sonra işler durdurulur ve kuyruktaki arka plan işleri (şifre sıfırlama, şifresiz giriş e-postaları vb.) tamamlanır. Orkestratörünüzün sonlandırma süresini bundan uzun tutun.

## 3. Migration'lar

- Migration'lar ikiliye gömülüdür (`migrations/`); `rust-authentication migrate` uygular. sqlx migrator'ı veritabanı düzeyinde kilit kullanır; sürüm sırasına değil "uygulanmamış" kümesine bakar.
- **Önerilen hat:** `migrate` (şema sahibi rolüyle, tek bir iş/CI adımı) → `SELECT authn_apply_least_privilege('authn_app', 'authn_maintenance');` (veritabanı sahibi olarak) → yeni sürümün `serve`'ü (uygulama rolüyle). Ayrıntı ve doğrulama sorguları: [least-privilege.md](least-privilege.md).
- **`database.migrate_on_start` uyarısı:** en az yetkili kurulumda kullanılamaz (uygulama rolü DDL yapamaz). Ayrıca birden fazla örnek aynı anda migration çalıştırırsa `CREATE INDEX CONCURRENTLY` içeren migration'larda (ilk satırı `-- no-transaction` olan dosyalar; ör. `2050`–`2053`, `1402`–`1404`) biri kilitlenme hatası alıp başlamayabilir. Büyük tablolarda migration'ı tek bir yerden çalıştırın.
- **`CONCURRENTLY` migration'ları** (`-- no-transaction`, dosya başına tek ifade, `IF NOT EXISTS` yok) canlı tabloda yazma kilidi almaz. Yarıda kalırsa (öldürülen dağıtım, `statement_timeout`, kilitlenme) PostgreSQL geride **INVALID** bir indeks bırakır ve migration kaydedilmez; yeniden çalıştırma `already exists` ile durur. Çözüm: `DROP INDEX CONCURRENTLY <indeks>;` sonra `migrate`. Büyük tablolarda şema sahibinin bağlantısında `statement_timeout`'u indeks yapımına yetecek kadar yükseltin. Ayrıntı ve test: [performance.md](performance.md#bulunan-darboğazlar-ve-yapılan-düzeltmeler).
- Uygulanmış migration asla değiştirilmez (checksum uyuşmazlığı hazır olma kontrolünü düşürür); geri alma migration'ı yoktur — **ileri düzeltin** ve dağıtımdan önce yedek alın ([backup.md](backup.md)).
- **Kademeli (rolling) dağıtım (K-106):** migration'lar **yalnızca genişletir** (expand-only; kural ve daraltmanın iki sürüme bölünmesi: [contracts.md §6](../architecture/contracts.md)). Bu yüzden hazır olma kontrolü ve açılış (`authn_store::MigrationStatus::is_compatible`) yalnızca **ikilinin kendi** migration'larına bakar:

  | Durum | `/health/ready` | `serve` açılışı |
  |-------|-----------------|-----------------|
  | İkilinin bütün migration'ları uygulanmış, checksum'lar eşleşiyor | `200` | açılır |
  | Üstelik daha yeni bir sürümün migration'ları da uygulanmış (`unknown_applied`) | `200` | açılır, `WARN database schema is ahead of this binary` |
  | Daha yeni sürümün bir migration'ı **başarısız** kaydedilmiş | `200` | açılır (`migrate_on_start = true` olsa bile ikilinin bekleyen migration'ı yoksa migrator hiç çalıştırılmaz; o migration'ı yeni sürüm onarır) |
  | İkilinin bir migration'ı bekliyor / başarısız / checksum'ı farklı | `503` | açılmaz, çıkış `69` |
  | Daha yeni bir sürümün **daraltan** migration'ı (`<sürüm>_contract_<…>.sql`) uygulanmış | `503` | açılmaz; `migrate` / `migrate_on_start` hiçbir şey uygulamadan reddeder (geri alma ve bakım penceresi sonrası eski örnek koruması) |

  Akış: (1) yedek alın, (2) **yeni sürümün** `migrate` adımı (şema sahibi rolüyle, tek bir yerden), (3) `authn_apply_least_privilege(...)` (yeni tablolar için), (4) örnekleri sırayla yeni sürümle değiştirin. (2) ile (4) arasında eski örnekler hazır kalır ve trafik almaya devam eder; yeniden başlatılırlarsa (`migrate_on_start` açık ya da kapalı) yine açılırlar. `migrate`, eski bir ikiliyle ileri bir şemada çalıştırılırsa `schema is ahead of this binary … compatible: true` yazar ve hiçbir şey yapmaz.
  - Geriye dönük uyumsuz (daraltan) bir değişiklik gerektiren sürüm, sürüm notunda bunu açıkça belirtir ve migration dosyasını `<sürüm>_contract_<açıklama>.sql` diye adlandırır; o sürüm için migration'dan önce bütün eski örnekleri durdurun (bakım penceresi). Bu ada sahip bir migration uygulandıktan sonra eski ikililer açılmaz ve hazır olmaz; o sürümden geri dönmek yedekten geri yükleme gerektirir.
  - Liveness yoklamasını yine `/health/live`'a bağlayın: bağlantı kopması gibi geçici veritabanı sorunlarında `/health/ready` `503` döner ve örnek yalnızca trafikten çıkarılmalıdır, öldürülmemelidir.

## 4. Sağlık uçları

| Uç | Anlam | Kullanım |
|----|-------|----------|
| `GET /health/live` | Süreç HTTP'ye yanıt veriyor; her zaman `200 {"status":"ok"}` | liveness probe |
| `GET /health/ready` | Veritabanı erişilebilir **ve** şema güncel: `200 {"status":"ready","database":"ok","migrations":"up_to_date"}`; değilse `503 {"status":"not_ready", …}` | readiness probe, yük dengeleyici sağlık kontrolü |

Her ikisi de kimlik doğrulama istemez, `Cache-Control: no-store` döner, sürüm/host/hata metni sızdırmaz. `/health/` öneki **Host doğrulamasından ve genel IP oran sınırından muaftır** (IP ile adreslenen yoklamalar çalışır).

## 5. Ağ ve vekil

- Genel API: `server.bind_addr` (varsayılan `0.0.0.0:8080`). TLS'i önündeki vekil/yük dengeleyici sonlandırır; `server.public_base_url` her zaman dışarıdan görünen `https://` adres olmalıdır (üretimde zorunlu).
- **İstemci IP'si:** vekilin ağını `server.trusted_proxies`'e ekleyin ve vekilin `X-Forwarded-For`'u (veya `Forwarded`, `server.client_ip_header`) **kendisinin yazdığından** emin olun. `0.0.0.0/0` gibi geniş aralıklar reddedilir. Yanlış ayar ya tüm istemcileri vekilin IP'si yapar (oran sınırları herkesi birlikte keser) ya da IP'yi sahtelenebilir kılar.
- **Host:** `protect.allowed_hosts` boşsa yalnızca `public_base_url`'in host'u kabul edilir; vekil `Host` başlığını korumalıdır (aksi `421 host_not_allowed`).
- **Metrikler:** `server.metrics_bind_addr` (varsayılan `127.0.0.1:9090`) ayrı ve kimlik doğrulamasız bir dinleyicidir; **internete asla açmayın**. `"off"` (veya `""`; ortam değişkeniyle `AUTHN__SERVER__METRICS_BIND_ADDR=off`) dinleyiciyi tamamen kapatır (K-109). Docker imajı `AUTHN__SERVER__METRICS_BIND_ADDR=0.0.0.0:9090` ile gelir, çünkü loopback konteyner dışından erişilemez (§6): `9090`'u yalnızca izleme ağına yayımlayın (Kubernetes'te `NetworkPolicy`, Docker'da `-p 127.0.0.1:9090:9090` veya iç ağ), yük dengeleyiciye/Ingress'e eklemeyin.
- **Giden bağlantılar:** PostgreSQL, (opsiyonel) Redis, SMTP (TLS zorunlu), SMS sağlayıcısı, HIBP (`api.pwnedpasswords.com`), CAPTCHA sağlayıcısı, sosyal giriş sağlayıcıları (discovery, JWKS, token uçları), organizasyon webhook URL'leri (herkese açık adresler; özel ağlar SSRF korumasıyla engellenir).

## 6. Docker imajı

`Dockerfile` iki aşamalıdır: `rust:1.97-bookworm` ile `cargo build --release --locked -p authn-server --bin rust-authentication --features redis` (varsayılan özellikler + `redis`, K-109), ardından `gcr.io/distroless/cc-debian12:nonroot` (kabuk ve paket yöneticisi yok, `nonroot` kullanıcı). İmaj `/etc/authn/example.toml` ve `/usr/share/doc/rust-authentication/THIRD_PARTY_LICENSES.txt` içerir; `ENV AUTHN__SERVER__METRICS_BIND_ADDR=0.0.0.0:9090` (metrik dinleyicisi konteyner ağında; §5); `EXPOSE 8080 9090`; `ENTRYPOINT ["/usr/local/bin/rust-authentication"]`, `CMD ["serve"]`. `crates/authn-server/tests/dockerfile.rs` Docker olmadan tutarlılığı zorlar: derleme satırındaki her özellik `Cargo.toml`'da var ve `redis` içeriyor, metrik adresi tüm arayüzlere bağlı ve portu `EXPOSE`'da. `redis` özelliğinin getirdiği crate'ler (`fred` ailesi) `THIRD_PARTY_LICENSES.txt`'te zaten vardır (bildirim dosyası `--all-features` ile üretilir).

```bash
docker build -t rust-authentication .
docker run --rm -e AUTHN_CONFIG=/etc/authn/authn.toml \
  -v "$PWD/config/authn.toml:/etc/authn/authn.toml:ro" rust-authentication check-config
docker run --rm -e AUTHN_CONFIG=/etc/authn/authn.toml \
  -v "$PWD/config/authn.toml:/etc/authn/authn.toml:ro" rust-authentication migrate
docker run -d -p 8080:8080 -e AUTHN_CONFIG=/etc/authn/authn.toml \
  -v "$PWD/config/authn.toml:/etc/authn/authn.toml:ro" rust-authentication
```

Notlar:

- Distroless imajda kabuk yoktur: `HEALTHCHECK` içinde `curl` çalıştıramazsınız; sağlık kontrolünü orkestratörün HTTP yoklamasıyla (`/health/live`, `/health/ready`) yapın.
- İmaj `redis` özelliğiyle derlenir; Redis kullanmıyorsanız (`backend = "postgres"`) özellik yalnızca kullanılmayan kod demektir.
- Metrik dinleyicisini istemiyorsanız `-e AUTHN__SERVER__METRICS_BIND_ADDR=off`; yayımlıyorsanız yalnızca iç ağa (`-p 127.0.0.1:9090:9090` veya izleme ağı).
- Sırları imaja koymayın; ortam değişkeni veya salt-okunur mount kullanın. `config/example.toml`'daki anahtarlar herkese açıktır ve production/staging'de reddedilir.
- `docker-compose.yml` yalnızca **geliştirme** bağımlılıklarını (PostgreSQL 16, Redis 7, Mailpit) `127.0.0.1`'e bağlar; üretim için değildir. Mailpit'in sertifikası herkese açık bir geliştirme sertifikasıdır ve `notify.email.smtp.extra_ca_file` development/test dışında reddedilir (`config/dev-certs/README.md`).

## 7. Arka plan işleri

`serve` her örnekte şu işleri çalıştırır; hepsi çoklu örnekte güvenlidir (`FOR UPDATE SKIP LOCKED`, advisory lock veya idempotent silme). Ayrı bir zamanlayıcı gerekmez.

| İş | Aralık |
|----|--------|
| Outbox teslimi (e-posta/SMS bildirimleri, webhook'lar, domain olayları) | sürekli (`audit.outbox.poll_interval`, 1 sn) |
| İmza anahtarı önbelleği dinleyicisi (`LISTEN authn_signing_keys`, ayrı bağlantı) | sürekli |
| Temizlikler (süresi dolan oturum/challenge/token/seremoni/state/kilit/oran sınırı kovaları, doğrulanmamış hesaplar, zamanı gelen hesap/organizasyon silmeleri, süresi dolan davetler…) | 1 dk |
| Sosyal sağlayıcı token iptalleri (Apple) | 1 dk |
| İmza anahtarı rotasyon kontrolü (`crypto.signing_keys.rotation_interval`) | 1 saat |
| Dış audit çıpası: zincir başının `scheduled` kontrol noktası, `anchor = "<seq>:<hash>"` INFO logu (bakım rolüyle; K-107) | saatte bir kontrol, `audit.checkpoint_interval` (24 saat) başına tüm örneklerde **bir** kez (advisory lock) |
| Audit saklama temizliği (`retention_purge` kontrol noktası yalnızca silinen olay varsa) + outbox / webhook teslim geçmişi temizliği (bakım rolüyle) | 1 gün |

Bir işin hatası loglanır ve bir sonraki turda yeniden denenir; sunucuyu durdurmaz.

## 8. Dağıtım kontrol listesi

- [ ] `server.environment = "production"` (varsayılan), `public_base_url` https.
- [ ] Tüm anahtarlar yeni üretildi (`openssl rand -base64 32`); örnek anahtar yok.
- [ ] `database.url` ve `maintenance_url` `sslmode=verify-full`; roller [least-privilege.md](least-privilege.md)'ye göre.
- [ ] `trusted_proxies`, `allowed_hosts`, `webauthn.rp_id` / `allowed_origins`, CORS ve `csrf_allowed_origins` topolojiye göre ([web rehberi](../integration/web.md)).
- [ ] SMTP (`notify.email`), `from_address` gerçek domain.
- [ ] `rate_limit.backend` `postgres` veya `redis`.
- [ ] `rust-authentication check-config` CI'da yeşil.
- [ ] `migrate` → `authn_apply_least_privilege` → `serve`; `/health/ready` `200`.
- [ ] Break-glass admin oluşturuldu ([admin-recovery.md](admin-recovery.md)).
- [ ] Audit zinciri yükseltme kontrol noktası dışarıda saklandı ve `audit.chain.legacy_until_seq` sabitlendi ([key-management.md](key-management.md#5-audit-zinciri-anahtarı-k-77)).
- [ ] Metrik kazıma ve alarmlar ([monitoring.md](monitoring.md)), yedekler ([backup.md](backup.md)).
- [ ] Log hattı `anchor` alanlı `audit chain scheduled checkpoint` satırlarını WORM depoya taşıyor (K-107, [key-management.md §5](key-management.md#5-audit-zinciri-anahtarı-k-77)).
- [ ] `export-erasures` zamanlanmış (ör. saatlik) ve çıktısı veritabanı yedeklerinden **ayrı** bir depoya ekleniyor (K-108, [backup.md](backup.md)).
- [ ] Metrik portu yalnızca iç ağda (veya `metrics_bind_addr = "off"`).
