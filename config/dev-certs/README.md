# Geliştirme sertifikası — YALNIZCA YEREL GELİŞTİRME

> **Uyarı:** Bu dizindeki özel anahtar (`mailpit.key`) depoda **herkese açık** olarak yayımlanmıştır. Bu sertifikaya veya anahtara geliştirme makinenizdeki `docker compose` Mailpit kapsayıcısı dışında hiçbir yerde güvenmeyin; üretimde veya staging'de kullanmayın.

## Neden var?

`authn-notify`'ın SMTP taşıyıcısı TLS'i zorunlu kılar ve sunucu sertifikasını doğrular (NTF-03). Mailpit `sans:localhost` ile her açılışta **yeni** bir kendinden imzalı sertifika üretiyordu; güvenilecek sabit bir dosya olmadığı için `config/example.toml` yerelde TLS doğrulamasında başarısız oluyordu. Bu dizin, Mailpit'e bağlanan sabit bir sertifika ile bu sorunu çözer.

| Dosya | İçerik |
|-------|--------|
| `mailpit.pem` | Kendinden imzalı X.509 v3 sertifikası (ECDSA P-256, SHA-256). SAN: `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`; `CA:FALSE`, `keyUsage=digitalSignature`, `extendedKeyUsage=serverAuth`; 20 yıl geçerli (2046-10-27'ye kadar). Konu: `O=rust-authentication DEVELOPMENT ONLY - NEVER TRUST IN PRODUCTION` |
| `mailpit.key` | Sertifikanın PKCS#8 özel anahtarı (yayımlanmış, gizli **değil**) |

SHA-256 parmak izi: `11:26:1F:17:AD:83:B7:7E:C0:00:F8:26:A3:B3:32:69:47:E1:FA:69:35:DD:D0:46:BD:E6:D4:28:EB:14:C4:05`

## Nasıl bağlanır?

- `docker-compose.yml`: dizin Mailpit kapsayıcısına salt-okunur bağlanır (`./config/dev-certs:/certs:ro`); `MP_SMTP_TLS_CERT=/certs/mailpit.pem`, `MP_SMTP_TLS_KEY=/certs/mailpit.key`, `MP_SMTP_REQUIRE_STARTTLS=true` (üretimdeki gibi STARTTLS'ten önce `MAIL`/`AUTH` yok).
- `config/example.toml`: `[notify.email.smtp]` altında `# extra_ca_file = "config/dev-certs/mailpit.pem"` satırı hazırdır; yerelde Mailpit'e e-posta göndermek için **yorumu kaldırın** (yol çalışma dizinine, yani depo köküne göredir). Satır, örnek dosyadaki isteğe bağlı tüm `[notify]` anahtarları gibi yorum olarak belgelenir (authn-notify `ntf_03_example_config_documents_every_notify_key`); böylece dosya üretime kopyalandığında da bu ayar kendiliğinden gelmez. Alternatif: `AUTHN__NOTIFY__EMAIL__SMTP__EXTRA_CA_FILE=config/dev-certs/mailpit.pem`.

## Üretimde neden kullanılamaz?

- `AppConfig::validate` (`crates/authn-core/src/config/mod.rs`) `notify.email.smtp.extra_ca_file`'ı `development` ve `test` dışındaki her ortamda reddeder; `server.environment`'ın varsayılanı `production`'dır. `check-config` de aynı hatayı verir.
- `authn-notify`'ın SMTP taşıyıcısı aynı kuralı açılışta bir kez daha uygular.
- Sertifika yalnızca `localhost` / geri döngü adresleri için geçerlidir; başka bir ana bilgisayar adıyla doğrulama başarısız olur.

## Yeniden üretme

Gerekirse (ör. süresi dolmadan önce) aynı özelliklerle yeniden üretin ve parmak izini bu dosyada güncelleyin:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 7300 \
  -keyout mailpit.key -out mailpit.pem \
  -subj "/O=rust-authentication DEVELOPMENT ONLY - NEVER TRUST IN PRODUCTION/OU=docker-compose Mailpit, published private key/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth"
chmod 644 mailpit.key   # kapsayıcı içindeki Mailpit kullanıcısı okuyabilmeli
```

Doğrulama testi: `crates/authn-testkit/tests/dev_certs.rs` (`ntf_03_*`, `ops_08_*`) sertifikayı rustls/webpki ile `localhost` için doğrular, başka adları reddettiğini, anahtarın sertifikayla eşleştiğini ve `docker-compose.yml` / `config/example.toml` bağlantılarını denetler.
