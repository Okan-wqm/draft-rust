# Test sertifikaları (YALNIZCA TEST)

`authn-notify` SMTP entegrasyon testlerindeki yerel TLS sunucusu için üretilmiş, **herkese açık ve gizli olmayan** test materyali. Üretimde veya geliştirme ortamında kullanmayın.

| Dosya | İçerik |
|-------|--------|
| `test-ca.pem` | Kendinden imzalı test CA'sı (P-256, 100 yıl) — `notify.email.smtp.extra_ca_file` testleri |
| `localhost.pem` | `localhost` / `127.0.0.1` için CA imzalı sunucu sertifikası |
| `localhost.key` | Sunucu özel anahtarı (PKCS#8) |

CA özel anahtarı saklanmadı; yeniden üretmek için `openssl` ile yeni bir CA ve sunucu sertifikası oluşturun (SAN: `DNS:localhost`, `IP:127.0.0.1`, EKU: `serverAuth`).
