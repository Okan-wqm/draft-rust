# Test anahtarları

Bu klasördeki anahtarlar **yalnızca testler için** üretilmiş, depoda herkese açık olan anahtarlardır (sahte sağlayıcıların ID token imzaları ve Apple `client_secret` testi). Hiçbir ortamda gerçek sağlayıcı anahtarı olarak kullanılamazlar.

| Dosya | Tür | Kullanım |
|-------|-----|----------|
| `test_rsa_a.pem` | RSA 2048 (PKCS#1) | sahte sağlayıcının birinci imza anahtarı (`kid = key-a`) |
| `test_rsa_b.pem` | RSA 2048 (PKCS#1) | anahtar rotasyonu ve "yanlış anahtar" testleri (`kid = key-b`) |
| `test_ec_p256.pem` | P-256 (PKCS#8) | Apple `client_secret` (ES256) ve ES256 ID token testleri |
