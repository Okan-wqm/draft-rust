# İstemci entegrasyon rehberleri (DOC-05)

`rust-authentication`'a bağlanan her istemci türü için adım adım rehberler. Her rehber yalnızca sunucuda gerçekten var olan uçları, başlıkları ve ayarları anlatır; referans ayrıntıları [`docs/api/`](../api/README.md)'dadır.

| Rehber | Kimin için |
|--------|-----------|
| [`web.md`](web.md) | Tarayıcı uygulamaları: aynı origin / aynı site çerez oturumu, SPA, BFF; CSRF; passkey, magic link, sosyal giriş |
| [`native.md`](native.md) | Tüm native istemcilerin ortak kuralları: `X-Authn-Client: native`, challenge başlığı, refresh token rotasyonu ve yeniden kullanım tespiti |
| [`ios.md`](ios.md) | iOS / macOS: passkey (AASA `webcredentials`), Sign in with Apple, universal link'ler, Keychain |
| [`android.md`](android.md) | Android: Credential Manager ile passkey (`assetlinks.json`, `android:apk-key-hash:`), Google ile giriş, App Links, Keystore |
| [`resource-server.md`](resource-server.md) | Kendi API'niz: JWKS ile JWT doğrulama (Rust örneği), introspection |
| [`b2b.md`](b2b.md) | B2B SaaS: organizasyonlar, aktif organizasyon, roller/izinler, davetler, domain'ler, politikalar (`login_method_not_allowed`, `org_policy_mfa_required`), API anahtarları, servis hesapları |
| [`oidc-provider.md`](oidc-provider.md) | OAuth 2.1 / OIDC sağlayıcısı (K-80): istemci kaydı, giriş / onay sayfası (headless), RP akışı (code + PKCE, ID token doğrulama, refresh, userinfo, iptal), kaynak sunucusu |
| [`webhooks.md`](webhooks.md) | Webhook alıcısı: Standard Webhooks imza doğrulaması (Rust örneği), yeniden deneme, tekilleştirme |

## Hangi kimlik bilgisi?

| İstemci | Kimlik bilgisi | Rehber |
|---------|----------------|--------|
| Tarayıcı (aynı site) | `__Host-authn_session` çerezi + CSRF | web |
| Mobil / masaüstü uygulaması | Ed25519 JWT access token + dönen refresh token | native, ios, android |
| Kullanıcı adına çalışan arka uç (BFF) | native akış, token'lar sunucuda | web §5 |
| Makineden makineye (organizasyon kapsamlı) | Organizasyon API anahtarı `ak_…` | b2b §6 |
| Kendi API'niz token'ı doğrular | JWKS (yerel) veya introspection (API anahtarıyla) | resource-server |
| Kayıtlı (üçüncü taraf) uygulama | OIDC: authorization code + PKCE, sağlayıcı access / ID / refresh token'ı | oidc-provider |

Native ve çerez akışlarındaki istemciler birinci taraftır (`client_id: "first-party"`). Faz 2'nin ilk kalemi olarak OAuth 2.1 / OIDC **sağlayıcısı** (K-80) eklendi ve varsayılan kapalıdır ([oidc-provider.md](oidc-provider.md)); device flow, client credentials, token exchange ve dinamik kayıt hâlâ [`docs/roadmap.md`](../roadmap.md)'de Faz 2 kapsamındadır.
