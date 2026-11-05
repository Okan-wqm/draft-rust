# authn-notify

İşlemsel mesajlaşma: `Notifier` portunun transactional outbox ile uygulanması, her bildirim türü için Türkçe ve İngilizce şablonlar (HTML + düz metin, minijinja, otomatik escape), e-posta taşıyıcıları (zorunlu TLS'li SMTP, log, bellek) ve SMS göndericileri (genel HTTP sağlayıcı, log, bellek).

## Sahip olunan gereksinimler

| Kimlik | Nasıl karşılanıyor | Başlıca testler |
|--------|--------------------|-----------------|
| NTF-01 | `OutboxNotifier` (`Notifier` portu): `notify` kendi transaction'ında, `notify_in_tx` çağıranın transaction'ında **bir `outbox` satırı** yazar (`notification.email`); 20 bildirim türünün tamamı için TR/EN şablon. SMS için porta geriye uyumlu `notify_sms_in_tx` eklendi (`notification.sms`). | `tests/outbox.rs` (`ntf_01_*`), `templates::tests::ntf_01_*` |
| NTF-02 | `TemplateRenderer`: TR/EN, HTML + düz metin; `.html` dosyalarında otomatik HTML escape (dosya adına göre, şablon kapatamaz); kullanıcı verisi ayrıca `sanitize` ile nötrleştirilir; şablonlar `notify.template_dir`'den geçersiz kılınabilir ve açılışta doğrulanır; linkler yalnızca `server.public_base_url` + `notify.links.*` ile kurulur. | `templates::tests::ntf_02_*`, `links::tests`, `sanitize::tests` |
| NTF-03 | `SmtpEmailTransport` (lettre, yalnızca STARTTLS/örtük TLS), `LogEmailTransport` (yalnızca development/test), `MemoryEmailTransport` / `DisabledEmailTransport`; gönderim outbox işçisi üzerinden `NotificationDeliverer` ile (istek yolunu bloklamaz, yeniden denenir). | `tests/smtp.rs`, `tests/outbox.rs` (`ntf_03_*`) |
| NTF-04 | `HttpSmsSender` (`sms` feature'ı, `HttpClient` portu üzerinden genel JSON sağlayıcı), `LogSmsSender`, `MemorySmsSender`, `DisabledSmsSender`; yalnızca E.164 (`PhoneNumber`); TR/EN SMS şablonları. | `tests/sms_http.rs`, `tests/outbox.rs` (`ntf_04_*`) |

Uygulanmayan SHOULD/MAY maddesi yoktur. Sınırlamalar aşağıda.

## Bağımlılık kuralı

Dalga A: yalnızca `authn-core`, `authn-crypto`, `authn-store`. `authn-audit`'e bağımlı **değildir**: outbox satırı bu crate'te doğrudan `INSERT` edilir (contracts §5 izni) ve teslim, `authn-audit`'in işçisine sunucunun kuracağı küçük bir köprüyle bağlanır. Yeni harici bağımlılık eklenmedi (yalnızca `minijinja`'ya yerel `fuel` özelliği ve dev-dependency olarak workspace'teki `rustls`); kullanılmayan `reqwest`, `secrecy` ve (normal) `rustls` bağımlılıkları ile `tower`, `http-body-util`, `wiremock` dev-bağımlılıkları kaldırıldı; `zeroize` ve `http` eklendi (workspace'te mevcut).

## Genel API

| Öğe | Açıklama |
|-----|----------|
| `OutboxNotifier` | `Notifier` uygulaması. `new(pool, cipher, clock)`, `from_config(&NotifyConfig, pool, cipher, clock, rate_limiter)`, `with_max_attempts`, `with_recipient_limit`, `enqueue_email(conn, &Notification) -> Option<OutboxMessageId>`, `enqueue_sms(conn, &SmsNotification)`, `notify_sms(sms)` |
| `NotificationDeliverer` | `new(cipher, renderer, email, sms, clock)`, `handles(topic)`, `deliver(DeliveryRequest) -> Result<(), DeliveryFailure>` |
| `DeliveryRequest<'a>` | Talep edilen outbox satırının alanları: `id`, `topic`, `payload`, `sealed_payload`, `attempt`, `max_attempts` |
| `DeliveryFailure` | `Retry { reason, retry_after }` / `Permanent { reason }`; `is_retryable()`, `reason()`, `from_transport_error(&AuthError)` |
| `TemplateRenderer` | `from_config(&AppConfig)`, `new(&NotifyConfig, &Url)`, `render_email(&Notification, now) -> RenderedEmail`, `render_sms(&SmsNotification, now) -> SensitiveString`, `validate()`, `overridden()` |
| `LinkBuilder`, `LinkTarget` | `public_base_url` + yol + `#token=…` |
| `SmtpEmailTransport`, `LogEmailTransport`, `MemoryEmailTransport` (+ `InjectedFailure`), `DisabledEmailTransport`, `email_transport_from_config(&NotifyConfig, Environment)` | `EmailTransport` uygulamaları |
| `HttpSmsSender` (feature `sms`), `LogSmsSender`, `MemorySmsSender`, `DisabledSmsSender`, `sms_sender_from_config(&NotifyConfig, Environment, Arc<dyn HttpClient>)` | `SmsSender` uygulamaları |
| `NotifyServices::from_config(&AppConfig, pool, cipher, clock, rate_limiter, http)` | Hepsi bir arada, hızlı başarısızlık; alanlar: `notifier`, `deliverer`, `renderer`, `email`, `sms`; `notifier_port()` |
| `EMAIL_TOPIC`, `SMS_TOPIC`, `NOTIFICATION_TOPIC_PREFIX`, `sealed_payload_context(id)` | Outbox sözleşmesi |
| `sanitize::{user_text, header_value, text_body, is_header_safe}` | Güvenilmeyen metnin nötrleştirilmesi |
| `NotifyError`, `RenderError` | Açılış / işleme hataları (sır içermez) |

## Outbox satırı

| Kolon | İçerik |
|-------|--------|
| `topic` | `notification.email` veya `notification.sms` |
| `payload` (açık `jsonb`) | Yalnızca yönlendirme bilgisi: `{"v":1,"channel":"email","template":"password_reset","locale":"tr","user_id":…,"recipient":"a***@example.com"}` |
| `sealed_payload` | Bildirimin **tamamı** (alıcı adresi, görünen ad, token'lar, kodlar) — CRY-08 zarfı, AAD = `outbox.sealed_payload#<satır kimliği>`; başka satıra kopyalanırsa açılmaz. Teslim edilince `authn-audit` siler (`outbox_sealed_wiped_check`). |
| `max_attempts` | `notify.max_attempts` (varsayılan 10) |

Hiçbir sır veya kişisel veri düz metin olarak saklanmaz (test: `ntf_01_notify_enqueues_one_sealed_outbox_row`). Düz metin JSON'u tutan tampon 32 KiB olarak önceden boyutlandırılır, **asla büyütülmez** (daha büyük bildirim yeniden ayırma yerine hatayla reddedilir; yeniden ayırma sıfırlanmamış bir kopya bırakırdı) ve `Zeroizing` ile sıfırlanır (test: `ntf_01_sealed_plaintext_buffer_never_grows`).

### Teslim sınıflandırması (`NotificationDeliverer`)

| Durum | Sonuç |
|-------|-------|
| Zaman aşımı, bağlantı/TLS hatası, SMTP 4xx, SMTP kimlik doğrulama hatası (530/534/535/538), SMS 408/425/429/5xx, taşıyıcıdan `service_unavailable` | `Retry` (sağlayıcının `Retry-After`'ı taşınır, SMS'te en fazla 1 saat) |
| Zarfın KEK'i yapılandırılmamış (`UnknownKey`) | `Retry` (operatör düzeltebilir) |
| SMTP 5xx (geçersiz alıcı, politika reddi), SMS 4xx → `delivery_rejected` | `Permanent` |
| SMS sağlayıcısı yok (`sms_unavailable`) | `Permanent` |
| Bilinmeyen konu, bozuk/desteklenmeyen payload, eksik/kurcalanmış zarf, payload–zarf uyumsuzluğu | `Permanent` |
| Link/kod teslimden önce süresi dolmuş | `Permanent` (ölü link gönderilmez; güvenlik bildirimleri geç de olsa gider) |
| Şablon hatası, geçersiz token/kod biçimi | `Permanent` |

Nedenler statik dizgelerdir: adres, token, kod veya sağlayıcı yanıtı `outbox.last_error`'a ya da loglara girmez. E-postalar `Message-ID: <outbox-id@gönderen-domaini>` taşır; en-az-bir-kez teslimde alıcılar tekilleştirebilir.

## Şablonlar

Dosya düzeni (yerleşik: `templates/`, geçersiz kılma: `notify.template_dir` altında aynı göreli yol):

```
<locale>/email/layout.txt, layout.html
<locale>/email/<tür>.subject.txt | <tür>.txt | <tür>.html   (24 tür)
<locale>/sms/mfa_sms_code.txt, phone_verification.txt
```

`<locale>`: `en`, `tr`. Türler: `email_verification`, `registration_attempt`, `password_reset`, `password_changed`, `email_change_verification`, `email_changed`, `mfa_factor_added`, `mfa_factor_removed`, `mfa_reset`, `mfa_email_code`, `recovery_code_used`, `new_device_login`, `suspicious_login_blocked`, `account_deletion_scheduled`, `account_deletion_cancelled`, `invitation`, `magic_link`, `login_code`, `org_ownership_transfer`, `impersonation_started`, `identity_linked`, `identity_unlinked`, `passkey_clone_suspected`, `email_change_reverted`.

Wave 1 (K-18, K-19, K-40): `IdentityLinked { provider, at }` / `IdentityUnlinked { provider, at }` (sağlayıcı görünen adı; şablonda kaçışlı ve uzunluk sınırlı), `PasskeyCloneSuspected { at }` (bir passkey'in klonlanmış olabileceği uyarısı; alıcı başına limit uygulanır, çünkü klonu elinde tutan tespiti istediği kadar tetikleyebilir), `EmailChangeReverted { at }` (geri alma sonrası "oturumlar kapatıldı, şifrenizi sıfırlayın" uyarısı). `registration_attempt` metni hem kayıt hem e-posta değişikliği girişimini kapsayacak şekilde genelleştirildi ("bu adres bir hesap için kullanılmak istendi"). Test: `ntf_01_identity_passkey_clone_and_revert_notices`. Üreticiler (authn-oidc-client bağlama/ayırma, authn-webauthn klon tespiti, authn-account geri alma) wave 2'de bağlanacak.

Kurallar:

- `.html` dosyaları **her zaman** HTML escape edilir (karar dosya adına göredir). `|safe`, `{% filter safe %}`, `{% autoescape %}`, `{% include/import/from %}` ve diğer türden ya da hesaplanmış bir şablonu `extends` etmek yerleşik ve geçersiz kılınan şablonlarda **reddedilir**. Tarama kaynaktaki **her** `{%`'yi inceler (anahtar kelimeden sonra boşluk gerekmez: `{%include"x"%}` de yakalanır; dizge içindeki `{%`/`%}` sonraki etiketi gizleyemez).
- `safe` ve `tojson` filtreleri (çıktıları "güvenli" işaretlidir; `tojson` `"` karakterini kaçırmaz, tırnaklı özniteliği kırar) ile `debug()` fonksiyonu (tüm bağlamı — link ve kod dahil — döker) ortamdan **kaldırılmıştır**: `map("safe")` gibi hiçbir yazım onlara ulaşamaz (test: `ntf_02_escape_guards_cannot_be_bypassed_by_syntax_tricks`).
- Değerler veridir, şablon kaynağı değildir: `{{ 7*7 }}` adlı bir kullanıcı adı aynen yazılır.
- Tanımsız değişken hatadır (strict mod); her render minijinja yakıtıyla sınırlıdır; hata ayıklama çıktısı (değerleri gösterebilir) kapalıdır.
- Açılışta her tür × her dil örnek veriyle render edilir; derlenmeyen, render edilmeyen, linki veya kodu düşüren şablon, bilinmeyen dosya adı (yazım hatası), 64 KiB'den büyük veya UTF-8 olmayan dosya **servisi açtırmaz**.
- Konu satırında link veya kod **olamaz**: konu şablonlarına `link` ve `code` değişkenleri verilmez; bunları yazdırmaya çalışan geçersiz kılma (strict mod) açılışta reddedilir (konular aktarıcılardan şifresiz geçer, kilit ekranında ve `Debug` çıktısında görünür; test: `ntf_02_subject_templates_cannot_reveal_links_or_codes`). Zamanlar UTC olarak dile göre yazılır (`1 Kasım 2026 14:05 (UTC)`); kalan süre (`30 dakika`) **teslim anında** hesaplanır.
- HTML'de harici görsel, yazı tipi veya izleme pikseli yoktur; linklerde `rel="noopener noreferrer"`, sayfada `referrer: no-referrer`.

Her şablonda bulunan değişkenler: `app_name`, `locale`, `base_url`, `recipient_name` (temizlenmiş veya yok), `sign_in_link`, `reset_request_link`, `link` (token'lı link veya yok), `code` (veya yok), `expires_at`, `expires_in` (veya yok), gövdelerde ayrıca `subject`.

| Tür | Ek değişkenler |
|-----|----------------|
| `password_changed` | `at`, `ip_masked`, `device` (son ikisi opsiyonel) |
| `email_changed` | `new_email_masked`, `revert_expires_at` |
| `mfa_factor_added` / `mfa_factor_removed` | `factor` (yerelleştirilmiş ad), `at` |
| `mfa_reset`, `account_deletion_cancelled` | `at` |
| `recovery_code_used` | `remaining`, `low_on_codes` (≤ 3), `at` |
| `new_device_login` | `device`, `approximate_location` (opsiyonel), `ip_masked`, `at` |
| `suspicious_login_blocked` | `device`, `ip_masked`, `at` |
| `account_deletion_scheduled` | `scheduled_for` |
| `invitation` | `org_name`, `inviter_name` (opsiyonel) |
| `org_ownership_transfer` | `org_name` |
| `impersonation_started` | `at`, `ends_at` |
| SMS (her iki tür) | `app_name`, `locale`, `code`, `expires_at`, `expires_in`, `domain` (`public_base_url` host'u; son satır `@domain #kod` — origin-bound one-time code, WebOTP/otomatik doldurma yalnızca doğru alan adında çalışır) |

### Güvenilmeyen değerler (`sanitize`)

Görünen ad, organizasyon adı, davet eden adı, cihaz/konum açıklaması (user-agent'tan gelir, saldırgan kontrolündedir): kontrol karakterleri ve satır ayırıcılar boşluğa çevrilir (başlık/paragraf enjeksiyonu yok), bidi ve sıfır genişlikli karakterler silinir, boşluklar daraltılır, `://` → `[://]` (tıklanabilir sahte link yok; görünmez karakterle gizleme engellenir), uzunluk sınırlanır (ad 64, organizasyon 80, ayrıntı 120, konu 200 karakter). SMTP taşıyıcısı konu ve adları ayrıca yeniden temizler.

## Linkler (NTF-02, PWD-08)

`server.public_base_url` (yol öneki korunur) + `notify.links.<hedef>` + `#token=<token>`. Token **URL fragment'ındadır**: tarayıcı sunucuya göndermez; erişim loglarına, proxy'lere ve `Referer`'a sızmaz. Üreticiler yalnızca ham token verir; token `[A-Za-z0-9_-]{16,256}` dışında ise (`/`, `?`, `#`, `@`, `%`, boşluk…) reddedilir. `Host` başlığı ya da istekten türetilen hiçbir şey URL üretiminde kullanılmaz (bu crate'in istek bağlamına erişimi yoktur).

## E-posta taşıyıcıları (NTF-03)

| Taşıyıcı | İzinli ortam |
|----------|--------------|
| `smtp` | hepsi — `starttls` → `Tls::Required` (STARTTLS sunulmazsa veya başarısızsa oturum kesilir, düz metne düşüş yok), `tls` → örtük TLS (465). Sertifika host adına karşı platform doğrulayıcısıyla (rustls + ring) doğrulanır. Kimlik bilgileri yalnızca TLS üzerinden gider (test: `ntf_03_smtp_delivers_over_starttls_and_authenticates_only_after_tls`). |
| `log` | development, test — meta veri ve link/kodları `[REDACTED]` yapılmış düz metin gövde |
| `disabled` | production dışı |

- `EHLO` adı `hello_name` veya gönderen domainidir; makine host adı asla gönderilmez (`Received:` başlıklarına sızardı). `Message-ID` da gönderen domainindedir.
- `Auto-Submitted: auto-generated` ve `X-Auto-Response-Suppress: All` başlıkları otomatik yanıt döngülerini önler.
- SMTP sunucusunun yanıt metni (alıcı adresini içerebilir) hataya/loga girmez; yalnızca SMTP kodu loglanır.
- lettre'nin bağlantı havuzu Tokio görevleri başlatır: `SmtpEmailTransport::from_config` Tokio runtime'ı içinde çağrılmalıdır (aksi halde panik yerine hata döner).
- **Mailpit (docker compose):** Mailpit `sans:localhost` ile her açılışta yeni bir kendinden imzalı sertifika üretir. Yerelde SMTP kullanmak için Mailpit'i sabit bir sertifikayla çalıştırıp (`MP_SMTP_TLS_CERT`/`MP_SMTP_TLS_KEY` dosya yolu) `notify.email.smtp.extra_ca_file`'ı o sertifikaya yöneltin, ya da `transport = "log"` kullanın. `extra_ca_file` yalnızca development/test'te kabul edilir; dosyada en az bir PEM sertifikası olmalıdır.

## SMS göndericileri (NTF-04)

- `provider = "none"` (varsayılan): `is_configured() == false`, gönderim `sms_unavailable` (ARC-11: SMS kapalı davranır). `http` sağlayıcısı `sms` feature'ı olmadan seçilirse servis açılmaz.
- `http`: `POST http_url` (yalnızca https; operatör tarafından yapılandırıldığı için `OutboundTarget::Trusted`, zaman aşımı ve yanıt boyutu sınırı `authn-protect` istemcisinde). API anahtarı `http_auth_header`'da (`authorization: Bearer …` varsayılan), `sensitive` işaretli; `Debug`/log/hata çıktısına girmez. Gövde `http_body_template` JSON'undan üretilir: `{{to}}`, `{{text}}`, `{{sender_id}}` yer tutucuları **ayrıştırılmış JSON ağacındaki dizgelerde tek geçişte** değiştirilir — mesajdaki `"`, `\`, satır sonu veya `{{to}}` JSON'dan kaçamaz (proptest: `ntf_04_body_template_cannot_be_escaped`). Sağlayıcı mesaj kimliği `http_message_id_pointer` ile alınır (≤ 128 yazdırılabilir ASCII).
- Gövde 1–1600 karakter olmalı, `\n` dışında kontrol karakteri içeremez (tüm göndericiler).
- SMS pumping koruması (ülke izin listesi, numara/IP limiti, global bütçe) `authn-mfa`'nın işidir ve göndermeden **önce** yapılır.

## Bombalamaya karşı alıcı başına limit

Kullanıcının tetikleyebildiği türler (doğrulama, kayıt girişimi, sıfırlama, e-posta değişikliği doğrulaması, e-posta OTP, davet, magic link, giriş kodu, sahiplik devri ve tüm SMS'ler) alıcı adresi/numarası başına `notify.recipient_limit` ile sınırlıdır (varsayılan 30/saat, `RateLimiter` portu).

- **Bütçeler:** Erişim sağlayan her tür kendi bütçesine sahiptir — `notify_recipient_password_reset`, `notify_recipient_magic_link`, `notify_recipient_login_code`, `notify_recipient_mfa_email_code`, `notify_recipient_mfa_sms_code`. Diğerleri (doğrulama, kayıt girişimi, e-posta değişikliği doğrulaması, davet, sahiplik devri, telefon doğrulama) ortak `notify_recipient` bütçesini paylaşır. Aksi halde saldırgan ucuz kayıt girişimleriyle (ya da kendi hesabına kurbanın numarasını ekleyerek) kurbanın ortak bütçesini tüketip giriş ve ikinci faktör kodlarını sessizce düşürtebilirdi (hesap kilitleme; test: `ntf_01_cheap_kinds_cannot_starve_sign_in_and_mfa_codes`). Bir posta kutusuna saatte en fazla 5 × `limit` kullanıcı tetiklemeli e-posta gidebilir; üretici modüllerin kendi limitleri bunu ayrıca daraltır.
- **Anahtar:** e-posta için normalize adresin **alt adres etiketi atılmış** hali (`Victim+1@Example.com` → `victim@example.com`), aksi halde `+etiket` ile limit tamamen aşılırdı (test: `ntf_01_recipient_limit_cannot_be_bypassed_with_plus_addressing`); SMS için E.164 numara. Anahtarlar `RateLimiter` uygulamasında anahtarlı hash ile saklanır. Aşan mesaj **sessizce düşürülür** (log + `authn_notifications_dropped_total`): hata dönmek, adresin hesabı olduğunu üreticinin yanıtından sızdırırdı. Güvenlik uyarıları (şifre değişti, yeni cihaz, MFA değişiklikleri, kurtarma kodu, şüpheli giriş, hesap silme, impersonation) **asla** kısılmaz — saldırgan önce bombalayıp sonra sessizce işlem yapamaz. Limit arka ucu hata verirse mesaj yine kuyruğa alınır (fail-open).

## Konfigürasyon (`[notify]`, `crates/authn-core/src/config/notify.rs`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `app_name` | `rust-authentication` | Mesajlardaki ürün adı (≤ 64, kontrol karakteri yok) |
| `template_dir` | — | Geçersiz kılma dizini |
| `max_attempts` | 10 | 1–100 |
| `recipient_limit` | `{ limit = 30, period = "1h" }` | Yukarıya bakın |
| `links.*` | `/verify-email`, `/reset-password`, `/forgot-password`, `/login`, `/email-change/verify`, `/email-change/revert`, `/magic-link`, `/invitations/accept`, `/account/deletion/cancel`, `/security/not-me`, `/organizations/ownership/accept` | Mutlak yol; sorgu, fragment, boşluk yok |
| `email.transport` | `smtp` | `smtp` \| `log` \| `disabled` |
| `email.from_address` / `email.from_name` | `no-reply@localhost.localdomain` / `rust-authentication` | Ad: başlık için güvenli |
| `email.smtp.host` / `port` / `tls` | — / 587 / `starttls` | Düz metin modu yok |
| `email.smtp.username` / `password` | — | Birlikte |
| `email.smtp.timeout` | `10s` | 1 sn – 2 dk |
| `email.smtp.hello_name` | gönderen domaini | Host adı biçimi |
| `email.smtp.extra_ca_file` | — | Yalnızca development/test |
| `sms.provider` | `none` | `none` \| `http` \| `log` |
| `sms.http_url` / `http_api_key` | — | `http` için zorunlu, https |
| `sms.http_auth_header` / `http_auth_scheme` | `authorization` / `Bearer` | Şema boşsa ham anahtar |
| `sms.http_body_template` | `{"to":"{{to}}","text":"{{text}}","from":"{{sender_id}}"}` | JSON nesnesi, ≤ 8 KiB, `{{to}}` ve `{{text}}` zorunlu |
| `sms.http_message_id_pointer` | — | JSON pointer |
| `sms.sender_id` | — | 1–16 karakter |
| `sms.timeout` | `10s` | 1 sn – 1 dk |

Ortama bağlı kurallar (`server.environment`'a erişim gerektirdiği için) açılışta builder'larda uygulanır: `log` taşıyıcısı ve `log` SMS göndericisi yalnızca development/test; `disabled` taşıyıcı production'da yok; `extra_ca_file` yalnızca development/test. `AppConfig::validate` production'da `log` taşıyıcısını ayrıca reddeder.

## Hata kodları (`crates/authn-core/src/error/codes/notify.rs`)

| Kod | HTTP | Anlam |
|-----|------|-------|
| `delivery_rejected` | 502 | Sağlayıcı mesajı kalıcı olarak reddetti (yeniden denenmez) |
| `sms_unavailable` | 503 | SMS sağlayıcısı yapılandırılmamış |

Geçici hatalar ortak `service_unavailable` kodunu kullanır.

## Metrikler

`authn_notifications_enqueued_total{channel}`, `authn_notifications_delivered_total{channel}`, `authn_notification_failures_total{channel,class=retry|permanent}`, `authn_notifications_dropped_total{channel,reason}`.

## HTTP endpoint'leri

Yok. NTF-01…04 bir endpoint tanımlamaz; modüller `Notifier`/`SmsSender` portlarını kullanır. Bu yüzden `router<S>()` ve `OpenApi` yapısı yoktur.

## Migration

Yok (`1800–1899` aralığı kullanılmadı); `outbox` tablosu ve indeksleri `0010`'da yeterli.

## Sunucunun (authn-server) bağlaması gerekenler

1. Açılışta (Tokio runtime içinde):

   ```rust,ignore
   let notify = authn_notify::NotifyServices::from_config(
       &config, pool.clone(), crypto.envelopes.clone(), clock.clone(),
       rate_limiter.clone(), http_client.clone(), // authn-protect'in SSRF korumalı istemcisi
   )?;
   // AppState: Arc<dyn Notifier> = notify.notifier_port(); Arc<dyn SmsSender> = notify.sms.clone() (authn-mfa)
   ```

2. Outbox köprüsü (`authn-audit`'in işçisine `notification` öneki için):

   ```rust,ignore
   struct NotificationBridge(Arc<authn_notify::NotificationDeliverer>);

   #[async_trait]
   impl authn_audit::OutboxHandler for NotificationBridge {
       async fn handle(&self, m: &authn_audit::OutboxMessage) -> Result<(), authn_audit::HandlerError> {
           let request = authn_notify::DeliveryRequest {
               id: m.id,
               topic: &m.topic,
               payload: &m.payload,
               sealed_payload: m.sealed_payload.as_ref().map(|s| s.as_bytes()),
               attempt: m.attempts,
               max_attempts: m.max_attempts,
           };
           self.0.deliver(request).await.map_err(|failure| match failure {
               authn_notify::DeliveryFailure::Retry { reason, retry_after } => {
                   authn_audit::HandlerError::Retry { reason: reason.into(), retry_after }
               }
               authn_notify::DeliveryFailure::Permanent { reason } => {
                   authn_audit::HandlerError::permanent(reason)
               }
           })
       }
   }

   let handlers = audit.outbox_handlers(http)?
       .register(authn_notify::NOTIFICATION_TOPIC_PREFIX, Arc::new(NotificationBridge(notify.deliverer.clone())))?;
   ```

3. `check-config`: `TemplateRenderer::from_config(&config)` şablonları doğrular (runtime gerekmez); taşıyıcıları denemek için runtime içinde `NotifyServices::from_config`.
4. authn-mfa: senkron SMS için `SmsSender` portu, asenkron/yeniden denenen SMS için `Notifier::notify_sms_in_tx`; `is_configured() == false` iken SMS faktörünü sunmamalı.

## Güvenlik notları

| Saldırı | Savunma |
|---------|---------|
| Host header zehirlenmesi / open redirect ile sıfırlama linki çalma | Linkler yalnızca `public_base_url` + yapılandırılmış yol; token biçimi doğrulanır; token fragment'ta |
| HTML enjeksiyonu (organizasyon adı, görünen ad) | `.html`'de zorunlu otomatik escape; `safe`/`autoescape` yasak; testler: `ntf_02_user_values_are_html_escaped` |
| Düz metin/konu/başlık enjeksiyonu (CRLF, `Bcc:`) | `sanitize` + SMTP taşıyıcısında yeniden temizleme; lettre RFC 2047 kodlaması |
| Kimlik avı içeriği (ad alanına URL, bidi ile ters çevrilmiş metin) | `://` etkisizleştirme, bidi/sıfır genişlikli karakter silme, uzunluk sınırı |
| SSTI (şablon enjeksiyonu) | Değerler asla şablon kaynağı olarak derlenmez |
| Sırların durağan halde sızması (DB yedeği, outbox) | Tüm bildirim zarf şifreli, AAD satıra bağlı; teslimde silinir |
| Sırların loglara/`Debug`'a sızması | `SensitiveString`, `RenderedEmail`/`EmailMessage`/`SmsMessage`/`DeliveryRequest` redakte `Debug`; log taşıyıcıları sırları `[REDACTED]` yapar ve production/staging'de yok; minijinja hata ayıklama kapalı; hata nedenleri statik |
| SMTP düşürme (STARTTLS stripping), sahte sunucu | `Tls::Required`/`Wrapper`, sertifika doğrulaması; testler `ntf_03_smtp_never_falls_back_to_plain_text`, `ntf_03_smtp_rejects_untrusted_server_certificates` |
| JSON enjeksiyonu (SMS sağlayıcısı) | Ağaç içinde tek geçişli yer tutucu değişimi |
| Mail/SMS bombalama | Alıcı başına sessiz limit; güvenlik uyarıları muaf |
| Hesap varlığı sızıntısı | Limit aşımı ve teslim hataları üreticiye asla hata olarak dönmez; teslim asenkron (yanıt süresi SMTP'ye bağlı değil) |
| Bayat link/kod | Süresi dolmuş link/kod teslim edilmez |
| Operatör şablonunda DoS | Yakıt sınırı, 64 KiB dosya sınırı, strict mod, açılış doğrulaması |
| Geçersiz kılınan şablonda escape'i atlatma | Her `{%` taranır; `safe`/`tojson`/`debug()` ortamdan kaldırıldı; `extends` yalnızca aynı türden tek bir dizge sabiti |
| Konu satırında sır | Konu şablonlarına `link`/`code` verilmez |
| Uç tarihli zaman damgasıyla panik | `checked_to_offset` (UTC'ye çevrilemeyen değer kendi ofsetinde yazılır) |

### Güvenlik incelemesi (2026-11-01)

Bağımsız inceleme bulguları ve durumları:

| Önem | Bulgu | Durum | Regresyon testi |
|------|-------|-------|-----------------|
| Orta | Ortak alıcı bütçesi: ucuz türler (kayıt girişimi, başkasının numarasına telefon doğrulaması) kurbanın giriş/MFA kodlarını aç bırakıyordu (kimlik doğrulamasız hesap kilitleme) | Düzeltildi — erişim sağlayan türlere ayrı bütçe | `ntf_01_cheap_kinds_cannot_starve_sign_in_and_mfa_codes` |
| Orta | Alıcı limiti `+etiket` (alt adres) ile tamamen aşılabiliyordu (mail bombalama) | Düzeltildi — anahtar etiketsiz posta kutusu | `ntf_01_recipient_limit_cannot_be_bypassed_with_plus_addressing` |
| Düşük | Escape koruması atlatılabiliyordu: boşluksuz anahtar kelime (`{%include"x"%}`, `{%extends"…txt"%}`), koşullu `extends`, `map("safe")`, `tojson` ile öznitelik kırma, konuda `debug()` | Düzeltildi | `ntf_02_escape_guards_cannot_be_bypassed_by_syntax_tricks` |
| Düşük | Geçersiz kılınan konu şablonu link/kodu konuya yazabiliyordu (`Debug`, log taşıyıcısı, kilit ekranı) | Düzeltildi | `ntf_02_subject_templates_cannot_reveal_links_or_codes` |
| Düşük | `OffsetDateTime::to_offset` desteklenen aralık dışında panik (teslim işçisini düşürür) | Düzeltildi | `ntf_02_out_of_range_timestamps_never_panic` |
| Bilgi | 32 KiB'den büyük bildirimde düz metin tamponu yeniden ayrılıp sıfırlanmamış kopya bırakıyordu | Düzeltildi | `ntf_01_sealed_plaintext_buffer_never_grows` |

Bilinçli olarak kabul edilen riskler (gerekçeli):

- **Üretici dalında zamanlama farkı.** `notify_in_tx` (limit kontrolü + zarf şifreleme + `INSERT`) yalnızca bildirim gönderen dalda maliyet doğurur; hesabın var olup olmadığını sızdırmaması gereken akışlarda (PWD-07, SES-18, ACC-02) eşdeğer işi yapmak üreticinin sorumluluğudur (aşağıdaki sınırlamalara bakın). Bu crate istek bağlamını görmez.
- **Aynı türde bütçe tüketme.** Saldırgan bir kurbanın örn. şifre sıfırlama bütçesini tüketebilir; her alıcı başına limitin doğal sonucudur ve üretici modüllerin hesap başına limitleriyle aynı etkidir. Türler ayrı bütçelerde olduğu için başka türleri etkilemez.
- **Limit arka ucu çöktüğünde fail-open.** Bildirimin (ör. şifre sıfırlama) kaybı, savunma derinliği limitinin bir süre çalışmamasından daha zararlıdır; üreticilerin kendi limitleri ve `authn-protect` limitleri geçerliliğini korur.
- **Limit, üretici transaction'ı commit edilmeden tüketilir.** Geri alınan işlemler de bütçeden düşer; yalnızca savunma derinliği limitidir.
- **Yalnızca `+` alt adres ayırıcısı katlanır.** Sağlayıcıya özgü kurallar (Gmail'de noktalar, bazı sağlayıcılarda `-`) bilinmez; yanlış katlama başka bir posta kutusunun bütçesini paylaştırırdı.
- **Güvenlik uyarıları kısılmaz.** `SuspiciousLoginBlocked` gibi uyarıları tekilleştirmek/sınırlamak üreticinin (RSK-03, authn-session) işidir; burada kısmak saldırganın uyarıları bastırmasına izin verirdi.
- **Saldırgan kontrollü cihaz/konum metni.** User-agent'tan gelen `device` uyarı e-postalarında görünür; kontrol/bidi karakterleri silinir, `://` etkisizleşir, 120 karakterle sınırlanır. Çıplak alan adı veya telefon numarası gibi sosyal mühendislik metni tamamen engellenemez.
- **Operatör şablonları güvenilirdir.** Şablon korumaları operatör hatalarına karşı savunma derinliğidir; şablon dizinine yazabilen kötü niyetli bir operatör zaten tüm yapılandırmayı kontrol eder. Tarama yanlış pozitif verebilir (yorum veya dizge içindeki `{% include` reddedilir) — bu bilinçli tercihtir.
- **`Debug` çıktısında kişisel veri.** `Recipient.display_name`, organizasyon adı ve cihaz açıklaması (sır değil, kişisel veri) türetilmiş `Debug`'da görünür; adres maskelenir, token/kod redakte edilir. Bu crate ve mevcut üreticiler `Notification`'ı loglamaz; üreticiler loglamamalıdır.

K-58 değerlendirmesi (2026-11-05): yukarıdaki maddeler gerekçeleriyle kalır.

- Zamanlama farkı ve aynı türde bütçe tüketme üretici sözleşmesidir.
- Kesintide açık başarısızlık bilinçli bir seçimdir: kayıp bildirim daha zararlıdır.
- Bütçenin commit'ten önce tüketilmesi yalnızca savunma derinliği limitini etkiler.
- Sağlayıcıya özgü alt adres katlaması yanlış katlamada başkasının bütçesini paylaştırır.
- Güvenlik uyarılarını kısmak saldırganın işine yarar.
- Saldırgan kontrollü cihaz metni temizlenir ve kısaltılır; sosyal mühendislik metni tamamen engellenemez.
- Operatör şablonları güven sınırının içindedir.
- `Debug` çıktısında kişisel veri: üreticiler `Notification`'ı loglamaz.

Bu dalgadaki değişiklik ADR 0002'nin "kod oltalama" kalıntısıyla ilgilidir: doğrulama e-postası kodun yanında, kodun yalnızca kayıt olunan uygulamada/tarayıcıda girilmesi ve kimseyle paylaşılmaması uyarısını taşır (TR/EN; `acc_04_k58_verification_mail_warns_against_sharing_the_code`).

## Bilinen sınırlamalar

- `notify_in_tx` maliyeti (limit kontrolü + zarf şifreleme + bir `INSERT`, birkaç ms) yalnızca bildirim gönderen dalda oluşur. Hesap varlığını sızdırmaması gereken akışlarda (PWD-07, SES-18, ACC-02) üretici, diğer dalda eşdeğer iş yapmalı ya da her iki dalda da bir bildirim kuyruğa almalıdır (ör. ACC-02'de `RegistrationAttempt`); SMTP süresi zaten istek yolunda değildir.
- Kullanıcının saat dilimi `Notifier` sözleşmesinde yok; tarihler UTC yazılır (`Recipient`'e alan eklemek kırıcı değişiklik olurdu).
- Render edilmiş gövdeler `EmailMessage` (port) içinde `String`'dir; deliverer gönderimden sonra sıfırlar, ancak lettre'nin ve minijinja'nın iç kopyaları ile SMTP parolasının lettre içindeki kopyası sıfırlanamaz. SMS isteğinin `OutboundRequest.body` kopyası da `HttpClient` uygulamasındadır.
- `dead` durumundaki satırların zarfı, `authn-audit`'in saklama temizliğine kadar (şifreli olarak) kalır.
- SMS için sağlayıcı tarafında idempotency anahtarı gönderilmez (`SmsMessage` portunda alan yok); en-az-bir-kez teslimde nadiren aynı kod iki kez gelebilir.
- Düz metindeki çıplak alan adları (`evil.example`) bazı istemcilerde otomatik link olabilir; organizasyon adları tırnak içinde ve 80 karakterle sınırlıdır.
- ~~Mailpit'in rastgele sertifikası~~ — **kapatıldı:** `docker-compose.yml` Mailpit'e depodaki sabit geliştirme sertifikasını bağlar (`config/dev-certs/mailpit.pem` / `mailpit.key`, `MP_SMTP_TLS_CERT` / `MP_SMTP_TLS_KEY`); development/test yapılandırması onu `notify.email.smtp.extra_ca_file` ile güvenir, staging ve production bu ayarı reddeder (bkz. `config/dev-certs/README.md`).

## Testler

- Birim: `templates::tests` (her tür × iki dil, escape, SSTI, link hedefi, konu enjeksiyonu, geçersiz kılma ve reddedilen şablonlar, yakıt), `sanitize` (proptest dahil), `links`, `format`, `email` (log redaksiyonu, ortam kuralları), `sms::http` (yer tutucu proptest'i, mesaj kimliği).
- Entegrasyon (`#[sqlx::test]`, gerçek PostgreSQL): `tests/outbox.rs` — tek satır + mühürleme, transaction'a bağlılık, uçtan uca teslim, AAD kopyala-yapıştır, kurcalama, konu/şablon uyumsuzluğu, bilinmeyen KEK → retry, süresi dolmuş link/kod, hata sınıflandırması, `Retry-After`, SMS outbox, sağlayıcısız SMS, alıcı limiti (güvenlik uyarıları muaf, fail-open), bozuk sırların reddi, düşmanca değerlerin tüm hattan güvenli geçişi.
- `tests/smtp.rs`: `tests/fixtures`'taki **yalnızca test** CA'sıyla yerel TLS SMTP sunucusu — STARTTLS + TLS sonrası AUTH, düz metne düşmeme, güvenilmeyen sertifika, örtük TLS, 5xx/4xx sınıflandırması, başlık enjeksiyonu, runtime dışı güvenli davranış, `extra_ca_file` ortam kuralı.
- `tests/sms_http.rs`: istek biçimi, hassas başlık, özel gövde şablonu, yanıt sınıflandırması, `Retry-After` sınırı, geçersiz gövdelerin gönderilmemesi, yapılandırma doğrulaması.
- `tests/services.rs`: yapılandırmadan kurulum, ortam kuralları, bozuk şablon dizini, `config/example.toml`'daki tüm `[notify]` anahtarları.

## Komutlar

```bash
cargo test -p authn-notify --all-features
cargo clippy -p authn-notify --all-targets --all-features -- -D warnings
cargo clippy -p authn-notify --all-targets --no-default-features -- -D warnings
cargo fmt -p authn-notify
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
