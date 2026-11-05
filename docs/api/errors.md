# Hata kodu kataloğu (DOC-04)

> **Üretilmiş tablo — elle düzenlemeyin.** Kaynak: `crates/authn-core/src/error/codes/*.rs` (her kod `ErrorCode::new(kod, durum, İngilizce, Türkçe)`), açıklama sütunu kodun kendi Türkçe mesajıdır; notlar `generate_reference.py` içindedir.

Toplam **128** kararlı kod. Yayımlanmış bir kod asla yeniden adlandırılmaz ve anlamı değişmez (contracts §8). İstemciler `message`'a değil `code`'a göre dallanmalıdır.

## Hata zarfı

Her 4xx/5xx yanıt (yönlendirici ve katmanlardan gelen JSON olmayan hatalar dahil) aynı zarfı taşır:

```json
{"error": {"code": "rate_limited", "message": "…", "request_id": "0190…", "details": {}}}
```

- `message`: `Accept-Language`'e göre (`tr` / `en`, yoksa `server.default_locale`) yerelleştirilmiş, kullanıcıya gösterilebilir metin. İç ayrıntı içermez; 5xx'te daima genel mesaj.
- `request_id`: sunucunun her istek için ürettiği UUIDv7; yanıtın `x-request-id` başlığıyla aynıdır. İstemcinin gönderdiği `x-request-id` yok sayılır.
- `details`: yalnızca bazı kodlarda, kimliği doğrulanmamış birine gösterilmesi güvenli yapılandırılmış bilgi (ör. `validation_failed` → alan adı, `password_policy_violation` → kural).
- `429` ve bazı `503` yanıtları `Retry-After` (saniye, yukarı yuvarlanmış, en az 1) taşır.
- Bearer token reddinde ayrıca `WWW-Authenticate: Bearer error="invalid_token"`.

Kodu doğrudan üreten bir handler yoksa (`method_not_allowed`, `payload_too_large` gibi) zarf, `authn_core::error::codes::common::for_status` ile durum kodundan türetilir (`crates/authn-core/src/http/context.rs`).

**Hesap varlığını sızdırmama:** kayıt, şifre sıfırlama, magic link, e-posta kodu ve giriş akışları var olan ve olmayan hesaplar için aynı durum, gövde ve benzer süreyle yanıt verir; bu akışlarda `conflict` veya "hesap bulunamadı" türünde bir kod görmezsiniz.

## Ortak (`codes::common`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `internal_error` | 500 | Beklenmeyen bir hata oluştu. Lütfen daha sonra tekrar deneyin. | İç ayrıntı yalnızca loglanır (`request_id` ile eşleştirin). |
| `bad_request` | 400 | İstek hatalı biçimlendirilmiş. | Bozuk JSON, yol parametresi, tekrarlanan başlık vb. Gövde içeriği yankılanmaz. |
| `validation_failed` | 422 | Bir veya daha fazla alan geçersiz. | `details` alan adlarını taşıyabilir. Bozuk sayfalama `cursor`'ı da bu koddur. |
| `unauthenticated` | 401 | Kimlik doğrulaması gerekiyor. | Kimlik bilgisi yok/geçersiz. Bearer hatasında ayrıca `WWW-Authenticate: Bearer error="invalid_token"`. |
| `forbidden` | 403 | Bu işlemi yapma yetkiniz yok. | Yetki yok (eksik organizasyon izni, salt-okunur impersonation altında yazma vb.). |
| `not_found` | 404 | İstenen kaynak bulunamadı. | Başka kiracının kaynağı da `404` (ORG-10). |
| `method_not_allowed` | 405 | Bu kaynak için bu yöntem desteklenmiyor. | Yalnızca yönlendirici tarafından üretilir (`for_status`). |
| `conflict` | 409 | İstek, kaynağın mevcut durumuyla çakışıyor. |  |
| `payload_too_large` | 413 | İstek gövdesi çok büyük. | `server.limits.body_limit_bytes` aşımı; katman tarafından üretilir. |
| `unsupported_media_type` | 415 | İstek içerik türü desteklenmiyor. |  |
| `request_timeout` | 408 | İstek zaman aşımına uğradı. | `server.limits.request_timeout` aşımı. |
| `rate_limited` | 429 | Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin. | `Retry-After` başlığıyla. Bkz. [rate-limiting.md](rate-limiting.md). |
| `too_many_attempts` | 429 | Çok fazla deneme yapıldı. Yeni bir kod isteyin veya daha sonra tekrar deneyin. | Bir kod/faktör için deneme hakkı bitti veya MFA geçici kilidi (`mfa.lockout_duration`; `Retry-After` ile). |
| `service_unavailable` | 503 | Hizmet geçici olarak kullanılamıyor. Lütfen daha sonra tekrar deneyin. | Havuz zaman aşımı, bağımlılık kesintisi. |
| `step_up_required` | 401 | Devam etmek için kimliğinizi yeniden doğrulayın. | `POST /v1/reauth` ile yeniden doğrulayıp isteği tekrarlayın. Organizasyonun oturum ömrü üst sınırı aşıldığında da döner. |
| `invalid_or_expired_token` | 400 | Bağlantı geçersiz veya süresi dolmuş. | Bilinmeyen/kullanılmış/iptal/süresi dolmuş link token'ı — ayırt edilmez. |
| `invalid_code` | 400 | Kod geçersiz veya süresi dolmuş. | Yanlış/süresi dolmuş kod — ayırt edilmez. |

## Oturum ve giriş (`codes::session`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `invalid_credentials` | 401 | Giriş bilgileri hatalı. | Tek tip: hesap yok, şifre yanlış, şifre yok. |
| `csrf_failed` | 403 | İstek doğrulanamadı. Sayfayı yenileyip tekrar deneyin. | Origin/`Sec-Fetch-Site` veya `X-CSRF-Token` denetimi başarısız. Bkz. [authentication.md](authentication.md#3-csrf). |
| `invalid_refresh_token` | 401 | Oturum sona erdi. Lütfen yeniden giriş yapın. | Bilinmeyen, süresi dolmuş, iptal edilmiş veya tekrar kullanılmış — hepsi aynı; tekrar kullanım aileyi iptal eder. |
| `reauthentication_failed` | 401 | Kimliğiniz doğrulanamadı. |  |
| `step_up_method_not_allowed` | 403 | Bu doğrulama yöntemi burada kullanılamaz. |  |
| `challenge_invalid` | 401 | Giriş isteğinin süresi doldu. Lütfen baştan başlayın. | Kullanılmış, süresi dolmuş, deneme hakkı bitmiş veya başka cihaz/istemci türü — tek tip. |
| `login_method_not_allowed` | 403 | Bu organizasyon kullandığınız giriş yöntemine izin vermiyor. İzin verilen bir yöntemle yeniden giriş yapın. | Organizasyon politikası bu giriş yöntemine izin vermiyor. K-57'den beri organizasyonu etkinleştirmemiş oturumlarda da **her** `/v1/orgs/{org_id}/…` isteğinde denetlenir. |
| `impersonation_not_allowed` | 403 | Bu hesabın yerine geçilemez. |  |
| `magic_link_confirmation_required` | 409 | Bu giriş bağlantısı başka bir cihazda istendi. Bu cihazda giriş yapmak için onaylayın. | Link başka bir cihazda açıldı; `confirm_other_device` ile yeniden gönderin. |
| `challenge_step_not_allowed` | 403 | Bu adım bu giriş için kullanılamaz. |  |

## Hesap (`codes::account`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `invalid_email` | 422 | E-posta adresi geçersiz. |  |
| `email_domain_not_allowed` | 422 | Bu alan adına ait e-posta adresleri kullanılamaz. Lütfen başka bir adres kullanın. |  |
| `invalid_display_name` | 422 | Görünen ad kabul edilmiyor. Tek bir alfabeden harfler, boşluk ve basit noktalama işaretleri kullanın. |  |
| `invalid_time_zone` | 422 | Saat dilimi geçerli bir IANA saat dilimi adı değil (örneğin Europe/Istanbul). |  |
| `email_unchanged` | 422 | Yeni e-posta adresi mevcut adresle aynı. |  |
| `email_already_verified` | 409 | E-posta adresiniz zaten doğrulanmış. |  |
| `email_verification_required` | 403 | Lütfen önce e-posta adresinizi doğrulayın. Doğrulama iletisi için gelen kutunuzu kontrol edin. |  |
| `account_locked` | 403 | Bu hesap geçici olarak kilitlendi. Lütfen daha sonra tekrar deneyin. |  |
| `account_suspended` | 403 | Bu hesap askıya alındı. Lütfen destek ekibiyle iletişime geçin. |  |
| `account_disabled` | 403 | Bu hesap devre dışı. |  |
| `account_status_transition_not_allowed` | 409 | Bu değişiklik hesabın mevcut durumunda yapılamaz. |  |
| `account_deletion_blocked_last_owner` | 409 | Bir organizasyonun son sahibisiniz. Hesabınızı silmeden önce sahipliği devredin. |  |
| `account_deletion_not_scheduled` | 409 | Planlanmış bir hesap silme işlemi yok. |  |
| `terms_acceptance_required` | 422 | Lütfen güncel kullanım şartlarını ve gizlilik politikasını kabul edin. |  |
| `terms_version_not_current` | 409 | Belgenin bu sürümü güncel değil. Lütfen sayfayı yenileyip güncel sürümü kabul edin. |  |
| `email_change_revert_conflict` | 409 | Önceki e-posta adresi artık geri yüklenemiyor. Lütfen destek ekibiyle iletişime geçin. |  |
| `registration_confirmation_required` | 403 | Tamamlamak için kayıt olurken seçtiğiniz şifreyi girin veya yeni bir şifre belirleyin. | Link kaydı yapan istemci dışında açıldı: `password` (kayıttaki şifre) veya `new_password` isteyin (ADR 0002). |
| `registration_password_mismatch` | 403 | Bu, bu kayıt için seçilen şifre değil. Kaydı siz yapmadıysanız bunun yerine yeni bir şifre belirleyin. |  |

## Şifre (`codes::password`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `password_policy_violation` | 422 | Şifre gereksinimleri karşılamıyor. |  |
| `password_breach_check_unavailable` | 503 | Şifre şu anda kontrol edilemiyor. Lütfen daha sonra tekrar deneyin. | HIBP erişilemedi ve `password.breach_check.fail_open = false`. |
| `current_password_incorrect` | 403 | Mevcut şifre hatalı. |  |
| `password_unchanged` | 422 | Yeni şifre mevcut şifreden farklı olmalıdır. |  |
| `password_already_set` | 409 | Bu hesabın zaten bir şifresi var. Bunun yerine şifreyi değiştirin. |  |
| `password_not_set` | 409 | Bu hesabın bir şifresi yok. |  |
| `password_removal_not_allowed` | 409 | Passkey gibi başka bir giriş yöntemi eklenmeden şifre kaldırılamaz. |  |

## MFA (`codes::mfa`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `mfa_factor_not_available` | 403 | Bu doğrulama yöntemi kullanılamıyor. |  |
| `mfa_factor_already_enrolled` | 409 | Bu doğrulama yöntemi zaten kurulu. |  |
| `mfa_factor_limit_reached` | 409 | En fazla doğrulama yöntemi sayısına ulaşıldı. Önce birini kaldırın. |  |
| `mfa_last_factor_required` | 409 | Bu hesap için iki adımlı doğrulama zorunlu; bu yöntemi kaldırmadan önce başka bir yöntem ekleyin. |  |
| `mfa_invalid_phone_number` | 422 | Telefon numarasını uluslararası biçimde girin, ör. +905551112233. |  |
| `mfa_phone_country_not_allowed` | 422 | Bu ülkeye ait telefon numaraları için SMS doğrulaması kullanılamıyor. |  |
| `mfa_enrollment_not_pending` | 409 | Bu doğrulama yöntemi için bekleyen bir kurulum yok. Kurulumu yeniden başlatın. |  |

## Passkey (`codes::webauthn`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `passkey_ceremony_invalid` | 400 | Passkey isteğinin süresi doldu veya artık geçerli değil. Lütfen tekrar deneyin. |  |
| `passkey_registration_failed` | 400 | Passkey kaydedilemedi. Lütfen tekrar deneyin. |  |
| `passkey_authentication_failed` | 401 | Passkey doğrulaması başarısız oldu. |  |
| `passkey_already_registered` | 409 | Bu passkey zaten kayıtlı. |  |
| `passkey_limit_reached` | 409 | En fazla passkey sayısına ulaşıldı. Önce birini kaldırın. |  |
| `passkey_last_login_method` | 409 | Bu, giriş yapmanın son yolu. Kaldırmadan önce bir şifre veya başka bir passkey ekleyin. |  |
| `passkey_not_allowed` | 403 | Bu güvenlik anahtarı veya passkey sağlayıcısına kuruluşunuz izin vermiyor. |  |
| `passkey_not_available` | 400 | Bu hesap için kullanılabilir bir passkey yok. |  |

## Organizasyon (`codes::org`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `org_slug_taken` | 409 | Bu organizasyon adresi zaten kullanılıyor. |  |
| `org_last_owner` | 409 | Bir organizasyonun en az bir sahibi olmalıdır. Önce başka bir üyeyi sahip yapın. |  |
| `org_role_escalation` | 403 | Kendinizde olmayan yetkileri veremez veya yönetemezsiniz. |  |
| `org_already_member` | 409 | Bu kullanıcı zaten organizasyonun üyesi. |  |
| `org_invitation_pending` | 409 | Bu adres için bekleyen bir davet zaten var. Bunun yerine daveti yeniden gönderin. |  |
| `org_invitation_email_mismatch` | 403 | Bu davet farklı bir e-posta adresine gönderildi. Davet edilen hesapla giriş yapın. |  |
| `org_email_verification_required` | 403 | Önce e-posta adresinizi doğrulayın. |  |
| `org_role_key_taken` | 409 | Bu anahtara sahip bir rol zaten var. |  |
| `org_builtin_role_immutable` | 409 | Yerleşik roller değiştirilemez. |  |
| `org_role_in_use` | 409 | Rol hâlâ atanmış durumda. Önce üyelerini, davetlerini ve servis hesaplarını başka role taşıyın. |  |
| `org_limit_reached` | 409 | Bu kaynak türü için sınıra ulaşıldı. |  |
| `org_domain_exists` | 409 | Bu alan adı organizasyona zaten eklenmiş. |  |
| `org_domain_claimed` | 409 | Bu alan adı başka bir organizasyon tarafından zaten doğrulanmış. |  |
| `org_domain_verification_failed` | 422 | Doğrulama TXT kaydı bulunamadı. DNS değişikliklerinin yayılması zaman alabilir. |  |
| `org_domain_not_verified` | 409 | Önce alan adını doğrulayın. |  |
| `org_policy_lockout` | 422 | Bu politika sizi organizasyonun dışında bırakır. Politikayı düzenleyin veya önce ona uygun şekilde giriş yapın. | Yeni politika çağıranı dışarıda bırakırdı; `details.reason` ∈ `ip_allowlist`, `mfa`, `login_method`. |
| `org_policy_ip_denied` | 403 | Bu organizasyona ağınızdan erişime izin verilmiyor. | İstemci IP'si organizasyonun izin listesinde değil. |
| `org_policy_mfa_required` | 403 | Bu organizasyon daha güçlü bir giriş gerektiriyor. İkinci faktörünüz veya passkey ile doğrulayın. | Organizasyon MFA / phishing'e dayanıklı MFA istiyor ya da oturumun ikinci faktörü `allowed_mfa_factors`'ta değil (K-57, K-78). İzinli faktörle step-up yapın. |
| `org_pending_deletion` | 409 | Organizasyon silinmek üzere planlandı. |  |
| `org_deletion_not_scheduled` | 409 | Organizasyon silinmek üzere planlanmamış. |  |
| `org_suspended` | 403 | Organizasyon askıya alınmış. |  |
| `org_owner_required` | 403 | Bunu yalnızca organizasyonun sahibi yapabilir. |  |
| `org_transfer_target_invalid` | 422 | Sahiplik yalnızca başka bir aktif üyeye devredilebilir. |  |
| `api_key_expiry_invalid` | 422 | Gelecekte ve izin verilen en uzun süre içinde bir son kullanma tarihi seçin. |  |
| `api_key_scope_invalid` | 422 | Bir veya daha fazla kapsam geçersiz ya da bu anahtara verilemez. |  |
| `api_key_inactive` | 409 | API anahtarı artık etkin değil. |  |
| `service_account_disabled` | 409 | Servis hesabı devre dışı. |  |
| `service_account_name_taken` | 409 | Bu ada sahip bir servis hesabı zaten var. |  |

## Sosyal giriş (`codes::oidc_client`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `oauth_provider_unknown` | 404 | Bu giriş sağlayıcısı kullanılamıyor. |  |
| `oauth_state_invalid` | 400 | Giriş isteğinin süresi doldu veya artık geçerli değil. Lütfen yeniden başlayın. |  |
| `oauth_nonce_invalid` | 400 | Giriş isteğinin süresi doldu veya artık geçerli değil. Lütfen yeniden başlayın. |  |
| `oauth_token_invalid` | 401 | Sağlayıcı ile giriş doğrulanamadı. |  |
| `oauth_authorization_denied` | 400 | Sağlayıcı ile giriş iptal edildi veya reddedildi. |  |
| `oauth_email_not_verified` | 403 | Sağlayıcınız doğrulanmış bir e-posta adresi bildirmedi. Adresi sağlayıcıda doğrulayın veya e-posta ile kaydolun. |  |
| `oauth_link_required` | 409 | Bu e-posta adresiyle bir hesap zaten var. O hesaba giriş yapın ve bu sağlayıcıyı hesap ayarlarınızdan bağlayın. | Adres başka bir hesaba ait; oturum açıp kimliği açıkça bağlayın. |
| `oauth_native_not_supported` | 400 | Bu sağlayıcı mobil uygulamadan kullanılamaz. |  |
| `identity_already_linked` | 409 | Bu sağlayıcı hesabı başka bir hesaba bağlı. |  |
| `identity_provider_already_linked` | 409 | Bu sağlayıcıya ait bir hesap zaten bağlı. Önce onu kaldırın. |  |
| `identity_last_login_method` | 409 | Bu, giriş yapmanın son yolu. Kaldırmadan önce bir şifre veya passkey ekleyin. |  |
| `identity_link_not_allowed` | 403 | Bir giriş sağlayıcısı bağlamadan önce e-posta adresinizi doğrulayın. |  |

## Koruma (`codes::protect`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `captcha_required` | 403 | Devam etmek için doğrulama adımını tamamlayın. | İsteği CAPTCHA yanıtıyla (`captcha` alanı) tekrarlayın. |
| `captcha_failed` | 403 | Doğrulama adımı başarısız oldu. Lütfen tekrar deneyin. |  |
| `login_temporarily_blocked` | 429 | Bu cihazdan çok fazla başarısız giriş denemesi yapıldı. Daha sonra tekrar deneyin, passkey veya güvenilir bir cihazla giriş yapın ya da şifrenizi sıfırlayın. | Hesap yumuşak kilitli (PRT-03); `Retry-After` taşıyabilir. |
| `suspicious_login_blocked` | 403 | Bu giriş şüpheli görüldüğü için engellendi. Hesap sahibine bildirim gönderildi. |  |
| `host_not_allowed` | 421 | Bu ana makine burada sunulmuyor. | `Host` `protect.allowed_hosts`'ta değil (`/health/` muaf). |
| `cors_origin_not_allowed` | 403 | Bu kaynaktan gelen çapraz kaynak isteklerine izin verilmiyor. | İzin listesi dışı origin'den veya izinsiz yöntem/başlıkla preflight. |
| `invalid_redirect` | 400 | Yönlendirme adresine izin verilmiyor. |  |
| `outbound_destination_not_allowed` | 422 | Hedef adrese izin verilmiyor. Herkese açık bir https adresi kullanın. | Kullanıcının verdiği URL özel/loopback adrese veya düz http'ye gidiyor (SSRF koruması). |

## Audit ve webhook (`codes::audit`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `webhook_url_invalid` | 422 | Webhook adresi, kimlik bilgisi içermeyen ve herkese açık bir https:// adresi olmalıdır. |  |
| `webhook_endpoint_limit_reached` | 409 | Bu organizasyon için izin verilen en fazla webhook uç noktası sayısına ulaşıldı. |  |
| `webhook_delivery_in_progress` | 409 | Bu teslimat hâlâ planlanmış durumda; tamamlanmasını bekleyin. |  |
| `webhook_endpoint_disabled` | 409 | Webhook uç noktası devre dışı. Önce etkinleştirin. |  |

## Bildirim (`codes::notify`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `delivery_rejected` | 502 | İleti teslim edilemedi. Lütfen adresi veya numarayı kontrol edip tekrar deneyin. | Sağlayıcı teslimi reddetti. |
| `sms_unavailable` | 503 | SMS gönderimi kullanılamıyor. | SMS sağlayıcısı yok veya `sms` özelliği derlenmedi. |

## Platform admin (`codes::admin`)

| Kod | HTTP | Anlam (sunucunun Türkçe mesajı) | Not |
|-----|------|----------------------------------|-----|
| `admin_phishing_resistant_mfa_required` | 403 | Yönetim konsolunu kullanmak için passkey ile giriş yapın. |  |
| `admin_reason_required` | 422 | Bu işlem için 1 ile 1000 arasında yazdırılabilir karakterden oluşan bir gerekçe gereklidir. |  |
| `admin_target_not_allowed` | 403 | Bu işlem bu hesap üzerinde yapılamaz. |  |
| `admin_confirmation_required` | 422 | Acil durum işlemini, adını onay alanına yazarak onaylayın. |  |
| `admin_approval_required` | 403 | Bu işlem ikinci bir platform yöneticisinin onayını gerektirir. |  |
| `admin_approval_invalid` | 403 | Onay bu işlem için geçerli değil. Yeni bir onay isteyin. |  |
| `admin_self_approval_not_allowed` | 403 | Bir istek farklı bir platform yöneticisi tarafından onaylanmalıdır. |  |
