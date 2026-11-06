# OWASP ASVS eşleme tablosu (DOC-03)

> **Durum:** `claude/compassionate-darwin-aa1tiy` dalı, `47c84a7` (2026-11-05).
>
> **Sürüm: OWASP ASVS 4.0.3.** ASVS 5.0 (2025) yayımlandı ve bölüm yapısı değişti (ör. kimlik doğrulama V6, oturum V7, yetkilendirme V8, kendi kendine yeten token'lar V9, OAuth/OIDC V10, kriptografi V11). Bu tablo, gereksinim numaralarını güvenilir biçimde eşleyebildiğimiz 4.0.3 numaralandırmasını kullanır. 5.0'a geçiş ayrı bir iş olarak yapılmalıdır (§11).
>
> **Kapsam:** kimlik doğrulama sistemiyle ilgili bölümler: V2 (kimlik doğrulama), V3 (oturum), V4 (erişim denetimi), V6 (saklanan kriptografi), V7 (hata işleme ve loglama), V8 (veri koruma), V13 (API), V14 (yapılandırma). V1, V5, V9 – V12 bu tabloda yok. ASVS düzeyleri (L1/L2/L3) bu belgede izlenmez.
>
> **Yöntem:** her satırın "Kod" sütunu açılıp okundu; "Test" sütunundaki her ad depoda `fn <ad>` olarak `grep` ile doğrulandı. Test adı yoksa bu açıkça yazılır. Davranışın yalnızca bir kısmı karşılanıyorsa satır "kısmi"dir ve eksik kısım "Not"tadır. "Kod" sütunundaki `crates/` ile başlamayan kısa yollar (ör. `password/legacy.rs`, `envelope/`, `headers.rs`) aynı tabloda yukarıda tam yoluyla anılan crate'in `src/` dizinine göredir.

Gösterim: ✅ karşılanıyor · 🟡 kısmi · ❌ karşılanmıyor · — uygulanmaz (N/A, gerekçesi notta)

## Özet

| Bölüm | ✅ | 🟡 | ❌ | — | Toplam |
|-------|----|----|----|----|--------|
| V2 Kimlik doğrulama | 38 | 12 | 0 | 7 | 57 |
| V3 Oturum yönetimi | 15 | 2 | 0 | 3 | 20 |
| V4 Erişim denetimi | 8 | 0 | 0 | 1 | 9 |
| V6 Saklanan kriptografi | 8 | 5 | 1 | 2 | 16 |
| V7 Hata işleme ve loglama | 9 | 3 | 0 | 0 | 12 |
| V8 Veri koruma | 11 | 3 | 0 | 3 | 17 |
| V13 API ve web servisleri | 19 | 2 | 0 | 0 | 21 |
| V14 Yapılandırma | 17 | 5 | 1 | 1 | 24 |
| **Toplam** | **125** | **32** | **2** | **17** | **176** |

Sayım tablodaki satırlardan üretildi. "Karşılanıyor" olup adında gereksinim kimliği taşıyan bir testi olmayan satırlar "Test" sütununda ayrıca belirtilir.

Karşılanmayan iki madde: **V6.4.2** (anahtar materyali uygulama belleğinde; KMS/HSM yok, Faz 2 K-96) ve **V14.4.2** (API yanıtlarında genel `Content-Disposition: attachment` yok).

## V2 — Kimlik doğrulama

### V2.1 Şifre güvenliği

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.1.1 | Kullanıcı şifresi en az 12 karakter | ✅ | `crates/authn-core/src/config/password.rs` (`min_length` = 12), `crates/authn-password/src/policy/` | `pwd_01_defaults_follow_the_specification`, `pwd_01_length_limits_are_enforced_in_characters` | Varsayılan 12. İşletmeci `password.min_length`'i 8'e kadar düşürebilir (doğrulama aralığı 8–64); bu durumda madde karşılanmaz |
| 2.1.2 | En az 64 karakter izinli, 128'den uzunu reddedilir | ✅ | `crates/authn-core/src/config/password.rs` (`max_length` = 128, 64–1024) | `pwd_01_length_limits_are_enforced_in_characters`, `pwd_01_invalid_values_are_reported_by_key` | Uzunluk NFKC sonrası karakterle ölçülür |
| 2.1.3 | Şifre kırpılmaz | ✅ | `crates/authn-crypto/src/password/canonical.rs` | `pwd_02_length_and_verdict_use_the_nfkc_form`, `cry_01_oversized_input_is_refused` | Kırpma yok; aşırı uzun girdi reddedilir. Tek istisna: eski bcrypt hash'leri (yalnızca göç, ilk girişte Argon2id'ye geçer) ilk 72 baytı kullanır |
| 2.1.4 | Her yazdırılabilir Unicode karakter ve boşluk izinli | ✅ | `crates/authn-password/src/policy/` | `pwd_01_no_composition_rules_lowercase_passphrase_with_spaces_is_accepted`, `pwd_02_nfkc_normalization_is_applied` | — |
| 2.1.5 | Kullanıcı şifresini değiştirebilir | ✅ | `crates/authn-password/src/service/manage.rs` | `pwd_06_change_with_current_password_revokes_other_sessions_and_notifies` | — |
| 2.1.6 | Değiştirme mevcut ve yeni şifreyi ister | 🟡 | `service/manage.rs` | `pwd_06_wrong_current_password_is_refused_audited_and_rate_limited`, `pwd_06_change_without_current_password_requires_recent_step_up` | PWD-06 gereği mevcut şifre **ya da** son `session.step_up_max_age` (10 dk) içinde yapılmış step-up yeterlidir |
| 2.1.7 | Kayıt, giriş ve değiştirmede sızdırılmış şifre kontrolü (k-anonymity) | 🟡 | `crates/authn-password/src/breach.rs`, `policy/` | `pwd_03_only_the_five_character_prefix_is_sent_with_padding`, `pwd_03_breached_password_is_rejected_with_feedback` | Yeni şifre belirlenen her yolda (kayıt, değiştirme, sıfırlama, ekleme) kontrol edilir. **Girişte** kontrol yapılmaz. HIBP erişilemezse varsayılan açık başarısızlıktır (`password.breach_check.fail_open`) |
| 2.1.8 | Şifre gücü göstergesi | ✅ | `crates/authn-password/src/routes.rs` (şifre kontrol ucu, PWD-05) | `pwd_05_check_endpoint_returns_verdict_with_localized_feedback`, `pwd_04_weak_passwords_fail_the_minimum_score_with_localized_feedback` | Gösterge API ile sağlanır; arayüz istemcinindir |
| 2.1.9 | Karakter sınıfı kuralı yok | ✅ | `policy/` | `pwd_01_no_composition_rules_lowercase_passphrase_with_spaces_is_accepted` | — |
| 2.1.10 | Periyodik rotasyon / şifre geçmişi yok | ✅ | `crates/authn-password/` | Test yok (yokluk) | Şifre geçmişi ve zorunlu periyodik değişiklik yok. Admin `must_change_password` (PWD-12) ve acil toplu sıfırlama (ADM-06) olay bazlıdır |
| 2.1.11 | Yapıştırma ve şifre yöneticileri izinli | — | — | — | Arayüz istemcinindir (API-öncelikli sistem) |
| 2.1.12 | Maskelenmiş şifreyi geçici gösterme | — | — | — | Arayüz istemcinindir |

### V2.2 Genel kimlik doğrulayıcı güvenliği

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.2.1 | Kaba kuvvet, credential stuffing ve kilitleme saldırılarına karşı otomasyon kontrolleri | ✅ | `crates/authn-protect/src/login.rs`, `rate_limit/`, `captcha/` | `ses_01_concurrent_guesses_cannot_outrun_the_captcha_budget`, `prt_02_captcha_is_required_after_identifier_failures`, `prt_03_soft_lock_blocks_only_untrusted_password_attempts`, `prt_02_login_attempts_per_ip_are_limited_with_retry_after` | Yumuşak kilit hesabı kapatmaz (PRT-03) |
| 2.2.2 | Zayıf doğrulayıcılar (SMS, e-posta) yalnızca ikincil doğrulamada | 🟡 | `crates/authn-session/src/login/passwordless.rs`, `crates/authn-mfa/` | `mfa_06_sms_unavailable_without_provider_or_countries`, `ses_21_organization_login_methods_apply_to_passwordless_logins` | SMS yalnızca ikinci faktördür. Ancak magic link ve e-posta kodu (SES-18/19) **birincil** giriş yöntemidir. Organizasyonlar bunları izinli giriş yöntemlerinden çıkarabilir; e-posta girişi "son yöntem" kurallarında güçlü yöntem sayılmaz |
| 2.2.3 | Kimlik bilgisi değişikliklerinde ve riskli girişte bildirim | ✅ | `crates/authn-notify/`, üretici modüller | `pwd_06_change_with_current_password_revokes_other_sessions_and_notifies`, `mfa_07_removal_notifies_audits_and_revokes_trusted_devices`, `acc_07_link_confirmation_changes_address_and_notifies_old_one`, `rsk_04_new_device_login_sends_notification_with_not_me_token` | Kurtarma kodu yeniden üretimi bildirilmez (audit'lenir; bkz. 2.5.5) |
| 2.2.4 | Phishing'e dayanıklılık (kriptografik çok faktör) | ✅ | `crates/authn-webauthn/`, `crates/authn-mfa/src/policy.rs` | `ses_21_passkey_satisfies_mfa_and_phishing_resistant_policy`, `mfa_08_only_webauthn_is_phishing_resistant`, `adm_01_rejects_admin_without_passkey_amr` | Passkey her kullanıcıya açıktır; platform adminleri ve politikası isteyen organizasyonlar için zorunludur |
| 2.2.5 | CSP ile doğrulayıcı ayrıysa karşılıklı TLS | — | — | — | Tek bileşen; ayrı kimlik bilgisi sağlayıcısı yok |
| 2.2.6 | Tekrar oynatmaya dayanıklılık | ✅ | `crates/authn-crypto/src/totp.rs`, `crates/authn-mfa/`, `crates/authn-store/src/one_time_tokens.rs` | `mfa_02_totp_code_cannot_be_replayed`, `mfa_04_recovery_code_is_single_use_and_notifies`, `pky_01_authentication_ceremony_is_single_use` | — |
| 2.2.7 | Kimlik doğrulama niyeti (OTP girişi veya kullanıcı eylemi) | ✅ | `crates/authn-webauthn/src/service/authentication.rs` | `pky_02_passwordless_login_requires_user_verification`, `pky_02_step_up_round_trip_requires_a_user_verifying_passkey` | — |

### V2.3 Kimlik doğrulayıcı yaşam döngüsü

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.3.1 | Sistemin ürettiği ilk şifre/aktivasyon kodu rastgele, kısa ömürlü, kalıcı şifre olmaz | ✅ | `crates/authn-admin/src/break_glass.rs`, `crates/authn-server/src/cli.rs` | `adm_05_cli_create_admin_prints_the_one_time_password_exactly_once`, `adm_05_k11_break_glass_passkey_enrollment_link` | Normal kullanıcıya sistem şifre üretmez. Break-glass `create-admin` 256 bit rastgele bir şifre üretir; bu şifre tek kullanımlıktır: 24 saat sonra geçersiz olur ve ilk girişte değiştirilmesi zorunludur (K-110, `adm_05_k110_break_glass_initial_password_is_one_time_and_expires`). Önerilen yol `--passkey-link`'tir (tek kullanımlık, varsayılan 30 dk) |
| 2.3.2 | Kullanıcının kendi cihazlarını (FIDO/U2F) kaydedebilmesi | ✅ | `crates/authn-webauthn/` | `pky_01_registration_round_trip_stores_a_verified_passkey`, `tst_06_passkey_registration_step_up_and_login` | — |
| 2.3.3 | Süreli doğrulayıcılar için yenileme talimatı | — | — | — | Süreli kullanıcı doğrulayıcısı yok. API anahtarlarının son kullanma tarihi zorunludur (ORG-08), yenileme bildirimi yoktur |

### V2.4 Kimlik bilgisi saklama

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.4.1 | Şifreler tuzlu, onaylı bir şifre hash fonksiyonuyla | ✅ | `crates/authn-crypto/src/password/argon.rs` | `cry_01_hash_is_argon2id_phc_with_configured_parameters` | Argon2id |
| 2.4.2 | Tuz ≥ 32 bit, kimlik bilgisine özgü | ✅ | `password/argon.rs` | `cry_01_hash_is_argon2id_phc_with_configured_parameters`, `cry_14_argon2id_reference_phc_vector` | 16 bayt (128 bit) CSPRNG tuzu |
| 2.4.3 | PBKDF2 kullanılıyorsa ≥ 100 000 iterasyon | — | `password/legacy.rs` | `cry_04_pbkdf2_verifies_and_must_be_upgraded` | PBKDF2 yalnızca içe aktarılmış eski hash'leri doğrulamak içindir; ilk girişte Argon2id'ye geçilir. Eski hash'in iterasyon sayısı içe aktaran sistemindir |
| 2.4.4 | bcrypt kullanılıyorsa maliyet ≥ 10 | — | `password/legacy.rs` | `cry_04_bcrypt_rejects_variants_and_dos_costs` | Yalnızca eski hash doğrulaması (maliyet 4–15 kabul edilir) |
| 2.4.5 | Gizli tuz (pepper) ile ek KDF/HMAC, ayrı saklanır | 🟡 | `crates/authn-crypto/src/password/pepper.rs` | `cry_02_the_pepper_is_part_of_the_hash`, `cry_02_cry_03_pepper_rotation_upgrades_on_login` | `HMAC-SHA256(pepper, şifre)`, pepper ≥ 256 bit ve veritabanından ayrı (yapılandırma). ASVS'nin önerdiği HSM'de saklama yok (Faz 2, K-96) |

### V2.5 Kimlik bilgisi kurtarma

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.5.1 | Kurtarma sırrı açık metin olarak gönderilmez | ✅ | `crates/authn-notify/src/links.rs`, `email/` | `ntf_02_links_use_only_the_public_base_url_and_configured_path`, `ntf_03_smtp_never_falls_back_to_plain_text` | Şifre asla e-postayla gönderilmez; tek kullanımlık bağlantı token'ı URL parçasındadır; SMTP'de TLS zorunlu |
| 2.5.2 | Şifre ipucu / gizli soru yok | ✅ | — | Test yok (yokluk) | Kodda böyle bir yöntem yok |
| 2.5.3 | Kurtarma mevcut şifreyi açıklamaz | ✅ | `crates/authn-password/src/service/reset.rs` | `pwd_09_reset_endpoint_replaces_the_password_without_issuing_a_session` | Yalnızca hash saklanır |
| 2.5.4 | Paylaşılan / varsayılan hesap yok | ✅ | `crates/authn-server/src/cli.rs` (`create-admin`), `config/` | `ops_08_example_keys_are_refused_in_production`, `adm_05_break_glass_admin_creation` | Hiçbir hesap tohumlanmaz; admin yalnızca CLI ile, belirtilen adresle oluşturulur |
| 2.5.5 | Doğrulama faktörü değişince kullanıcıya bildirim | 🟡 | `crates/authn-mfa/`, `crates/authn-webauthn/`, `crates/authn-oidc-client/` | `mfa_07_removal_notifies_audits_and_revokes_trusted_devices`, `pky_05_clone_suspicion_notifies_the_owner_once`, `soc_06_link_and_unlink_notify_the_account_owner`, `mfa_07_admin_reset_removes_everything_and_notifies` | Kurtarma kodu **yeniden üretimi** e-posta bildirimi göndermez (MFA-04 yalnızca kullanımı ister; `authn-mfa` README) |
| 2.5.6 | Unutulan şifre için güvenli kurtarma mekanizması | 🟡 | `crates/authn-password/src/service/reset.rs` | `pwd_07_reset_token_is_256_bit_single_use_and_only_its_hash_is_stored`, `pwd_09_reset_revokes_every_session_refresh_token_and_trusted_device`, `tst_06_password_reset_ends_every_session_and_trusted_device` | E-postayla tek kullanımlık bağlantı/kod; sıfırlama MFA'yı atlatmaz. ASVS'nin örneklediği TOTP/push tabanlı kurtarma yok |
| 2.5.7 | Faktör kaybında kayıttaki düzeyde kimlik kanıtı | 🟡 | `crates/authn-mfa/src/recovery.rs`, `crates/authn-admin/src/service/actions.rs` | `ses_02_native_challenge_with_recovery_code`, `adm_03_reset_mfa_removes_passkeys_and_they_no_longer_authenticate` | Kurtarma kodu veya gerekçeli admin MFA sıfırlaması. Kimlik kanıtlama süreci işletmecinin destek prosedürüdür, yazılımla zorlanmaz |

### V2.6 Arama (look-up) sırları

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.6.1 | Tek kullanımlık | ✅ | `crates/authn-mfa/src/store/` | `mfa_04_recovery_code_is_single_use_and_notifies`, `mfa_04_concurrent_use_of_the_same_code_has_exactly_one_winner` | — |
| 2.6.2 | ≥ 112 bit, değilse benzersiz tuzla hash | 🟡 | `crates/authn-mfa/src/recovery.rs` | `mfa_04_alphabet_has_32_unambiguous_symbols_and_50_bits`, `mfa_04_hash_is_keyed_and_bound_to_the_user` | 50 bit (MFA-04 asgarisi). Rastgele tuz yerine sunucu anahtarlı HMAC + kullanıcı kimliği bağlaması kullanılır |
| 2.6.3 | Çevrimdışı saldırıya dayanıklı | ✅ | `recovery.rs` | `mfa_04_hash_is_keyed_and_bound_to_the_user` | Anahtar (`RecoveryCode` HKDF amacı) olmadan veritabanı sızıntısı 2^50 uzayında kaba kuvvete yetmez |

### V2.7 Bant dışı (out-of-band) doğrulayıcı

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.7.1 | SMS varsayılan olarak sunulmaz | ✅ | `crates/authn-core/src/config/mfa.rs`, `crates/authn-mfa/` | `mfa_06_sms_unavailable_without_provider_or_countries` | Ülke listesi boşsa SMS kapalı (varsayılan) |
| 2.7.2 | Bant dışı kodlar 10 dk'da sona erer | 🟡 | `crates/authn-core/src/config/mfa.rs`, `crates/authn-core/src/config/session.rs`, `crates/authn-core/src/config/password.rs`, `crates/authn-core/src/config/account.rs` | `mfa_05_code_expires_after_ten_minutes`, `pwd_07_link_expires_after_thirty_minutes_and_code_after_fifteen` | MFA e-posta/SMS kodu ve e-posta giriş kodu 10 dk. Şifre sıfırlama kodu ve kayıt doğrulama kodu **15 dk**, magic link 15 dk (yapılandırılabilir) |
| 2.7.3 | Tek kullanımlık ve yalnızca asıl isteğe bağlı | ✅ | `crates/authn-store/src/one_time_tokens.rs`, `crates/authn-mfa/src/service/codes.rs` | `mfa_05_code_of_a_challenge_is_useless_elsewhere`, `ses_19_code_is_bound_to_the_requesting_device`, `cry_07_correct_code_is_single_use_and_purpose_bound` | — |
| 2.7.4 | Güvenli, bağımsız kanal | ✅ | `crates/authn-notify/src/email/`, `sms/` | `ntf_03_smtp_never_falls_back_to_plain_text`, `ntf_03_smtp_rejects_untrusted_server_certificates` | SMTP STARTTLS/TLS zorunlu; SMS sağlayıcısına SSRF-güvenli HTTP |
| 2.7.5 | Yalnızca kodun hash'i saklanır | ✅ | `crates/authn-crypto/src/otp.rs` | `cry_07_hash_is_keyed_and_purpose_bound` | Anahtarlı HMAC, amaca bağlı |
| 2.7.6 | Kod ≥ 20 bit entropi, CSPRNG | ✅ | `otp.rs`, `random.rs` | `cry_07_generated_codes_are_uniform`, `cry_07_codes_are_six_digits` | 6 hane (ASVS "altı haneli rastgele sayı genellikle yeterli" der); modulo yanlılığı yok |

### V2.8 Tek kullanımlık (OTP) doğrulayıcı

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.8.1 | TOTP'nin tanımlı ömrü var | ✅ | `crates/authn-crypto/src/totp.rs` | `mfa_01_codes_of_the_adjacent_steps_are_accepted`, `mfa_01_parameters_are_bounded` | 30 sn, ±1 adım |
| 2.8.2 | OTP doğrulama anahtarları korunur | 🟡 | `crates/authn-mfa/src/service/enroll.rs` | `mfa_01_secret_is_envelope_encrypted_and_bound_to_its_row` | Zarf şifreli (XChaCha20-Poly1305, AAD satıra bağlı). HSM yok |
| 2.8.3 | Onaylı algoritmalar | ✅ | `totp.rs` | `cry_14_totp_rfc6238_vectors`, `cry_14_hotp_rfc4226_vectors` | RFC 6238 HMAC-SHA-1 (uyumluluk) |
| 2.8.4 | TOTP geçerlilik süresinde bir kez | ✅ | `totp.rs`, `crates/authn-mfa/src/service/verify.rs` | `mfa_02_totp_code_cannot_be_replayed`, `mfa_02_concurrent_duplicate_submissions_only_one_succeeds` | — |
| 2.8.5 | Tekrar kullanım loglanır, reddedilir, sahibine bildirilir | 🟡 | `verify.rs` | `mfa_02_totp_code_cannot_be_replayed` | Reddedilir ve başarısız doğrulama sayılır (`mfa.failed`). Sahibine ayrı bildirim **gönderilmez** |
| 2.8.6 | Fiziksel OTP üreteci iptal edilebilir | ✅ | `crates/authn-mfa/src/service/manage.rs` | `mfa_07_http_step_up_and_removal` | Her faktör silinebilir; ayrıca admin MFA sıfırlaması |
| 2.8.7 | Biyometri yalnızca ikincil faktör | — | — | — | Sunucu biyometri işlemez; platform UV'si WebAuthn'ün parçasıdır |

### V2.9 Kriptografik doğrulayıcı

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.9.1 | Doğrulamada kullanılan anahtarlar korunur | ✅ | `crates/authn-webauthn/src/store/` | `pky_04_list_shows_metadata_without_key_material` | Sunucu yalnızca passkey açık anahtarlarını saklar |
| 2.9.2 | Challenge nonce'u ≥ 64 bit, benzersiz | ✅ | `webauthn-rs-core` 0.6.2 (`CHALLENGE_SIZE_BYTES = 32`) | `pky_01_registration_ceremony_is_single_use`, `pky_01_authentication_ceremony_is_single_use` | 256 bit; seremoni tek kullanımlık ve süreli |
| 2.9.3 | Onaylı algoritmalar | ✅ | `webauthn-rs` | `pky_01_registration_round_trip_stores_a_verified_passkey`, `pky_02_discoverable_login_round_trip` | — |

### V2.10 Servis kimlik doğrulaması

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 2.10.1 | Servisler arası sırlar değişmeyen kimlik bilgilerine dayanmaz | 🟡 | `crates/authn-org/src/api_key.rs`, `service/api_keys.rs` | `org_08_expiry_is_mandatory_and_bounded`, `org_08_api_keys_are_limited_by_scopes_and_bound_to_their_org` | Makine kimlik doğrulaması API anahtarıyladır (kapsamlı, son kullanma zorunlu, en çok 1 yıl, rotasyon). Kısa ömürlü OAuth `client_credentials` yok (Faz 2, K-84) |
| 2.10.2 | Servis hesabı varsayılan kimlik bilgisi kullanmaz | ✅ | `crates/authn-org/src/service/service_accounts.rs` | `org_09_service_accounts_are_org_owned_and_authenticate_by_key_only` | Servis hesabının kimlik bilgisi yalnızca oluşturulan API anahtarıdır; varsayılan yok |
| 2.10.3 | Şifreler çevrimdışı kurtarmaya karşı korunur | ✅ | `crates/authn-org/src/api_key.rs` | `org_08_debug_never_contains_the_key` | API anahtarları yalnızca SHA-256 olarak saklanır (256 bit rastgele değer) |
| 2.10.4 | Sırlar kaynak kodda değil | ✅ | `crates/authn-core/src/config/mod.rs` (`reject_public_keys`) | `cry_02_published_keys_are_refused_in_production`, `ops_08_example_keys_are_refused_in_production` | `config/example.toml`'daki anahtarlar yayımlanmış örneklerdir ve üretim/staging'de reddedilir |

## V3 — Oturum yönetimi

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 3.1.1 | Oturum token'ı URL'de yok | ✅ | `crates/authn-session/src/cookies.rs`, `middleware.rs`; `crates/authn-notify/src/links.rs` | `ses_03_session_cookie_is_host_prefixed_http_only_secure_lax`, `ntf_02_links_use_only_the_public_base_url_and_configured_path` | Oturum çerezde, Bearer başlıkta; e-posta bağlantılarındaki tek kullanımlık token URL parçasında |
| 3.2.1 | Kimlik doğrulamada yeni oturum token'ı | ✅ | `crates/authn-session/src/service/establish.rs` | `ses_03_cookie_authenticates_and_every_login_gets_a_fresh_session` | MFA, org değiştirme ve step-up'ta da yenilenir |
| 3.2.2 | Token ≥ 64 bit entropi | ✅ | `crates/authn-crypto/src/token.rs` | `cry_06_tokens_have_256_bits_and_canonical_form` | 256 bit |
| 3.2.3 | Tarayıcıda yalnızca güvenli çerezde | ✅ | `cookies.rs` | `ses_03_session_cookie_attributes` | Web için `HttpOnly` çerez. Web impersonation token'ı konsol belleğinde tutulur (bilinçli, K-12) |
| 3.2.4 | Onaylı algoritmalarla üretim | ✅ | `token.rs`, `random.rs` | `cry_06_random_bytes_differ`, `cry_06_generated_tokens_are_unique` | İşletim sistemi CSPRNG'si |
| 3.3.1 | Çıkış ve süre dolumu token'ı geçersiz kılar | ✅ | `crates/authn-session/src/service/manage.rs`, `authenticate.rs` | `ses_12_logout_revokes_clears_cookie_and_site_data`, `ses_05_revoked_session_rejects_its_access_tokens_at_once`, `ses_06_idle_expiry_and_absolute_expiry_with_fake_clock` | Bearer token'larda oturum kontrolü üretimde kapatılamaz |
| 3.3.2 | Periyodik yeniden kimlik doğrulama (L1: 30 gün; L2: 12 sa veya 30 dk boşta) | 🟡 | `crates/authn-core/src/config/session.rs` | `ses_06_defaults_follow_the_specification_and_validate`, `ses_06_refresh_never_extends_the_absolute_expiry` | Web: boşta 2 sa / mutlak 12 sa; beni hatırla: 14 gün / 30 gün; refresh: 30 gün / 90 gün. Mutlak süre uzamaz. L2'nin 30 dk boşta sınırı varsayılanla karşılanmaz (yapılandırılabilir); native refresh mutlak süresi 90 gün |
| 3.3.3 | Şifre değişince diğer oturumları kapatma | ✅ | `crates/authn-password/src/service/manage.rs` | `pwd_06_change_with_current_password_revokes_other_sessions_and_notifies` | Seçenek değil, her zaman yapılır |
| 3.3.4 | Aktif oturumları görme ve kapatma | 🟡 | `crates/authn-session/src/routes.rs`, `service/manage.rs` | `ses_11_session_list_masks_ip_and_marks_the_current_session`, `ses_11_revoke_others_keeps_the_current_session`, `ses_12_logout_everywhere_revokes_all_sessions_and_trusted_devices` | ASVS kapatmadan önce yeniden kimlik doğrulama ister; oturum kapatma uçları step-up istemez |
| 3.4.1 | `Secure` | ✅ | `cookies.rs` | `ses_03_session_cookie_is_host_prefixed_http_only_secure_lax` | — |
| 3.4.2 | `HttpOnly` | ✅ | `cookies.rs` | `ses_03_session_cookie_is_host_prefixed_http_only_secure_lax` | — |
| 3.4.3 | `SameSite` | ✅ | `cookies.rs` | `ses_03_session_cookie_is_host_prefixed_http_only_secure_lax` | Oturum `Lax`; challenge, kayıt tutamacı, passkey bağlama ve login CSRF çerezleri `Strict` |
| 3.4.4 | `__Host-` öneki | ✅ | `cookies.rs` | `ses_03_session_cookie_attributes`, `ses_03_cookie_tossing_is_ambiguous` | — |
| 3.4.5 | En dar `Path` | ✅ | `cookies.rs` | `ses_03_session_cookie_attributes` | `__Host-` öneki `Path=/` gerektirir; alt alan adı paylaşımı `__Host-` ile engellenir |
| 3.5.1 | Bağlı uygulamaların OAuth token'larını iptal | — | — | — | Sistem OAuth sağlayıcısı değil (Faz 2, K-80). Sosyal kimlik ayırma vardır (`soc_06_link_and_unlink_notify_the_account_owner`) |
| 3.5.2 | Statik API sırları yerine oturum token'ları | ✅ | `crates/authn-session/`, `crates/authn-org/src/api_key.rs` | `ses_10_api_keys_authenticate_only_on_organization_routes`, `org_08_api_keys_only_authenticate_organization_paths` | İnsan kullanıcılar oturum/JWT kullanır; API anahtarları yalnızca makineler için ve yalnızca org uçlarında |
| 3.5.3 | Durumsuz token'lar imzalı, kurcalamaya ve anahtar değiştirmeye dayanıklı | ✅ | `crates/authn-crypto/src/jwt.rs` | `cry_09_alg_none_and_symmetric_algorithms_are_rejected`, `cry_09_kid_and_typ_are_enforced`, `cry_09_any_modification_breaks_the_signature` | [ADR 0001](../architecture/adr/0001-jwt-implementation.md) |
| 3.6.1 | RP'nin azami kimlik doğrulama süresini belirtmesi | — | — | — | Sistem bir CSP/IdP olarak dış RP'lere hizmet etmez (Faz 2) |
| 3.6.2 | CSP'nin son kimlik doğrulamayı RP'ye bildirmesi | — | `crates/authn-session/src/claims.rs` | `ses_08_access_token_claims_follow_rfc_9068_without_personal_data` | Uygulanmaz (Faz 2); access token zaten `auth_time` taşır |
| 3.7.1 | Hassas işlemlerden önce yeniden doğrulama | ✅ | `crates/authn-core/src/domain/principal.rs` (`require_recent_authentication`) | `ses_13_step_up_window`, `acc_07_email_change_requires_step_up`, `acc_09_deletion_requires_step_up_and_a_session`, `acc_10_export_requires_step_up_and_is_rate_limited`, `mfa_07_factor_changes_require_step_up_and_a_real_session` | SES-13 listesi |

## V4 — Erişim denetimi

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 4.1.1 | Erişim kuralları güvenilir servis katmanında | ✅ | `crates/authn-org/src/authz.rs`, `crates/authn-admin/src/guard.rs` | `org_03_default_deny_and_role_permissions`, `adm_01_authorization_matrix_with_real_sessions` | — |
| 4.1.2 | Erişim kararındaki öznitelikler kullanıcı tarafından değiştirilemez | ✅ | `crates/authn-core/src/domain/principal.rs`, `crates/authn-session/src/service/authenticate.rs` | `org_07_k57_bearer_token_does_not_inherit_factors_of_a_later_step_up`, `ses_08_tampered_and_foreign_tokens_are_rejected_by_the_middleware` | `Principal` sunucuda, oturum kaydından ve imzalı token'dan kurulur |
| 4.1.3 | En az yetki | ✅ | `migrations/2900_least_privilege.sql`, `2901_least_privilege_no_temp.sql`, `crates/authn-org/src/permission.rs` | `ops_10_least_privilege_grants_are_exact`, `ops_10_the_application_runs_as_the_restricted_role`, `org_08_api_keys_are_limited_by_scopes_and_bound_to_their_org` | Personel için ayrıntılı roller yok (tek "platform admin", Faz 2 K-93) |
| 4.1.5 | Hata durumunda güvenli başarısızlık | ✅ | `authz.rs`, `crates/authn-server/src/hooks.rs` | `org_03_unknown_database_values_grant_nothing`, `ops_07_hooks_fail_closed_once_the_services_are_dropped` | Varsayılan reddet |
| 4.2.1 | IDOR'a karşı koruma | ✅ | `authz.rs`, modül sorgularında `user_id`/`org_id` filtreleri | `arc_10_org_10_every_endpoint_hides_other_tenants_from_a_session_owner`, `mfa_07_foreign_factor_ids_are_not_found`, `pky_04_other_users_passkeys_are_not_found`, `aud_07_endpoints_of_other_tenants_are_not_found` | Başka kiracının kaynağı `404` |
| 4.2.2 | Güçlü anti-CSRF | ✅ | `crates/authn-session/src/csrf.rs` | `ops_02_every_state_changing_route_is_behind_authentication_and_csrf`, `ses_04_login_csrf_pre_session_token`, `ses_04_origin_check` | — |
| 4.3.1 | Yönetim arayüzleri MFA ister | ✅ | `crates/authn-admin/src/guard.rs` | `adm_01_rejects_admin_without_passkey_amr`, `adm_01_rejects_admin_without_recent_step_up` | Passkey zorunlu |
| 4.3.2 | Dizin listeleme / meta veri dosyaları kapalı | — | — | — | Statik dosya sunulmaz; yalnızca tanımlı rotalar (`arc_08_unknown_route_uses_error_envelope`) |
| 4.3.3 | Ek yetkilendirme (step-up / uyarlamalı) ve görev ayrılığı | ✅ | `crates/authn-admin/src/service/approvals.rs`, `principal.rs` | `adm_06_k66_emergency_needs_an_approval_and_uses_it_once`, `adm_03_k66_self_approval_target_approval_and_foreign_use_are_refused`, `ses_13_strictest_membership_policy_applies_outside_the_strict_org` | Four-eyes (K-66) |

## V6 — Saklanan kriptografi

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 6.1.1 | Düzenlemeye tabi özel veri şifreli saklanır | 🟡 | `crates/authn-crypto/src/envelope/` | `mfa_01_secret_is_envelope_encrypted_and_bound_to_its_row`, `cry_08_rotate_kek_covers_every_sealed_column_of_the_schema` | Sırlar (TOTP, sağlayıcı token'ları, webhook sırları, imza anahtarları, bildirim yükleri) zarf şifreli. Kişisel veri (e-posta, telefon, görünen ad, IP) kolon düzeyinde **şifreli değil**; disk/DB şifrelemesi işletmecinin işidir |
| 6.1.2 | Sağlık verisi | — | — | — | İşlenmez |
| 6.1.3 | Finansal veri | — | — | — | İşlenmez |
| 6.2.1 | Kripto modülleri güvenli başarısız olur, padding oracle yok | ✅ | `crates/authn-crypto/src/error.rs`, `envelope/` | `cry_13_errors_map_to_generic_codes`, `cry_08_every_byte_is_authenticated` | AEAD; hatalar genel koda dönüşür |
| 6.2.2 | Kanıtlanmış algoritmalar ve kütüphaneler | ✅ | `crates/authn-crypto/` | `cry_14_hmac_sha256_rfc4231_vectors`, `cry_14_ed25519_rfc8032_vectors`, `cry_14_argon2id_rfc9106_vector` | RustCrypto, dalek; kendi algoritmamız yok |
| 6.2.3 | IV, şifre yapılandırması, mod güncel öneriye göre | ✅ | `envelope/mod.rs` | `cry_08_seal_open_round_trip`, `cry_08_prop_round_trip` | XChaCha20-Poly1305, 192 bit rastgele nonce |
| 6.2.4 | Algoritma/anahtar/parametre değiştirilebilir | 🟡 | `envelope/` (sürüm baytı, `kek_id`), `password/` (rehash), `jwt.rs` (`kid`), `crates/authn-audit/src/keys.rs` (zincir anahtarı sürümü) | `cry_03_outdated_parameters_trigger_rehash`, `cry_08_kek_rotation_rewraps_without_touching_data`, `k_77_key_rotation_applies_to_new_events_and_old_ones_still_verify` | Anahtarlar ve parametreler değiştirilebilir. JWT algoritması bilinçli olarak sabittir (EdDSA). `hmac_root_key` tek sürümlüdür |
| 6.2.5 | Güvensiz algoritma yok (ECB, MD5, SHA-1 vb.) | ✅ | `password/legacy.rs`, `totp.rs`, `crates/authn-password/src/breach.rs` | `cry_04_wrapped_md5_and_sha1_hashes`, `pwd_03_sha1_known_answer_and_split` | Gerekçeli istisnalar: SHA-1 yalnızca RFC 6238 TOTP ve HIBP biçimi için; MD5/SHA-1 yalnızca eski hash'leri Argon2id içinde sarmak için |
| 6.2.6 | Nonce/IV bir anahtarla tekrar kullanılmaz | ✅ | `envelope/mod.rs` | `cry_08_seal_open_round_trip` | Değer başına yeni DEK + rastgele 192 bit nonce. Nonce tekrarını doğrudan ölçen test yok |
| 6.2.7 | Şifreli veri doğrulanır | ✅ | `envelope/` | `cry_08_every_byte_is_authenticated`, `cry_08_aad_binds_table_column_and_row` | AEAD + AAD |
| 6.2.8 | Kripto işlemleri sabit zamanlı | 🟡 | `crates/authn-crypto/src/ct.rs` | `cry_12_eq_array`, `cry_12_position_of_scans_all_candidates`, `cry_06_hash_is_sha256_of_text_and_compares_in_constant_time` | Rust tarafı karşılaştırmalar `subtle` ile. Token araması SQL'de SHA-256 hash'i üzerinden yapılır (sabit zamanlı değil; saldırgan hash baytlarını seçemez, [cryptography.md](cryptography.md) §6) |
| 6.3.1 | Rastgele değerler CSPRNG ile | ✅ | `crates/authn-crypto/src/random.rs` | `cry_06_random_bytes_differ`, `cry_07_uniform_below_stays_in_range` | `getrandom` |
| 6.3.2 | Rastgele GUID'ler v4 + CSPRNG | 🟡 | `crates/authn-core/src/id.rs` | `arc_05_generated_ids_are_uuid_v7_and_unique` | Kimlikler UUIDv7'dir (ARC-05, zaman sıralı). Kimlikler sır olarak kullanılmaz; tahmin edilemezlik gereken her yerde 256 bit token vardır |
| 6.3.3 | Yük altında yeterli entropi | ✅ | `random.rs` | Test yok | Çekirdek CSPRNG'si (`getrandom`); hata `CryptoError::Rng` olarak kapalı başarısız olur |
| 6.4.1 | Sır yönetimi çözümü (kasa) | 🟡 | `crates/authn-crypto/src/envelope/provider.rs` (`KeyProvider`) | `cry_08_provider_configuration` | Yalnızca ortam/yapılandırma sağlayıcısı (`EnvKeyProvider`). KMS/Vault uygulaması Faz 2 (K-96) |
| 6.4.2 | Anahtar materyali uygulamaya açılmaz | ❌ | `provider.rs` | — | KEK, pepper ve HMAC kökü süreç belleğindedir. Faz 2 (K-96) |

## V7 — Hata işleme ve loglama

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 7.1.1 | Kimlik bilgisi loglanmaz; oturum token'ı yalnızca hash'li | ✅ | `crates/authn-core/src/secret.rs`, `crates/authn-crypto/src/secret.rs` | `pwd_05_passwords_tokens_and_codes_never_appear_in_logs`, `ntf_03_development_logs_redact_links_and_codes`, `k_77_chain_key_never_appears_in_logs_or_debug` | — |
| 7.1.2 | Hassas kişisel veri loglanmaz | ✅ | `crates/authn-core/src/redact.rs` | `ops_03_email_is_partially_masked`, `ops_03_ip_is_partially_masked`, `ops_03_redacted_hides_value` | E-posta ve IP kısmen maskelenir |
| 7.1.3 | Güvenlik olayları loglanır (başarılı/başarısız kimlik doğrulama, erişim hataları, doğrulama hataları) | 🟡 | `crates/authn-core/src/ports/audit.rs` (`SecurityEventKind`), `crates/authn-audit/` | `aud_01_every_security_event_kind_is_recordable_and_duplicates_are_ignored`, `aud_01_record_survives_a_failed_business_transaction` | Kimlik doğrulama, MFA, oturum, hesap, org, admin, hız sınırı olayları audit'lenir. Her erişim reddi (`403`/`404`) ve her girdi doğrulama hatası için ayrı audit olayı **yoktur** |
| 7.1.4 | Olay zaman çizelgesi için yeterli bilgi | ✅ | `crates/authn-audit/src/sink.rs` | `aud_01_record_persists_event_with_pseudonyms_and_pii`, `aud_03_impersonation_records_the_real_actor` | Zaman, aktör (+ gerçek aktör), kaynak, sonuç, istek kimliği, IP/UA (zincir dışı) |
| 7.2.1 | Tüm kimlik doğrulama kararları loglanır | ✅ | `crates/authn-session/src/login/`, `crates/authn-protect/src/audit.rs` | `ses_13_wrong_password_fails_uniformly_and_is_audited`, `prt_01_abuse_events_are_audited_once_per_window` | — |
| 7.2.2 | Erişim denetimi kararları loglanabilir, başarısızlar loglanır | 🟡 | `crates/authn-admin/`, `crates/authn-org/` | `adm_06_k66_approval_requests_are_capped_per_requester` | Admin işlemleri (başarısızlar dahil) ve API anahtarı doğrulama hataları (`api_key.auth_failed`) audit'lenir. Genel org/kullanıcı uçlarındaki yetki retleri audit'lenmez |
| 7.3.1 | Log enjeksiyonuna karşı kodlama | ✅ | `crates/authn-server/src/telemetry.rs` (JSON log), `crates/authn-audit/src/sanitize.rs` | `aud_04_user_agent_spoofing_characters_are_removed`, `adm_08_justification_rejects_hidden_and_line_breaking_characters` | Yapılandırılmış JSON log (`server.log_format`, varsayılan `json`) |
| 7.3.3 | Güvenlik logları yetkisiz erişim ve değişikliğe karşı korunur | ✅ | `crates/authn-audit/`, `migrations/1703_audit_keyed_chain.sql`, `2900_least_privilege.sql` | `aud_02_append_only_trigger_refuses_update_delete_and_truncate`, `k_77_forger_without_the_key_cannot_recompute_the_chain`, `aud_04_org_audit_log_requires_permission_and_hides_other_tenants` | Sondan kesme yalnızca dış çıpayla tespit edilir ([known-limitations.md](known-limitations.md)) |
| 7.3.4 | Zaman kaynakları senkron, UTC | 🟡 | `crates/authn-audit/src/chain.rs` | `aud_02_timestamps_are_microsecond_utc` | Zaman damgaları UTC; NTP senkronizasyonu işletmecinin işidir |
| 7.4.1 | Beklenmeyen hatada genel mesaj + destek kimliği | ✅ | `crates/authn-core/src/error/auth_error.rs`, `http/context.rs` | `arc_08_internal_details_never_rendered`, `arc_08_errors_are_localized_and_carry_request_id` | `request_id` her yanıtta |
| 7.4.2 | Beklenen ve beklenmeyen hatalar için istisna işleme | ✅ | Workspace lint'leri (`unwrap_used`, `expect_used`, `panic` = deny) | `arc_08_foreign_errors_are_wrapped_without_leaking` | Üretim kodunda `unwrap`/`expect`/`panic!` yok (clippy) |
| 7.4.3 | Son çare hata işleyicisi | ✅ | `crates/authn-server/src/app.rs` (iki `CatchPanicLayer`: handler'a en yakın olanı güvenlik başlıkları/CORS katmanlarının içinde, dıştaki ara katman panikleri için; K-114) | `arc_08_k114_panicking_handler_yields_a_generic_500_envelope` | Panikleyen handler kararlı zarfta genel `500 internal_error` (istek kimliğiyle) döner; panik mesajı yanıta girmez, güvenlik başlıkları korunur. Arka plan işlerinde: `aud_06_handler_panics_and_timeouts_are_retried`, `acc_02_panicking_job_releases_its_queue_slot` |

## V8 — Veri koruma

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 8.1.1 | Hassas veri sunucu bileşenlerinde önbelleklenmez | ✅ | `crates/authn-protect/src/web/headers.rs` | `prt_07_hsts_preload_and_handler_cache_policy`, `prt_07_security_headers_on_every_response` | Her yanıtta varsayılan `Cache-Control: no-store` (JWKS gibi açık veriler kendi önbelleğini koyar) |
| 8.1.2 | Sunucudaki geçici kopyalar korunur/temizlenir | — | — | — | Uygulama hassas veri önbelleği tutmaz (imza anahtarı önbelleği süreç belleğinde, kısa ömürlü) |
| 8.1.3 | İstekteki parametreler en aza indirilir | ✅ | Modül `routes.rs` dosyaları | `arc_07_unknown_keys_are_rejected` (yapılandırma) | Gizli alan/çerez kullanımı en az; istek gövdeleri tipli |
| 8.1.4 | Anormal istek sayısı tespit edilir ve uyarılır | 🟡 | `crates/authn-protect/src/rate_limit/`, `audit.rs`, metrikler | `prt_01_abuse_events_are_audited_once_per_window` | Hız sınırı + `protect.rate_limited` olayı + Prometheus metrikleri. Uyarı kuralları işletmecinin izleme sistemindedir |
| 8.1.5 | Düzenli yedek ve geri yükleme testi | — | — | — | İşletme süreci (DOC-06 kapsamı) |
| 8.1.6 | Yedekler güvenli saklanır | — | — | — | İşletme süreci |
| 8.2.1 | Tarayıcıda önbellek engelleyici başlıklar | ✅ | `headers.rs` | `prt_07_security_headers_have_the_specified_values` | — |
| 8.2.2 | Tarayıcı depolamasında hassas veri yok | ✅ | `crates/authn-session/src/cookies.rs` | `ses_03_session_cookie_is_host_prefixed_http_only_secure_lax` | Çerezlerde yalnızca opak token'lar. Web impersonation token'ı konsol belleğinde (K-12) |
| 8.2.3 | Oturum bitince istemci verisi temizlenir | ✅ | `crates/authn-session/src/routes.rs` (logout) | `ses_12_logout_revokes_clears_cookie_and_site_data` | `Clear-Site-Data: "cookies"` |
| 8.3.1 | Hassas veri sorgu dizesinde değil | ✅ | `crates/authn-notify/src/links.rs` | `ntf_02_links_use_only_the_public_base_url_and_configured_path`, `adm_05_k11_enrollment_link_keeps_the_token_in_the_fragment` | Token'lar URL parçasında; dışa aktarma `POST` (`acc_10_k58_export_is_a_post_never_a_get`) |
| 8.3.2 | Kullanıcı verisini dışa aktarabilir ve silebilir | ✅ | `crates/authn-account/src/service/export.rs`, `deletion.rs` | `acc_10_export_contains_every_registered_section_and_no_secrets`, `acc_09_purge_after_grace_period_erases_everything` | — |
| 8.3.3 | Açık dil ve onay | 🟡 | `crates/authn-account/src/service/consent.rs` | `acc_11_acceptance_is_recorded_with_ip_and_user_agent`, `acc_11_new_version_requiring_reacceptance_is_reported_at_login` | Onay kaydı ve yeniden onay var. Metinlerin içeriği işletmecinindir; `account.require_terms_acceptance` varsayılan `false` |
| 8.3.4 | Hassas veri envanteri ve politika | ✅ | [`docs/compliance/kvkk-gdpr.md`](../compliance/kvkk-gdpr.md) | `doc_07_data_inventory_covers_every_table`, `doc_07_required_sections_are_present` | — |
| 8.3.5 | Hassas veriye erişim audit'lenir | ✅ | `crates/authn-admin/src/service/users.rs` | `adm_02_detail_contains_no_secrets_and_is_audited`, `adm_04_defaults_read_only_fifteen_minutes_with_admin_session` | Personelin kullanıcı detayı görüntülemesi ve impersonation audit'lenir |
| 8.3.6 | Bellekteki hassas veri işi bitince üzerine yazılır | 🟡 | `crates/authn-crypto/src/secret.rs`, `password/canonical.rs` | `cry_13_debug_output_contains_no_secrets`, `pwd_02_capacity_is_exact` | Kendi tiplerimiz `Zeroizing`. zxcvbn, serde/axum gövde tamponları, lettre ve minijinja'nın iç kopyaları sıfırlanmaz |
| 8.3.7 | Şifrelenmesi gereken veri onaylı AEAD ile | ✅ | `crates/authn-crypto/src/envelope/` | `cry_08_every_byte_is_authenticated` | — |
| 8.3.8 | Saklama süresine göre otomatik silme | ✅ | `crates/authn-audit/src/retention.rs`, `crates/authn-account/src/service/maintenance.rs`, `crates/authn-server/src/jobs.rs` | `aud_05_retention_purge_deletes_old_prefix_with_checkpoint`, `acc_05_unverified_accounts_are_purged_after_seven_days`, `aud_06_old_messages_are_purged` | — |

## V13 — API ve web servisleri

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 13.1.1 | Bileşenler aynı kodlama ve ayrıştırıcıları kullanır | ✅ | `crates/authn-core/src/http/extract.rs` | `arc_08_json_rejections_use_the_envelope`, `pwd_05_malformed_bodies_get_envelopes_that_never_echo_the_password` | Handler'lar `serde_json` tabanlı `authn_core::http::Json`/`Query`/`Path` çıkarıcılarını kullanır; sır taşıyan gövdeler için password, mfa ve account kendi `extract.rs` sarmalayıcılarını kullanır (aynı ayrıştırıcı, hata ayrıntısı loglanmaz) |
| 13.1.3 | API URL'leri hassas bilgi içermez | ✅ | Rota tanımları | `ops_09_every_routed_path_is_documented` | API anahtarı ve token'lar başlıkta/gövdede |
| 13.1.4 | Yetkilendirme hem rota hem kaynak düzeyinde | ✅ | `crates/authn-server/src/app.rs`, `crates/authn-org/src/authz.rs` | `ops_02_account_admin_and_org_routes_refuse_anonymous_callers`, `arc_10_org_10_every_endpoint_hides_other_tenants_from_a_session_owner` | — |
| 13.1.5 | Beklenmeyen içerik türü reddedilir (406/415) | ✅ | `extract.rs` | `arc_08_json_rejections_use_the_envelope`, `pwd_05_content_type_detection`, `mfa_10_content_type_detection` | `415 unsupported_media_type` |
| 13.2.1 | HTTP yöntemleri eyleme uygun | ✅ | Rota tanımları | `acc_10_k58_export_is_a_post_never_a_get`, `acc_10_k79_openapi_documents_the_export_as_post_only` | Durum değiştiren hiçbir işlem güvenli yöntemle yapılmaz |
| 13.2.2 | JSON şema doğrulaması | 🟡 | İstek tipleri (`serde`) | `arc_08_json_rejections_use_the_envelope` | Tipli serileştirme; çok sayıda istek tipinde `deny_unknown_fields`. Ayrı bir JSON Schema doğrulayıcısı yok |
| 13.2.3 | Çerezli REST servisleri CSRF'ye karşı korunur | ✅ | `crates/authn-session/src/csrf.rs` | `ses_04_state_changing_cookie_requests_need_origin_and_csrf_token`, `ses_04_csrf_protects_other_modules_behind_the_session_layer` | — |
| 13.2.5 | `Content-Type` açıkça denetlenir | ✅ | `extract.rs` | `pwd_05_content_type_detection` | — |
| 13.2.6 | Başlık ve gövdenin aktarımda değişmediği | 🟡 | `crates/authn-protect/src/web/headers.rs` (HSTS) | `prt_07_security_headers_have_the_specified_values` | TLS sonlandırma işletmecinin proxy'sindedir; üretimde `public_base_url` `https` zorunlu. Mesaj imzası yok (webhook'lar hariç) |

V13.3 (SOAP) ve V13.4 (GraphQL) uygulanmaz ve sayıma dahil edilmedi.

### OAuth 2.1 / OIDC sağlayıcısı (K-80; ASVS 5.0 V10'a göre, yukarıdaki 4.0.3 sayımına dahil değil)

| ASVS 5.0 | Gereksinim (özet) | Durum | Kod | Test | Not |
|----------|-------------------|-------|-----|------|-----|
| 10.4.1 | `redirect_uri` önceden kayıtlı değerle birebir eşleşir | ✅ | `crates/authn-oidc-provider/src/redirect.rs` | `oidp_02_exact_match_rejects_variants`, `oidp_02_unregistered_redirects_are_never_followed` | Tek istisna RFC 8252 loopback portu |
| 10.4.2 | Kod tek kullanımlık; tekrarında token'lar iptal | ✅ | `src/service/token.rs` | `oidp_06_code_replay_revokes_every_token_of_the_grant` | — |
| 10.4.3 | Kod kısa ömürlü | ✅ | `oidc_provider.authorization_code_ttl` (60 sn) | `oidp_06_code_is_bound_to_client_redirect_verifier_and_lifetime` | — |
| 10.4.4 | Yalnızca gerekli grant türleri (implicit / ROPC yok) | ✅ | `src/request.rs` | `oidp_03_only_the_code_flow_exists` | — |
| 10.4.5 | Refresh token rotasyonu ve tekrar tespiti | ✅ | `src/service/token.rs` | `oidp_07_refresh_rotation_and_replay_detection` | — |
| 10.4.6 | PKCE `S256` zorunlu | ✅ | `src/pkce.rs`, `src/request.rs` | `oidp_03_missing_and_plain_pkce_are_redirected_errors`, `oidp_03_rfc_7636_appendix_b_vector` | — |
| 10.4.8 | Refresh token'ın mutlak ömrü var | ✅ | `oidc_provider.refresh_token_absolute_ttl` + oturum bağı | `oidp_12_ended_session_ends_the_grant` | — |
| 10.4.10 | Gizli istemci kimlik doğrulaması | ✅ | `src/service/token.rs` (`authenticate_client`, sabit zamanlı hash karşılaştırması) | `oidp_06_basic_credentials_are_form_decoded_and_exclusive`, `oidp_02_native_public_client_with_loopback_port_and_no_secret` | `private_key_jwt` K-84 |
| 10.4.11 | İstemci yalnızca izinli kapsamları alır | ✅ | `src/request.rs` | `oidp_03_scope_and_resource_policy` | — |
| 10.5.1 | ID token `nonce` / `aud` / `at_hash` doğrulanabilir | ✅ | `src/claims.rs` | `oidp_06_web_client_code_flow_with_pkce_and_independent_id_token_check` | Bağımsız Ed25519 doğrulayıcısıyla |
| 10.6.1 | Mix-up savunması (`iss` yanıt parametresi) | ✅ | `src/service/authorize.rs` | `oidp_06_web_client_code_flow_with_pkce_and_independent_id_token_check` | RFC 9207 |
| 10.7.1 | Onay kaydı ve geri alma | ✅ | `src/service/authorize.rs` | `oidp_05_existing_consent_gives_sso_and_prompt_consent_asks_again` | — |
| 10.3.x | Access token `aud` kısıtı / tür ayrımı | ✅ | `src/service/token.rs` (`mint`) | `oidp_08_resource_indicators_set_the_audience`, `oidp_08_provider_and_native_tokens_are_never_interchangeable` | RFC 8707 |


## V14 — Yapılandırma

| ASVS | Gereksinim (özet) | Durum | Kod | Test | Not |
|------|-------------------|-------|-----|------|-----|
| 14.1.1 | Güvenli, tekrarlanabilir derleme ve dağıtım | ✅ | `.github/workflows/ci.yml`, `Dockerfile`, `Cargo.lock` | CI işleri | `--locked` derleme; Docker imajı bu ortamda derlenmedi (K-55) |
| 14.1.2 | Derleyici korumaları | ✅ | `Cargo.toml` `[workspace.lints]` | CI clippy | Rust bellek güvenliği; `unsafe_code = "forbid"` |
| 14.1.3 | Sunucu yapılandırması sertleştirilmiş | ✅ | `crates/authn-core/src/config/mod.rs` (`validate_cross_section`) | `ses_08_k58_session_check_cannot_be_switched_off_in_production_or_staging`, `adm_06_k66_four_eyes_cannot_be_switched_off_in_production`, `prt_05_k58_captcha_hostnames_are_required_in_production` | Kuralların çoğu yalnızca `production`'da uygulanır ([known-limitations.md](known-limitations.md)) |
| 14.1.4 | Otomatik yeniden dağıtım / runbook | 🟡 | `Dockerfile`, `docker-compose.yml`, [`docs/operations/`](../operations/) | — | Docker imajı ve compose dosyası hiç çalıştırılmadı (K-55). Helm/HA referansı yok (Faz 2, K-99) |
| 14.1.5 | Güvenlikle ilgili yapılandırmanın bütünlüğü doğrulanabilir | ✅ | `crates/authn-server/src/cli.rs` (`check-config`) | `arc_07_check_config_refuses_what_serve_would_refuse`, `ops_01_check_config_refusals_exit_with_the_configuration_code` | — |
| 14.2.1 | Bileşenler güncel, bağımlılık denetimi | ✅ | `deny.toml`, `.cargo/audit.toml`, CI | CI `cargo deny check`, `cargo audit` | İki RustSec uyarısı gerekçeyle yok sayılır (yalnızca açık anahtarla doğrulama) |
| 14.2.2 | Gereksiz özellik, örnek ve yapılandırmalar kaldırılmış | 🟡 | `config/`, `crates/authn-core/src/config/` | `ops_08_example_keys_are_refused_in_production`, `ntf_03_development_transports_are_refused_in_production` | Örnek anahtarlar ve geliştirme taşıyıcıları üretimde reddedilir. OpenAPI belgesi varsayılan açıktır (`server.openapi_enabled`) |
| 14.2.3 | Harici varlıklar için SRI | — | — | — | Sunucu HTML/JS sunmaz |
| 14.2.4 | Bileşenler güvenilir depolardan | ✅ | `deny.toml` `[sources]` | CI `cargo deny check` | Yalnızca crates.io; bilinmeyen kayıt ve git reddedilir |
| 14.2.5 | SBOM | 🟡 | `Cargo.lock`, `THIRD_PARTY_LICENSES.txt`, `licenses/generate_notices.py` | CI `licence-notices` işi | Lisans bildirimleri üretilir; standart biçimde (CycloneDX/SPDX) bir SBOM üretilmez |
| 14.2.6 | Üçüncü taraf kütüphaneler kapsüllenir | 🟡 | `crates/authn-core/src/ports/` (hexagonal portlar), `crates/authn-protect/src/outbound/` | `prt_12_trusted_targets_may_be_internal_and_keep_headers` | Dış etkiler portların arkasında; süreç düzeyinde sandbox yok |
| 14.3.2 | Üretimde hata ayıklama modu kapalı | ✅ | `crates/authn-core/src/config/mod.rs`, `crates/authn-notify/` | `ntf_03_development_only_settings_fail_fast_outside_development`, `cry_02_published_keys_are_refused_in_production` | Hata yanıtları iç ayrıntı içermez (her ortamda) |
| 14.3.3 | Yanıtlar sürüm bilgisi göstermez | ✅ | `crates/authn-server/src/app.rs` | Test yok | Sunucu `Server` / `X-Powered-By` başlığı eklemez (canlı yanıtla kontrol edildi, `GET /health/ready`). Bunu doğrulayan otomatik test yok |
| 14.4.1 | Her yanıtta doğru `Content-Type` | ✅ | `crates/authn-core/src/error/auth_error.rs`, axum `Json` | `arc_08_envelope_shape_and_locale` | JSON yanıtlar `application/json` |
| 14.4.2 | API yanıtlarında `Content-Disposition: attachment` | ❌ | `crates/authn-account/src/routes.rs`, `crates/authn-admin/src/routes.rs` | `acc_10_export_contains_every_registered_section_and_no_secrets` | Yalnızca dışa aktarma uçları ekler. Diğer API yanıtlarında yok (CSP `default-src 'none'` ve `nosniff` riski azaltır) |
| 14.4.3 | CSP | ✅ | `crates/authn-protect/src/web/headers.rs` | `prt_07_security_headers_have_the_specified_values` | `default-src 'none'; frame-ancestors 'none'` |
| 14.4.4 | `X-Content-Type-Options: nosniff` | ✅ | `headers.rs` | `prt_07_security_headers_on_every_response` | — |
| 14.4.5 | HSTS, alt alan adlarıyla | ✅ | `headers.rs` | `prt_07_security_headers_have_the_specified_values`, `prt_07_hsts_preload_and_handler_cache_policy` | 2 yıl, `includeSubDomains`, opsiyonel `preload` |
| 14.4.6 | Uygun `Referrer-Policy` | ✅ | `headers.rs` | `prt_07_security_headers_have_the_specified_values` | `no-referrer` |
| 14.4.7 | Üçüncü taraf sitede çerçevelenemez | ✅ | `headers.rs` | `prt_07_security_headers_have_the_specified_values` | `frame-ancestors 'none'` |
| 14.5.1 | Yalnızca kullanılan HTTP yöntemleri kabul edilir | 🟡 | Rota tanımları (axum) | `acc_10_k58_export_is_a_post_never_a_get` | Tanımsız yöntem `405`; geçersiz istekler için uyarı/alarm yok |
| 14.5.2 | `Origin` kimlik doğrulama/yetki kararında kullanılmaz | ✅ | `crates/authn-session/src/csrf.rs` | `ses_04_origin_check` | `Origin` yalnızca CSRF savunmasının bir katmanıdır; tek başına yetki vermez |
| 14.5.3 | CORS sıkı izin listesi, `null` yok | ✅ | `crates/authn-protect/src/web/cors.rs`, `crates/authn-server/src/cors.rs` | `prt_08_wildcard_or_null_origins_are_refused_at_start_up`, `prt_08_other_origins_are_never_reflected_or_wildcarded` | — |
| 14.5.4 | Güvenilir proxy'nin eklediği başlıklar doğrulanır | ✅ | `crates/authn-core/src/http/client_ip.rs` | `prt_06_untrusted_peer_ignores_forwarding_headers`, `prt_06_k57_near_catch_all_trusted_proxies_are_refused` | — |

## 10. Notlar

1. "Test yok" yazan satırlar, davranışın kodda olduğunu ama adında gereksinim kimliği taşıyan otomatik bir testin bulunmadığını söyler. Bunlar QA sertleştirmesinde (remaining-work §6) kapatılmalıdır.
2. "CI işleri" yazan satırlar `.github/workflows/ci.yml` içindeki işlerdir (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check`, `cargo audit`, `licence-notices`, `cargo llvm-cov`, fuzz derleme).

## 11. Bakım

- Bir gereksinimin durumu değişince satırı **kodla birlikte** güncelleyin; test adı değişirse buradaki adı da değiştirin.
- ASVS 5.0'a geçişte: kimlik doğrulama (V6), oturum (V7), yetkilendirme (V8), kendi kendine yeten token (V9), OAuth/OIDC (V10, Faz 2 ile anlamlı hâle gelir), kriptografi (V11), güvenli iletişim (V12), yapılandırma (V13), veri koruma (V14), loglama (V16) bölümlerine yeniden eşleyin.
