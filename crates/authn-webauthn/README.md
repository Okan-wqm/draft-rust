# authn-webauthn

Passkey / WebAuthn: kayıt ve doğrulama seremonileri, kimlik bilgisi yönetimi, mobil ilişkilendirme dosyaları ve authn-session'ın kullandığı passkey kimlik doğrulama API'si.

**Tüm WebAuthn doğrulaması `webauthn-rs`'tedir** (imza, origin, challenge, RP id hash'i, kullanıcı varlığı/doğrulaması, algoritma, imza sayacı, yedekleme bayrakları, attestation zinciri ve AAGUID). Bu crate elle doğrulama yapmaz; etrafına sunucu tarafı seremoni durumu, bağlama, tek kullanım, kalıcılık, politika, audit ve bildirim ekler.

## Sahip olunan gereksinimler

| Kimlik | Durum | Nerede |
|--------|-------|--------|
| PKY-01 | Uygulandı | `service/registration.rs`, `service/authentication.rs`, `store/ceremonies.rs` — sunucu tarafı durum, `webauthn.ceremony_ttl` (5 dk), tek kullanım (atomik `UPDATE … RETURNING`), kullanıcı/oturum/challenge/bağlama token'ına bağlı. Wave 2B (K-11): oturumsuz **kayıt bağlantısı** seremonisi — kullanıcıya ve bağlantı token'ının SHA-256'sına bağlı (`start_enrollment_registration`, `verify_enrollment_registration`, `store_enrollment_in_tx`; migration `1401`) |
| PKY-02 | Uygulandı | Passkey hem birincil (kullanıcı adısız, conditional UI) hem ikinci faktör; discoverable credential tercih edilir (`residentKey: "preferred"`); UV birincil giriş ve step-up için `required`, ikinci faktör için `preferred` |
| PKY-03 | Uygulandı | `store/handles.rs` — 16 bayt CSPRNG kullanıcı tanıtıcısı, e-postadan ve kullanıcı kimliğinden bağımsız |
| PKY-04 | Uygulandı | `service/manage.rs` — liste (ad, oluşturulma, son kullanım, yedeklenebilir/yedeklenmiş, UV, keşfedilebilirlik, attestation, klon şüphesi), yeniden adlandırma, silme (step-up; son giriş yöntemi / zorunlu son MFA faktörü engellenir), ekleme/kaldırma bildirimi |
| PKY-05 | Uygulandı | `webauthn-rs` sayaç ve yedekleme tutarlılığı kontrolü + satır kilitli güncel sayaçla ikinci karşılaştırma; **imzası doğrulanmış** bir onaydaki sayaç gerilemesi `passkey.clone_suspected` olayı, `clone_suspected_at` işareti, giriş reddi ve (passkey'in ilk tespitinde, aynı transaction'da) sahibine `passkey_clone_suspected` e-postası (wave 2B, K-19) üretir |
| PKY-06 | Uygulandı | `rp.rs` + `authn_core::config::webauthn` — `rp_id`, tam eşleşen origin listesi (web + `android:apk-key-hash:`), fail-fast doğrulama |
| PKY-07 | Uygulandı | `well_known.rs` — `/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json`, `/.well-known/webauthn` |
| PKY-08 | Uygulandı | `policy.rs` — attestation varsayılan `none`; kuruluş AAGUID izin listesi (`PasskeyPolicy`, girdi yapısı) yalnızca **doğrulanmış** attestation ile; `PasskeyPolicySource` kayıtta ve **her** kimlik doğrulamada uygulanır |

## Bağımlılık kuralı

Dalga A. `core`, `crypto`, `store` dışında hiçbir authn crate'ine bağımlı değildir. Başka modüllerin verisi `hooks.rs`'teki trait'lerle gelir (authn-server uygular). Ayrıntılar: [`docs/architecture/contracts.md`](../../docs/architecture/contracts.md).

## Sahip olunan dosyalar ve kaynaklar

| Kaynak | Değer |
|--------|-------|
| Crate | `crates/authn-webauthn/**` |
| Konfigürasyon dosyası | `crates/authn-core/src/config/webauthn.rs` |
| Hata kodu dosyası | `crates/authn-core/src/error/codes/webauthn.rs` |
| Uygulanan portlar | `DataExporter` (`PasskeyDataExporter`, bölüm `passkeys`) |
| Sahip olunan tablolar | `webauthn_user_handles`, `webauthn_credentials`, `webauthn_ceremonies` |
| Migration | `1400_webauthn_hardening.sql`, `1401_webauthn_enrollment_binding.sql`, `1402`–`1404` (wave 6B, K-70: `webauthn_ceremonies` yabancı anahtar indeksleri `user_id`, `session_id`, `challenge_id`; `CREATE INDEX CONCURRENTLY`, dosya başına tek ifade, `IF NOT EXISTS` yok; testler `authn-server/tests/schema_foreign_keys.rs`) (aralık `1400–1499`) |
| Fuzz hedefi | `fuzz/fuzz_targets/webauthn_response_parse.rs` (kaydı §13 talebinde) |

## Genel API

### Servis

`WebauthnService::new(WebauthnServiceDeps { pool, clock, rate_limiter, notifier, audit, account_methods, policy_source }, WebauthnServiceSettings::from_app_config(&config)?)` — RP'yi doğrular ve well-known belgelerini üretir; geçersiz konfigürasyonda hata döner.

| Metot | Gereksinim | Çağıran |
|-------|-----------|---------|
| `start_registration(&ctx, &principal, RegistrationOptionsRequest) -> RegistrationStart` | PKY-01/02/03/08 | HTTP |
| `finish_registration(&ctx, &principal, RegistrationVerifyRequest) -> PasskeySummary` | PKY-01/02/08 | HTTP |
| `list_passkeys(&principal) -> Vec<PasskeySummary>` | PKY-04 | HTTP |
| `rename_passkey(&ctx, &principal, CredentialId, &str) -> PasskeySummary` | PKY-04 | HTTP |
| `delete_passkey(&ctx, &principal, CredentialId)` | PKY-04 | HTTP |
| `remove_all_passkeys_in_tx(&mut conn, &ctx, UserId, PasskeyRemovalReason) -> u32` | ADM-03, PKY-04, ACC-07 (wave 1, K-01; K-68) | authn-admin (MFA sıfırlama, break-glass kimlik bilgisi değişimi: `AdminReset`) ve server'ın e-posta geri alma kancası (`EmailChangeReverted`). Çağıranın transaction'ında **tüm** passkey'leri siler; step-up ve son giriş yöntemi kuralı **yok** (yetki çağıranın işi), kullanıcı satırını kilitler, passkey başına `passkey.removed` (`Actor::System`, `reason`: `admin_reset` / `email_change_reverted`), en az biri silindiyse bir `mfa_factor_removed` bildirimi; kullanıcının açık seremonileri (kayıt dahil) aynı transaction'da yakılır. Testler: `pky_04_remove_all_passkeys_in_tx_for_admin_reset`, `pky_04_remove_all_passkeys_in_tx_cancels_open_ceremonies`, `pky_04_k68_revert_removal_is_audited_with_its_own_reason` |
| `start_authentication(&ctx, AuthenticationTarget, &PasskeyPolicy) -> AuthenticationStart` (verilen politika `PasskeyPolicySource` ile en katı biçimde birleştirilir) | PKY-01/02/08 | authn-session |
| `finish_authentication(&ctx, AuthenticationFinish) -> AuthenticatedPasskey` | PKY-01/02/05 | authn-session |
| `passkey_count_in(&mut conn, user, login_capable_only) -> u32` | MFA-07/08, PWD-11 | authn-server (authn-mfa / authn-password trait'leri) |
| `purge_expired_ceremonies() -> u64` | OPS-06 | authn-server arka plan işi |
| `well_known() -> WellKnownDocuments` | PKY-07 | authn-server (`FromRef`) |

`AuthenticationTarget`:

- `Discoverable { conditional_ui }` — kullanıcı adısız passkey girişi (SES-20). `allowCredentials` boş, UV `required`, `conditional_ui = true` ise `mediation: "conditional"`. Yalnızca UV ile kaydedilmiş (`usage = both`) passkey'ler kabul edilir.
- `SecondFactor { user_id, challenge_id }` — giriş challenge'ına (`auth_challenges`) bağlı ikinci faktör. Kullanıcının uygun passkey'leri `allowCredentials`'ta; UV `preferred` (izinli tüm passkey'ler UV ile kaydedildiyse `required`).
- `StepUp { user_id, session_id }` — oturuma bağlı yeniden doğrulama (SES-13), UV `required`.

`AuthenticatedPasskey { user_id, credential_id, purpose, user_verified, backup_eligible, backup_state, amr }` — `amr`: senkronize passkey için `swk`, cihaza bağlı anahtar için `hwk`, her zaman `user`, UV yapıldıysa `mfa` (SES-21).

### Trait'ler (authn-server uygular)

- `AccountMethodsSource` — `other_login_methods(conn, user) -> Vec<LoginMethod>` (passkey **dışındaki** giriş yöntemleri) ve `mfa_facts(conn, user) -> MfaFacts { mfa_required, other_factor_count }` (varsayılan: MFA zorunlu değil). Silme transaction'ında, `users` satırı kilitliyken çağrılır. Hazır uygulama: `PasswordOnlyMethods` (yalnızca şifre; sosyal kimlikleri bilmediği için yalnızca engelleyebilir).
- `PasskeyPolicySource` — `policy_for_user(conn, user, active_org) -> PasskeyPolicy` (PKY-08). Kayıtta etkin organizasyonla, **her kimlik doğrulamada** `active_org = None` ile çağrılır (kullanıcı adısız girişte kullanıcı belli olunca, bitişte); `None` için kullanıcının hangi organizasyona geçerse geçsin geçerli olan politikayı döndürmeli (ör. etkin üyeliklerin `PasskeyPolicy::strictest` birleşimi). Hazır uygulama: `UnrestrictedPolicySource`.

### Router'lar

- `router::<S>()` (`WebauthnService: FromRef<S>`) — oturum + CSRF katmanının arkasında.
- `well_known_router::<S>()` (`WellKnownDocuments: FromRef<S>`) — kökte, kimlik doğrulamasız.
- OpenAPI: `WebauthnApi`.

## HTTP uç noktaları

| Yöntem | Yol | Kimlik doğrulama | Gereksinim |
|--------|-----|------------------|------------|
| `POST` | `/v1/me/passkeys/registration/options` | kullanıcının kendi oturumu (impersonation asla); hesapta passkey varsa (varsayılan: her zaman) step-up | PKY-01/02/03/08 |
| `POST` | `/v1/me/passkeys/registration/verify` | seremoniyi başlatan **aynı** oturum (impersonation asla) | PKY-01/02/08 |
| `GET` | `/v1/me/passkeys` | oturum (salt-okunur impersonation olur) | PKY-04 |
| `PATCH` | `/v1/me/passkeys/{passkey_id}` | oturum | PKY-04 |
| `DELETE` | `/v1/me/passkeys/{passkey_id}` | oturum + step-up | PKY-04 |
| `GET` | `/.well-known/apple-app-site-association` | yok | PKY-07 |
| `GET` | `/.well-known/assetlinks.json` | yok | PKY-07 |
| `GET` | `/.well-known/webauthn` | yok | PKY-07 |

Kayıt uç noktaları yalnızca `passkey` feature'ı ile vardır. Passkey **giriş** / ikinci faktör / step-up uç noktaları authn-session'dadır (SES-20) ve yukarıdaki servis API'sini kullanır. Tüm `/v1` yanıtları `Cache-Control: no-store`; well-known belgeleri `application/json` + `Cache-Control: public, max-age=<well_known_max_age>` + `nosniff`, yapılandırılmamışsa `404`.

## Konfigürasyon (`[webauthn]`)

| Anahtar | Varsayılan | Not |
|---------|-----------|-----|
| `rp_id` | `localhost` | Küçük harfli alan adı (IP değil). Değiştirmek tüm passkey'leri geçersiz kılar. |
| `rp_name` | `rust-authentication` | 1–64 karakter |
| `allowed_origins` | `["http://localhost:8080"]` | Tam eşleşme. Web origin'i `rp_id` veya alt alan adı ya da `related_origins`'te; düz `http` yalnızca `localhost`; Android için `android:apk-key-hash:<base64url SHA-256>`; en az biri `rp_id` ile aynı site. Üretimde web origin'leri `https`. |
| `ceremony_ttl` | `5m` | 1–15 dk; istemciye gönderilen authenticator zaman aşımı da budur |
| `max_credentials_per_user` | 20 | 1–100 |
| `step_up_for_first_passkey` | `true` | `false`: yalnızca ek passkey'ler step-up ister |
| `registration_per_user` | 10 / 1 sa | kayıt başlatma, kullanıcı başına |
| `authentication_per_ip` | 60 / 15 dk | kimlik doğrulama başlatma, IP başına (bilinen kullanıcıda ayrıca kullanıcı başına) |
| `apple_app_ids` | `[]` | `TEAMID.bundle.id` |
| `android_apps[] {package_name, sha256_cert_fingerprints}` | `[]` | parmak izi `AA:BB:…` (32 bayt, büyük harf) |
| `related_origins` | `[]` | `/.well-known/webauthn` |
| `app_link_paths` | `[]` | universal link / app link yolları (`/login/*`); boşsa yalnızca passkey ilişkilendirmesi yayınlanır |
| `well_known_max_age` | `1h` | 1 dk – 7 gün |
| `attestation_roots[] {name, ca_pem, aaguids}` | `[]` | PKY-08; açılışta ayrıştırılır (geçersiz PEM ⇒ servis açılmaz) |

`session.step_up_max_age` ekleme/silme step-up penceresidir.

## Güvenlik notları

- **Seremoni bağlama (PKY-01):** Kayıt seremonisi kullanıcıya **ve oturuma** bağlıdır; başka bir hesap ya da aynı kullanıcının başka bir oturumu onu bitiremez (ve denemesi seremoniyi tüketmez). Kimlik doğrulama seremonileri ayrıca 256 bit bir bağlama token'ı taşır (yalnızca SHA-256'sı saklanır); ikinci faktör giriş challenge'ına, step-up oturuma bağlıdır. Tüketim tek atomik `UPDATE`; bilinmeyen/süresi dolmuş/kullanılmış/başka yere bağlı seremoniler ayırt edilemez (`passkey_ceremony_invalid`). Tüketim doğrulamadan **önce** commit edilir: başarısız bir yanıt challenge'ı yakar, eşzamanlı iki bitirme isteğinden tam olarak biri durumu alır (testli).
- **Origin (PKY-06):** Alt alan adı ve port joker karakteri kapalı; kardeş alt alan adı (`evil.auth.example.com`) ve phishing alan adları sunucuda reddedilir (testli). Android origin'leri yalnızca yapılandırılan imza sertifikası hash'iyle kabul edilir.
- **UV (PKY-02):** Şifresiz giriş ve step-up'ta UV zorunlu (`webauthn-rs` politikası + ek kontrol); UV'siz kaydedilmiş anahtarlar (`usage = second_factor`) şifresiz giriş/step-up için hiç kullanılamaz. UV ile kaydedilmiş passkey'ler ikinci faktörde de UV ister.
- **Kullanıcı adıyla passkey girişi yok:** Kullanıcı adı önce girilen passkey girişi bilerek sunulmuyor (izin listesi hangi hesapların passkey'i olduğunu sızdırırdı). Kullanıcı adısız (discoverable) giriş hesap varlığı hakkında hiçbir şey söylemez; kullanıcı tanıtıcıları 128 bit rastgeledir.
- **Klon tespiti (PKY-05):** Yalnızca **imzası doğrulanmış** bir onaydaki sayaç gerilemesi klon işareti (`clone_suspected_at`) ve `passkey.clone_suspected` olayı üretir; bilinen kullanıcı akışlarında seremoni anlık görüntüsü eski olabileceği için sayaç ayrıca satır kilidi altında güncel değerle yeniden karşılaştırılır (eşzamanlı kullanım testli). Saklanan sayaç asla geri alınmaz. `webauthn-rs`'in yedekleme bayrağı kontrolleri (yedeklenebilirlik değişimi, uygun olmadan yedeklenmiş) imzadan **önce** çalışır; bu yüzden seremoniyi yalnızca reddeder, işaret/olay üretmez (aşağıdaki güvenlik incelemesi).
- **PKY-08:** AAGUID yalnızca doğrulanmış attestation ile saklanır; `none` attestation'daki AAGUID kendi beyanıdır ve yazılımsal bir authenticator tarafından kolayca taklit edilir. Kısıtlayıcı politika, mevcut (attestation'sız) passkey'lere kimlik doğrulamada da uygulanır: çağıranın verdiği politika `PasskeyPolicySource` ile en katı biçimde birleştirilir — ikinci faktör/step-up'ta başlangıçta, kullanıcı adısız girişte kullanıcı belli olunca bitişte. İzinli modellerin hiçbirini kapsamayan kök yoksa kayıt baştan `passkey_not_allowed` döner.
- **Impersonation (ADM-04):** Passkey ekleme (başlatma ve bitirme) her türlü impersonation'da `forbidden` döner — salt-okunur olmasa bile; yönetici tarafından eklenen bir passkey impersonation bittikten sonra da çalışan bir giriş yöntemi olurdu. Silme step-up gerektirdiği için impersonation'da zaten reddedilir; yeniden adlandırma yazılabilir impersonation'da serbesttir ve audit'e gerçek aktörle yazılır.
- **Son giriş yöntemi (PKY-04):** Silme, `users` satırını `FOR UPDATE` kilitler (authn-password PWD-11 ve authn-oidc-client SOC-06 ile aynı kilit); eşzamanlı iki silmeden yalnızca biri başarılı olur (testli). Zorunlu MFA'da son faktör `mfa_last_factor_required` ile korunur.
- **Sızıntı yok:** Liste, dışa aktarma ve audit kayıtları açık anahtar, ham credential id veya sayaç içermez; kullanıcı tarafından verilen passkey adı audit'e yazılmaz (AUD-03). Adlarda kontrol, bidi-override ve görünmez karakterler reddedilir. Hata yanıtları girdiyi yansıtmaz.
- **Sınırlar:** Passkey sayısı, kayıt başlatma (kullanıcı başına, yalnızca yetkilendirmeden sonra sayılır), kimlik doğrulama başlatma (IP ve kullanıcı başına), credential id uzunluğu (16–1023 bayt), transport listesi.
- **Bilinen sınırlama:** Kayıt bitişinde step-up yeniden kontrol edilmez; başlangıçta kontrol edilir ve seremoni aynı oturuma bağlı, en fazla `ceremony_ttl` ömürlüdür.

### Güvenlik incelemesi (2026-11-01)

Düzeltilen bulgular (her biri, düzeltme olmadan başarısız olan bir regresyon testiyle):

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| Orta | `webauthn-rs` yedekleme bayrağı tutarsızlıklarını (`CredentialBackupEligibilityInconsistent`, `CredentialMayNotBeHardwareBound`) **imza doğrulamasından önce** bildirir. Bunlar klon sinyali sayıldığı için credential id'sini bilen biri (ör. şifreyi ele geçirip ikinci faktör `allowCredentials` listesini gören saldırgan) imzasız, sahte authenticator verisiyle kurbanın passkey'ini `clone_suspected` işaretleyip sahte `passkey.clone_suspected` audit olayları üretebiliyordu (güvenlik sinyalinin bütünlüğü; kullanıcıyı gerçek passkey'ini silmeye yönlendirme). | Yalnızca imzadan sonra üretilen `CredentialPossibleCompromise` (sayaç gerilemesi) klon sinyalidir; diğerleri yalnızca reddedilir. | `pky_05_unsigned_backup_flag_tampering_never_flags_a_clone` |
| Orta | Kuruluş AAGUID politikası (PKY-08) kullanıcı adısız girişte uygulanmıyordu: session başlangıçta kullanıcıyı bilemez, `AuthenticatedPasskey` AAGUID taşımaz ve `PasskeyPolicySource` yalnızca kayıtta kullanılıyordu; politikadan önce kaydedilmiş senkronize bir passkey, kısıtlı kuruluşun kullanıcısına şifresiz giriş yaptırıyordu. Bilinen kullanıcı akışları da tamamen çağıranın politikayı geçirmesine bağlıydı. | Çağıranın politikası her seremonide `PasskeyPolicySource::policy_for_user(conn, user, None)` ile en katı biçimde birleştirilir (bilinen kullanıcıda başlangıçta, kullanıcı adısız girişte bitişte). | `pky_08_policy_source_applies_to_every_authentication` |
| Orta | Yazılabilir impersonation passkey kaydedebiliyordu: tek engel step-up'tı ve `step_up_for_first_passkey = false` iken ilk passkey için kalkıyordu; yönetici kurbanın hesabına, impersonation bittikten sonra da çalışan bir giriş yöntemi ekleyebiliyordu. | Kayıt başlatma ve bitirme her impersonation'ı `forbidden` ile reddeder (seremoni tüketilmeden). | `pky_01_impersonation_never_registers_a_passkey` |

Kabul edilen riskler (gerekçeli; düzeltme gerektirmez):

- **Klon şüpheli passkey kullanılmaya devam eder.** İşaret + audit olayı + listede gösterim + kullanıcıya e-posta (wave 2B, K-19: passkey başına yalnızca ilk tespitte, outbox alıcı başına limitli; tekrarlayan tespitler yalnızca audit olayı üretir); passkey'i kaldırma kararı kullanıcıdadır (WebAuthn bu kararı RP'ye bırakır). Otomatik devre dışı bırakma gerçek authenticator'ı da kilitleyebilirdi. İşaret artık yalnızca imzalı kanıttan üretildiği için session/risk katmanı onu güvenle kullanabilir.
- **"Giriş yapabilen" passkey sayımı keşfedilebilirliğe bakmaz.** `passkey_count_in(.., true)` ve son giriş yöntemi kuralı UV ile kaydedilmiş (`usage = both`) tüm passkey'leri sayar; `credProps.rk` istemci beyanıdır (imzasız, çoğu zaman yok) ve güvenlik kararında kullanılamaz. Resident olmayan bir anahtar tek giriş yöntemi kalırsa kullanıcı adısız giriş onu bulamaz; kurtarma e-posta ile şifre sıfırlamadır.
- **`second_factor` niyetiyle kaydedilen ama UV yapan bir anahtar `both` olur** (şifresiz girişte de kullanılabilir). UV kayıtta kanıtlanmıştır ve şifresiz giriş/step-up'ta `webauthn-rs` UV'yi zorunlu kılar; anahtar iki faktörlü bir authenticator'dır.
- **Bağlama token'ı karşılaştırması SQL'de** (`binding_hash IS NOT DISTINCT FROM $n`) yapılır, sabit zamanlı değildir. Karşılaştırılan değer 256 bit rastgele token'ın SHA-256'sıdır; zamanlamadan hash öneki öğrenmek token hakkında bilgi vermez (depodaki tüm token aramalarıyla aynı desen).
- **Global `credential_id` benzersizliği:** başka bir hesaptaki credential id'si ile kayıt denendiğinde `passkey_already_registered` döner. Bu yalnızca o ham credential id'sini zaten bilen ve kendi oturumunda kayıt seremonisi başlatabilen birine id'nin kayıtlı olduğunu söyler; hesap ele geçirme imkânı yoktur (her satır kendi açık anahtarıyla doğrulanır).
- **Passkey adlarında Unicode normalizasyonu (NFC) / benzer glif kontrolü yok.** Adlar yalnızca sahibine gösterilir, audit ve bildirimlere girmez; kontrol, bidi-override, görünmez ve etiket karakterleri reddedilir.
- **Attestation sertifikalarının geçerlilik zamanı** `webauthn-rs` içinde `SystemTime` ile kontrol edilir (enjekte edilen `Clock` değil); yalnızca kısıtlayıcı politika altındaki kayıtları etkiler.

### Güvenlik incelemesi (wave 1, K-01 — 2026-11-04)

| Önem | Bulgu | Düzeltme | Test |
|------|-------|----------|------|
| Düşük | `remove_all_passkeys_in_tx` yalnızca kimlik bilgilerini siliyordu; sıfırlamadan **önce** başlatılmış bir **kayıt** seremonisi sıfırlamadan sonra tamamlanabiliyor ve "tüm passkey'leri sil"in hemen ardından yeni bir passkey ekliyordu. Admin MFA sıfırlaması aynı transaction'da tüm oturumları kapattığı için varsayılan yapılandırmada sömürülemez; ancak `session.access_token_session_check = false` iken iptal edilmiş oturumun access token'ı `access_token_ttl` boyunca geçerli kalır ve bu pencerede seremoni bitirilebilirdi. Belge ("devam eden seremoniler tamamlanamaz") yalnızca kimlik doğrulama seremonileri için doğruydu. | Kullanıcının açık seremonileri (`webauthn_ceremonies`, `user_id` eşleşen, tüketilmemiş) aynı transaction'da tüketilmiş işaretlenir — passkey olmasa da. | `pky_04_remove_all_passkeys_in_tx_cancels_open_ceremonies` |

Kabul edilen riskler:

- **Son giriş yöntemi kuralı bilinçli olarak uygulanmaz.** Yalnızca passkey'le giren (şifresiz, sosyal kimliği olmayan) bir hesapta sıfırlamadan sonra passkey ve şifre kalmaz. Hesap kullanılamaz hâle gelmez: e-posta adresine sahip olan kullanıcı magic link / e-posta koduyla (SES-18/19) girer, ardından zorunlu adımlar (SES-22) yeni passkey veya MFA kaydını ister; kullanıcıya hem `mfa_reset` hem `mfa_factor_removed` bildirimi gider. Kuralı uygulamak, saldırganın eklediği passkey'i korumak demek olurdu (K-01'in kendisi).
- **Personel IP'si kullanıcı olaylarında görünmez (wave 2B):** `remove_all_passkeys_in_tx`'in `passkey.removed` olayları `Actor::System` ile yazılır ve yalnızca istek kimliğini taşır; adminin IP'si / user-agent'ı kullanıcının güvenlik olayları listesine girmez (K-14 ile aynı kural).
- **`access_token_session_check = false` iken** iptal edilmiş oturumun access token'ı `access_token_ttl` (varsayılan 10 dk) boyunca kabul edildiğinden, o token'ı elinde tutan biri sıfırlamadan sonra **yeni** bir kayıt seremonisi başlatıp ilk passkey'i ekleyebilir (`step_up_for_first_passkey = false` ise step-up da gerekmez). Bu, oturum katmanının belgelenmiş ödünleşimidir (authn-session README); yüksek güvenlik gereken kurulumlarda kontrol açık kalmalıdır (varsayılan).

## authn-server / Dalga B'nin bağlaması gerekenler

1. `WebauthnService` ve `WellKnownDocuments` için `FromRef<AppState>`; `router` oturum + CSRF katmanının arkasına, `well_known_router` köke; `WebauthnApi` OpenAPI'ye.
2. `AccountMethodsSource` (şifre + sosyal kimlikler + MFA zorunluluğu) ve `PasskeyPolicySource` (authn-org politikaları) uygulamaları.
3. authn-server `authn-webauthn`'u `features = ["passkey"]` ile almalı (workspace girdisi `default-features = false`).
4. Arka plan işi: `purge_expired_ceremonies()`.
5. authn-account dışa aktarma toplayıcısına `PasskeyDataExporter`.
6. authn-mfa `MfaPolicySource::webauthn_factor_count` ve authn-password `LoginMethodInventory` için `passkey_count_in`.
8. Wave 2B (K-11): `start_enrollment_registration` / `verify_enrollment_registration` / `store_enrollment_in_tx` yalnızca authn-admin'in break-glass kayıt bağlantısı akışı içindir (bağlantı token'ını o doğrular ve tüketir); migration `1401` gömülü migrator ile gelir.
7. authn-session: passkey girişi/ikinci faktör/step-up uç noktaları `start_authentication` / `finish_authentication` ile; `binding_token` web'de `HttpOnly; Secure; SameSite=Strict` kısa ömürlü çerezde, native'de gövdede; `AuthenticationTarget` istemciden değil session'ın kendi kaydından kurulur; başarıdan sonra hesap durumu, challenge/oturum geçerliliği, audit (`login.*`, `mfa.*`, `step_up.*`) ve AMR birleştirmesi session'dadır.

Ayrıntılı talepler: `docs/architecture/contract-change-requests.md` → `## authn-webauthn`.

## SHOULD / MAY notları

- `/.well-known/webauthn` (MAY) uygulandı; boş yapılandırmada `404`.
- PKY-08 (opsiyonel) uygulandı; FIDO MDS entegrasyonu yok — güvenilir kökler konfigürasyondan gelir.
- Ekleme/kaldırma `MfaFactorAdded/Removed { factor: webauthn }` ile gider (admin MFA sıfırlamasında passkey sayısından bağımsız **tek** `mfa_factor_removed`; test: authn-admin `adm_03_mfa_reset_sends_one_notice_not_one_per_passkey`). Klon şüphesi `NotificationKind::PasskeyCloneSuspected` ile (wave 2B, K-19; `pky_05_clone_suspicion_notifies_the_owner_once`).

## Testler

`tests/` altındaki entegrasyon testleri `webauthn-authenticator-rs` yazılımsal authenticator'ları (`SoftPasskey`, attestation için `SoftToken`) ile gerçek kayıt + giriş gidiş-dönüşleri yapar: tekrar oynatılan / süresi dolmuş / başka kullanıcıya-oturuma-challenge'a takılmış seremoniler, yanlış ve phishing origin'leri, Android origin'i, sayaç gerilemesi (öncesi ve seremoni sırasında), şifresiz giriş için UV zorunluluğu, eşzamanlı bitirme ve silme yarışları, IDOR, AAGUID politikası, HTTP katmanı ve OpenAPI. `SoftPasskey` resident key saklayamadığı için discoverable girişte platformun credential seçimi test yardımcıları içinde simüle edilir (`userHandle` imzalı değildir).

## Komutlar

```bash
cargo test -p authn-webauthn --all-features
cargo clippy -p authn-webauthn --all-targets --all-features -- -D warnings
cargo clippy -p authn-webauthn --all-targets --no-default-features -- -D warnings
cargo fmt -p authn-webauthn
```

> Not: Diğer agent'lar paralel çalışırken `cargo fmt --all` çalıştırmayın.
