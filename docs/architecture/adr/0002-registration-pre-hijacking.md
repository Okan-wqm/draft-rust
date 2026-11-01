# ADR 0002 — Kayıtta hesap ön-ele geçirme (pre-hijacking) savunması: kayda bağlı kimlik bilgileri

- **Durum:** Kabul edildi (2026-11-01)
- **Sahip:** `authn-account`
- **İlgili gereksinimler:** ACC-01, ACC-02, ACC-04, ACC-05, ACC-07, ACC-10, ACC-11, PWD-09, SES-18, SOC-05, ADM-03, TST-02
- **Kod:** `crates/authn-account/src/service/{signup,registration,verification,revocation,email_change}.rs`, `crates/authn-account/src/registration_store.rs`, `migrations/1201_pending_registrations.sql`
- **Testler:** `crates/authn-account/tests/prehijack.rs` (`acc_02_*`, `acc_04_*`, `acc_05_*`, `acc_07_*`, `acc_10_*`, `acc_11_*`), `tests/verification.rs`, `tests/signup.rs`
- **Kaynak:** A. Sudhodanan, A. Paverd, "Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web", USENIX Security 2022

## Bağlam

Ön-ele geçirmede saldırgan, kurbanın e-posta adresiyle **kurbandan önce** (veya kurbanın kaydı ile doğrulaması **arasında**) bir şey yapar ve kurban hesabı kullanmaya başladığında hesabın kontrolü saldırgandadır. Makaledeki sınıflar ve bu sistemdeki karşılıkları:

| Sınıf | Bu sistemde nasıl olurdu |
|-------|--------------------------|
| Classic-federated merge | Saldırgan adresle şifreli hesap açar, kurban aynı adresle sosyal girişe gelir, hesaplar birleşir (SOC-05 otomatik birleştirmeyi zaten yasaklar) |
| Unexpired session | Saldırgan doğrulanmamış hesapta oturum açar (`limited` mod), kurban hesabı devralınca oturum yaşamaya devam eder |
| Trojan identifier | Saldırgan doğrulanmamış hesaba kendi kimlik bilgisini (sosyal kimlik, passkey) ekler |
| Unexpired email change | Saldırgan hesabın adresini değiştirme talebinde bulunur, kurban devraldıktan sonra link hâlâ çalışır |
| Non-verifying IdP | Sağlayıcı e-postayı doğrulamadan "bu adres" der |

Önceki tasarımın iki somut açığı vardı (Dalga A incelemesinde "kabul edilen risk" olarak işaretlenmişti; bu ürün için kabul edilemez):

1. **Saldırgan ikinci:** kurban kayıt olur, doğrulamadan önce saldırgan aynı adresle tekrar kayıt olur; "son kayıt olan kazanır" kuralı şifreyi saldırganınkiyle değiştirir; kurban (gelen kutusundaki en yeni) linke tıklar ve hesap **saldırganın şifresiyle** doğrulanır.
2. **Saldırgan önce:** saldırgan kurbanın adresiyle kendi şifresiyle kayıt olur; kurban gelen doğrulama e-postasındaki linke tıklar (ya da kendisi kayıt olur ve aynı linke tıklar) ve hesap **saldırganın şifresiyle** doğrulanır. Link sahibinin (posta kutusu sahibi) şifreyi seçen kişi olduğunu hiçbir şey kanıtlamıyordu.

Kök neden: **posta kutusu kontrolünün kanıtı (link/kod) ile kimlik bilgisinin sahipliği (şifreyi kimin seçtiği) birbirine bağlı değildi.** Doğrulama, "bu adresin hesabındaki şu anki şifre"yi etkinleştiriyordu; o şifreyi kimin seçtiği belirsizdi.

## Hedef (değişmez)

> Kayıt, yeniden gönderme, doğrulama, e-posta değişikliği ve şifre sıfırlamanın **hiçbir sırası**, posta kutusu sahibi dışında birinin, aynı akışta posta kutusu kontrolünü kanıtlamadan **seçtiği kimlik bilgileriyle doğrulanmış bir hesabı kontrol etmesine** yol açmaz; posta kutusu sahibi **her zaman** hesabı geri alabilir.

## Değerlendirilen seçenekler

| Seçenek | Artı | Eksi |
|---------|------|------|
| A. "Son kayıt olan kazanır" (eski) | Basit | Saldırgan ikinci kazanır; saldırgan önce de linkle kazanır |
| B. "İlk kayıt olan kazanır", sonrakiler bildirim alır | Saldırgan ikinci kaybeder | Saldırgan önce kazanır (kurban linke tıklarsa); kurban "zaten var" çıkmazına düşer |
| C. Şifre doğrulama anında seçilir (kayıtta şifre yok) | Link alan kişi şifreyi seçer — posta kutusu sahibi kazanır | ACC-01 "e-posta + şifre ile kayıt" deneyimini bozar; her kayıt iki adım |
| D. Doğrulanmamış hesap hiç oluşturulmaz (`users` satırı yalnızca doğrulamada) | En temiz | Durum makinesini (`pending_verification`), ACC-05 `limited` modunu, Dalga B'nin varsayımlarını ve tüm testleri bozar |
| **E. Her kaydın kimlik bilgisi kendi doğrulamasına ve kendi istemcisine bağlı (seçilen)** | Saldırgan önce ve ikinci kaybeder; kayıt deneyimi korunur; durum makinesi değişmez | Yeni tablo; doğrulama sayfası "başka cihaz" durumunu ele almalı |

## Karar

**Seçenek E.** Kurallar:

1. **Kayıt kimlik bilgisi yazmaz.** İlk kayıt, adres için **kimlik bilgisi olmayan** bir `pending_verification` yer tutucu hesap oluşturur. Gönderilen şifre hash'i (Argon2id + pepper), görünen ad, dil, saat dilimi ve kabul edilen şart sürümleri `pending_registrations` satırında bekler. Yer tutucu hesabın şifresi olmadığından şifreyle giriş yapılamaz (`invalid_credentials`), oturum açılamaz, authn-password sıfırlama göndermez (yalnızca var olan şifreyi değiştirir).
2. **Her kayıt üç sırra bağlıdır:** e-postayla giden **link** (256 bit, 24 sa), **kod** (6 hane, 15 dk) ve kayıt yanıtında istemciye verilen **tutamaç** (handle; 256 bit, yanıt gövdesinde `registration` ve `__Host-authn_registration` çerezinde: `HttpOnly; Secure; SameSite=Strict; Path=/`, ömrü `account.unverified_purge_after`). Tutamaç adresten bağımsız rastgele veridir; yanıt her adres için aynı biçimdedir (ACC-02).
3. **Tamamlama yalnızca o kaydın kimlik bilgisini etkinleştirir ve şunlardan birini ister:**

   | Sunulan kanıt | Etkinleşen kimlik bilgisi |
   |---------------|---------------------------|
   | link + tutamaç (kaydı yapan tarayıcı, çerez) | kaydınki |
   | link + o kayıtta seçilen şifre (başka cihaz) | kaydınki |
   | link + **yeni** şifre (+ zorunluysa şartların kabulü) | yeni şifre; kaydın profil ve onayları atılır |
   | yalnızca link | hiçbiri — `registration_confirmation_required` (403) |
   | kod + tutamaç (kaydı yapan istemcinin akışı) | kaydınki |
   | tutamaçsız kod (ör. eski "e-posta + kod") | hiçbiri — `invalid_code` |

   Link posta kutusu kontrolünü kanıtlar; tutamaç veya şifre "bu kimlik bilgisini ben seçtim"i kanıtlar; yeni şifre ise kimlik bilgisini **posta kutusu sahibinin** aynı akışta seçmesidir. Böylece yalnızca link, tıklayanın seçmediği bir şifreye doğrulanmış hesap **veremez**.
4. **Tamamlama tek transaction'dır** (adres advisory kilidi → kayıt satır kilidi → kullanıcı satır kilidi): şifre, profil, onaylar (kaydın zamanı/IP'si/UA'sı ile), adresin kayıttaki yazımı yazılır; adres doğrulanır, `pending_verification → active` (ACC-06, audit); hesabın **bütün** bekleyen kayıtları silinir (linkleri, kodları, tutamaçları ölür); bekleyen doğrulama token'ları iptal edilir; **tüm oturumlar ve güvenilir cihazlar** iptal edilir ("unexpired session" sınıfı). Eşzamanlı tamamlamalardan tam olarak biri başarılı olur.
5. **Aynı adrese yeniden kayıt hiçbir şeyi değiştirmez.** Doğrulanmış hesap → sahibine "biri bu adresle kayıt olmaya çalıştı" e-postası (giriş ve şifre sıfırlama yolları ile; şifre değişmez). Doğrulanmamış hesap → aynı yer tutucuya **ayrı** bir kayıt (adres başına günde `registration_notice_per_email`, hesap başına en fazla 10 canlı kayıt); mevcut kayıtlara, oturumlara, profile dokunulmaz. Yanıt, durum ve süre her durumda aynıdır (ACC-02; hesaba bağlı iş arka planda).
6. **Tahmin sınırları:** kayıt başına ömür boyu `verification.code_max_attempts` (5) yanlış kod (yeniden gönderme kodu yeniler, sayacı sıfırlamaz), adres başına saatlik `code_attempts_per_email`, IP başına `verify_per_ip`; link sayfasında "seçtiğiniz şifre" için kayıt başına `MAX_PASSWORD_CONFIRMATIONS` (5) yanlış yanıt, sonra yalnızca yeni şifre.
7. **Doğrulanmamış hesap süresi dolar:** kayıt `unverified_purge_after` (7 gün) sonra silinir; yer tutucu, canlı kaydı kalmayınca temizlenir (sonraki bir kaydı erken bitirmez).
8. **Posta kutusu sahibi her zaman kazanır / geri alır:**
   - Herhangi bir kaydın linki (ya da yeniden gönderilen yenisi) + yeni şifre → hesap posta kutusu sahibinin.
   - Oturumla verilmiş doğrulama linki (`POST /v1/me/email/verification`, `limited` mod) aynı kurala uyar: oturumun sahibi, hesabın şifresi ya da yeni şifre; yeni şifre tüm oturumları kapatır.
   - **Şifre sıfırlama** doğrulanmamış hesapta (yalnızca şifresi olan eski/başka kaynaklı hesaplar) adresi doğrular, bekleyen kayıtları siler; oturumlar sıfırlamanın kendisiyle kapanır (`MailboxProof::PasswordReset`).
   - Magic link / giriş kodu / sağlayıcının doğruladığı e-posta / admin işaretlemesi (`MailboxProof::Passwordless`, `Administrator`) doğrulanmamış hesapta kanıtlanmamış şifreyi **siler**, kayıtları siler, oturumları kapatır.
9. **E-posta değişikliği linki de bağlıdır (ACC-07):** `POST /v1/email/change/confirm` artık hesap sahibinin oturumunu ister. Aksi hâlde saldırgan kendi (şifreli, passkey'li) hesabının adresini kurbanın adresine değiştirmeyi ister, kurban istenmeyen "adresinizi onaylayın" e-postasına tıklar ve saldırganın kimlik bilgileriyle kurbanın adresine **doğrulanmış** bir hesap oluşur. Kod yolu (`/v1/me/email/confirm`) zaten oturuma bağlıydı.
10. **Bekleyen e-posta değişikliği, kimlik bilgisi sıfırlanınca ölür:** şifre sıfırlama/değiştirme, "tümünü kapat", "bu ben değilim", refresh token yeniden kullanımı, askıya alma/admin ve acil durum iptalleri `email_change` / `email_change_code` token'larını iptal eder (geri alma linkleri korunur — sahibin geri dönüş yolu).

### Bağlama (diğer crate'leri değiştirmeden)

authn-password'ün sıfırlama tamamlaması ve authn-session'ın toplu iptalleri zaten `SessionRevoker` portunu **kendi transaction'larında** çağırır. `authn_account::AccountAwareSessionRevoker`, bu portu saran bir dekoratördür: iç iptalden sonra aynı bağlantıda `on_sessions_revoked_in_tx` (madde 8 ve 10) uygulanır. authn-server, authn-session'ın revoker'ını bir kez sarar ve sarılmış portu tüm modüllere verir; `AccountServiceDeps::sessions`'a iç revoker verilir. Kural: `RevocationReason::PasswordReset` yalnızca e-postayla gelen sıfırlamanın tamamlanmasında kullanılır (adresi doğruladığı için).

## Sonuçlar

**Olumlu**
- "Saldırgan ikinci" ve "saldırgan önce" senaryoları kapandı; ikinci kayıt hiçbir şeyi değiştirmez, link kimseye seçmediği şifreyi vermez.
- Doğrulanmamış hesaplarla şifreli giriş yapılamaz; giriş yanıtı var olmayan hesapla aynıdır (ACC-02 güçlendi).
- Kurban "zaten var" çıkmazına düşmez: kendi kaydı kendi e-postasını alır.
- Oturum, güvenilir cihaz ve bekleyen e-posta değişikliği kalıntıları tamamlamada ve sıfırlamada temizlenir.

**Olumsuz / ödünleşimler**
- `limited` mod (ACC-05) kayıtla oluşan hesaplar için şifreli giriş anlamına gelmez: kayıt tamamlanmadan hesabın kimlik bilgisi yoktur. Kayıttan sonraki "sınırlı erişim", kaydı yapan istemcinin tutamaçla yaptığı işlemlerdir (kodla doğrulama, yeniden gönderme). Politika, kimlik bilgisi başka yoldan gelmiş doğrulanmamış hesaplar için (`assess_login` → `verify_email` zorunlu adımı) aynen geçerlidir.
- Kayıt bir cihazda, link başka cihazda açılırsa kullanıcı şifresini bir kez daha girer.
- Kayıt doğrulanmadan şifresini unutan kullanıcı, şifre sıfırlama yerine linkteki "yeni şifre" yolunu (veya yeniden kaydı) kullanır.
- Doğrulama linki 24 saat boyunca "yeni şifre" ile hesabı kurabildiğinden, bu süre içinde sızan bir link, sızdığı kişiye hesabı verir (önceki tasarımda da link hesabı doğruluyordu; şifre sıfırlama linkiyle aynı sınıf).
- `MAX_LIVE_REGISTRATIONS` ve adres başına kayıt sınırı, bir saldırganın kurbanın aynı gün içindeki kaydını sessizce düşürmesine izin verir (hedefli DoS); kurban yine elindeki herhangi bir link ve yeni şifreyle veya ertesi gün tamamlar.

**Artık riskler**
- **Kod oltalama:** saldırgan kurbanın adresiyle kayıt olup kendi tutamacını tutar ve kurbandan e-postadaki kodu "okumasını" isterse, kodu kendi tutamacıyla girerek kazanır. Bu, posta kutusu sahibinin sırrı gönüllü vermesidir (makalenin tehdit modeli dışında); e-posta metni "kayıt olmadıysanız yok sayın" der. Link için aynı oltalama hem link hem şifre/tutamaç gerektirir.
- **Kod tahmini:** adres başına günde en fazla ~`registration_notice_per_email` kayıt × 5 deneme (≈ 15) → hedeflenen adres başına günde ≈ 1,5·10⁻⁵ başarı olasılığı (ACC-04'ün 6 haneli kod tasarımından).
- **Diğer modüllerin kimlik bilgileri:** bu crate `identities`/`webauthn_credentials`'ı göremez. authn-oidc-client ve authn-webauthn, `pending_verification` bir hesaba kimlik bilgisi **eklememeli**; sağlayıcının doğruladığı e-postayla bağlarken `confirm_mailbox_control_in_tx(…, MailboxProof::Passwordless)` çağrılmalıdır ("Trojan identifier" sınıfı).
- **Kilit sırası:** sıfırlama tamamlaması (kullanıcı → kayıt satırları) ile kayıt tamamlaması (kayıt → kullanıcı) aynı anda çakışırsa PostgreSQL kilitlenmeyi tespit edip birini geri alır; tutarsız durum oluşmaz.

## Reddedilen alternatifler

- **B (ilk kazanır):** saldırgan önce senaryosunu açık bırakır — makaledeki en yaygın sınıf.
- **C (şifre doğrulamada):** güvenli ama ACC-01 deneyimini ve mobil akışı değiştirir; E, "yeni şifre" yolunu C'nin güvenli kısmı olarak zaten içerir.
- **D (doğrulanmadan `users` satırı yok):** en temiz model, fakat Dalga A'nın durum makinesi, `limited` politika ve Dalga B sözleşmeleri üzerinde kırıcı; E aynı güvenlik özelliğini bunları bozmadan sağlar.
